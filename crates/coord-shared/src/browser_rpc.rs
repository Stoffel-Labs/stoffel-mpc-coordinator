//! Browser-reachable JSON-RPC transport over server-authenticated TLS.
//!
//! Unlike [`crate::rpc::start_coord`], this transport never requests a client
//! certificate. Browser clients authenticate at the RPC layer instead. Every
//! HTTP request must carry exactly one `Origin` header whose value exactly
//! matches the configured allowlist before jsonrpsee can perform a WebSocket
//! upgrade.

use crate::CoordinatorError;
use futures_util::{Future, FutureExt, TryFutureExt};
use hyper::body::Bytes;
use hyper::header::{HeaderValue, ORIGIN};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use jsonrpsee::core::BoxError;
use jsonrpsee::server::{
    HttpBody, HttpResponse, Methods, RpcModule, Server, ServerConfig, ServerHandle,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tower::{Layer, Service, ServiceBuilder};

/// An exact allowlist for HTTP `Origin` header values.
///
/// Values are compared as header bytes: no URL normalization, wildcard
/// matching, suffix matching, or case folding is performed.
#[derive(Clone, Debug)]
pub struct BrowserOriginAllowlist {
    allowed: Arc<HashSet<HeaderValue>>,
}

impl BrowserOriginAllowlist {
    /// Construct an exact origin allowlist.
    pub fn new<I, S>(origins: I) -> Result<Self, hyper::header::InvalidHeaderValue>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed = origins
            .into_iter()
            .map(|origin| HeaderValue::from_str(origin.as_ref()))
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }

    fn permits<B>(&self, request: &Request<B>) -> bool {
        let mut origins = request.headers().get_all(ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return false;
        };

        // Multiple Origin fields are ambiguous and therefore rejected even if
        // one of them is allowed.
        origins.next().is_none() && self.allowed.contains(origin)
    }
}

/// Tower layer that rejects requests without exactly one allowed `Origin`.
#[derive(Clone, Debug)]
pub struct BrowserOriginLayer {
    allowlist: BrowserOriginAllowlist,
}

impl BrowserOriginLayer {
    pub fn new(allowlist: BrowserOriginAllowlist) -> Self {
        Self { allowlist }
    }
}

impl<S> Layer<S> for BrowserOriginLayer {
    type Service = BrowserOriginService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BrowserOriginService {
            inner,
            allowlist: self.allowlist.clone(),
        }
    }
}

/// Tower service produced by [`BrowserOriginLayer`].
#[derive(Clone, Debug)]
pub struct BrowserOriginService<S> {
    inner: S,
    allowlist: BrowserOriginAllowlist,
}

impl<S, B> Service<Request<B>> for BrowserOriginService<S>
where
    S: Service<Request<B>, Response = HttpResponse<HttpBody>>,
    S::Response: 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if self.allowlist.permits(&request) {
            Box::pin(self.inner.call(request).map_err(Into::into))
        } else {
            async {
                Ok(HttpResponse::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(HttpBody::from("WebSocket Origin not allowed"))
                    .expect("static HTTP response is valid"))
            }
            .boxed()
        }
    }
}

/// Running browser RPC server resources.
///
/// Call `server_handle.stop()` to request shutdown, then await `task` if the
/// caller needs to wait for the listener loop to exit.
pub struct BrowserRpcServer {
    pub local_addr: SocketAddr,
    pub server_handle: ServerHandle,
    pub task: JoinHandle<()>,
}

/// Build a server-authenticated TLS configuration that does not request or
/// verify client certificates.
pub fn browser_server_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Start a WSS-only jsonrpsee server for browser clients.
///
/// TLS authenticates only the server. Client authentication belongs in the
/// supplied RPC module (for example, capability-token checks). The origin
/// middleware runs before jsonrpsee examines or upgrades the request.
pub async fn start_browser_rpc<Context>(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    allowed_origins: BrowserOriginAllowlist,
    rpc_module: RpcModule<Context>,
) -> Result<BrowserRpcServer, CoordinatorError> {
    let full_addr = format!("{addr}:{port}");
    let tls_config = browser_server_tls_config(cert_der, key_der)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&full_addr)
        .await
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;

    let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();
    let methods: Methods = rpc_module.into();
    let service_builder = Server::builder()
        .set_config(ServerConfig::builder().ws_only().build())
        .set_http_middleware(ServiceBuilder::new().layer(BrowserOriginLayer::new(allowed_origins)))
        .to_service_builder();

    let task = tokio::spawn(async move {
        loop {
            let (tcp_stream, peer_addr) = tokio::select! {
                _ = stop_handle.clone().shutdown() => break,
                accepted = listener.accept() => match accepted {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!("Browser RPC TCP accept failed: {error}");
                        continue;
                    }
                },
            };

            let tls_acceptor = tls_acceptor.clone();
            let service_builder = service_builder.clone();
            let methods = methods.clone();
            let connection_stop = stop_handle.clone();
            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        tracing::warn!(
                            "Browser RPC TLS handshake from {peer_addr} failed: {error}"
                        );
                        return;
                    }
                };

                let rpc_service = service_builder.build(methods, connection_stop);
                if let Err(error) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls_stream),
                        TowerToHyperService::new(rpc_service),
                    )
                    .with_upgrades()
                    .await
                {
                    tracing::warn!("Browser RPC connection from {peer_addr} failed: {error}");
                }
            });
        }
    });

    Ok(BrowserRpcServer {
        local_addr,
        server_handle,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{self_signed_certs, setup_test};
    use hyper::header::ORIGIN;
    use rustls::pki_types::ServerName;
    use std::convert::Infallible;
    use tower::ServiceExt;

    fn origin_service() -> BrowserOriginService<
        tower::util::BoxCloneService<Request<HttpBody>, HttpResponse<HttpBody>, Infallible>,
    > {
        let inner = tower::util::BoxCloneService::new(tower::service_fn(
            |_request: Request<HttpBody>| async {
                Ok::<_, Infallible>(
                    HttpResponse::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .body(HttpBody::empty())
                        .unwrap(),
                )
            },
        ));
        BrowserOriginLayer::new(
            BrowserOriginAllowlist::new(["https://app.example", "http://localhost:5173"]).unwrap(),
        )
        .layer(inner)
    }

    #[tokio::test]
    async fn exact_allowed_origin_reaches_inner_service() {
        let response = origin_service()
            .oneshot(
                Request::builder()
                    .header(ORIGIN, "https://app.example")
                    .body(HttpBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[tokio::test]
    async fn missing_mismatched_and_non_exact_origins_are_rejected() {
        for origin in [
            None,
            Some("https://evil.example"),
            Some("https://app.example/"),
            Some("HTTPS://app.example"),
        ] {
            let mut request = Request::builder();
            if let Some(origin) = origin {
                request = request.header(ORIGIN, origin);
            }
            let response = origin_service()
                .oneshot(request.body(HttpBody::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin:?}");
        }
    }

    #[tokio::test]
    async fn multiple_origin_headers_are_rejected() {
        let request = Request::builder()
            .header(ORIGIN, "https://app.example")
            .header(ORIGIN, "https://app.example")
            .body(HttpBody::empty())
            .unwrap();
        let response = origin_service().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn browser_tls_accepts_client_without_certificate() {
        setup_test();
        let cert = self_signed_certs::server_cert();
        let tls_config =
            browser_server_tls_config(cert.cert.der().to_vec(), cert.signing_key.serialize_der())
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(self_signed_certs::SelfSignedServerVerifier {}));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let client_result = connector
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await;

        assert!(client_result.is_ok());
        assert!(server.await.unwrap().is_ok());
    }
}
