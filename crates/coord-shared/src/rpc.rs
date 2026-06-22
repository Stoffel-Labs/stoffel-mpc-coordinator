use crate::{self_signed_certs, CoordinatorError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use jsonrpsee::{
    server::ServerHandle,
    server::{RpcModule, Server},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Barrier, Mutex};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

/// A wrapper around a share element that is serializable and deserializable for use with JSON-RPC.
#[derive(Clone, Debug)]
pub struct ValueWrapper<T: CanonicalSerialize + CanonicalDeserialize> {
    pub value: T,
}

impl<'d, T: CanonicalSerialize + CanonicalDeserialize> Deserialize<'d> for ValueWrapper<T> {
    fn deserialize<D>(deserializer: D) -> Result<ValueWrapper<T>, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        T::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
            .map(|value| ValueWrapper::<T> { value })
            .map_err(serde::de::Error::custom)
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> Serialize for ValueWrapper<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.value
            .serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;

        serializer.serialize_bytes(&bytes)
    }
}

/// Information stored by an RPC server about a connected client.
pub struct ClientInfo {
    pub cert: Vec<u8>,
    pub thread: JoinHandle<()>,
    pub stop_tx: ServerHandle,
}

/// The internal state of a JSON-RPC server. This is shared state across all client connections.
pub trait RPCServerShared {
    fn add_client(
        &mut self,
        cert_der: Vec<u8>,
        client_handle: JoinHandle<()>,
        stop_tx: ServerHandle,
    );
}

/// This represents the JSON-RPC server's state for one client connection. Internally, it refers to
/// some cross-client shared state of the server and also stores the client's public key.
/// This allows the JSON-RPC methods that implement a `jsonrpsee` trait created using the `#rpc`
/// attribute to access such client-specific information, in particular the client's identity.
pub trait RPCServerConnection {
    type Internal: RPCServerShared + 'static + Send;
    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self;
    fn into_rpc(self) -> RpcModule<Self>
    where
        Self: Sized;
}

/// Starts a JSON-RPC server, which listens for Websocket connections over TLS.
pub async fn start_coord<T: RPCServerConnection>(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    rpc_server_data: Arc<Mutex<T::Internal>>,
) -> Result<JoinHandle<()>, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let tls_config = self_signed_certs::server_tls_config(cert_der, key_der)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&full_addr)
        .await
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;

    Ok(tokio::spawn({
        let tls_acceptor = tls_acceptor.clone();
        let rpc_server_data = rpc_server_data.clone();

        async move {
            loop {
                let (tcp_stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let tls_acceptor = tls_acceptor.clone();
                let rpc_server_data = rpc_server_data.clone();

                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("TLS handshake failed: {}", e);
                        continue;
                    }
                };

                let (stop_rx, stop_tx) = jsonrpsee::server::stop_channel();
                let cert_der = match tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| c.to_vec())
                {
                    Some(c) => c,
                    None => {
                        tracing::warn!("Client connected without a certificate, rejecting");
                        continue;
                    }
                };

                let public_key = match X509Certificate::from_der(&cert_der) {
                    Ok((_remainder, parsed_cert)) => parsed_cert
                        .public_key()
                        .subject_public_key
                        .data
                        .as_ref()
                        .to_vec(),
                    Err(e) => {
                        tracing::warn!("Failed to parse client X.509 certificate: {}", e);
                        continue;
                    }
                };

                let rpc_server = T::new(rpc_server_data.clone(), public_key);
                let rpc_module = rpc_server.into_rpc();
                let rpc_service = Server::builder()
                    .to_service_builder()
                    .build(rpc_module, stop_rx);

                // Barrier needed, since we start the client thread but only add the client
                // info afterwards; client info is accessible to the JSON-RPC methods, so if a
                // request comes in after starting the client thread but before adding the
                // client info, we may have a problem.
                let barrier = Arc::new(Barrier::new(2));
                let client_handle = tokio::spawn({
                    let barrier = barrier.clone();
                    async move {
                        barrier.wait().await;
                        if let Err(e) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                TowerToHyperService::new(rpc_service),
                            )
                            .with_upgrades()
                            .await
                        {
                            tracing::warn!("Connection error: {}", e);
                        }
                    }
                });

                rpc_server_data
                    .lock()
                    .await
                    .add_client(cert_der, client_handle, stop_tx);
                barrier.clone().wait().await;
            }
        }
    }))
}
