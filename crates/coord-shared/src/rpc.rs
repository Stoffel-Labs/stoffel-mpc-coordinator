use crate::pin::{PinError, SpkiDer};
use crate::{self_signed_certs, ClientIdentity, CoordinatorError};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use jsonrpsee::server::middleware::rpc::{
    Batch, MethodResponse, Notification, RpcServiceBuilder, RpcServiceT,
};
use jsonrpsee::server::{RpcModule, Server, ServerConfig, ServerHandle};
use jsonrpsee::types::Request;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

/// The caller identity every RPC is authorized on. `SpkiDer::from_certificate_der`
/// followed by `client_identity`, so trailing bytes, unsupported algorithms and
/// non-canonical encodings are refused.
pub fn caller_identity(cert_der: &[u8]) -> Result<ClientIdentity, PinError> {
    Ok(SpkiDer::from_certificate_der(cert_der)?.client_identity())
}

/// This represents the JSON-RPC server's state for one client connection. Internally, it refers to
/// some cross-client shared state of the server and also stores the client's public key.
/// This allows the JSON-RPC methods that implement a `jsonrpsee` trait created using the `#rpc`
/// attribute to access such client-specific information, in particular the client's identity.
pub trait RPCServerConnection {
    type Internal: 'static + Send;
    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self;
    fn into_rpc(self) -> RpcModule<Self>
    where
        Self: Sized;
    /// Which connection pool `id` draws on. Default `Unreserved`.
    fn capacity_class(_internal: &Self::Internal, _id: &ClientIdentity) -> CapacityClass {
        CapacityClass::Unreserved
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityClass {
    /// A roster node: bounded only by `max_connections_per_identity`, so by `n` times it.
    Node,
    /// A client bound to a slot of a live execution (coordinator), or holding a registered
    /// reservation (node RPC listener).
    BoundClient,
    /// Everyone else.
    Unreserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcServerLimits {
    /// Accepted TCP connections whose TLS handshake has not finished, all sources (default 1024).
    pub max_pending_handshakes: usize,
    /// The same, from one source IP address (default 16).
    pub max_pending_handshakes_per_ip: usize,
    /// A connection whose TLS handshake has not finished by then is closed (default 10 s).
    pub handshake_timeout: Duration,
    /// Established connections of `CapacityClass::Unreserved` identities (default 4096).
    pub max_connections: usize,
    /// Established connections of `CapacityClass::BoundClient` identities (default 1024).
    pub max_bound_client_connections: usize,
    /// Established connections of one identity, whatever its class (default 8).
    pub max_connections_per_identity: usize,
    /// An unreserved connection with no call in progress, no live subscription and no call
    /// started for this long is closed (default 30 s).
    pub idle_timeout: Duration,
    /// jsonrpsee's per-connection subscription bound (default 64; jsonrpsee's own default is 1024).
    pub max_subscriptions_per_connection: u32,
    /// Messages a connection may have queued before its subscriptions stop receiving
    /// (default 16; jsonrpsee's own default is 1024).
    pub message_buffer_capacity: u32,
}

impl Default for RpcServerLimits {
    fn default() -> Self {
        Self {
            max_pending_handshakes: 1024,
            max_pending_handshakes_per_ip: 16,
            handshake_timeout: Duration::from_secs(10),
            max_connections: 4096,
            max_bound_client_connections: 1024,
            max_connections_per_identity: 8,
            idle_timeout: Duration::from_secs(30),
            max_subscriptions_per_connection: 64,
            message_buffer_capacity: 16,
        }
    }
}

/// Owns one listener and all connections accepted by it.
pub struct RPCServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl RPCServerHandle {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for RPCServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

/// Counts TCP connections whose TLS handshake has not finished, in total and per source.
/// Nothing before the handshake can tell a node from anyone else, so these bounds apply to
/// every source alike.
struct PendingHandshakes {
    max_total: usize,
    max_per_ip: usize,
    counts: std::sync::Mutex<PendingCounts>,
}

#[derive(Default)]
struct PendingCounts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Holds one pending-handshake slot; dropping it releases the slot.
struct PendingHandshakePermit {
    pending: Arc<PendingHandshakes>,
    ip: IpAddr,
}

impl PendingHandshakes {
    fn new(limits: &RpcServerLimits) -> Arc<Self> {
        Arc::new(Self {
            max_total: limits.max_pending_handshakes,
            max_per_ip: limits.max_pending_handshakes_per_ip,
            counts: std::sync::Mutex::new(PendingCounts::default()),
        })
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PendingHandshakePermit> {
        let mut counts = self
            .counts
            .lock()
            .expect("pending handshake counts poisoned");
        let from_ip = counts.per_ip.get(&ip).copied().unwrap_or(0);
        if counts.total >= self.max_total || from_ip >= self.max_per_ip {
            return None;
        }
        counts.total += 1;
        counts.per_ip.insert(ip, from_ip + 1);
        Some(PendingHandshakePermit {
            pending: self.clone(),
            ip,
        })
    }
}

impl Drop for PendingHandshakePermit {
    fn drop(&mut self) {
        let mut counts = self
            .pending
            .counts
            .lock()
            .expect("pending handshake counts poisoned");
        counts.total -= 1;
        if let Some(from_ip) = counts.per_ip.get_mut(&self.ip) {
            *from_ip -= 1;
            if *from_ip == 0 {
                counts.per_ip.remove(&self.ip);
            }
        }
    }
}

/// Counts established connections per identity and per capacity pool.
struct EstablishedConnections {
    limits: RpcServerLimits,
    counts: std::sync::Mutex<EstablishedCounts>,
}

#[derive(Default)]
struct EstablishedCounts {
    per_identity: HashMap<ClientIdentity, usize>,
    unreserved: usize,
    bound_clients: usize,
}

/// Why an established connection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionRefusal {
    IdentityFull,
    PoolFull(CapacityClass),
}

/// Holds one established-connection slot; dropping it releases the slot.
struct EstablishedPermit {
    connections: Arc<EstablishedConnections>,
    identity: ClientIdentity,
    class: CapacityClass,
}

impl EstablishedConnections {
    fn new(limits: RpcServerLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            counts: std::sync::Mutex::new(EstablishedCounts::default()),
        })
    }

    fn try_acquire(
        self: &Arc<Self>,
        identity: ClientIdentity,
        class: CapacityClass,
    ) -> Result<EstablishedPermit, ConnectionRefusal> {
        let mut counts = self.counts.lock().expect("connection counts poisoned");
        let of_identity = counts.per_identity.get(&identity).copied().unwrap_or(0);
        if of_identity >= self.limits.max_connections_per_identity {
            return Err(ConnectionRefusal::IdentityFull);
        }
        match class {
            CapacityClass::Node => {}
            CapacityClass::BoundClient => {
                if counts.bound_clients >= self.limits.max_bound_client_connections {
                    return Err(ConnectionRefusal::PoolFull(class));
                }
                counts.bound_clients += 1;
            }
            CapacityClass::Unreserved => {
                if counts.unreserved >= self.limits.max_connections {
                    return Err(ConnectionRefusal::PoolFull(class));
                }
                counts.unreserved += 1;
            }
        }
        counts
            .per_identity
            .insert(identity.clone(), of_identity + 1);
        Ok(EstablishedPermit {
            connections: self.clone(),
            identity,
            class,
        })
    }
}

impl Drop for EstablishedPermit {
    fn drop(&mut self) {
        let mut counts = self
            .connections
            .counts
            .lock()
            .expect("connection counts poisoned");
        match self.class {
            CapacityClass::Node => {}
            CapacityClass::BoundClient => counts.bound_clients -= 1,
            CapacityClass::Unreserved => counts.unreserved -= 1,
        }
        if let Some(of_identity) = counts.per_identity.get_mut(&self.identity) {
            *of_identity -= 1;
            if *of_identity == 0 {
                counts.per_identity.remove(&self.identity);
            }
        }
    }
}

/// What one connection is doing, as the RPC middleware observes it.
struct ConnectionActivity {
    calls_in_progress: AtomicUsize,
    live_subscriptions: AtomicUsize,
    last_call_started: std::sync::Mutex<Instant>,
}

impl ConnectionActivity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls_in_progress: AtomicUsize::new(0),
            live_subscriptions: AtomicUsize::new(0),
            last_call_started: std::sync::Mutex::new(Instant::now()),
        })
    }

    fn call_started(&self) {
        self.calls_in_progress.fetch_add(1, Ordering::SeqCst);
        *self
            .last_call_started
            .lock()
            .expect("connection activity poisoned") = Instant::now();
    }

    fn call_finished(&self, method: &str, response: &MethodResponse) {
        if response.is_success() {
            if response.is_subscription() {
                self.live_subscriptions.fetch_add(1, Ordering::SeqCst);
            } else if method.starts_with(UNSUBSCRIBE_METHOD_PREFIX) {
                let _ = self.live_subscriptions.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |live| live.checked_sub(1),
                );
            }
        }
        self.calls_in_progress.fetch_sub(1, Ordering::SeqCst);
    }

    /// How long until this connection may be idle, or `None` when it is idle now.
    fn remaining_until_idle(&self, idle_timeout: Duration) -> Option<Duration> {
        if self.calls_in_progress.load(Ordering::SeqCst) > 0
            || self.live_subscriptions.load(Ordering::SeqCst) > 0
        {
            return Some(idle_timeout);
        }
        let since = self
            .last_call_started
            .lock()
            .expect("connection activity poisoned")
            .elapsed();
        idle_timeout
            .checked_sub(since)
            .filter(|left| !left.is_zero())
    }
}

/// Every unsubscribe method of this crate's RPC traits carries this prefix.
const UNSUBSCRIBE_METHOD_PREFIX: &str = "unsub_";

/// RPC middleware that stamps call starts and ends and counts live subscriptions, so an idle
/// unreserved connection can be closed. A subscription counts as live from its successful
/// answer until the caller unsubscribes or the connection ends; a subscription the server
/// ends on its own therefore keeps its connection open, never the reverse.
#[derive(Clone)]
struct ActivityTracking<S> {
    inner: S,
    activity: Arc<ConnectionActivity>,
}

impl<S> RpcServiceT for ActivityTracking<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        let activity = self.activity.clone();
        async move {
            activity.call_started();
            let method = request.method_name().to_owned();
            let response = inner.call(request).await;
            activity.call_finished(&method, &response);
            response
        }
    }

    fn batch<'a>(&self, requests: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        let activity = self.activity.clone();
        async move {
            activity.call_started();
            let response = inner.batch(requests).await;
            activity.call_finished("", &response);
            response
        }
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        let inner = self.inner.clone();
        let activity = self.activity.clone();
        async move {
            activity.call_started();
            let response = inner.notification(notification).await;
            activity.call_finished("", &response);
            response
        }
    }
}

/// Resolves after stopping `handle` once `activity` has been idle for `idle_timeout`.
async fn close_when_idle(
    activity: Arc<ConnectionActivity>,
    idle_timeout: Duration,
    handle: ServerHandle,
) {
    while let Some(left) = activity.remaining_until_idle(idle_timeout) {
        tokio::time::sleep(left).await;
    }
    let _ = handle.stop();
}

/// Starts a JSON-RPC server, which listens for Websocket connections over TLS 1.3.
///
/// Connections are bounded before the handshake (in total and per source address, and in
/// time), and after it by the identity's capacity class and per identity. A caller whose
/// certificate `caller_identity` refuses is disconnected before any RPC module is built.
pub async fn start_coord<T: RPCServerConnection>(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    rpc_server_data: Arc<Mutex<T::Internal>>,
    limits: RpcServerLimits,
) -> Result<RPCServerHandle, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let tls_config = self_signed_certs::server_tls_config(cert_der, key_der)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&full_addr)
        .await
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;

    let pending = PendingHandshakes::new(&limits);
    let established = EstablishedConnections::new(limits);
    let server_config = ServerConfig::builder()
        .max_subscriptions_per_connection(limits.max_subscriptions_per_connection)
        .set_message_buffer_capacity(limits.message_buffer_capacity)
        .build();

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (tcp_stream, peer) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::warn!("Accept failed: {error}");
                            continue;
                        }
                    };
                    let Some(pending_permit) = pending.try_acquire(peer.ip()) else {
                        tracing::warn!("Too many pending TLS handshakes, closing connection from {peer}");
                        continue;
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let rpc_server_data = rpc_server_data.clone();
                    let established = established.clone();
                    let server_config = server_config.clone();
                    connections.spawn(async move {
                        let handshake = tokio::time::timeout(
                            limits.handshake_timeout,
                            tls_acceptor.accept(tcp_stream),
                        )
                        .await;
                        drop(pending_permit);
                        let tls_stream = match handshake {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                tracing::warn!("TLS handshake with {peer} failed: {error}");
                                return;
                            }
                            Err(_) => {
                                tracing::warn!("TLS handshake with {peer} timed out");
                                return;
                            }
                        };

                        let cert_der = match tls_stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|certificates| certificates.first())
                            .map(|certificate| certificate.to_vec())
                        {
                            Some(certificate) => certificate,
                            None => {
                                tracing::warn!("Client connected without a certificate, rejecting");
                                return;
                            }
                        };

                        let identity = match caller_identity(&cert_der) {
                            Ok(identity) => identity,
                            Err(error) => {
                                tracing::warn!("Refusing caller certificate from {peer}: {error}");
                                return;
                            }
                        };

                        let class = {
                            let internal = rpc_server_data.lock().await;
                            T::capacity_class(&internal, &identity)
                        };
                        let _established_permit =
                            match established.try_acquire(identity.clone(), class) {
                                Ok(permit) => permit,
                                Err(refusal) => {
                                    tracing::warn!(
                                        "Refusing connection from {peer}: {refusal:?}"
                                    );
                                    return;
                                }
                            };

                        let activity = ConnectionActivity::new();
                        let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();
                        let rpc_middleware = RpcServiceBuilder::new().layer_fn({
                            let activity = activity.clone();
                            move |inner| ActivityTracking {
                                inner,
                                activity: activity.clone(),
                            }
                        });
                        let rpc_service = Server::builder()
                            .set_config(server_config)
                            .set_rpc_middleware(rpc_middleware)
                            .to_service_builder()
                            .build(T::new(rpc_server_data, identity).into_rpc(), stop_handle);

                        let idle_handle = server_handle.clone();
                        let idle = async move {
                            match class {
                                CapacityClass::Unreserved => {
                                    close_when_idle(
                                        activity,
                                        limits.idle_timeout,
                                        idle_handle,
                                    )
                                    .await
                                }
                                CapacityClass::Node | CapacityClass::BoundClient => {
                                    std::future::pending::<()>().await
                                }
                            }
                        };
                        tokio::pin!(idle);

                        let serve = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                TowerToHyperService::new(rpc_service),
                            )
                            .with_upgrades();
                        tokio::select! {
                            result = serve => {
                                if let Err(error) = result {
                                    tracing::warn!("Connection error: {error}");
                                }
                            }
                            _ = &mut idle => {
                                tracing::debug!("Closing idle connection from {peer}");
                                return;
                            }
                        }
                        // Hyper finishes after upgrading the socket, while jsonrpsee continues
                        // the WebSocket in its own task. Keep the connection's permit owned by
                        // this task until that upgraded task ends or the connection idles out.
                        tokio::select! {
                            _ = server_handle.clone().stopped() => {}
                            _ = &mut idle => {
                                tracing::debug!("Closed idle connection from {peer}");
                                server_handle.stopped().await;
                            }
                        }
                    });
                }
            }
        }
        connections.shutdown().await;
    });

    Ok(RPCServerHandle {
        shutdown: Some(shutdown_tx),
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::test_certificates::{ed25519_certificate, p256_certificate, with_spki};
    use crate::pin::KeyAlgorithm;
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn a_caller_identity_is_derived_once_and_refuses_what_the_pin_refuses() {
        for certified in [p256_certificate(), ed25519_certificate()] {
            let der = certified.cert.der().to_vec();
            let (_, parsed) = X509Certificate::from_der(&der).unwrap();
            let identity = caller_identity(&der).unwrap();
            assert_eq!(
                identity,
                parsed.public_key().subject_public_key.data.to_vec()
            );
            assert_eq!(
                KeyAlgorithm::of_client_identity(&identity),
                Some(SpkiDer::from_certificate_der(&der).unwrap().key_algorithm())
            );

            let mut trailing = der.clone();
            trailing.push(0);
            assert_eq!(
                caller_identity(&trailing),
                Err(PinError::TrailingBytes { trailing: 1 })
            );
        }

        let p256 = p256_certificate();
        let der = p256.cert.der().to_vec();
        let point = p256.signing_key.public_key_raw().to_vec();
        let mut hybrid_spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut hybrid = point.clone();
        hybrid[0] = 0x06 | (point[64] & 1);
        hybrid_spki.extend_from_slice(&hybrid);
        assert_eq!(
            caller_identity(&with_spki(&der, &hybrid_spki)),
            Err(PinError::NonCanonicalPublicKey {
                algorithm: KeyAlgorithm::EcdsaP256
            })
        );
        let x25519_spki = [
            &[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
            ][..],
            &[5; 32],
        ]
        .concat();
        assert_eq!(
            caller_identity(&with_spki(&der, &x25519_spki)),
            Err(PinError::UnsupportedKeyAlgorithm {
                algorithm: "1.3.101.110".to_string()
            })
        );
    }

    fn limits() -> RpcServerLimits {
        RpcServerLimits {
            max_pending_handshakes: 3,
            max_pending_handshakes_per_ip: 2,
            max_connections: 4,
            max_bound_client_connections: 2,
            max_connections_per_identity: 2,
            ..RpcServerLimits::default()
        }
    }

    #[test]
    fn pending_handshakes_are_bounded_per_source_and_in_total() {
        let pending = PendingHandshakes::new(&limits());
        let first: IpAddr = "10.0.0.1".parse().unwrap();
        let second: IpAddr = "10.0.0.2".parse().unwrap();
        let third: IpAddr = "10.0.0.3".parse().unwrap();

        let a = pending.try_acquire(first).unwrap();
        let _b = pending.try_acquire(first).unwrap();
        assert!(
            pending.try_acquire(first).is_none(),
            "a third pending handshake from one address is refused"
        );
        let _c = pending.try_acquire(second).unwrap();
        assert!(
            pending.try_acquire(third).is_none(),
            "a fourth pending handshake from any address is refused"
        );
        drop(a);
        assert!(
            pending.try_acquire(third).is_some(),
            "a finished handshake frees its counts"
        );
    }

    #[test]
    fn established_connections_are_bounded_per_class_and_per_identity() {
        let established = EstablishedConnections::new(limits());
        let identity = |byte: u8| vec![byte; 65];

        let mut unreserved = (0..4)
            .map(|byte| {
                established
                    .try_acquire(identity(byte), CapacityClass::Unreserved)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            established
                .try_acquire(identity(9), CapacityClass::Unreserved)
                .err(),
            Some(ConnectionRefusal::PoolFull(CapacityClass::Unreserved))
        );

        let _bound = (10..12)
            .map(|byte| {
                established
                    .try_acquire(identity(byte), CapacityClass::BoundClient)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            established
                .try_acquire(identity(12), CapacityClass::BoundClient)
                .err(),
            Some(ConnectionRefusal::PoolFull(CapacityClass::BoundClient))
        );

        // Neither full pool touches what a node needs to connect.
        let node = identity(20);
        let _first = established
            .try_acquire(node.clone(), CapacityClass::Node)
            .unwrap();
        let _second = established
            .try_acquire(node.clone(), CapacityClass::Node)
            .unwrap();
        assert_eq!(
            established.try_acquire(node, CapacityClass::Node).err(),
            Some(ConnectionRefusal::IdentityFull)
        );

        unreserved.pop();
        assert!(established
            .try_acquire(identity(9), CapacityClass::Unreserved)
            .is_ok());
    }
}

/// A minimal RPC listener for this crate's transport tests.
#[cfg(test)]
pub(crate) mod probe {
    use super::*;
    use jsonrpsee::core::{async_trait, RpcResult, SubscriptionResult};
    use jsonrpsee::proc_macros::rpc;
    use jsonrpsee::PendingSubscriptionSink;

    #[rpc(server, client)]
    pub trait Probe {
        /// Answers with the caller identity the listener derived.
        #[method(name = "whoami")]
        async fn whoami(&self) -> RpcResult<Vec<u8>>;

        /// Accepts and keeps the subscription open without ever sending.
        #[subscription(name = "sub_silence", unsubscribe = "unsub_silence", item = u64)]
        async fn silence(&self) -> SubscriptionResult;
    }

    /// Identities `capacity_class` answers `Node` for.
    #[derive(Default)]
    pub struct ProbeState {
        pub nodes: Vec<ClientIdentity>,
        pub bound_clients: Vec<ClientIdentity>,
        pub parked: Vec<jsonrpsee::SubscriptionSink>,
    }

    pub struct ProbeConnection {
        state: Arc<Mutex<ProbeState>>,
        id: ClientIdentity,
    }

    impl RPCServerConnection for ProbeConnection {
        type Internal = ProbeState;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self {
                state: internal,
                id,
            }
        }

        fn into_rpc(self) -> RpcModule<Self> {
            ProbeServer::into_rpc(self)
        }

        fn capacity_class(internal: &Self::Internal, id: &ClientIdentity) -> CapacityClass {
            if internal.nodes.contains(id) {
                CapacityClass::Node
            } else if internal.bound_clients.contains(id) {
                CapacityClass::BoundClient
            } else {
                CapacityClass::Unreserved
            }
        }
    }

    #[async_trait]
    impl ProbeServer for ProbeConnection {
        async fn whoami(&self) -> RpcResult<Vec<u8>> {
            Ok(self.id.clone())
        }

        async fn silence(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
            let sink = pending.accept().await?;
            self.state.lock().await.parked.push(sink);
            Ok(())
        }
    }

    pub fn free_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    pub fn parts(certified: &rcgen::CertifiedKey<rcgen::KeyPair>) -> (Vec<u8>, Vec<u8>) {
        (
            certified.cert.der().to_vec(),
            certified.signing_key.serialize_der(),
        )
    }

    /// Starts a probe listener on a free port with `server`'s certificate.
    pub async fn start_probe(
        server: &rcgen::CertifiedKey<rcgen::KeyPair>,
        state: ProbeState,
        limits: RpcServerLimits,
    ) -> (RPCServerHandle, u16, Arc<Mutex<ProbeState>>) {
        crate::setup_test();
        let port = free_port();
        let state = Arc::new(Mutex::new(state));
        let (cert_der, key_der) = parts(server);
        let handle = start_coord::<ProbeConnection>(
            "127.0.0.1",
            port,
            cert_der,
            key_der,
            state.clone(),
            limits,
        )
        .await
        .unwrap();
        (handle, port, state)
    }
}

#[cfg(test)]
mod listener_tests {
    use super::probe::*;
    use super::*;
    use crate::pin::test_certificates::p256_certificate;
    use crate::pin::ServerPin;
    use crate::self_signed_certs::setup_client;
    use tokio::io::AsyncReadExt;

    fn pin_of(certified: &rcgen::CertifiedKey<rcgen::KeyPair>) -> ServerPin {
        ServerPin::Exact(SpkiDer::from_certificate_der(certified.cert.der()).unwrap())
    }

    /// Whether the listener closed a raw TCP connection that never starts a handshake.
    async fn closed_within(stream: &mut tokio::net::TcpStream, within: Duration) -> bool {
        let mut buf = [0u8; 1];
        matches!(
            tokio::time::timeout(within, stream.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    #[tokio::test]
    async fn the_listener_bounds_pending_handshakes_per_source_and_in_total() {
        let server = p256_certificate();
        let limits = RpcServerLimits {
            max_pending_handshakes_per_ip: 2,
            handshake_timeout: Duration::from_millis(600),
            ..RpcServerLimits::default()
        };
        let (_handle, port, _) = start_probe(&server, ProbeState::default(), limits).await;
        let address = ("127.0.0.1", port);

        let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut third = tokio::net::TcpStream::connect(address).await.unwrap();
        assert!(
            closed_within(&mut third, Duration::from_millis(300)).await,
            "a third stalled connection from one address is closed at once"
        );
        assert!(!closed_within(&mut first, Duration::from_millis(50)).await);

        // A stalled handshake is closed after `handshake_timeout` and frees its counts.
        assert!(closed_within(&mut first, Duration::from_secs(2)).await);
        assert!(closed_within(&mut second, Duration::from_secs(2)).await);
        let client = p256_certificate();
        let (cert_der, key_der) = parts(&client);
        let connected = setup_client("127.0.0.1", port, cert_der, key_der, &pin_of(&server))
            .await
            .expect("freed pending slots admit a new handshake");
        assert_eq!(
            ProbeClient::whoami(&connected.client).await.unwrap(),
            client.signing_key.public_key_raw().to_vec()
        );
    }

    #[tokio::test]
    async fn a_roster_node_connects_through_a_flood_of_unreserved_and_bound_connections() {
        let server = p256_certificate();
        let node = p256_certificate();
        let bound = [p256_certificate(), p256_certificate(), p256_certificate()];
        let state = ProbeState {
            nodes: vec![node.signing_key.public_key_raw().to_vec()],
            bound_clients: bound
                .iter()
                .map(|certified| certified.signing_key.public_key_raw().to_vec())
                .collect(),
            ..ProbeState::default()
        };
        let limits = RpcServerLimits {
            max_connections: 4,
            max_bound_client_connections: 2,
            ..RpcServerLimits::default()
        };
        let (_handle, port, _) = start_probe(&server, state, limits).await;
        let pin = pin_of(&server);
        let connect = |certified: &rcgen::CertifiedKey<rcgen::KeyPair>| {
            let (cert_der, key_der) = parts(certified);
            let pin = pin.clone();
            async move { setup_client("127.0.0.1", port, cert_der, key_der, &pin).await }
        };

        let mut flood = Vec::new();
        for _ in 0..4 {
            let connected = connect(&p256_certificate()).await.unwrap();
            ProbeClient::whoami(&connected.client).await.unwrap();
            flood.push(connected);
        }
        let refused = connect(&p256_certificate()).await;
        assert!(refused.is_err(), "the unreserved pool is full");

        for certified in &bound[..2] {
            let connected = connect(certified).await.unwrap();
            ProbeClient::whoami(&connected.client).await.unwrap();
            flood.push(connected);
        }
        assert!(
            connect(&bound[2]).await.is_err(),
            "the bound-client pool is full"
        );

        let mut stalled = Vec::new();
        for _ in 0..RpcServerLimits::default().max_pending_handshakes_per_ip - 1 {
            stalled.push(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap(),
            );
        }

        let node_connection = connect(&node).await.expect("a roster node still connects");
        assert_eq!(
            ProbeClient::whoami(&node_connection.client).await.unwrap(),
            node.signing_key.public_key_raw().to_vec()
        );
    }

    #[tokio::test]
    async fn connections_per_identity_are_bounded_and_idle_unreserved_ones_are_closed() {
        let server = p256_certificate();
        let node = p256_certificate();
        let state = ProbeState {
            nodes: vec![node.signing_key.public_key_raw().to_vec()],
            ..ProbeState::default()
        };
        let limits = RpcServerLimits {
            max_connections_per_identity: 2,
            idle_timeout: Duration::from_millis(400),
            ..RpcServerLimits::default()
        };
        let (_handle, port, _) = start_probe(&server, state, limits).await;
        let pin = pin_of(&server);
        let connect = |certified: &rcgen::CertifiedKey<rcgen::KeyPair>| {
            let (cert_der, key_der) = parts(certified);
            let pin = pin.clone();
            async move { setup_client("127.0.0.1", port, cert_der, key_der, &pin).await }
        };

        let repeated = p256_certificate();
        let first = connect(&repeated).await.unwrap();
        let second = connect(&repeated).await.unwrap();
        assert!(
            connect(&repeated).await.is_err(),
            "a third connection of one certificate is refused"
        );

        let subscribed = connect(&p256_certificate()).await.unwrap();
        let _subscription = ProbeClient::silence(&subscribed.client).await.unwrap();
        let node_connection = connect(&node).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(
            !first.client.is_connected() && !second.client.is_connected(),
            "unreserved connections that make no call are closed"
        );
        assert!(
            subscribed.client.is_connected(),
            "a connection with a live subscription is not idle"
        );
        assert!(
            node_connection.client.is_connected(),
            "a node's connection is never closed for idling"
        );
        ProbeClient::whoami(&node_connection.client).await.unwrap();

        // Closed connections released their identity's slots.
        let third = connect(&repeated).await.unwrap();
        ProbeClient::whoami(&third.client).await.unwrap();
    }
}
