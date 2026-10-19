//! TLS utilities for mutual TLS (mTLS) connections using self-signed certificates.
//!
//! Both sides of a connection authenticate with self-signed certificates, so there is no CA
//! chain to validate. A server accepts any client certificate whose handshake signature
//! verifies and authorizes each RPC on the derived caller identity. A client admits only a
//! server whose key its `ServerPin` names; there is no unpinned client. Every listener and
//! client speaks TLS 1.3 only.

use crate::pin::{ServerPin, SpkiDer};
use crate::roster::NodeRoster;
use crate::CoordinatorError;
use jsonrpsee::async_client::Client;
use jsonrpsee::client_transport::ws::WsTransportClientBuilder;
use jsonrpsee::core::client::ClientBuilder;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::ClientConfig;
use rustls::DistinguishedName;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Server-side verifier that accepts any self-signed client certificate.
///
/// Skips chain validation entirely; used when clients authenticate with
/// self-signed certs that have no CA anchor.
#[derive(Debug)]
pub struct SelfSignedClientVerifier;

/// Client-side verifier that admits exactly the server keys its pin names.
///
/// The identity is the key, exactly as it is for stoffelnet: `intermediates`, the server name
/// and the validity period are not consulted. The handshake signature is still verified
/// against the same end-entity certificate, which is what binds the connection to the pinned
/// key rather than to a copy of a public certificate. There is no constructor without a pin.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pin: ServerPin,
}

impl PinnedServerVerifier {
    pub fn new(pin: ServerPin) -> Self {
        Self { pin }
    }
}

/// A client connection whose server proved possession of a pinned key.
pub struct PinnedClient {
    pub client: Client,
    /// The key the server proved possession of in this handshake. Always admitted by the pin.
    pub server_spki: SpkiDer,
}

impl ClientCertVerifier for SelfSignedClientVerifier {
    /// Returns no CA hint subjects — chain validation is not performed.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Accepts any client certificate unconditionally.
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    /// Admits the end-entity certificate only when its key is canonical and pinned.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = SpkiDer::from_certificate_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if !self.pin.admits(&spki) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Generates a self-signed certificate for the server, valid for `localhost` and `127.0.0.1`.
pub fn server_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Generates a self-signed certificate for a client.
pub fn client_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["client".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Builds a TLS 1.3-only `rustls::ServerConfig` for mTLS using `SelfSignedClientVerifier`.
///
/// Clients must present a certificate, but chain validation is skipped: authorization is per
/// RPC, on the caller identity `rpc::caller_identity` derives.
pub fn server_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(Arc::new(SelfSignedClientVerifier {}))
        .with_single_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Builds a TLS 1.3-only `rustls::ClientConfig` for mTLS that admits only `pin`'s server keys.
fn client_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pin: &ServerPin,
) -> Result<ClientConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(pin.clone())))
        .with_client_auth_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Whether a TLS connect failure is the pin refusing the server's key.
fn is_pin_refusal(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|inner| {
            matches!(
                inner,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            )
        })
}

/// Connects to a remote WebSocket server over mTLS, admitting only a server that proves
/// possession of a key `pin` names.
///
/// A server presenting any other key is `CoordinatorError::ServerPinMismatch`, which callers
/// must not retry; every other failure is `ConnectError`.
pub async fn setup_client(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pin: &ServerPin,
) -> Result<PinnedClient, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let url = format!("wss://{}/", full_addr);
    let tls_config = client_tls_config(cert_der, key_der, pin)?;

    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let tcp_stream = TcpStream::connect(&full_addr)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;
    let domain = ServerName::try_from(addr)
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?
        .to_owned();
    let tls_stream = tls_connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|e| {
            if is_pin_refusal(&e) {
                CoordinatorError::ServerPinMismatch {
                    address: full_addr.clone(),
                }
            } else {
                CoordinatorError::ConnectError(e.to_string())
            }
        })?;

    // Re-derive the key from the certificate this handshake actually authenticated.
    let server_spki = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            CoordinatorError::ConnectError(format!("{full_addr} presented no certificate"))
        })
        .and_then(|certificate| Ok(SpkiDer::from_certificate_der(certificate.as_ref())?))?;
    if !pin.admits(&server_spki) {
        return Err(CoordinatorError::ServerPinMismatch { address: full_addr });
    }

    let (sender, receiver) = WsTransportClientBuilder::default()
        .build_with_stream(
            Url::parse(&url).map_err(|e| CoordinatorError::ConnectError(e.to_string()))?,
            tls_stream,
        )
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    Ok(PinnedClient {
        client: ClientBuilder::default().build_with_tokio(sender, receiver),
        server_spki,
    })
}

/// How long one node RPC leg may take to connect: TCP connect, the TLS handshake and the
/// WebSocket upgrade together.
pub const NODE_LEG_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One pinned node RPC connection and the roster position of the key that answered it.
pub struct RosterLeg {
    pub client: Client,
    pub position: usize,
}

/// Connects to every address in `addrs`, admitting only servers that prove possession of a key
/// in `roster`, and attributes each connection to the answering member's roster position.
///
/// Each address is connected concurrently under `connect_timeout`. A leg that cannot be
/// reached — refused, reset, failed handshake, or one that does not finish within
/// `connect_timeout` — is logged and dropped: up to `t` nodes may be offline or corrupt, and
/// reconstruction by position does not need them. A connection is refused outright, never
/// dropped, when it shows the address list itself is wrong:
///
/// - more addresses than the roster has nodes is `TooManyNodeAddresses`;
/// - an address presenting a key outside the roster is `ServerPinMismatch`;
/// - two addresses answering as one member is `DuplicateNodeIdentity`, since that member's
///   share would otherwise count twice.
///
/// Legs that fail are dropped, never fatal: unreachable, stalled, presenting a key the roster
/// pin does not admit, or duplicating a roster position already connected. Each node owns its
/// own listener, so any fatal case here would be a denial-of-service switch that one corrupt
/// roster member could throw at every client. Callers decide how many legs they need — the
/// share reconstruction downstream enforces that — and a caller wanting all `n` must compare
/// `legs.len()` itself.
///
/// When `addrs` is non-empty and no leg connects, the result is `ConnectError` naming every
/// failure. `TooManyNodeAddresses` remains fatal: that is the caller's own argument being
/// wrong, not a node misbehaving. The whole call takes at most `connect_timeout`.
pub async fn connect_roster_legs(
    roster: &NodeRoster,
    addrs: &[(String, u16)],
    cert_der: &[u8],
    key_der: &[u8],
    connect_timeout: Duration,
) -> Result<Vec<RosterLeg>, CoordinatorError> {
    if addrs.len() as u64 > roster.n() {
        return Err(CoordinatorError::TooManyNodeAddresses {
            given: addrs.len(),
            n: roster.n(),
        });
    }
    let pin = ServerPin::roster_node(roster);
    let attempts = futures_util::future::join_all(addrs.iter().map(|(addr, port)| {
        tokio::time::timeout(
            connect_timeout,
            setup_client(addr, *port, cert_der.to_vec(), key_der.to_vec(), &pin),
        )
    }))
    .await;

    let mut positions = HashSet::new();
    let mut legs = Vec::with_capacity(attempts.len());
    let mut failures = Vec::new();
    for ((addr, port), attempt) in addrs.iter().zip(attempts) {
        let address = format!("{addr}:{port}");
        let connection = match attempt {
            Ok(Ok(connection)) => connection,
            // A node controls its own listener, so presenting a key the roster pin does not
            // admit is something ONE corrupt or misconfigured node can do at will. Failing
            // the whole call here would hand any single roster member a denial-of-service
            // switch over every client. Drop the leg instead, exactly like an unreachable
            // one: the pin still refuses the impostor, it simply costs that node its leg
            // rather than the client's run.
            Ok(Err(refusal @ CoordinatorError::ServerPinMismatch { .. })) => {
                tracing::warn!(
                    %address,
                    error = %refusal,
                    "node RPC leg presented a key outside the roster; dropping it"
                );
                failures.push(format!("{address}: {refusal}"));
                continue;
            }
            Ok(Err(error)) => {
                tracing::warn!(%address, %error, "node RPC leg is unreachable; dropping it");
                failures.push(format!("{address}: {error}"));
                continue;
            }
            Err(_elapsed) => {
                tracing::warn!(
                    %address,
                    timeout = ?connect_timeout,
                    "node RPC leg did not connect in time; dropping it"
                );
                failures.push(format!(
                    "{address}: did not connect within {connect_timeout:?}"
                ));
                continue;
            }
        };
        let position = roster
            .position_of(&connection.server_spki)
            .expect("a roster pin only admits roster members");
        if !positions.insert(position) {
            // Same reasoning as the pin mismatch above: two addresses answering as the same
            // roster member is a misconfiguration or a corrupt node, and the second one is
            // redundant rather than fatal. Keep the leg already established and drop this one.
            tracing::warn!(
                %address,
                position,
                "a second address answered as an already-connected roster member; dropping it"
            );
            failures.push(format!(
                "{address}: duplicate of roster position {position}"
            ));
            continue;
        }
        legs.push(RosterLeg {
            client: connection.client,
            position,
        });
    }

    if legs.is_empty() && !failures.is_empty() {
        return Err(CoordinatorError::ConnectError(format!(
            "no node RPC leg connected: {}",
            failures.join("; ")
        )));
    }
    Ok(legs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::test_certificates::p256_certificate;
    use crate::roster::NodeCertificateDer;
    use crate::rpc::probe::{free_port, parts, start_probe, ProbeClient, ProbeState};
    use crate::rpc::RpcServerLimits;
    use tokio_rustls::TlsAcceptor;

    fn exact_pin(certified: &rcgen::CertifiedKey<rcgen::KeyPair>) -> ServerPin {
        ServerPin::Exact(SpkiDer::from_certificate_der(certified.cert.der()).unwrap())
    }

    #[tokio::test]
    async fn a_pinned_client_reaches_the_pinned_server() {
        let server = p256_certificate();
        let (_handle, port, _) =
            start_probe(&server, ProbeState::default(), RpcServerLimits::default()).await;
        let client = p256_certificate();
        let (cert_der, key_der) = parts(&client);
        let connected = setup_client("127.0.0.1", port, cert_der, key_der, &exact_pin(&server))
            .await
            .unwrap();
        assert_eq!(
            connected.server_spki,
            SpkiDer::from_certificate_der(server.cert.der()).unwrap()
        );
        assert_eq!(
            ProbeClient::whoami(&connected.client).await.unwrap(),
            client.signing_key.public_key_raw().to_vec()
        );
    }

    #[tokio::test]
    async fn a_pinned_client_refuses_a_server_presenting_another_key() {
        let server = p256_certificate();
        let (_handle, port, _) =
            start_probe(&server, ProbeState::default(), RpcServerLimits::default()).await;
        let (cert_der, key_der) = parts(&p256_certificate());
        let impostor_pin = exact_pin(&p256_certificate());
        let refused = setup_client("127.0.0.1", port, cert_der, key_der, &impostor_pin).await;
        assert!(
            matches!(
                refused,
                Err(CoordinatorError::ServerPinMismatch { ref address })
                    if *address == format!("127.0.0.1:{port}")
            ),
            "expected ServerPinMismatch, got {:?}",
            refused.err()
        );

        // No server at all is a connect error, not a pin mismatch.
        let (cert_der, key_der) = parts(&p256_certificate());
        let absent = setup_client("127.0.0.1", free_port(), cert_der, key_der, &impostor_pin).await;
        assert!(matches!(absent, Err(CoordinatorError::ConnectError(_))));
    }

    #[tokio::test]
    async fn a_roster_node_pin_reports_which_member_answered() {
        let members = [p256_certificate(), p256_certificate(), p256_certificate()];
        let roster = NodeRoster::new(
            1,
            members
                .iter()
                .map(|certified| NodeCertificateDer::from_der(certified.cert.der().to_vec()))
                .collect(),
        )
        .unwrap();
        let pin = ServerPin::roster_node(&roster);

        let (_first, first_port, _) = start_probe(
            &members[2],
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (_second, second_port, _) = start_probe(
            &members[0],
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (_outsider, outsider_port, _) = start_probe(
            &p256_certificate(),
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;

        let client = p256_certificate();
        for (port, member) in [(first_port, &members[2]), (second_port, &members[0])] {
            let (cert_der, key_der) = parts(&client);
            let connected = setup_client("127.0.0.1", port, cert_der, key_der, &pin)
                .await
                .unwrap();
            let expected = SpkiDer::from_certificate_der(member.cert.der()).unwrap();
            assert_eq!(connected.server_spki, expected);
            assert!(roster.position_of(&connected.server_spki).is_some());
        }
        let (cert_der, key_der) = parts(&client);
        assert!(matches!(
            setup_client("127.0.0.1", outsider_port, cert_der, key_der, &pin).await,
            Err(CoordinatorError::ServerPinMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn every_listener_and_client_is_tls13_only() {
        let server = p256_certificate();
        let (_handle, port, _) =
            start_probe(&server, ProbeState::default(), RpcServerLimits::default()).await;

        // A client restricted to TLS 1.2 fails the handshake with the listener.
        let client = p256_certificate();
        let (cert_der, key_der) = parts(&client);
        let tls12_client = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(exact_pin(
                &server,
            ))))
            .with_client_auth_cert(
                vec![CertificateDer::from(cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
            )
            .unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let handshake = TlsConnector::from(Arc::new(tls12_client))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await;
        assert!(handshake.is_err(), "a TLS 1.2-only client must not connect");

        // `setup_client` refuses a TLS 1.2-only server.
        let tls12_port = free_port();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", tls12_port))
            .await
            .unwrap();
        let (server_cert, server_key) = parts(&server);
        let tls12_server =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_client_cert_verifier(Arc::new(SelfSignedClientVerifier {}))
                .with_single_cert(
                    vec![CertificateDer::from(server_cert)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key)),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls12_server));
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await.is_err()
        });
        let refused = setup_client(
            "127.0.0.1",
            tls12_port,
            cert_der,
            key_der,
            &exact_pin(&server),
        )
        .await;
        assert!(matches!(refused, Err(CoordinatorError::ConnectError(_))));
        assert!(
            accept.await.unwrap(),
            "the TLS 1.2 server saw a failed handshake"
        );
    }

    fn roster_of(t: u64, members: &[rcgen::CertifiedKey<rcgen::KeyPair>]) -> NodeRoster {
        NodeRoster::new(
            t,
            members
                .iter()
                .map(|certified| NodeCertificateDer::from_der(certified.cert.der().to_vec()))
                .collect(),
        )
        .unwrap()
    }

    /// A listener that accepts TCP connections and never answers the TLS handshake.
    async fn start_stalled_listener() -> (tokio::task::JoinHandle<()>, u16) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (task, port)
    }

    #[tokio::test]
    async fn roster_legs_drop_unreachable_and_stalled_nodes_within_the_timeout() {
        let members = [
            p256_certificate(),
            p256_certificate(),
            p256_certificate(),
            p256_certificate(),
        ];
        let roster = roster_of(1, &members);
        let (_second, second_port, _) = start_probe(
            &members[1],
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (_fourth, fourth_port, _) = start_probe(
            &members[3],
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (stalled, stalled_port) = start_stalled_listener().await;
        let addrs = [free_port(), stalled_port, second_port, fourth_port]
            .into_iter()
            .map(|port| ("127.0.0.1".to_string(), port))
            .collect::<Vec<_>>();

        let (cert_der, key_der) = parts(&p256_certificate());
        let connect_timeout = Duration::from_millis(500);
        let started = std::time::Instant::now();
        let legs = tokio::time::timeout(
            Duration::from_secs(10),
            connect_roster_legs(&roster, &addrs, &cert_der, &key_der, connect_timeout),
        )
        .await
        .expect("a stalled handshake must not hold the constructor past its connect timeout")
        .expect("unreachable and stalled legs are dropped, not fatal");
        assert!(started.elapsed() < Duration::from_secs(5));
        // Roster positions follow the roster's canonical order, not `members`' order.
        let position_of = |member: &rcgen::CertifiedKey<rcgen::KeyPair>| {
            roster
                .position_of(&SpkiDer::from_certificate_der(member.cert.der()).unwrap())
                .unwrap()
        };
        assert_eq!(
            legs.iter().map(|leg| leg.position).collect::<Vec<_>>(),
            vec![position_of(&members[1]), position_of(&members[3])]
        );
        for leg in &legs {
            assert!(ProbeClient::whoami(&leg.client).await.is_ok());
        }
        stalled.abort();
    }

    #[tokio::test]
    async fn roster_legs_drop_impostor_and_duplicate_legs_instead_of_failing_the_client() {
        let members = [p256_certificate(), p256_certificate(), p256_certificate()];
        let roster = roster_of(1, &members);
        let (_member, member_port, _) = start_probe(
            &members[0],
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (_outsider, outsider_port, _) = start_probe(
            &p256_certificate(),
            ProbeState::default(),
            RpcServerLimits::default(),
        )
        .await;
        let (cert_der, key_der) = parts(&p256_certificate());
        let timeout = Duration::from_secs(5);
        let addrs_of = |ports: &[u16]| {
            ports
                .iter()
                .map(|port| ("127.0.0.1".to_string(), *port))
                .collect::<Vec<_>>()
        };

        let outsider = connect_roster_legs(
            &roster,
            &addrs_of(&[free_port(), member_port, outsider_port]),
            &cert_der,
            &key_der,
            timeout,
        )
        .await;
        // The impostor costs itself its leg; the genuine member's leg survives. If this
        // returned Err, one corrupt node could deny every client its connection.
        let outsider = outsider.expect("an impostor leg is dropped, not fatal");
        assert_eq!(
            outsider.iter().map(|leg| leg.position).collect::<Vec<_>>(),
            vec![roster
                .position_of(&SpkiDer::from_certificate_der(members[0].cert.der()).unwrap())
                .unwrap()],
            "only the roster member's leg is kept"
        );
        assert!(ProbeClient::whoami(&outsider[0].client).await.is_ok());

        let duplicated = connect_roster_legs(
            &roster,
            &addrs_of(&[free_port(), member_port, member_port]),
            &cert_der,
            &key_der,
            timeout,
        )
        .await;
        let duplicated = duplicated.expect("a duplicate leg is dropped, not fatal");
        assert_eq!(
            duplicated.len(),
            1,
            "the same roster member answering twice yields one leg, not an error"
        );

        let too_many = connect_roster_legs(
            &roster,
            &addrs_of(&[member_port, free_port(), free_port(), free_port()]),
            &cert_der,
            &key_der,
            timeout,
        )
        .await;
        assert!(matches!(
            too_many,
            Err(CoordinatorError::TooManyNodeAddresses { given: 4, n: 3 })
        ));

        let (dead, also_dead) = (free_port(), free_port());
        let none = connect_roster_legs(
            &roster,
            &addrs_of(&[dead, also_dead]),
            &cert_der,
            &key_der,
            timeout,
        )
        .await;
        match none {
            Err(CoordinatorError::ConnectError(message)) => {
                assert!(message.contains(&format!("127.0.0.1:{dead}")));
                assert!(message.contains(&format!("127.0.0.1:{also_dead}")));
            }
            other => panic!("no reachable leg is a ConnectError, got {:?}", other.err()),
        }

        assert!(
            connect_roster_legs(&roster, &[], &cert_der, &key_der, timeout)
                .await
                .unwrap()
                .is_empty(),
            "an empty address list connects no legs without failing"
        );
    }
}
