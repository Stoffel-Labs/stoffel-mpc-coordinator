use std::future::Future;
use ark_bls12_381::Fr;
use thiserror::Error;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::sync::Once;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

static INIT: Once = Once::new();
fn setup_test() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}

mod self_signed_certs {
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::UnixTime;
    use rustls::pki_types::ServerName;
    use rustls::server::danger::{ClientCertVerifier, ClientCertVerified};
    use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
    use rustls::DistinguishedName;
    use std::sync::Arc;
    use jsonrpsee::client_transport::ws::WsTransportClientBuilder;
    use jsonrpsee::core::client::ClientBuilder;
    use url::Url;
    use jsonrpsee::async_client::Client;
    use rustls::ClientConfig;
    use tokio_rustls::TlsConnector;
    use tokio::net::TcpStream;

    #[derive(Debug)]
    pub struct SelfSignedClientVerifier;

    #[derive(Debug)]
    pub struct SelfSignedServerVerifier;

    impl ClientCertVerifier for SelfSignedClientVerifier {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }
    
        fn verify_client_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
    
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
    
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    impl ServerCertVerifier for SelfSignedServerVerifier {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
    
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
    
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    pub fn server_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

        Arc::new(rcgen::generate_simple_self_signed(subject_alt_names).unwrap())
    }

    pub fn client_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
        let subject_alt_names = vec!["client".to_string()];

        Arc::new(rcgen::generate_simple_self_signed(subject_alt_names).unwrap())
    }

    pub fn server_tls_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> rustls::ServerConfig {
        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(SelfSignedClientVerifier {}))
            .with_single_cert(certs, key).unwrap()
    }

    fn client_tls_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> ClientConfig {
        let certs = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(certs, key).unwrap()
    }

    pub async fn setup_client(addr: &str, port: u16, cert_der: Vec<u8>, key_der: Vec<u8>) -> Client {
        let full_addr = format!("{}:{}", addr, port);
        let url = format!("wss://{}/", full_addr);
        let mut tls_config = client_tls_config(cert_der, key_der);
        tls_config.dangerous().set_certificate_verifier(Arc::new(SelfSignedServerVerifier {}));

        let tls_connector = TlsConnector::from(Arc::new(tls_config));
        let tcp_stream = TcpStream::connect(full_addr).await.unwrap();
        let domain = ServerName::try_from(addr).unwrap().to_owned();
        let tls_stream = tls_connector.connect(domain, tcp_stream).await.unwrap();
        
        let (sender, receiver) = WsTransportClientBuilder::default()
            .build_with_stream(Url::parse(&url).unwrap(), tls_stream)
            .await.unwrap();

        ClientBuilder::default()
            .build_with_tokio(sender, receiver)
    }
}

pub mod rpc {
    use serde::{Serialize, Serializer, Deserialize, Deserializer};
    use ark_ff::FftField;
    use ark_serialize::{Compress, Validate};
    use std::sync::Arc;
    use tokio::task::JoinHandle;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use x509_parser::prelude::*;
    use jsonrpsee::{server::{RpcModule, Server}, server::ServerHandle};
    use tokio::sync::{Mutex, Barrier};
    use hyper_util::service::TowerToHyperService;
    use hyper_util::rt::TokioIo;

    #[derive(Clone, Debug)]
    pub struct FieldElement<T: FftField> {
        pub value: T
    }
    
    impl<'d, T: FftField> Deserialize<'d> for FieldElement<T> {
        fn deserialize<D>(deserializer: D) -> Result<FieldElement<T>, D::Error>
        where
            D: Deserializer<'d>
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            T::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
                .map(|value| FieldElement::<T> { value }).map_err(serde::de::Error::custom)
        }
    }
    
    impl<T: FftField> Serialize for FieldElement<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            self.value.serialize_with_mode(&mut bytes, Compress::Yes)
                .map_err(serde::ser::Error::custom)?;
            
            serializer.serialize_bytes(&bytes)
        }
    }

    pub struct ClientInfo {
        pub cert: Vec<u8>,
        pub thread: JoinHandle<()>,
        pub stop_tx: ServerHandle
    }

    pub trait RPCServerInternal {
        fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle);
    }

    pub trait RPCServerImpl {
        type Internal : RPCServerInternal + 'static + Send;
        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self;
        fn into_rpc(self) -> RpcModule<Self> where Self: Sized;
    }

    pub async fn start_coord<T: RPCServerImpl>(addr: &str, port: u16, cert_der: Vec<u8>, key_der: Vec<u8>, rpc_server_data: Arc<Mutex<T::Internal>>) -> JoinHandle<()> {
        let full_addr = format!("{}:{}", addr, port);
        let tls_config = crate::self_signed_certs::server_tls_config(cert_der, key_der);
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(full_addr).await.unwrap();

        tokio::spawn({
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
                    Err(e) => { eprintln!("Handshake failed: {}", e); return; }
                };
            
                let (stop_rx, stop_tx) = jsonrpsee::server::stop_channel();
                let cert_der = 
                    tls_stream.get_ref().1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .map(|c| c.to_vec())
                        .expect("Client certificate required");

                let (_remainder, parsed_cert) = X509Certificate::from_der(&cert_der)
                    .expect("Failed to parse X.509 certificate DER");
                let public_key = parsed_cert.public_key()
                    .subject_public_key.data.as_ref();

                let rpc_server = T::new(rpc_server_data.clone(), public_key.to_vec());
                let mut rpc_module = RpcModule::new(());
                rpc_module.merge(rpc_server.into_rpc()).unwrap();
                let rpc_service = Server::builder()
                    .to_service_builder()
                    .build(rpc_module, stop_rx);

                // Barrier needed, since we start the client thread but only add the client
                // info afterwards; client info is accessible to the JSON-RPC methods, so if a
                // request comes in after starting the client thread but before adding the
                // client info, we may have a problem.
                let barrier = Arc::new(Barrier::new(2));
                let client_handle = tokio::spawn({
                    let barrier = barrier.clone(); async move {
                    barrier.wait().await;
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls_stream), TowerToHyperService::new(rpc_service))
                        .with_upgrades()
                        .await {
                        eprintln!("Connection error: {}", e);
                    }
                }});

                rpc_server_data.lock().await.add_client(cert_der, client_handle, stop_tx);
                barrier.clone().wait().await;
            }}
        })
    }
}

pub trait Coordinator {
    type ClientIdentity;

    fn trigger_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn init_input_masks(&mut self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input_mask_init(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn obtain_mask_indices(&mut self, n_indices: u64) -> impl Future<Output = Result<Vec<u64>, CoordinatorError>>;
    fn send_masked_input(&self, masked_input: Fr, i: u64) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_inputs(&self, n_clients: u64, mask_shares: Vec<RobustShare<Fr>>) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<RobustShare<Fr>>>, CoordinatorError>>;
    fn trigger_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_indices(&self, n_clients: u64) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, u64>, CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<Fr>, CoordinatorError>>;
    fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<Fr>>) -> impl Future<Output = Result<(), CoordinatorError>>;
}

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorError {
    #[error("The index {0:?} is already reserved.")]
    IndexAlreadyReserved(usize),
    #[error("The masked input for index {0:?} has already been sent.")]
    MaskedInputAlreadySent(usize),
}

pub mod on_chain {
    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, BigInteger};
    use alloy::{
        sol_types::SolValue,
        providers::{Provider, ProviderBuilder, WsConnect},
        signers::local::PrivateKeySigner,
        network::EthereumWallet,
        signers::Signer
    };
    use alloy_primitives::{U256, Address, Signature, Bytes, Keccak256};
    use stoffel_solidity_bindings::{
        fake_coordinator::FakeCoordinator::{InputMaskReservationStarted, MaskedInputEvent, ReservedInputEvent, EnoughPrivateOutputShares },
        fake_coordinator::FakeCoordinator::FakeCoordinatorInstance,
        fake_coordinator::FakeCoordinator,
        fake_coordinator::FakeCoordinator::FakeCoordinatorErrors
    };
    use futures_util::stream::StreamExt;
    use std::collections::HashMap;
    use std::str::FromStr;
    use super::{Coordinator, CoordinatorError};
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use stoffelmpc_mpc::common::SecretSharingScheme;
    use hpke::{
        aead::AesGcm256, 
        kdf::HkdfSha256, 
        kem::{DhP256HkdfSha256, Kem},
        single_shot_open, single_shot_seal, 
        Deserializable, Serializable,
        HpkeError, OpModeR, OpModeS,
    };
    use p256::{SecretKey, pkcs8::DecodePrivateKey};
    use rand::{SeedableRng, rngs::StdRng};
    use ark_serialize::CanonicalSerialize;

    type KemImpl = DhP256HkdfSha256;
    type KdfImpl = HkdfSha256;
    type AeadImpl = AesGcm256;

    type ClientIdentity = Address;
    
    #[derive(Clone)]
    pub struct OnChainCoordinator<P: Provider + WalletProvider + Clone> {
        coord: FakeCoordinatorInstance<P>,
        contract_block: u64,
        t: u64,
        n_outputs: Option<u64>,
        key_der: Option<Vec<u8>>
    }

    pub mod node_rpc {
        use ark_bls12_381::Fr;
        use alloy::providers::{WalletProvider, Provider};
        use alloy_primitives::{Address, Bytes};
        use stoffel_solidity_bindings::{
            fake_coordinator::FakeCoordinator::FakeCoordinatorInstance,
        };
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        use jsonrpsee::{core::{SubscriptionResult, to_json_raw_value}, async_client::Client, server::RpcModule, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::ServerHandle};
        use async_trait::async_trait;
        use tokio::task::JoinHandle;
        use super::ClientIdentity;
        use crate::rpc::ClientInfo;
        use tokio::task::JoinSet;
        use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
        use stoffelmpc_mpc::common::SecretSharingScheme;
        use ark_serialize::CanonicalSerialize;

        pub struct NodeRPCServer<P: Provider + WalletProvider + Clone> {
            rpc_server: Arc<Mutex<NodeRPCServerInternal<P>>>,
            addr: String,
            port: u16,
            server_handle: JoinHandle<()>,
        }

        pub struct NodeRPCClient {
            node_rpcs: Vec<Client>,
            t: usize
        }

        impl NodeRPCClient {
            pub async fn start_rpc_client_from_cert(t: usize, addrs: Vec<(String, u16)>, client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
                Self::start_rpc_client(t, addrs, client_cert.cert.der().to_vec(), client_cert.signing_key.serialize_der()).await
            }

            pub async fn start_rpc_client(t: usize, addrs: Vec<(String, u16)>, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
                let mut node_rpcs = Vec::new();

                // connect to all nodes
                for (addr, port) in addrs.iter() {
                    let node_rpc = crate::self_signed_certs::setup_client(addr, *port, cert_der.clone(), key_der.clone()).await;
                    node_rpcs.push(node_rpc);
                }

                Self {
                    node_rpcs,
                    t
                }
            }

            pub async fn receive_mask_share(&self, sig: Vec<u8>, addr: Address) -> Fr {
                let mut share_futures = JoinSet::new();

                for rpc in self.node_rpcs.iter() {
                    let mut sub = rpc.receive_mask_share(sig.clone(), addr).await.unwrap();
                    share_futures.spawn(async move { sub.next().await });
                }

                let mut mask_shares = Vec::new();

                while let Some(share_bytes) = share_futures.join_next().await {
                    let share = ark_serialize::CanonicalDeserialize::deserialize_compressed(share_bytes.unwrap().unwrap().unwrap().as_slice()).unwrap();
                    mask_shares.push(share);

                    if mask_shares.len() >= 2 * self.t + 1 {
                        match RobustShare::recover_secret(&mask_shares, 4 * self.t + 1) {
                            Ok((_, mask)) => {
                                return mask;
                            }
                            Err(_) => {
                                panic!("reconstruction of mask failed");
                            }
                        }
                    }
                }

                panic!("mask could not be reconstructed");
            }
        }

        impl<P: Provider + WalletProvider + Clone + 'static> NodeRPCServer<P> {
            pub async fn start_from_cert(addr: &str, port: u16, coord: FakeCoordinatorInstance<P>, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
                Self::start(addr, port, coord, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
            }

            pub async fn start(addr: &str, port: u16, coord: FakeCoordinatorInstance<P>, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
                let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::new(coord)));
                let server_handle = crate::rpc::start_coord::<NodeRPCServerImpl<P>>(addr, port, cert_der, key_der, rpc_server_data.clone()).await;
                Self {
                    rpc_server: rpc_server_data,
                    addr: String::from(addr),
                    port,
                    server_handle
                }
            }

            pub fn get_addr(&self) -> String {
                self.addr.clone()
            }

            pub async fn add_auth_status(&mut self, addr: Address, status: bool) {
                let mut d = self.rpc_server.lock().await;

                assert!(!d.auth_status.contains_key(&addr));
                d.auth_status.insert(addr, status);

                if !status {
                    panic!();
                }

                if let Some(i) = d.client_to_index.get(&addr) {
                    if let Some(status) = d.auth_status.get(&addr) {
                        if !status {
                            panic!();
                        }
                        if let Some(share) = d.mask_shares.get(i) {
                            if let Some(sink) = d.sinks.get(&addr) {
                                let mut share_bytes = Vec::new();
                                share.serialize_compressed(&mut share_bytes).unwrap();
                                let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                                match sink.send(json).await {
                                    Ok(_) => { },
                                    Err(_) => {
                                        println!("Client {} disconnected, either true error or already reconstructed input masks", addr);
                                    }
                                };
                            }
                        }
                    }
                }
            }

            // called when the client has reserved indices at the coordinator
            pub async fn add_reserved_index(&mut self, addr: ClientIdentity, i: u64) {
                let mut d = self.rpc_server.lock().await;

                assert!(!d.index_to_client.contains_key(&i));
                d.index_to_client.insert(i, addr);
                d.client_to_index.insert(addr, i);

                if let Some(status) = d.auth_status.get(&addr) {
                    if !status {
                        panic!();
                    }
                    if let Some(share) = d.mask_shares.get(&i) {
                        if let Some(sink) = d.sinks.get(&addr) {
                            let mut share_bytes = Vec::new();
                            share.serialize_compressed(&mut share_bytes).unwrap();
                            let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                            match sink.send(json).await {
                                Ok(_) => { },
                                Err(_) => {
                                    println!("Client {} disconnected, either true error or already reconstructed input masks", addr);
                                }
                            };
                        }
                    }
                }
            }
            
            // called when preprocessing has generated the mask shares
            pub async fn add_mask_share(&mut self, i: u64, share: RobustShare<Fr>) {
                let mut d = self.rpc_server.lock().await;

                assert!(!d.mask_shares.contains_key(&i));
                d.mask_shares.insert(i, share.clone());

                if let Some(addr) = d.index_to_client.get(&i) {
                    if let Some(status) = d.auth_status.get(addr) {
                        if !status {
                            panic!();
                        }
                    }
                    if let Some(sink) = d.sinks.get(addr) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).unwrap();
                        let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                        match sink.send(json).await {
                            Ok(_) => { },
                            Err(_) => {
                                println!("Client {} disconnected, either true error or already reconstructed input masks", addr);
                            }
                        };
                    }
                }
            }
        }

        pub struct NodeRPCServerImpl<P: Provider + WalletProvider + Clone> {
            d: Arc<Mutex<NodeRPCServerInternal<P>>>,
            id: Vec<u8>
        }

        impl<P: Provider + WalletProvider + Clone + 'static> crate::rpc::RPCServerImpl for NodeRPCServerImpl<P> {
            type Internal = NodeRPCServerInternal<P>;

            fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
                Self { d: internal, id }
            }

            fn into_rpc(self) -> RpcModule<Self> where Self: Sized {
                crate::on_chain::node_rpc::OnChainNodeRPCServer::into_rpc(self)
            }
        }

        pub struct NodeRPCServerInternal<P: Provider + WalletProvider + Clone> {
            index_to_client: HashMap<u64, ClientIdentity>,
            client_to_index: HashMap<ClientIdentity, u64>,
            auth_status: HashMap<ClientIdentity, bool>,
            sinks: HashMap<ClientIdentity, SubscriptionSink>,
            mask_shares: HashMap<u64, RobustShare<Fr>>,
            id_to_addr: HashMap<Vec<u8>, ClientIdentity>,
            clients: HashMap<Vec<u8>, ClientInfo>,
            coord: FakeCoordinatorInstance<P>
        }

        impl<P: Provider + WalletProvider + Clone> NodeRPCServerInternal<P> {
            pub fn new(coord: FakeCoordinatorInstance<P>) -> Self {
                Self {
                    index_to_client: HashMap::new(),
                    client_to_index: HashMap::new(),
                    auth_status: HashMap::new(),
                    sinks: HashMap::new(),
                    mask_shares: HashMap::new(),
                    id_to_addr: HashMap::new(),
                    clients: HashMap::new(),
                    coord
                }
            }
        }

        impl<P: Provider + WalletProvider + Clone> crate::rpc::RPCServerInternal for NodeRPCServerInternal<P> {
            fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle) {
                self.clients.insert(cert_der.clone(), ClientInfo { cert: cert_der, thread: client_handle, stop_tx });
            }
        }

        #[rpc(server, client)]
        pub trait OnChainNodeRPC {
            #[subscription(name = "sub_receive_mask_share", unsubscribe = "unsub_receive_mask_share", item = Vec<u8>)]
            async fn receive_mask_share(&self, sig: Vec<u8>, addr: Address) -> SubscriptionResult;
        }

        #[async_trait]
        impl<P: Provider + WalletProvider + Clone + 'static> OnChainNodeRPCServer for NodeRPCServerImpl<P> {
            async fn receive_mask_share(&self, pending: PendingSubscriptionSink, sig: Vec<u8>, addr: Address) -> SubscriptionResult {
                let sink = pending.accept().await?;

                let mut d = self.d.lock().await;

                // each address can only be used by once client
                if d.sinks.contains_key(&addr) {
                    panic!();
                }

                d.sinks.insert(addr, sink);

                // each client can only request shares once
                if d.id_to_addr.contains_key(&self.id) {
                    panic!();
                }

                // address needs to reserve index before requesting shares, so the contract knows
                // what message the signature signs, since the signed nonce is index-dependent
                match d.auth_status.get(&addr) {
                    Some(false) => { panic!(); }
                    Some(true) => {
                        // enough signatures were sent to authenticate the client, no need to send more;
                        // can send the share immediately if available
                        if let Some(i) = d.client_to_index.get(&addr) {
                            if let Some(share) = d.mask_shares.get(i) {
                                let mut share_bytes = Vec::new();
                                share.serialize_compressed(&mut share_bytes).unwrap();
                                let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                                match d.sinks.get(&addr).unwrap().send(json).await {
                                    Ok(_) => { },
                                    Err(_) => {
                                        println!("Client {} disconnected, either true error or already reconstructed input masks", addr);
                                    }
                                };
                            }
                        }
                    }
                    None => {
                        // client not authenticated yet, send signature to coordinator
                        d.coord.authenticateClient(addr, Bytes::from(sig)).send().await.expect("sending TX failed")
                            .watch().await.expect("TX failed");
                    }
                }

                Ok(())
            }
        }
    }

    fn u256_to_u64(x: U256) -> Option<u64> {
        x.try_into().ok()
    }

    // lossless: Fr elements always fit into 256 bits
    fn fr_to_u256(x: Fr) -> U256 {
        let bytes = x.into_bigint().to_bytes_le();
        U256::from_le_slice(&bytes)
    }
    
    fn u256_to_fr(x: U256) -> Option<Fr> {
        let r = {
            let r = <Fr as PrimeField>::MODULUS;
            let r_bytes = r.to_bytes_le();
            U256::from_le_slice(&r_bytes)
        };
    
        if x >= r {
            return None;
        }
    
        let bytes = x.to_le_bytes::<32>();
        Some(Fr::from_le_bytes_mod_order(&bytes))
    }
    
    pub async fn generate_client_sig(base_nonce: u64, i: u64, signer: PrivateKeySigner) -> Signature {
        let hash = {
            let mut hasher = Keccak256::new();
            hasher.update((base_nonce + i).abi_encode());
            hasher.finalize()
        };
        signer.sign_message(hash.as_slice()).await.expect("signing failed")
    }
    
    pub async fn ws_connect(addr: &str, wallet_sk: &str) -> impl Provider + WalletProvider + Clone {
        let ws = WsConnect::new(addr);
        let wallet = EthereumWallet::from(PrivateKeySigner::from_str(wallet_sk).expect("invalid private key"));

        match ProviderBuilder::new().wallet(wallet).connect_ws(ws).await {
            Ok(p) => { p }
            Err(e) => {
                panic!("could not connect to Ethereum node at {} via WebSockets: {}", addr, e);
            }
        }
    }
    
    pub async fn setup_coord<T>(eth: T, contract_addr: Address, t: u64, n_outputs: u64, key_der: Option<Vec<u8>>)
        -> OnChainCoordinator<T> 
        where T: Provider + WalletProvider + Clone {
        let coord_instance = FakeCoordinator::new(contract_addr, eth.clone());
        OnChainCoordinator::new(coord_instance, t, n_outputs, key_der).await
    }
    
    impl<P: Provider + WalletProvider + Clone> OnChainCoordinator<P> {
        pub async fn new(coord: FakeCoordinatorInstance<P>, t: u64, n_outputs: u64, key_der: Option<Vec<u8>>) -> Self {
            let contract_block = Self::coord_creation_block(&coord).await;
            Self { coord, contract_block, t, n_outputs: Some(n_outputs), key_der }
        }

        pub fn coord(&self) -> FakeCoordinatorInstance<P> {
            self.coord.clone()
        }
    
        async fn coord_creation_block(coord: &FakeCoordinatorInstance<P>) -> u64 {
                let x = coord.creationBlock().call().await.expect("sending TX failed");
                u256_to_u64(x).expect("impossible bug: block number does not fit into u64")
        }

        pub async fn base_nonce(&self) -> u64 {
            let base_nonce = self.coord.baseNonce().call().await.expect("sending TX failed");
            u256_to_u64(base_nonce).expect("impossible bug: block number does not fit into u64")
        }
    
        pub async fn auth_client(&self, raw_sig: Vec<u8>, addr: Address) {
            let builder = self.coord.authenticateClient(addr, Bytes::from(raw_sig));
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                }
                Err(e) => {
                    println!("{}", e);
                    if let Some(decoded_error) = e.as_decoded_interface_error::<FakeCoordinatorErrors>() {
                        match decoded_error {
                            FakeCoordinatorErrors::NoIndicesReserved(FakeCoordinator::NoIndicesReserved { client }) => {
                                println!("no indices reserved by address {}", client);
                            }
                            FakeCoordinatorErrors::AccessControlUnauthorizedAccount(_) => {
                                println!("unauthorized account");
                            }
                            _ => {
                                println!("other error");
                            }
                        }
                    }
                    panic!();
                }
            }
        }

        pub async fn wait_for_client_auth(&self, addr: Address) -> Result<bool, CoordinatorError> {
            let mut events = self.coord
                .ClientAuthenticated_filter()
                .from_block(self.contract_block)
                .topic1(addr)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((FakeCoordinator::ClientAuthenticated { client, success }, _))) = events.next().await {
                return Ok(success);
            }
    
            panic!();
        }

        pub async fn grant_roles(&self, nodes: Vec<Address>) -> Result<(), CoordinatorError> {
            assert_eq!(nodes.len(), 5);
        
            let PARTY_ROLE = {
                let builder = self.coord.PARTY_ROLE();
                builder.call().await.expect("sending TX failed")
            };
            //let DESIGNATED_PARTY_ROLE = {
            //    let builder = self.coord.DESIGNATED_PARTY_ROLE();
            //    builder.call().await.expect("sending TX failed")
            //};
        
            // grant party roles
            for i in 0..nodes.len() {
                let builder = self.coord.grantRole(PARTY_ROLE, nodes[i]);
                let result = builder.send().await;
                match result {
                    Ok(r) => {
                        r.watch().await.expect("TX failed");
                    }
                    Err(e) => {
                        println!("{}", e);
                        panic!();
                    }
                }
            }

            Ok(())
        }
    }

    static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";
    
            use alloy::providers::WalletProvider;
    impl<P: Provider + WalletProvider + Clone> Coordinator for OnChainCoordinator<P> {
        type ClientIdentity = Address;

        async fn wait_for_indices(&self, n_clients: u64) -> Result<HashMap<ClientIdentity, u64>, CoordinatorError> {
            let mut addr_to_i: HashMap<Address, u64> = HashMap::new();
            
            // spawn thread to receive all ReservedInputEvents
            let mut events = self.coord
                .ReservedInputEvent_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
            
            while let Some(Ok((ReservedInputEvent { client, reservedIndices }, _))) = events.next().await {
                assert_eq!(reservedIndices.len(), 1);
                addr_to_i.insert(client, u256_to_u64(reservedIndices[0]).expect("conversion from U256 to u64 failed"));
                eprintln!("[party] Recorded reserved mask index {} for client address {:?}",
                         reservedIndices[0], client);
                if addr_to_i.len() as u64 == n_clients {
                    break;
                }
            }
    
            Ok(addr_to_i)
        }

        async fn wait_for_inputs(&self, n_clients: u64, mask_shares: Vec<RobustShare<Fr>>) -> Result<HashMap<ClientIdentity, Vec<RobustShare<Fr>>>, CoordinatorError> {
            let mut events = self.coord
                .MaskedInputEvent_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            let mut inputs: HashMap<ClientIdentity, Vec<RobustShare<Fr>>> = HashMap::new();
            for _ in 0..n_clients {
                if let Some(Ok((MaskedInputEvent { client, maskedInput, reservedIndex }, _))) = events.next().await {
                    let masked_input = match u256_to_fr(maskedInput) {
                        Some(v) => v,
                        None => {
                            panic!();
                        }
                    };
                    let i = u256_to_u64(reservedIndex).expect("conversion from U256 to u64 failed") as usize;
                    let mask_share = &mask_shares[i];
                    let input = RobustShare::new(
                        masked_input - mask_share.share[0],
                        mask_share.id,
                        mask_share.degree
                    );

                    inputs.insert(client, vec![input]);
                } else {
                    panic!();
                }
            }
            Ok(inputs)
        }

        async fn trigger_input(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.collectInputs();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    println!("{:?}", e);
                    panic!();
                }
            }
        }
        
        async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .InputMaskReservationStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.startPreprocessing();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    let err = e.as_decoded_error::<FakeCoordinator::NotAnExistingParty>().unwrap();
                    println!("No such account {}", err.account);
                    panic!();
                }
            }
        }
        
        async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .PreprocessingStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
            let builder = self.coord.reserveInputMasks();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    println!("{:?}", e);
                    panic!();
                }
            }
        }
        
        async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .InputMaskReservationStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((InputMaskReservationStarted { executor, timeOfExecution }, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn obtain_mask_indices(&mut self, n_indices: u64) -> Result<Vec<u64>, CoordinatorError> {
            let builder = self.coord.obtainInputMasks(U256::from(n_indices));
            let tx = builder.send().await.expect("failed to send TX");
            let receipt = tx.get_receipt().await.expect("failed to get receipt");

            if !receipt.status() {
                panic!();
            }

            let mut indices = None;

            for log in receipt.inner.logs() {
                if let Ok(e) = log.log_decode::<FakeCoordinator::ReservedInputEvent>() {
                    indices = Some(e.inner.reservedIndices.clone());
                    break; 
                }
            }

            if let Some(indices) = indices {
                return indices.iter().map(|i| {
                    u256_to_u64(*i).ok_or_else(|| {
                        panic!("conversion from U256 to u64 failed for index {}", i);
                    })
                }).collect();
            }

            panic!("no index reservation event found");
        }

        async fn send_masked_input(&self, masked_input: Fr, i: u64) -> Result<(), CoordinatorError> {
            let builder = self.coord.submitMaskedInput(fr_to_u256(masked_input), U256::from(i));
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    panic!();
                }
            }
        }
        
        async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.startMPC();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    panic!();
                }
            }
        }
        
        async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .MPCStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.sendOutputs();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(_) => {
                    panic!();
                }
            }
        }
        
        async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .OutputSendingStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }

        async fn finalize(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.finalize();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    println!("{}", e);
                    if let Some(decoded) = e.as_decoded_interface_error::<FakeCoordinatorErrors>() {
                        println!("{:?}", decoded);
                    }
                    panic!();
                }
            }
        }

        async fn obtain_outputs(&self) -> Result<Vec<Fr>, CoordinatorError> {
            let client_sk = {
                let der_bytes = self.key_der.clone().unwrap();
                let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                    .expect("Failed to parse the DER envelope as PKCS#8");
                let raw_sk = parsed_secret_key.to_bytes();

                <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk).unwrap()
            };

            let mut events = self.coord
                .EnoughPrivateOutputShares_filter()
                .from_block(self.contract_block)
                .topic1(self.coord.provider().default_signer_address())
                .watch()
                .await.unwrap().into_stream();
        
            while let Some(Ok((EnoughPrivateOutputShares { client: _, shares }, _))) = events.next().await {
                if (shares.len() as u64) < 2 * self.t + 1 {
                    println!("BUG: less than 2t+1 output shares received, coordinator should make sure this does not happen!!!");
                    panic!();
                }

                let output_shares = shares.iter().filter_map(|bytes| {
                    let (encapped_key_bytes, c): (Vec<u8>, Vec<u8>) = ark_serialize::CanonicalDeserialize::deserialize_compressed(bytes.to_vec().as_slice()).unwrap();
                    let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(&encapped_key_bytes).unwrap();
                    let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                        &OpModeR::Base, &client_sk, &encapped_key, ENC_INFO, &c, b"",
                    ).unwrap();
                    let shares: Vec<RobustShare<Fr>> = ark_serialize::CanonicalDeserialize::deserialize_compressed(output_shares_bytes.as_slice()).unwrap();

                    if shares.len() as u64 != self.n_outputs.unwrap() {
                        println!("Some node sent an invalid number of output shares, ignoring.");
                        return None;
                    }

                    Some(shares)
                }).collect::<Vec<_>>();

                let outputs: Vec<_> = (0..self.n_outputs.unwrap() as usize).filter_map(|i| {
                    // shares for the ith output
                    let shares_i: Vec<_> = output_shares.iter().map(|shares| shares[i].clone()).collect();

                    // at least 2t+1 shares available as checked previously by the coordinator
                    match RobustShare::recover_secret(&shares_i, (4 * self.t + 1) as usize) {
                        Ok((_, output_i)) => {
                            Some(output_i)
                        }
                        Err(_) => {
                            println!("Reconstruction failed for output {}, waiting for more shares.", i);
                            None
                        }
                    }
                }).collect();

                if outputs.len() == self.n_outputs.unwrap() as usize {
                    return Ok(outputs);
                }
            }

            panic!();
        }

        async fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<Fr>>) -> Result<(), CoordinatorError> {
            let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key).unwrap();
            let mut output_shares_bytes = Vec::new();
            output_shares.serialize_compressed(&mut output_shares_bytes).unwrap();

            let mut rng = StdRng::from_os_rng();
            let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &client_pk,
                ENC_INFO,
                &output_shares_bytes,
                b"",
                &mut rng,
            ).unwrap();
            let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

            let mut bytes = Vec::new();
            c.serialize_compressed(&mut bytes).unwrap();
            let builder = self.coord.sendPrivateOutputShares(client_id, Bytes::from(bytes));
            let result = builder.send().await;

            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    println!("{}", e);
                    if let Some(decoded) = e.as_decoded_interface_error::<FakeCoordinatorErrors>() {
                        println!("{:?}", decoded);
                    }
                    panic!();
                }
            }
        }
    }
    
    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy::signers::local::PrivateKeySigner;
        use ark_std::test_rng;
        use ark_bls12_381::Fr;
        use alloy::node_bindings::{Anvil, AnvilInstance};
        use alloy_primitives::{Address, U256, FixedBytes, address};
        use stoffel_solidity_bindings::{
            fake_coordinator::FakeCoordinator,
        };
        use tokio::time::{timeout, Duration};
        use tokio::sync::Barrier;
        use std::sync::Arc;
        use rand::Rng;
        use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
        use stoffelmpc_mpc::common::SecretSharingScheme;

        static SK: [&str; 10] = [
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
            "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
            "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
            "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
        ];
    
        static ACC: [Address; 10] = [
            address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            address!("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
            address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
            address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
            address!("0x976EA74026E726554dB657fA54763abd0C3a0aa9"),
            address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"),
            address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"),
            address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
        ];
    
        fn spawn_anvil() -> AnvilInstance {
            Anvil::new().spawn()
        }
        
        #[tokio::test]
        pub async fn sig_gen_onchain() {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            let n = U256::from(5);
            let t = 1;
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let contract = FakeCoordinator::deploy(provider.clone(), hash, n, U256::from(t), ACC[0], initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
            let mut coord = OnChainCoordinator::new(contract.clone(), t, 1, None).await;
            let signer = PrivateKeySigner::from_str(SK[0]).unwrap();
            let i = 42;

            // grant roles to parties
            coord.grant_roles(initial_mpc_nodes).await.expect("granting roles failed");
    
            // Generate signature
            let _ = coord.obtain_mask_indices(1).await.expect("obtaining mask indices failed");
            let base_nonce = coord.base_nonce().await;
            let sig = generate_client_sig(base_nonce, i, signer.clone()).await;
    
            // simulate 2 * t + 1 = 3 nodes that have received valid signatures from a client
            {
                let provider = ws_connect(&anvil.ws_endpoint(), SK[1]).await;
                let instance = FakeCoordinatorInstance::new(*contract.address(), provider.clone());
                let coord = OnChainCoordinator::new(instance, t, 1, None).await;
                coord.auth_client(sig.as_bytes().to_vec(), ACC[0]).await;
            }
            {
                let provider = ws_connect(&anvil.ws_endpoint(), SK[2]).await;
                let instance = FakeCoordinatorInstance::new(*contract.address(), provider.clone());
                let coord = OnChainCoordinator::new(instance, t, 1, None).await;
                coord.auth_client(sig.as_bytes().to_vec(), ACC[0]).await;
            }
            {
                let provider = ws_connect(&anvil.ws_endpoint(), SK[3]).await;
                let instance = FakeCoordinatorInstance::new(*contract.address(), provider.clone());
                let coord = OnChainCoordinator::new(instance, t, 1, None).await;
                coord.auth_client(sig.as_bytes().to_vec(), ACC[0]).await;
            }

            // TODO: wait for ClientAuthenticated event
        }
    
        #[test]
        pub fn fr_u256_conversion() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let n: u64 = rng.random();
                let fr = Fr::from(n);
                let u = fr_to_u256(fr);
                let fr2 = u256_to_fr(u);
                assert!(fr2.is_some());
                assert_eq!(fr, fr2.unwrap());
            }
        }
    
        #[test]
        pub fn u64_u256_conversion() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let n1: u64 = rng.random();
                let n1_u256 = U256::from(n1);
                let n2 = u256_to_u64(n1_u256);
                assert!(n2.is_some());
                assert_eq!(n1, n2.unwrap());
            }
        }

        #[tokio::test]
        pub async fn coord_creation_block() {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            let n = U256::from(5);
            let t = 1;
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, U256::from(t), designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
            let coord = OnChainCoordinator::new(coord_instance, t, 1, None).await;
            assert_eq!(coord.contract_block, 1);
        }
    
        #[tokio::test]
        pub async fn event_listening() {
            // event triggered BEFORE waiting for the event
            {
                let anvil = spawn_anvil();
                let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
                let n = U256::from(5);
                let t = 1;
                let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
                let designated_party = ACC[0];
                let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
                let n_inputs = U256::from(1);
    
                let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, U256::from(t), designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
                let coord = OnChainCoordinator::new(coord_instance, t, 1, None).await;
    
                coord.trigger_pp().await.unwrap();
                coord.wait_for_pp().await.unwrap();
            }
    
            // event triggered AFTER waiting for the event
            {
                let anvil = spawn_anvil();
                let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
                let n = U256::from(5);
                let t = 1;
                let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
                let designated_party = ACC[0];
                let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
                let n_inputs = U256::from(1);
    
                let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, U256::from(t), designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
                let coord = OnChainCoordinator::new(coord_instance, t, 1, None).await;
    
                tokio::spawn({
                    let coord = coord.clone();
                    async move {
                        if timeout(Duration::from_millis(500), coord.wait_for_pp()).await.is_err() {
                            panic!();
                        }
                    }
                });
                    
                coord.trigger_pp().await.unwrap();
            }
        }

        #[tokio::test]
        pub async fn start_node_rpc() {
            crate::setup_test();

            let node_rpc_addrs = vec![
                ("127.0.0.1".to_string(), 12348),
                ("127.0.0.1".to_string(), 12349),
                ("127.0.0.1".to_string(), 12350)
            ];
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            let n = U256::from(5);
            let t = 1;
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let contract = FakeCoordinator::deploy(provider.clone(), hash, n, U256::from(t), designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
    
            // simulate 2 * t + 1 = 3 nodes that have received valid signatures from a client
            let mut node_rpcs = Vec::new();
            for i in 0..node_rpc_addrs.len() {
                let provider = ws_connect(&anvil.ws_endpoint(), SK[i]).await;
                let instance = FakeCoordinatorInstance::new(*contract.address(), provider.clone());

                let node_rpc = super::node_rpc::NodeRPCServer::start_from_cert(&node_rpc_addrs[i].0,
                    node_rpc_addrs[i].1, instance.clone(), crate::self_signed_certs::server_cert()).await;
                node_rpcs.push(node_rpc);
            }
            let _ = super::node_rpc::NodeRPCClient::start_rpc_client_from_cert(t, node_rpc_addrs.clone(), crate::self_signed_certs::client_cert()).await;
        }

        #[tokio::test]
        pub async fn end_to_end() {
            crate::setup_test();

            let certs = (0..7).map(|_| crate::self_signed_certs::client_cert()).collect::<Vec<_>>();
            let public_keys = certs.iter().map(|c| c.signing_key.public_key_raw().to_vec()).collect::<Vec<_>>();

            let correct_mask = Fr::from(42);
            let correct_output = Fr::from(31415);

            let node_rpc_addrs = vec![
                ("127.0.0.1".to_string(), 12351),
                ("127.0.0.1".to_string(), 12352),
                ("127.0.0.1".to_string(), 12353)
            ];
            let anvil = spawn_anvil();
            let n = 5;
            let t = 1;
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let provider = ws_connect(&anvil.ws_endpoint(), SK[9]).await;
            let contract = FakeCoordinator::deploy(provider.clone(), hash, U256::from(n), U256::from(t), designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");

            let barrier = Arc::new(Barrier::new(3));

            // MPC node (designated party), also RPC client
            tokio::spawn({
                let barrier = barrier.clone();

                let mut instances = Vec::new();
                for i in 0..3 {
                    let provider = ws_connect(&anvil.ws_endpoint(), SK[i]).await;
                    let instance = FakeCoordinatorInstance::new(*contract.address(), provider);
                    instances.push(instance);
                }

                let mut coords = Vec::new();
                for i in 0..3 {
                    let coord =
                        OnChainCoordinator::new(instances[i].clone(), 1, 1, None).await;
                    coords.push(coord);
                }

                // grant roles to parties
                coords[0].grant_roles(initial_mpc_nodes.clone()).await.expect("granting roles failed");

                // simulate 2 * t + 1 = 3 RPC nodes for client authentication; we just have one
                // node here, but we use 3 RPC nodes to make the process work
                let mask = Fr::from(42);
                let mut rng = test_rng();
                let mask_shares = RobustShare::compute_shares(mask, n, t as usize, None, &mut rng).unwrap();
                let output_shares = RobustShare::compute_shares(correct_output, n, t as usize, None, &mut rng).unwrap();

                let mut node_rpcs = Vec::new();
                for i in 0..3 {
                    let mut node_rpc = super::node_rpc::NodeRPCServer::start_from_cert(&node_rpc_addrs[i].0,
                        node_rpc_addrs[i].1, instances[i].clone(), certs[i].clone()).await;

                    node_rpc.add_mask_share(0, mask_shares[i].clone()).await;
                    node_rpcs.push(node_rpc);
                }

                let client_public_key = public_keys[5].clone();

                async move {
                    coords[0].trigger_pp().await.unwrap();
                    let _ = coords[0].wait_for_pp().await;
                    coords[0].init_input_masks().await.unwrap();
                    let _ = coords[0].wait_for_input_mask_init().await;
                    let client_to_index = coords[0].wait_for_indices(1).await.unwrap();  // called by node
                    for (c, i) in client_to_index {
                        println!("NODE: client {:?} reserved index {}", c, i);
                        for node_rpc in node_rpcs.iter_mut() {
                            // just received by one node here, but in reality would be received by
                            // all nodes, so we simulate this here for more nodes
                            node_rpc.add_reserved_index(c, i).await;
                        }
                    }

                    // just received by one node here, but in reality would be received by
                    // all nodes, so we simulate it for more nodes
                    if !coords[0].wait_for_client_auth(ACC[5]).await.unwrap() {
                        panic!();
                    }
                    for node_rpc in node_rpcs.iter_mut() {
                        node_rpc.add_auth_status(ACC[5], true).await;
                    }

                    coords[0].trigger_input().await.unwrap();
                    let _ = coords[0].wait_for_input().await;
                    let client_to_masked_input = coords[0].wait_for_inputs(1, vec![mask_shares[0].clone()]).await.unwrap();
                    for (c, masked_inputs) in client_to_masked_input {
                        for masked_input in masked_inputs {
                            println!("NODE: client {:?} submitted masked input {}", c, masked_input.share[0]);
                        }
                    }
                    coords[0].trigger_mpc().await.unwrap();
                    let _ = coords[0].wait_for_mpc().await;
                    coords[0].trigger_outputs().await.unwrap();
                    let _ = coords[0].wait_for_outputs().await;
                    for (i, coord) in coords.iter_mut().enumerate() {
                        coord.send_output_shares(ACC[5], client_public_key.clone(), vec![output_shares[i].clone()]).await.unwrap();
                    }
                    coords[0].finalize().await.unwrap();

                    barrier.wait().await;
                }
            });

            // MPC client, also RPC client
            tokio::spawn({
                let barrier = barrier.clone();

                let provider = ws_connect(&anvil.ws_endpoint(), SK[5]).await;
                let instance = FakeCoordinatorInstance::new(*contract.address(), provider.clone());
                let mut coord = OnChainCoordinator::new(instance, t, 1, Some(certs[5].signing_key.serialize_der())).await;

                async move {
                    let rpc_client = super::node_rpc::NodeRPCClient::start_rpc_client_from_cert(t as usize, node_rpc_addrs.clone(), certs[5].clone()).await;
                    let _ = coord.wait_for_pp().await;
                    let _ = coord.wait_for_input_mask_init().await;

                    let indices = coord.obtain_mask_indices(1).await.expect("obtaining mask indices failed");
                    assert_eq!(indices.len(), 1);
                    println!("CLIENT: obtained index {}", indices[0]);

                    let base_nonce = coord.base_nonce().await;
                    let signer = PrivateKeySigner::from_str(SK[5]).unwrap();
                    let sig = generate_client_sig(base_nonce, indices[0], signer.clone()).await;
                    let mask = rpc_client.receive_mask_share(sig.into(), ACC[5]).await;
                    assert_eq!(mask, correct_mask);

                    let _ = coord.wait_for_input().await;

                    let masked_input = mask + Fr::from(1337);
                    coord.send_masked_input(Fr::from(masked_input), indices[0]).await.unwrap();

                    let _ = coord.wait_for_mpc().await;
                    let _ = coord.wait_for_outputs().await;
                    let outputs = coord.obtain_outputs().await.unwrap();
                    println!("CLIENT: obtained outputs {:?}", outputs);
                    assert_eq!(outputs.len(), 1);
                    assert_eq!(outputs[0], correct_output);

                    barrier.wait().await;
                }
            });

            barrier.wait().await;
        }
    }
}

pub mod off_chain {
    use ark_bls12_381::Fr;
    use jsonrpsee::{core::{SubscriptionResult, RpcResult, to_json_raw_value}, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::ServerHandle};
    use serde::{Serialize, Deserialize};
    use crate::{Coordinator, CoordinatorError, rpc::{FieldElement, ClientInfo}};
    use events::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use async_trait::async_trait;
    use jsonrpsee::server::RpcModule;
    use jsonrpsee::async_client::Client;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use stoffelmpc_mpc::common::SecretSharingScheme;
    use hpke::{
        aead::AesGcm256, 
        kdf::HkdfSha256, 
        kem::{DhP256HkdfSha256, Kem},
        single_shot_open, single_shot_seal, 
        Deserializable, Serializable,
        HpkeError, OpModeR, OpModeS,
    };
    use p256::{SecretKey, pkcs8::DecodePrivateKey};
    use rand::{SeedableRng, rngs::StdRng};
    use ark_serialize::CanonicalSerialize;

    type KemImpl = DhP256HkdfSha256;
    type KdfImpl = HkdfSha256;
    type AeadImpl = AesGcm256;

    type ClientIdentity = Vec<u8>;

    pub mod node_rpc {
        use ark_bls12_381::Fr;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        use jsonrpsee::{core::{SubscriptionResult, to_json_raw_value}, async_client::Client, server::RpcModule, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::ServerHandle};
        use async_trait::async_trait;
        use tokio::task::JoinHandle;
        use super::ClientIdentity;
        use crate::rpc::ClientInfo;
        use tokio::task::JoinSet;
        use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
        use stoffelmpc_mpc::common::SecretSharingScheme;
        use ark_serialize::CanonicalSerialize;

        #[rpc(server, client)]
        pub trait OffChainNodeRPC {
            #[subscription(name = "sub_receive_mask_share", unsubscribe = "unsub_receive_mask_share", item = Vec<u8>)]
            async fn receive_mask_share(&self) -> SubscriptionResult;
        }

        pub struct NodeRPCServer {
            rpc_server: Arc<Mutex<NodeRPCServerInternal>>,
            addr: String,
            port: u16,
            server_handle: JoinHandle<()>,
        }

        pub struct NodeRPCClient {
            node_rpcs: Vec<Client>,
            t: usize
        }

        impl NodeRPCClient {
            pub async fn start_rpc_client_from_cert(t: usize, addrs: Vec<(String, u16)>, client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
                Self::start_rpc_client(t, addrs, client_cert.cert.der().to_vec(), client_cert.signing_key.serialize_der()).await
            }

            pub async fn start_rpc_client(t: usize, addrs: Vec<(String, u16)>, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
                let mut node_rpcs = Vec::new();

                // connect to all nodes
                for (addr, port) in addrs.iter() {
                    let node_rpc = crate::self_signed_certs::setup_client(addr, *port, cert_der.clone(), key_der.clone()).await;
                    node_rpcs.push(node_rpc);
                }

                Self {
                    node_rpcs,
                    t
                }
            }

            pub async fn receive_mask(&self) -> Fr {
                let mut share_futures = JoinSet::new();

                for rpc in self.node_rpcs.iter() {
                    let mut sub = rpc.receive_mask_share().await.unwrap();
                    share_futures.spawn(async move { sub.next().await });
                }

                let mut mask_shares = Vec::new();

                while let Some(share_bytes) = share_futures.join_next().await {
                    let share = ark_serialize::CanonicalDeserialize::deserialize_compressed(share_bytes.unwrap().unwrap().unwrap().as_slice()).unwrap();
                    mask_shares.push(share);

                    if mask_shares.len() >= 2 * self.t + 1 {
                        match RobustShare::recover_secret(&mask_shares, 4 * self.t + 1) {
                            Ok((_, mask)) => {
                                return mask;
                            }
                            Err(_) => {
                                panic!("reconstruction of mask failed");
                            }
                        }
                    }
                }

                panic!("mask could not be reconstructed");
            }
        }

        impl NodeRPCServer {
            pub async fn start_from_cert(addr: &str, port: u16, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
                Self::start(addr, port, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
            }

            pub async fn start(addr: &str, port: u16, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
                let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::new()));
                let server_handle = crate::rpc::start_coord::<NodeRPCServerImpl>(addr, port, cert_der, key_der, rpc_server_data.clone()).await;
                Self {
                    rpc_server: rpc_server_data,
                    addr: String::from(addr),
                    port,
                    server_handle
                }
            }

            pub fn get_addr(&self) -> String {
                self.addr.clone()
            }

            // called when the client has reserved indices at the coordinator
            pub async fn add_reserved_index(&mut self, id: ClientIdentity, i: u64) {
                let mut d = self.rpc_server.lock().await;

                assert!(!d.index_to_client.contains_key(&i));
                d.index_to_client.insert(i, id.clone());
                d.client_to_index.insert(id.clone(), i);

                // if mask share is there and share has been requested, send it
                if let Some(share) = d.mask_shares.get(&i) {
                    if let Some(sink) = d.sinks.get(&id) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).unwrap();
                        let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                        sink.send(json).await.unwrap();
                    }
                }
            }
            
            // called when preprocessing has generated the mask shares
            pub async fn add_mask_share(&mut self, i: u64, share: RobustShare<Fr>) {
                let mut d = self.rpc_server.lock().await;

                assert!(!d.mask_shares.contains_key(&i));
                d.mask_shares.insert(i, share.clone());

                // if mask share is there and share has been requested, send it
                if let Some(id) = d.index_to_client.get(&i) {
                    if let Some(sink) = d.sinks.get(id) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).unwrap();
                        let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                        sink.send(json).await.unwrap();
                    }
                }
            }
        }

        pub struct NodeRPCServerImpl {
            d: Arc<Mutex<NodeRPCServerInternal>>,
            id: Vec<u8>
        }

        impl crate::rpc::RPCServerImpl for NodeRPCServerImpl {
            type Internal = NodeRPCServerInternal;

            fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
                Self { d: internal, id }
            }

            fn into_rpc(self) -> RpcModule<Self> where Self: Sized {
                crate::off_chain::node_rpc::OffChainNodeRPCServer::into_rpc(self)
            }
        }

        pub struct NodeRPCServerInternal {
            index_to_client: HashMap<u64, ClientIdentity>,
            client_to_index: HashMap<ClientIdentity, u64>,
            sinks: HashMap<ClientIdentity, SubscriptionSink>,
            mask_shares: HashMap<u64, RobustShare<Fr>>,
            clients: HashMap<Vec<u8>, ClientInfo>,
        }

        impl crate::rpc::RPCServerInternal for NodeRPCServerInternal {
            fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle) {
                self.clients.insert(cert_der.clone(), ClientInfo { cert: cert_der, thread: client_handle, stop_tx });
            }
        }

        impl NodeRPCServerInternal {
            pub fn new() -> Self {
                Self {
                    index_to_client: HashMap::new(),
                    client_to_index: HashMap::new(),
                    sinks: HashMap::new(),
                    mask_shares: HashMap::new(),
                    clients: HashMap::new(),
                }
            }
        }

        #[async_trait]
        impl OffChainNodeRPCServer for NodeRPCServerImpl {
            async fn receive_mask_share(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
                let sink = pending.accept().await?;

                let mut d = self.d.lock().await;

                if d.sinks.contains_key(&self.id) {
                    panic!();
                }
                d.sinks.insert(self.id.clone(), sink);

                if let Some(i) = d.client_to_index.get(&self.id) {
                    if let Some(share) = d.mask_shares.get(i) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).unwrap();
                        let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                        d.sinks.get(&self.id.clone()).unwrap().send(json).await.unwrap();
                    }
                }

                Ok(())
            }
        }
    }


    pub mod events {
        use ark_bls12_381::Fr;
        use serde::{Serialize, Deserialize};
        use super::{ClientIdentity, FieldElement};
        use downcast_rs::{Downcast, impl_downcast};
        use dyn_clone::{DynClone, clone_trait_object};
    //    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    //    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    //    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    //    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    //    event CoordinatorInitialized(address coordinator, uint256 timeofInitialization, uint256 creationBlock, address designatedParty);
    //    event InitializeStoffelAccessControl(uint256 nParties, uint256 t, address initializer);

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ExecutionDone {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct IndexBufferEvent {
            pub total_indices: u64,
            pub designated_party: ClientIdentity
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct InputCollectionStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct InputMaskReservationStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct MPCStarted {
            //address executor
            //uint256 timeOfExecution
        }
   
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct MaskedInputEvent {
            pub client: ClientIdentity,
            pub masked_input: FieldElement<Fr>,
            pub reserved_index: u64
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct OutputSendingStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct OutputsPublished {
            //bytes32 stoffelProgramHash
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct PreprocessingStarted {
            pub designated_party: ClientIdentity,
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ReservedInputEvent {
            pub client: ClientIdentity,
            pub reserved_indices: Vec<u64>
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ClientInputMaskReservationEvent {
            //address executor;
            //uint256 timeOfExecution
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ClientOutputCollection {
            //address executor
            //uint256 timeOfExecution
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct CoordinatorInitialized {
            //address coordinator
            //uint256 timeofInitialization;
            pub creation_block: u64,
            pub designated_party: ClientIdentity
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct PreprocessingRoundExecuted {
            //address designatedParty
            //uint256 timeOfExecution
        }

        pub trait TransitionEvent : Downcast + DynClone + Send { }
        impl_downcast!(TransitionEvent);
        clone_trait_object!(TransitionEvent);
    
        impl TransitionEvent for ExecutionDone { }
        impl TransitionEvent for InputCollectionStarted { }
        impl TransitionEvent for InputMaskReservationStarted { }
        impl TransitionEvent for MPCStarted { }
        impl TransitionEvent for OutputSendingStarted { }
        impl TransitionEvent for PreprocessingStarted { }
        impl TransitionEvent for CoordinatorInitialized { }
    }
    
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum Round {
        Idle,
        Preprocessing,
        InputMaskReservation,
        InputCollection,
        MPC,
        Output
    }

    fn round_before(current: Round) -> Round {
        match current {
            Round::Idle => Round::Output,
            Round::Preprocessing => Round::Idle,
            Round::InputMaskReservation => Round::Preprocessing,
            Round::InputCollection => Round::InputMaskReservation,
            Round::MPC => Round::InputCollection,
            Round::Output => Round::MPC
        }
    }

    fn next_round(current: Round) -> Round {
        match current {
            Round::Idle => Round::Preprocessing,
            Round::Preprocessing => Round::InputMaskReservation,
            Round::InputMaskReservation => Round::InputCollection,
            Round::InputCollection => Round::MPC,
            Round::MPC => Round::Output,
            Round::Output => Round::Idle
        }
    }

    
    #[rpc(server, client)]
    pub trait CoordinatorRPC {
    //        function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
    //        function DESIGNATED_PARTY_ROLE() external view returns (bytes32);
    //        function PARTY_ROLE() external view returns (bytes32);
    // function creationTime() external view returns (uint256);
    // function getRoleAdmin(bytes32 role) external view returns (bytes32);
    // function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    // function getRoleMemberCount(bytes32 role) external view returns (uint256);
    // function getRoleMembers(bytes32 role) external view returns (address[] memory);
    // function grantRole(bytes32 role, address account) external;
    // function hasRole(bytes32 role, address account) external view returns (bool);
    // function isDesignatedParty(address account) external view returns (bool);
    // function isParty(address account) external view returns (bool);
    // function owner() external view returns (address);
    // function renounceOwnership() external;
    // function renounceRole(bytes32 role, address account) external;
    // function resetAccessControl(uint256 t, address[] memory initialMPCNodes) external;
    // function resetInputManager(uint256 nIndicesToReserve) external;
    // function revokeRole(bytes32 role, address account) external;
    // function round() external view returns (StoffelCoordinator.Round);
    // function setPublicOutputs(bytes memory publicOutputs) external;
    // function shareReceived(address from, address to) external;
    // function supportsInterface(bytes4 interfaceId) external view returns (bool);
    // function transferOwnership(address newOwner) external;
    // constructor(bytes32 stoffelProgramHash, uint256 n, uint256 t, address designatedParty, address[] initialMPCNodes, uint256 nInputs);
    
        #[subscription(name = "sub_collect_input", unsubscribe = "unsub_collect_inputs", item = InputCollectionStarted)]
        async fn sub_collect_inputs(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "auth_client")]
        async fn auth_client(&self, i: u64, sig: Vec<u8>, key: ClientIdentity) -> RpcResult<bool>;
    
        #[method(name = "available_input_masks")]
        async fn available_input_masks(&self) -> RpcResult<u64>;
    
        #[method(name = "obtain_input_masks")]
        async fn obtain_mask_indices(&self, n_indices: u64) -> RpcResult<Vec<u64>>;

        #[subscription(name = "sub_reserve_input_masks", unsubscribe = "unsub_reserve_input_masks", item = InputMaskReservationStarted)]
        async fn sub_reserve_input_masks(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "reset")]
        async fn reset(&self, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_inputs: u64);
    
        #[subscription(name = "sub_send_outputs", unsubscribe = "unsub_send_outputs", item = OutputSendingStarted)]
        async fn sub_send_outputs(&self, timestamp: u64) -> SubscriptionResult;
    
        #[subscription(name = "sub_start_mpc", unsubscribe = "unsub_start_mpc", item = MPCStarted)]
        async fn sub_start_mpc(&self, timestamp: u64) -> SubscriptionResult;
    
        #[subscription(name = "sub_start_pp", unsubscribe = "unsub_start_pp", item = PreprocessingStarted)]
        async fn sub_start_pp(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "submit_masked_input")]
        async fn submit_masked_input(&self, masked_input: FieldElement<Fr>, reserved_index: u64) -> RpcResult<()>;

        #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = ReservedInputEvent)]
        async fn sub_reserved_indices(&self, timestamp: u64) -> SubscriptionResult;

        #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = MaskedInputEvent)]
        async fn sub_masked_inputs(&self, timestamp: u64) -> SubscriptionResult;

        #[method(name = "transition")]
        async fn transition(&self, next_round: Round) -> RpcResult<()>;

        #[method(name = "send_output_shares")]
        async fn send_output_shares(&self, client_id: ClientIdentity, enc_shares: (Vec<u8>, Vec<u8>)) -> RpcResult<()>;

        #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = Vec<(Vec<u8>, Vec<u8>)>)]
        async fn obtain_output_shares(&self) -> SubscriptionResult;
    }

    struct CoordinatorRPCServerImpl {
        d: Arc<Mutex<CoordinatorRPCServerImplInternal>>,
        id: ClientIdentity
    }

    struct CoordinatorRPCServerImplInternal {
        // contains the sinks of clients, which subscribed to the transition to the given round
        sinks: HashMap<Round, Vec<SubscriptionSink>>,
        trans_events: HashMap<Round, Vec<(u64, Box<dyn TransitionEvent>)>>,
        reserved_index_events: Vec<(u64, ReservedInputEvent)>,
        reserved_index_sinks: Vec<SubscriptionSink>,
        masked_input_events: Vec<(u64, MaskedInputEvent)>,
        masked_input_sinks: Vec<SubscriptionSink>,
        next_i: u64,
        reserved_indices: Vec<Option<ClientIdentity>>,
        input_masks: Vec<Option<Fr>>,
        round: Round,
        prog_hash: [u8; 32],
        n: u64,
        t: u64,
        mpc_nodes: Option<Vec<ClientIdentity>>,
        clients: HashMap<ClientIdentity, ClientInfo>,
        output_shares: HashMap<(ClientIdentity, ClientIdentity), (Vec<u8>, Vec<u8>)>,
        output_sinks: HashMap<ClientIdentity, SubscriptionSink>,
    }

    impl CoordinatorRPCServerImplInternal {
        pub fn new(prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_inputs: u64) -> Self {
            Self {
                sinks: HashMap::from([
                    (Round::Idle, vec![]),
                    (Round::Preprocessing, vec![]),
                    (Round::InputMaskReservation, vec![]),
                    (Round::InputCollection, vec![]),
                    (Round::MPC, vec![]),
                    (Round::Output, vec![])
                ]),
                trans_events: HashMap::from([
                    (Round::Idle, vec![]),
                    (Round::Preprocessing, vec![]),
                    (Round::InputMaskReservation, vec![]),
                    (Round::InputCollection, vec![]),
                    (Round::MPC, vec![]),
                    (Round::Output, vec![])
                ]),
                reserved_index_events: vec![],
                reserved_index_sinks: vec![],
                masked_input_events: vec![],
                masked_input_sinks: vec![],
                next_i: 0,
                reserved_indices: vec![None; n_inputs as usize],
                input_masks: vec![None; n_inputs as usize],
                round: Round::Idle,
                prog_hash,
                n,
                t,
                mpc_nodes: Some(initial_mpc_nodes),
                clients: HashMap::new(),
                output_shares: HashMap::new(),
                output_sinks: HashMap::new()
            }
        }

        pub fn add_client(&mut self, cert: Vec<u8>, thread: JoinHandle<()>, stop_tx: ServerHandle) {
            let info = ClientInfo {
                cert: cert.clone(),
                thread,
                stop_tx
            };
            self.clients.insert(cert, info);
        }

        async fn subscribe_oneshot<E: TransitionEvent + Serialize>(&mut self, pending: PendingSubscriptionSink, timestamp: u64, round: Round) -> SubscriptionResult {
            let sink = pending.accept().await?;

            {
                let events = &self.trans_events[&round];
                let index = events.partition_point(|e| e.0 < timestamp);

                // check if there is an event since the coordinator was reset the last time
                if index != events.len() {
                    let event = *events[index].1.clone().downcast::<E>().map_err(|_| "BUG: Downcasting failed").unwrap();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();

                    return Ok(());
                }
            }


            self.sinks.get_mut(&round).expect(&format!("BUG: {:?} must be present!", round)).push(sink);
            Ok(())
        }

        async fn subscribe_reserved_indices(&mut self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let sink = pending.accept().await?;

            let events = &self.reserved_index_events;
            let index = events.partition_point(|e| e.0 < timestamp);

            // check if there are events since the coordinator was reset the last time
            if index != events.len() {
                // send all such events
                for i in index..events.len() {
                    let event = events[i].1.clone();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                return Ok(());
            }

            self.reserved_index_sinks.push(sink);
            Ok(())
        }

        async fn subscribe_masked_inputs(&mut self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let sink = pending.accept().await?;

            let events = &self.masked_input_events;
            let index = events.partition_point(|e| e.0 < timestamp);

            // check if there are events since the coordinator was reset the last time
            if index != events.len() {
                // send all such events
                for i in index..events.len() {
                    let event = events[i].1.clone();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                return Ok(());
            }

            self.masked_input_sinks.push(sink);
            Ok(())
        }

        async fn transition<E: TransitionEvent + Serialize>(&mut self, event: E, round: Round) -> Result<(), CoordinatorError> {
            if self.round != round_before(round) {
                panic!();
            }

            let sinks = self.sinks.get_mut(&round).expect(&format!("BUG: {:?} must be present!", round));

            // broadcast event to all subscribed RPC clients
            for sink in sinks.iter() {
                let json = to_json_raw_value(&event).expect("failed convert to JSON");
                sink.send(json).await.unwrap();
            }

            // clear all subscribed RPC clients
            sinks.clear();

            // add event to event history
            self.trans_events
                .get_mut(&round)
                .expect(&format!("BUG: {:?} must be present!", round))
                .push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), Box::new(event)));

            self.round = round;

            Ok(())
        }
    }

    impl crate::rpc::RPCServerInternal for CoordinatorRPCServerImplInternal {
        fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle) {
            self.add_client(cert_der, client_handle, stop_tx);
        }
    }

    impl crate::rpc::RPCServerImpl for CoordinatorRPCServerImpl {
        type Internal = CoordinatorRPCServerImplInternal;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self> {
            crate::off_chain::CoordinatorRPCServer::into_rpc(self)
        }
    }


    #[async_trait]
    impl CoordinatorRPCServer for CoordinatorRPCServerImpl {
        async fn sub_collect_inputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_oneshot::<InputCollectionStarted>(pending, timestamp, Round::InputCollection).await
        }

        async fn auth_client(&self, i: u64, sig: Vec<u8>, key: ClientIdentity) -> RpcResult<bool> {
            let message = i.to_be_bytes();
            let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key);
            Ok(verifier.verify(&message, &sig).is_ok())
        }

        async fn available_input_masks(&self) -> RpcResult<u64> {
            let d = self.d.lock().await;

            Ok(d.input_masks.len() as u64 - d.next_i)
        }

        async fn sub_reserve_input_masks(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_oneshot::<InputMaskReservationStarted>(pending, timestamp, Round::InputMaskReservation).await
        }

        async fn reset(&self, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_inputs: u64) {
            let mut d = self.d.lock().await;

            if d.round != Round::Idle {
                panic!();
            }

            d.round = Round::Idle;
            d.next_i = 0;
            d.input_masks = vec![None; n_inputs as usize];
            d.reserved_indices = vec![None; n_inputs as usize];
            d.prog_hash = prog_hash;
            d.n = n;
            d.t = t;
            d.mpc_nodes = Some(initial_mpc_nodes);
        }

        async fn sub_send_outputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_oneshot::<OutputSendingStarted>(pending, timestamp, Round::Output).await
        }

        async fn sub_start_mpc(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_oneshot::<MPCStarted>(pending, timestamp, Round::MPC).await
        }

        async fn sub_start_pp(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_oneshot::<PreprocessingStarted>(pending, timestamp, Round::Preprocessing).await
        }

        async fn submit_masked_input(&self, masked_input: FieldElement<Fr>, raw_reserved_index: u64) -> RpcResult<()> {
            let mut d = self.d.lock().await;

            if d.round != Round::InputCollection {
                panic!();
            }

            let reserved_index = raw_reserved_index as usize;

            if reserved_index >= d.input_masks.len(){
                panic!();
            }

            match &d.reserved_indices[reserved_index] {
                Some(public_key) => {
                    if *public_key != self.id {
                        panic!();
                    }
                    if d.input_masks[reserved_index].is_some() {
                        panic!();
                    }
                    d.input_masks[reserved_index] = Some(masked_input.value);

                    let event = MaskedInputEvent { client: self.id.clone(), masked_input, reserved_index: raw_reserved_index };
                    for sink in &d.masked_input_sinks {
                        let json = to_json_raw_value(&event).expect("failed convert to JSON");
                        sink.send(json).await.unwrap();
                    }
                    d.masked_input_events.push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), event));
                }
                None => {
                    panic!();
                }
            }

            Ok(())
        }

        async fn sub_reserved_indices(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_reserved_indices(pending, timestamp).await
        }

        async fn sub_masked_inputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.d.lock().await;

            d.subscribe_masked_inputs(pending, timestamp).await
        }

        async fn obtain_mask_indices(&self, n_indices: u64) -> RpcResult<Vec<u64>> {
            let mut d = self.d.lock().await;

            if d.round != Round::InputMaskReservation {
                panic!();
            }

            if d.next_i + n_indices > d.input_masks.len() as u64 {
                panic!();
            }

            for i in d.next_i..d.next_i + n_indices {
                d.reserved_indices[i as usize] = Some(self.id.clone());

                let event = ReservedInputEvent { client: self.id.clone(), reserved_indices: vec![i] };

                // broadcast reserved index to all subscribed RPC clients
                for sink in &d.reserved_index_sinks {
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                d.reserved_index_events.push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), event));
            }

            let indices = (d.next_i..(d.next_i + n_indices)).collect();
            d.next_i += n_indices;

            Ok(indices)
        }

        async fn transition(&self, next_round: Round) -> RpcResult<()> {
            let mut d = self.d.lock().await;

            if self.id != d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0] {
                panic!();
            }

            match next_round {
                Round::Idle => d.transition(ExecutionDone { }, next_round).await.unwrap(),
                Round::Preprocessing => d.transition(PreprocessingStarted { designated_party: self.id.clone() }, next_round).await.unwrap(),
                Round::InputMaskReservation => d.transition(InputMaskReservationStarted { }, next_round).await.unwrap(),
                Round::InputCollection => d.transition(InputCollectionStarted { }, next_round).await.unwrap(),
                Round::MPC => d.transition(MPCStarted { }, next_round).await.unwrap(),
                Round::Output => d.transition(OutputSendingStarted { }, next_round).await.unwrap()
            };

            Ok(())
        }

        async fn send_output_shares(&self, client_id: ClientIdentity, enc_shares: (Vec<u8>, Vec<u8>)) -> RpcResult<()> {
            let mut d = self.d.lock().await;

            if d.output_shares.contains_key(&(client_id.clone(), self.id.clone())) {
                // a node cannot send output shares for a client twice
                panic!();
            }

            // output shares for `client_id` from `self.id`
            d.output_shares.insert((client_id.clone(), self.id.clone()), enc_shares);

            let output_shares: Vec<_> = d.output_shares.iter().filter(|((cid, _), _)| *cid == client_id).map(|(_, shares)| shares.clone()).collect();

            if output_shares.len() as u64 >= 2 * d.t + 1 {
                if let Some(sink) = d.output_sinks.get(&client_id) {
                    let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
                    sink.send(json.clone()).await.unwrap();
                }
            }
            Ok(())
        }

        async fn obtain_output_shares(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
            let sink = pending.accept().await?;

            let mut d = self.d.lock().await;

            if d.output_sinks.contains_key(&self.id) {
                panic!();
            }
            d.output_sinks.insert(self.id.clone(), sink);

            let output_shares: Vec<_> = d.output_shares.iter().filter(|((client_id, _), _)| *client_id == self.id).map(|(_, shares)| shares.clone()).collect();

            if output_shares.len() as u64 >= 2 * d.t + 1 {
                let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
                let sink = d.output_sinks.get(&self.id).unwrap();

                sink.send(json.clone()).await.unwrap();
            }

            Ok(())
        }
    }

    pub struct OffChainCoordinator {
        rpc_server: Option<Arc<Mutex<CoordinatorRPCServerImplInternal>>>,
        rpc_coord: Option<Client>,
        addr: Option<String>,
        port: Option<u16>,
        server_handle: Option<JoinHandle<()>>,
        timestamp: Option<u64>,
        t: u64,
        n_outputs: Option<u64>,
        key_der: Option<Vec<u8>>
    }

    impl OffChainCoordinator {
        pub async fn start_coord_from_cert(addr: &str, port: u16, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_outputs: u64, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
            Self::start_coord(addr, port, prog_hash, n, t, initial_mpc_nodes, n_outputs, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
        }

        pub async fn start_coord(addr: &str, port: u16, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_outputs: u64, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
            let rpc_server_data = Arc::new(Mutex::new(CoordinatorRPCServerImplInternal::new(prog_hash, n, t, initial_mpc_nodes.clone(), n_outputs)));
            let server_handle = crate::rpc::start_coord::<CoordinatorRPCServerImpl>(addr, port, cert_der, key_der, rpc_server_data.clone()).await;
            Self {
                rpc_server: Some(rpc_server_data),
                rpc_coord: None,
                addr: Some(String::from(addr)),
                port: Some(port),
                server_handle: Some(server_handle),
                timestamp: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
                t,
                n_outputs: None,
                key_der: None
            }
        }

        pub async fn start_rpc_client_from_cert(addr: &str, port: u16, timestamp: u64, t: u64, n_outputs: u64, client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
            Self::start_rpc_client(addr, port, timestamp, t, n_outputs, client_cert.cert.der().to_vec(), client_cert.signing_key.serialize_der()).await
        }

        pub async fn start_rpc_client(addr: &str, port: u16, timestamp: u64, t: u64, n_outputs: u64, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
            let rpc_coord = crate::self_signed_certs::setup_client(addr, port, cert_der, key_der.clone()).await;

            Self {
                rpc_server: None,
                rpc_coord: Some(rpc_coord),
                addr: None,
                port: None,
                server_handle: None,
                timestamp: Some(timestamp),
                t,
                n_outputs: Some(n_outputs),
                key_der: Some(key_der)
             }
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone().expect("Coordinator server not started")
        }

        pub fn get_timestamp(&self) -> u64 {
            self.timestamp.expect("Coordinator server not started")
        }
    }

    static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";
    
    impl Coordinator for OffChainCoordinator {
        type ClientIdentity = ClientIdentity;

        async fn wait_for_indices(&self, n_clients: u64) -> Result<HashMap<ClientIdentity, u64>, CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_reserved_indices(self.get_timestamp()).await.unwrap();

            let mut map = HashMap::new();

            for _ in 0..n_clients {
                let ReservedInputEvent { client, reserved_indices } = sub.next().await.unwrap().unwrap();
                assert_eq!(reserved_indices.len(), 1);
                map.insert(client, reserved_indices[0]);
            }

            Ok(map)
        }

        async fn wait_for_inputs(&self, n_clients: u64, mask_shares: Vec<RobustShare<Fr>>) -> Result<HashMap<ClientIdentity, Vec<RobustShare<Fr>>>, CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_masked_inputs(self.get_timestamp()).await.unwrap();

            let mut map = HashMap::new();

            for _ in 0..n_clients {
                let MaskedInputEvent { client, masked_input, reserved_index } = sub.next().await.unwrap().unwrap();
                let masked_input = masked_input.value;
                let i = reserved_index as usize;
                let mask_share = &mask_shares[i];
                let input = RobustShare::new(
                    masked_input - mask_share.share[0],
                    mask_share.id,
                    mask_share.degree
                );

                map.insert(client, vec![input]);
            }

            Ok(map)
        }

        async fn trigger_input(&self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::InputCollection).await.unwrap();

            Ok(())
        }

        async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_collect_inputs(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::Preprocessing).await.unwrap();

            Ok(())
        }

        async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_start_pp(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::InputMaskReservation).await.unwrap();

            Ok(())
        }

        async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_reserve_input_masks(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn send_masked_input(&self, masked_input: Fr, i: u64) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").submit_masked_input(FieldElement { value: masked_input }, i).await.unwrap();

            Ok(())
        }


        async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::MPC).await.unwrap();

            Ok(())
        }

        async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_start_mpc(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::Output).await.unwrap();

            Ok(())
        }

        async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_send_outputs(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn obtain_mask_indices(&mut self, n_indices: u64) -> Result<Vec<u64>, CoordinatorError> {
            let indices = self.rpc_coord.as_ref().expect("client not started").obtain_mask_indices(n_indices).await.unwrap();

            Ok(indices)
        }

        async fn finalize(&self) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").transition(Round::Idle).await.unwrap();

            Ok(())
        }

        async fn obtain_outputs(&self) -> Result<Vec<Fr>, CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").obtain_output_shares().await.unwrap();

            let client_sk = {
                let der_bytes = self.key_der.clone().unwrap();
                let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                    .expect("Failed to parse the DER envelope as PKCS#8");
                let raw_sk = parsed_secret_key.to_bytes();

                <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk).unwrap()
            };

            loop {
                let enc_output_shares = sub.next().await.unwrap().unwrap();

                if (enc_output_shares.len() as u64) < 2 * self.t + 1 {
                    println!("BUG: less than 2t+1 output shares received, coordinator should make sure this does not happen!!!");
                    panic!();
                }

                let output_shares = enc_output_shares.iter().filter_map(|(encapped_key_bytes, c)| {
                    let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(encapped_key_bytes).unwrap();
                    let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                        &OpModeR::Base, &client_sk, &encapped_key, ENC_INFO, c, b"",
                    ).unwrap();
                    let shares: Vec<RobustShare<Fr>> = ark_serialize::CanonicalDeserialize::deserialize_compressed(output_shares_bytes.as_slice()).unwrap();

                    if shares.len() as u64 != self.n_outputs.unwrap() {
                        println!("Some node sent an invalid number of output shares, ignoring.");
                        return None;
                    }

                    Some(shares)
                }).collect::<Vec<_>>();

                let outputs: Vec<_> = (0..self.n_outputs.unwrap() as usize).filter_map(|i| {
                    // shares for the ith output
                    let shares_i: Vec<_> = output_shares.iter().map(|shares| shares[i].clone()).collect();

                    // at least 2t+1 shares available as checked previously by the coordinator
                    match RobustShare::recover_secret(&shares_i, (4 * self.t + 1) as usize) {
                        Ok((_, output_i)) => {
                            Some(output_i)
                        }
                        Err(_) => {
                            println!("Reconstruction failed for output {}, waiting for more shares.", i);
                            None
                        }
                    }
                }).collect();

                if outputs.len() == self.n_outputs.unwrap() as usize {
                    return Ok(outputs);
                }
            }
        }

        async fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<Fr>>) -> Result<(), CoordinatorError> {
            let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key).unwrap();
            let mut output_shares_bytes = Vec::new();
            output_shares.serialize_compressed(&mut output_shares_bytes).unwrap();

            let mut rng = StdRng::from_os_rng();
            let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &client_pk,
                ENC_INFO,
                &output_shares_bytes,
                b"",
                &mut rng,
            ).unwrap();
            let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

            self.rpc_coord.as_ref().expect("client not started").send_output_shares(client_id, c).await.unwrap();

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::sync::Barrier;
        use crate::self_signed_certs::{server_cert, client_cert};
        use ark_std::test_rng;
        use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
        use stoffelmpc_mpc::common::SecretSharingScheme;

        #[tokio::test]
        async fn start_client_server() {
            crate::setup_test();

            let certs = (0..7).map(|_| server_cert()).collect::<Vec<_>>();
            let public_keys = certs.iter().map(|c| c.signing_key.public_key_raw().to_vec()).collect::<Vec<_>>();

            let addr = "127.0.0.1";
            let port = 12345;
            let coord = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
            let timestamp = coord.get_timestamp();

            let _ = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, client_cert()).await;
        }

        #[tokio::test]
        async fn trigger_pp() {
            crate::setup_test();

            // event triggered BEFORE waiting for the event
            {
                let mut certs = (0..5).map(|_| server_cert()).collect::<Vec<_>>();
                let public_keys = certs.iter().map(|c| c.signing_key.public_key_raw().to_vec()).collect::<Vec<_>>();

                let addr = "127.0.0.1";
                let port = 12346;
                let coord = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
                let timestamp = coord.get_timestamp();

                let node0 = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;
                let node1 = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;

                node0.trigger_pp().await.unwrap();

                if tokio::time::timeout(std::time::Duration::from_millis(500), node1.wait_for_pp()).await.is_err() {
                    panic!();
                }
            }

            // event triggered AFTER waiting for the event
            {
                let mut certs = (0..5).map(|_| server_cert()).collect::<Vec<_>>();
                let public_keys = certs.iter().map(|c| c.signing_key.public_key_raw().to_vec()).collect::<Vec<_>>();

                let addr = "127.0.0.1";
                let port = 12347;
                let coord = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
                let timestamp = coord.get_timestamp();
                let barrier = Arc::new(Barrier::new(2));

                let node0 = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;
                let node1 = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;

                tokio::spawn({
                    let barrier = barrier.clone();
                    async move {
                        if tokio::time::timeout(std::time::Duration::from_millis(500), node1.wait_for_pp()).await.is_err() {
                            panic!();
                        }
                        barrier.wait().await;
                    }
                });

                node0.trigger_pp().await.unwrap();
                barrier.wait().await;
            }
        }

        #[tokio::test]
        async fn end_to_end() {
            crate::setup_test();

            let node_rpc_addrs = vec![
                ("127.0.0.1".to_string(), 12349),
                ("127.0.0.1".to_string(), 12350),
                ("127.0.0.1".to_string(), 12351)
            ];

            let certs = (0..7).map(|_| client_cert()).collect::<Vec<_>>();
            let public_keys = certs.iter().map(|c| c.signing_key.public_key_raw().to_vec()).collect::<Vec<_>>();

            let correct_mask = Fr::from(42);
            let correct_output = Fr::from(31415);

            let n: usize = 5;
            let t: usize = 1;
            let coord_addr = "127.0.0.1";
            let coord_port = 12348;
            let coord = OffChainCoordinator::start_coord_from_cert(coord_addr, coord_port, [0u8; 32], n as u64, t as u64, public_keys[..5].to_vec().clone(), 2, server_cert()).await;
            let timestamp = coord.get_timestamp();
            let barrier = Arc::new(Barrier::new(3));

            // MPC node (designated party), also RPC client
            tokio::spawn({
                let barrier = barrier.clone();

                let mut coords = Vec::new();
                for i in 0..3 {
                    let coord =
                        OffChainCoordinator::start_rpc_client_from_cert(coord_addr, coord_port, timestamp, 1, 1, certs[i].clone()).await;
                    coords.push(coord);
                }

                // simulate 2 * t + 1 = 3 RPC nodes for client authentication; we just have one
                // node here, but we use 3 RPC nodes to make the process work
                let mut rng = test_rng();
                let mask_shares = RobustShare::compute_shares(correct_mask, n, t, None, &mut rng).unwrap();
                let output_shares = RobustShare::compute_shares(correct_output, n, t, None, &mut rng).unwrap();

                let mut node_rpcs = Vec::new();
                for i in 0..3 {
                    let mut node_rpc = super::node_rpc::NodeRPCServer::start_from_cert(&node_rpc_addrs[i].0,
                        node_rpc_addrs[i].1, certs[i].clone()).await;

                    node_rpc.add_mask_share(0, mask_shares[i].clone()).await;
                    node_rpcs.push(node_rpc);
                }

                async move {
                    coords[0].trigger_pp().await.unwrap();
                    coords[0].wait_for_pp().await.unwrap();
                    coords[0].init_input_masks().await.unwrap();
                    coords[0].wait_for_input_mask_init().await.unwrap();
                    let client_to_index = coords[0].wait_for_indices(1).await.unwrap();  // called by node
                    for (c, i) in &client_to_index {
                        println!("NODE: client {:?} reserved index {}", c, i);
                        for node_rpc in node_rpcs.iter_mut() {
                            // just received by one node here, but in reality would be received by
                            // all nodes, so we simulate this here for more nodes
                            node_rpc.add_reserved_index(c.to_vec(), *i).await;
                        }
                    }

                    coords[0].trigger_input().await.unwrap();
                    coords[0].wait_for_input().await.unwrap();
                    let client_to_masked_input = coords[0].wait_for_inputs(1, vec![mask_shares[0].clone()]).await.unwrap();
                    for (c, masked_inputs) in client_to_masked_input {
                        for masked_input in masked_inputs {
                            println!("NODE: client {:?} submitted masked input {}", c, masked_input.share[0]);
                        }
                    }
                    coords[0].trigger_mpc().await.unwrap();
                    coords[0].wait_for_mpc().await.unwrap();
                    coords[0].trigger_outputs().await.unwrap();
                    coords[0].wait_for_outputs().await.unwrap();
                    for (i, coord) in coords.iter_mut().enumerate() {
                        coord.send_output_shares(public_keys[5].clone(), public_keys[5].clone(), vec![output_shares[i].clone()]).await.unwrap();
                    }
                    coords[0].finalize().await.unwrap();

                    barrier.wait().await;
                }
            });

            // MPC client, also RPC client
            tokio::spawn({
                let barrier = barrier.clone();
                let cert = certs[5].clone();
                let mut coord =
                    OffChainCoordinator::start_rpc_client_from_cert(coord_addr, coord_port, timestamp, 1, 1, cert.clone()).await;
                let rpc_client = super::node_rpc::NodeRPCClient::start_rpc_client_from_cert(t, node_rpc_addrs.clone(), cert.clone()).await;
                async move {
                    coord.wait_for_pp().await.unwrap();
                    coord.wait_for_input_mask_init().await.unwrap();

                    let indices = coord.obtain_mask_indices(1).await.expect("obtaining mask indices failed");
                    assert_eq!(indices.len(), 1);
                    println!("CLIENT: obtained index {}", indices[0]);

                    let mask = rpc_client.receive_mask().await;
                    assert_eq!(mask, correct_mask);

                    coord.wait_for_input().await.unwrap();

                    let masked_input = mask + Fr::from(1337);
                    coord.send_masked_input(Fr::from(masked_input), indices[0]).await.unwrap();

                    coord.wait_for_mpc().await.unwrap();
                    coord.wait_for_outputs().await.unwrap();
                    let outputs = coord.obtain_outputs().await.unwrap();
                    println!("CLIENT: obtained outputs {:?}", outputs);
                    assert_eq!(outputs.len(), 1);
                    assert_eq!(outputs[0], correct_output);

                    barrier.wait().await;
                }
            });

            barrier.wait().await;
        }

        #[tokio::test]
        async fn stop_rpc_server() {
            // TODO: try using stop_tx
        }

        //#[tokio::test]
        //async fn gen() {
        //    use std::fs;
        //    let cert = self_signed_certs::client_cert();
        //    let cert_der = cert.cert.der().to_vec();
        //    let key_der = cert.signing_key.serialize_der();

        //    fs::write("cert.crt", cert_der).unwrap();
        //    fs::write("key.der", key_der).unwrap();
        //}
    }
}
