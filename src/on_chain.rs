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
    fake_coordinator::FakeCoordinator::{MaskedInputEvent, ReservedInputEvent, EnoughPrivateOutputShares },
    fake_coordinator::FakeCoordinator::FakeCoordinatorInstance,
    fake_coordinator::FakeCoordinator,
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
    OpModeR, OpModeS,
};
use p256::{SecretKey, pkcs8::DecodePrivateKey};
use rand::{SeedableRng, rngs::StdRng};
use ark_serialize::CanonicalSerialize;
use alloy::providers::WalletProvider;

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
    use jsonrpsee::{
        core::{SubscriptionResult, to_json_raw_value},
        async_client::Client,
        server::{RpcModule, ServerHandle},
        proc_macros::rpc,
        PendingSubscriptionSink, SubscriptionSink,
        types::{ErrorObjectOwned, error::ErrorCode},
    };

    use async_trait::async_trait;
    use tokio::task::JoinHandle;
    use super::ClientIdentity;
    use crate::{CoordinatorError, rpc::ClientInfo};
    use tokio::task::JoinSet;
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use stoffelmpc_mpc::common::SecretSharingScheme;
    use ark_serialize::CanonicalSerialize;
    use stoffel_solidity_bindings::fake_coordinator::{
        FakeCoordinator, FakeCoordinator::FakeCoordinatorErrors
    };
    use serde::{Serialize, Deserialize};
    use crate::NodeRPCError;

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

        pub async fn receive_mask(&self, sig: Vec<u8>, addr: Address) -> Result<Fr, CoordinatorError> {
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
                    match RobustShare::recover_secret(&mask_shares, 4 * self.t + 1, self.t) {
                        Ok((_, mask)) => {
                            return Ok(mask);
                        }
                        Err(_) => {
                            return Err(CoordinatorError::MaskReconstructionFailed(mask_shares.len()));
                        }
                    }
                }
            }

            Err(CoordinatorError::MaskReconstructionFailed(mask_shares.len()))
        }
    }

    impl<P: Provider + WalletProvider + Clone + 'static> NodeRPCServer<P> {
        pub async fn start_from_cert(addr: &str, port: u16, coord: FakeCoordinatorInstance<P>, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
            Self::start(addr, port, coord, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
        }

        pub async fn ids_and_addrs(&self) -> Vec<(Vec<u8>, ClientIdentity)> {
            self.rpc_server.lock().await.ids_and_addrs.clone()
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

        pub async fn add_auth_status(&mut self, addr: Address) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.auth_status.contains_key(&addr));
            d.auth_status.insert(addr, true);

            if let Some(i) = d.client_to_index.get(&addr) {
                if let Some(share) = d.mask_shares.get(i) {
                    if let Some(sink) = d.sinks.get(&addr) {
                       let mut share_bytes = Vec::new();
                       share.serialize_compressed(&mut share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                       let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                       sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    }
                }
            }

            Ok(())
        }

        // called when the client has reserved indices at the coordinator
        pub async fn add_reserved_index(&mut self, addr: ClientIdentity, i: u64) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.index_to_client.contains_key(&i));
            d.index_to_client.insert(i, addr);
            d.client_to_index.insert(addr, i);

            if d.auth_status.contains_key(&addr) {
                if let Some(share) = d.mask_shares.get(&i) {
                    if let Some(sink) = d.sinks.get(&addr) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                        let json = to_json_raw_value(&share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    }
                }
            }

            Ok(())
        }

        // called when preprocessing has generated the mask shares
        pub async fn add_mask_share(&mut self, i: u64, share: RobustShare<Fr>) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.mask_shares.contains_key(&i));
            d.mask_shares.insert(i, share.clone());

            if let Some(addr) = d.index_to_client.get(&i) {
                if d.auth_status.contains_key(addr) {
                    if let Some(sink) = d.sinks.get(addr) {
                        let mut share_bytes = Vec::new();
                        share.serialize_compressed(&mut share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                        let json = to_json_raw_value(&share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    }
                }
            }

            Ok(())
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

        // sinks stored if some info to send shares to clients is still missing, but client has
        // already sent the RPC request
        sinks: HashMap<ClientIdentity, SubscriptionSink>,
        mask_shares: HashMap<u64, RobustShare<Fr>>,
        ids_and_addrs: Vec<(Vec<u8>, ClientIdentity)>,
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
                ids_and_addrs: Vec::new(),
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

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OnChainNodeRPCServerError {
        SerializationError = 1,
        EthereumError = 2,
    }

    #[async_trait]
    impl<P: Provider + WalletProvider + Clone + 'static> OnChainNodeRPCServer for NodeRPCServerImpl<P> {
        async fn receive_mask_share(&self, pending: PendingSubscriptionSink, sig: Vec<u8>, addr: Address) -> SubscriptionResult {
            use OnChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

            // each client can only authenticate one address and each address can only be
            // authenticated once
            if d.ids_and_addrs.iter().any(|(id, prev_addr)| {
                self.id == *id || addr == *prev_addr
            }) {
                pending.reject(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("Client {} already requested mask share", addr),
                    None::<()>)
                ).await;
                return Ok(());
            }

            // address needs to reserve index before requesting shares, so the contract knows
            // what message the signature signs, since the signed nonce is index-dependent
            match d.auth_status.get(&addr) {
                Some(false) => { panic!("BUG: only true values inserted"); }
                Some(true) => {
                    // enough signatures were sent to authenticate the client, no need to send more;
                    // can send the share immediately if available
                    if let Some(i) = d.client_to_index.get(&addr) {
                        if let Some(share) = d.mask_shares.get(i) {
                            let mut share_bytes = Vec::new();
                            match share.serialize_compressed(&mut share_bytes) {
                                Ok(_) => { },
                                Err(e) => {
                                    pending.reject(ErrorObjectOwned::owned(
                                        ErrorCode::ServerError(SerializationError as i32).code(),
                                        format!("Serializing share bytes failed: {e}"),
                                        None::<()>)
                                    ).await;
                                    return Ok(());
                                }
                            };

                            let json = match to_json_raw_value(&share_bytes) {
                                Ok(j) => j,
                                Err(e) => {
                                    pending.reject(ErrorObjectOwned::owned(
                                        ErrorCode::ServerError(SerializationError as i32).code(),
                                        format!("Converting serialized shares to JSON failed: {e}"),
                                        None::<()>)
                                    ).await;
                                    return Ok(());
                                }
                            };

                            let sink = pending.accept().await?;
                            sink.send(json).await?;

                            return Ok(());
                        }
                    }

                    let sink = pending.accept().await?;
                    d.sinks.insert(addr, sink);
                    d.ids_and_addrs.push((self.id.clone(), addr));

                    Ok(())
                }
                None => {
                    // client not authenticated yet, send signature to coordinator
                    let builder = d.coord.authenticateClient(addr, Bytes::from(sig));
                    let result = builder.send().await;
                    match result {
                        Ok(r) => {
                            r.watch().await?;

                            let sink = pending.accept().await?;
                            d.sinks.insert(addr, sink);
                            d.ids_and_addrs.push((self.id.clone(), addr));

                            Ok(())
                        }
                        Err(e) => {
                            let msg = {
                                if let Some(decoded_error) = e.as_decoded_interface_error::<FakeCoordinatorErrors>() {
                                    match decoded_error {
                                        FakeCoordinatorErrors::NoIndicesReserved(FakeCoordinator::NoIndicesReserved { client }) => {
                                            format!("No indices reserved by address {}", client)
                                        }
                                        FakeCoordinatorErrors::AccessControlUnauthorizedAccount(_) => {
                                            "Unauthorized account".to_string()
                                        }
                                        _ => {
                                            "Unexpected error".to_string()
                                        }
                                    }
                                } else {
                                    "Unknown error".to_string()
                                }
                            };
                            let err = format!("Authenticating client via smart contract failed: {e}: {msg}");

                            println!("{}", err);
                            pending.reject(ErrorObjectOwned::owned(
                                ErrorCode::ServerError(EthereumError as i32).code(),
                                err,
                                None::<()>)
                            ).await;
                            Ok(())
                        }
                    }
                }
            }
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

    pub async fn wait_for_client_auth(&self, addr: Address) -> Result<bool, CoordinatorError> {
        let mut events = match self.coord
            .ClientAuthenticated_filter()
            .from_block(self.contract_block)
            .topic1(addr)
            .watch().await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for ClientAuthenticated events: {}", e)));
            }
       };

        match events.next().await {
            Some(Ok((FakeCoordinator::ClientAuthenticated { client, success }, _))) => {
                Ok(success)
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for ClientAuthenticated event".to_string()))
            }
        }
    }

    pub async fn grant_roles(&self, nodes: Vec<Address>) -> Result<(), CoordinatorError> {
        assert_eq!(nodes.len(), 5);

        let party_role = {
            let builder = self.coord.PARTY_ROLE();
            builder.call().await.expect("sending TX failed")
        };

        // grant party roles
        for i in 0..nodes.len() {
            let builder = self.coord.grantRole(party_role, nodes[i]);
            match builder.send().await {
                Ok(r) => {
                    match r.watch().await {
                        Ok(_) => { },
                        Err(e) => {
                            return Err(CoordinatorError::EthereumError(format!("error waiting for transaction to grant role to be mined: {}", e)));
                        }
                    }
                }
                Err(e) => {
                    return Err(CoordinatorError::EthereumError(format!("error sending transaction to grant role: {}", e)));
                }
            }
        }

        Ok(())
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

impl<P: Provider + WalletProvider + Clone> Coordinator<Fr> for OnChainCoordinator<P> {
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
        let mut events = match self.coord
            .MaskedInputEvent_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for MaskedInputEvent events: {}", e)));
            }
        };

        let mut inputs: HashMap<ClientIdentity, Vec<RobustShare<Fr>>> = HashMap::new();
        for _ in 0..n_clients {
            match events.next().await {
                Some(Ok((MaskedInputEvent { client, maskedInput, reservedIndex }, _))) => {
                    let masked_input = u256_to_fr(maskedInput).ok_or(CoordinatorError::U256ToFrError)?;
                    let i: usize = u256_to_u64(reservedIndex)
                        .ok_or(CoordinatorError::U256ToU64Error)?.try_into()
                        .map_err(|_| CoordinatorError::U256ToU64Error)?;
                    let mask_share = &mask_shares[i];
                    let input = RobustShare::new(
                        masked_input - mask_share.share[0],
                        mask_share.id,
                        mask_share.degree
                    );

                    inputs.insert(client, vec![input]);
                }
                _ => {
                    return Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for MaskedInputEvent events".to_string()));
                }
            }
        }
        Ok(inputs)
    }

    async fn trigger_input(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.collectInputs();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to trigger input phase to be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to trigger input phase: {}", e)))
            }
        }
    }

    async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
        let mut events = match self.coord
            .InputCollectionStarted_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for InputCollectionStarted events: {}", e)));
            }
        };

        match events.next().await {
            Some(Ok((_, _))) => {
                Ok(())
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for InputCollectionStarted events".to_string()))
            }
        }
    }

    async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.startPreprocessing();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to start preprocessing to be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to start preprocessing: {}", e)))
            }
        }
    }

    async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
        let mut events = match self.coord
            .PreprocessingStarted_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for PreprocessingStarted events: {}", e)));
            }
        };

        match events.next().await {
            Some(Ok((_, _))) => {
                Ok(())
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for PreprocessingStarted events".to_string()))
            }
        }
    }

    async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
        let builder = self.coord.reserveInputMasks();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to start reservation of mask indices be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to start reservation of mask indices: {}", e)))
            }
        }
    }

    async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
        let mut events = match self.coord
            .InputMaskReservationStarted_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for InputMaskReservationStarted events: {}", e)));
            }
        };

        match events.next().await {
            Some(Ok((_, _))) => {
                Ok(())
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for InputMaskReservationStarted events".to_string()))
            }
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

        if let Some(indices_u256) = indices {
            let mut indices = Vec::new();
            for i_u256 in indices_u256.iter() {
                let i = u256_to_u64(*i_u256).ok_or(CoordinatorError::U256ToU64Error)?;
                indices.push(i);
            }

            Ok(indices)
        } else {
            panic!("BUG: no ReservedInputEvent found in transaction logs, coordinator should emit such an event!!!");
        }
    }

    async fn send_masked_input(&self, masked_input: Fr, i: u64) -> Result<(), CoordinatorError> {
        let builder = self.coord.submitMaskedInput(fr_to_u256(masked_input), U256::from(i));
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to submit masked inputs be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to submit masked inputs: {}", e)))
            }
        }
    }

    async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.startMPC();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to trigger MPC to be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to trigger MPC: {}", e)))
            }
        }
    }

    async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
        let mut events = match self.coord
            .MPCStarted_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for MPCStarted events: {}", e)));
            }
        };

        match events.next().await {
            Some(Ok((_, _))) => {
                Ok(())
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for MPCStarted events".to_string()))
            }
        }
    }

    async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.sendOutputs();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to trigger output phase to be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to trigger output phase: {}", e)))
            }
        }
    }

    async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
        let mut events = match self.coord
            .OutputSendingStarted_filter()
            .from_block(self.contract_block)
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for OutputSendingStarted events: {}", e)));
            }
        };

        match events.next().await {
            Some(Ok((_, _))) => {
                Ok(())
            }
            _ => {
                Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for OutputSendingStarted events".to_string()))
            }
        }
    }

    async fn finalize(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.finalize();
        match builder.send().await {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to finalize be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to finalize: {}", e)))
            }
        }
    }

    async fn obtain_outputs(&self) -> Result<Vec<Fr>, CoordinatorError> {
        let client_sk = {
            let der_bytes = self.key_der.clone().unwrap();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes).map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk).map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        let mut events = match self.coord
            .EnoughPrivateOutputShares_filter()
            .from_block(self.contract_block)
            .topic1(self.coord.provider().default_signer_address())
            .watch()
            .await {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!("error setting up event listener for MPCStarted events: {}", e)));
            }
        };

        while let Some(Ok((EnoughPrivateOutputShares { client: _, shares }, _))) = events.next().await {
            if (shares.len() as u64) < 2 * self.t + 1 {
                panic!("BUG: less than 2t+1 output shares received, coordinator should make sure this does not happen!!!");
            }

            let mut output_shares = Vec::new();
            for bytes in shares.iter() {
                let (encapped_key_bytes, c): (Vec<u8>, Vec<u8>) = ark_serialize::CanonicalDeserialize::deserialize_compressed(bytes.to_vec().as_slice()).map_err(|_| CoordinatorError::DeserializationError)?;
                let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(&encapped_key_bytes).map_err(|_| CoordinatorError::ParsingEncapsulatedKeyFailed)?;
                let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base, &client_sk, &encapped_key, ENC_INFO, &c, b"",
                ).map_err(|_| CoordinatorError::DecryptionError)?;
                let shares: Vec<RobustShare<Fr>> = ark_serialize::CanonicalDeserialize::deserialize_compressed(output_shares_bytes.as_slice()).map_err(|_| CoordinatorError::DeserializationError)?;

                if shares.len() as u64 != self.n_outputs.unwrap() {
                    println!("Some node sent an invalid number of output shares, ignoring.");
                    continue;
                }

                output_shares.push(shares);
            }

            let outputs: Vec<_> = (0..self.n_outputs.unwrap() as usize).filter_map(|i| {
                // shares for the ith output
                let shares_i: Vec<_> = output_shares.iter().map(|shares| shares[i].clone()).collect();

                // at least 2t+1 shares available as checked previously by the coordinator
                match RobustShare::recover_secret(&shares_i, (4 * self.t + 1) as usize, self.t as usize) {
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

        Err(CoordinatorError::EthereumError("event stream ended unexpectedly while waiting for EnoughPrivateOutputShares events".to_string()))
    }

    async fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<Fr>>) -> Result<(), CoordinatorError> {
        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key).map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let mut output_shares_bytes = Vec::new();
        output_shares.serialize_compressed(&mut output_shares_bytes).map_err(|_| CoordinatorError::SerializationError)?;

        let mut rng = StdRng::from_os_rng();
        let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
            &OpModeS::Base,
            &client_pk,
            ENC_INFO,
            &output_shares_bytes,
            b"",
            &mut rng,
        ).map_err(|_| CoordinatorError::EncryptionError)?;
        let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

        let mut bytes = Vec::new();
        c.serialize_compressed(&mut bytes).map_err(|_| CoordinatorError::SerializationError)?;
        let builder = self.coord.sendPrivateOutputShares(client_id, Bytes::from(bytes));
        let result = builder.send().await;

        match result {
            Ok(r) => {
                match r.watch().await {
                    Ok(_) => { Ok(()) },
                    Err(e) => {
                        Err(CoordinatorError::EthereumError(format!("error waiting for transaction to send output shares to be mined: {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(CoordinatorError::EthereumError(format!("error sending transaction to send output shares: {}", e)))
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

        let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, U256::from(t), initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
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

            let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, U256::from(t), initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
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

            let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, U256::from(t), initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
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

        let contract = FakeCoordinator::deploy(provider.clone(), hash, U256::from(t), initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");

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
        let contract = FakeCoordinator::deploy(provider.clone(), hash, U256::from(t), initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");

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

                node_rpc.add_mask_share(0, mask_shares[i].clone()).await.unwrap();
                node_rpcs.push(node_rpc);
            }

            async move {
                coords[0].trigger_pp().await.unwrap();
                let _ = coords[0].wait_for_pp().await;
                coords[0].init_input_masks().await.unwrap();
                let _ = coords[0].wait_for_input_mask_init().await;
                let client_to_index = coords[0].wait_for_indices(1).await.unwrap();  // called by node
                assert_eq!(client_to_index.len(), 1);
                assert!(client_to_index.contains_key(&ACC[5]));
                for (c, i) in client_to_index {
                    println!("NODE: client {:?} reserved index {}", c, i);
                    for node_rpc in node_rpcs.iter_mut() {
                        // just received by one node here, but in reality would be received by
                        // all nodes, so we simulate this here for more nodes
                        node_rpc.add_reserved_index(c, i).await.unwrap();
                    }
                }

                // just received by one node here, but in reality would be received by
                // all nodes, so we simulate it for more nodes
                if !coords[0].wait_for_client_auth(ACC[5]).await.unwrap() {
                    panic!();
                }
                for node_rpc in node_rpcs.iter_mut() {
                    node_rpc.add_auth_status(ACC[5]).await.unwrap();
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

                // check that all nodes have the same mapping
                for node_rpc in node_rpcs.iter_mut() {
                    let ids_and_addrs = node_rpc.ids_and_addrs().await;
                    assert_eq!(ids_and_addrs.len(), 1);
                    let client_public_key = &ids_and_addrs.iter().find(|(_, addr)| *addr == ACC[5]).expect("client address not found").0;
                    assert_eq!(public_keys[5], *client_public_key);
                }

                // all nodes send output shares to the coordinator
                for (i, coord) in coords.iter_mut().enumerate() {
                    coord.send_output_shares(ACC[5], public_keys[5].clone(), vec![output_shares[i].clone()]).await.unwrap();
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
                let mask = rpc_client.receive_mask(sig.into(), ACC[5]).await.unwrap();
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
