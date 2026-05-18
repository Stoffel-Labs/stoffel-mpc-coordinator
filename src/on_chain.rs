use super::{Coordinator, CoordinatorError};
use crate::{Round, ShareBound};
use alloy::providers::WalletProvider;
use alloy::{
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
    signers::Signer,
    sol_types::SolValue,
};
use alloy_primitives::{Address, Bytes, Keccak256, Signature, U256};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use futures_util::stream::StreamExt;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, single_shot_seal, Deserializable, OpModeR, OpModeS, Serializable,
};
use p256::{pkcs8::DecodePrivateKey, SecretKey};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::str::FromStr;
use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator;
use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator::StoffelCoordinatorErrors;
use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator::StoffelCoordinatorInstance;

type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

pub type ClientIdentity = Address;

#[derive(Clone)]
pub struct OnChainCoordinator<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>> {
    coord: StoffelCoordinatorInstance<P>,
    pub contract_block: u64,
    t: u64,
    n_outputs: Option<u64>,
    key_der: Option<Vec<u8>>,
    _marker: std::marker::PhantomData<(F, S)>,
}

/// RPC interface on the node.
pub mod node_rpc {
    use alloy::{
        providers::{Provider, WalletProvider},
        sol_types::SolValue,
    };
    use alloy_primitives::{Address, Keccak256, Signature, SignatureError};
    use ark_ff::FftField;
    use jsonrpsee::{
        async_client::Client,
        core::{to_json_raw_value, SubscriptionResult},
        proc_macros::rpc,
        server::{RpcModule, ServerHandle},
        types::{error::ErrorCode, ErrorObjectOwned},
        PendingSubscriptionSink, SubscriptionSink,
    };
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use super::ClientIdentity;
    use crate::{rpc::ClientInfo, CoordinatorError, NodeRPCError, ShareBound};
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};
    use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator::StoffelCoordinatorInstance;
    use tokio::task::JoinHandle;
    use tokio::task::JoinSet;

    async fn verify_client_sig(
        base_nonce: u64,
        i: u64,
        addr: Address,
        sig_bytes: Vec<u8>,
    ) -> Result<bool, SignatureError> {
        let sig = Signature::from_raw(&sig_bytes)?;

        let hash = {
            let mut hasher = Keccak256::new();
            hasher.update((base_nonce + i).abi_encode());
            hasher.finalize()
        };

        let sig_addr = sig.recover_address_from_msg(hash)?;

        Ok(sig_addr == addr)
    }

    /// Exterior representation of the node-side RPC interface.
    pub struct NodeRPCServer<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>> {
        pub(super) rpc_server: Arc<Mutex<NodeRPCServerShared<P, F, S>>>,
        addr: String,
        port: u16,
        server_handle: JoinHandle<()>,
    }

    /// Exterior representation of an RPC client that interfaces with the node-side RPC interface.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        node_rpcs: Vec<Client>,
        t: usize,
        _marker: std::marker::PhantomData<(F, S)>,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        /// Start an RPC client from a certificate generated using rcgen.
        pub async fn start_rpc_client_from_cert(
            t: usize,
            addrs: Vec<(String, u16)>,
            client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        ) -> Self {
            Self::start_rpc_client(
                t,
                addrs,
                client_cert.cert.der().to_vec(),
                client_cert.signing_key.serialize_der(),
            )
            .await
        }

        /// Start an RPC client from a raw certificate and corresponding private key in DER format.
        /// The information is the same as for `start_rpc_client_from_cert`, but the format
        /// differs.
        pub async fn start_rpc_client(
            t: usize,
            addrs: Vec<(String, u16)>,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Self {
            let node_rpcs: Vec<Client> = futures_util::future::join_all(
                addrs.iter().map(|(addr, port)| {
                    crate::self_signed_certs::setup_client(
                        addr,
                        *port,
                        cert_der.clone(),
                        key_der.clone(),
                    )
                }),
            )
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("failed to connect to node RPC");

            Self {
                node_rpcs,
                t,
                _marker: std::marker::PhantomData,
            }
        }

        /// Returns a mask whose index has been previously reserved by the client by receiving the
        /// individual shares from nodes and reconstructing the mask from them.
        pub async fn receive_mask(
            &self,
            sig: Vec<u8>,
            addr: Address,
        ) -> Result<S::SecretType, CoordinatorError> {
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc.receive_mask_share(sig.clone(), addr).await.unwrap();
                share_futures.spawn(async move { sub.next().await });
            }

            let mut mask_shares = Vec::new();

            while let Some(share_bytes) = share_futures.join_next().await {
                let share = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                    share_bytes.unwrap().unwrap().unwrap().as_slice(),
                )
                .unwrap();
                mask_shares.push(share);

                if mask_shares.len() >= 2 * self.t + 1 {
                    match S::recover_secret(&mask_shares, 4 * self.t + 1, self.t) {
                        Ok((_, mask)) => {
                            return Ok(mask);
                        }
                        Err(_) => {
                            return Err(CoordinatorError::MaskReconstructionFailed(
                                mask_shares.len(),
                            ));
                        }
                    }
                }
            }

            Err(CoordinatorError::MaskReconstructionFailed(
                mask_shares.len(),
            ))
        }
    }

    impl<P: Provider + WalletProvider + Clone + 'static, F: FftField, S: ShareBound<F>>
        NodeRPCServer<P, F, S>
    {
        /// Start the node-side RPC server from a certificate generated using rcgen.
        pub async fn start_from_cert(
            addr: &str,
            port: u16,
            coord: StoffelCoordinatorInstance<P>,
            cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        ) -> Self {
            Self::start(
                addr,
                port,
                coord,
                cert.cert.der().to_vec(),
                cert.signing_key.serialize_der(),
            )
            .await
        }

        pub async fn start(
            addr: &str,
            port: u16,
            coord: StoffelCoordinatorInstance<P>,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Self {
            let base_nonce = super::u256_to_u64(
                coord
                    .baseNonce()
                    .call()
                    .await
                    .expect("failed to fetch base nonce"),
            )
            .expect("base nonce does not fit in u64");
            let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerShared::new(coord, base_nonce)));
            let server_handle = crate::rpc::start_coord::<NodeRPCServerConnection<P, F, S>>(
                addr,
                port,
                cert_der,
                key_der,
                rpc_server_data.clone(),
            )
            .await
            .expect("failed to start node RPC server");
            Self {
                rpc_server: rpc_server_data,
                addr: String::from(addr),
                port,
                server_handle,
            }
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone()
        }

        pub async fn ids_and_addrs(&self) -> Vec<(Vec<u8>, ClientIdentity)> {
            let d = self.rpc_server.lock().await;

            d.ids_and_addrs
                .iter()
                .filter(|(_, _, sig)| sig.is_none())
                .map(|(id, addr, _)| (id.clone(), *addr))
                .collect()
        }

        pub async fn reset(&mut self) {
            let mut d = self.rpc_server.lock().await;
            let base_nonce = super::u256_to_u64(
                d.coord
                    .baseNonce()
                    .call()
                    .await
                    .expect("failed to fetch base nonce"),
            )
            .expect("base nonce does not fit in u64");
            d.index_to_client.clear();
            d.client_to_index.clear();
            d.authenticated.clear();
            d.sinks.clear();
            d.mask_shares.clear();
            d.ids_and_addrs.clear();
            d.base_nonce = base_nonce;
        }

        // called when the client has reserved indices at the coordinator
        pub async fn add_reserved_index(
            &mut self,
            addr: ClientIdentity,
            i: u64,
        ) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.index_to_client.contains_key(&i));
            d.index_to_client.insert(i, addr);
            d.client_to_index.insert(addr, i);

            if let Some(entry) = d.ids_and_addrs.iter_mut().find(|(_, a, _)| *a == addr) {
                assert!(entry.2.is_some(), "client entry for addr must be pending when add_reserved_index is called before authentication");
                let sig_bytes = entry.2.take().unwrap();
                let tls_id = entry.0.clone();

                let authenticated = verify_client_sig(d.base_nonce, i, addr, sig_bytes)
                    .await
                    .unwrap_or(false);

                if !authenticated {
                    return Err(NodeRPCError::AuthenticationFailed(tls_id));
                }

                d.authenticated.insert(addr);

                if let Some(share) = d.mask_shares.get(&i) {
                    if let Some(sink) = d.sinks.get(&addr) {
                        let mut share_bytes = Vec::new();
                        share
                            .serialize_compressed(&mut share_bytes)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        let json = to_json_raw_value(&share_bytes)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    }
                }
            }

            Ok(())
        }

        // called when preprocessing has generated the mask shares
        pub async fn add_mask_share(&mut self, i: u64, share: S) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.mask_shares.contains_key(&i));
            d.mask_shares.insert(i, share.clone());

            if let Some(addr) = d.index_to_client.get(&i) {
                if d.authenticated.contains(addr) {
                    if let Some(sink) = d.sinks.get(addr) {
                        let mut share_bytes = Vec::new();
                        share
                            .serialize_compressed(&mut share_bytes)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        let json = to_json_raw_value(&share_bytes)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    }
                }
            }

            Ok(())
        }
    }

    /// Represents a connection with a client on the node-side RPC server.
    pub struct NodeRPCServerConnection<
        P: Provider + WalletProvider + Clone,
        F: FftField,
        S: ShareBound<F>,
    > {
        /// Reference to the server's shared state
        d: Arc<Mutex<NodeRPCServerShared<P, F, S>>>,
        /// The MPC client's node-facing identity
        id: Vec<u8>,
    }

    impl<P: Provider + WalletProvider + Clone + 'static, F: FftField, S: ShareBound<F>>
        crate::rpc::RPCServerConnection for NodeRPCServerConnection<P, F, S>
    {
        type Internal = NodeRPCServerShared<P, F, S>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self>
        where
            Self: Sized,
        {
            crate::on_chain::node_rpc::OnChainNodeRPCServer::into_rpc(self)
        }
    }

    pub struct NodeRPCServerShared<
        P: Provider + WalletProvider + Clone,
        F: FftField,
        S: ShareBound<F>,
    > {
        index_to_client: HashMap<u64, ClientIdentity>,
        client_to_index: HashMap<ClientIdentity, u64>,
        authenticated: HashSet<ClientIdentity>,

        // sinks stored if some info to send shares to clients is still missing, but client has
        // already sent the RPC request
        sinks: HashMap<ClientIdentity, SubscriptionSink>,
        mask_shares: HashMap<u64, S>,
        // (tls_id, addr, pending_sig): pending_sig is Some while awaiting index reservation,
        // None once authenticated
        ids_and_addrs: Vec<(Vec<u8>, ClientIdentity, Option<Vec<u8>>)>,
        clients: HashMap<Vec<u8>, ClientInfo>,
        base_nonce: u64,
        coord: StoffelCoordinatorInstance<P>,
        _marker: std::marker::PhantomData<F>,
    }

    impl<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>>
        NodeRPCServerShared<P, F, S>
    {
        pub fn new(coord: StoffelCoordinatorInstance<P>, base_nonce: u64) -> Self {
            Self {
                index_to_client: HashMap::new(),
                client_to_index: HashMap::new(),
                authenticated: HashSet::new(),
                sinks: HashMap::new(),
                mask_shares: HashMap::new(),
                ids_and_addrs: Vec::new(),
                clients: HashMap::new(),
                base_nonce,
                coord,
                _marker: std::marker::PhantomData,
            }
        }
    }

    impl<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>>
        crate::rpc::RPCServerShared for NodeRPCServerShared<P, F, S>
    {
        fn add_client(
            &mut self,
            cert_der: Vec<u8>,
            client_handle: JoinHandle<()>,
            stop_tx: ServerHandle,
        ) {
            self.clients.insert(
                cert_der.clone(),
                ClientInfo {
                    cert: cert_der,
                    thread: client_handle,
                    stop_tx,
                },
            );
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
    impl<P: Provider + WalletProvider + Clone + 'static, F: FftField, S: ShareBound<F>>
        OnChainNodeRPCServer for NodeRPCServerConnection<P, F, S>
    {
        async fn receive_mask_share(
            &self,
            pending: PendingSubscriptionSink,
            sig_bytes: Vec<u8>,
            addr: Address,
        ) -> SubscriptionResult {
            use OnChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

            // each client can only authenticate one address and each address can only be
            // authenticated once
            if d.ids_and_addrs
                .iter()
                .any(|(id, prev_addr, _)| self.id == *id || addr == *prev_addr)
            {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::InvalidParams.code(),
                        format!("Client {} already requested mask share", addr),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            }

            // pending_sig is None if verified immediately, Some if deferred until index arrives
            let pending_sig: Option<Vec<u8>>;

            if let Some(&i) = d.client_to_index.get(&addr) {
                // reservation already known: verify immediately
                let authenticated = verify_client_sig(d.base_nonce, i, addr, sig_bytes)
                    .await
                    .unwrap_or(false);

                if !authenticated {
                    pending
                        .reject(ErrorObjectOwned::owned(
                            ErrorCode::InvalidParams.code(),
                            format!("Authentication failed for address {}", addr),
                            None::<()>,
                        ))
                        .await;
                    return Ok(());
                }

                d.authenticated.insert(addr);

                if let Some(share) = d.mask_shares.get(&i) {
                    let mut share_bytes = Vec::new();
                    match share.serialize_compressed(&mut share_bytes) {
                        Ok(_) => {}
                        Err(e) => {
                            pending
                                .reject(ErrorObjectOwned::owned(
                                    ErrorCode::ServerError(SerializationError as i32).code(),
                                    format!("Serializing share bytes failed: {e}"),
                                    None::<()>,
                                ))
                                .await;
                            return Ok(());
                        }
                    };
                    let json = match to_json_raw_value(&share_bytes) {
                        Ok(j) => j,
                        Err(e) => {
                            pending
                                .reject(ErrorObjectOwned::owned(
                                    ErrorCode::ServerError(SerializationError as i32).code(),
                                    format!("Converting serialized shares to JSON failed: {e}"),
                                    None::<()>,
                                ))
                                .await;
                            return Ok(());
                        }
                    };
                    let sink = pending.accept().await?;
                    sink.send(json).await?;
                    d.ids_and_addrs.push((self.id.clone(), addr, None));
                    return Ok(());
                }
                // share not yet available: fall through to store sink
                pending_sig = None;
            } else {
                // reservation not yet known: store sig for verification once index arrives
                pending_sig = Some(sig_bytes);
            }

            let sink = pending.accept().await?;
            d.sinks.insert(addr, sink);
            d.ids_and_addrs.push((self.id.clone(), addr, pending_sig));

            Ok(())
        }
    }
}

fn u256_to_u64(x: U256) -> Option<u64> {
    x.try_into().ok()
}

fn to_bytes<T: CanonicalSerialize>(x: T) -> Result<Bytes, SerializationError> {
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes)?;

    Ok(Bytes::from(bytes))
}

fn from_bytes<T: CanonicalDeserialize>(x: Bytes) -> Result<T, SerializationError> {
    let element = T::deserialize_compressed(x.as_ref())?;
    Ok(element)
}

pub async fn generate_client_sig(
    base_nonce: u64,
    i: u64,
    signer: PrivateKeySigner,
) -> Result<Signature, alloy::signers::Error> {
    let hash = {
        let mut hasher = Keccak256::new();
        hasher.update((base_nonce + i).abi_encode());
        hasher.finalize()
    };
    let sig = signer.sign_message(hash.as_slice()).await?;

    Ok(sig)
}

pub async fn ws_connect(
    addr: &str,
    wallet_sk: &str,
) -> impl Provider + WalletProvider + Clone + 'static {
    let ws = WsConnect::new(addr);
    let wallet =
        EthereumWallet::from(PrivateKeySigner::from_str(wallet_sk).expect("invalid private key"));

    match ProviderBuilder::new().wallet(wallet).connect_ws(ws).await {
        Ok(p) => p,
        Err(e) => {
            panic!(
                "could not connect to Ethereum node at {} via WebSockets: {}",
                addr, e
            );
        }
    }
}

pub async fn setup_coord<T, F: FftField, S: ShareBound<F>>(
    eth: T,
    contract_addr: Address,
    t: u64,
    n_outputs: u64,
    key_der: Option<Vec<u8>>,
) -> OnChainCoordinator<T, F, S>
where
    T: Provider + WalletProvider + Clone,
{
    let coord_instance = StoffelCoordinator::new(contract_addr, eth.clone());
    OnChainCoordinator::new(coord_instance, t, n_outputs, key_der).await
}

impl<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>>
    OnChainCoordinator<P, F, S>
{
    pub async fn new(
        coord: StoffelCoordinatorInstance<P>,
        t: u64,
        n_outputs: u64,
        key_der: Option<Vec<u8>>,
    ) -> Self {
        let contract_block = Self::coord_creation_block(&coord).await;
        Self {
            coord,
            contract_block,
            t,
            n_outputs: Some(n_outputs),
            key_der,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn coord(&self) -> StoffelCoordinatorInstance<P> {
        self.coord.clone()
    }

    async fn coord_creation_block(coord: &StoffelCoordinatorInstance<P>) -> u64 {
        let x = coord
            .creationBlock()
            .call()
            .await
            .expect("sending TX failed");
        u256_to_u64(x).expect("impossible bug: block number does not fit into u64")
    }

    pub async fn base_nonce(&self) -> u64 {
        let base_nonce = self
            .coord
            .baseNonce()
            .call()
            .await
            .expect("sending TX failed");
        u256_to_u64(base_nonce).expect("impossible bug: block number does not fit into u64")
    }

    /// Resets local state after the smart contract has been reset, so subsequent event listeners
    /// do not replay events from previous rounds.
    pub async fn reset(&mut self) -> Result<(), CoordinatorError> {
        self.contract_block = self
            .coord
            .provider()
            .get_block_number()
            .await
            .map_err(|e| {
                CoordinatorError::EthereumError(format!(
                    "error getting current block number: {}",
                    e
                ))
            })?;
        Ok(())
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        let result = match round {
            Round::Idle => {
                panic!();
            }
            Round::Preprocessing => self.coord.startPreprocessing().send().await,
            Round::InputMaskReservation => self.coord.reserveInputMasks().send().await,
            Round::InputCollection => self.coord.collectInputs().send().await,
            Round::MPCExecution => self.coord.startMpc().send().await,
            Round::OutputDistribution => self.coord.sendOutputs().send().await,
            Round::ProgramFinished => self.coord.finalize().send().await,
        };
        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to trigger input phase to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to trigger input phase: {}",
                e
            ))),
        }
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

impl<P: Provider + WalletProvider + Clone, F: FftField, S: ShareBound<F>> Coordinator<F, S>
    for OnChainCoordinator<P, F, S>
{
    type ClientIdentity = Address;

    async fn start_preprocessing(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.startPreprocessing();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to start preprocessing to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to start preprocessing: {}",
                e
            ))),
        }
    }

    async fn reserve_input_masks(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.reserveInputMasks();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to reserve input masks to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to reserve input masks: {}",
                e
            ))),
        }
    }

    async fn collect_inputs(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.collectInputs();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to collect inputs to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to collect inputs: {}",
                e
            ))),
        }
    }

    async fn start_mpc(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.startMpc();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to start MPC to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to start MPC: {}",
                e
            ))),
        }
    }

    async fn send_output(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.sendOutputs();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to send outputs to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to send outputs: {}",
                e
            ))),
        }
    }

    async fn finalize(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.finalize();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to finalize to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to finalize: {}",
                e
            ))),
        }
    }

    async fn reset_coord(&self) -> Result<(), CoordinatorError> {
        let builder = self.coord.resetCoordinator();
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to reset coordinator to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to reset coordinator: {}",
                e
            ))),
        }
    }

    async fn wait_for_indices(
        &self,
        n_clients: u64,
    ) -> Result<HashMap<ClientIdentity, u64>, CoordinatorError> {
        let mut addr_to_i = HashMap::new();

        // spawn thread to receive all ReservedInputEvents
        let mut events = self
            .coord
            .ReservedInputEvent_filter()
            .from_block(self.contract_block)
            .watch()
            .await
            .unwrap()
            .into_stream();

        while let Some(Ok((
            StoffelCoordinator::ReservedInputEvent {
                client,
                reservedIndex,
            },
            _,
        ))) = events.next().await
        {
            addr_to_i.insert(
                client,
                u256_to_u64(reservedIndex).expect("conversion from U256 to u64 failed"),
            );
            eprintln!(
                "[party] Recorded reserved mask index {} for client address {:?}",
                reservedIndex, client
            );
            if addr_to_i.len() as u64 == n_clients {
                break;
            }
        }

        Ok(addr_to_i)
    }

    async fn wait_for_inputs(
        &self,
        n_clients: u64,
        mask_shares: Vec<S>,
    ) -> Result<HashMap<ClientIdentity, Vec<S>>, CoordinatorError> {
        let mut events = match self
            .coord
            .MaskedInputEvent_filter()
            .from_block(self.contract_block)
            .watch()
            .await
        {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!(
                    "error setting up event listener for MaskedInputEvent events: {}",
                    e
                )));
            }
        };

        let mut inputs: HashMap<ClientIdentity, Vec<S>> = HashMap::new();
        for _ in 0..n_clients {
            match events.next().await {
                Some(Ok((
                    StoffelCoordinator::MaskedInputEvent {
                        client,
                        maskedInput,
                        reservedIndex,
                    },
                    _,
                ))) => {
                    let i: usize = u256_to_u64(reservedIndex)
                        .ok_or(CoordinatorError::U256ToU64Error)?
                        .try_into()
                        .map_err(|_| CoordinatorError::U256ToU64Error)?;
                    let mask_share = &mask_shares[i];
                    let masked_input_value = from_bytes::<S::SecretType>(maskedInput)
                        .map_err(|_| CoordinatorError::DeserializationError)?;
                    let input = S::compute_masked_input(masked_input_value, mask_share)
                        .map_err(|_| CoordinatorError::ShareError)?;

                    inputs.insert(client, vec![input]);
                }
                _ => {
                    return Err(CoordinatorError::EthereumError(
                        "event stream ended unexpectedly while waiting for MaskedInputEvent events"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(inputs)
    }

    async fn wait_for_round(&self, round: Round) -> Result<(), CoordinatorError> {
        macro_rules! wait_for_event {
            ($filter:expr, $name:expr) => {{
                let watcher = $filter
                    .from_block(self.contract_block)
                    .watch()
                    .await
                    .map_err(|e| {
                        CoordinatorError::EthereumError(format!(
                            "error setting up event listener for {} events: {}",
                            $name, e
                        ))
                    })?;

                let mut stream = watcher.into_stream();

                match stream.next().await {
                    Some(Ok(_)) => Ok(()),
                    _ => Err(CoordinatorError::EthereumError(format!(
                        "event stream ended unexpectedly while waiting for {} events",
                        $name
                    ))),
                }
            }};
        }

        match round {
            Round::Idle => panic!(),
            Round::Preprocessing => wait_for_event!(
                self.coord.PreprocessingStarted_filter(),
                "PreprocessingStarted"
            ),
            Round::InputCollection => wait_for_event!(
                self.coord.InputCollectionStarted_filter(),
                "InputCollectionStarted"
            ),
            Round::InputMaskReservation => wait_for_event!(
                self.coord.InputMaskReservationStarted_filter(),
                "InputMaskReservationStarted"
            ),
            Round::MPCExecution => wait_for_event!(self.coord.MPCStarted_filter(), "MPCStarted"),
            Round::OutputDistribution => wait_for_event!(
                self.coord.OutputSendingStarted_filter(),
                "OutputSendingStarted"
            ),
            Round::ProgramFinished => {
                wait_for_event!(self.coord.ExecutionDone_filter(), "ExecutionDone")
            }
        }
    }

    async fn reserve_mask_index(&mut self, i: u64) -> Result<(), CoordinatorError> {
        let builder = self.coord.reserveMaskIndex(U256::from(i));
        let tx = builder.send().await.expect("failed to send TX");
        let receipt = tx.get_receipt().await.expect("failed to get receipt");

        if !receipt.status() {
            return Err(CoordinatorError::EthereumError(
                "invalid receipt sending transaction to obtain input mask indices".to_string(),
            ));
        }

        // TODO: check if reservation successful

        Ok(())
    }

    async fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> Result<(), CoordinatorError> {
        let masked_input_bytes =
            to_bytes(masked_input).map_err(|_| CoordinatorError::SerializationError)?;
        let builder = self
            .coord
            .submitMaskedInput(masked_input_bytes, U256::from(i));
        match builder.send().await {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to submit masked inputs be mined: {}",
                    e
                ))),
            },
            Err(e) => {
                let msg = if let Some(decoded_error) =
                    e.as_decoded_interface_error::<StoffelCoordinatorErrors>()
                {
                    match decoded_error {
                        StoffelCoordinatorErrors::IndexNotReserved(
                            StoffelCoordinator::IndexNotReserved { client, index },
                        ) => {
                            format!("Index {} not reserved by address {}", index, client)
                        }
                        StoffelCoordinatorErrors::ZeroMaskedInput(
                            StoffelCoordinator::ZeroMaskedInput { client },
                        ) => {
                            format!(
                                "Masked input cannot be zero, but client {} submitted zero",
                                client
                            )
                        }
                        StoffelCoordinatorErrors::AlreadySubmittedInputs(
                            StoffelCoordinator::AlreadySubmittedInputs { client },
                        ) => {
                            format!("Client {} already submitted masked inputs", client)
                        }
                        _ => "Unexpected error".to_string(),
                    }
                } else {
                    "Unknown error".to_string()
                };
                Err(CoordinatorError::EthereumError(format!(
                    "error sending transaction to submit masked inputs: {}",
                    msg
                )))
            }
        }
    }

    async fn obtain_outputs(&self) -> Result<Vec<S::ValueType>, CoordinatorError> {
        let client_sk = {
            let der_bytes = self.key_der.clone().unwrap();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk)
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        let mut events = match self
            .coord
            .EnoughOutputShares_filter()
            .from_block(self.contract_block)
            .topic1(self.coord.provider().default_signer_address())
            .watch()
            .await
        {
            Ok(e) => e.into_stream(),
            Err(e) => {
                return Err(CoordinatorError::EthereumError(format!(
                    "error setting up event listener for MPCStarted events: {}",
                    e
                )));
            }
        };

        while let Some(Ok((StoffelCoordinator::EnoughOutputShares { client: _, shares }, _))) =
            events.next().await
        {
            if (shares.len() as u64) < 2 * self.t + 1 {
                panic!("BUG: less than 2t+1 output shares received, coordinator should make sure this does not happen!!!");
            }

            let mut output_shares = Vec::new();
            for bytes in shares.iter() {
                let (encapped_key_bytes, c): (Vec<u8>, Vec<u8>) =
                    ark_serialize::CanonicalDeserialize::deserialize_compressed(
                        bytes.to_vec().as_slice(),
                    )
                    .map_err(|_| CoordinatorError::DeserializationError)?;
                let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(&encapped_key_bytes)
                    .map_err(|_| CoordinatorError::ParsingEncapsulatedKeyFailed)?;
                let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base,
                    &client_sk,
                    &encapped_key,
                    ENC_INFO,
                    &c,
                    b"",
                )
                .map_err(|_| CoordinatorError::DecryptionError)?;
                let shares: Vec<S> = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                    output_shares_bytes.as_slice(),
                )
                .map_err(|_| CoordinatorError::DeserializationError)?;

                if shares.len() as u64 != self.n_outputs.unwrap() {
                    println!("Some node sent an invalid number of output shares, ignoring.");
                    continue;
                }

                output_shares.push(shares);
            }

            let outputs: Vec<_> = (0..self.n_outputs.unwrap() as usize)
                .filter_map(|i| {
                    // shares for the ith output
                    let shares_i: Vec<_> = output_shares
                        .iter()
                        .map(|shares| shares[i].clone())
                        .collect();

                    // at least 2t+1 shares available as checked previously by the coordinator
                    match S::recover_secret(
                        shares_i.as_slice(),
                        (4 * self.t + 1) as usize,
                        self.t as usize,
                    ) {
                        Ok((_, output_i)) => Some(output_i),
                        Err(_) => {
                            println!(
                                "Reconstruction failed for output {}, waiting for more shares.",
                                i
                            );
                            None
                        }
                    }
                })
                .collect();

            if outputs.len() == self.n_outputs.unwrap() as usize {
                return Ok(outputs);
            }
        }

        Err(CoordinatorError::EthereumError(
            "event stream ended unexpectedly while waiting for EnoughOutputShares events"
                .to_string(),
        ))
    }

    async fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> Result<(), CoordinatorError> {
        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key)
            .map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let mut output_shares_bytes = Vec::new();
        output_shares
            .serialize_compressed(&mut output_shares_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;

        let mut rng = StdRng::from_os_rng();
        let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
            &OpModeS::Base,
            &client_pk,
            ENC_INFO,
            &output_shares_bytes,
            b"",
            &mut rng,
        )
        .map_err(|_| CoordinatorError::EncryptionError)?;
        let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

        let mut bytes = Vec::new();
        c.serialize_compressed(&mut bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;
        let builder = self.coord.sendOutputShares(client_id, Bytes::from(bytes));
        let result = builder.send().await;

        match result {
            Ok(r) => match r.watch().await {
                Ok(_) => Ok(()),
                Err(e) => Err(CoordinatorError::EthereumError(format!(
                    "error waiting for transaction to send output shares to be mined: {}",
                    e
                ))),
            },
            Err(e) => Err(CoordinatorError::EthereumError(format!(
                "error sending transaction to send output shares: {}",
                e
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use ark_bls12_381::Fr;
    use rand::Rng;

    #[test]
    pub fn fr_bytes_conversion() {
        let mut rng = rand::rng();
        for _ in 0..100 {
            let n: u64 = rng.random();
            let fr = Fr::from(n);
            let bytes = to_bytes(fr).unwrap();
            let fr2: Result<Fr, _> = from_bytes(bytes);
            assert!(fr2.is_ok());
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
}
