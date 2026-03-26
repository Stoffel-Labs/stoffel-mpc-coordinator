use ark_ff::FftField;
use jsonrpsee::{core::{SubscriptionResult, RpcResult, to_json_raw_value}, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Serialize, Deserialize};
use crate::{Coordinator, CoordinatorError, rpc::{ClientInfo, FieldElement}};
use events::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use async_trait::async_trait;
use jsonrpsee::server::RpcModule;
use jsonrpsee::async_client::Client;
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
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use CoordinatorRPCError::*;

type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

type ClientIdentity = Vec<u8>;

pub mod node_rpc {
    use ark_ff::FftField;
    use std::collections::HashMap;
    use std::marker::PhantomData;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use jsonrpsee::{core::{SubscriptionResult, to_json_raw_value}, async_client::Client, server::RpcModule, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::ServerHandle, types::{ErrorObjectOwned, error::ErrorCode}};
    use async_trait::async_trait;
    use tokio::task::JoinHandle;
    use super::ClientIdentity;
    use crate::{CoordinatorError, rpc::ClientInfo};
    use tokio::task::JoinSet;
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use stoffelmpc_mpc::common::SecretSharingScheme;
    use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
    use crate::NodeRPCError;
    use serde::{Serialize, Deserialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OffChainNodeRPCServerError {
        SerializationError = 1,
    }

    #[rpc(server, client)]
    pub trait OffChainNodeRPC {
        #[subscription(name = "sub_receive_mask_share", unsubscribe = "unsub_receive_mask_share", item = Vec<u8>)]
        async fn receive_mask_share(&self) -> SubscriptionResult;
    }

    pub struct NodeRPCServer<F: FftField> {
        rpc_server: Arc<Mutex<NodeRPCServerInternal<F>>>,
        addr: String,
        port: u16,
        server_handle: JoinHandle<()>,
    }

    pub struct NodeRPCClient<F: FftField> {
        node_rpcs: Vec<Client>,
        t: usize,
        _phantom: PhantomData<F>,
    }

    impl<F: FftField> NodeRPCClient<F> {
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
                t,
                _phantom: PhantomData,
            }
        }

        pub async fn receive_mask(&self) -> Result<F, CoordinatorError> {
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc.receive_mask_share().await.unwrap();
                share_futures.spawn(async move { sub.next().await });
            }

            let mut mask_shares: Vec<RobustShare<F>> = Vec::new();

            while let Some(share_bytes) = share_futures.join_next().await {
                let share: RobustShare<F> = CanonicalDeserialize::deserialize_compressed(
                    share_bytes.unwrap().unwrap().unwrap().as_slice(),
                ).unwrap();
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

    impl<F: FftField> NodeRPCServer<F> {
        pub async fn start_from_cert(addr: &str, port: u16, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
            Self::start(addr, port, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
        }

        pub async fn start(addr: &str, port: u16, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
            let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::<F>::new()));
            let server_handle = crate::rpc::start_coord::<NodeRPCServerImpl<F>>(addr, port, cert_der, key_der, rpc_server_data.clone()).await;
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
        pub async fn add_reserved_index(&mut self, id: ClientIdentity, i: u64) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            if d.index_to_client.contains_key(&i) {
                return Err(NodeRPCError::IndexAlreadyAdded);
            }

            d.index_to_client.insert(i, id.clone());
            d.client_to_index.insert(id.clone(), i);

            // if mask share is there and share has been requested, send it
            if let Some(share) = d.mask_shares.get(&i) {
                if let Some(sink) = d.sinks.get(&id) {
                    let mut share_bytes = Vec::new();
                    share.serialize_compressed(&mut share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                    let json = to_json_raw_value(&share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                }
            }

            Ok(())
        }

        // called when preprocessing has generated the mask shares
        pub async fn add_mask_share(&mut self, i: u64, share: &RobustShare<F>) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.mask_shares.contains_key(&i));

            // if client already registered and has a sink, send the share now
            if let Some(id) = d.index_to_client.get(&i) {
                if let Some(sink) = d.sinks.get(id) {
                    let mut share_bytes = Vec::new();
                    share.serialize_compressed(&mut share_bytes).map_err(|_| NodeRPCError::SerializationError)?;
                    let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                }
            }

            d.mask_shares.insert(i, share.clone());

            Ok(())
        }
    }

    pub struct NodeRPCServerImpl<F: FftField> {
        d: Arc<Mutex<NodeRPCServerInternal<F>>>,
        id: Vec<u8>
    }

    impl<F: FftField> crate::rpc::RPCServerImpl for NodeRPCServerImpl<F> {
        type Internal = NodeRPCServerInternal<F>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self> where Self: Sized {
            crate::off_chain::node_rpc::OffChainNodeRPCServer::into_rpc(self)
        }
    }

    pub struct NodeRPCServerInternal<F: FftField> {
        index_to_client: HashMap<u64, ClientIdentity>,
        client_to_index: HashMap<ClientIdentity, u64>,
        sinks: HashMap<ClientIdentity, SubscriptionSink>,
        mask_shares: HashMap<u64, RobustShare<F>>,
        clients: HashMap<Vec<u8>, ClientInfo>,
    }

    impl<F: FftField> crate::rpc::RPCServerInternal for NodeRPCServerInternal<F> {
        fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle) {
            self.clients.insert(cert_der.clone(), ClientInfo { cert: cert_der, thread: client_handle, stop_tx });
        }
    }

    impl<F: FftField> NodeRPCServerInternal<F> {
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
    impl<F: FftField> OffChainNodeRPCServer for NodeRPCServerImpl<F> {
        async fn receive_mask_share(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

            // each client can only request shares once from a node
            if d.sinks.contains_key(&self.id) {
                pending.reject(ErrorObjectOwned::owned(
                        ErrorCode::InvalidParams.code(),
                        format!("Client {:?} already requested mask share", self.id),
                        None::<()>)
                ).await;
                return Ok(());
            }

            if let Some(i) = d.client_to_index.get(&self.id) {
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
            d.sinks.insert(self.id.clone(), sink);

            Ok(())
        }
    }
}


pub mod events {
    use ark_ff::FftField;
    use serde::{Serialize, Deserialize};
    use super::ClientIdentity;
    use crate::rpc::FieldElement;
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
    #[serde(bound = "")]
    pub struct MaskedInputEvent<F: FftField> {
        pub client: ClientIdentity,
        pub masked_input: FieldElement<F>,
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

#[rpc(server, client,
    server_bounds(F: FftField),
    client_bounds(F: FftField)
)]
pub trait CoordinatorRPC<F: FftField> {
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

    #[method(name = "available_input_masks")]
    async fn available_input_masks(&self) -> RpcResult<u64>;

    #[method(name = "obtain_input_masks")]
    async fn obtain_mask_indices(&self, n_indices: u64) -> RpcResult<Vec<u64>>;

    #[subscription(name = "sub_reserve_input_masks", unsubscribe = "unsub_reserve_input_masks", item = InputMaskReservationStarted)]
    async fn sub_reserve_input_masks(&self, timestamp: u64) -> SubscriptionResult;

    #[method(name = "reset")]
    async fn reset(&self, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_inputs: u64) -> RpcResult<()>;

    #[subscription(name = "sub_send_outputs", unsubscribe = "unsub_send_outputs", item = OutputSendingStarted)]
    async fn sub_send_outputs(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_start_mpc", unsubscribe = "unsub_start_mpc", item = MPCStarted)]
    async fn sub_start_mpc(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_start_pp", unsubscribe = "unsub_start_pp", item = PreprocessingStarted)]
    async fn sub_start_pp(&self, timestamp: u64) -> SubscriptionResult;

    #[method(name = "submit_masked_input")]
    async fn submit_masked_input(&self, masked_input: FieldElement<F>, reserved_index: u64) -> RpcResult<()>;

    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = ReservedInputEvent)]
    async fn sub_reserved_indices(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = MaskedInputEvent<F>)]
    async fn sub_masked_inputs(&self, timestamp: u64) -> SubscriptionResult;

    #[method(name = "transition")]
    async fn transition(&self, next_round: Round) -> RpcResult<()>;

    #[method(name = "send_output_shares")]
    async fn send_output_shares(&self, client_id: ClientIdentity, enc_shares: (Vec<u8>, Vec<u8>)) -> RpcResult<()>;

    #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = Vec<(Vec<u8>, Vec<u8>)>)]
    async fn obtain_output_shares(&self) -> SubscriptionResult;
}

struct CoordinatorRPCServerImpl<F: FftField> {
    d: Arc<Mutex<CoordinatorRPCServerImplInternal<F>>>,
    id: ClientIdentity
}

struct CoordinatorRPCServerImplInternal<F: FftField> {
    // contains the sinks of clients, which subscribed to the transition to the given round
    sinks: HashMap<Round, Vec<SubscriptionSink>>,
    trans_events: HashMap<Round, Vec<(u64, Box<dyn TransitionEvent>)>>,
    reserved_index_events: Vec<(u64, ReservedInputEvent)>,
    reserved_index_sinks: Vec<SubscriptionSink>,
    masked_input_events: Vec<(u64, MaskedInputEvent<F>)>,
    masked_input_sinks: Vec<SubscriptionSink>,
    next_i: u64,
    reserved_indices: Vec<Option<ClientIdentity>>,
    masked_inputs: Vec<Option<F>>,
    round: Round,
    prog_hash: [u8; 32],
    n: u64,
    t: u64,
    mpc_nodes: Option<Vec<ClientIdentity>>,
    clients: HashMap<ClientIdentity, ClientInfo>,
    output_shares: HashMap<(ClientIdentity, ClientIdentity), (Vec<u8>, Vec<u8>)>,
    output_sinks: HashMap<ClientIdentity, SubscriptionSink>,
}

impl<F: FftField> CoordinatorRPCServerImplInternal<F> {
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
            masked_inputs: vec![None; n_inputs as usize],
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

impl<F: FftField> crate::rpc::RPCServerInternal for CoordinatorRPCServerImplInternal<F> {
    fn add_client(&mut self, cert_der: Vec<u8>, client_handle: JoinHandle<()>, stop_tx: ServerHandle) {
        self.add_client(cert_der, client_handle, stop_tx);
    }
}

impl<F: FftField> crate::rpc::RPCServerImpl for CoordinatorRPCServerImpl<F> {
    type Internal = CoordinatorRPCServerImplInternal<F>;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        crate::off_chain::CoordinatorRPCServer::into_rpc(self)
    }
}

pub enum CoordinatorRPCError {
    NotDesignatedParty = 1,
    WrongRound = 2,
    IndexOutOfBounds = 3,
    BadID = 4,
    MaskedInputAlreadySubmitted = 5,
    IndexNotReserved = 6,
    OutOfIndices = 7,
    OutputSharesAlreadySent = 8,
    OutputSharesAlreadyRequested = 9,
    NotParty = 10,
}

#[async_trait]
impl<F: FftField> CoordinatorRPCServer<F> for CoordinatorRPCServerImpl<F> {
    async fn sub_collect_inputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_oneshot::<InputCollectionStarted>(pending, timestamp, Round::InputCollection).await
    }

    async fn available_input_masks(&self) -> RpcResult<u64> {
        let d = self.d.lock().await;

        Ok(d.masked_inputs.len() as u64 - d.next_i)
    }

    async fn sub_reserve_input_masks(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_oneshot::<InputMaskReservationStarted>(pending, timestamp, Round::InputMaskReservation).await
    }

    async fn reset(&self, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_inputs: u64) -> RpcResult<()> {
        let mut d = self.d.lock().await;

        let designated_party = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0].clone();
        if self.id != designated_party {
            return Err(ErrorObjectOwned::owned(
                    NotDesignatedParty as i32,
                    format!("Only designated party {:?} can reset the coordinator.", designated_party),
                    None::<()>
            ));
        }

        if d.round != Round::Idle {
            return Err(ErrorObjectOwned::owned(
                    WrongRound as i32,
                    format!("Need round {:?}, current round is {:?}", Round::Idle, d.round),
                    None::<()>
            ));
        }

        d.round = Round::Idle;
        d.next_i = 0;
        d.masked_inputs = vec![None; n_inputs as usize];
        d.reserved_indices = vec![None; n_inputs as usize];
        d.prog_hash = prog_hash;
        d.n = n;
        d.t = t;
        d.mpc_nodes = Some(initial_mpc_nodes);

        Ok(())
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

    async fn submit_masked_input(&self, masked_input: FieldElement<F>, raw_reserved_index: u64) -> RpcResult<()> {
        let mut d = self.d.lock().await;

        if d.round != Round::InputCollection {
            return Err(ErrorObjectOwned::owned(
                    WrongRound as i32,
                    format!("Need round {:?}, current round is {:?}", Round::InputCollection, d.round),
                    None::<()>
            ));
        }

        let reserved_index = raw_reserved_index as usize;

        if reserved_index >= d.masked_inputs.len(){
            return Err(ErrorObjectOwned::owned(
                    IndexOutOfBounds as i32,
                    format!("The index {} is out of bounds, there are only {} input masks.", reserved_index, d.masked_inputs.len()),
                    None::<()>
            ));
        }

        match &d.reserved_indices[reserved_index] {
            Some(public_key) => {
                if *public_key != self.id {
                    return Err(ErrorObjectOwned::owned(
                            BadID as i32,
                            format!("Client {:?} cannot submit a masked input for index {}, since this index has been reserved by {:?}", self.id, reserved_index, *public_key),
                            None::<()>
                    ));
                }
                if d.masked_inputs[reserved_index].is_some() {
                    return Err(ErrorObjectOwned::owned(
                            MaskedInputAlreadySubmitted as i32,
                            format!("Client {:?} has already submitted a masked input for index {}", self.id, reserved_index),
                            None::<()>
                    ));
                }
                d.masked_inputs[reserved_index] = Some(masked_input.value);

                let event = MaskedInputEvent { client: self.id.clone(), masked_input, reserved_index: raw_reserved_index };
                for sink in &d.masked_input_sinks {
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }
                d.masked_input_events.push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), event));
            }
            None => {
                return Err(ErrorObjectOwned::owned(
                        IndexNotReserved as i32,
                        format!("Cannot submit a masked input for index {}, since it has not been reserved", reserved_index),
                        None::<()>
                ));
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
            return Err(ErrorObjectOwned::owned(
                    WrongRound as i32,
                    format!("Need round {:?}, current round is {:?}", Round::InputMaskReservation, d.round),
                    None::<()>
            ));
        }

        if d.next_i + n_indices > d.masked_inputs.len() as u64 {
            return Err(ErrorObjectOwned::owned(
                    OutOfIndices as i32,
                    format!("Cannot return {} indices, only have {} left.", n_indices, d.masked_inputs.len() as u64 - d.next_i),
                    None::<()>
            ));
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

        let designated_party = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0].clone();
        if self.id != designated_party {
            return Err(ErrorObjectOwned::owned(
                    NotDesignatedParty as i32,
                    format!("Only designated party {:?} can reset the coordinator.", designated_party),
                    None::<()>
            ));
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

        let mpc_nodes = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!");
        if !mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                    NotParty as i32,
                    "Only parties can send output shares.",
                    None::<()>
            ));
        }

        // a node cannot send output shares for a client twice
        if d.output_shares.contains_key(&(client_id.clone(), self.id.clone())) {
            return Err(ErrorObjectOwned::owned(
                OutputSharesAlreadySent as i32,
                format!("Client {:?} already has submitted their output shares.", client_id),
                None::<()>
            ));
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
        let mut d = self.d.lock().await;

        if d.output_sinks.contains_key(&self.id) {
            pending.reject(ErrorObjectOwned::owned(
                OutputSharesAlreadyRequested as i32,
                format!("Client {:?} already has requested their output shares.", self.id),
                None::<()>
            )).await;
            return Ok(());
        }

        let sink = pending.accept().await?;
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

pub struct OffChainCoordinator<F: FftField> {
    rpc_server: Option<Arc<Mutex<CoordinatorRPCServerImplInternal<F>>>>,
    rpc_coord: Option<Client>,
    addr: Option<String>,
    port: Option<u16>,
    server_handle: Option<JoinHandle<()>>,
    timestamp: Option<u64>,
    t: u64,
    n_outputs: Option<u64>,
    key_der: Option<Vec<u8>>,
}

impl<F: FftField> OffChainCoordinator<F> {
    pub async fn start_coord_from_cert(addr: &str, port: u16, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_outputs: u64, cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> Self {
        Self::start_coord(addr, port, prog_hash, n, t, initial_mpc_nodes, n_outputs, cert.cert.der().to_vec(), cert.signing_key.serialize_der()).await
    }

    pub async fn start_coord(addr: &str, port: u16, prog_hash: [u8; 32], n: u64, t: u64, initial_mpc_nodes: Vec<ClientIdentity>, n_outputs: u64, cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        let rpc_server_data = Arc::new(Mutex::new(CoordinatorRPCServerImplInternal::<F>::new(prog_hash, n, t, initial_mpc_nodes.clone(), initial_mpc_nodes.len() as u64)));
        let server_handle = crate::rpc::start_coord::<CoordinatorRPCServerImpl<F>>(addr, port, cert_der, key_der, rpc_server_data.clone()).await;
        Self {
            rpc_server: Some(rpc_server_data),
            rpc_coord: None,
            addr: Some(String::from(addr)),
            port: Some(port),
            server_handle: Some(server_handle),
            timestamp: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            t,
            n_outputs: None,
            key_der: None,
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
            key_der: Some(key_der),
        }
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone().expect("Coordinator server not started")
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp.expect("Coordinator server not started")
    }

    fn rpc(&self) -> &Client {
        self.rpc_coord.as_ref().expect("client not started")
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

impl<F: FftField> Coordinator<F> for OffChainCoordinator<F> {
    type ClientIdentity = ClientIdentity;

    async fn trigger_input(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCClient::<F>::transition(self.rpc(), Round::InputCollection).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(())
    }

    async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
        match CoordinatorRPCClient::<F>::transition(self.rpc(), Round::Preprocessing).await {
            Ok(_) => Ok(()),
            Err(e) => Err(CoordinatorError::JSONError(e.to_string()))
        }
    }

    async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
        match CoordinatorRPCClient::<F>::transition(self.rpc(), Round::InputMaskReservation).await {
            Ok(_) => Ok(()),
            Err(e) => Err(CoordinatorError::JSONError(e.to_string()))
        }
    }

    async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_collect_inputs(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()))
        }
    }

    async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_start_pp(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()))
        }
    }

    async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_reserve_input_masks(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()))
        }
    }

    async fn obtain_mask_indices(&mut self, n_indices: u64) -> Result<Vec<u64>, CoordinatorError> {
        let indices = CoordinatorRPCClient::<F>::obtain_mask_indices(self.rpc(), n_indices).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(indices)
    }

    async fn send_masked_input(&self, masked_input: F, i: u64) -> Result<(), CoordinatorError> {
        match CoordinatorRPCClient::<F>::submit_masked_input(self.rpc(), FieldElement { value: masked_input }, i).await {
            Ok(_) => Ok(()),
            Err(e) => Err(CoordinatorError::JSONError(e.to_string()))
        }
    }

    async fn wait_for_inputs(&self, n_clients: u64, mask_shares: Vec<RobustShare<F>>) -> Result<HashMap<ClientIdentity, Vec<RobustShare<F>>>, CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_masked_inputs(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let mut map = HashMap::new();

        for _ in 0..n_clients {
            if let Some(Ok(MaskedInputEvent { client, masked_input, reserved_index })) = sub.next().await {
                let i = reserved_index as usize;
                let mask_share = &mask_shares[i];
                let input = RobustShare::new(
                    masked_input.value - mask_share.share[0],
                    mask_share.id,
                    mask_share.degree
                );

                map.insert(client, vec![input]);
            } else {
                return Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()));
            }
        }

        Ok(map)
    }

    async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCClient::<F>::transition(self.rpc(), Round::MPC).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_start_mpc(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()))
        }
    }

    async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCClient::<F>::transition(self.rpc(), Round::Output).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_send_outputs(self.rpc(), self.get_timestamp()).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()))
        }
    }

    async fn wait_for_indices(&self, n_clients: u64) -> Result<HashMap<ClientIdentity, u64>, CoordinatorError> {
        let mut sub = CoordinatorRPCClient::<F>::sub_reserved_indices(self.rpc(), self.get_timestamp()).await.unwrap();

        let mut map = HashMap::new();

        for _ in 0..n_clients {
            if let Some(Ok(ReservedInputEvent { client, reserved_indices })) = sub.next().await {
                assert_eq!(reserved_indices.len(), 1);
                map.insert(client, reserved_indices[0]);
            } else {
                return Err(CoordinatorError::JSONError("Subscription ended before event could be received".to_string()));
            }
        }

        Ok(map)
    }

    async fn finalize(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCClient::<F>::transition(self.rpc(), Round::Idle).await.map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn obtain_outputs(&self) -> Result<Vec<F>, CoordinatorError> {
        let mut sub = match CoordinatorRPCClient::<F>::obtain_output_shares(self.rpc()).await {
            Ok(sub) => sub,
            Err(e) => {
                return Err(CoordinatorError::JSONError(e.to_string()));
            }
        };

        let client_sk = {
            let der_bytes = self.key_der.clone().unwrap();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes).map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk).map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        while let Some(Ok(enc_output_shares)) = sub.next().await {
            if (enc_output_shares.len() as u64) < 2 * self.t + 1 {
                panic!("BUG: less than 2t+1 output shares received, coordinator should make sure this does not happen!!!");
            }

            let mut output_shares = Vec::new();
            for (encapped_key_bytes, c) in enc_output_shares.iter() {
                let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(encapped_key_bytes).map_err(|_| CoordinatorError::ParsingEncapsulatedKeyFailed)?;
                let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base, &client_sk, &encapped_key, ENC_INFO, c, b"",
                ).map_err(|_| CoordinatorError::DecryptionError)?;
                let shares: Vec<RobustShare<F>> = CanonicalDeserialize::deserialize_compressed(
                    output_shares_bytes.as_slice(),
                ).map_err(|_| CoordinatorError::DeserializationError)?;

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

        Err(CoordinatorError::JSONError("Output shares subscription ended before enough output shares could be obtained".to_string()))
    }

    async fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<F>>) -> Result<(), CoordinatorError> {
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

        if let Err(e) = CoordinatorRPCClient::<F>::send_output_shares(self.rpc(), client_id, c).await {
            return Err(CoordinatorError::JSONError(e.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
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
        let coord: OffChainCoordinator<Fr> = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
        let timestamp = coord.get_timestamp();

        let _: OffChainCoordinator<Fr> = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, client_cert()).await;
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
            let coord: OffChainCoordinator<Fr> = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
            let timestamp = coord.get_timestamp();

            let node0: OffChainCoordinator<Fr> = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;
            let node1: OffChainCoordinator<Fr> = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;

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
            let coord: OffChainCoordinator<Fr> = OffChainCoordinator::start_coord_from_cert(addr, port, [0u8; 32], 5, 1, public_keys, 2, server_cert()).await;
            let timestamp = coord.get_timestamp();
            let barrier = Arc::new(Barrier::new(2));

            let node0: OffChainCoordinator<Fr> = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;
            let node1: OffChainCoordinator<Fr> = OffChainCoordinator::start_rpc_client_from_cert(addr, port, timestamp, 1, 1, certs.remove(0)).await;

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
        let coord: OffChainCoordinator<Fr> = OffChainCoordinator::start_coord_from_cert(coord_addr, coord_port, [0u8; 32], n as u64, t as u64, public_keys[..5].to_vec().clone(), 2, server_cert()).await;
        let timestamp = coord.get_timestamp();
        let barrier = Arc::new(Barrier::new(3));

        // MPC node (designated party), also RPC client
        tokio::spawn({
            let barrier = barrier.clone();

            let mut coords: Vec<OffChainCoordinator<Fr>> = Vec::new();
            for i in 0..3 {
                let coord: OffChainCoordinator<Fr> =
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

                node_rpc.add_mask_share(0, &mask_shares[i]).await.unwrap();
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
                        node_rpc.add_reserved_index(c.to_vec(), *i).await.unwrap();
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
            let mut coord: OffChainCoordinator<Fr> =
                OffChainCoordinator::start_rpc_client_from_cert(coord_addr, coord_port, timestamp, 1, 1, cert.clone()).await;
            let rpc_client: super::node_rpc::NodeRPCClient<Fr> = super::node_rpc::NodeRPCClient::start_rpc_client_from_cert(t, node_rpc_addrs.clone(), cert.clone()).await;
            async move {
                coord.wait_for_pp().await.unwrap();
                coord.wait_for_input_mask_init().await.unwrap();

                let indices = coord.obtain_mask_indices(1).await.expect("obtaining mask indices failed");
                assert_eq!(indices.len(), 1);
                println!("CLIENT: obtained index {}", indices[0]);

                let mask = rpc_client.receive_mask().await.unwrap();
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
