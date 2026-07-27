pub mod tests;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, single_shot_seal, Deserializable, OpModeR, OpModeS, Serializable,
};
use jsonrpsee::async_client::Client;
use jsonrpsee::server::RpcModule;
use jsonrpsee::types::{error::ErrorCode, ErrorObjectOwned};
use jsonrpsee::{
    core::{to_json_raw_value, RpcResult, SubscriptionResult},
    proc_macros::rpc,
    PendingSubscriptionSink, SubscriptionSink,
};
use p256::{pkcs8::DecodePrivateKey, SecretKey};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use stoffel_mpc_coordinator_shared::{
    round_before, rpc::RPCServerHandle, Coordinator, CoordinatorError, ExecutionId, Round,
    ShareBound,
};
use tokio::sync::{MappedMutexGuard, Mutex, MutexGuard};
use CoordinatorRPCBaseError::*;

/// KEM, KDF, and AEAD instantiations are needed to encrypt the output shares for an MPC client
/// before sending them to the coordinator.
type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

/// An MPC client interacts with two types of entities: the coordinator and nodes.
/// Towards the nodes, the MPC client uses a public key (currently ECDSA).
/// Towards the coordinator, it uses either an Ethereum address (on-chain) or the same public key as for the nodes (off-chain).
///
/// In the on-chain case we make clients sign a nonce with the Ethereum address,
/// which is sent to the nodes through a TLS channel that authenticates the client as
/// the owner of the public key, so the node can deduce that the public key and the
/// owner of the Ethereum address are the same and the node can safely send its mask share to the client.
///
/// In the off-chain case, no signature is needed, since the identities towards coordinator and nodes
/// must simply be the same: if a client requests a mask share from a node for a previously reserved
/// mask index, then the node simply checks that the public keys used for both these actions are the same.
pub type ClientIdentity = Vec<u8>;

/// A deliberately small, explicit bound for the number of live executions owned by one RPC
/// listener. Finished executions must be retired before this many more are registered.
pub const DEFAULT_MAX_CONCURRENT_EXECUTIONS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskReservation {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskedInputEvent {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub masked_input: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputSlotAssignment {
    pub client: ClientIdentity,
    pub label: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputAssignment {
    pub input_slots: Vec<InputSlotAssignment>,
}

/// Immutable data that binds one invocation to its program and client I/O layout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRegistration {
    pub execution_id: ExecutionId,
    pub program_hash: [u8; 32],
    pub n_inputs: u64,
    pub output_clients: Vec<ClientIdentity>,
    pub input_assignment: InputAssignment,
    /// Number of independently encrypted node shares required before an output client is notified.
    pub min_output_shares: u64,
}

/// The node-side RPC interface.
pub mod node_rpc {
    use super::{AssignedMaskReservation, AssignedMaskShare, ClientIdentity};
    use ark_ff::FftField;
    use ark_serialize::CanonicalSerialize;
    use async_trait::async_trait;
    use jsonrpsee::{
        async_client::Client,
        core::{to_json_raw_value, SubscriptionResult},
        proc_macros::rpc,
        server::RpcModule,
        types::{error::ErrorCode, ErrorObjectOwned},
        PendingSubscriptionSink, SubscriptionSink,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::marker::PhantomData;
    use std::sync::Arc;
    use stoffel_mpc_coordinator_shared::{
        rpc::RPCServerHandle, CoordinatorError, ExecutionId, NodeRPCError, ShareBound,
    };
    use tokio::sync::Mutex;
    use tokio::task::JoinSet;

    /// Errors returned by the node-side RPC interface.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OffChainNodeRPCServerError {
        SerializationError = 1,
        ExecutionNotFound = 2,
    }

    /// The off-chain node-side JSON-RPC interface.
    #[rpc(server, client)]
    pub trait OffChainNodeRPC {
        #[subscription(name = "sub_receive_assigned_mask_shares", unsubscribe = "unsub_receive_assigned_mask_shares", item = Vec<AssignedMaskShare>)]
        async fn receive_assigned_mask_shares(
            &self,
            execution_id: ExecutionId,
            start: u64,
            count: u64,
        ) -> SubscriptionResult;
    }

    pub struct NodeRPCServer {
        rpc_server: Arc<Mutex<NodeRPCServerInternal>>,
        addr: String,
        server_handle: RPCServerHandle,
    }

    /// An object used by an MPC client to connect to the RPC interfaces of many nodes.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        /// The per-node client handles for each connection to a node.
        node_rpcs: Vec<Client>,
        /// Total number of MPC nodes in the network (used for share reconstruction).
        n: usize,
        /// The threshold value.
        t: usize,
        /// The program invocation to which all RPC calls made by this handle belong.
        execution_id: ExecutionId,
        _phantom: PhantomData<(F, S)>,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        pub async fn start_rpc_client_for_execution(
            n: usize,
            t: usize,
            addrs: Vec<(String, u16)>,
            execution_id: ExecutionId,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let node_rpcs: Vec<Client> =
                futures_util::future::join_all(addrs.iter().map(|(addr, port)| {
                    stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
                        addr,
                        *port,
                        cert_der.clone(),
                        key_der.clone(),
                    )
                }))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self {
                node_rpcs,
                n,
                t,
                execution_id,
                _phantom: PhantomData,
            })
        }

        pub async fn receive_assigned_masks(
            &self,
            start: u64,
            count: u64,
        ) -> Result<Vec<S::ValueType>, CoordinatorError> {
            let end = start.checked_add(count).ok_or_else(|| {
                CoordinatorError::JSONError("Assigned mask range overflows u64".to_string())
            })?;
            if count == 0 {
                return Ok(Vec::new());
            }
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc
                    .receive_assigned_mask_shares(self.execution_id, start, count)
                    .await
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                share_futures.spawn(async move { sub.next().await });
            }

            let mut share_sets: HashMap<u64, Vec<S>> = HashMap::new();
            let expected_indices = (start..end).collect::<Vec<_>>();

            while let Some(share_result) = share_futures.join_next().await {
                let assigned_shares_option =
                    share_result.map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                let assigned_shares = match assigned_shares_option {
                    Some(res) => {
                        res.map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?
                    }
                    None => continue,
                };

                let mut indices = assigned_shares
                    .iter()
                    .map(|assigned_share| assigned_share.reserved_index)
                    .collect::<Vec<_>>();
                indices.sort_unstable();
                if expected_indices != indices {
                    return Err(CoordinatorError::JSONError(
                        "MPC node returned the wrong assigned mask share range".to_string(),
                    ));
                }

                for assigned_share in assigned_shares {
                    let share: S = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                        assigned_share.share_bytes.as_slice(),
                    )
                    .map_err(|_| CoordinatorError::DeserializationError)?;

                    share_sets
                        .entry(assigned_share.reserved_index)
                        .or_default()
                        .push(share);
                }

                if expected_indices.iter().all(|reserved_index| {
                    share_sets
                        .get(reserved_index)
                        .is_some_and(|shares| shares.len() >= S::min_shares(self.t))
                }) {
                    break;
                }
            }

            let mut outputs = Vec::with_capacity(share_sets.len());
            for reserved_index in expected_indices {
                let Some(mask_shares) = share_sets.remove(&reserved_index) else {
                    return Err(CoordinatorError::MaskReconstructionFailed(0));
                };
                if mask_shares.len() < S::min_shares(self.t) {
                    return Err(CoordinatorError::MaskReconstructionFailed(
                        mask_shares.len(),
                    ));
                }
                let (_, mask) = S::recover_secret(&mask_shares, self.n, self.t)
                    .map_err(|_| CoordinatorError::MaskReconstructionFailed(mask_shares.len()))?;
                outputs.push(mask);
            }

            Ok(outputs)
        }
    }

    impl NodeRPCServer {
        pub async fn start(
            addr: &str,
            port: u16,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::new()));
            let server_handle =
                stoffel_mpc_coordinator_shared::rpc::start_coord::<NodeRPCServerImpl>(
                    addr,
                    port,
                    cert_der,
                    key_der,
                    rpc_server_data.clone(),
                )
                .await?;
            Ok(Self {
                rpc_server: rpc_server_data,
                addr: String::from(addr),
                server_handle,
            })
        }

        pub async fn start_for_execution(
            addr: &str,
            port: u16,
            execution_id: ExecutionId,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let server = Self::start(addr, port, cert_der, key_der).await?;
            server.register_execution(execution_id).await?;
            Ok(server)
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone()
        }

        pub async fn shutdown(self) {
            self.server_handle.shutdown().await;
        }

        /// Registers a program invocation on this long-running listener.
        pub async fn register_execution(
            &self,
            execution_id: ExecutionId,
        ) -> Result<(), CoordinatorError> {
            self.rpc_server
                .lock()
                .await
                .register_execution(execution_id)
        }

        /// Stops admitting new RPCs for an invocation and drops all of its node-side state.
        pub async fn retire_execution(&self, execution_id: ExecutionId) -> bool {
            self.rpc_server.lock().await.retire_execution(execution_id)
        }

        async fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Result<Arc<Mutex<NodeRPCExecutionState>>, NodeRPCError> {
            self.rpc_server
                .lock()
                .await
                .execution_state(execution_id)
                .ok_or(NodeRPCError::ExecutionNotFound)
        }

        pub async fn add_assigned_reserved_index_for_execution(
            &self,
            execution_id: ExecutionId,
            reservation: AssignedMaskReservation,
        ) -> Result<(), NodeRPCError> {
            let d = self.execution_state(execution_id).await?;
            let mut d = d.lock().await;
            let id = reservation.client.clone();
            let i = reservation.reserved_index;

            if d.index_to_client.contains_key(&i) {
                return Err(NodeRPCError::IndexAlreadyAdded);
            }

            d.index_to_client.insert(i, id.clone());
            d.assigned_reservations.insert(i, reservation.clone());

            // Complete an exact-range request once its final assignment and share exist.
            if d.mask_shares.contains_key(&i) {
                if let Some(request) = d.assigned_sinks.remove(&id) {
                    if let Some(assigned_shares) =
                        d.assigned_mask_shares_for_client(&id, request.start, request.count)?
                    {
                        let json = to_json_raw_value(&assigned_shares)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        request
                            .sink
                            .send(json)
                            .await
                            .map_err(|_| NodeRPCError::JSONError)?;
                    } else {
                        d.assigned_sinks.insert(id.clone(), request);
                    }
                }
            }

            Ok(())
        }

        pub async fn add_reserved_index_for_execution(
            &self,
            execution_id: ExecutionId,
            client: ClientIdentity,
            reserved_index: u64,
        ) -> Result<(), NodeRPCError> {
            self.add_assigned_reserved_index_for_execution(
                execution_id,
                AssignedMaskReservation {
                    client,
                    reserved_index,
                    input_ordinal: reserved_index,
                },
            )
            .await
        }

        pub async fn add_mask_share_for_execution<S: CanonicalSerialize>(
            &self,
            execution_id: ExecutionId,
            i: u64,
            share: &S,
        ) -> Result<(), NodeRPCError> {
            let d = self.execution_state(execution_id).await?;
            let mut d = d.lock().await;

            if d.mask_shares.contains_key(&i) {
                return Err(NodeRPCError::IndexAlreadyAdded);
            }
            let mut share_bytes = Vec::new();
            share
                .serialize_compressed(&mut share_bytes)
                .map_err(|_| NodeRPCError::SerializationError)?;
            d.mask_shares.insert(i, share_bytes.clone());

            // Complete an exact-range request once its final share exists.
            if let Some(id) = d.index_to_client.get(&i).cloned() {
                if let Some(request) = d.assigned_sinks.remove(&id) {
                    if let Some(assigned_shares) =
                        d.assigned_mask_shares_for_client(&id, request.start, request.count)?
                    {
                        let json = to_json_raw_value(&assigned_shares)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        request
                            .sink
                            .send(json)
                            .await
                            .map_err(|_| NodeRPCError::JSONError)?;
                    } else {
                        d.assigned_sinks.insert(id.clone(), request);
                    }
                }
            }

            Ok(())
        }
    }

    /// The server-side information for one client connection to the node-side RPC interface.
    pub struct NodeRPCServerImpl {
        /// A reference to the server's shared state.
        d: Arc<Mutex<NodeRPCServerInternal>>,
        /// The connected client's identity, which is the client's public key in DER format.
        id: Vec<u8>,
    }

    impl NodeRPCServerImpl {
        async fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Option<Arc<Mutex<NodeRPCExecutionState>>> {
            self.d.lock().await.execution_state(execution_id)
        }
    }

    impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection for NodeRPCServerImpl {
        type Internal = NodeRPCServerInternal;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self>
        where
            Self: Sized,
        {
            crate::node_rpc::OffChainNodeRPCServer::into_rpc(self)
        }
    }

    /// The internal state of the node-side RPC server.
    pub struct NodeRPCServerInternal {
        executions: HashMap<ExecutionId, Arc<Mutex<NodeRPCExecutionState>>>,
    }

    /// State that must never be shared between two program invocations.
    struct NodeRPCExecutionState {
        /// Maps reserved indices to the clients that have reserved them.
        index_to_client: HashMap<u64, ClientIdentity>,
        assigned_reservations: HashMap<u64, AssignedMaskReservation>,
        assigned_sinks: HashMap<ClientIdentity, AssignedMaskRequest>,
        /// Preprocessed mask shares, indexed only within this execution.
        mask_shares: HashMap<u64, Vec<u8>>,
    }

    struct AssignedMaskRequest {
        start: u64,
        count: u64,
        sink: SubscriptionSink,
    }

    impl NodeRPCServerInternal {
        fn new() -> Self {
            Self {
                executions: HashMap::new(),
            }
        }

        fn register_execution(
            &mut self,
            execution_id: ExecutionId,
        ) -> Result<(), CoordinatorError> {
            if execution_id.is_zero() {
                return Err(CoordinatorError::JSONError(
                    "zero execution IDs are not valid for persistent RPC listeners".to_string(),
                ));
            }
            if self.executions.contains_key(&execution_id) {
                return Err(CoordinatorError::JSONError(format!(
                    "Execution {execution_id} is already registered"
                )));
            }
            if self.executions.len() >= super::DEFAULT_MAX_CONCURRENT_EXECUTIONS {
                return Err(CoordinatorError::JSONError(format!(
                    "Execution capacity {} reached",
                    super::DEFAULT_MAX_CONCURRENT_EXECUTIONS
                )));
            }
            self.executions.insert(
                execution_id,
                Arc::new(Mutex::new(NodeRPCExecutionState::new())),
            );
            Ok(())
        }

        fn retire_execution(&mut self, execution_id: ExecutionId) -> bool {
            self.executions.remove(&execution_id).is_some()
        }

        fn execution_state(
            &self,
            execution_id: ExecutionId,
        ) -> Option<Arc<Mutex<NodeRPCExecutionState>>> {
            self.executions.get(&execution_id).cloned()
        }
    }

    impl NodeRPCExecutionState {
        fn new() -> Self {
            Self {
                index_to_client: HashMap::new(),
                assigned_reservations: HashMap::new(),
                assigned_sinks: HashMap::new(),
                mask_shares: HashMap::new(),
            }
        }
    }

    impl NodeRPCExecutionState {
        fn assigned_mask_share(
            &self,
            reserved_index: u64,
            share_bytes: &[u8],
        ) -> Result<AssignedMaskShare, NodeRPCError> {
            self.assigned_reservations
                .get(&reserved_index)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            Ok(AssignedMaskShare {
                reserved_index,
                share_bytes: share_bytes.to_vec(),
            })
        }

        fn assigned_mask_shares_for_client(
            &self,
            id: &ClientIdentity,
            start: u64,
            count: u64,
        ) -> Result<Option<Vec<AssignedMaskShare>>, NodeRPCError> {
            let end = start
                .checked_add(count)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            let mut assigned_shares = Vec::new();
            for i in start..end {
                let Some(client) = self.index_to_client.get(&i) else {
                    return Ok(None);
                };
                if client != id {
                    return Err(NodeRPCError::AuthenticationFailed(id.clone()));
                }
                let Some(share) = self.mask_shares.get(&i) else {
                    return Ok(None);
                };
                assigned_shares.push(self.assigned_mask_share(i, share)?);
            }

            Ok(Some(assigned_shares))
        }
    }

    #[async_trait]
    impl OffChainNodeRPCServer for NodeRPCServerImpl {
        async fn receive_assigned_mask_shares(
            &self,
            pending: PendingSubscriptionSink,
            execution_id: ExecutionId,
            start: u64,
            count: u64,
        ) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let Some(d) = self.execution_state(execution_id).await else {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(ExecutionNotFound as i32).code(),
                        format!("Execution {execution_id} is not registered"),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            };
            let mut d = d.lock().await;

            if d.assigned_sinks.contains_key(&self.id) {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::InvalidParams.code(),
                        format!(
                            "Client {:?} already requested assigned mask shares",
                            self.id
                        ),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            }

            let assigned_shares = match d.assigned_mask_shares_for_client(&self.id, start, count) {
                Ok(assigned_shares) => assigned_shares,
                Err(e) => {
                    pending
                        .reject(ErrorObjectOwned::owned(
                            ErrorCode::ServerError(SerializationError as i32).code(),
                            format!("Serializing assigned shares failed: {e}"),
                            None::<()>,
                        ))
                        .await;
                    return Ok(());
                }
            };

            if let Some(assigned_shares) = assigned_shares {
                let json = match to_json_raw_value(&assigned_shares) {
                    Ok(j) => j,
                    Err(e) => {
                        pending
                            .reject(ErrorObjectOwned::owned(
                                ErrorCode::ServerError(SerializationError as i32).code(),
                                format!("Converting assigned shares to JSON failed: {e}"),
                                None::<()>,
                            ))
                            .await;
                        return Ok(());
                    }
                };

                let sink = pending.accept().await?;
                sink.send(json).await?;

                return Ok(());
            }

            let sink = pending.accept().await?;
            d.assigned_sinks
                .insert(self.id.clone(), AssignedMaskRequest { start, count, sink });

            Ok(())
        }
    }
}

/// Events that mimic those used for the on-chain coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    CoordinatorInitialized {
        creation_block: u64,
        designated_party: ClientIdentity,
    },
    MaskedInputEvent {
        client: ClientIdentity,
        masked_input: Vec<u8>,
        reserved_index: u64,
    },
    IndexBufferEvent {
        total_indices: u64,
        designated_party: ClientIdentity,
    },
    ReservedInputEvent {
        client: ClientIdentity,
        reserved_index: u64,
    },
    PreprocessingStarted {
        designated_party: ClientIdentity,
    },
    InputCollectionStarted,
    InputMaskReservationStarted,
    MPCStarted,
    ExecutionDone,
    OutputSendingStarted,
    OutputsPublished,
    ClientInputMaskReservationEvent,
    ClientOutputCollection,
    PreprocessingRoundExecuted,
}

/// RPC interface implemented by the developer.
#[rpc(server, client)]
pub trait StoffelCoordinatorRPC {
    #[method(name = "start_preprocessing")]
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "reserve_input_masks")]
    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "collect_inputs")]
    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "start_mpc")]
    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "send_output")]
    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()>;
    #[method(name = "finalize")]
    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()>;
}

// RPC interface already implemented by this library.
#[rpc(server, client)]
pub trait CoordinatorRPCBase {
    #[method(name = "register_execution")]
    async fn register_execution(&self, registration: ExecutionRegistration) -> RpcResult<()>;

    #[method(name = "retire_execution")]
    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()>;

    /// Wait for round `round` to be started.
    #[subscription(name = "sub_round", unsubscribe = "unsub_round", item = Event)]
    async fn sub_round(&self, execution_id: ExecutionId, round: Round) -> SubscriptionResult;

    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = Event)]
    async fn sub_reserved_indices(&self, execution_id: ExecutionId) -> SubscriptionResult;

    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = Event)]
    async fn sub_masked_inputs(&self, execution_id: ExecutionId) -> SubscriptionResult;

    #[subscription(name = "sub_assigned_reserved_indices", unsubscribe = "unsub_assigned_reserved_indices", item = AssignedMaskReservation)]
    async fn sub_assigned_reserved_indices(&self, execution_id: ExecutionId) -> SubscriptionResult;

    #[subscription(name = "sub_assigned_masked_inputs", unsubscribe = "unsub_assigned_masked_inputs", item = AssignedMaskedInputEvent)]
    async fn sub_assigned_masked_inputs(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// Returns the number of available input masks left. TODO: this involves a race condition
    /// since querying this and reserving an index is not atomic. remove it?
    #[method(name = "available_input_masks")]
    async fn available_input_masks(&self, execution_id: ExecutionId) -> RpcResult<u64>;

    /// MPC clients can request index `i`.
    #[method(name = "reserve_mask_index")]
    async fn reserve_mask_index(&self, execution_id: ExecutionId, i: u64) -> RpcResult<()>;

    /// An MPC client uses this to submit a masked input `masked_input`, for which it has
    /// previously reserved the index `reserved_index`.
    #[method(name = "submit_masked_input")]
    async fn submit_masked_input(
        &self,
        execution_id: ExecutionId,
        masked_input: Vec<u8>,
        reserved_index: u64,
    ) -> RpcResult<()>;

    /// The designated party uses this to transition to the new round `next_round`.
    #[method(name = "transition")]
    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()>;

    /// MPC nodes use this to send encrypted output shares `enc_shares` for a client with identity
    /// `client_id`.
    #[method(name = "send_output_shares")]
    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()>;

    /// MPC clients use this to receive their output shares from the coordinator, so they can
    /// reconstruct their private output.
    #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = Vec<(Vec<u8>, Vec<u8>)>)]
    async fn obtain_output_shares(&self, execution_id: ExecutionId) -> SubscriptionResult;
}

/// Errors returned to RPC clients by the basic coordinator RPC interface.
pub enum CoordinatorRPCBaseError {
    NotDesignatedParty = 1,
    WrongRound = 2,
    IndexOutOfBounds = 3,
    BadID = 4,
    MaskedInputAlreadySubmitted = 5,
    IndexNotReserved = 6,
    IndexAlreadyReserved = 7,
    OutputSharesAlreadySent = 8,
    OutputSharesAlreadyRequested = 9,
    NotParty = 10,
    SendingFailed = 11,
    NotOutputClient = 12,
    UnauthorizedClientIo = 15,
    ExecutionNotFound = 16,
    ExecutionAlreadyRegistered = 17,
}

fn execution_not_found(execution_id: ExecutionId) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        ErrorCode::ServerError(CoordinatorRPCBaseError::ExecutionNotFound as i32).code(),
        format!("Execution {execution_id} is not registered"),
        None::<()>,
    )
}

/// The basic server-side information for one client connection to the coordinator RPC interface.
/// Can be extended by the developer.
#[derive(Clone)]
pub struct CoordinatorRPCServerConnectionBase {
    /// A reference to the server's shared state.
    d: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    /// The connected client's identity, which is the client's public key in DER format.
    id: ClientIdentity,
}

/// The basic internal state of the coordinator RPC server.
/// Can be extended by the developer.
pub struct CoordinatorRPCServerSharedBase {
    mpc_nodes: Vec<ClientIdentity>,
    n: u64,
    executions: HashMap<ExecutionId, CoordinatorExecutionState>,
}

/// All mutable protocol state for one program invocation.
struct CoordinatorExecutionState {
    registration: ExecutionRegistration,
    retirement_acks: HashSet<ClientIdentity>,
    // Contains the sinks of clients, which subscribed to the transition to the given round.
    sinks: HashMap<Round, Vec<SubscriptionSink>>,
    trans_events: HashMap<Round, Event>,
    reserved_index_events: Vec<Event>,
    reserved_index_sinks: Vec<SubscriptionSink>,
    assigned_reserved_index_events: Vec<AssignedMaskReservation>,
    assigned_reserved_index_sinks: Vec<SubscriptionSink>,
    masked_input_events: Vec<Event>,
    masked_input_sinks: Vec<SubscriptionSink>,
    assigned_masked_input_events: Vec<AssignedMaskedInputEvent>,
    assigned_masked_input_sinks: Vec<SubscriptionSink>,
    n_reserved: u64,
    reserved_indices: Vec<Option<ClientIdentity>>,
    masked_inputs: Vec<Option<Vec<u8>>>,
    /// The current round.
    round: Round,
    /// Stores encrypted output shares sent by MPC nodes for MPC clients. The first element of the key is the client ID,
    /// the second is the node ID.
    output_shares: HashMap<(ClientIdentity, ClientIdentity), (Vec<u8>, Vec<u8>)>,
    /// A client remains subscribed as additional parties submit output shares.
    output_sinks: HashMap<ClientIdentity, Arc<SubscriptionSink>>,
    /// The set of clients that are permitted to call `obtain_output_shares`.
    output_clients: Vec<ClientIdentity>,
    /// Optional index assignments used to prevent clients from reserving indices assigned to others.
    input_assignments: Vec<InputSlotAssignment>,
}

impl CoordinatorRPCServerConnectionBase {
    pub fn new(internal: Arc<Mutex<CoordinatorRPCServerSharedBase>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    async fn execution_state(
        &self,
        execution_id: ExecutionId,
    ) -> Result<MappedMutexGuard<'_, CoordinatorExecutionState>, ErrorObjectOwned> {
        let shared = self.d.lock().await;
        if !shared.executions.contains_key(&execution_id) {
            return Err(execution_not_found(execution_id));
        }
        Ok(MutexGuard::map(shared, |shared| {
            shared
                .executions
                .get_mut(&execution_id)
                .expect("execution presence checked before mapping")
        }))
    }
}

impl CoordinatorRPCServerSharedBase {
    pub fn new(
        n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
    ) -> Result<Self, CoordinatorError> {
        validate_topology(n, t, &initial_mpc_nodes)?;
        Ok(Self {
            mpc_nodes: initial_mpc_nodes,
            n,
            executions: HashMap::new(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_execution(
        execution_id: ExecutionId,
        prog_hash: [u8; 32],
        n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
        n_inputs: u64,
        output_clients: Vec<ClientIdentity>,
        input_assignment: InputAssignment,
    ) -> Result<Self, CoordinatorError> {
        let min_output_shares = t
            .checked_mul(2)
            .and_then(|threshold| threshold.checked_add(1))
            .ok_or_else(|| CoordinatorError::JSONError("output quorum overflow".to_owned()))?;
        let mut shared = Self::new(n, t, initial_mpc_nodes)?;
        shared.register_execution(ExecutionRegistration {
            execution_id,
            program_hash: prog_hash,
            n_inputs,
            output_clients,
            input_assignment,
            min_output_shares,
        })?;
        Ok(shared)
    }

    pub fn register_execution(
        &mut self,
        registration: ExecutionRegistration,
    ) -> Result<(), CoordinatorError> {
        if let Some(existing) = self.executions.get(&registration.execution_id) {
            if existing.registration == registration {
                return Ok(());
            }
            return Err(CoordinatorError::JSONError(format!(
                "Execution {} is already registered with different metadata",
                registration.execution_id
            )));
        }
        if self.executions.len() >= DEFAULT_MAX_CONCURRENT_EXECUTIONS {
            return Err(CoordinatorError::JSONError(format!(
                "Execution capacity {} reached",
                DEFAULT_MAX_CONCURRENT_EXECUTIONS
            )));
        }
        let execution = CoordinatorExecutionState::new(registration.clone(), self.n)?;
        self.executions.insert(registration.execution_id, execution);
        Ok(())
    }

    pub fn retire_execution(
        &mut self,
        execution_id: ExecutionId,
        party: &ClientIdentity,
    ) -> Result<(), CoordinatorError> {
        let execution = self.executions.get_mut(&execution_id).ok_or_else(|| {
            CoordinatorError::JSONError(format!("Execution {execution_id} is not registered"))
        })?;
        execution.retirement_acks.insert(party.clone());
        if execution.retirement_acks.len() == self.mpc_nodes.len() {
            self.executions.remove(&execution_id);
        }
        Ok(())
    }
}

fn validate_topology(
    n: u64,
    t: u64,
    initial_mpc_nodes: &[ClientIdentity],
) -> Result<(), CoordinatorError> {
    if initial_mpc_nodes.is_empty() {
        return Err(CoordinatorError::JSONError(
            "Coordinator requires at least one MPC node".to_string(),
        ));
    }
    let n_usize = usize::try_from(n).map_err(|_| CoordinatorError::U64ToUsizeError)?;
    if initial_mpc_nodes.len() != n_usize {
        return Err(CoordinatorError::JSONError(format!(
            "Coordinator was configured for {n} MPC nodes, but received {} node identities",
            initial_mpc_nodes.len()
        )));
    }
    if t >= n {
        return Err(CoordinatorError::JSONError(format!(
            "Threshold {t} must be less than the MPC node count {n}"
        )));
    }
    if initial_mpc_nodes
        .iter()
        .enumerate()
        .any(|(index, node)| initial_mpc_nodes[..index].contains(node))
    {
        return Err(CoordinatorError::JSONError(
            "MPC node identities must be unique".to_string(),
        ));
    }
    Ok(())
}

impl CoordinatorExecutionState {
    fn new(registration: ExecutionRegistration, n: u64) -> Result<Self, CoordinatorError> {
        if registration.execution_id.is_zero() {
            return Err(CoordinatorError::JSONError(
                "execution ID must be nonzero".to_string(),
            ));
        }
        if registration.program_hash == [0; 32] {
            return Err(CoordinatorError::JSONError(
                "program hash must be nonzero".to_string(),
            ));
        }
        if !registration.input_assignment.input_slots.is_empty()
            && registration.n_inputs as usize != registration.input_assignment.input_slots.len()
        {
            return Err(CoordinatorError::JSONError(format!(
                "Input assignment has {} inputs, but coordinator was configured with {} inputs",
                registration.input_assignment.input_slots.len(),
                registration.n_inputs
            )));
        }
        if registration.min_output_shares == 0 || registration.min_output_shares > n {
            return Err(CoordinatorError::JSONError(format!(
                "Output quorum {} must be between 1 and {n}",
                registration.min_output_shares
            )));
        }
        let n_inputs = usize::try_from(registration.n_inputs)
            .map_err(|_| CoordinatorError::U64ToUsizeError)?;
        Ok(Self {
            registration: registration.clone(),
            retirement_acks: HashSet::new(),
            sinks: HashMap::new(),
            trans_events: HashMap::new(),
            reserved_index_events: vec![],
            reserved_index_sinks: vec![],
            assigned_reserved_index_events: vec![],
            assigned_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            assigned_masked_input_events: vec![],
            assigned_masked_input_sinks: vec![],
            n_reserved: 0,
            reserved_indices: vec![None; n_inputs],
            masked_inputs: vec![None; n_inputs],
            round: Round::Idle,
            output_shares: HashMap::new(),
            output_sinks: HashMap::new(),
            output_clients: registration.output_clients.clone(),
            input_assignments: registration.input_assignment.input_slots.clone(),
        })
    }

    async fn subscribe_oneshot(
        &mut self,
        pending: PendingSubscriptionSink,
        round: Round,
    ) -> SubscriptionResult {
        if round_before(round).is_none() {
            pending
                .reject(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("Cannot subscribe to round {:?}", round),
                    None::<()>,
                ))
                .await;
            return Ok(());
        }

        let sink = pending.accept().await?;

        if let Some(event) = self.trans_events.get(&round) {
            let json = to_json_raw_value(event).expect("failed convert to JSON");
            sink.send(json).await?;
            return Ok(());
        }

        self.sinks.entry(round).or_default().push(sink);
        Ok(())
    }

    async fn subscribe_reserved_indices(
        &mut self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        if !self.reserved_index_events.is_empty() {
            for event in &self.reserved_index_events {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                sink.send(json).await?;
            }
        }

        self.reserved_index_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_masked_inputs(
        &mut self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        if !self.masked_input_events.is_empty() {
            for event in &self.masked_input_events {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                sink.send(json).await?;
            }
        }

        self.masked_input_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_assigned_reserved_indices(
        &mut self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        for event in &self.assigned_reserved_index_events {
            let json = to_json_raw_value(event).expect("failed convert to JSON");
            sink.send(json).await?;
        }

        self.assigned_reserved_index_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_assigned_masked_inputs(
        &mut self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        for event in &self.assigned_masked_input_events {
            let json = to_json_raw_value(event).expect("failed convert to JSON");
            sink.send(json).await?;
        }

        self.assigned_masked_input_sinks.push(sink);
        Ok(())
    }

    async fn transition(&mut self, event: Event, round: Round) -> Result<(), CoordinatorError> {
        if round_before(round).is_none() {
            return Err(CoordinatorError::CannotTransitionToIdle);
        }

        let sinks = self.sinks.remove(&round).unwrap_or_default();

        // Record the round even if one of the existing subscribers has disconnected.
        // Late subscribers will replay this event from history.
        self.trans_events.insert(round, event.clone());

        self.round = round;

        // Broadcast event to all subscribed RPC clients concurrently.
        let results = futures_util::future::join_all(sinks.iter().map(|sink| {
            let json = to_json_raw_value(&event).expect("failed convert to JSON");
            sink.send(json)
        }))
        .await;
        for result in results {
            if result.is_err() {
                eprintln!(
                    "coordinator subscriber disconnected while broadcasting {:?}",
                    round
                );
            }
        }

        Ok(())
    }

    fn ready_output_snapshot(
        &mut self,
        client_id: &ClientIdentity,
        min_shares: usize,
    ) -> Option<(Arc<SubscriptionSink>, Vec<(Vec<u8>, Vec<u8>)>)> {
        let waiter = self.output_sinks.get(client_id)?.clone();
        if waiter.is_closed() {
            self.output_sinks.remove(client_id);
            return None;
        }

        let output_shares = self
            .output_shares
            .iter()
            .filter(|((candidate, _), _)| candidate == client_id)
            .map(|(_, shares)| shares.clone())
            .collect::<Vec<_>>();
        if output_shares.len() < min_shares {
            return None;
        }

        Some((waiter, output_shares))
    }
}

async fn deliver_ready_output_waiters(
    shared: &Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    execution_id: ExecutionId,
    client_id: &ClientIdentity,
    min_shares: usize,
) {
    let Some((waiter, output_shares)) = ({
        let mut shared = shared.lock().await;
        shared
            .executions
            .get_mut(&execution_id)
            .expect("output execution remains registered")
            .ready_output_snapshot(client_id, min_shares)
    }) else {
        return;
    };

    let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
    if waiter.send(json).await.is_err() {
        let mut shared = shared.lock().await;
        if let Some(execution) = shared.executions.get_mut(&execution_id) {
            if execution
                .output_sinks
                .get(client_id)
                .is_some_and(|current| Arc::ptr_eq(current, &waiter))
            {
                execution.output_sinks.remove(client_id);
            }
        }
    }
}

/// Pre-implemented RPC methods.
#[async_trait]
impl CoordinatorRPCBaseServer for CoordinatorRPCServerConnectionBase {
    async fn register_execution(&self, registration: ExecutionRegistration) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only configured MPC parties can register executions.",
                None::<()>,
            ));
        }
        shared.register_execution(registration).map_err(|error| {
            ErrorObjectOwned::owned(
                ErrorCode::ServerError(ExecutionAlreadyRegistered as i32).code(),
                error.to_string(),
                None::<()>,
            )
        })
    }

    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only configured MPC parties can retire executions.",
                None::<()>,
            ));
        }
        shared
            .retire_execution(execution_id, &self.id)
            .map_err(|error| {
                ErrorObjectOwned::owned(
                    ErrorCode::ServerError(ExecutionNotFound as i32).code(),
                    error.to_string(),
                    None::<()>,
                )
            })
    }

    async fn sub_round(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
        round: Round,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };
        d.subscribe_oneshot(pending, round).await
    }

    async fn available_input_masks(&self, execution_id: ExecutionId) -> RpcResult<u64> {
        let d = self.execution_state(execution_id).await?;
        Ok(d.masked_inputs.len() as u64 - d.n_reserved)
    }

    async fn sub_assigned_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };
        d.subscribe_assigned_reserved_indices(pending).await
    }

    async fn sub_assigned_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };
        d.subscribe_assigned_masked_inputs(pending).await
    }

    async fn submit_masked_input(
        &self,
        execution_id: ExecutionId,
        masked_input: Vec<u8>,
        raw_reserved_index: u64,
    ) -> RpcResult<()> {
        let mut d = self.execution_state(execution_id).await?;

        if d.round != Round::InputCollection {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Need round {:?}, current round is {:?}",
                    Round::InputCollection,
                    d.round
                ),
                None::<()>,
            ));
        }

        let reserved_index = raw_reserved_index as usize;

        if reserved_index >= d.masked_inputs.len() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(IndexOutOfBounds as i32).code(),
                format!(
                    "The index {} is out of bounds, there are only {} input masks.",
                    reserved_index,
                    d.masked_inputs.len()
                ),
                None::<()>,
            ));
        }

        match &d.reserved_indices[reserved_index] {
            Some(public_key) => {
                if *public_key != self.id {
                    return Err(ErrorObjectOwned::owned(
                            ErrorCode::ServerError(BadID as i32).code(),
                            format!("Client {:?} cannot submit a masked input for index {}, since this index has been reserved by {:?}", self.id, reserved_index, *public_key),
                            None::<()>
                    ));
                }
                if d.masked_inputs[reserved_index].is_some() {
                    return Err(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(MaskedInputAlreadySubmitted as i32).code(),
                        format!(
                            "Client {:?} has already submitted a masked input for index {}",
                            self.id, reserved_index
                        ),
                        None::<()>,
                    ));
                }
                d.masked_inputs[reserved_index] = Some(masked_input.clone());

                let masked_input_for_assigned = masked_input.clone();
                let event = Event::MaskedInputEvent {
                    client: self.id.clone(),
                    masked_input,
                    reserved_index: raw_reserved_index,
                };
                let assigned_event =
                    d.input_assignments
                        .get(reserved_index)
                        .map(|slot| AssignedMaskedInputEvent {
                            client: self.id.clone(),
                            reserved_index: raw_reserved_index,
                            input_ordinal: slot.label,
                            masked_input: masked_input_for_assigned,
                        });
                d.masked_input_events.push(event.clone());
                if let Some(assigned_event) = assigned_event.clone() {
                    d.assigned_masked_input_events.push(assigned_event);
                }

                let sinks = std::mem::take(&mut d.masked_input_sinks);
                for sink in sinks {
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    if sink.send(json).await.is_ok() {
                        d.masked_input_sinks.push(sink);
                    } else {
                        eprintln!("coordinator masked-input subscriber disconnected");
                    }
                }
                if let Some(assigned_event) = assigned_event {
                    let assigned_sinks = std::mem::take(&mut d.assigned_masked_input_sinks);
                    for sink in assigned_sinks {
                        let json =
                            to_json_raw_value(&assigned_event).expect("failed convert to JSON");
                        if sink.send(json).await.is_ok() {
                            d.assigned_masked_input_sinks.push(sink);
                        } else {
                            eprintln!("coordinator assigned masked-input subscriber disconnected");
                        }
                    }
                }
            }
            None => {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(IndexNotReserved as i32).code(),
                    format!(
                        "Cannot submit a masked input for index {}, since it has not been reserved",
                        reserved_index
                    ),
                    None::<()>,
                ));
            }
        }

        Ok(())
    }

    async fn sub_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };
        d.subscribe_reserved_indices(pending).await
    }

    async fn sub_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };
        d.subscribe_masked_inputs(pending).await
    }

    async fn reserve_mask_index(&self, execution_id: ExecutionId, i: u64) -> RpcResult<()> {
        let mut d = self.execution_state(execution_id).await?;

        if d.round != Round::InputMaskReservation {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Need round {:?}, current round is {:?}",
                    Round::InputMaskReservation,
                    d.round
                ),
                None::<()>,
            ));
        }

        if i as usize >= d.reserved_indices.len() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(IndexOutOfBounds as i32).code(),
                format!(
                    "The index {} is out of bounds, there are only {} input masks.",
                    i,
                    d.reserved_indices.len()
                ),
                None::<()>,
            ));
        }

        if d.reserved_indices[i as usize].is_some() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(IndexAlreadyReserved as i32).code(),
                format!("Index {} already reserved.", i),
                None::<()>,
            ));
        }

        let assigned_reservation = if let Some(slot) = d.input_assignments.get(i as usize) {
            // The duplicate-reservation check above only proves the index is free; assigned input
            // slots also need to be reserved by the client they were bound to.
            if slot.client != self.id {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(UnauthorizedClientIo as i32).code(),
                    format!(
                        "Client {:?} cannot reserve assigned input index {}, which belongs to {:?}",
                        self.id, i, slot.client
                    ),
                    None::<()>,
                ));
            }
            Some(AssignedMaskReservation {
                client: self.id.clone(),
                reserved_index: i,
                input_ordinal: slot.label,
            })
        } else {
            None
        };

        d.reserved_indices[i as usize] = Some(self.id.clone());

        let event = Event::ReservedInputEvent {
            client: self.id.clone(),
            reserved_index: i,
        };

        d.n_reserved += 1;
        d.reserved_index_events.push(event.clone());

        if let Some(assigned_reservation) = assigned_reservation.clone() {
            d.assigned_reserved_index_events
                .push(assigned_reservation.clone());
        }

        // Broadcast reserved index to all subscribed RPC clients. Disconnected
        // subscribers are pruned; late/restarted nodes replay from event history.
        let sinks = std::mem::take(&mut d.reserved_index_sinks);
        for sink in sinks {
            let json = to_json_raw_value(&event).expect("failed convert to JSON");
            if sink.send(json).await.is_ok() {
                d.reserved_index_sinks.push(sink);
            } else {
                eprintln!("coordinator reserved-index subscriber disconnected");
            }
        }
        if let Some(assigned_reservation) = assigned_reservation {
            let assigned_sinks = std::mem::take(&mut d.assigned_reserved_index_sinks);
            for sink in assigned_sinks {
                let json =
                    to_json_raw_value(&assigned_reservation).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.assigned_reserved_index_sinks.push(sink);
                } else {
                    eprintln!("coordinator assigned reserved-index subscriber disconnected");
                }
            }
        }

        Ok(())
    }

    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()> {
        let designated_party = {
            let shared = self.d.lock().await;
            shared.mpc_nodes[0].clone()
        };
        let mut d = self.execution_state(execution_id).await?;

        if self.id != designated_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotDesignatedParty as i32).code(),
                format!(
                    "Only designated party {:?} can do transitions.",
                    designated_party
                ),
                None::<()>,
            ));
        }

        let skips_empty_input_rounds = d.masked_inputs.is_empty()
            && d.round == Round::Preprocessing
            && next_round == Round::MPCExecution;
        if round_before(next_round) != Some(d.round) && !skips_empty_input_rounds {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Cannot transition execution {execution_id} from {:?} to {:?}",
                    d.round, next_round
                ),
                None::<()>,
            ));
        }

        match next_round {
            Round::Idle => {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("Round {:?} cannot be transitioned to", Round::Idle),
                    None::<()>,
                ));
            }
            Round::Preprocessing => d
                .transition(
                    Event::PreprocessingStarted {
                        designated_party: self.id.clone(),
                    },
                    next_round,
                )
                .await
                .unwrap(),
            Round::InputMaskReservation => d
                .transition(Event::InputMaskReservationStarted, next_round)
                .await
                .unwrap(),
            Round::InputCollection => d
                .transition(Event::InputCollectionStarted, next_round)
                .await
                .unwrap(),
            Round::MPCExecution => d.transition(Event::MPCStarted, next_round).await.unwrap(),
            Round::OutputDistribution => d
                .transition(Event::OutputSendingStarted, next_round)
                .await
                .unwrap(),
            Round::ProgramFinished => d
                .transition(Event::ExecutionDone, next_round)
                .await
                .unwrap(),
        };

        #[cfg(feature = "benchmark")]
        {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            println!("BENCH_ROUND: {:?} ts={}", next_round, ts);
        }

        Ok(())
    }

    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()> {
        let is_party = {
            let shared = self.d.lock().await;
            shared.mpc_nodes.contains(&self.id)
        };
        let mut d = self.execution_state(execution_id).await?;

        if !is_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only parties can send output shares.",
                None::<()>,
            ));
        }
        if !d.output_clients.contains(&client_id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotOutputClient as i32).code(),
                "Output client is not authorized for this execution.",
                None::<()>,
            ));
        }

        // a node cannot send output shares for a client twice
        if d.output_shares
            .contains_key(&(client_id.clone(), self.id.clone()))
        {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(OutputSharesAlreadySent as i32).code(),
                format!(
                    "Client {:?} already has submitted their output shares.",
                    client_id
                ),
                None::<()>,
            ));
        }

        // output shares for `client_id` from `self.id`
        d.output_shares
            .insert((client_id.clone(), self.id.clone()), enc_shares);

        let min_shares = d.registration.min_output_shares as usize;
        drop(d);
        deliver_ready_output_waiters(&self.d, execution_id, &client_id, min_shares).await;
        Ok(())
    }

    async fn obtain_output_shares(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        let Ok(mut d) = self.execution_state(execution_id).await else {
            pending.reject(execution_not_found(execution_id)).await;
            return Ok(());
        };

        if !d.output_clients.contains(&self.id) {
            pending
                .reject(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(NotOutputClient as i32).code(),
                    format!("Client {:?} is not an authorized output client.", self.id),
                    None::<()>,
                ))
                .await;
            return Ok(());
        }

        if d.output_sinks
            .get(&self.id)
            .is_some_and(|sink| !sink.is_closed())
        {
            pending
                .reject(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(OutputSharesAlreadyRequested as i32).code(),
                    "Output shares already requested.",
                    None::<()>,
                ))
                .await;
            return Ok(());
        }

        let sink = pending.accept().await?;
        d.output_sinks.insert(self.id.clone(), Arc::new(sink));
        let min_shares = d.registration.min_output_shares as usize;
        drop(d);
        deliver_ready_output_waiters(&self.d, execution_id, &self.id, min_shares).await;

        Ok(())
    }
}

/// The pre-implemented RPC server-side connection can be used as a full-fledged RPC server
/// connection.
impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection
    for CoordinatorRPCServerConnectionBase
{
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        crate::CoordinatorRPCBaseServer::into_rpc(self)
    }
}

/// The exterior wrapper of the server-side coordinator.
pub struct OffChainCoordinatorServer<C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection> {
    addr: String,
    server_handle: RPCServerHandle,
    _connection: std::marker::PhantomData<C>,
}

pub struct OffChainCoordinatorClient<F: FftField, S: ShareBound<F>> {
    rpc_coord: Client,
    execution_id: ExecutionId,
    t: u64,
    n_parties: u64,
    n_outputs: u64,
    key_der: Vec<u8>,
    _phantom: std::marker::PhantomData<(F, S)>,
}

impl<C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection> OffChainCoordinatorServer<C> {
    pub async fn start_coord_from_cert(
        shared: C::Internal,
        addr: &str,
        port: u16,
        t: u64,
        cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
    ) -> Result<Self, CoordinatorError> {
        Self::start_coord(
            shared,
            addr,
            port,
            t,
            cert.cert.der().to_vec(),
            cert.signing_key.serialize_der(),
        )
        .await
    }

    pub async fn start_coord(
        shared: C::Internal,
        addr: &str,
        port: u16,
        _t: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        let server_handle = stoffel_mpc_coordinator_shared::rpc::start_coord::<C>(
            addr,
            port,
            cert_der,
            key_der,
            rpc_server_data.clone(),
        )
        .await?;
        Ok(Self {
            addr: String::from(addr),
            server_handle,
            _connection: std::marker::PhantomData,
        })
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone()
    }

    /// Stops the listener. Dropping the server state closes its connections.
    pub async fn shutdown(self) {
        self.server_handle.shutdown().await;
    }
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    #[allow(clippy::too_many_arguments)]
    pub async fn start_rpc_client_for_execution(
        addr: &str,
        port: u16,
        t: u64,
        n_parties: u64,
        n_outputs: u64,
        execution_id: ExecutionId,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_coord = stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
            addr,
            port,
            cert_der,
            key_der.clone(),
        )
        .await?;

        Ok(Self {
            rpc_coord,
            execution_id,
            t,
            n_parties,
            n_outputs,
            key_der,
            _phantom: std::marker::PhantomData,
        })
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::transition(self.rpc(), self.execution_id, round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(())
    }

    pub async fn register_execution(
        &self,
        registration: ExecutionRegistration,
    ) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::register_execution(self.rpc(), registration)
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))
    }

    pub async fn retire_execution(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::retire_execution(self.rpc(), self.execution_id)
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))
    }

    fn rpc(&self) -> &Client {
        &self.rpc_coord
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

fn execution_enc_info(execution_id: ExecutionId) -> Vec<u8> {
    let mut info = Vec::with_capacity(ENC_INFO.len() + execution_id.as_bytes().len());
    info.extend_from_slice(ENC_INFO);
    info.extend_from_slice(execution_id.as_bytes());
    info
}

impl<F: FftField, S: ShareBound<F>> Coordinator<F, S> for OffChainCoordinatorClient<F, S> {
    type ClientIdentity = ClientIdentity;

    async fn start_preprocessing(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_preprocessing(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn reserve_input_masks(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::reserve_input_masks(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn collect_inputs(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::collect_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn start_mpc(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_mpc(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn send_output(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::send_output(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn finalize(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::finalize(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> Result<HashMap<ClientIdentity, Vec<u64>>, CoordinatorError> {
        // Wait for reserved index events.
        let mut sub = CoordinatorRPCBaseClient::sub_reserved_indices(self.rpc(), self.execution_id)
            .await
            .unwrap();

        let mut map: HashMap<ClientIdentity, Vec<u64>> = HashMap::new();

        // Parse reserved index events one after the other.
        for _ in 0..n_inputs {
            if let Some(Ok(Event::ReservedInputEvent {
                client,
                reserved_index,
            })) = sub.next().await
            {
                map.entry(client).or_default().push(reserved_index);
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before event could be received".to_string(),
                ));
            }
        }

        Ok(map)
    }

    async fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> Result<HashMap<ClientIdentity, Vec<S>>, CoordinatorError> {
        // Wait for masked input events.
        let mut sub = CoordinatorRPCBaseClient::sub_masked_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let mut map: HashMap<ClientIdentity, Vec<(u64, S)>> = HashMap::new();

        // Parse masked input events one after the other.
        for _ in 0..n_inputs {
            if let Some(Ok(Event::MaskedInputEvent {
                client,
                masked_input,
                reserved_index,
            })) = sub.next().await
            {
                let i = reserved_index as usize;
                let mask_share = &mask_shares[i];
                let masked_input = S::ValueType::deserialize_compressed(masked_input.as_slice())
                    .map_err(|_| CoordinatorError::DeserializationError)?;
                let input = S::compute_masked_input(masked_input, mask_share)
                    .map_err(|_| CoordinatorError::ShareError)?;

                map.entry(client).or_default().push((reserved_index, input));
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before event could be received".to_string(),
                ));
            }
        }

        Ok(map
            .into_iter()
            .map(|(client, mut indexed_inputs)| {
                indexed_inputs.sort_by_key(|(reserved_index, _)| *reserved_index);
                let inputs = indexed_inputs
                    .into_iter()
                    .map(|(_, input)| input)
                    .collect::<Vec<_>>();
                (client, inputs)
            })
            .collect())
    }

    async fn wait_for_round(&self, round: Round) -> Result<(), CoordinatorError> {
        let mut sub = CoordinatorRPCBaseClient::sub_round(self.rpc(), self.execution_id, round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        if let Some(Ok(_)) = sub.next().await {
            Ok(())
        } else {
            Err(CoordinatorError::JSONError(
                "Subscription ended before event could be received".to_string(),
            ))
        }
    }

    async fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> Result<(), CoordinatorError> {
        let mut masked_input_bytes = Vec::new();
        masked_input
            .serialize_compressed(&mut masked_input_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;
        match CoordinatorRPCBaseClient::submit_masked_input(
            self.rpc(),
            self.execution_id,
            masked_input_bytes,
            i,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(CoordinatorError::JSONError(e.to_string())),
        }
    }

    async fn reserve_mask_index(&mut self, i: u64) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::reserve_mask_index(self.rpc(), self.execution_id, i)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn obtain_outputs(&self) -> Result<Vec<S::ValueType>, CoordinatorError> {
        // Wait for output shares.
        let mut sub =
            match CoordinatorRPCBaseClient::obtain_output_shares(self.rpc(), self.execution_id)
                .await
            {
                Ok(sub) => sub,
                Err(e) => {
                    return Err(CoordinatorError::JSONError(e.to_string()));
                }
            };

        // Parse the secret key for decryption.
        let client_sk = {
            let der_bytes = self.key_der.clone();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk)
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        let enc_info = execution_enc_info(self.execution_id);

        // Try to decrypt and reconstruct outputs until it succeeds.
        while let Some(Ok(enc_output_shares)) = sub.next().await {
            let min_shares = S::min_shares(self.t as usize);
            if enc_output_shares.len() < min_shares {
                return Err(CoordinatorError::SubscriptionError(format!(
                    "Received {} output shares, but at least {} are required",
                    enc_output_shares.len(),
                    min_shares
                )));
            }

            let mut output_shares = Vec::new();
            for (encapped_key_bytes, c) in enc_output_shares.iter() {
                let encapped_key = <KemImpl as Kem>::EncappedKey::from_bytes(encapped_key_bytes)
                    .map_err(|_| CoordinatorError::ParsingEncapsulatedKeyFailed)?;
                let output_shares_bytes = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base,
                    &client_sk,
                    &encapped_key,
                    &enc_info,
                    c,
                    b"",
                )
                .map_err(|_| CoordinatorError::DecryptionError)?;
                let shares: Vec<S> =
                    CanonicalDeserialize::deserialize_compressed(output_shares_bytes.as_slice())
                        .map_err(|_| CoordinatorError::DeserializationError)?;

                if shares.len() as u64 != self.n_outputs {
                    println!("Some node sent an invalid number of output shares, ignoring.");
                    continue;
                }

                output_shares.push(shares);
            }

            let outputs: Vec<_> = (0..self.n_outputs as usize)
                .filter_map(|i| {
                    // shares for the ith output
                    let shares_i: Vec<_> = output_shares
                        .iter()
                        .map(|shares| shares[i].clone())
                        .collect();

                    // At least S::min_shares(t) shares are available as checked above.
                    match S::recover_secret(&shares_i, self.n_parties as usize, self.t as usize) {
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

            // Once all outputs have successfully been reconstructed, return them.
            if outputs.len() == self.n_outputs as usize {
                return Ok(outputs);
            }
        }

        Err(CoordinatorError::JSONError(
            "Output shares subscription ended before enough output shares could be obtained"
                .to_string(),
        ))
    }

    async fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> Result<(), CoordinatorError> {
        // Parse the inputs.
        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key)
            .map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let mut output_shares_bytes = Vec::new();
        output_shares
            .serialize_compressed(&mut output_shares_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;

        // Encrypt the shares.
        let mut rng = StdRng::from_os_rng();
        let enc_info = execution_enc_info(self.execution_id);
        let (encapsulated_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
            &OpModeS::Base,
            &client_pk,
            &enc_info,
            &output_shares_bytes,
            b"",
            &mut rng,
        )
        .map_err(|_| CoordinatorError::EncryptionError)?;
        let c = (encapsulated_key.to_bytes().to_vec(), ciphertext);

        // Send the encrypted shares.
        if let Err(e) = CoordinatorRPCBaseClient::send_output_shares(
            self.rpc(),
            self.execution_id,
            client_id,
            c,
        )
        .await
        {
            return Err(CoordinatorError::JSONError(e.to_string()));
        }

        Ok(())
    }
}
