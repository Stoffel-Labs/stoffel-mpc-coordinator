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
use jsonrpsee::core::JsonRawValue;
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
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
pub use stoffel_mpc_coordinator_shared::ClientIdentity;
use stoffel_mpc_coordinator_shared::{
    masked_inputs_signing_bytes, round_before, round_index,
    rpc::{CapacityClass, RPCServerHandle, RpcServerLimits},
    sealed_output_signing_bytes, sign_with_pkcs8, verify_identity_signature, AbortReason,
    AdmissionError, AdmissionPolicy, AdmissionPolicyKind, AssociationRequest, ClientAdmission,
    ClientAdmissionRecord, ClientAdmissionSet, ClientIndex, ClientSlotTable, Coordinator,
    CoordinatorError, ExecutionDeadlines, ExecutionId, ExecutionOutcome, InputRange,
    InvitationContext, KeyAlgorithm, NodeRoster, NodeRosterWire, OutputRights, PositionedShare,
    Reconstruction, RegistrationError, RegistrationNonce, RosterDigest, Round, RpcRefusal,
    ServerPin, ShareBound, SpkiDer, SubmissionError, UnixSeconds, MAX_MASKED_INPUT_BYTES,
    MAX_SEALED_OUTPUT_BYTES,
};
use tokio::sync::{oneshot, Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;

/// KEM, KDF, and AEAD instantiations are needed to encrypt the output shares for an MPC client
/// before sending them to the coordinator.
type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

// An MPC client interacts with two types of entities: the coordinator and nodes. Towards both it
// authenticates with the same certificate key over mutual TLS, and both key every authorization
// on the caller's `ClientIdentity`: the coordinator binds it to a client slot when the client
// associates, and a node releases a mask share only to the identity the agreed admission set
// names for that share's index. `ClientIdentity` lives in `stoffel-mpc-coordinator-shared` and is
// re-exported here.

/// A deliberately small, explicit bound for the number of live executions owned by one RPC
/// listener. Finished executions must be retired before this many more are registered.
pub const DEFAULT_MAX_CONCURRENT_EXECUTIONS: usize = 1024;
/// How long a replayed subscription item may wait for the subscriber's connection queue.
const SUBSCRIPTION_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a one-off coordinator waits, once the retirement quorum of a terminal round has
/// acknowledged, for the execution to be removed. Unanimous acknowledgement closes sooner.
pub const DEFAULT_ONE_OFF_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
pub struct OneOffShutdownConfig {
    pub execution_id: ExecutionId,
    pub grace: Duration,
}

/// How many sealed-but-not-unanimously-acknowledged executions are remembered. A sealed
/// execution holds no protocol state, so this only has to be large enough that a slow but
/// honest party can still acknowledge its own executions after the quorum sealed them.
pub const DEFAULT_MAX_RETIRED_EXECUTIONS: usize = 4096;
/// How many ended executions are remembered, whatever path they left by. Acknowledgements
/// never shorten this memory; only the bound does, oldest first.
pub const DEFAULT_MAX_ENDED_EXECUTIONS: usize = 4096;
/// How long an execution with output slots stays after its unanimous retirement, so a client
/// that subscribes late still receives every node's sealed output.
pub const DEFAULT_OUTPUT_RETENTION: Duration = Duration::from_secs(60);
/// Parked subscriptions one caller may hold in one list; parking a fifth drops its oldest.
pub const MAX_PARKED_SUBSCRIPTIONS_PER_CALLER: usize = 4;

/// One mask share a node's RPC listener releases to `client`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskReservation {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    /// `reserved_index - input_range.start` of the client's agreed admission.
    pub input_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

/// The reservations an agreed admission set implies: every index of every record's input
/// range, owned by that record's identity, with `input_ordinal = index - start`. Every node
/// applies this same rule to the same frozen set, so every node releases each mask share to the
/// same identity.
pub fn admitted_reservations(set: &ClientAdmissionSet) -> Vec<AssignedMaskReservation> {
    set.records
        .iter()
        .filter_map(|record| record.input_range.map(|range| (record, range)))
        .flat_map(|(record, range)| {
            (range.start..range.end()).map(move |reserved_index| AssignedMaskReservation {
                client: record.client.clone(),
                reserved_index,
                input_ordinal: reserved_index - range.start,
            })
        })
        .collect()
}

/// Immutable data that binds one invocation to its program, its client slot table and its
/// admission policy. Registered in-process by the operator; never sent over the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRegistration {
    pub execution_id: ExecutionId,
    /// `program_hash_of` the compiled program bytes.
    pub program_hash: [u8; 32],
    pub client_slots: ClientSlotTable,
    pub admission: AdmissionPolicy,
    /// Required under `Open` and `Invitation`, optional under `PreRegistered`.
    pub deadlines: Option<ExecutionDeadlines>,
}

impl ExecutionRegistration {
    /// The rows of the validation table that read no coordinator state, in table order.
    pub fn validate(
        &self,
        roster: &NodeRoster,
        server_spki: &SpkiDer,
        now: UnixSeconds,
    ) -> Result<(), RegistrationError> {
        if self.execution_id.is_zero() {
            return Err(RegistrationError::ZeroExecutionId);
        }
        if self.program_hash == [0; 32] {
            return Err(RegistrationError::ZeroProgramHash);
        }
        self.client_slots.check_bounds()?;
        self.admission
            .check(&self.client_slots, roster, server_spki)?;
        self.admission.check_deadlines(self.deadlines, now)
    }
}

/// What any caller may learn about a registered execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub execution_id: ExecutionId,
    pub registration_nonce: RegistrationNonce,
    pub program_hash: [u8; 32],
    pub client_slots: ClientSlotTable,
    pub admission: AdmissionPolicyKind,
    pub deadlines: Option<ExecutionDeadlines>,
    pub round: Round,
}

/// One slot's masked inputs exactly as its client submitted them and the coordinator delivered
/// them, before any node unmasks them. `Event::MaskedInputEvent` carries one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedInputSubmission {
    pub client: ClientIdentity,
    pub first_index: u64,
    pub masked_inputs: Vec<Vec<u8>>,
    /// The client's signature over `masked_inputs_signing_bytes`.
    pub signature: Vec<u8>,
}

/// `send_output_shares`' parameter: one node's sealed output shares for one client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOutput {
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// The sending node's signature over `sealed_output_signing_bytes`.
    pub signature: Vec<u8>,
}

/// `obtain_output_shares`' item: one node's `SealedOutput`, with the roster position of the node
/// that sent it. One message per node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOutputShares {
    pub node_position: u32,
    pub sealed: SealedOutput,
}

/// The node-side RPC interface.
pub mod node_rpc {
    use super::{AssignedMaskReservation, AssignedMaskShare, ClientIdentity};
    use ark_ff::FftField;
    use ark_serialize::CanonicalSerialize;
    use async_trait::async_trait;
    use jsonrpsee::{
        async_client::Client,
        core::{to_json_raw_value, JsonRawValue, SubscriptionResult},
        proc_macros::rpc,
        server::RpcModule,
        types::{error::ErrorCode, ErrorObjectOwned},
        PendingSubscriptionSink, SubscriptionSink,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, HashSet};
    use std::marker::PhantomData;
    use std::sync::Arc;
    use stoffel_mpc_coordinator_shared::{
        rpc::{CapacityClass, RPCServerHandle, RpcServerLimits},
        self_signed_certs::{connect_roster_legs, NODE_LEG_CONNECT_TIMEOUT},
        CoordinatorError, ExecutionId, NodeRPCError, NodeRoster, PositionedShare, Reconstruction,
        ShareBound,
    };
    use tokio::sync::{oneshot, Mutex};
    use tokio::task::JoinSet;

    /// Errors returned by the node-side RPC interface.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OffChainNodeRPCServerError {
        SerializationError = 1,
        ExecutionNotFound = 2,
        /// The requested range names an index registered to another identity, overflows, or —
        /// once the execution's reservations are sealed — names an index registered to no one.
        RangeNotAssignedToCaller = 3,
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
    ///
    /// Every leg is pinned to a member of the node roster, and every share a leg serves is
    /// attributed to that member's roster position.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        /// One pinned connection per distinct roster member.
        legs: Vec<NodeLeg>,
        /// Total number of MPC nodes in the roster (used for share reconstruction).
        n: usize,
        /// The roster's threshold.
        t: usize,
        /// The program invocation to which all RPC calls made by this handle belong.
        execution_id: ExecutionId,
        _phantom: PhantomData<(F, S)>,
    }

    /// One pinned node RPC connection and the roster position of the key that answered it.
    struct NodeLeg {
        /// Shared so each leg's subscription runs in its own task, independent of the others.
        client: Arc<Client>,
        position: usize,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        /// Connects to every address in `addrs`, admitting only servers that prove possession
        /// of a key in `roster`.
        ///
        /// A leg that misbehaves costs only itself: unreachable, not connected within
        /// `NODE_LEG_CONNECT_TIMEOUT`, presenting a key outside the roster, or answering as a
        /// roster member already connected — each is dropped with a warning. A node owns its
        /// own listener, so making any of these fatal would hand one corrupt roster member a
        /// denial-of-service switch over every client. If NO address connects the result is
        /// `ConnectError`. `TooManyNodeAddresses` remains fatal because it is the caller's own
        /// argument being wrong.
        ///
        /// Callers that need a minimum number of nodes must check [`Self::leg_count`]; share
        /// reconstruction enforces its own threshold downstream. See `connect_roster_legs`.
        /// How many distinct roster members actually answered.
        ///
        /// Legs are dropped rather than fatal, so this can be smaller than the address list
        /// the caller passed — and smaller than `n`. A caller needing a quorum checks it here.
        pub fn leg_count(&self) -> usize {
            self.legs.len()
        }

        pub async fn start_rpc_client_for_execution(
            roster: &NodeRoster,
            addrs: Vec<(String, u16)>,
            execution_id: ExecutionId,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let n = usize::try_from(roster.n()).map_err(|_| CoordinatorError::U64ToUsizeError)?;
            let t = usize::try_from(roster.t()).map_err(|_| CoordinatorError::U64ToUsizeError)?;
            let legs = connect_roster_legs(
                roster,
                &addrs,
                &cert_der,
                &key_der,
                NODE_LEG_CONNECT_TIMEOUT,
            )
            .await?
            .into_iter()
            .map(|leg| NodeLeg {
                client: Arc::new(leg.client),
                position: leg.position,
            })
            .collect();

            Ok(Self {
                legs,
                n,
                t,
                execution_id,
                _phantom: PhantomData,
            })
        }

        /// Receives the mask shares for `start..start + count` from every leg and reconstructs
        /// each mask by roster position.
        ///
        /// A leg that refuses the subscription, ends without an answer, answers for another index
        /// range or serves a share that does not deserialize counts as that leg answering with
        /// nothing. Legs are awaited concurrently, so a stalled leg never delays the others. Returns as soon as
        /// every index reconstructs; fails with `MaskReconstructionFailed` once every leg has
        /// answered or ended without that. It takes no timeout of its own.
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

            // Each leg subscribes and waits inside its own task, so a leg that refuses the
            // subscription (for example one that has not registered or has already retired the
            // execution) or never answers only fails to contribute; it neither aborts the call
            // nor delays the other legs.
            for leg in self.legs.iter() {
                let client = Arc::clone(&leg.client);
                let position = leg.position;
                let execution_id = self.execution_id;
                share_futures.spawn(async move {
                    let answer = match client
                        .receive_assigned_mask_shares(execution_id, start, count)
                        .await
                    {
                        Ok(mut sub) => sub.next().await,
                        Err(error) => {
                            tracing::debug!(
                                position,
                                %error,
                                "node leg refused the assigned mask share subscription"
                            );
                            None
                        }
                    };
                    (position, answer)
                });
            }

            let expected_indices = (start..end).collect::<Vec<_>>();
            let mut shares_by_index: HashMap<u64, Vec<PositionedShare<S>>> = HashMap::new();
            let mut secrets: HashMap<u64, S::ValueType> = HashMap::new();

            while let Some(joined) = share_futures.join_next().await {
                let Ok((position, Some(Ok(assigned_shares)))) = joined else {
                    // A leg that ended, failed or panicked contributes nothing.
                    continue;
                };
                let Some(shares) = leg_shares::<F, S>(&assigned_shares, &expected_indices) else {
                    continue;
                };
                for (reserved_index, share) in expected_indices.iter().zip(shares) {
                    if secrets.contains_key(reserved_index) {
                        continue;
                    }
                    let positioned = shares_by_index.entry(*reserved_index).or_default();
                    positioned.push(PositionedShare { position, share });
                    if let Reconstruction::Secret(secret) =
                        S::reconstruct(positioned, self.n, self.t)
                    {
                        secrets.insert(*reserved_index, secret);
                    }
                }

                if secrets.len() == expected_indices.len() {
                    break;
                }
            }

            expected_indices
                .iter()
                .map(|reserved_index| {
                    secrets.remove(reserved_index).ok_or(
                        CoordinatorError::MaskReconstructionFailed {
                            index: *reserved_index,
                        },
                    )
                })
                .collect()
        }
    }

    /// One leg's answer as shares in `expected_indices` order, or `None` when the answer covers
    /// another range or any of its shares does not deserialize.
    fn leg_shares<F: FftField, S: ShareBound<F>>(
        assigned_shares: &[AssignedMaskShare],
        expected_indices: &[u64],
    ) -> Option<Vec<S>> {
        let mut by_index = assigned_shares
            .iter()
            .map(|assigned_share| (assigned_share.reserved_index, assigned_share))
            .collect::<HashMap<_, _>>();
        if by_index.len() != assigned_shares.len() || by_index.len() != expected_indices.len() {
            return None;
        }
        expected_indices
            .iter()
            .map(|reserved_index| {
                let assigned_share = by_index.remove(reserved_index)?;
                ark_serialize::CanonicalDeserialize::deserialize_compressed(
                    assigned_share.share_bytes.as_slice(),
                )
                .ok()
            })
            .collect()
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
                    RpcServerLimits::default(),
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
            self.add_assigned_reserved_indices_for_execution(execution_id, vec![reservation])
                .await
        }

        /// Registers every reservation in `reservations` in one call and leaves the execution
        /// open to further reservations. A registered reservation is what releases a mask
        /// share. Refused with `ReservationsSealed` once
        /// `register_admitted_reservations_for_execution` has run for the execution.
        pub async fn add_assigned_reserved_indices_for_execution(
            &self,
            execution_id: ExecutionId,
            reservations: Vec<AssignedMaskReservation>,
        ) -> Result<(), NodeRPCError> {
            self.register_reservations(
                execution_id,
                reservations,
                ReservationRegistration::Incremental,
            )
            .await
        }

        /// Registers an execution's complete reservation set — `admitted_reservations` of its
        /// agreed, frozen admission set — and seals it. A node registers only the reservations
        /// that set implies, so every node releases each mask share to the same identity.
        ///
        /// Once sealed, no reservation can be added, and a mask request is answered only when
        /// every index of its range is registered to its caller: every parked request that
        /// does not qualify (including every request from an identity holding no reservation)
        /// is dropped, which closes its stream, and a later one is refused at subscribe time.
        pub async fn register_admitted_reservations_for_execution(
            &self,
            execution_id: ExecutionId,
            reservations: Vec<AssignedMaskReservation>,
        ) -> Result<(), NodeRPCError> {
            self.register_reservations(execution_id, reservations, ReservationRegistration::Sealing)
                .await
        }

        async fn register_reservations(
            &self,
            execution_id: ExecutionId,
            reservations: Vec<AssignedMaskReservation>,
            registration: ReservationRegistration,
        ) -> Result<(), NodeRPCError> {
            let state = self.execution_state(execution_id).await?;
            let completed;
            {
                let mut d = state.lock().await;

                // Every check runs before any mutation, so a refused batch leaves no index
                // registered and can be retried as a whole.
                if d.reservations_sealed {
                    return Err(NodeRPCError::ReservationsSealed);
                }
                let mut batch_indices = HashSet::with_capacity(reservations.len());
                for reservation in &reservations {
                    if d.index_to_client.contains_key(&reservation.reserved_index)
                        || !batch_indices.insert(reservation.reserved_index)
                    {
                        return Err(NodeRPCError::IndexAlreadyAdded);
                    }
                }

                // Phase 1: register every reservation in the batch before checking any pending
                // range request below. A range request only completes once every index in its
                // range has both a reservation and a share, so checking it once per registration
                // in this batch (instead of once after all of them land) can only produce the
                // same answer more slowly.
                let mut touched_clients: Vec<ClientIdentity> = Vec::new();
                for reservation in &reservations {
                    let id = reservation.client.clone();
                    let i = reservation.reserved_index;

                    d.index_to_client.insert(i, id.clone());
                    d.assigned_reservations.insert(i, reservation.clone());
                    if !touched_clients.contains(&id) {
                        touched_clients.push(id);
                    }
                }

                // Phase 2: check the affected requests. This cannot fail: a request that turns
                // out to name an index that is not its caller's fails alone (see
                // `complete_pending_requests`). Sealing re-checks every parked request, since a
                // request no reservation touched can never complete once nothing more is
                // registered.
                let to_check = match registration {
                    ReservationRegistration::Incremental => touched_clients,
                    ReservationRegistration::Sealing => {
                        d.reservations_sealed = true;
                        d.assigned_sinks.keys().cloned().collect()
                    }
                };
                completed = d.complete_pending_requests(to_check);
            }
            drop(state);

            self.rpc_server
                .lock()
                .await
                .record_reservations(execution_id, &reservations);

            send_completed_requests(completed);

            Ok(())
        }

        pub async fn add_mask_share_for_execution<S: CanonicalSerialize>(
            &self,
            execution_id: ExecutionId,
            i: u64,
            share: &S,
        ) -> Result<(), NodeRPCError> {
            self.add_mask_shares_for_execution(execution_id, &[(i, share)])
                .await
        }

        /// Batch form of `add_mask_share_for_execution`: registers every `(index, share)` pair
        /// in `shares` while holding this execution's state lock only once, instead of the
        /// caller looping and re-acquiring the lock (and re-checking every affected client's
        /// pending range request) once per index.
        pub async fn add_mask_shares_for_execution<S: CanonicalSerialize>(
            &self,
            execution_id: ExecutionId,
            shares: &[(u64, &S)],
        ) -> Result<(), NodeRPCError> {
            let state = self.execution_state(execution_id).await?;
            let completed;
            {
                let mut d = state.lock().await;

                // Every check, including serialization, runs before any mutation, so a refused
                // batch leaves no share recorded.
                let mut batch_indices = HashSet::with_capacity(shares.len());
                let mut serialized = Vec::with_capacity(shares.len());
                for (i, share) in shares {
                    if d.mask_shares.contains_key(i) || !batch_indices.insert(*i) {
                        return Err(NodeRPCError::IndexAlreadyAdded);
                    }
                    let mut share_bytes = Vec::new();
                    share
                        .serialize_compressed(&mut share_bytes)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    serialized.push((*i, share_bytes));
                }

                // Phase 1: record every share in the batch before checking any pending range
                // request below, for the same reason `add_assigned_reserved_indices_for_execution`
                // does.
                let mut touched_clients: Vec<ClientIdentity> = Vec::new();
                for (i, share_bytes) in serialized {
                    d.mask_shares.insert(i, share_bytes);

                    if let Some(id) = d.index_to_client.get(&i).cloned() {
                        if !touched_clients.contains(&id) {
                            touched_clients.push(id);
                        }
                    }
                }

                // Phase 2: now that the batch's shares are all recorded, check once per affected
                // client whether its pending range request can be satisfied.
                completed = d.complete_pending_requests(touched_clients);
            }

            send_completed_requests(completed);

            Ok(())
        }
    }

    /// The server-side information for one client connection to the node-side RPC interface.
    pub struct NodeRPCServerImpl {
        /// A reference to the server's shared state.
        d: Arc<Mutex<NodeRPCServerInternal>>,
        /// The connected client's identity (`caller_identity` of its certificate).
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

        /// A caller holding a registered reservation is a bound client; everyone else,
        /// including every other node (no node dials this listener), is unreserved.
        fn capacity_class(internal: &Self::Internal, id: &ClientIdentity) -> CapacityClass {
            if internal.reserved_identities.contains_key(id) {
                CapacityClass::BoundClient
            } else {
                CapacityClass::Unreserved
            }
        }
    }

    /// The internal state of the node-side RPC server.
    pub struct NodeRPCServerInternal {
        executions: HashMap<ExecutionId, Arc<Mutex<NodeRPCExecutionState>>>,
        /// Every identity holding a registered reservation, with the executions it holds one
        /// in. Read by `capacity_class` without touching any execution's state lock.
        reserved_identities: HashMap<ClientIdentity, HashSet<ExecutionId>>,
    }

    /// State that must never be shared between two program invocations.
    struct NodeRPCExecutionState {
        /// Maps reserved indices to the clients that have reserved them.
        index_to_client: HashMap<u64, ClientIdentity>,
        assigned_reservations: HashMap<u64, AssignedMaskReservation>,
        /// One pending request per identity; a closed one is dropped before any insertion, so
        /// the map is bounded by live connections.
        assigned_sinks: HashMap<ClientIdentity, AssignedMaskRequest>,
        /// Preprocessed mask shares, indexed only within this execution.
        mask_shares: HashMap<u64, Vec<u8>>,
        /// Set by `register_admitted_reservations_for_execution`: no reservation is added
        /// afterwards, so an unregistered index in a requested range is a refusal, not a wait.
        reservations_sealed: bool,
    }

    /// Whether a reservation registration leaves the execution open to more.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReservationRegistration {
        Incremental,
        Sealing,
    }

    /// What a mask request gets, decided under the execution's state lock and carried out
    /// after it is released.
    enum MaskRequestDecision {
        Answer(Box<JsonRawValue>),
        Park,
        Refuse(ErrorObjectOwned),
    }

    /// What an accepted mask subscription does once its request is re-checked.
    enum AcceptedMaskRequest {
        Answer(Box<JsonRawValue>),
        Parked(oneshot::Receiver<()>),
        Refused(ErrorObjectOwned),
    }

    /// One parked range request. Dropping it releases the subscription's handler, which then
    /// closes the caller's stream, so a request that is superseded, pruned or refused ends
    /// rather than leaving the caller waiting on a stream that will never answer.
    struct AssignedMaskRequest {
        start: u64,
        count: u64,
        sink: SubscriptionSink,
        _release: oneshot::Sender<()>,
    }

    /// Sends every completed request's answer, and only then drops the request, so the
    /// stream's close never overtakes its answer.
    ///
    /// Each send runs on its own task, bounded by `SUBSCRIPTION_SEND_TIMEOUT`: a caller that
    /// stops reading its socket neither stalls the registration that completed its request
    /// nor delays any other caller's answer.
    fn send_completed_requests(completed: Vec<(AssignedMaskRequest, Box<JsonRawValue>)>) {
        for (request, json) in completed {
            tokio::spawn(async move {
                let _ = request
                    .sink
                    .send_timeout(json, super::SUBSCRIPTION_SEND_TIMEOUT)
                    .await;
                drop(request);
            });
        }
    }

    impl NodeRPCServerInternal {
        fn new() -> Self {
            Self {
                executions: HashMap::new(),
                reserved_identities: HashMap::new(),
            }
        }

        fn record_reservations(
            &mut self,
            execution_id: ExecutionId,
            reservations: &[AssignedMaskReservation],
        ) {
            if !self.executions.contains_key(&execution_id) {
                return;
            }
            for reservation in reservations {
                self.reserved_identities
                    .entry(reservation.client.clone())
                    .or_default()
                    .insert(execution_id);
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
            self.reserved_identities.retain(|_, executions| {
                executions.remove(&execution_id);
                !executions.is_empty()
            });
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
                reservations_sealed: false,
            }
        }

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
            // Ownership is checked over the registered prefix of the range before any share
            // is looked at, so a range naming another identity's index is refused as soon as
            // that index is registered rather than only once its share arrives. Both passes
            // stop at the first gap, so the work is bounded by what is registered. Once the
            // reservations are sealed, a gap can never be filled, so it is a refusal.
            for i in start..end {
                match self.index_to_client.get(&i) {
                    None if self.reservations_sealed => {
                        return Err(NodeRPCError::AuthenticationFailed(id.clone()));
                    }
                    None => return Ok(None),
                    Some(client) if client != id => {
                        return Err(NodeRPCError::AuthenticationFailed(id.clone()));
                    }
                    Some(_) => {}
                }
            }
            let mut assigned_shares = Vec::new();
            for i in start..end {
                let Some(share) = self.mask_shares.get(&i) else {
                    return Ok(None);
                };
                assigned_shares.push(self.assigned_mask_share(i, share)?);
            }

            Ok(Some(assigned_shares))
        }

        /// Decides a mask request from `id` for `count` indices from `start`.
        fn mask_request_decision(
            &self,
            id: &ClientIdentity,
            start: u64,
            count: u64,
        ) -> MaskRequestDecision {
            use OffChainNodeRPCServerError::*;

            match self.assigned_mask_shares_for_client(id, start, count) {
                Ok(None) => MaskRequestDecision::Park,
                Ok(Some(assigned_shares)) => match to_json_raw_value(&assigned_shares) {
                    Ok(json) => MaskRequestDecision::Answer(json),
                    Err(e) => MaskRequestDecision::Refuse(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(SerializationError as i32).code(),
                        format!("Converting assigned shares to JSON failed: {e}"),
                        None::<()>,
                    )),
                },
                Err(e) => MaskRequestDecision::Refuse(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(RangeNotAssignedToCaller as i32).code(),
                    format!("The requested range is not assigned to the caller: {e}"),
                    None::<()>,
                )),
            }
        }

        /// Answers every pending request of `touched_clients` that is now complete, and keeps
        /// the others.
        ///
        /// A request fails alone: one that names an index registered to another identity (a
        /// range a client parked before registration, which may be hostile) or whose answer
        /// does not serialize is dropped, which closes that caller's stream, and every other
        /// client's request is still checked. Registration never fails because of what a
        /// client asked for.
        fn complete_pending_requests(
            &mut self,
            touched_clients: Vec<ClientIdentity>,
        ) -> Vec<(AssignedMaskRequest, Box<JsonRawValue>)> {
            let mut pending_sends = Vec::new();
            for id in touched_clients {
                let Some(request) = self.assigned_sinks.remove(&id) else {
                    continue;
                };
                if request.sink.is_closed() {
                    continue;
                }
                match self.assigned_mask_shares_for_client(&id, request.start, request.count) {
                    Ok(Some(assigned_shares)) => match to_json_raw_value(&assigned_shares) {
                        Ok(json) => pending_sends.push((request, json)),
                        Err(error) => {
                            tracing::debug!(%error, "dropping a mask request whose answer does not serialize");
                        }
                    },
                    Ok(None) => {
                        self.assigned_sinks.insert(id, request);
                    }
                    Err(error) => {
                        tracing::debug!(
                            %error,
                            start = request.start,
                            count = request.count,
                            "dropping a mask request for a range not assigned to its caller"
                        );
                    }
                }
            }
            pending_sends
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

            let Some(state) = self.execution_state(execution_id).await else {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(ExecutionNotFound as i32).code(),
                        format!("Execution {execution_id} is not registered"),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            };

            // Nothing that waits on a caller's socket (`reject`, `accept`, `send`) runs under the
            // state lock: a caller that stops reading stalls only its own handler, never a
            // registration or another caller.
            let decision = {
                let mut d = state.lock().await;
                // A new subscription from the same client supersedes any previous one still
                // pending: the client only ever moves on to the next input after it has
                // consumed (or given up on) the last one, so a still-registered sink at this
                // point is stale rather than a genuine conflict.
                d.assigned_sinks.remove(&self.id);
                d.mask_request_decision(&self.id, start, count)
            };
            let answer = match decision {
                MaskRequestDecision::Refuse(error) => {
                    drop(state);
                    pending.reject(error).await;
                    return Ok(());
                }
                MaskRequestDecision::Answer(json) => Some(json),
                MaskRequestDecision::Park => None,
            };
            if let Some(json) = answer {
                drop(state);
                let sink = pending.accept().await?;
                sink.send(json).await?;
                return Ok(());
            }

            let sink = pending.accept().await?;
            // Registration may have landed while accepting, so the request is decided again
            // before it parks.
            let accepted = {
                let mut d = state.lock().await;
                match d.mask_request_decision(&self.id, start, count) {
                    MaskRequestDecision::Answer(json) => AcceptedMaskRequest::Answer(json),
                    MaskRequestDecision::Refuse(error) => AcceptedMaskRequest::Refused(error),
                    MaskRequestDecision::Park => {
                        // Every other identity's closed request goes first, so the map never
                        // holds more requests than this listener has live connections.
                        d.assigned_sinks
                            .retain(|_, request| !request.sink.is_closed());
                        let (release, released) = oneshot::channel();
                        // Replaces, and so releases, a request the same identity parked while
                        // this one was being accepted.
                        d.assigned_sinks.insert(
                            self.id.clone(),
                            AssignedMaskRequest {
                                start,
                                count,
                                sink: sink.clone(),
                                _release: release,
                            },
                        );
                        AcceptedMaskRequest::Parked(released)
                    }
                }
            };
            // The handler never holds the execution state across a wait. Retiring the execution
            // then drops the state, and with it this request, which releases the wait below and
            // closes the caller's stream.
            drop(state);

            match accepted {
                AcceptedMaskRequest::Answer(json) => {
                    sink.send(json).await?;
                    Ok(())
                }
                AcceptedMaskRequest::Refused(error) => Err(error.message().into()),
                AcceptedMaskRequest::Parked(released) => {
                    // Held until the request is answered, superseded, pruned, refused or its
                    // execution retired; the error then closes the caller's stream.
                    tokio::select! {
                        _ = released => {}
                        _ = sink.closed() => {}
                    }
                    Err("the node closed this mask share subscription".into())
                }
            }
        }
    }

    /// A weak handle on one execution's node-side state, for tests: it reports whether anything
    /// (such as a parked subscription's handler) still keeps the state alive.
    #[doc(hidden)]
    pub struct ExecutionStateProbe(std::sync::Weak<Mutex<NodeRPCExecutionState>>);

    impl ExecutionStateProbe {
        /// Whether the execution's state has been dropped.
        pub fn is_dropped(&self) -> bool {
            self.0.strong_count() == 0
        }
    }

    /// A probe on `execution_id`'s node-side state, if the execution is registered, for tests.
    #[doc(hidden)]
    pub async fn execution_state_probe(
        server: &NodeRPCServer,
        execution_id: ExecutionId,
    ) -> Option<ExecutionStateProbe> {
        server
            .execution_state(execution_id)
            .await
            .ok()
            .map(|state| ExecutionStateProbe(Arc::downgrade(&state)))
    }

    /// The number of pending mask-share requests parked for `execution_id`, for tests.
    #[doc(hidden)]
    pub async fn parked_mask_requests(server: &NodeRPCServer, execution_id: ExecutionId) -> usize {
        match server.execution_state(execution_id).await {
            Ok(state) => state.lock().await.assigned_sinks.len(),
            Err(_) => 0,
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
    /// One slot's whole submission, as its client signed it.
    MaskedInputEvent {
        submission: MaskedInputSubmission,
    },
    IndexBufferEvent {
        total_indices: u64,
        designated_party: ClientIdentity,
    },
    /// One slot's whole reservation: every index of its admitted input range.
    ReservedInputEvent {
        client: ClientIdentity,
        reserved_indices: Vec<u64>,
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
    /// The coordinator aborted the execution; sent on every `Event` stream, after which the
    /// stream ends.
    ExecutionAborted {
        reason: AbortReason,
    },
}

/// Serializes exactly as the matching `Event` variant, from borrowed slot data, so a live
/// broadcast and every replay send a stored submission without copying it.
#[derive(Serialize)]
#[serde(rename = "Event")]
enum EventRef<'a> {
    MaskedInputEvent {
        submission: &'a MaskedInputSubmission,
    },
    ReservedInputEvent {
        client: &'a ClientIdentity,
        reserved_indices: Vec<u64>,
    },
}

impl EventRef<'_> {
    fn to_json(&self) -> Box<JsonRawValue> {
        to_json_raw_value(self).expect("events serialize to JSON")
    }
}

fn reservation_event_json(client: &ClientIdentity, range: InputRange) -> Box<JsonRawValue> {
    EventRef::ReservedInputEvent {
        client,
        reserved_indices: (range.start..range.end()).collect(),
    }
    .to_json()
}

fn event_json(event: &Event) -> Box<JsonRawValue> {
    to_json_raw_value(event).expect("events serialize to JSON")
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
    /// The node roster this coordinator was started with. Process-wide and immutable for the
    /// coordinator's lifetime; served to any caller that completed the mTLS handshake, rate
    /// limited per caller identity. Returned in wire form so the receiver runs the roster check
    /// itself (`NodeRoster::try_from`) and keeps its typed error.
    #[method(name = "get_node_roster")]
    async fn get_node_roster(&self) -> RpcResult<NodeRosterWire>;

    /// What any caller may learn about an execution: its program, slot table, policy kind,
    /// deadlines and round. Rate limited per caller identity, sharing `get_node_roster`'s bucket.
    #[method(name = "get_execution_summary")]
    async fn get_execution_summary(&self, execution_id: ExecutionId)
        -> RpcResult<ExecutionSummary>;

    /// Binds the caller's identity to a client slot under the execution's admission policy.
    #[method(name = "associate_client")]
    async fn associate_client(
        &self,
        execution_id: ExecutionId,
        request: AssociationRequest,
    ) -> RpcResult<ClientAdmission>;

    /// The frozen admission set, for nodes only.
    #[method(name = "get_client_admissions")]
    async fn get_client_admissions(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<ClientAdmissionSet>;

    #[method(name = "retire_execution")]
    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()>;

    /// Wait for round `round` to be started. Nodes and admitted clients only.
    #[subscription(name = "sub_round", unsubscribe = "unsub_round", item = Event)]
    async fn sub_round(&self, execution_id: ExecutionId, round: Round) -> SubscriptionResult;

    /// One `ReservedInputEvent` per slot that reserved, in reservation order. Nodes only.
    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = Event)]
    async fn sub_reserved_indices(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// One `MaskedInputEvent` per slot that submitted, in submission order. Nodes only.
    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = Event)]
    async fn sub_masked_inputs(&self, execution_id: ExecutionId) -> SubscriptionResult;

    /// Reserves the caller's whole admitted input range, in one call.
    #[method(name = "reserve_mask_indices")]
    async fn reserve_mask_indices(
        &self,
        execution_id: ExecutionId,
        indices: Vec<u64>,
    ) -> RpcResult<()>;

    /// Submits the caller's whole admitted input range, in one call signed with the caller's
    /// certificate key over `masked_inputs_signing_bytes`.
    #[method(name = "submit_masked_inputs")]
    async fn submit_masked_inputs(
        &self,
        execution_id: ExecutionId,
        first_index: u64,
        masked_inputs: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> RpcResult<()>;

    /// A node proposes that the execution advance to `next_round`.
    #[method(name = "transition")]
    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()>;

    /// A node sends its sealed, signed output shares for the client bound to `client_index`.
    #[method(name = "send_output_shares")]
    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_index: ClientIndex,
        sealed: SealedOutput,
    ) -> RpcResult<()>;

    /// An admitted client with output rights receives one item per node, live and on replay.
    #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = SealedOutputShares)]
    async fn obtain_output_shares(&self, execution_id: ExecutionId) -> SubscriptionResult;
}

/// The stable JSON-RPC error codes of the coordinator RPC interface.
///
/// Codes 1 (`NotDesignatedParty`), 3 (`IndexOutOfBounds`), 4 (`BadID`), 7
/// (`IndexAlreadyReserved`), 11 (`SendingFailed`), 13 (`MismatchedBatchLengths`), 15
/// (`UnauthorizedClientIo`), 17 (`ExecutionAlreadyRegistered`), 18 (`ShutdownNotAccepted`) and 19
/// (`EmptyBatch`) are retired and never reused; 34 is not allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorRPCBaseError {
    WrongRound = 2,
    MaskedInputAlreadySubmitted = 5,
    IndexNotReserved = 6,
    OutputSharesAlreadySent = 8,
    OutputSharesAlreadyRequested = 9,
    NotParty = 10,
    NotOutputClient = 12,
    ClientAlreadyReserved = 14,
    ExecutionNotFound = 16,
    AssociationClosed = 20,
    CapacityExhausted = 21,
    SlotOutOfRange = 22,
    SlotTaken = 23,
    NotPreRegistered = 24,
    PreRegisteredSlotMismatch = 25,
    InvitationRequired = 26,
    InvitationRejected = 27,
    UnexpectedInvitation = 28,
    UnsupportedClientKey = 29,
    AlreadyAssociated = 30,
    NotAdmitted = 31,
    ReservationOutsideAdmission = 32,
    AdmissionsNotFrozen = 33,
    ExecutionAborted = 35,
    MaskedInputTooLarge = 36,
    SubmissionOutsideAdmission = 37,
    BadMaskedInputSignature = 38,
    SealedOutputTooLarge = 39,
    BadOutputSignature = 40,
    RateLimited = 41,
}

impl CoordinatorRPCBaseError {
    const ALL: [Self; 30] = [
        Self::WrongRound,
        Self::MaskedInputAlreadySubmitted,
        Self::IndexNotReserved,
        Self::OutputSharesAlreadySent,
        Self::OutputSharesAlreadyRequested,
        Self::NotParty,
        Self::NotOutputClient,
        Self::ClientAlreadyReserved,
        Self::ExecutionNotFound,
        Self::AssociationClosed,
        Self::CapacityExhausted,
        Self::SlotOutOfRange,
        Self::SlotTaken,
        Self::NotPreRegistered,
        Self::PreRegisteredSlotMismatch,
        Self::InvitationRequired,
        Self::InvitationRejected,
        Self::UnexpectedInvitation,
        Self::UnsupportedClientKey,
        Self::AlreadyAssociated,
        Self::NotAdmitted,
        Self::ReservationOutsideAdmission,
        Self::AdmissionsNotFrozen,
        Self::ExecutionAborted,
        Self::MaskedInputTooLarge,
        Self::SubmissionOutsideAdmission,
        Self::BadMaskedInputSignature,
        Self::SealedOutputTooLarge,
        Self::BadOutputSignature,
        Self::RateLimited,
    ];

    /// The JSON-RPC `code` of this refusal.
    pub const fn code(self) -> i32 {
        self as i32
    }

    pub fn from_code(code: i32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.code() == code)
    }

    /// The untyped refusal this code names, if it carries no typed error.
    pub const fn refusal(self) -> Option<RpcRefusal> {
        match self {
            Self::WrongRound => Some(RpcRefusal::WrongRound),
            Self::MaskedInputAlreadySubmitted => Some(RpcRefusal::MaskedInputAlreadySubmitted),
            Self::IndexNotReserved => Some(RpcRefusal::IndexNotReserved),
            Self::OutputSharesAlreadySent => Some(RpcRefusal::OutputSharesAlreadySent),
            Self::OutputSharesAlreadyRequested => Some(RpcRefusal::OutputSharesAlreadyRequested),
            Self::NotParty => Some(RpcRefusal::NotParty),
            Self::ClientAlreadyReserved => Some(RpcRefusal::ClientAlreadyReserved),
            Self::ExecutionNotFound => Some(RpcRefusal::ExecutionNotFound),
            Self::RateLimited => Some(RpcRefusal::RateLimited),
            _ => None,
        }
    }

    /// The code an `AdmissionError` is returned with.
    pub const fn of_admission(error: &AdmissionError) -> Self {
        match error {
            AdmissionError::AssociationClosed { .. } => Self::AssociationClosed,
            AdmissionError::CapacityExhausted { .. } => Self::CapacityExhausted,
            AdmissionError::SlotOutOfRange { .. } => Self::SlotOutOfRange,
            AdmissionError::SlotTaken { .. } => Self::SlotTaken,
            AdmissionError::NotPreRegistered { .. } => Self::NotPreRegistered,
            AdmissionError::PreRegisteredSlotMismatch { .. } => Self::PreRegisteredSlotMismatch,
            AdmissionError::InvitationRequired { .. } => Self::InvitationRequired,
            AdmissionError::InvitationRejected { .. } => Self::InvitationRejected,
            AdmissionError::UnexpectedInvitation { .. } => Self::UnexpectedInvitation,
            AdmissionError::UnsupportedClientKey { .. } => Self::UnsupportedClientKey,
            AdmissionError::AlreadyAssociated { .. } => Self::AlreadyAssociated,
            AdmissionError::NotAdmitted { .. } => Self::NotAdmitted,
            AdmissionError::ReservationOutsideAdmission { .. } => Self::ReservationOutsideAdmission,
            AdmissionError::AdmissionsNotFrozen { .. } => Self::AdmissionsNotFrozen,
            AdmissionError::NoOutputRights { .. } => Self::NotOutputClient,
        }
    }

    /// The code a `SubmissionError` is returned with.
    pub const fn of_submission(error: &SubmissionError) -> Self {
        match error {
            SubmissionError::MaskedInputTooLarge { .. } => Self::MaskedInputTooLarge,
            SubmissionError::SubmissionOutsideAdmission { .. } => Self::SubmissionOutsideAdmission,
            SubmissionError::BadMaskedInputSignature => Self::BadMaskedInputSignature,
            SubmissionError::SealedOutputTooLarge { .. } => Self::SealedOutputTooLarge,
            SubmissionError::BadOutputSignature => Self::BadOutputSignature,
        }
    }
}

fn refusal(code: CoordinatorRPCBaseError, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code.code(), message, None::<()>)
}

fn admission_refusal(error: AdmissionError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        CoordinatorRPCBaseError::of_admission(&error).code(),
        error.to_string(),
        Some(&error),
    )
}

fn submission_refusal(error: SubmissionError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        CoordinatorRPCBaseError::of_submission(&error).code(),
        error.to_string(),
        Some(&error),
    )
}

fn aborted_refusal(execution_id: ExecutionId, reason: &AbortReason) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        CoordinatorRPCBaseError::ExecutionAborted.code(),
        format!("execution {execution_id} was aborted by the coordinator: {reason}"),
        Some(reason),
    )
}

fn execution_not_found(execution_id: ExecutionId) -> ErrorObjectOwned {
    refusal(
        CoordinatorRPCBaseError::ExecutionNotFound,
        format!("Execution {execution_id} is not registered"),
    )
}

fn not_party(action: &str) -> ErrorObjectOwned {
    refusal(
        CoordinatorRPCBaseError::NotParty,
        format!("Only roster nodes can {action}."),
    )
}

fn wrong_round(needed: Round, current: Round) -> ErrorObjectOwned {
    refusal(
        CoordinatorRPCBaseError::WrongRound,
        format!("Need round {needed:?}, current round is {current:?}"),
    )
}

/// Decodes a coordinator refusal into the typed error its code and `data` name.
fn decode_error_object(execution_id: ExecutionId, object: &ErrorObjectOwned) -> CoordinatorError {
    let untyped = || CoordinatorError::JSONError(object.to_string());
    let Some(code) = CoordinatorRPCBaseError::from_code(object.code()) else {
        return untyped();
    };
    if let Some(refusal) = code.refusal() {
        return CoordinatorError::Refused {
            refusal,
            message: object.message().to_string(),
        };
    }
    let Some(data) = object.data() else {
        return untyped();
    };
    let data = data.get();
    match code {
        CoordinatorRPCBaseError::ExecutionAborted => serde_json::from_str::<AbortReason>(data)
            .map(|reason| CoordinatorError::ExecutionAborted {
                execution_id,
                reason,
            })
            .unwrap_or_else(|_| untyped()),
        CoordinatorRPCBaseError::MaskedInputTooLarge
        | CoordinatorRPCBaseError::SubmissionOutsideAdmission
        | CoordinatorRPCBaseError::BadMaskedInputSignature
        | CoordinatorRPCBaseError::SealedOutputTooLarge
        | CoordinatorRPCBaseError::BadOutputSignature => {
            serde_json::from_str::<SubmissionError>(data)
                .map(CoordinatorError::Submission)
                .unwrap_or_else(|_| untyped())
        }
        _ => serde_json::from_str::<AdmissionError>(data)
            .map(CoordinatorError::Admission)
            .unwrap_or_else(|_| untyped()),
    }
}

/// Decodes a failed call or a refused subscription: a refusal by its code and `data`, anything
/// else as the transport failure it is.
fn decode_client_error(
    execution_id: ExecutionId,
    error: jsonrpsee::core::client::Error,
) -> CoordinatorError {
    match error {
        jsonrpsee::core::client::Error::Call(object) => decode_error_object(execution_id, &object),
        other => CoordinatorError::JSONError(other.to_string()),
    }
}

/// Tokens a caller identity earns per minute for the rate-limited read methods.
pub const SUMMARY_READS_PER_MINUTE: u32 = 60;
/// Tokens a caller identity may hold at once.
pub const SUMMARY_READ_BURST: u32 = 10;
/// Caller identities whose buckets are remembered; the least recently used is forgotten first.
pub const SUMMARY_READ_BUCKETS: usize = 65_536;

/// One caller identity's token bucket.
#[derive(Clone, Copy, Debug)]
struct ReadBucket {
    tokens: f64,
    refilled_at: Instant,
    last_used: u64,
}

/// Per-identity token buckets for the read methods any mTLS caller may use, in a map bounded
/// at `SUMMARY_READ_BUCKETS` identities that forgets the least recently used first, so
/// reconnecting does not refill a bucket.
struct ReadRateLimiter {
    buckets: HashMap<ClientIdentity, ReadBucket>,
    by_use: BTreeMap<u64, ClientIdentity>,
    uses: u64,
    capacity: usize,
}

impl ReadRateLimiter {
    fn new(capacity: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            by_use: BTreeMap::new(),
            uses: 0,
            capacity,
        }
    }

    /// Takes one token from `identity`'s bucket; false when it is empty.
    fn try_take(&mut self, identity: &ClientIdentity, now: Instant) -> bool {
        self.uses += 1;
        let use_stamp = self.uses;
        let burst = f64::from(SUMMARY_READ_BURST);
        let bucket = match self.buckets.get_mut(identity) {
            Some(bucket) => {
                self.by_use.remove(&bucket.last_used);
                let elapsed = now.saturating_duration_since(bucket.refilled_at);
                let earned = elapsed.as_secs_f64() * f64::from(SUMMARY_READS_PER_MINUTE) / 60.0;
                bucket.tokens = (bucket.tokens + earned).min(burst);
                bucket.refilled_at = now;
                bucket
            }
            None => {
                if self.buckets.len() >= self.capacity {
                    if let Some((_, evicted)) = self.by_use.pop_first() {
                        self.buckets.remove(&evicted);
                    }
                }
                self.buckets.entry(identity.clone()).or_insert(ReadBucket {
                    tokens: burst,
                    refilled_at: now,
                    last_used: use_stamp,
                })
            }
        };
        bucket.last_used = use_stamp;
        self.by_use.insert(use_stamp, identity.clone());
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Pause points that let a test hold one delivery path at an exact interleaving. Unset in every
/// production configuration; each point pauses once.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct DeliveryHooks {
    /// A subscription, after `accept` and before it re-locks the state.
    pub after_subscription_accept: Option<Arc<PausePoint>>,
    /// `submit_masked_inputs`, after sending its broadcast and before it re-locks the state,
    /// still holding the execution's delivery guard.
    pub during_masked_input_broadcast: Option<Arc<PausePoint>>,
    /// `send_output_shares`, after it released the state to deliver and before it re-locks it.
    pub before_output_relock: Option<Arc<PausePoint>>,
}

/// A one-shot pause: the paused path signals `reached` and waits for `resume`.
#[doc(hidden)]
pub struct PausePoint {
    armed: AtomicBool,
    reached: Semaphore,
    resume: Semaphore,
}

impl PausePoint {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            armed: AtomicBool::new(true),
            reached: Semaphore::new(0),
            resume: Semaphore::new(0),
        })
    }

    /// Resolves once a path has paused here.
    pub async fn reached(&self) {
        self.reached
            .acquire()
            .await
            .expect("pause point semaphores are never closed")
            .forget();
    }

    /// Lets the paused path continue.
    pub fn resume(&self) {
        self.resume.add_permits(1);
    }

    async fn pause(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.reached.add_permits(1);
            self.resume
                .acquire()
                .await
                .expect("pause point semaphores are never closed")
                .forget();
        }
    }
}

async fn pause_at(point: &Option<Arc<PausePoint>>) {
    if let Some(point) = point {
        point.pause().await;
    }
}

/// One parked subscription. Dropping it releases the subscription's handler, which then closes
/// the caller's stream, so every path that discards a parked sink — delivery, a failed send,
/// the per-caller bound, an abort, a removal — ends the stream rather than leaving it silent.
struct ParkedSink {
    caller: ClientIdentity,
    sink: SubscriptionSink,
    _release: oneshot::Sender<()>,
}

impl ParkedSink {
    fn new(caller: ClientIdentity, sink: &SubscriptionSink) -> (Self, oneshot::Receiver<()>) {
        let (release, released) = oneshot::channel();
        (
            Self {
                caller,
                sink: sink.clone(),
                _release: release,
            },
            released,
        )
    }

    /// Sends without waiting; false when the subscriber's queue is full or it is gone.
    fn try_send(&mut self, json: Box<JsonRawValue>) -> bool {
        self.sink.try_send(json).is_ok()
    }
}

/// A parked list, bounded per caller.
#[derive(Default)]
struct ParkedSinks {
    entries: Vec<ParkedSink>,
}

impl ParkedSinks {
    /// Drops the list's closed sinks, then the caller's oldest while it holds
    /// `MAX_PARKED_SUBSCRIPTIONS_PER_CALLER`, then parks `entry`.
    fn park(&mut self, entry: ParkedSink) {
        self.entries.retain(|parked| !parked.sink.is_closed());
        while self
            .entries
            .iter()
            .filter(|parked| parked.caller == entry.caller)
            .count()
            >= MAX_PARKED_SUBSCRIPTIONS_PER_CALLER
        {
            let oldest = self
                .entries
                .iter()
                .position(|parked| parked.caller == entry.caller)
                .expect("the caller has parked entries");
            self.entries.remove(oldest);
        }
        self.entries.push(entry);
    }

    fn take(&mut self) -> Vec<ParkedSink> {
        std::mem::take(&mut self.entries)
    }
}

/// Holds a parked subscription's handler until its parked entry is dropped or the caller goes
/// away; the error it returns closes the caller's stream.
async fn hold_until_released(
    sink: &SubscriptionSink,
    released: oneshot::Receiver<()>,
) -> SubscriptionResult {
    tokio::select! {
        _ = released => {}
        _ = sink.closed() => {}
    }
    Err("the coordinator closed this subscription".into())
}

/// Sends `Event::ExecutionAborted` to every entry without waiting, then drops them all.
fn send_aborted(entries: Vec<ParkedSink>, reason: &AbortReason) {
    let json = event_json(&Event::ExecutionAborted {
        reason: reason.clone(),
    });
    for mut entry in entries {
        entry.try_send(json.clone());
    }
}

/// The basic server-side information for one client connection to the coordinator RPC interface.
/// Can be extended by the developer.
#[derive(Clone)]
pub struct CoordinatorRPCServerConnectionBase {
    /// A reference to the server's shared state.
    d: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    /// The connected caller's identity (`caller_identity` of its certificate).
    id: ClientIdentity,
}

/// The basic internal state of the coordinator RPC server.
/// Can be extended by the developer.
pub struct CoordinatorRPCServerSharedBase {
    /// The node roster, fixed by the constructor for the coordinator's whole lifetime.
    node_roster: NodeRoster,
    /// The roster's wire form, built once; `get_node_roster` clones the `Arc`.
    node_roster_wire: Arc<NodeRosterWire>,
    /// The key of the certificate the operator serves this state with. Every listener start
    /// refuses a certificate with another key.
    server_spki: SpkiDer,
    /// Derived views of `node_roster`: its identities in canonical order, `n` and `t`.
    mpc_nodes: Vec<ClientIdentity>,
    n: u64,
    t: u64,
    read_rate: ReadRateLimiter,
    executions: HashMap<ExecutionId, CoordinatorExecutionState>,
    /// Executions that reached the retirement quorum and were evicted. Their protocol state has
    /// been dropped; only the acknowledging identities are kept so that stragglers can still
    /// retire cleanly.
    retired: RetiredExecutions,
    /// How every execution that left `executions` ended.
    ended: EndedExecutions,
    /// Every identity bound to a slot of a live execution, with the number of such bindings.
    /// `capacity_class` reads it.
    bound_identities: HashMap<ClientIdentity, usize>,
    output_retention: Duration,
    /// Signalled by every path that can change `watch_for_retirement_quorum`'s condition or
    /// remove an execution.
    retirement_changed: Arc<Notify>,
    /// Wakes the deadline sweeper when a registration or a retention changes its schedule.
    sweeper_wake: Arc<Notify>,
    hooks: DeliveryHooks,
}

/// A bounded, insertion-ordered set of executions that have been sealed but not yet
/// acknowledged by every party. Bounding this (rather than waiting for acknowledgements that
/// a faulty party may never send) is what keeps a silent party from consuming memory forever.
#[derive(Default)]
struct RetiredExecutions {
    acks: HashMap<ExecutionId, HashSet<ClientIdentity>>,
    order: VecDeque<ExecutionId>,
}

impl RetiredExecutions {
    fn seal(&mut self, execution_id: ExecutionId, acks: HashSet<ClientIdentity>) {
        if self.acks.insert(execution_id, acks).is_none() {
            self.order.push_back(execution_id);
        }
        while self.order.len() > DEFAULT_MAX_RETIRED_EXECUTIONS {
            if let Some(evicted) = self.order.pop_front() {
                self.acks.remove(&evicted);
            }
        }
    }

    /// Records one more acknowledgement, forgetting the execution entirely once every party
    /// has acknowledged it. Returns false when the execution is not sealed.
    fn acknowledge(&mut self, execution_id: ExecutionId, party: &ClientIdentity, n: usize) -> bool {
        let Some(acks) = self.acks.get_mut(&execution_id) else {
            return false;
        };
        acks.insert(party.clone());
        if acks.len() >= n {
            self.acks.remove(&execution_id);
            self.order.retain(|candidate| *candidate != execution_id);
        }
        true
    }

    fn contains(&self, execution_id: ExecutionId) -> bool {
        self.acks.contains_key(&execution_id)
    }
}

/// Bounded, insertion-ordered: the last `DEFAULT_MAX_ENDED_EXECUTIONS` executions that left
/// `executions`, by any path — unanimous retirement, retention expiry, eviction of a
/// quorum-retired or an aborted execution. Acknowledgements never remove an entry; only the
/// bound does, oldest first.
#[derive(Default)]
struct EndedExecutions {
    outcomes: HashMap<ExecutionId, ExecutionOutcome>,
    order: VecDeque<ExecutionId>,
}

impl EndedExecutions {
    fn record(&mut self, execution_id: ExecutionId, outcome: ExecutionOutcome) {
        if self.outcomes.insert(execution_id, outcome).is_none() {
            self.order.push_back(execution_id);
        }
        while self.order.len() > DEFAULT_MAX_ENDED_EXECUTIONS {
            if let Some(forgotten) = self.order.pop_front() {
                self.outcomes.remove(&forgotten);
            }
        }
    }

    fn outcome(&self, execution_id: ExecutionId) -> Option<&ExecutionOutcome> {
        self.outcomes.get(&execution_id)
    }
}

/// All mutable protocol state for one program invocation.
struct CoordinatorExecutionState {
    registration_nonce: RegistrationNonce,
    registration: Arc<ExecutionRegistration>,
    admissions: ClientAdmissions,
    /// Built once, when the execution enters `InputCollection` (or skips to `MPCExecution`).
    frozen_admissions: Option<Arc<ClientAdmissionSet>>,
    /// The current round.
    round: Round,
    aborted: Option<AbortReason>,
    retirement_acks: HashSet<ClientIdentity>,
    /// Set at unanimous retirement of an execution with output slots: removed then.
    retained_until: Option<Instant>,
    /// Parties that have proposed each round transition. A round is applied once its proposer
    /// set reaches the transition quorum.
    transition_votes: HashMap<Round, HashSet<ClientIdentity>>,
    /// The event each applied round was started with; late subscribers replay it.
    round_events: HashMap<Round, Event>,
    round_sinks: HashMap<Round, ParkedSinks>,
    reservation_sinks: ParkedSinks,
    submission_sinks: ParkedSinks,
    /// Each output client's sealed items, in arrival order; one per node.
    outputs: HashMap<ClientIndex, Vec<Arc<SealedOutputShares>>>,
    /// At most one parked output waiter per output client.
    output_waiters: HashMap<ClientIndex, ParkedSink>,
    /// Serializes every broadcast of the execution. Lock order: delivery guard, then the
    /// coordinator state mutex.
    delivery: Arc<Mutex<()>>,
}

/// The client→slot bindings of one execution. A binding is only ever added.
struct ClientAdmissions {
    /// Indexed by `ClientIndex`.
    slots: Vec<Option<AdmittedClient>>,
    by_identity: HashMap<ClientIdentity, ClientIndex>,
    /// Slot order of successful reservations and submissions, for replay.
    reservation_order: Vec<ClientIndex>,
    submission_order: Vec<ClientIndex>,
}

struct AdmittedClient {
    client: ClientIdentity,
    admission: ClientAdmission,
    /// The request that bound or first claimed the slot. `None` only for a pre-registered slot
    /// whose client has not called `associate_client` yet.
    request: Option<AssociationRequest>,
    /// The slot's reservation: its whole input range, made in one call.
    reserved: bool,
    submission: Option<Arc<MaskedInputSubmission>>,
}

impl ClientAdmissions {
    fn new(capacity: usize) -> Self {
        Self {
            slots: (0..capacity).map(|_| None).collect(),
            by_identity: HashMap::new(),
            reservation_order: Vec::new(),
            submission_order: Vec::new(),
        }
    }

    fn bind(
        &mut self,
        client: ClientIdentity,
        admission: ClientAdmission,
        request: Option<AssociationRequest>,
    ) {
        let index = admission.client_index;
        self.by_identity.insert(client.clone(), index);
        self.slots[index.0 as usize] = Some(AdmittedClient {
            client,
            admission,
            request,
            reserved: false,
            submission: None,
        });
    }

    fn slot(&self, index: ClientIndex) -> Option<&AdmittedClient> {
        self.slots.get(index.0 as usize).and_then(Option::as_ref)
    }

    fn slot_of(&self, client: &ClientIdentity) -> Option<&AdmittedClient> {
        self.by_identity
            .get(client)
            .and_then(|index| self.slot(*index))
    }

    fn slot_of_mut(&mut self, client: &ClientIdentity) -> Option<&mut AdmittedClient> {
        let index = *self.by_identity.get(client)?;
        self.slots
            .get_mut(index.0 as usize)
            .and_then(Option::as_mut)
    }

    fn unbound(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_none()).count()
    }

    fn identities(&self) -> impl Iterator<Item = &ClientIdentity> {
        self.slots.iter().flatten().map(|slot| &slot.client)
    }
}

type TransitionDelivery = (Event, Vec<ParkedSink>);

/// Sends each applied round's event to its parked waiters without waiting, then releases them.
fn deliver_transitions(deliveries: Vec<TransitionDelivery>) {
    for (event, entries) in deliveries {
        let json = event_json(&event);
        for mut entry in entries {
            if !entry.try_send(json.clone()) {
                eprintln!("coordinator round subscriber is gone or too slow; dropping it");
            }
        }
    }
}

/// The replay history a subscription reads, and where it parks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventStream {
    Reservations,
    Submissions,
}

/// One replayed item, cloned or `Arc`-shared under the state mutex and serialized after it.
enum ReplayItem {
    Reservation {
        client: ClientIdentity,
        range: InputRange,
    },
    Submission(Arc<MaskedInputSubmission>),
    Output(Arc<SealedOutputShares>),
    Round(Event),
}

impl ReplayItem {
    fn to_json(&self) -> Box<JsonRawValue> {
        match self {
            Self::Reservation { client, range } => reservation_event_json(client, *range),
            Self::Submission(submission) => EventRef::MaskedInputEvent { submission }.to_json(),
            Self::Output(item) => to_json_raw_value(&**item).expect("items serialize to JSON"),
            Self::Round(event) => event_json(event),
        }
    }
}

/// What a subscription does after one look at the state.
enum ReplayStep {
    /// Everything the subscription exists for has been sent.
    Done,
    /// The execution was removed.
    Gone,
    Aborted(AbortReason),
    Replay(Vec<ReplayItem>),
    Parked(oneshot::Receiver<()>),
    /// Another live output waiter for the same client won the race.
    Superseded,
}

impl CoordinatorRPCServerConnectionBase {
    pub fn new(internal: Arc<Mutex<CoordinatorRPCServerSharedBase>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    /// Sends replayed items, then parks, looping while the history grows between looks. An
    /// abort sends `Event::ExecutionAborted` on an `Event`-typed stream (`carries_events`) and
    /// ends it; any other stream just ends, as it does when the execution is gone.
    async fn replay_then_park(
        &self,
        sink: SubscriptionSink,
        execution_id: ExecutionId,
        carries_events: bool,
        mut look: impl FnMut(
            &mut CoordinatorExecutionState,
            &mut usize,
            &SubscriptionSink,
        ) -> ReplayStep,
    ) -> SubscriptionResult {
        let mut sent = 0usize;
        loop {
            let step = {
                let mut shared = self.d.lock().await;
                match shared.executions.get_mut(&execution_id) {
                    None => ReplayStep::Gone,
                    Some(execution) => match &execution.aborted {
                        Some(reason) => ReplayStep::Aborted(reason.clone()),
                        None => look(execution, &mut sent, &sink),
                    },
                }
            };
            match step {
                ReplayStep::Done => return Ok(()),
                ReplayStep::Gone | ReplayStep::Superseded => {
                    return Err("the coordinator closed this subscription".into())
                }
                ReplayStep::Aborted(reason) => {
                    if carries_events {
                        let _ = sink
                            .send_timeout(
                                event_json(&Event::ExecutionAborted { reason }),
                                SUBSCRIPTION_SEND_TIMEOUT,
                            )
                            .await;
                    }
                    return Err("the coordinator aborted this execution".into());
                }
                ReplayStep::Replay(items) => {
                    for item in items {
                        if sink
                            .send_timeout(item.to_json(), SUBSCRIPTION_SEND_TIMEOUT)
                            .await
                            .is_err()
                        {
                            eprintln!(
                                "coordinator subscriber disconnected or timed out during replay"
                            );
                            return Ok(());
                        }
                    }
                }
                ReplayStep::Parked(released) => return hold_until_released(&sink, released).await,
            }
        }
    }

    /// A node-only `Event` subscription over one slot-ordered history.
    async fn event_stream_subscription(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
        stream: EventStream,
    ) -> SubscriptionResult {
        let gate = {
            let shared = self.d.lock().await;
            if !shared.mpc_nodes.contains(&self.id) {
                Err(not_party("subscribe to reservations and masked inputs"))
            } else {
                shared
                    .live_execution(execution_id)
                    .map(|_| shared.hooks.after_subscription_accept.clone())
            }
        };
        let hook = match gate {
            Ok(hook) => hook,
            Err(error) => {
                pending.reject(error).await;
                return Ok(());
            }
        };
        let sink = pending.accept().await?;
        pause_at(&hook).await;

        let caller = self.id.clone();
        self.replay_then_park(sink, execution_id, true, move |execution, sent, sink| {
            let history = match stream {
                EventStream::Reservations => &execution.admissions.reservation_order,
                EventStream::Submissions => &execution.admissions.submission_order,
            };
            if history.len() > *sent {
                let items = history[*sent..]
                    .iter()
                    .filter_map(|index| execution.admissions.slot(*index))
                    .filter_map(|slot| match stream {
                        EventStream::Reservations => {
                            slot.admission
                                .input_range
                                .map(|range| ReplayItem::Reservation {
                                    client: slot.client.clone(),
                                    range,
                                })
                        }
                        EventStream::Submissions => {
                            slot.submission.clone().map(ReplayItem::Submission)
                        }
                    })
                    .collect();
                *sent = history.len();
                return ReplayStep::Replay(items);
            }
            let (entry, released) = ParkedSink::new(caller.clone(), sink);
            match stream {
                EventStream::Reservations => execution.reservation_sinks.park(entry),
                EventStream::Submissions => execution.submission_sinks.park(entry),
            }
            ReplayStep::Parked(released)
        })
        .await
    }
}

impl CoordinatorRPCServerSharedBase {
    /// `server_spki` is the key of the certificate the operator serves this state with.
    /// The roster, and so `n`, `t` and the MPC node identities, never change afterwards: a
    /// different roster is a different coordinator process.
    pub fn new(node_roster: NodeRoster, server_spki: SpkiDer) -> Self {
        Self {
            node_roster_wire: Arc::new(node_roster.to_wire()),
            mpc_nodes: node_roster.node_identities(),
            n: node_roster.n(),
            t: node_roster.t(),
            node_roster,
            server_spki,
            read_rate: ReadRateLimiter::new(SUMMARY_READ_BUCKETS),
            executions: HashMap::new(),
            retired: RetiredExecutions::default(),
            ended: EndedExecutions::default(),
            bound_identities: HashMap::new(),
            output_retention: DEFAULT_OUTPUT_RETENTION,
            retirement_changed: Arc::new(Notify::new()),
            sweeper_wake: Arc::new(Notify::new()),
            hooks: DeliveryHooks::default(),
        }
    }

    pub fn new_for_execution(
        node_roster: NodeRoster,
        server_spki: SpkiDer,
        registration: ExecutionRegistration,
    ) -> Result<Self, CoordinatorError> {
        let mut shared = Self::new(node_roster, server_spki);
        shared.register_execution(registration)?;
        Ok(shared)
    }

    /// How long an execution with output slots is kept after its unanimous retirement
    /// (`DEFAULT_OUTPUT_RETENTION` by default).
    pub fn with_output_retention(mut self, retention: Duration) -> Self {
        self.output_retention = retention;
        self
    }

    #[doc(hidden)]
    pub fn set_delivery_hooks(&mut self, hooks: DeliveryHooks) {
        self.hooks = hooks;
    }

    pub fn node_roster(&self) -> &NodeRoster {
        &self.node_roster
    }

    pub fn server_spki(&self) -> &SpkiDer {
        &self.server_spki
    }

    /// `Node` for a roster node, `BoundClient` for an identity bound to a slot of a live
    /// execution, `Unreserved` for everyone else.
    pub fn capacity_class(&self, id: &ClientIdentity) -> CapacityClass {
        if self.mpc_nodes.contains(id) {
            CapacityClass::Node
        } else if self.bound_identities.contains_key(id) {
            CapacityClass::BoundClient
        } else {
            CapacityClass::Unreserved
        }
    }

    /// How many distinct parties must propose a round transition before it is applied.
    ///
    /// The upper bound is the liveness bound `n - t`: requiring more than that would let `t`
    /// faulty parties halt every execution simply by staying silent, which is the failure this
    /// quorum exists to remove. Within that bound we prefer the honest-majority quorum `2t + 1`.
    /// The lower bound `t + 1` guarantees at least one honest proposer, so a colluding minority
    /// can never advance a round on its own.
    ///
    /// Note that a quorum is not what makes an early transition *safe* — a quorum containing a
    /// single honest party is still enough to advance. Safety comes from the coordinator-side
    /// preconditions checked in `blocking_precondition`; the quorum is what removes the single
    /// designated proposer as a point of failure.
    fn transition_quorum(&self) -> usize {
        let liveness_bound = (self.n - self.t) as usize;
        let honest_majority = (2 * self.t + 1) as usize;
        honest_majority
            .min(liveness_bound)
            .max((self.t + 1) as usize)
    }

    /// How many parties must acknowledge completion before an execution may be evicted, and a
    /// one-off coordinator may start draining. Bounded by `n - t` for the same reason as
    /// [`Self::transition_quorum`].
    fn retirement_quorum(&self) -> usize {
        (self.n - self.t) as usize
    }

    /// Registers an execution, running the checks strictly in this order: an identical live
    /// registration returns its nonce; an ended id is `ExecutionIdRetired`; a different live
    /// registration is `ConflictingRegistration`; `ExecutionRegistration::validate`; then, at
    /// `DEFAULT_MAX_CONCURRENT_EXECUTIONS`, one evictable execution is evicted or the
    /// registration is `ExecutionCapacityReached`. Finally draws the nonce and registers.
    pub fn register_execution(
        &mut self,
        registration: ExecutionRegistration,
    ) -> Result<RegistrationNonce, CoordinatorError> {
        let execution_id = registration.execution_id;
        if let Some(existing) = self.executions.get(&execution_id) {
            if *existing.registration == registration {
                return Ok(existing.registration_nonce);
            }
        }
        if self.ended.outcome(execution_id).is_some() {
            return Err(RegistrationError::ExecutionIdRetired { execution_id }.into());
        }
        if self.executions.contains_key(&execution_id) {
            return Err(RegistrationError::ConflictingRegistration { execution_id }.into());
        }
        registration.validate(&self.node_roster, &self.server_spki, UnixSeconds::now())?;

        if self.executions.len() >= DEFAULT_MAX_CONCURRENT_EXECUTIONS {
            // Healthy stragglers need the completed round history until they have also reached
            // ProgramFinished. Keep that history during normal operation, and only compact a
            // quorum-retired or aborted execution when its slot is actually needed.
            let retirement_quorum = self.retirement_quorum();
            let evictable = self.executions.iter().find_map(|(candidate, execution)| {
                (execution.aborted.is_some()
                    || execution.retirement_acks.len() >= retirement_quorum)
                    .then_some(*candidate)
            });
            let Some(evicted) = evictable else {
                return Err(RegistrationError::ExecutionCapacityReached {
                    capacity: DEFAULT_MAX_CONCURRENT_EXECUTIONS as u64,
                }
                .into());
            };
            if let Some(execution) = self.remove_execution(evicted) {
                self.retired.seal(evicted, execution.retirement_acks);
            }
        }

        let nonce = RegistrationNonce::generate();
        let execution = CoordinatorExecutionState::new(Arc::new(registration), nonce);
        for identity in execution.admissions.identities() {
            *self.bound_identities.entry(identity.clone()).or_default() += 1;
        }
        self.executions.insert(execution_id, execution);
        self.sweeper_wake.notify_one();
        Ok(nonce)
    }

    /// Returns the current round of the given execution, or `None` if it is not registered
    /// (either because it never was, or because it has already been removed).
    pub fn round(&self, execution_id: ExecutionId) -> Option<Round> {
        self.executions
            .get(&execution_id)
            .map(|execution| execution.round)
    }

    /// The nonce of the live registration of `execution_id`.
    pub fn registration_nonce(&self, execution_id: ExecutionId) -> Option<RegistrationNonce> {
        self.executions
            .get(&execution_id)
            .map(|execution| execution.registration_nonce)
    }

    /// The number of subscriptions parked for `round` of `execution_id`, for tests.
    #[doc(hidden)]
    pub fn parked_round_subscriptions(&self, execution_id: ExecutionId, round: Round) -> usize {
        self.executions
            .get(&execution_id)
            .and_then(|execution| execution.round_sinks.get(&round))
            .map_or(0, |parked| parked.entries.len())
    }

    /// The number of `sub_reserved_indices` subscriptions parked for `execution_id`, for tests.
    #[doc(hidden)]
    pub fn parked_reservation_subscriptions(&self, execution_id: ExecutionId) -> usize {
        self.executions
            .get(&execution_id)
            .map_or(0, |execution| execution.reservation_sinks.entries.len())
    }

    /// How `execution_id` ended, while this process remembers it.
    pub fn ended_outcome(&self, execution_id: ExecutionId) -> Option<ExecutionOutcome> {
        self.ended.outcome(execution_id).cloned()
    }

    /// Acknowledges that `party` has finished with `execution_id`.
    ///
    /// Once `n - t` parties have acknowledged, the execution is evictable under capacity
    /// pressure, but its complete round history stays live so a healthy straggler can still
    /// finish. Unanimity removes it — at once, or `output_retention` later when its slot table
    /// has output slots, so late output clients still receive their items. Acknowledging an
    /// execution that is gone is a success.
    pub fn retire_execution(
        &mut self,
        execution_id: ExecutionId,
        party: &ClientIdentity,
    ) -> Result<(), CoordinatorError> {
        // The RPC entry point already rejects non-parties, but this is a public method and the
        // acknowledgement count is a quorum: counting an identity that is not on the roster would
        // let one party's acknowledgements stand in for several.
        if !self.mpc_nodes.contains(party) {
            return Err(CoordinatorError::Refused {
                refusal: RpcRefusal::NotParty,
                message: "Only roster nodes can retire executions.".to_string(),
            });
        }
        let n = self.mpc_nodes.len();
        if self.retired.acknowledge(execution_id, party, n) {
            return Ok(());
        }
        let output_retention = self.output_retention;
        let Some(execution) = self.executions.get_mut(&execution_id) else {
            // Already removed. Acknowledging twice is not an error: a party that retries after a
            // lost connection must not see its cleanup fail.
            return Ok(());
        };
        execution.retirement_acks.insert(party.clone());
        let unanimous = execution.retirement_acks.len() >= n;
        let retain = unanimous && execution.registration.client_slots.has_output_slots();
        if retain && execution.retained_until.is_none() {
            execution.retained_until = Some(Instant::now() + output_retention);
            self.sweeper_wake.notify_one();
        }
        self.retirement_changed.notify_waiters();
        if unanimous && !retain {
            self.remove_execution(execution_id);
        }
        Ok(())
    }

    /// Whether `execution_id` has reached its retirement quorum but not yet been forgotten.
    pub fn is_retired(&self, execution_id: ExecutionId) -> bool {
        self.retired.contains(execution_id)
            || self.executions.get(&execution_id).is_some_and(|execution| {
                execution.retirement_acks.len() >= self.retirement_quorum()
            })
    }

    fn retirement_progress(&self, execution_id: ExecutionId) -> (usize, usize) {
        let n = self.mpc_nodes.len();
        if let Some(execution) = self.executions.get(&execution_id) {
            return (execution.retirement_acks.len(), n);
        }
        if let Some(acks) = self.retired.acks.get(&execution_id) {
            return (acks.len(), n);
        }
        (n, n)
    }

    /// Whether the one-off drain may start: the execution is gone, or it is in a terminal
    /// round and the retirement quorum acknowledged it.
    fn retirement_quorum_reached(&self, execution_id: ExecutionId) -> bool {
        match self.executions.get(&execution_id) {
            None => true,
            Some(execution) => {
                matches!(execution.round, Round::ProgramFinished | Round::Aborted)
                    && execution.retirement_acks.len() >= self.retirement_quorum()
            }
        }
    }

    /// Resolves once `execution_id` is absent, or is in a terminal round (`ProgramFinished` or
    /// `Aborted`) with at least the retirement quorum of acknowledgements. Woken by every path
    /// that changes that condition, without polling.
    pub async fn watch_for_retirement_quorum(state: Arc<Mutex<Self>>, execution_id: ExecutionId) {
        Self::wait_until(state, move |shared| {
            shared.retirement_quorum_reached(execution_id)
        })
        .await;
    }

    /// Resolves once `execution_id` has been removed.
    async fn wait_for_removal(state: Arc<Mutex<Self>>, execution_id: ExecutionId) {
        Self::wait_until(state, move |shared| {
            !shared.executions.contains_key(&execution_id)
        })
        .await;
    }

    async fn wait_until(state: Arc<Mutex<Self>>, condition: impl Fn(&Self) -> bool) {
        loop {
            let notified = {
                let shared = state.lock().await;
                if condition(&shared) {
                    return;
                }
                let notified = shared.retirement_changed.clone().notified_owned();
                let mut notified = Box::pin(notified);
                // Registered before the mutex is released, so a notification sent between the
                // check and the wait is not lost.
                notified.as_mut().enable();
                notified
            };
            notified.await;
        }
    }

    /// Removes `execution_id` by any path, records how it ended and unbinds its identities.
    /// Dropping its parked sinks ends their subscribers' streams.
    fn remove_execution(&mut self, execution_id: ExecutionId) -> Option<CoordinatorExecutionState> {
        let execution = self.executions.remove(&execution_id)?;
        for identity in execution.admissions.identities() {
            if let Some(count) = self.bound_identities.get_mut(identity) {
                *count -= 1;
                if *count == 0 {
                    self.bound_identities.remove(identity);
                }
            }
        }
        let outcome = match &execution.aborted {
            Some(reason) => ExecutionOutcome::Aborted(reason.clone()),
            None => ExecutionOutcome::Finished,
        };
        self.ended.record(execution_id, outcome);
        self.retirement_changed.notify_waiters();
        Some(execution)
    }

    /// The live execution, or the refusal for one that is unknown (16), ended as aborted (35)
    /// or aborted while still live (35).
    fn live_execution(
        &self,
        execution_id: ExecutionId,
    ) -> Result<&CoordinatorExecutionState, ErrorObjectOwned> {
        let execution = self
            .executions
            .get(&execution_id)
            .ok_or_else(|| self.gone_refusal(execution_id))?;
        match &execution.aborted {
            Some(reason) => Err(aborted_refusal(execution_id, reason)),
            None => Ok(execution),
        }
    }

    fn live_execution_mut(
        &mut self,
        execution_id: ExecutionId,
    ) -> Result<&mut CoordinatorExecutionState, ErrorObjectOwned> {
        self.live_execution(execution_id)?;
        Ok(self
            .executions
            .get_mut(&execution_id)
            .expect("presence checked above"))
    }

    /// The refusal for an execution that is not live: `ExecutionAborted` with its reason when
    /// this process remembers it aborted, `ExecutionNotFound` otherwise.
    fn gone_refusal(&self, execution_id: ExecutionId) -> ErrorObjectOwned {
        match self.ended.outcome(execution_id) {
            Some(ExecutionOutcome::Aborted(reason)) => aborted_refusal(execution_id, reason),
            _ => execution_not_found(execution_id),
        }
    }

    /// Removes retention-expired executions, and returns the executions whose deadlines are due
    /// together with the earliest instant anything is due next.
    fn sweep(&mut self) -> (Vec<ExecutionId>, Option<Instant>) {
        let now_instant = Instant::now();
        let now_system = SystemTime::now();
        let expired = self
            .executions
            .iter()
            .filter(|(_, execution)| {
                execution
                    .retained_until
                    .is_some_and(|until| until <= now_instant)
            })
            .map(|(execution_id, _)| *execution_id)
            .collect::<Vec<_>>();
        for execution_id in expired {
            self.remove_execution(execution_id);
        }

        let mut due = Vec::new();
        let mut next: Option<Instant> = None;
        let mut consider = |at: Instant| next = Some(next.map_or(at, |earliest| earliest.min(at)));
        for (execution_id, execution) in &self.executions {
            if let Some(until) = execution.retained_until {
                consider(until);
            }
            if execution.aborted.is_some() {
                continue;
            }
            if execution.abort_condition(now_system).is_some() {
                due.push(*execution_id);
                continue;
            }
            for deadline in execution.pending_deadlines() {
                let wait = deadline
                    .as_system_time()
                    .duration_since(now_system)
                    .unwrap_or(Duration::ZERO);
                consider(now_instant + wait);
            }
        }
        (due, next)
    }
}

impl CoordinatorExecutionState {
    fn new(
        registration: Arc<ExecutionRegistration>,
        registration_nonce: RegistrationNonce,
    ) -> Self {
        let slots = &registration.client_slots;
        let mut admissions = ClientAdmissions::new(slots.slots().len());
        if let AdmissionPolicy::PreRegistered { clients } = &registration.admission {
            for (position, client) in clients.iter().enumerate() {
                let client_index = ClientIndex(position as u32);
                admissions.bind(
                    client.clone(),
                    admission_of(&registration, client_index),
                    None,
                );
            }
        }
        Self {
            registration_nonce,
            registration,
            admissions,
            frozen_admissions: None,
            round: Round::Idle,
            aborted: None,
            retirement_acks: HashSet::new(),
            retained_until: None,
            transition_votes: HashMap::new(),
            round_events: HashMap::new(),
            round_sinks: HashMap::new(),
            reservation_sinks: ParkedSinks::default(),
            submission_sinks: ParkedSinks::default(),
            outputs: HashMap::new(),
            output_waiters: HashMap::new(),
            delivery: Arc::new(Mutex::new(())),
        }
    }

    fn execution_id(&self) -> ExecutionId {
        self.registration.execution_id
    }

    /// The masked inputs of slots that have inputs but no submission.
    fn missing_inputs(&self) -> u64 {
        self.registration
            .client_slots
            .slots()
            .iter()
            .enumerate()
            .filter(|(position, spec)| {
                spec.input_count > 0
                    && self
                        .admissions
                        .slot(ClientIndex(*position as u32))
                        .is_none_or(|slot| slot.submission.is_none())
            })
            .map(|(_, spec)| spec.input_count)
            .sum()
    }

    fn association_open(&self) -> bool {
        matches!(
            self.round,
            Round::Idle | Round::Preprocessing | Round::InputMaskReservation
        )
    }

    fn before_mpc_execution(&self) -> bool {
        round_index(self.round) < round_index(Round::MPCExecution)
    }

    /// The abort a deadline sweep would apply now, if any.
    fn abort_condition(&self, now: SystemTime) -> Option<AbortReason> {
        if self.aborted.is_some() {
            return None;
        }
        let deadlines = self.registration.deadlines?;
        let unbound_slots = self.admissions.unbound();
        if now >= deadlines.association.as_system_time()
            && self.association_open()
            && unbound_slots > 0
        {
            return Some(AbortReason::AssociationDeadline {
                deadline: deadlines.association,
                unbound_slots: unbound_slots as u32,
            });
        }
        let missing_inputs = self.missing_inputs();
        if now >= deadlines.input.as_system_time()
            && self.before_mpc_execution()
            && missing_inputs > 0
        {
            return Some(AbortReason::InputDeadline {
                deadline: deadlines.input,
                missing_inputs,
            });
        }
        None
    }

    /// The deadlines that could still abort this execution when they pass.
    fn pending_deadlines(&self) -> Vec<UnixSeconds> {
        let Some(deadlines) = self.registration.deadlines else {
            return Vec::new();
        };
        let mut pending = Vec::new();
        if self.association_open() && self.admissions.unbound() > 0 {
            pending.push(deadlines.association);
        }
        if self.before_mpc_execution() && self.missing_inputs() > 0 {
            pending.push(deadlines.input);
        }
        pending
    }

    /// True for the `Preprocessing` → `MPCExecution` skip over the input rounds.
    fn is_input_skip(&self, next_round: Round) -> bool {
        self.round == Round::Preprocessing && next_round == Round::MPCExecution
    }

    /// True for the `MPCExecution` → `ProgramFinished` skip over output distribution.
    fn is_output_skip(&self, next_round: Round) -> bool {
        self.round == Round::MPCExecution && next_round == Round::ProgramFinished
    }

    /// A reason the coordinator must not enter `next_round` yet, independent of how many parties
    /// proposed it. Each is a wait, not a rejection: proposals are recorded, and the round
    /// applies inside whichever call makes it legal.
    ///
    /// This is what actually protects the protocol from a malicious proposer. Round order alone
    /// is not enough: entering `MPCExecution` while input slots are still empty would run the
    /// program on a truncated input set, silently censoring the clients that had not submitted.
    fn blocking_precondition(&self, next_round: Round) -> Option<String> {
        let slots = &self.registration.client_slots;
        let input_skip = self.is_input_skip(next_round);
        if next_round == Round::MPCExecution && !input_skip {
            let missing = self.missing_inputs();
            if missing > 0 {
                return Some(format!(
                    "{missing} of {} masked inputs have not been submitted",
                    slots.n_inputs()
                ));
            }
        }
        if next_round == Round::InputCollection || input_skip {
            let unbound = self.admissions.unbound();
            if unbound > 0 {
                return Some(format!(
                    "{unbound} of {} client slots are unbound",
                    slots.capacity()
                ));
            }
        }
        if input_skip && slots.n_inputs() > 0 {
            return Some(format!(
                "the registration has {} inputs; the input rounds cannot be skipped",
                slots.n_inputs()
            ));
        }
        if self.is_output_skip(next_round) {
            let output_slots = slots
                .slots()
                .iter()
                .filter(|slot| slot.output_count > 0)
                .count();
            if output_slots > 0 {
                return Some(format!(
                    "{output_slots} client slots have output rights; OutputDistribution cannot be skipped"
                ));
            }
        }
        None
    }

    /// The next round that both follows the current one and has reached the proposer quorum.
    fn next_quorum_round(&self, quorum: usize) -> Option<Round> {
        const ORDERED_ROUNDS: [Round; 6] = [
            Round::Preprocessing,
            Round::InputMaskReservation,
            Round::InputCollection,
            Round::MPCExecution,
            Round::OutputDistribution,
            Round::ProgramFinished,
        ];
        ORDERED_ROUNDS.into_iter().find(|&candidate| {
            (round_before(candidate) == Some(self.round)
                || self.is_input_skip(candidate)
                || self.is_output_skip(candidate))
                && self
                    .transition_votes
                    .get(&candidate)
                    .is_some_and(|voters| voters.len() >= quorum)
        })
    }

    /// Applies every round whose proposer quorum is already satisfied and whose preconditions
    /// hold, returning the waiters to deliver to once the state mutex is released.
    ///
    /// This cascades rather than applying a single round so that proposals which arrived out of
    /// order — a fast party proposing round `R + 1` before the coordinator applied `R` — are not
    /// stranded. It is also why proposals for a future round are recorded rather than rejected.
    fn try_advance(
        &mut self,
        quorum: usize,
        roster_head: &ClientIdentity,
    ) -> Vec<TransitionDelivery> {
        let mut deliveries = Vec::new();
        if self.aborted.is_some() {
            return deliveries;
        }
        while let Some(next_round) = self.next_quorum_round(quorum) {
            if let Some(reason) = self.blocking_precondition(next_round) {
                eprintln!(
                    "coordinator holding {:?} for execution {}: {reason}",
                    next_round,
                    self.execution_id()
                );
                return deliveries;
            }

            let event = match next_round {
                Round::Preprocessing => Event::PreprocessingStarted {
                    // Informational only: retained so the off-chain event mirrors its on-chain
                    // counterpart. No party derives authority from this field.
                    designated_party: roster_head.clone(),
                },
                Round::InputMaskReservation => Event::InputMaskReservationStarted,
                Round::InputCollection => Event::InputCollectionStarted,
                Round::MPCExecution => Event::MPCStarted,
                Round::OutputDistribution => Event::OutputSendingStarted,
                Round::ProgramFinished => Event::ExecutionDone,
                // Neither is a member of the ordered rounds, so neither is reached here.
                Round::Idle | Round::Aborted => return deliveries,
            };

            // The admission set freezes on entering InputCollection, or MPCExecution through the
            // input skip; the preconditions above make it complete at that moment.
            if next_round == Round::InputCollection || self.is_input_skip(next_round) {
                self.freeze_admissions();
            }

            self.round_events.insert(next_round, event.clone());
            self.round = next_round;
            let sinks = self
                .round_sinks
                .remove(&next_round)
                .map(|mut parked| parked.take())
                .unwrap_or_default();
            deliveries.push((event, sinks));

            #[cfg(feature = "benchmark")]
            {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                println!("BENCH_ROUND: {:?} ts={}", next_round, ts);
            }
        }
        deliveries
    }

    fn freeze_admissions(&mut self) {
        let records = self
            .admissions
            .slots
            .iter()
            .flatten()
            .map(|slot| ClientAdmissionRecord {
                client: slot.client.clone(),
                client_index: slot.admission.client_index,
                input_range: slot.admission.input_range,
                output_rights: slot.admission.output_rights,
            })
            .collect();
        self.frozen_admissions = Some(Arc::new(ClientAdmissionSet {
            execution_id: self.execution_id(),
            records,
        }));
    }

    /// Takes every parked sink and output waiter, for an abort.
    fn take_all_sinks(&mut self) -> (Vec<ParkedSink>, Vec<ParkedSink>) {
        let mut event_sinks = Vec::new();
        for (_, mut parked) in self.round_sinks.drain() {
            event_sinks.extend(parked.take());
        }
        event_sinks.extend(self.reservation_sinks.take());
        event_sinks.extend(self.submission_sinks.take());
        let waiters = self
            .output_waiters
            .drain()
            .map(|(_, entry)| entry)
            .collect();
        (event_sinks, waiters)
    }
}

fn admission_of(
    registration: &ExecutionRegistration,
    client_index: ClientIndex,
) -> ClientAdmission {
    ClientAdmission {
        execution_id: registration.execution_id,
        client_index,
        input_range: registration.client_slots.input_range(client_index),
        output_rights: registration.client_slots.output_rights(client_index),
    }
}

/// Aborts `execution_id` if one of its deadlines still applies once its delivery guard is held.
async fn abort_if_due(
    state: &Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    execution_id: ExecutionId,
) {
    let Some(delivery) = ({
        let shared = state.lock().await;
        shared
            .executions
            .get(&execution_id)
            .map(|execution| execution.delivery.clone())
    }) else {
        return;
    };
    let _delivery_guard = delivery.lock().await;
    let (reason, event_sinks, waiters) = {
        let mut shared = state.lock().await;
        let retirement_changed = shared.retirement_changed.clone();
        let Some(execution) = shared.executions.get_mut(&execution_id) else {
            return;
        };
        let Some(reason) = execution.abort_condition(SystemTime::now()) else {
            return;
        };
        execution.round = Round::Aborted;
        execution.aborted = Some(reason.clone());
        let (event_sinks, waiters) = execution.take_all_sinks();
        retirement_changed.notify_waiters();
        (reason, event_sinks, waiters)
    };
    eprintln!("coordinator aborted execution {execution_id}: {reason}");
    send_aborted(event_sinks, &reason);
    drop(waiters);
}

/// One deadline sweeper per listener: sleeps until the earliest pending deadline or retention
/// expiry, or until a registration or retention wakes it, then acts on what is due.
fn spawn_deadline_sweeper(state: Arc<Mutex<CoordinatorRPCServerSharedBase>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let wake = state.lock().await.sweeper_wake.clone();
        loop {
            let (due, next) = state.lock().await.sweep();
            for execution_id in due {
                abort_if_due(&state, execution_id).await;
            }
            match next {
                Some(at) => {
                    tokio::select! {
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => {}
                        _ = wake.notified() => {}
                    }
                }
                None => wake.notified().await,
            }
        }
    })
}

/// Owns a sweeper task; dropping it stops the sweeper.
struct SweeperHandle(JoinHandle<()>);

impl Drop for SweeperHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Pre-implemented RPC methods.
#[async_trait]
impl CoordinatorRPCBaseServer for CoordinatorRPCServerConnectionBase {
    async fn get_node_roster(&self) -> RpcResult<NodeRosterWire> {
        let roster = {
            let mut shared = self.d.lock().await;
            if !shared.read_rate.try_take(&self.id, Instant::now()) {
                return Err(refusal(
                    CoordinatorRPCBaseError::RateLimited,
                    "Too many roster reads from this identity; retry later.",
                ));
            }
            shared.node_roster_wire.clone()
        };
        Ok(NodeRosterWire::clone(&roster))
    }

    async fn get_execution_summary(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<ExecutionSummary> {
        let (registration, registration_nonce, round) = {
            let mut shared = self.d.lock().await;
            if !shared.read_rate.try_take(&self.id, Instant::now()) {
                return Err(refusal(
                    CoordinatorRPCBaseError::RateLimited,
                    "Too many summary reads from this identity; retry later.",
                ));
            }
            // A live aborted execution still answers its summary, round `Aborted`.
            let execution = shared
                .executions
                .get(&execution_id)
                .ok_or_else(|| shared.gone_refusal(execution_id))?;
            (
                execution.registration.clone(),
                execution.registration_nonce,
                execution.round,
            )
        };
        Ok(ExecutionSummary {
            execution_id,
            registration_nonce,
            program_hash: registration.program_hash,
            client_slots: registration.client_slots.clone(),
            admission: registration.admission.kind(),
            deadlines: registration.deadlines,
            round,
        })
    }

    async fn associate_client(
        &self,
        execution_id: ExecutionId,
        request: AssociationRequest,
    ) -> RpcResult<ClientAdmission> {
        // 1. Snapshot, under the state mutex.
        let (quorum, roster_head, roster_digest, registration, nonce, delivery) = {
            let shared = self.d.lock().await;
            let execution = shared.live_execution(execution_id)?;
            (
                shared.transition_quorum(),
                shared.mpc_nodes[0].clone(),
                shared.node_roster.digest(),
                execution.registration.clone(),
                execution.registration_nonce,
                execution.delivery.clone(),
            )
        };

        // 2–3. Pure checks with no lock held; verdicts are not returned yet.
        let invitation_verdict = match (&registration.admission, &request.invitation) {
            (AdmissionPolicy::Invitation { issuer }, Some(signed)) => Some(signed.verify(
                issuer,
                &InvitationContext {
                    execution_id,
                    registration_nonce: nonce,
                    program_hash: &registration.program_hash,
                    roster_digest,
                    caller: &self.id,
                    now: UnixSeconds::now(),
                },
            )),
            _ => None,
        };
        let sealable = KeyAlgorithm::of_client_identity(&self.id) == Some(KeyAlgorithm::EcdsaP256);

        // 4. Binding: the delivery guard, then the state again.
        let _delivery_guard = delivery.lock().await;
        let mut guard = self.d.lock().await;
        let shared = &mut *guard;
        let execution = match shared.executions.get(&execution_id) {
            None => return Err(shared.gone_refusal(execution_id)),
            Some(execution) => execution,
        };
        if let Some(reason) = &execution.aborted {
            return Err(aborted_refusal(execution_id, reason));
        }
        if execution.registration_nonce != nonce {
            // Removed and registered again while the pure checks ran.
            return Err(execution_not_found(execution_id));
        }
        let execution = shared
            .executions
            .get_mut(&execution_id)
            .expect("presence checked above");

        // 5. Idempotency.
        if let Some(slot) = execution.admissions.slot_of_mut(&self.id) {
            return match &slot.request {
                Some(recorded) if *recorded == request => Ok(slot.admission.clone()),
                None => {
                    if request.invitation.is_some() {
                        return Err(admission_refusal(AdmissionError::UnexpectedInvitation {
                            execution_id,
                        }));
                    }
                    if let Some(requested) = request.slot {
                        if requested != slot.admission.client_index {
                            return Err(admission_refusal(
                                AdmissionError::PreRegisteredSlotMismatch {
                                    registered: slot.admission.client_index,
                                    requested,
                                },
                            ));
                        }
                    }
                    slot.request = Some(request);
                    Ok(slot.admission.clone())
                }
                Some(_) => Err(admission_refusal(AdmissionError::AlreadyAssociated {
                    execution_id,
                    admission: slot.admission.clone(),
                })),
            };
        }

        // 6. Round.
        if !execution.association_open() {
            return Err(admission_refusal(AdmissionError::AssociationClosed {
                execution_id,
                current: execution.round,
            }));
        }

        // 7. Policy.
        let requested = match &registration.admission {
            AdmissionPolicy::PreRegistered { .. } => {
                return Err(admission_refusal(AdmissionError::NotPreRegistered {
                    execution_id,
                }));
            }
            AdmissionPolicy::Open => {
                if request.invitation.is_some() {
                    return Err(admission_refusal(AdmissionError::UnexpectedInvitation {
                        execution_id,
                    }));
                }
                request.slot
            }
            AdmissionPolicy::Invitation { .. } => {
                let Some(signed) = &request.invitation else {
                    return Err(admission_refusal(AdmissionError::InvitationRequired {
                        execution_id,
                    }));
                };
                if let Some(Err(reason)) = invitation_verdict {
                    return Err(admission_refusal(AdmissionError::InvitationRejected {
                        reason,
                    }));
                }
                let invited = signed.invitation.client_index;
                if let Some(requested) = request.slot {
                    if requested != invited {
                        return Err(admission_refusal(AdmissionError::InvitationRejected {
                            reason:
                                stoffel_mpc_coordinator_shared::InvitationRejection::SlotMismatch {
                                    invited,
                                    requested,
                                },
                        }));
                    }
                }
                Some(invited)
            }
        };

        // 8. Slot.
        let capacity = registration.client_slots.capacity();
        let client_index = match requested {
            Some(requested) => {
                if requested.0 >= capacity {
                    return Err(admission_refusal(AdmissionError::SlotOutOfRange {
                        execution_id,
                        requested,
                        slots: capacity,
                    }));
                }
                if execution.admissions.slot(requested).is_some() {
                    return Err(admission_refusal(AdmissionError::SlotTaken {
                        execution_id,
                        requested,
                    }));
                }
                requested
            }
            None => match execution.admissions.slots.iter().position(Option::is_none) {
                Some(position) => ClientIndex(position as u32),
                None => {
                    return Err(admission_refusal(AdmissionError::CapacityExhausted {
                        execution_id,
                        capacity,
                    }));
                }
            },
        };

        // 9. Output slots need a key output shares can be sealed to.
        if registration.client_slots.slots()[client_index.0 as usize].output_count > 0 && !sealable
        {
            return Err(admission_refusal(AdmissionError::UnsupportedClientKey {
                client_index,
            }));
        }

        // 10. Bind, index the identity, and apply any round this binding released.
        let admission = admission_of(&registration, client_index);
        execution
            .admissions
            .bind(self.id.clone(), admission.clone(), Some(request));
        let transitions = execution.try_advance(quorum, &roster_head);
        *shared.bound_identities.entry(self.id.clone()).or_default() += 1;
        drop(guard);
        deliver_transitions(transitions);
        Ok(admission)
    }

    async fn get_client_admissions(
        &self,
        execution_id: ExecutionId,
    ) -> RpcResult<ClientAdmissionSet> {
        let frozen = {
            let shared = self.d.lock().await;
            if !shared.mpc_nodes.contains(&self.id) {
                return Err(not_party("read client admissions"));
            }
            let execution = shared.live_execution(execution_id)?;
            execution.frozen_admissions.clone().ok_or_else(|| {
                admission_refusal(AdmissionError::AdmissionsNotFrozen {
                    execution_id,
                    current: execution.round,
                })
            })?
        };
        Ok(ClientAdmissionSet::clone(&frozen))
    }

    async fn retire_execution(&self, execution_id: ExecutionId) -> RpcResult<()> {
        let mut shared = self.d.lock().await;
        if !shared.mpc_nodes.contains(&self.id) {
            return Err(not_party("retire executions"));
        }
        shared
            .retire_execution(execution_id, &self.id)
            .map_err(|error| refusal(CoordinatorRPCBaseError::NotParty, error.to_string()))
    }

    async fn sub_round(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
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

        // Accepting a JSON-RPC subscription performs WebSocket I/O. Never do that while holding
        // the coordinator-wide state mutex.
        let gate = {
            let shared = self.d.lock().await;
            shared.live_execution(execution_id).and_then(|execution| {
                if shared.mpc_nodes.contains(&self.id)
                    || execution.admissions.by_identity.contains_key(&self.id)
                {
                    Ok(shared.hooks.after_subscription_accept.clone())
                } else {
                    Err(admission_refusal(AdmissionError::NotAdmitted {
                        execution_id,
                    }))
                }
            })
        };
        let hook = match gate {
            Ok(hook) => hook,
            Err(error) => {
                pending.reject(error).await;
                return Ok(());
            }
        };
        let sink = pending.accept().await?;
        pause_at(&hook).await;

        let caller = self.id.clone();
        self.replay_then_park(sink, execution_id, true, move |execution, sent, sink| {
            if *sent > 0 {
                return ReplayStep::Done;
            }
            if let Some(event) = execution.round_events.get(&round) {
                *sent = 1;
                return ReplayStep::Replay(vec![ReplayItem::Round(event.clone())]);
            }
            let (entry, released) = ParkedSink::new(caller.clone(), sink);
            execution.round_sinks.entry(round).or_default().park(entry);
            ReplayStep::Parked(released)
        })
        .await
    }

    async fn sub_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        self.event_stream_subscription(pending, execution_id, EventStream::Reservations)
            .await
    }

    async fn sub_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        self.event_stream_subscription(pending, execution_id, EventStream::Submissions)
            .await
    }

    async fn reserve_mask_indices(
        &self,
        execution_id: ExecutionId,
        indices: Vec<u64>,
    ) -> RpcResult<()> {
        let delivery = {
            let shared = self.d.lock().await;
            shared.live_execution(execution_id)?.delivery.clone()
        };
        let _delivery_guard = delivery.lock().await;
        let (client, range, entries) = {
            let mut shared = self.d.lock().await;
            let execution = shared.live_execution_mut(execution_id)?;
            if execution.round != Round::InputMaskReservation {
                return Err(wrong_round(Round::InputMaskReservation, execution.round));
            }
            let Some(slot) = execution.admissions.slot_of_mut(&self.id) else {
                return Err(admission_refusal(AdmissionError::NotAdmitted {
                    execution_id,
                }));
            };
            let Some(range) = slot.admission.input_range else {
                return Err(admission_refusal(
                    AdmissionError::ReservationOutsideAdmission { admitted: None },
                ));
            };
            if slot.reserved {
                return Err(refusal(
                    CoordinatorRPCBaseError::ClientAlreadyReserved,
                    "This client has already reserved its input range; a range is reserved in one call.",
                ));
            }
            if !range.is_exactly(&indices) {
                return Err(admission_refusal(
                    AdmissionError::ReservationOutsideAdmission {
                        admitted: Some(range),
                    },
                ));
            }
            slot.reserved = true;
            let client = slot.client.clone();
            let client_index = slot.admission.client_index;
            execution.admissions.reservation_order.push(client_index);
            (client, range, execution.reservation_sinks.take())
        };

        // Live broadcasts never wait on a subscriber.
        let json = reservation_event_json(&client, range);
        let delivered = entries
            .into_iter()
            .filter_map(|mut entry| entry.try_send(json.clone()).then_some(entry))
            .collect::<Vec<_>>();

        let mut shared = self.d.lock().await;
        if let Some(execution) = shared.executions.get_mut(&execution_id) {
            match execution.aborted.clone() {
                Some(reason) => {
                    drop(shared);
                    send_aborted(delivered, &reason);
                }
                None => {
                    for entry in delivered {
                        execution.reservation_sinks.park(entry);
                    }
                }
            }
        }
        Ok(())
    }

    async fn submit_masked_inputs(
        &self,
        execution_id: ExecutionId,
        first_index: u64,
        masked_inputs: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> RpcResult<()> {
        // Snapshot and the state checks.
        let (delivery, nonce, client_index) = {
            let shared = self.d.lock().await;
            let execution = shared.live_execution(execution_id)?;
            if execution.round != Round::InputCollection {
                return Err(wrong_round(Round::InputCollection, execution.round));
            }
            let Some(slot) = execution.admissions.slot_of(&self.id) else {
                return Err(admission_refusal(AdmissionError::NotAdmitted {
                    execution_id,
                }));
            };
            let Some(range) = slot.admission.input_range else {
                return Err(submission_refusal(
                    SubmissionError::SubmissionOutsideAdmission { admitted: None },
                ));
            };
            if !slot.reserved {
                return Err(refusal(
                    CoordinatorRPCBaseError::IndexNotReserved,
                    "This client has not reserved its input range.",
                ));
            }
            if slot.submission.is_some() {
                return Err(refusal(
                    CoordinatorRPCBaseError::MaskedInputAlreadySubmitted,
                    "This client has already submitted its masked inputs.",
                ));
            }
            if first_index != range.start || masked_inputs.len() as u64 != range.count.get() {
                return Err(submission_refusal(
                    SubmissionError::SubmissionOutsideAdmission {
                        admitted: Some(range),
                    },
                ));
            }
            (
                execution.delivery.clone(),
                execution.registration_nonce,
                slot.admission.client_index,
            )
        };

        // Pure checks, no lock held.
        for (offset, masked_input) in masked_inputs.iter().enumerate() {
            let len = masked_input.len() as u64;
            if len > MAX_MASKED_INPUT_BYTES {
                return Err(submission_refusal(SubmissionError::MaskedInputTooLarge {
                    reserved_index: first_index + offset as u64,
                    len,
                    max: MAX_MASKED_INPUT_BYTES,
                }));
            }
        }
        let signing_bytes = masked_inputs_signing_bytes(
            execution_id,
            nonce,
            client_index,
            first_index,
            &masked_inputs,
        );
        if verify_identity_signature(&self.id, &signing_bytes, &signature).is_err() {
            return Err(submission_refusal(SubmissionError::BadMaskedInputSignature));
        }
        let submission = Arc::new(MaskedInputSubmission {
            client: self.id.clone(),
            first_index,
            masked_inputs,
            signature,
        });

        // Record and broadcast, under the delivery guard.
        let _delivery_guard = delivery.lock().await;
        let (entries, hook) = {
            let mut shared = self.d.lock().await;
            let hook = shared.hooks.during_masked_input_broadcast.clone();
            let execution = shared.live_execution_mut(execution_id)?;
            if execution.registration_nonce != nonce {
                return Err(execution_not_found(execution_id));
            }
            if execution.round != Round::InputCollection {
                return Err(wrong_round(Round::InputCollection, execution.round));
            }
            let slot = execution
                .admissions
                .slot_of_mut(&self.id)
                .expect("bindings are never removed");
            if slot.submission.is_some() {
                return Err(refusal(
                    CoordinatorRPCBaseError::MaskedInputAlreadySubmitted,
                    "This client has already submitted its masked inputs.",
                ));
            }
            slot.submission = Some(submission.clone());
            execution.admissions.submission_order.push(client_index);
            (execution.submission_sinks.take(), hook)
        };

        let json = EventRef::MaskedInputEvent {
            submission: &submission,
        }
        .to_json();
        let delivered = entries
            .into_iter()
            .filter_map(|mut entry| entry.try_send(json.clone()).then_some(entry))
            .collect::<Vec<_>>();
        pause_at(&hook).await;

        let transitions = {
            let mut shared = self.d.lock().await;
            let quorum = shared.transition_quorum();
            let roster_head = shared.mpc_nodes[0].clone();
            let Some(execution) = shared.executions.get_mut(&execution_id) else {
                return Ok(());
            };
            if let Some(reason) = execution.aborted.clone() {
                drop(shared);
                send_aborted(delivered, &reason);
                return Ok(());
            }
            for entry in delivered {
                execution.submission_sinks.park(entry);
            }
            // This input may have been the last one the `MPCExecution` precondition was waiting
            // on: re-checking here makes the precondition a wait rather than a rejection.
            execution.try_advance(quorum, &roster_head)
        };
        deliver_transitions(transitions);
        Ok(())
    }

    /// Proposes that `execution_id` advance to `next_round`.
    ///
    /// Any roster node may propose. The coordinator applies the transition once a quorum of
    /// distinct nodes has proposed the same round and the round's preconditions hold, so no
    /// single node can either drive the protocol alone or halt it by falling silent.
    ///
    /// A proposal is never rejected for arriving early or late: it is recorded, and acted on when
    /// (or if) it becomes both current and supported.
    async fn transition(&self, execution_id: ExecutionId, next_round: Round) -> RpcResult<()> {
        let (quorum, roster_head, delivery) = {
            let shared = self.d.lock().await;
            if !shared.mpc_nodes.contains(&self.id) {
                return Err(not_party("propose transitions"));
            }
            if round_before(next_round).is_none() {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::InvalidParams.code(),
                    format!("Round {next_round:?} cannot be transitioned to"),
                    None::<()>,
                ));
            }
            (
                shared.transition_quorum(),
                shared.mpc_nodes[0].clone(),
                shared.live_execution(execution_id)?.delivery.clone(),
            )
        };

        let _delivery_guard = delivery.lock().await;
        let transitions = {
            let mut shared = self.d.lock().await;
            let retirement_changed = shared.retirement_changed.clone();
            let execution = shared.live_execution_mut(execution_id)?;
            if round_index(next_round) <= round_index(execution.round) {
                // Already applied. A party that proposes a round the quorum passed without it is
                // simply late, which is the normal outcome for the slowest parties.
                return Ok(());
            }
            execution
                .transition_votes
                .entry(next_round)
                .or_default()
                .insert(self.id.clone());
            let transitions = execution.try_advance(quorum, &roster_head);
            if execution.round == Round::ProgramFinished {
                retirement_changed.notify_waiters();
            }
            transitions
        };
        deliver_transitions(transitions);
        Ok(())
    }

    async fn send_output_shares(
        &self,
        execution_id: ExecutionId,
        client_index: ClientIndex,
        sealed: SealedOutput,
    ) -> RpcResult<()> {
        // Snapshot and the state checks.
        let (position, nonce, delivery) = {
            let shared = self.d.lock().await;
            let Some(position) = shared.mpc_nodes.iter().position(|node| *node == self.id) else {
                return Err(not_party("send output shares"));
            };
            let execution = shared.live_execution(execution_id)?;
            let has_rights = execution.admissions.slot(client_index).is_some_and(|slot| {
                matches!(slot.admission.output_rights, OutputRights::Receive { .. })
            });
            if !has_rights {
                return Err(admission_refusal(AdmissionError::NoOutputRights {
                    execution_id,
                }));
            }
            if output_already_sent(execution, client_index, position) {
                return Err(output_already_sent_refusal());
            }
            (
                position as u32,
                execution.registration_nonce,
                execution.delivery.clone(),
            )
        };

        // Pure checks, no lock held.
        let len = sealed.ciphertext.len() as u64;
        if len > MAX_SEALED_OUTPUT_BYTES {
            return Err(submission_refusal(SubmissionError::SealedOutputTooLarge {
                len,
                max: MAX_SEALED_OUTPUT_BYTES,
            }));
        }
        let signing_bytes = sealed_output_signing_bytes(
            execution_id,
            nonce,
            client_index,
            position,
            &sealed.encapsulated_key,
            &sealed.ciphertext,
        );
        if verify_identity_signature(&self.id, &signing_bytes, &sealed.signature).is_err() {
            return Err(submission_refusal(SubmissionError::BadOutputSignature));
        }
        let item = Arc::new(SealedOutputShares {
            node_position: position,
            sealed,
        });

        // Store and deliver, under the delivery guard.
        let _delivery_guard = delivery.lock().await;
        let (waiter, hook) = {
            let mut shared = self.d.lock().await;
            let hook = shared.hooks.before_output_relock.clone();
            let execution = shared.live_execution_mut(execution_id)?;
            if execution.registration_nonce != nonce {
                return Err(execution_not_found(execution_id));
            }
            if output_already_sent(execution, client_index, position as usize) {
                return Err(output_already_sent_refusal());
            }
            execution
                .outputs
                .entry(client_index)
                .or_default()
                .push(item.clone());
            (execution.output_waiters.remove(&client_index), hook)
        };

        let delivered = waiter.and_then(|mut waiter| {
            let json = to_json_raw_value(&*item).expect("items serialize to JSON");
            waiter.try_send(json).then_some(waiter)
        });
        pause_at(&hook).await;

        // The execution may have been removed or aborted meanwhile: that ends this work quietly.
        let mut shared = self.d.lock().await;
        if let Some(execution) = shared.executions.get_mut(&execution_id) {
            if execution.aborted.is_none() {
                if let Some(waiter) = delivered {
                    execution
                        .output_waiters
                        .entry(client_index)
                        .or_insert(waiter);
                }
            }
        }
        Ok(())
    }

    async fn obtain_output_shares(
        &self,
        pending: PendingSubscriptionSink,
        execution_id: ExecutionId,
    ) -> SubscriptionResult {
        // Validate under the state mutex, but never hold it while completing the WebSocket
        // subscription handshake.
        let gate = {
            let shared = self.d.lock().await;
            shared.live_execution(execution_id).and_then(|execution| {
                let slot = execution.admissions.slot_of(&self.id).filter(|slot| {
                    matches!(slot.admission.output_rights, OutputRights::Receive { .. })
                });
                let Some(slot) = slot else {
                    return Err(admission_refusal(AdmissionError::NoOutputRights {
                        execution_id,
                    }));
                };
                let client_index = slot.admission.client_index;
                if execution
                    .output_waiters
                    .get(&client_index)
                    .is_some_and(|waiter| !waiter.sink.is_closed())
                {
                    return Err(refusal(
                        CoordinatorRPCBaseError::OutputSharesAlreadyRequested,
                        "Output shares already requested.",
                    ));
                }
                Ok((client_index, shared.hooks.after_subscription_accept.clone()))
            })
        };
        let (client_index, hook) = match gate {
            Ok(gate) => gate,
            Err(error) => {
                pending.reject(error).await;
                return Ok(());
            }
        };
        let sink = pending.accept().await?;
        pause_at(&hook).await;

        let caller = self.id.clone();
        self.replay_then_park(sink, execution_id, false, move |execution, sent, sink| {
            let history = execution
                .outputs
                .get(&client_index)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if history.len() > *sent {
                let items = history[*sent..]
                    .iter()
                    .cloned()
                    .map(ReplayItem::Output)
                    .collect();
                *sent = history.len();
                return ReplayStep::Replay(items);
            }
            if execution
                .output_waiters
                .get(&client_index)
                .is_some_and(|waiter| !waiter.sink.is_closed())
            {
                return ReplayStep::Superseded;
            }
            let (entry, released) = ParkedSink::new(caller.clone(), sink);
            execution.output_waiters.insert(client_index, entry);
            ReplayStep::Parked(released)
        })
        .await
    }
}

fn output_already_sent(
    execution: &CoordinatorExecutionState,
    client_index: ClientIndex,
    position: usize,
) -> bool {
    execution.outputs.get(&client_index).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.node_position as usize == position)
    })
}

fn output_already_sent_refusal() -> ErrorObjectOwned {
    refusal(
        CoordinatorRPCBaseError::OutputSharesAlreadySent,
        "This node has already sent its output shares for this client.",
    )
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

    fn capacity_class(internal: &Self::Internal, id: &ClientIdentity) -> CapacityClass {
        internal.capacity_class(id)
    }
}

/// The connection type embedders serve: `CoordinatorRPCBase` merged with the
/// `StoffelCoordinatorRPC` façade, whose methods propose the named round.
#[derive(Clone)]
pub struct OffChainCoordinatorConnection {
    base: CoordinatorRPCServerConnectionBase,
}

impl stoffel_mpc_coordinator_shared::rpc::RPCServerConnection for OffChainCoordinatorConnection {
    type Internal = CoordinatorRPCServerSharedBase;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
        let base_rpc = CoordinatorRPCBaseServer::into_rpc(self.base);
        rpc.merge(base_rpc)
            .expect("the façade and the base interface have disjoint method names");
        rpc
    }

    fn capacity_class(internal: &Self::Internal, id: &ClientIdentity) -> CapacityClass {
        internal.capacity_class(id)
    }
}

#[async_trait]
impl StoffelCoordinatorRPCServer for OffChainCoordinatorConnection {
    async fn start_preprocessing(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::Preprocessing)
            .await
    }

    async fn reserve_input_masks(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputMaskReservation)
            .await
    }

    async fn collect_inputs(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::InputCollection)
            .await
    }

    async fn start_mpc(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::MPCExecution)
            .await
    }

    async fn send_output(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::OutputDistribution)
            .await
    }

    async fn finalize(&self, execution_id: ExecutionId) -> RpcResult<()> {
        self.base
            .transition(execution_id, Round::ProgramFinished)
            .await
    }
}

/// The exterior wrapper of the server-side coordinator.
pub struct OffChainCoordinatorServer<C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection> {
    addr: String,
    state: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    server_handle: RPCServerHandle,
    _sweeper: SweeperHandle,
    _connection: std::marker::PhantomData<C>,
}

/// One pinned coordinator connection plus the node roster it served, fetched and verified
/// exactly once, at connect. Not generic over the share type, so a node can open it before it
/// knows its backend and curve.
pub struct CoordinatorLink {
    rpc: Client,
    node_roster: NodeRoster,
    own_spki: SpkiDer,
    key_der: Vec<u8>,
}

impl CoordinatorLink {
    /// Connects to the coordinator at `addr:port`, admitting only a server that proves
    /// possession of `coordinator`, then fetches and verifies its node roster.
    ///
    /// `expected_roster_digest` is `--expect-roster-digest`: a served digest that differs is
    /// `CoordinatorError::UnexpectedRosterDigest { served, expected }`. A roster that fails
    /// the receiver check is `CoordinatorError::Roster`.
    pub async fn connect(
        addr: &str,
        port: u16,
        coordinator: &SpkiDer,
        expected_roster_digest: Option<RosterDigest>,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let own_spki = SpkiDer::from_certificate_der(&cert_der)?;
        let connection = stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
            addr,
            port,
            cert_der,
            key_der.clone(),
            &ServerPin::Exact(coordinator.clone()),
        )
        .await?;
        let wire = CoordinatorRPCBaseClient::get_node_roster(&connection.client)
            .await
            .map_err(|error| CoordinatorError::JSONError(error.to_string()))?;
        let node_roster = NodeRoster::try_from(wire)?;
        if let Some(expected) = expected_roster_digest {
            if node_roster.digest() != expected {
                return Err(CoordinatorError::UnexpectedRosterDigest {
                    served: node_roster.digest(),
                    expected,
                });
            }
        }
        Ok(Self {
            rpc: connection.client,
            node_roster,
            own_spki,
            key_der,
        })
    }

    pub fn node_roster(&self) -> &NodeRoster {
        &self.node_roster
    }

    /// The key of the certificate this link authenticated with.
    pub fn own_spki(&self) -> &SpkiDer {
        &self.own_spki
    }
}

impl<C> OffChainCoordinatorServer<C>
where
    C: stoffel_mpc_coordinator_shared::rpc::RPCServerConnection<
        Internal = CoordinatorRPCServerSharedBase,
    >,
{
    pub async fn start_coord_from_cert(
        shared: CoordinatorRPCServerSharedBase,
        addr: &str,
        port: u16,
        cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        limits: RpcServerLimits,
    ) -> Result<Self, CoordinatorError> {
        Self::start_coord(
            shared,
            addr,
            port,
            cert.cert.der().to_vec(),
            cert.signing_key.serialize_der(),
            limits,
        )
        .await
    }

    /// Starts a standing coordinator listener and its deadline sweeper. Refuses to bind when
    /// `cert_der` is not a certificate for the key `shared` was built with
    /// (`ServerCertificateMismatch`), or is itself refused (`Pin`).
    pub async fn start_coord(
        shared: CoordinatorRPCServerSharedBase,
        addr: &str,
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        limits: RpcServerLimits,
    ) -> Result<Self, CoordinatorError> {
        check_served_certificate(&shared, &cert_der)?;
        let state = Arc::new(Mutex::new(shared));
        let sweeper = SweeperHandle(spawn_deadline_sweeper(state.clone()));
        let server_handle = stoffel_mpc_coordinator_shared::rpc::start_coord::<C>(
            addr,
            port,
            cert_der,
            key_der,
            state.clone(),
            limits,
        )
        .await?;
        Ok(Self {
            addr: String::from(addr),
            state,
            server_handle,
            _sweeper: sweeper,
            _connection: std::marker::PhantomData,
        })
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone()
    }

    /// The state this listener serves, for an embedding operator that registers further
    /// executions while it runs.
    pub fn state(&self) -> Arc<Mutex<CoordinatorRPCServerSharedBase>> {
        self.state.clone()
    }

    /// Serves exactly `shutdown.execution_id`, then drains and returns. The drain starts once
    /// the execution is absent, or is in a terminal round (`ProgramFinished` or `Aborted`) and
    /// the retirement quorum acknowledged it; it then waits until the execution is removed, or
    /// `shutdown.grace` has passed, and shuts the listener and its sweeper down.
    pub async fn start_coord_one_off(
        shared: CoordinatorRPCServerSharedBase,
        addr: &str,
        port: u16,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
        shutdown: OneOffShutdownConfig,
        limits: RpcServerLimits,
    ) -> Result<(), CoordinatorError> {
        let server = Self::start_coord(shared, addr, port, cert_der, key_der, limits).await?;
        let state = server.state();
        CoordinatorRPCServerSharedBase::watch_for_retirement_quorum(
            state.clone(),
            shutdown.execution_id,
        )
        .await;

        let drained = tokio::time::timeout(
            shutdown.grace,
            CoordinatorRPCServerSharedBase::wait_for_removal(state.clone(), shutdown.execution_id),
        )
        .await
        .is_ok();
        if !drained {
            let (acknowledged, parties) = state
                .lock()
                .await
                .retirement_progress(shutdown.execution_id);
            eprintln!(
                "one-off coordinator shutdown grace expired after {:?}: {acknowledged}/{parties} parties acknowledged",
                shutdown.grace
            );
        }

        server.shutdown().await;
        Ok(())
    }

    /// Stops the listener and the deadline sweeper. Dropping the server state closes its
    /// connections.
    pub async fn shutdown(self) {
        self.server_handle.shutdown().await;
    }
}

/// Refuses a listener certificate whose key is not the key `shared` was built for.
fn check_served_certificate(
    shared: &CoordinatorRPCServerSharedBase,
    cert_der: &[u8],
) -> Result<(), CoordinatorError> {
    if SpkiDer::from_certificate_der(cert_der)? != shared.server_spki {
        return Err(CoordinatorError::ServerCertificateMismatch);
    }
    Ok(())
}

/// A node's copy of the frozen admission set, with the registration nonce its summary named.
struct AgreedAdmissions {
    registration_nonce: RegistrationNonce,
    set: ClientAdmissionSet,
}

pub struct OffChainCoordinatorClient<F: FftField, S: ShareBound<F>> {
    rpc_coord: Client,
    execution_id: ExecutionId,
    node_roster: NodeRoster,
    own_spki: SpkiDer,
    key_der: Vec<u8>,
    /// A client's admission, with the nonce of the summary it associated against.
    admission: Option<(ClientAdmission, RegistrationNonce)>,
    /// A node's admission set, stored by `get_client_admissions`.
    agreed: Option<AgreedAdmissions>,
    _phantom: std::marker::PhantomData<(F, S)>,
}

/// `8 + output_count × share_len + 16`: a sealed vector of `output_count` shares, its length
/// prefix and the AES-GCM tag.
fn sealed_outputs_bytes(output_count: u64, share_len: usize) -> u64 {
    8u64.saturating_add(output_count.saturating_mul(share_len as u64))
        .saturating_add(16)
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    /// A client for `execution_id` over an already verified link.
    pub fn from_link(link: CoordinatorLink, execution_id: ExecutionId) -> Self {
        Self {
            rpc_coord: link.rpc,
            execution_id,
            node_roster: link.node_roster,
            own_spki: link.own_spki,
            key_der: link.key_der,
            admission: None,
            agreed: None,
            _phantom: std::marker::PhantomData,
        }
    }

    /// `CoordinatorLink::connect` + `from_link`. The roster supplies `n` and `t`.
    pub async fn start_rpc_client_for_execution(
        addr: &str,
        port: u16,
        coordinator: &SpkiDer,
        expected_roster_digest: Option<RosterDigest>,
        execution_id: ExecutionId,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let link = CoordinatorLink::connect(
            addr,
            port,
            coordinator,
            expected_roster_digest,
            cert_der,
            key_der,
        )
        .await?;
        Ok(Self::from_link(link, execution_id))
    }

    pub fn node_roster(&self) -> &NodeRoster {
        &self.node_roster
    }

    pub fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    fn decode(&self, error: jsonrpsee::core::client::Error) -> CoordinatorError {
        decode_client_error(self.execution_id, error)
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        if round == Round::Aborted {
            return Err(CoordinatorError::RoundNotProposable { round });
        }
        CoordinatorRPCBaseClient::transition(self.rpc(), self.execution_id, round)
            .await
            .map_err(|error| self.decode(error))
    }

    pub async fn get_execution_summary(&self) -> Result<ExecutionSummary, CoordinatorError> {
        CoordinatorRPCBaseClient::get_execution_summary(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }

    /// Reads the summary first and returns, without sending the association:
    /// `TopologyUnsupportedByBackend` when `n < S::min_parties(t)`; `SealedOutputsExceedBound`
    /// when a slot's `8 + output_count × S::serialized_share_len(t) + 16` exceeds
    /// `MAX_SEALED_OUTPUT_BYTES`. Stores the returned admission with the summary's nonce;
    /// `send_masked_inputs` and `obtain_outputs` take both from it.
    pub async fn associate_client(
        &mut self,
        request: AssociationRequest,
    ) -> Result<ClientAdmission, CoordinatorError> {
        let summary = self.get_execution_summary().await?;
        let (n, t) = (self.node_roster.n(), self.node_roster.t());
        let required = S::min_parties(t as usize) as u64;
        if n < required {
            return Err(CoordinatorError::TopologyUnsupportedByBackend { n, t, required });
        }
        let share_len = S::serialized_share_len(t as usize);
        for (position, slot) in summary.client_slots.slots().iter().enumerate() {
            if slot.output_count == 0 {
                continue;
            }
            let bytes = sealed_outputs_bytes(slot.output_count, share_len);
            if bytes > MAX_SEALED_OUTPUT_BYTES {
                return Err(CoordinatorError::SealedOutputsExceedBound {
                    client_index: ClientIndex(position as u32),
                    bytes,
                    max: MAX_SEALED_OUTPUT_BYTES,
                });
            }
        }
        let admission =
            CoordinatorRPCBaseClient::associate_client(self.rpc(), self.execution_id, request)
                .await
                .map_err(|error| self.decode(error))?;
        self.admission = Some((admission.clone(), summary.registration_nonce));
        Ok(admission)
    }

    pub fn admission(&self) -> Option<&ClientAdmission> {
        self.admission.as_ref().map(|(admission, _)| admission)
    }

    /// Reads the frozen admission set and the summary's nonce, and stores both;
    /// `send_output_shares` maps an identity to its slot through them.
    pub async fn get_client_admissions(&mut self) -> Result<ClientAdmissionSet, CoordinatorError> {
        let set = CoordinatorRPCBaseClient::get_client_admissions(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))?;
        let summary = self.get_execution_summary().await?;
        self.agreed = Some(AgreedAdmissions {
            registration_nonce: summary.registration_nonce,
            set: set.clone(),
        });
        Ok(set)
    }

    /// Every submission, ascending `first_index`, once their input counts sum to `n_inputs`.
    pub async fn wait_for_masked_input_submissions(
        &self,
        n_inputs: u64,
    ) -> Result<Vec<MaskedInputSubmission>, CoordinatorError> {
        if n_inputs == 0 {
            return Ok(Vec::new());
        }
        let mut sub = CoordinatorRPCBaseClient::sub_masked_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))?;
        let mut submissions = Vec::new();
        let mut received = 0u64;
        while received < n_inputs {
            match sub.next().await {
                Some(Ok(Event::MaskedInputEvent { submission })) => {
                    received += submission.masked_inputs.len() as u64;
                    submissions.push(submission);
                }
                Some(Ok(Event::ExecutionAborted { reason })) => {
                    return Err(CoordinatorError::ExecutionAborted {
                        execution_id: self.execution_id,
                        reason,
                    });
                }
                _ => {
                    return Err(CoordinatorError::JSONError(
                        "Subscription ended before every masked input was received".to_string(),
                    ));
                }
            }
        }
        submissions.sort_by_key(|submission| submission.first_index);
        Ok(submissions)
    }

    /// Unmasks `submissions` with this node's mask shares; `mask_shares[i]` is index `i`'s.
    pub fn unmask_submissions(
        submissions: &[MaskedInputSubmission],
        mask_shares: &[S],
    ) -> Result<Vec<(u64, ClientIdentity, S)>, CoordinatorError> {
        let mut unmasked = Vec::new();
        for submission in submissions {
            for (offset, masked_input) in submission.masked_inputs.iter().enumerate() {
                let index = submission.first_index + offset as u64;
                let mask_share = usize::try_from(index)
                    .ok()
                    .and_then(|position| mask_shares.get(position))
                    .ok_or(CoordinatorError::MaskReconstructionFailed { index })?;
                let masked_input = S::ValueType::deserialize_compressed(masked_input.as_slice())
                    .map_err(|_| CoordinatorError::DeserializationError)?;
                let input = S::compute_masked_input(masked_input, mask_share)
                    .map_err(|_| CoordinatorError::ShareError)?;
                unmasked.push((index, submission.client.clone(), input));
            }
        }
        Ok(unmasked)
    }

    pub async fn retire_execution(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::retire_execution(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }

    /// The nonce and admission set a node agreed on, stored or read now.
    async fn agreed_admissions(
        &self,
    ) -> Result<(RegistrationNonce, ClientAdmissionSet), CoordinatorError> {
        if let Some(agreed) = &self.agreed {
            return Ok((agreed.registration_nonce, agreed.set.clone()));
        }
        let set = CoordinatorRPCBaseClient::get_client_admissions(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))?;
        let summary = self.get_execution_summary().await?;
        Ok((summary.registration_nonce, set))
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
            .map_err(|error| self.decode(error))
    }
    async fn reserve_input_masks(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::reserve_input_masks(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }
    async fn collect_inputs(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::collect_inputs(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }
    async fn start_mpc(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_mpc(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }
    async fn send_output(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::send_output(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }
    async fn finalize(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::finalize(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))
    }

    async fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> Result<HashMap<ClientIdentity, Vec<u64>>, CoordinatorError> {
        let mut map: HashMap<ClientIdentity, Vec<u64>> = HashMap::new();
        if n_inputs == 0 {
            return Ok(map);
        }
        let mut sub = CoordinatorRPCBaseClient::sub_reserved_indices(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))?;

        // Each event carries one slot's whole range, so keep receiving events until enough
        // indices have actually been seen.
        let mut received = 0u64;
        while received < n_inputs {
            match sub.next().await {
                Some(Ok(Event::ReservedInputEvent {
                    client,
                    reserved_indices,
                })) => {
                    received += reserved_indices.len() as u64;
                    map.entry(client).or_default().extend(reserved_indices);
                }
                Some(Ok(Event::ExecutionAborted { reason })) => {
                    return Err(CoordinatorError::ExecutionAborted {
                        execution_id: self.execution_id,
                        reason,
                    });
                }
                _ => {
                    return Err(CoordinatorError::JSONError(
                        "Subscription ended before event could be received".to_string(),
                    ));
                }
            }
        }

        Ok(map)
    }

    /// Verifies each submission's signature against the identity and slot the admission set
    /// names for it, then unmasks. Nodes that must agree on the submissions before unmasking use
    /// `wait_for_masked_input_submissions` and `unmask_submissions` instead.
    async fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> Result<HashMap<ClientIdentity, Vec<S>>, CoordinatorError> {
        let submissions = self.wait_for_masked_input_submissions(n_inputs).await?;
        let (registration_nonce, set) = self.agreed_admissions().await?;
        for submission in &submissions {
            let record = set
                .record_of(&submission.client)
                .ok_or(CoordinatorError::Submission(
                    SubmissionError::BadMaskedInputSignature,
                ))?;
            let signing_bytes = masked_inputs_signing_bytes(
                self.execution_id,
                registration_nonce,
                record.client_index,
                submission.first_index,
                &submission.masked_inputs,
            );
            verify_identity_signature(&submission.client, &signing_bytes, &submission.signature)
                .map_err(|_| {
                    CoordinatorError::Submission(SubmissionError::BadMaskedInputSignature)
                })?;
        }
        let mut map: HashMap<ClientIdentity, Vec<S>> = HashMap::new();
        for (_, client, input) in Self::unmask_submissions(&submissions, &mask_shares)? {
            map.entry(client).or_default().push(input);
        }
        Ok(map)
    }

    async fn wait_for_round(&self, round: Round) -> Result<(), CoordinatorError> {
        if round == Round::Aborted {
            return Err(CoordinatorError::RoundNotProposable { round });
        }
        let mut sub = CoordinatorRPCBaseClient::sub_round(self.rpc(), self.execution_id, round)
            .await
            .map_err(|error| self.decode(error))?;

        match sub.next().await {
            Some(Ok(Event::ExecutionAborted { reason })) => {
                Err(CoordinatorError::ExecutionAborted {
                    execution_id: self.execution_id,
                    reason,
                })
            }
            Some(Ok(_)) => Ok(()),
            _ => Err(CoordinatorError::JSONError(
                "Subscription ended before event could be received".to_string(),
            )),
        }
    }

    async fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> Result<(), CoordinatorError> {
        self.send_masked_inputs(&[(i, masked_input)]).await
    }

    /// Submits the admitted range in one call, signed with this client's certificate key.
    async fn send_masked_inputs(
        &self,
        inputs: &[(u64, S::ValueType)],
    ) -> Result<(), CoordinatorError> {
        let Some((admission, registration_nonce)) = &self.admission else {
            return Err(CoordinatorError::NotAssociated);
        };
        let indices = inputs.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        let range = admission
            .input_range
            .filter(|range| range.is_exactly(&indices))
            .ok_or(CoordinatorError::Submission(
                SubmissionError::SubmissionOutsideAdmission {
                    admitted: admission.input_range,
                },
            ))?;
        let mut masked_inputs = Vec::with_capacity(inputs.len());
        for (_, masked_input) in inputs {
            let mut masked_input_bytes = Vec::new();
            masked_input
                .serialize_compressed(&mut masked_input_bytes)
                .map_err(|_| CoordinatorError::SerializationError)?;
            masked_inputs.push(masked_input_bytes);
        }
        let signing_bytes = masked_inputs_signing_bytes(
            self.execution_id,
            *registration_nonce,
            admission.client_index,
            range.start,
            &masked_inputs,
        );
        let signature =
            sign_with_pkcs8(self.own_spki.key_algorithm(), &self.key_der, &signing_bytes)?;

        CoordinatorRPCBaseClient::submit_masked_inputs(
            self.rpc(),
            self.execution_id,
            range.start,
            masked_inputs,
            signature,
        )
        .await
        .map_err(|error| self.decode(error))
    }

    async fn reserve_mask_index(&mut self, i: u64) -> Result<(), CoordinatorError> {
        self.reserve_mask_indices(&[i]).await
    }

    async fn reserve_mask_indices(&mut self, indices: &[u64]) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::reserve_mask_indices(
            self.rpc(),
            self.execution_id,
            indices.to_vec(),
        )
        .await
        .map_err(|error| self.decode(error))
    }

    /// Takes one sealed item per node, checks its node's signature against the roster, and
    /// reconstructs every output by position as items arrive.
    async fn obtain_outputs(&self) -> Result<Vec<S::ValueType>, CoordinatorError> {
        let Some((admission, registration_nonce)) = &self.admission else {
            return Err(CoordinatorError::NotAssociated);
        };
        let OutputRights::Receive { output_count } = admission.output_rights else {
            return Err(CoordinatorError::Admission(
                AdmissionError::NoOutputRights {
                    execution_id: self.execution_id,
                },
            ));
        };
        let output_count =
            usize::try_from(output_count.get()).map_err(|_| CoordinatorError::U64ToUsizeError)?;
        let n =
            usize::try_from(self.node_roster.n()).map_err(|_| CoordinatorError::U64ToUsizeError)?;
        let t =
            usize::try_from(self.node_roster.t()).map_err(|_| CoordinatorError::U64ToUsizeError)?;

        let mut sub = CoordinatorRPCBaseClient::obtain_output_shares(self.rpc(), self.execution_id)
            .await
            .map_err(|error| self.decode(error))?;

        let client_sk = {
            let parsed_secret_key = SecretKey::from_pkcs8_der(&self.key_der)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            <KemImpl as Kem>::PrivateKey::from_bytes(&parsed_secret_key.to_bytes())
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };
        let enc_info = execution_enc_info(self.execution_id);
        let node_identities = self.node_roster.node_identities();

        let mut seen_positions = HashSet::new();
        let mut shares_by_output: Vec<Vec<PositionedShare<S>>> =
            (0..output_count).map(|_| Vec::new()).collect();
        let mut outputs: Vec<Option<S::ValueType>> = (0..output_count).map(|_| None).collect();

        while let Some(item) = sub.next().await {
            let Ok(item) = item else {
                continue;
            };
            let position = item.node_position as usize;
            if position >= n || !seen_positions.insert(position) {
                continue;
            }
            let signing_bytes = sealed_output_signing_bytes(
                self.execution_id,
                *registration_nonce,
                admission.client_index,
                item.node_position,
                &item.sealed.encapsulated_key,
                &item.sealed.ciphertext,
            );
            if verify_identity_signature(
                &node_identities[position],
                &signing_bytes,
                &item.sealed.signature,
            )
            .is_err()
            {
                // Not this node's item: the position may still be answered by the real one.
                seen_positions.remove(&position);
                continue;
            }
            let Ok(encapped_key) =
                <KemImpl as Kem>::EncappedKey::from_bytes(&item.sealed.encapsulated_key)
            else {
                continue;
            };
            let Ok(plaintext) = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                &OpModeR::Base,
                &client_sk,
                &encapped_key,
                &enc_info,
                &item.sealed.ciphertext,
                b"",
            ) else {
                continue;
            };
            let Ok(shares) =
                <Vec<S> as CanonicalDeserialize>::deserialize_compressed(plaintext.as_slice())
            else {
                continue;
            };
            if shares.len() != output_count {
                continue;
            }
            for (output, share) in shares.into_iter().enumerate() {
                if outputs[output].is_some() {
                    continue;
                }
                shares_by_output[output].push(PositionedShare { position, share });
                if let Reconstruction::Secret(secret) =
                    S::reconstruct(&shares_by_output[output], n, t)
                {
                    outputs[output] = Some(secret);
                }
            }
            if outputs.iter().all(Option::is_some) {
                return Ok(outputs.into_iter().flatten().collect());
            }
        }

        // The stream ended first. An execution that was aborted says so, with its reason, in
        // any execution-scoped refusal other than its summary's.
        let summary = self.get_execution_summary().await?;
        if summary.round == Round::Aborted {
            if let Err(error) =
                CoordinatorRPCBaseClient::obtain_output_shares(self.rpc(), self.execution_id).await
            {
                return Err(self.decode(error));
            }
        }
        let output = outputs.iter().position(Option::is_none).unwrap_or_default() as u64;
        Err(CoordinatorError::OutputReconstructionFailed { output })
    }

    /// Seals `output_shares` to `key`, signs with this node's roster position and the agreed
    /// nonce, and sends by the client's slot.
    async fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> Result<(), CoordinatorError> {
        let (registration_nonce, set) = self.agreed_admissions().await?;
        let Some(record) = set.record_of(&client_id) else {
            return Err(CoordinatorError::Admission(AdmissionError::NotAdmitted {
                execution_id: self.execution_id,
            }));
        };
        let Some(position) = self.node_roster.position_of(&self.own_spki) else {
            return Err(CoordinatorError::Refused {
                refusal: RpcRefusal::NotParty,
                message: "this identity is not a node of the served roster".to_string(),
            });
        };

        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key)
            .map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let mut output_shares_bytes = Vec::new();
        output_shares
            .serialize_compressed(&mut output_shares_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;

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
        let bytes = ciphertext.len() as u64;
        if bytes > MAX_SEALED_OUTPUT_BYTES {
            return Err(CoordinatorError::SealedOutputsExceedBound {
                client_index: record.client_index,
                bytes,
                max: MAX_SEALED_OUTPUT_BYTES,
            });
        }
        let encapsulated_key = encapsulated_key.to_bytes().to_vec();
        let node_position = position as u32;
        let signing_bytes = sealed_output_signing_bytes(
            self.execution_id,
            registration_nonce,
            record.client_index,
            node_position,
            &encapsulated_key,
            &ciphertext,
        );
        let signature =
            sign_with_pkcs8(self.own_spki.key_algorithm(), &self.key_der, &signing_bytes)?;

        CoordinatorRPCBaseClient::send_output_shares(
            self.rpc(),
            self.execution_id,
            record.client_index,
            SealedOutput {
                encapsulated_key,
                ciphertext,
                signature,
            },
        )
        .await
        .map_err(|error| self.decode(error))
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use std::num::NonZeroU64;
    use stoffel_mpc_coordinator_shared::{
        ClientSlotSpec, InvitationIssuer, MAX_CLIENT_SLOTS, MAX_INPUTS, MAX_INPUTS_PER_SLOT,
        MAX_OUTPUTS_PER_SLOT,
    };

    const TEN_MIB: usize = 10 * 1024 * 1024;

    /// The size of `item` inside jsonrpsee's notification envelope, with a 20-digit
    /// subscription id.
    fn notification_len<T: Serialize>(method: &str, item: &T) -> usize {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": { "subscription": "18446744073709551615", "result": item },
        }))
        .unwrap()
        .len()
    }

    #[test]
    fn borrowed_events_serialize_exactly_as_owned_events() {
        let submission = MaskedInputSubmission {
            client: vec![4; 65],
            first_index: 3,
            masked_inputs: vec![vec![1, 2], vec![3]],
            signature: vec![9; 72],
        };
        assert_eq!(
            EventRef::MaskedInputEvent {
                submission: &submission
            }
            .to_json()
            .get(),
            event_json(&Event::MaskedInputEvent {
                submission: submission.clone()
            })
            .get()
        );
        let range = InputRange {
            start: 5,
            count: NonZeroU64::new(3).unwrap(),
        };
        assert_eq!(
            reservation_event_json(&submission.client, range).get(),
            event_json(&Event::ReservedInputEvent {
                client: submission.client.clone(),
                reserved_indices: vec![5, 6, 7],
            })
            .get()
        );
        let decoded: Event =
            serde_json::from_str(reservation_event_json(&submission.client, range).get()).unwrap();
        assert!(matches!(decoded, Event::ReservedInputEvent { .. }));
    }

    /// The off-chain half of `registration_bounds_keep_every_response_under_the_wire_limit`
    /// (coord-shared's `admission.rs` holds the slot-table and admission-set half): the summary,
    /// a `MaskedInputEvent` at the per-slot bound and a `SealedOutputShares` at the ciphertext
    /// bound, every number at its largest and every byte `0xff`, fit C.1's measured sizes.
    #[test]
    fn registration_bounds_keep_every_response_under_the_wire_limit() {
        let identity = vec![0xff; 65];
        let signature = vec![0xff; 72];
        let issuer = InvitationIssuer::new(
            SpkiDer::from_certificate_der(
                rcgen::generate_simple_self_signed(vec!["issuer".to_string()])
                    .unwrap()
                    .cert
                    .der(),
            )
            .unwrap(),
        );
        let summary = ExecutionSummary {
            execution_id: ExecutionId::from_bytes([0xff; 32]),
            registration_nonce: RegistrationNonce::from_bytes([0xff; 32]),
            program_hash: [0xff; 32],
            client_slots: ClientSlotTable::new(vec![
                ClientSlotSpec {
                    input_count: MAX_INPUTS_PER_SLOT,
                    output_count: MAX_OUTPUTS_PER_SLOT,
                };
                MAX_CLIENT_SLOTS as usize
            ]),
            admission: AdmissionPolicyKind::Invitation { issuer },
            deadlines: Some(ExecutionDeadlines {
                association: UnixSeconds(u64::MAX),
                input: UnixSeconds(u64::MAX),
            }),
            round: Round::OutputDistribution,
        };
        let summary_len = serde_json::to_vec(&summary).unwrap().len();
        assert!(summary_len < TEN_MIB, "summary is {summary_len} bytes");

        let event = Event::MaskedInputEvent {
            submission: MaskedInputSubmission {
                client: identity.clone(),
                first_index: MAX_INPUTS - MAX_INPUTS_PER_SLOT,
                masked_inputs: vec![
                    vec![0xff; MAX_MASKED_INPUT_BYTES as usize];
                    MAX_INPUTS_PER_SLOT as usize
                ],
                signature: signature.clone(),
            },
        };
        let event_len = notification_len("sub_masked_inputs", &event);
        assert!(
            event_len <= 8_454_899,
            "MaskedInputEvent is {event_len} bytes"
        );

        let reservation = Event::ReservedInputEvent {
            client: identity,
            reserved_indices: (MAX_INPUTS - MAX_INPUTS_PER_SLOT..MAX_INPUTS).collect(),
        };
        let reservation_len = notification_len("sub_reserved_indices", &reservation);
        assert!(
            reservation_len <= 262_568,
            "ReservedInputEvent is {reservation_len} bytes"
        );

        let item = SealedOutputShares {
            node_position: u32::MAX,
            sealed: SealedOutput {
                encapsulated_key: vec![0xff; 65],
                ciphertext: vec![0xff; MAX_SEALED_OUTPUT_BYTES as usize],
                signature,
            },
        };
        let item_len = notification_len("sub_obtain_output_shares", &item);
        assert!(
            item_len <= 8_389_357,
            "SealedOutputShares is {item_len} bytes"
        );
    }
}

#[cfg(test)]
mod read_rate_limiter_tests {
    use super::*;

    #[test]
    fn buckets_refill_at_the_configured_rate_and_forget_the_least_recently_used() {
        let start = Instant::now();
        let mut limiter = ReadRateLimiter::new(2);
        let first = vec![1u8; 65];
        let second = vec![2u8; 65];
        let third = vec![3u8; 65];

        for _ in 0..SUMMARY_READ_BURST {
            assert!(limiter.try_take(&first, start));
        }
        assert!(!limiter.try_take(&first, start), "the burst is spent");
        let one_token = Duration::from_secs(60) / SUMMARY_READS_PER_MINUTE;
        assert!(
            limiter.try_take(&first, start + one_token),
            "one token is earned per 60 / SUMMARY_READS_PER_MINUTE seconds"
        );
        assert!(!limiter.try_take(&first, start + one_token));

        // `second` is used after `first`; a third identity evicts `first`, the least recent.
        assert!(limiter.try_take(&second, start + one_token));
        assert!(limiter.try_take(&third, start + one_token));
        assert_eq!(limiter.buckets.len(), 2);
        assert!(!limiter.buckets.contains_key(&first));
        assert!(limiter.buckets.contains_key(&second));
        assert_eq!(limiter.by_use.len(), 2);
    }
}
