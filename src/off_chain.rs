use crate::{
    round_before,
    rpc::{ClientInfo, ValueWrapper},
    Coordinator, CoordinatorError, Round, ShareBound,
};
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
    server::ServerHandle,
    PendingSubscriptionSink, SubscriptionSink,
};
use p256::{pkcs8::DecodePrivateKey, SecretKey};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskReservation {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "ValueWrapper<T>: Serialize",
    deserialize = "ValueWrapper<T>: Deserialize<'de>"
))]
pub struct AssignedMaskedInputEvent<T: CanonicalSerialize + CanonicalDeserialize + Clone> {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub masked_input: ValueWrapper<T>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSlotAssignment {
    pub client: ClientIdentity,
    pub label: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InputAssignment {
    pub input_slots: Vec<InputSlotAssignment>,
}

/// The node-side RPC interface.
pub mod node_rpc {
    use super::{AssignedMaskReservation, AssignedMaskShare, ClientIdentity};
    use crate::{rpc::ClientInfo, CoordinatorError, NodeRPCError, ShareBound};
    use ark_ff::FftField;
    use async_trait::async_trait;
    use jsonrpsee::{
        async_client::Client,
        core::{to_json_raw_value, SubscriptionResult},
        proc_macros::rpc,
        server::RpcModule,
        server::ServerHandle,
        types::{error::ErrorCode, ErrorObjectOwned},
        PendingSubscriptionSink, SubscriptionSink,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, VecDeque};
    use std::marker::PhantomData;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;
    use tokio::task::JoinSet;

    /// Errors returned by the node-side RPC interface.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum OffChainNodeRPCServerError {
        SerializationError = 1,
    }

    /// The off-chain node-side JSON-RPC interface.
    #[rpc(server, client)]
    pub trait OffChainNodeRPC {
        /// Called by an MPC client to receive a mask share from the node for that client's input.
        /// The node knows the reserved index and whether or not one has been reserved at all from
        /// the coordinator. In contrary to the on-chain coordinator, no additional information for
        /// authentication is needed, since the client's identity is the same as the one used to
        /// establish the TLS connection to access this very interface.
        #[subscription(name = "sub_receive_mask_share", unsubscribe = "unsub_receive_mask_share", item = Vec<u8>)]
        async fn receive_mask_share(&self) -> SubscriptionResult;

        #[subscription(name = "sub_receive_assigned_mask_shares", unsubscribe = "unsub_receive_assigned_mask_shares", item = Vec<AssignedMaskShare>)]
        async fn receive_assigned_mask_shares(&self) -> SubscriptionResult;
    }

    pub struct NodeRPCServer<F: FftField, S: ShareBound<F>> {
        rpc_server: Arc<Mutex<NodeRPCServerInternal<F, S>>>,
        addr: String,
        _port: u16,
        _server_handle: JoinHandle<()>,
    }

    /// An object used by an MPC client to connect to the RPC interfaces of many nodes.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        /// The per-node client handles for each connection to a node.
        node_rpcs: Vec<Client>,
        /// Total number of MPC nodes in the network (used for share reconstruction).
        n: usize,
        /// The threshold value.
        t: usize,
        _phantom: PhantomData<(F, S)>,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        pub async fn start_rpc_client_from_cert(
            n: usize,
            t: usize,
            addrs: Vec<(String, u16)>,
            client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        ) -> Result<Self, CoordinatorError> {
            Self::start_rpc_client(
                n,
                t,
                addrs,
                client_cert.cert.der().to_vec(),
                client_cert.signing_key.serialize_der(),
            )
            .await
        }

        /// Connects to a list of MPC nodes via Websockets over TLS.
        pub async fn start_rpc_client(
            n: usize,
            t: usize,
            addrs: Vec<(String, u16)>,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let node_rpcs: Vec<Client> =
                futures_util::future::join_all(addrs.iter().map(|(addr, port)| {
                    crate::self_signed_certs::setup_client(
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
                _phantom: PhantomData,
            })
        }

        /// Returns a mask whose index has been previously reserved by the client by receiving the
        /// individual shares from nodes and reconstructing the mask from them.
        pub async fn receive_mask(&self) -> Result<S::ValueType, CoordinatorError> {
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc
                    .receive_mask_share()
                    .await
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                share_futures.spawn(async move { sub.next().await });
            }

            let mut mask_shares: Vec<S> = Vec::new();

            while let Some(share_bytes_result) = share_futures.join_next().await {
                let share_bytes_option = share_bytes_result
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                let share_bytes_result = match share_bytes_option {
                    Some(res) => res,
                    None => {
                        continue;
                    }
                };
                let share_bytes = share_bytes_result
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                let share: S = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                    share_bytes.as_slice(),
                )
                .map_err(|_| CoordinatorError::DeserializationError)?;

                mask_shares.push(share);

                if mask_shares.len() >= S::min_shares(self.t) {
                    if let Ok((_, mask)) =
                        S::recover_secret(&mask_shares, self.n, self.t)
                    {
                        return Ok(mask);
                    }
                }
            }

            Err(CoordinatorError::MaskReconstructionFailed(
                mask_shares.len(),
            ))
        }

        pub async fn receive_assigned_masks(
            &self,
        ) -> Result<Vec<(AssignedMaskShare, S::ValueType)>, CoordinatorError> {
            let mut share_futures = JoinSet::new();

            for rpc in self.node_rpcs.iter() {
                let mut sub = rpc
                    .receive_assigned_mask_shares()
                    .await
                    .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                share_futures.spawn(async move { sub.next().await });
            }

            let mut share_sets: HashMap<u64, (AssignedMaskShare, Vec<S>)> = HashMap::new();
            let mut expected_indices: Option<Vec<u64>> = None;

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
                if let Some(expected_indices) = &expected_indices {
                    if *expected_indices != indices {
                        return Err(CoordinatorError::JSONError(
                            "Assigned mask share indices differ across MPC nodes".to_string(),
                        ));
                    }
                } else {
                    expected_indices = Some(indices);
                }

                for assigned_share in assigned_shares {
                    let share: S = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                        assigned_share.share_bytes.as_slice(),
                    )
                    .map_err(|_| CoordinatorError::DeserializationError)?;

                    let entry = share_sets
                        .entry(assigned_share.reserved_index)
                        .or_insert_with(|| (assigned_share.clone(), Vec::new()));
                    entry.1.push(share);
                }

                if let Some(expected_indices) = &expected_indices {
                    if expected_indices.iter().all(|reserved_index| {
                        share_sets
                            .get(reserved_index)
                            .is_some_and(|(_, shares)| shares.len() >= S::min_shares(self.t))
                    }) {
                        break;
                    }
                }
            }

            let mut outputs = Vec::with_capacity(share_sets.len());
            for reserved_index in expected_indices.unwrap_or_default() {
                let Some((metadata, mask_shares)) = share_sets.remove(&reserved_index) else {
                    return Err(CoordinatorError::MaskReconstructionFailed(0));
                };
                if mask_shares.len() < S::min_shares(self.t) {
                    return Err(CoordinatorError::MaskReconstructionFailed(
                        mask_shares.len(),
                    ));
                }
                let (_, mask) = S::recover_secret(&mask_shares, self.node_rpcs.len(), self.t)
                    .map_err(|_| CoordinatorError::MaskReconstructionFailed(mask_shares.len()))?;
                outputs.push((metadata, mask));
            }
            outputs.sort_by_key(|(metadata, _)| metadata.reserved_index);

            Ok(outputs)
        }
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCServer<F, S> {
        pub async fn start_from_cert(
            addr: &str,
            port: u16,
            cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        ) -> Result<Self, CoordinatorError> {
            Self::start(
                addr,
                port,
                cert.cert.der().to_vec(),
                cert.signing_key.serialize_der(),
            )
            .await
        }

        pub async fn start(
            addr: &str,
            port: u16,
            cert_der: Vec<u8>,
            key_der: Vec<u8>,
        ) -> Result<Self, CoordinatorError> {
            let rpc_server_data = Arc::new(Mutex::new(NodeRPCServerInternal::<F, S>::new()));
            let server_handle = crate::rpc::start_coord::<NodeRPCServerImpl<F, S>>(
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
                _port: port,
                _server_handle: server_handle,
            })
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone()
        }

        // called when the client has reserved indices at the coordinator
        pub async fn add_reserved_index(
            &mut self,
            id: ClientIdentity,
            i: u64,
        ) -> Result<(), NodeRPCError> {
            self.add_assigned_reserved_index(AssignedMaskReservation {
                client: id,
                reserved_index: i,
                input_ordinal: i,
            })
            .await
        }

        pub async fn add_assigned_reserved_index(
            &mut self,
            reservation: AssignedMaskReservation,
        ) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;
            let id = reservation.client.clone();
            let i = reservation.reserved_index;

            if d.index_to_client.contains_key(&i) {
                return Err(NodeRPCError::IndexAlreadyAdded);
            }

            d.index_to_client.insert(i, id.clone());
            d.assigned_reservations.insert(i, reservation.clone());
            d.client_to_index
                .entry(id.clone())
                .or_default()
                .push_back(i);

            // if mask share is there and share has been requested, send it
            if let Some(share) = d.mask_shares.get(&i).cloned() {
                if let Some(sink) = d.sinks.remove(&id) {
                    if let Some(indices) = d.client_to_index.get_mut(&id) {
                        if let Some(position) = indices.iter().position(|index| *index == i) {
                            indices.remove(position);
                        }
                        if indices.is_empty() {
                            d.client_to_index.remove(&id);
                        }
                    }
                    let mut share_bytes = Vec::new();
                    share
                        .serialize_compressed(&mut share_bytes)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    let json = to_json_raw_value(&share_bytes)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                }
                if let Some(sink) = d.assigned_sinks.remove(&id) {
                    if let Some(assigned_shares) = d.assigned_mask_shares_for_client(&id)? {
                        d.client_to_index.remove(&id);
                        let json = to_json_raw_value(&assigned_shares)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    } else {
                        d.assigned_sinks.insert(id.clone(), sink);
                    }
                }
            }

            Ok(())
        }

        // called when preprocessing has generated the mask shares
        pub async fn add_mask_share(&mut self, i: u64, share: &S) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;

            assert!(!d.mask_shares.contains_key(&i));
            d.mask_shares.insert(i, share.clone());

            // if reserved index has been added and client has requested the share already, send the share now
            if let Some(id) = d.index_to_client.get(&i).cloned() {
                if let Some(sink) = d.sinks.remove(&id) {
                    if let Some(indices) = d.client_to_index.get_mut(&id) {
                        if let Some(position) = indices.iter().position(|index| *index == i) {
                            indices.remove(position);
                        }
                        if indices.is_empty() {
                            d.client_to_index.remove(&id);
                        }
                    }
                    let mut share_bytes = Vec::new();
                    share
                        .serialize_compressed(&mut share_bytes)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    let json = to_json_raw_value(&share_bytes).expect("failed convert to JSON");
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                }
                if let Some(sink) = d.assigned_sinks.remove(&id) {
                    if let Some(assigned_shares) = d.assigned_mask_shares_for_client(&id)? {
                        d.client_to_index.remove(&id);
                        let json = to_json_raw_value(&assigned_shares)
                            .map_err(|_| NodeRPCError::SerializationError)?;
                        sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
                    } else {
                        d.assigned_sinks.insert(id.clone(), sink);
                    }
                }
            }

            Ok(())
        }
    }

    /// The server-side information for one client connection to the node-side RPC interface.
    pub struct NodeRPCServerImpl<F: FftField, S: ShareBound<F> + Send> {
        /// A reference to the server's shared state.
        d: Arc<Mutex<NodeRPCServerInternal<F, S>>>,
        /// The connected client's identity, which is the client's public key in DER format.
        id: Vec<u8>,
    }

    impl<F: FftField, S: ShareBound<F>> crate::rpc::RPCServerConnection for NodeRPCServerImpl<F, S> {
        type Internal = NodeRPCServerInternal<F, S>;

        fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self {
            Self { d: internal, id }
        }

        fn into_rpc(self) -> RpcModule<Self>
        where
            Self: Sized,
        {
            crate::off_chain::node_rpc::OffChainNodeRPCServer::into_rpc(self)
        }
    }

    /// The internal state of the node-side RPC server.
    pub struct NodeRPCServerInternal<F: FftField, S: ShareBound<F>> {
        /// Maps reserved indices to the clients that have reserved them.
        index_to_client: HashMap<u64, ClientIdentity>,
        assigned_reservations: HashMap<u64, AssignedMaskReservation>,
        /// The inverse mapping of `index_to_client`.
        client_to_index: HashMap<ClientIdentity, VecDeque<u64>>,
        /// Client sinks to send mask shares over Websockets.
        sinks: HashMap<ClientIdentity, SubscriptionSink>,
        assigned_sinks: HashMap<ClientIdentity, SubscriptionSink>,
        /// TODO
        mask_shares: HashMap<u64, S>,
        /// Maps client identities the per-client information stored by the server.
        clients: HashMap<Vec<u8>, ClientInfo>,
        _phantom: PhantomData<F>,
    }

    impl<F: FftField, S: ShareBound<F>> crate::rpc::RPCServerShared for NodeRPCServerInternal<F, S> {
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

    impl<F: FftField, S: ShareBound<F>> NodeRPCServerInternal<F, S> {
        pub fn new() -> Self {
            Self {
                index_to_client: HashMap::new(),
                assigned_reservations: HashMap::new(),
                client_to_index: HashMap::new(),
                sinks: HashMap::new(),
                assigned_sinks: HashMap::new(),
                mask_shares: HashMap::new(),
                clients: HashMap::new(),
                _phantom: PhantomData,
            }
        }
    }

    impl<F: FftField, S: ShareBound<F>> Default for NodeRPCServerInternal<F, S> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCServerInternal<F, S> {
        fn assigned_mask_share(
            &self,
            reserved_index: u64,
            share: &S,
        ) -> Result<AssignedMaskShare, NodeRPCError> {
            self.assigned_reservations
                .get(&reserved_index)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            let mut share_bytes = Vec::new();
            share
                .serialize_compressed(&mut share_bytes)
                .map_err(|_| NodeRPCError::SerializationError)?;
            Ok(AssignedMaskShare {
                reserved_index,
                share_bytes,
            })
        }

        fn assigned_mask_shares_for_client(
            &self,
            id: &ClientIdentity,
        ) -> Result<Option<Vec<AssignedMaskShare>>, NodeRPCError> {
            let Some(indices) = self.client_to_index.get(id) else {
                return Ok(Some(Vec::new()));
            };

            let mut assigned_shares = Vec::with_capacity(indices.len());
            for i in indices {
                let Some(share) = self.mask_shares.get(i) else {
                    return Ok(None);
                };
                assigned_shares.push(self.assigned_mask_share(*i, share)?);
            }
            assigned_shares.sort_by_key(|assigned_share| assigned_share.reserved_index);

            Ok(Some(assigned_shares))
        }
    }

    #[async_trait]
    impl<F: FftField, S: ShareBound<F>> OffChainNodeRPCServer for NodeRPCServerImpl<F, S> {
        async fn receive_mask_share(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

            // Each client may have multiple inputs, but only one mask-share request can be
            // outstanding per node connection.
            if d.sinks.contains_key(&self.id) {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::InvalidParams.code(),
                        format!("Client {:?} already requested mask share", self.id),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            }

            let next_index = d
                .client_to_index
                .get(&self.id)
                .and_then(|indices| indices.front().copied());
            let mut remove_client_indices = d
                .client_to_index
                .get(&self.id)
                .is_some_and(|indices| indices.is_empty());
            let share = if let Some(i) = next_index {
                if let Some(share) = d.mask_shares.get(&i).cloned() {
                    if let Some(indices) = d.client_to_index.get_mut(&self.id) {
                        indices.pop_front();
                        remove_client_indices = indices.is_empty();
                    }
                    Some(share)
                } else {
                    None
                }
            } else {
                None
            };
            if remove_client_indices {
                d.client_to_index.remove(&self.id);
            }

            if let Some(share) = share {
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

                return Ok(());
            }

            let sink = pending.accept().await?;
            d.sinks.insert(self.id.clone(), sink);

            Ok(())
        }

        async fn receive_assigned_mask_shares(
            &self,
            pending: PendingSubscriptionSink,
        ) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

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

            let assigned_shares = match d.assigned_mask_shares_for_client(&self.id) {
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
                d.client_to_index.remove(&self.id);
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
            d.assigned_sinks.insert(self.id.clone(), sink);

            Ok(())
        }
    }
}

/// Events that mimic those used for the on-chain coordinator.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "ValueWrapper<T>: Serialize",
    deserialize = "ValueWrapper<T>: Deserialize<'de>"
))]
pub enum Event<T: CanonicalSerialize + CanonicalDeserialize + Clone> {
    CoordinatorInitialized {
        creation_block: u64,
        designated_party: ClientIdentity,
    },
    MaskedInputEvent {
        client: ClientIdentity,
        masked_input: ValueWrapper<T>,
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
    async fn start_preprocessing(&self) -> RpcResult<()>;
    #[method(name = "reserve_input_masks")]
    async fn reserve_input_masks(&self) -> RpcResult<()>;
    #[method(name = "collect_inputs")]
    async fn collect_inputs(&self) -> RpcResult<()>;
    #[method(name = "start_mpc")]
    async fn start_mpc(&self) -> RpcResult<()>;
    #[method(name = "send_output")]
    async fn send_output(&self) -> RpcResult<()>;
    #[method(name = "finalize")]
    async fn finalize(&self) -> RpcResult<()>;
}

// RPC interface already implemented by this library.
#[rpc(server, client,
    server_bounds(F: FftField, S: ShareBound<F>),
    client_bounds(F: FftField, S: ShareBound<F>)
)]
pub trait CoordinatorRPCBase<F: FftField, S: ShareBound<F>> {
    /// Wait for round `round` to be started.
    #[subscription(name = "sub_round", unsubscribe = "unsub_round", item = Event<S::ValueType>)]
    async fn sub_round(&self, round: Round) -> SubscriptionResult;

    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = Event<S::ValueType>)]
    async fn sub_reserved_indices(&self) -> SubscriptionResult;

    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = Event<S::ValueType>)]
    async fn sub_masked_inputs(&self) -> SubscriptionResult;

    #[subscription(name = "sub_assigned_reserved_indices", unsubscribe = "unsub_assigned_reserved_indices", item = AssignedMaskReservation)]
    async fn sub_assigned_reserved_indices(&self) -> SubscriptionResult;

    #[subscription(name = "sub_assigned_masked_inputs", unsubscribe = "unsub_assigned_masked_inputs", item = AssignedMaskedInputEvent<S::ValueType>)]
    async fn sub_assigned_masked_inputs(&self) -> SubscriptionResult;

    /// Returns the number of available input masks left. TODO: this involves a race condition
    /// since querying this and reserving an index is not atomic. remove it?
    #[method(name = "available_input_masks")]
    async fn available_input_masks(&self) -> RpcResult<u64>;

    /// MPC clients can request index `i`.
    #[method(name = "reserve_mask_index")]
    async fn reserve_mask_index(&self, i: u64) -> RpcResult<()>;

    /// The designated party can reset the coordinator with this method.
    #[method(name = "reset")]
    async fn reset(&self) -> RpcResult<()>;

    /// An MPC client uses this to submit a masked input `masked_input`, for which it has
    /// previously reserved the index `reserved_index`.
    #[method(name = "submit_masked_input")]
    async fn submit_masked_input(
        &self,
        masked_input: ValueWrapper<S::ValueType>,
        reserved_index: u64,
    ) -> RpcResult<()>;

    /// The designated party uses this to transition to the new round `next_round`.
    #[method(name = "transition")]
    async fn transition(&self, next_round: Round) -> RpcResult<()>;

    /// MPC nodes use this to send encrypted output shares `enc_shares` for a client with identity
    /// `client_id`.
    #[method(name = "send_output_shares")]
    async fn send_output_shares(
        &self,
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()>;

    /// MPC clients use this to receive their output shares from the coordinator, so they can
    /// reconstruct their private output.
    #[subscription(name = "sub_obtain_output_shares", unsubscribe = "unsub_obtain_output_shares", item = Vec<(Vec<u8>, Vec<u8>)>)]
    async fn obtain_output_shares(&self) -> SubscriptionResult;
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
}

/// The basic server-side information for one client connection to the coordinator RPC interface.
/// Can be extended by the developer.
#[derive(Clone)]
pub struct CoordinatorRPCServerConnectionBase<F: FftField, S: ShareBound<F>> {
    /// A reference to the server's shared state.
    d: Arc<Mutex<CoordinatorRPCServerSharedBase<S::ValueType>>>,
    /// The connected client's identity, which is the client's public key in DER format.
    id: ClientIdentity,
}

/// The basic internal state of the coordinator RPC server.
/// Can be extended by the developer.
pub struct CoordinatorRPCServerSharedBase<T: CanonicalSerialize + CanonicalDeserialize + Clone> {
    // Contains the sinks of clients, which subscribed to the transition to the given round.
    sinks: HashMap<Round, Vec<SubscriptionSink>>,
    trans_events: HashMap<Round, Vec<Event<T>>>,
    reserved_index_events: Vec<Event<T>>,
    reserved_index_sinks: Vec<SubscriptionSink>,
    assigned_reserved_index_events: Vec<AssignedMaskReservation>,
    assigned_reserved_index_sinks: Vec<SubscriptionSink>,
    masked_input_events: Vec<Event<T>>,
    masked_input_sinks: Vec<SubscriptionSink>,
    assigned_masked_input_events: Vec<AssignedMaskedInputEvent<T>>,
    assigned_masked_input_sinks: Vec<SubscriptionSink>,
    n_reserved: u64,
    reserved_indices: Vec<Option<ClientIdentity>>,
    masked_inputs: Vec<Option<T>>,
    /// The current round.
    round: Round,
    /// The `t` value.
    t: u64,
    /// The MPC nodes.
    mpc_nodes: Option<Vec<ClientIdentity>>,
    /// The connected clients and their connection-specific information.
    clients: HashMap<ClientIdentity, ClientInfo>,
    /// Stores encrypted output shares sent by MPC nodes for MPC clients. The first element of the key is the client ID,
    /// the second is the node ID.
    output_shares: HashMap<(ClientIdentity, ClientIdentity), (Vec<u8>, Vec<u8>)>,
    /// Sinks for MPC clients that are waiting to obtain their output shares.
    output_sinks: HashMap<ClientIdentity, SubscriptionSink>,
    /// The set of clients that are permitted to call `obtain_output_shares`.
    output_clients: Vec<ClientIdentity>,
    /// Optional index assignments used to prevent clients from reserving indices assigned to others.
    input_assignments: Vec<InputSlotAssignment>,
}

impl<F: FftField, S: ShareBound<F>> CoordinatorRPCServerConnectionBase<F, S> {
    pub fn new(
        internal: Arc<Mutex<CoordinatorRPCServerSharedBase<S::ValueType>>>,
        id: ClientIdentity,
    ) -> Self {
        Self { d: internal, id }
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize + Clone> CoordinatorRPCServerSharedBase<T> {
    pub fn new(
        _prog_hash: [u8; 32],
        _n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
        n_inputs: u64,
        output_clients: Vec<ClientIdentity>,
    ) -> Self {
        Self {
            sinks: HashMap::from([
                (Round::Idle, vec![]),
                (Round::Preprocessing, vec![]),
                (Round::InputMaskReservation, vec![]),
                (Round::InputCollection, vec![]),
                (Round::MPCExecution, vec![]),
                (Round::OutputDistribution, vec![]),
                (Round::ProgramFinished, vec![]),
            ]),
            trans_events: HashMap::from([
                (Round::Preprocessing, vec![]),
                (Round::InputMaskReservation, vec![]),
                (Round::InputCollection, vec![]),
                (Round::MPCExecution, vec![]),
                (Round::OutputDistribution, vec![]),
                (Round::ProgramFinished, vec![]),
            ]),
            reserved_index_events: vec![],
            reserved_index_sinks: vec![],
            assigned_reserved_index_events: vec![],
            assigned_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            assigned_masked_input_events: vec![],
            assigned_masked_input_sinks: vec![],
            n_reserved: 0,
            reserved_indices: vec![None; n_inputs as usize],
            masked_inputs: vec![None; n_inputs as usize],
            round: Round::Idle,
            t,
            mpc_nodes: Some(initial_mpc_nodes),
            clients: HashMap::new(),
            output_shares: HashMap::new(),
            output_sinks: HashMap::new(),
            output_clients,
            input_assignments: vec![],
        }
    }

    pub fn new_with_input_assignment(
        _prog_hash: [u8; 32],
        _n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
        n_inputs: u64,
        output_clients: Vec<ClientIdentity>,
        input_assignment: InputAssignment,
    ) -> Result<Self, CoordinatorError> {
        if !input_assignment.input_slots.is_empty()
            && n_inputs as usize != input_assignment.input_slots.len()
        {
            return Err(CoordinatorError::JSONError(format!(
                "Input assignment has {} inputs, but coordinator was configured with {} inputs",
                input_assignment.input_slots.len(),
                n_inputs
            )));
        }
        Ok(Self {
            sinks: HashMap::from([
                (Round::Idle, vec![]),
                (Round::Preprocessing, vec![]),
                (Round::InputMaskReservation, vec![]),
                (Round::InputCollection, vec![]),
                (Round::MPCExecution, vec![]),
                (Round::OutputDistribution, vec![]),
                (Round::ProgramFinished, vec![]),
            ]),
            trans_events: HashMap::from([
                (Round::Preprocessing, vec![]),
                (Round::InputMaskReservation, vec![]),
                (Round::InputCollection, vec![]),
                (Round::MPCExecution, vec![]),
                (Round::OutputDistribution, vec![]),
                (Round::ProgramFinished, vec![]),
            ]),
            reserved_index_events: vec![],
            reserved_index_sinks: vec![],
            assigned_reserved_index_events: vec![],
            assigned_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            assigned_masked_input_events: vec![],
            assigned_masked_input_sinks: vec![],
            n_reserved: 0,
            reserved_indices: vec![None; n_inputs as usize],
            masked_inputs: vec![None; n_inputs as usize],
            round: Round::Idle,
            t,
            mpc_nodes: Some(initial_mpc_nodes),
            clients: HashMap::new(),
            output_shares: HashMap::new(),
            output_sinks: HashMap::new(),
            output_clients,
            input_assignments: input_assignment.input_slots,
        })
    }

    pub fn add_client(&mut self, cert: Vec<u8>, thread: JoinHandle<()>, stop_tx: ServerHandle) {
        let info = ClientInfo {
            cert: cert.clone(),
            thread,
            stop_tx,
        };
        self.clients.insert(cert, info);
    }

    async fn subscribe_oneshot(
        &mut self,
        pending: PendingSubscriptionSink,
        round: Round,
    ) -> SubscriptionResult {
        if !self.trans_events.contains_key(&round) {
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

        {
            let events = &self.trans_events[&round];

            if let Some(event) = events.last() {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                sink.send(json).await?;

                return Ok(());
            }
        }

        self.sinks
            .get_mut(&round)
            .unwrap_or_else(|| panic!("BUG: {:?} must be present!", round))
            .push(sink);
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

    async fn transition(&mut self, event: Event<T>, round: Round) -> Result<(), CoordinatorError> {
        if round_before(round).is_none() {
            return Err(CoordinatorError::CannotTransitionToIdle);
        }

        let sinks = self
            .sinks
            .get_mut(&round)
            .unwrap_or_else(|| panic!("BUG: {:?} must be present!", round));

        let sinks = std::mem::take(sinks);

        // Record the round even if one of the existing subscribers has disconnected.
        // Late subscribers will replay this event from history.
        self.trans_events
            .get_mut(&round)
            .expect(&format!("BUG: {:?} must be present!", round))
            .push(event.clone());

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
}


/// The basic shared state can be used as a full-fledged shared state.
impl<T: CanonicalSerialize + CanonicalDeserialize + Clone> crate::rpc::RPCServerShared
    for CoordinatorRPCServerSharedBase<T>
{
    fn add_client(
        &mut self,
        cert_der: Vec<u8>,
        client_handle: JoinHandle<()>,
        stop_tx: ServerHandle,
    ) {
        self.add_client(cert_der, client_handle, stop_tx);
    }
}

/// Pre-implemented RPC methods.
#[async_trait]
impl<F: FftField, S: ShareBound<F>> CoordinatorRPCBaseServer<F, S>
    for CoordinatorRPCServerConnectionBase<F, S>
{
    async fn sub_round(
        &self,
        pending: PendingSubscriptionSink,
        round: Round,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_oneshot(pending, round).await
    }

    async fn available_input_masks(&self) -> RpcResult<u64> {
        let d = self.d.lock().await;

        Ok(d.masked_inputs.len() as u64 - d.n_reserved)
    }

    async fn sub_assigned_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;
        d.subscribe_assigned_reserved_indices(pending).await
    }

    async fn sub_assigned_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;
        d.subscribe_assigned_masked_inputs(pending).await
    }

    async fn reset(&self) -> RpcResult<()> {
        let mut d = self.d.lock().await;

        let designated_party = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0].clone();
        if self.id != designated_party {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotDesignatedParty as i32).code(),
                format!(
                    "Only designated party {:?} can reset the coordinator.",
                    designated_party
                ),
                None::<()>,
            ));
        }

        let n_inputs = d.masked_inputs.len();

        d.round = Round::Idle;
        d.masked_inputs = vec![None; n_inputs as usize];
        d.n_reserved = 0;
        d.reserved_indices = vec![None; n_inputs as usize];
        d.reserved_index_events.clear();
        d.reserved_index_sinks.clear();
        d.assigned_reserved_index_events.clear();
        d.assigned_reserved_index_sinks.clear();
        d.masked_input_events.clear();
        d.masked_input_sinks.clear();
        d.assigned_masked_input_events.clear();
        d.assigned_masked_input_sinks.clear();
        d.output_shares.clear();
        d.output_sinks.clear();
        for sinks in d.sinks.values_mut() {
            sinks.clear();
        }
        for events in d.trans_events.values_mut() {
            events.clear();
        }

        Ok(())
    }

    async fn submit_masked_input(
        &self,
        masked_input: ValueWrapper<S::ValueType>,
        raw_reserved_index: u64,
    ) -> RpcResult<()> {
        let mut d = self.d.lock().await;

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
                d.masked_inputs[reserved_index] = Some(masked_input.value.clone());

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
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_reserved_indices(pending).await
    }

    async fn sub_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_masked_inputs(pending).await
    }

    async fn reserve_mask_index(&self, i: u64) -> RpcResult<()> {
        let mut d = self.d.lock().await;

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

        let event = Event::<S::ValueType>::ReservedInputEvent {
            client: self.id.clone(),
            reserved_index: i,
        };

        d.n_reserved += 1;
        d.reserved_index_events.push(event.clone());

        if let Some(assigned_reservation) = assigned_reservation.clone() {
            d.assigned_reserved_index_events.push(assigned_reservation.clone());
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

    async fn transition(&self, next_round: Round) -> RpcResult<()> {
        let mut d = self.d.lock().await;

        let designated_party = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0].clone();
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
        client_id: ClientIdentity,
        enc_shares: (Vec<u8>, Vec<u8>),
    ) -> RpcResult<()> {
        let mut d = self.d.lock().await;

        let mpc_nodes = d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!");
        if !mpc_nodes.contains(&self.id) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(NotParty as i32).code(),
                "Only parties can send output shares.",
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

        let output_shares: Vec<_> = d
            .output_shares
            .iter()
            .filter(|((cid, _), _)| *cid == client_id)
            .map(|(_, shares)| shares.clone())
            .collect();

        if output_shares.len() >= S::min_shares(d.t as usize) {
            if let Some(sink) = d.output_sinks.get(&client_id) {
                let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
                if sink.send(json.clone()).await.is_err() {
                    eprintln!("coordinator output subscriber disconnected");
                }
            }
        }
        Ok(())
    }

    async fn obtain_output_shares(&self, pending: PendingSubscriptionSink) -> SubscriptionResult {
        let mut d = self.d.lock().await;

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

        if d.output_sinks.contains_key(&self.id) {
            pending
                .reject(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(OutputSharesAlreadyRequested as i32).code(),
                    format!(
                        "Client {:?} already has requested their output shares.",
                        self.id
                    ),
                    None::<()>,
                ))
                .await;
            return Ok(());
        }

        let sink = pending.accept().await?;
        d.output_sinks.insert(self.id.clone(), sink);

        let output_shares: Vec<_> = d
            .output_shares
            .iter()
            .filter(|((client_id, _), _)| *client_id == self.id)
            .map(|(_, shares)| shares.clone())
            .collect();

        if output_shares.len() >= S::min_shares(d.t as usize) {
            let json = to_json_raw_value(&output_shares).expect("failed convert to JSON");
            let sink = d.output_sinks.get(&self.id).unwrap();

            sink.send(json.clone()).await?;
        }

        Ok(())
    }
}

/// The pre-implemented RPC server-side connection can be used as a full-fledged RPC server
/// connection.
impl<F: FftField, S: ShareBound<F>> crate::rpc::RPCServerConnection
    for CoordinatorRPCServerConnectionBase<F, S>
{
    type Internal = CoordinatorRPCServerSharedBase<S::ValueType>;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self { d: internal, id }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        crate::off_chain::CoordinatorRPCBaseServer::<F, S>::into_rpc(self)
    }
}

/// The exterior wrapper of the server-side coordinator.
pub struct OffChainCoordinatorServer<C: crate::rpc::RPCServerConnection> {
    rpc_server: Arc<Mutex<C::Internal>>,
    addr: String,
    port: u16,
    server_handle: JoinHandle<()>,
    t: u64,
}

pub struct OffChainCoordinatorClient<F: FftField, S: ShareBound<F>> {
    rpc_coord: Client,
    t: u64,
    n_parties: u64,
    n_outputs: u64,
    key_der: Vec<u8>,
    _phantom: std::marker::PhantomData<(F, S)>,
}

impl<C: crate::rpc::RPCServerConnection> OffChainCoordinatorServer<C> {
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
        t: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        let server_handle =
            crate::rpc::start_coord::<C>(addr, port, cert_der, key_der, rpc_server_data.clone())
                .await?;
        Ok(Self {
            rpc_server: rpc_server_data,
            addr: String::from(addr),
            port,
            server_handle,
            t,
        })
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone()
    }
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    pub async fn start_rpc_client_from_cert(
        addr: &str,
        port: u16,
        t: u64,
        n_parties: u64,
        n_outputs: u64,
        client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
    ) -> Result<Self, CoordinatorError> {
        Self::start_rpc_client_with_parties(
            addr,
            port,
            t,
            n_parties,
            n_outputs,
            client_cert.cert.der().to_vec(),
            client_cert.signing_key.serialize_der(),
        )
        .await
    }

    pub async fn start_rpc_client(
        addr: &str,
        port: u16,
        t: u64,
        n_parties: u64,
        n_outputs: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        Self::start_rpc_client_with_parties(
            addr,
            port,
            t,
            n_parties,
            n_outputs,
            cert_der,
            key_der,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn start_rpc_client_with_parties(
        addr: &str,
        port: u16,
        t: u64,
        n_parties: u64,
        n_outputs: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_coord =
            crate::self_signed_certs::setup_client(addr, port, cert_der, key_der.clone()).await?;

        Ok(Self {
            rpc_coord,
            t,
            n_parties,
            n_outputs,
            key_der,
            _phantom: std::marker::PhantomData,
        })
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::transition(self.rpc(), round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(())
    }

    fn rpc(&self) -> &Client {
        &self.rpc_coord
    }
}

static ENC_INFO: &[u8] = b"StoffelOutputShareEncryption";

impl<F: FftField, S: ShareBound<F>> Coordinator<F, S> for OffChainCoordinatorClient<F, S> {
    type ClientIdentity = ClientIdentity;

    async fn start_preprocessing(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_preprocessing(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn reserve_input_masks(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::reserve_input_masks(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn collect_inputs(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::collect_inputs(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn start_mpc(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::start_mpc(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn send_output(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::send_output(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }
    async fn finalize(&self) -> Result<(), CoordinatorError> {
        StoffelCoordinatorRPCClient::finalize(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn reset_coord(&self) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::reset(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> Result<HashMap<ClientIdentity, Vec<u64>>, CoordinatorError> {
        // Wait for reserved index events.
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_reserved_indices(self.rpc())
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
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_masked_inputs(self.rpc())
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
                let input = S::compute_masked_input(masked_input.value, mask_share)
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
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_round(self.rpc(), round)
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
        match CoordinatorRPCBaseClient::<F, S>::submit_masked_input(
            self.rpc(),
            ValueWrapper {
                value: masked_input,
            },
            i,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(CoordinatorError::JSONError(e.to_string())),
        }
    }

    async fn reserve_mask_index(&mut self, i: u64) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::reserve_mask_index(self.rpc(), i)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    async fn obtain_outputs(&self) -> Result<Vec<S::ValueType>, CoordinatorError> {
        // Wait for output shares.
        let mut sub = match CoordinatorRPCBaseClient::<F, S>::obtain_output_shares(self.rpc()).await
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
                    ENC_INFO,
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
                    match S::recover_secret(
                        &shares_i,
                        self.n_parties as usize,
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

        // Send the encrypted shares.
        if let Err(e) =
            CoordinatorRPCBaseClient::<F, S>::send_output_shares(self.rpc(), client_id, c).await
        {
            return Err(CoordinatorError::JSONError(e.to_string()));
        }

        Ok(())
    }
}
