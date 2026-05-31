use crate::{
    round_before,
    rpc::{ClientInfo, ValueWrapper},
    Coordinator, CoordinatorError, Round, ShareBound,
};
use ark_ff::{FftField, PrimeField};
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
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use stoffel_vm_types::{
    compiled_binary::{ClientIoManifest, ClientIoSchema},
    core_types::ShareType,
};
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
pub struct BoundClientIoSchema {
    pub schema_hash: [u8; 32],
    pub client: ClientIdentity,
    pub client_slot: u64,
    pub inputs: Vec<ShareType>,
    pub outputs: Vec<ShareType>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedMaskReservation {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub share_type: ShareType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "ValueWrapper<T>: Serialize",
    deserialize = "ValueWrapper<T>: Deserialize<'de>"
))]
pub struct TypedMaskedInput<T: CanonicalSerialize + CanonicalDeserialize + Clone> {
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub share_type: ShareType,
    pub masked_input: ValueWrapper<T>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "ValueWrapper<T>: Serialize",
    deserialize = "ValueWrapper<T>: Deserialize<'de>"
))]
pub struct TypedMaskedInputEvent<T: CanonicalSerialize + CanonicalDeserialize + Clone> {
    pub client: ClientIdentity,
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub share_type: ShareType,
    pub masked_input: ValueWrapper<T>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedMaskShare {
    pub reserved_index: u64,
    pub input_ordinal: u64,
    pub share_type: ShareType,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TypedOutputShare<S> {
    pub output_ordinal: u64,
    pub share_type: ShareType,
    pub share: S,
}

#[derive(Clone, Debug)]
pub struct TypedOutputShareEnvelope<S> {
    pub schema_hash: [u8; 32],
    pub outputs: Vec<TypedOutputShare<S>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClearShareValue {
    Integer(i64),
    Boolean(bool),
    FixedPoint(f64),
}

#[derive(Clone, Debug, PartialEq)]
pub struct TypedClearOutput {
    pub output_ordinal: u64,
    pub share_type: ShareType,
    pub value: ClearShareValue,
}

#[derive(Clone, Debug)]
struct InputSlotSchema {
    client: ClientIdentity,
    input_ordinal: u64,
    share_type: ShareType,
}

fn share_type_hash_update(ctx: &mut ring::digest::Context, share_type: ShareType) {
    match share_type {
        ShareType::SecretInt { bit_length } => {
            ctx.update(&[0]);
            ctx.update(&(bit_length as u64).to_le_bytes());
        }
        ShareType::SecretFixedPoint { precision } => {
            ctx.update(&[1]);
            ctx.update(&(precision.total_bits() as u64).to_le_bytes());
            ctx.update(&(precision.fractional_bits() as u64).to_le_bytes());
        }
    }
}

fn compute_schema_hash(schemas: &[BoundClientIoSchema]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"StoffelClientIoManifestV1");
    let mut ordered = schemas.to_vec();
    ordered.sort_by_key(|schema| schema.client_slot);
    for schema in ordered {
        ctx.update(&schema.client_slot.to_le_bytes());
        ctx.update(&(schema.inputs.len() as u64).to_le_bytes());
        for share_type in schema.inputs {
            share_type_hash_update(&mut ctx, share_type);
        }
        ctx.update(&(schema.outputs.len() as u64).to_le_bytes());
        for share_type in schema.outputs {
            share_type_hash_update(&mut ctx, share_type);
        }
    }
    ctx.finish().as_ref().try_into().expect("SHA-256 length")
}

type BoundClientIoBuildResult = (
    HashMap<ClientIdentity, BoundClientIoSchema>,
    Vec<InputSlotSchema>,
    Vec<ClientIdentity>,
);

fn build_bound_client_io(
    manifest: ClientIoManifest,
    bindings: Vec<(u64, ClientIdentity)>,
) -> Result<BoundClientIoBuildResult, CoordinatorError> {
    let mut by_slot: HashMap<u64, ClientIoSchema> = HashMap::new();
    for schema in manifest.clients {
        let client_slot = schema.client_slot;
        if by_slot.insert(client_slot, schema).is_some() {
            return Err(CoordinatorError::JSONError(format!(
                "Duplicate client_slot {client_slot} in client IO manifest"
            )));
        }
    }

    let mut bound_schemas = Vec::new();
    for (client_slot, client) in bindings {
        let schema = by_slot.remove(&client_slot).ok_or_else(|| {
            CoordinatorError::JSONError(format!(
                "No client IO manifest entry for bound client_slot {client_slot}"
            ))
        })?;
        bound_schemas.push(BoundClientIoSchema {
            schema_hash: [0u8; 32],
            client,
            client_slot,
            inputs: schema.inputs,
            outputs: schema.outputs,
        });
    }

    if !by_slot.is_empty() {
        let mut unbound_slots = by_slot.keys().copied().collect::<Vec<_>>();
        unbound_slots.sort_unstable();
        return Err(CoordinatorError::JSONError(format!(
            "Client IO manifest slots are not bound to off-chain identities: {unbound_slots:?}"
        )));
    }

    let schema_hash = compute_schema_hash(&bound_schemas);
    let mut map = HashMap::new();
    let mut input_slots = Vec::new();
    let mut output_clients = Vec::new();
    for mut schema in bound_schemas {
        schema.schema_hash = schema_hash;
        if !schema.outputs.is_empty() {
            output_clients.push(schema.client.clone());
        }
        for (input_ordinal, share_type) in schema.inputs.iter().copied().enumerate() {
            input_slots.push(InputSlotSchema {
                client: schema.client.clone(),
                input_ordinal: input_ordinal as u64,
                share_type,
            });
        }
        if map.insert(schema.client.clone(), schema).is_some() {
            return Err(CoordinatorError::JSONError(
                "Client identity is bound to multiple client IO slots".to_string(),
            ));
        }
    }

    Ok((map, input_slots, output_clients))
}

fn default_bound_schema(client: ClientIdentity) -> BoundClientIoSchema {
    BoundClientIoSchema {
        schema_hash: compute_schema_hash(&[]),
        client,
        client_slot: 0,
        inputs: vec![],
        outputs: vec![],
    }
}

pub fn encode_clear_input<F: PrimeField>(
    share_type: ShareType,
    value: ClearShareValue,
) -> Result<F, CoordinatorError> {
    match (share_type, value) {
        (ShareType::SecretInt { bit_length: 1 }, ClearShareValue::Boolean(value)) => {
            Ok(F::from(value as u64))
        }
        (ShareType::SecretInt { .. }, ClearShareValue::Integer(value)) => Ok(i64_to_field(value)),
        (ShareType::SecretFixedPoint { precision }, ClearShareValue::FixedPoint(value)) => {
            let scale = 2f64.powi(precision.fractional_bits() as i32);
            Ok(i64_to_field((value * scale).round() as i64))
        }
        (ShareType::SecretFixedPoint { precision }, ClearShareValue::Integer(value)) => {
            let scaled = value
                .checked_shl(precision.fractional_bits() as u32)
                .ok_or(CoordinatorError::SerializationError)?;
            Ok(i64_to_field(scaled))
        }
        _ => Err(CoordinatorError::SerializationError),
    }
}

pub fn decode_clear_output<F: PrimeField>(
    share_type: ShareType,
    value: F,
) -> Result<ClearShareValue, CoordinatorError> {
    match share_type {
        ShareType::SecretInt { bit_length: 1 } => Ok(ClearShareValue::Boolean(!value.is_zero())),
        ShareType::SecretInt { .. } => Ok(ClearShareValue::Integer(field_to_i64(value)?)),
        ShareType::SecretFixedPoint { precision } => {
            let scaled = field_to_i64(value)?;
            let scale = 2f64.powi(precision.fractional_bits() as i32);
            Ok(ClearShareValue::FixedPoint(scaled as f64 / scale))
        }
    }
}

fn i64_to_field<F: PrimeField>(value: i64) -> F {
    if value >= 0 {
        F::from(value as u64)
    } else {
        -F::from(value.unsigned_abs())
    }
}

fn field_to_i64<F: PrimeField>(value: F) -> Result<i64, CoordinatorError> {
    let positive = value.into_bigint();
    if positive.as_ref()[1..].iter().all(|limb| *limb == 0)
        && positive.as_ref()[0] <= i64::MAX as u64
    {
        return Ok(positive.as_ref()[0] as i64);
    }

    let negative = (-value).into_bigint();
    if negative.as_ref()[1..].iter().all(|limb| *limb == 0)
        && negative.as_ref()[0] <= i64::MAX as u64 + 1
    {
        let magnitude = negative.as_ref()[0];
        return if magnitude == (i64::MAX as u64 + 1) {
            Ok(i64::MIN)
        } else {
            Ok(-(magnitude as i64))
        };
    }

    Err(CoordinatorError::DeserializationError)
}

fn write_share_type_bytes(out: &mut Vec<u8>, share_type: ShareType) {
    match share_type {
        ShareType::SecretInt { bit_length } => {
            out.push(0);
            out.extend_from_slice(&(bit_length as u64).to_le_bytes());
        }
        ShareType::SecretFixedPoint { precision } => {
            out.push(1);
            out.extend_from_slice(&(precision.total_bits() as u64).to_le_bytes());
            out.extend_from_slice(&(precision.fractional_bits() as u64).to_le_bytes());
        }
    }
}

fn read_u64_from(cursor: &mut Cursor<&[u8]>) -> Result<u64, CoordinatorError> {
    let mut bytes = [0u8; 8];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| CoordinatorError::DeserializationError)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_share_type_bytes(cursor: &mut Cursor<&[u8]>) -> Result<ShareType, CoordinatorError> {
    let mut tag = [0u8; 1];
    cursor
        .read_exact(&mut tag)
        .map_err(|_| CoordinatorError::DeserializationError)?;
    match tag[0] {
        0 => {
            let bit_length = read_u64_from(cursor)? as usize;
            ShareType::try_secret_int(bit_length)
                .map_err(|_| CoordinatorError::DeserializationError)
        }
        1 => {
            let total_bits = read_u64_from(cursor)? as usize;
            let fractional_bits = read_u64_from(cursor)? as usize;
            Ok(ShareType::SecretFixedPoint {
                precision: stoffel_vm_types::core_types::FixedPointPrecision::try_new(
                    total_bits,
                    fractional_bits,
                )
                .map_err(|_| CoordinatorError::DeserializationError)?,
            })
        }
        _ => Err(CoordinatorError::DeserializationError),
    }
}

fn serialize_typed_output_envelope<S: CanonicalSerialize>(
    envelope: &TypedOutputShareEnvelope<S>,
) -> Result<Vec<u8>, CoordinatorError> {
    let mut out = Vec::new();
    out.extend_from_slice(&envelope.schema_hash);
    out.extend_from_slice(&(envelope.outputs.len() as u64).to_le_bytes());
    for output in &envelope.outputs {
        out.extend_from_slice(&output.output_ordinal.to_le_bytes());
        write_share_type_bytes(&mut out, output.share_type);
        let mut share_bytes = Vec::new();
        output
            .share
            .serialize_compressed(&mut share_bytes)
            .map_err(|_| CoordinatorError::SerializationError)?;
        out.extend_from_slice(&(share_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&share_bytes);
    }
    Ok(out)
}

fn deserialize_typed_output_envelope<S: CanonicalDeserialize>(
    bytes: &[u8],
) -> Result<TypedOutputShareEnvelope<S>, CoordinatorError> {
    let mut cursor = Cursor::new(bytes);
    let mut schema_hash = [0u8; 32];
    cursor
        .read_exact(&mut schema_hash)
        .map_err(|_| CoordinatorError::DeserializationError)?;
    let count = read_u64_from(&mut cursor)? as usize;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let output_ordinal = read_u64_from(&mut cursor)?;
        let share_type = read_share_type_bytes(&mut cursor)?;
        let share_len = read_u64_from(&mut cursor)? as usize;
        let mut share_bytes = vec![0u8; share_len];
        cursor
            .read_exact(&mut share_bytes)
            .map_err(|_| CoordinatorError::DeserializationError)?;
        let share = S::deserialize_compressed(share_bytes.as_slice())
            .map_err(|_| CoordinatorError::DeserializationError)?;
        outputs.push(TypedOutputShare {
            output_ordinal,
            share_type,
            share,
        });
    }
    Ok(TypedOutputShareEnvelope {
        schema_hash,
        outputs,
    })
}

/// The node-side RPC interface.
pub mod node_rpc {
    use super::{ClientIdentity, TypedMaskReservation, TypedMaskShare};
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

        #[subscription(name = "sub_receive_typed_mask_share", unsubscribe = "unsub_receive_typed_mask_share", item = TypedMaskShare)]
        async fn receive_typed_mask_share(&self) -> SubscriptionResult;
    }

    pub struct NodeRPCServer<F: FftField, S: ShareBound<F>> {
        rpc_server: Arc<Mutex<NodeRPCServerInternal<F, S>>>,
        addr: String,
    }

    /// An object used by an MPC client to connect to the RPC interfaces of many nodes.
    pub struct NodeRPCClient<F: FftField, S: ShareBound<F>> {
        /// The per-node client handles for each connection to a node.
        node_rpcs: Vec<Client>,
        /// The threshold value.
        t: usize,
        _phantom: PhantomData<(F, S)>,
    }

    impl<F: FftField, S: ShareBound<F>> NodeRPCClient<F, S> {
        pub async fn start_rpc_client_from_cert(
            t: usize,
            addrs: Vec<(String, u16)>,
            client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
        ) -> Result<Self, CoordinatorError> {
            Self::start_rpc_client(
                t,
                addrs,
                client_cert.cert.der().to_vec(),
                client_cert.signing_key.serialize_der(),
            )
            .await
        }

        /// Connects to a list of MPC nodes via Websockets over TLS.
        pub async fn start_rpc_client(
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

        pub async fn receive_typed_masks(
            &self,
            count: usize,
        ) -> Result<Vec<(TypedMaskShare, S::ValueType)>, CoordinatorError> {
            let mut outputs = Vec::with_capacity(count);
            for _ in 0..count {
                let output_count_before = outputs.len();
                let mut share_futures = JoinSet::new();

                for rpc in self.node_rpcs.iter() {
                    let mut sub = rpc
                        .receive_typed_mask_share()
                        .await
                        .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                    share_futures.spawn(async move { sub.next().await });
                }

                let mut mask_shares: Vec<S> = Vec::new();
                let mut first_metadata: Option<TypedMaskShare> = None;

                while let Some(share_result) = share_futures.join_next().await {
                    let typed_share_option = share_result
                        .map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?;
                    let typed_share = match typed_share_option {
                        Some(res) => {
                            res.map_err(|e| CoordinatorError::SubscriptionError(e.to_string()))?
                        }
                        None => continue,
                    };
                    let share: S = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                        typed_share.share_bytes.as_slice(),
                    )
                    .map_err(|_| CoordinatorError::DeserializationError)?;

                    if first_metadata.is_none() {
                        first_metadata = Some(typed_share.clone());
                    } else if first_metadata.as_ref().is_some_and(|metadata| {
                        metadata.reserved_index != typed_share.reserved_index
                            || metadata.input_ordinal != typed_share.input_ordinal
                            || metadata.share_type != typed_share.share_type
                    }) {
                        return Err(CoordinatorError::JSONError(
                            "Typed mask share metadata differs across MPC nodes".to_string(),
                        ));
                    }
                    mask_shares.push(share);

                    if mask_shares.len() >= S::min_shares(self.t) {
                        let metadata = first_metadata.expect("metadata set with first share");
                        let (_, mask) = S::recover_secret(&mask_shares, 4 * self.t + 1, self.t)
                            .map_err(|_| {
                                CoordinatorError::MaskReconstructionFailed(mask_shares.len())
                            })?;
                        outputs.push((metadata, mask));
                        break;
                    }
                }

                if outputs.len() == output_count_before {
                    return Err(CoordinatorError::MaskReconstructionFailed(
                        mask_shares.len(),
                    ));
                }
            }

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
            crate::rpc::start_coord::<NodeRPCServerImpl<F, S>>(
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
            self.add_typed_reserved_index(TypedMaskReservation {
                client: id,
                reserved_index: i,
                input_ordinal: i,
                share_type: stoffel_vm_types::core_types::ShareType::default_secret_int(),
            })
            .await
        }

        pub async fn add_typed_reserved_index(
            &mut self,
            reservation: TypedMaskReservation,
        ) -> Result<(), NodeRPCError> {
            let mut d = self.rpc_server.lock().await;
            let id = reservation.client.clone();
            let i = reservation.reserved_index;

            if d.index_to_client.contains_key(&i) {
                return Err(NodeRPCError::IndexAlreadyAdded);
            }

            d.index_to_client.insert(i, id.clone());
            d.typed_reservations.insert(i, reservation.clone());
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
                if let Some(sink) = d.typed_sinks.remove(&id) {
                    if let Some(indices) = d.client_to_index.get_mut(&id) {
                        if let Some(position) = indices.iter().position(|index| *index == i) {
                            indices.remove(position);
                        }
                        if indices.is_empty() {
                            d.client_to_index.remove(&id);
                        }
                    }
                    let typed_share = d.typed_mask_share(i, &share)?;
                    let json = to_json_raw_value(&typed_share)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
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
                if let Some(sink) = d.typed_sinks.remove(&id) {
                    if let Some(indices) = d.client_to_index.get_mut(&id) {
                        if let Some(position) = indices.iter().position(|index| *index == i) {
                            indices.remove(position);
                        }
                        if indices.is_empty() {
                            d.client_to_index.remove(&id);
                        }
                    }
                    let typed_share = d.typed_mask_share(i, share)?;
                    let json = to_json_raw_value(&typed_share)
                        .map_err(|_| NodeRPCError::SerializationError)?;
                    sink.send(json).await.map_err(|_| NodeRPCError::JSONError)?;
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
        typed_reservations: HashMap<u64, TypedMaskReservation>,
        /// The inverse mapping of `index_to_client`.
        client_to_index: HashMap<ClientIdentity, VecDeque<u64>>,
        /// Client sinks to send mask shares over Websockets.
        sinks: HashMap<ClientIdentity, SubscriptionSink>,
        typed_sinks: HashMap<ClientIdentity, SubscriptionSink>,
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
                typed_reservations: HashMap::new(),
                client_to_index: HashMap::new(),
                sinks: HashMap::new(),
                typed_sinks: HashMap::new(),
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
        fn typed_mask_share(
            &self,
            reserved_index: u64,
            share: &S,
        ) -> Result<TypedMaskShare, NodeRPCError> {
            let reservation = self
                .typed_reservations
                .get(&reserved_index)
                .ok_or(NodeRPCError::IndexNotAdded)?;
            let mut share_bytes = Vec::new();
            share
                .serialize_compressed(&mut share_bytes)
                .map_err(|_| NodeRPCError::SerializationError)?;
            Ok(TypedMaskShare {
                reserved_index,
                input_ordinal: reservation.input_ordinal,
                share_type: reservation.share_type,
                share_bytes,
            })
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

        async fn receive_typed_mask_share(
            &self,
            pending: PendingSubscriptionSink,
        ) -> SubscriptionResult {
            use OffChainNodeRPCServerError::*;

            let mut d = self.d.lock().await;

            if d.typed_sinks.contains_key(&self.id) {
                pending
                    .reject(ErrorObjectOwned::owned(
                        ErrorCode::InvalidParams.code(),
                        format!("Client {:?} already requested typed mask share", self.id),
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
            let typed_share = if let Some(i) = next_index {
                if let Some(share) = d.mask_shares.get(&i).cloned() {
                    if let Some(indices) = d.client_to_index.get_mut(&self.id) {
                        indices.pop_front();
                        remove_client_indices = indices.is_empty();
                    }
                    match d.typed_mask_share(i, &share) {
                        Ok(typed_share) => Some(typed_share),
                        Err(e) => {
                            pending
                                .reject(ErrorObjectOwned::owned(
                                    ErrorCode::ServerError(SerializationError as i32).code(),
                                    format!("Serializing typed share failed: {e}"),
                                    None::<()>,
                                ))
                                .await;
                            return Ok(());
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if remove_client_indices {
                d.client_to_index.remove(&self.id);
            }

            if let Some(typed_share) = typed_share {
                let json = match to_json_raw_value(&typed_share) {
                    Ok(j) => j,
                    Err(e) => {
                        pending
                            .reject(ErrorObjectOwned::owned(
                                ErrorCode::ServerError(SerializationError as i32).code(),
                                format!("Converting typed share to JSON failed: {e}"),
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
            d.typed_sinks.insert(self.id.clone(), sink);

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
    async fn sub_round(&self, round: Round, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = Event<S::ValueType>)]
    async fn sub_reserved_indices(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = Event<S::ValueType>)]
    async fn sub_masked_inputs(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_typed_reserved_indices", unsubscribe = "unsub_typed_reserved_indices", item = TypedMaskReservation)]
    async fn sub_typed_reserved_indices(&self, timestamp: u64) -> SubscriptionResult;

    #[subscription(name = "sub_typed_masked_inputs", unsubscribe = "unsub_typed_masked_inputs", item = TypedMaskedInputEvent<S::ValueType>)]
    async fn sub_typed_masked_inputs(&self, timestamp: u64) -> SubscriptionResult;

    #[method(name = "get_client_io_schema")]
    async fn get_client_io_schema(&self) -> RpcResult<BoundClientIoSchema>;

    #[method(name = "reserve_mask_indices")]
    async fn reserve_mask_indices(&self, count: u64) -> RpcResult<Vec<TypedMaskReservation>>;

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

    #[method(name = "submit_masked_inputs")]
    async fn submit_masked_inputs(
        &self,
        masked_inputs: Vec<TypedMaskedInput<S::ValueType>>,
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
    InvalidClientIoSchema = 13,
    InvalidReservationCount = 14,
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
    // Stores events that some round has been triggered along with a timestamp when it was
    // triggered.
    trans_events: HashMap<Round, Vec<(u64, Event<T>)>>,
    reserved_index_events: Vec<(u64, Event<T>)>,
    reserved_index_sinks: Vec<SubscriptionSink>,
    typed_reserved_index_events: Vec<(u64, TypedMaskReservation)>,
    typed_reserved_index_sinks: Vec<SubscriptionSink>,
    masked_input_events: Vec<(u64, Event<T>)>,
    masked_input_sinks: Vec<SubscriptionSink>,
    typed_masked_input_events: Vec<(u64, TypedMaskedInputEvent<T>)>,
    typed_masked_input_sinks: Vec<SubscriptionSink>,
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
    /// Client IO schemas bound from VM logical client slots to off-chain identities.
    client_io_schemas: HashMap<ClientIdentity, BoundClientIoSchema>,
    typed_input_slots: Vec<InputSlotSchema>,
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
            typed_reserved_index_events: vec![],
            typed_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            typed_masked_input_events: vec![],
            typed_masked_input_sinks: vec![],
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
            client_io_schemas: HashMap::new(),
            typed_input_slots: vec![],
        }
    }

    pub fn new_with_client_io_manifest(
        _prog_hash: [u8; 32],
        _n: u64,
        t: u64,
        initial_mpc_nodes: Vec<ClientIdentity>,
        manifest: ClientIoManifest,
        client_bindings: Vec<(u64, ClientIdentity)>,
    ) -> Result<Self, CoordinatorError> {
        let (client_io_schemas, typed_input_slots, output_clients) =
            build_bound_client_io(manifest, client_bindings)?;
        let n_inputs = typed_input_slots.len() as u64;
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
            typed_reserved_index_events: vec![],
            typed_reserved_index_sinks: vec![],
            masked_input_events: vec![],
            masked_input_sinks: vec![],
            typed_masked_input_events: vec![],
            typed_masked_input_sinks: vec![],
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
            client_io_schemas,
            typed_input_slots,
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
        timestamp: u64,
        round: Round,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        {
            let events = &self.trans_events[&round];
            let index = events.partition_point(|e| e.0 < timestamp);

            // check if there is an event since the coordinator was reset the last time
            if index != events.len() {
                let event = events[index].1.clone();
                let json = to_json_raw_value(&event).expect("failed convert to JSON");
                sink.send(json).await?;

                return Ok(());
            }

            if round_reached(self.round, round) {
                if let Some((_, event)) = events.last() {
                    let json = to_json_raw_value(event).expect("failed convert to JSON");
                    sink.send(json).await?;

                    return Ok(());
                }
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
        timestamp: u64,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        let events = &self.reserved_index_events;
        let index = events.partition_point(|e| e.0 < timestamp);

        // check if there are events since the coordinator was reset the last time
        if index != events.len() {
            // send all such events
            for (_, event) in events.iter().skip(index) {
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
        timestamp: u64,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        let events = &self.masked_input_events;
        let index = events.partition_point(|e| e.0 < timestamp);

        // check if there are events since the coordinator was reset the last time
        if index != events.len() {
            // send all such events
            for (_, event) in events.iter().skip(index) {
                let json = to_json_raw_value(event).expect("failed convert to JSON");
                sink.send(json).await?;
            }
        }

        self.masked_input_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_typed_reserved_indices(
        &mut self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        let events = &self.typed_reserved_index_events;
        let index = events.partition_point(|e| e.0 < timestamp);
        for (_, event) in events.iter().skip(index) {
            let json = to_json_raw_value(event).expect("failed convert to JSON");
            sink.send(json).await?;
        }

        self.typed_reserved_index_sinks.push(sink);
        Ok(())
    }

    async fn subscribe_typed_masked_inputs(
        &mut self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let sink = pending.accept().await?;

        let events = &self.typed_masked_input_events;
        let index = events.partition_point(|e| e.0 < timestamp);
        for (_, event) in events.iter().skip(index) {
            let json = to_json_raw_value(event).expect("failed convert to JSON");
            sink.send(json).await?;
        }

        self.typed_masked_input_sinks.push(sink);
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
            .unwrap_or_else(|| panic!("BUG: {:?} must be present!", round))
            .push((
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                event.clone(),
            ));

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

fn round_reached(current: Round, requested: Round) -> bool {
    let mut cursor = Some(current);
    while let Some(round) = cursor {
        if round == requested {
            return true;
        }
        cursor = crate::round_before(round);
    }
    false
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
        timestamp: u64,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_oneshot(pending, timestamp, round).await
    }

    async fn available_input_masks(&self) -> RpcResult<u64> {
        let d = self.d.lock().await;

        Ok(d.masked_inputs.len() as u64 - d.n_reserved)
    }

    async fn get_client_io_schema(&self) -> RpcResult<BoundClientIoSchema> {
        let d = self.d.lock().await;
        Ok(d.client_io_schemas
            .get(&self.id)
            .cloned()
            .unwrap_or_else(|| default_bound_schema(self.id.clone())))
    }

    async fn sub_typed_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;
        d.subscribe_typed_reserved_indices(pending, timestamp).await
    }

    async fn sub_typed_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;
        d.subscribe_typed_masked_inputs(pending, timestamp).await
    }

    async fn reserve_mask_indices(&self, count: u64) -> RpcResult<Vec<TypedMaskReservation>> {
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

        let schema = d.client_io_schemas.get(&self.id).ok_or_else(|| {
            ErrorObjectOwned::owned(
                ErrorCode::ServerError(UnauthorizedClientIo as i32).code(),
                format!("Client {:?} is not bound to a client IO schema", self.id),
                None::<()>,
            )
        })?;

        if count as usize != schema.inputs.len() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(InvalidReservationCount as i32).code(),
                format!(
                    "Client {:?} must reserve exactly {} typed inputs, got {}",
                    self.id,
                    schema.inputs.len(),
                    count
                ),
                None::<()>,
            ));
        }

        let mut reservations = Vec::with_capacity(count as usize);
        for (reserved_index, slot) in d.typed_input_slots.iter().enumerate() {
            if slot.client == self.id {
                if d.reserved_indices[reserved_index].is_some() {
                    return Err(ErrorObjectOwned::owned(
                        ErrorCode::ServerError(IndexAlreadyReserved as i32).code(),
                        format!("Index {} already reserved.", reserved_index),
                        None::<()>,
                    ));
                }
                reservations.push(TypedMaskReservation {
                    client: self.id.clone(),
                    reserved_index: reserved_index as u64,
                    input_ordinal: slot.input_ordinal,
                    share_type: slot.share_type,
                });
            }
        }

        if reservations.len() != count as usize {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(InvalidReservationCount as i32).code(),
                format!(
                    "Client {:?} has {} typed inputs in coordinator state, got request for {}",
                    self.id,
                    reservations.len(),
                    count
                ),
                None::<()>,
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for reservation in &reservations {
            let i = reservation.reserved_index as usize;
            d.reserved_indices[i] = Some(self.id.clone());
            d.n_reserved += 1;

            let legacy_event = Event::<S::ValueType>::ReservedInputEvent {
                client: self.id.clone(),
                reserved_index: reservation.reserved_index,
            };
            d.reserved_index_events.push((now, legacy_event.clone()));
            d.typed_reserved_index_events
                .push((now, reservation.clone()));

            let sinks = std::mem::take(&mut d.reserved_index_sinks);
            for sink in sinks {
                let json = to_json_raw_value(&legacy_event).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.reserved_index_sinks.push(sink);
                }
            }

            let typed_sinks = std::mem::take(&mut d.typed_reserved_index_sinks);
            for sink in typed_sinks {
                let json = to_json_raw_value(reservation).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.typed_reserved_index_sinks.push(sink);
                }
            }
        }

        Ok(reservations)
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

        if !matches!(d.round, Round::Idle | Round::ProgramFinished) {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(WrongRound as i32).code(),
                format!(
                    "Need round {:?} or {:?}, current round is {:?}",
                    Round::Idle,
                    Round::ProgramFinished,
                    d.round
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
        d.typed_reserved_index_events.clear();
        d.typed_reserved_index_sinks.clear();
        d.masked_input_events.clear();
        d.masked_input_sinks.clear();
        d.typed_masked_input_events.clear();
        d.typed_masked_input_sinks.clear();
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

                let masked_input_for_typed = masked_input.clone();
                let event = Event::MaskedInputEvent {
                    client: self.id.clone(),
                    masked_input,
                    reserved_index: raw_reserved_index,
                };
                let typed_event =
                    d.typed_input_slots
                        .get(reserved_index)
                        .map(|slot| TypedMaskedInputEvent {
                            client: self.id.clone(),
                            reserved_index: raw_reserved_index,
                            input_ordinal: slot.input_ordinal,
                            share_type: slot.share_type,
                            masked_input: masked_input_for_typed,
                        });
                d.masked_input_events.push((
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    event.clone(),
                ));
                if let Some(typed_event) = typed_event.clone() {
                    d.typed_masked_input_events.push((
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        typed_event.clone(),
                    ));
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
                if let Some(typed_event) = typed_event {
                    let typed_sinks = std::mem::take(&mut d.typed_masked_input_sinks);
                    for sink in typed_sinks {
                        let json = to_json_raw_value(&typed_event).expect("failed convert to JSON");
                        if sink.send(json).await.is_ok() {
                            d.typed_masked_input_sinks.push(sink);
                        } else {
                            eprintln!("coordinator typed masked-input subscriber disconnected");
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

    async fn submit_masked_inputs(
        &self,
        masked_inputs: Vec<TypedMaskedInput<S::ValueType>>,
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

        let schema = d.client_io_schemas.get(&self.id).ok_or_else(|| {
            ErrorObjectOwned::owned(
                ErrorCode::ServerError(UnauthorizedClientIo as i32).code(),
                format!("Client {:?} is not bound to a client IO schema", self.id),
                None::<()>,
            )
        })?;

        if masked_inputs.len() != schema.inputs.len() {
            return Err(ErrorObjectOwned::owned(
                ErrorCode::ServerError(InvalidReservationCount as i32).code(),
                format!(
                    "Client {:?} must submit exactly {} typed inputs, got {}",
                    self.id,
                    schema.inputs.len(),
                    masked_inputs.len()
                ),
                None::<()>,
            ));
        }

        let mut seen_reserved_indices = HashSet::with_capacity(masked_inputs.len());
        let mut seen_input_ordinals = HashSet::with_capacity(masked_inputs.len());
        for input in &masked_inputs {
            if !seen_reserved_indices.insert(input.reserved_index)
                || !seen_input_ordinals.insert(input.input_ordinal)
            {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(InvalidReservationCount as i32).code(),
                    format!(
                        "Client {:?} submitted duplicate typed input metadata",
                        self.id
                    ),
                    None::<()>,
                ));
            }

            let reserved_index = input.reserved_index as usize;
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

            let slot = d.typed_input_slots.get(reserved_index).ok_or_else(|| {
                ErrorObjectOwned::owned(
                    ErrorCode::ServerError(InvalidClientIoSchema as i32).code(),
                    format!(
                        "Index {} is not typed in the client IO schema",
                        reserved_index
                    ),
                    None::<()>,
                )
            })?;
            if slot.client != self.id
                || slot.input_ordinal != input.input_ordinal
                || slot.share_type != input.share_type
            {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(InvalidClientIoSchema as i32).code(),
                    format!(
                        "Typed input metadata for index {} does not match coordinator schema",
                        reserved_index
                    ),
                    None::<()>,
                ));
            }
            if d.reserved_indices[reserved_index].as_ref() != Some(&self.id) {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(IndexNotReserved as i32).code(),
                    format!(
                        "Cannot submit a masked input for index {}, since it has not been reserved by {:?}",
                        reserved_index, self.id
                    ),
                    None::<()>,
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
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for input in masked_inputs {
            let reserved_index = input.reserved_index as usize;
            d.masked_inputs[reserved_index] = Some(input.masked_input.value.clone());

            let legacy_event = Event::MaskedInputEvent {
                client: self.id.clone(),
                masked_input: input.masked_input.clone(),
                reserved_index: input.reserved_index,
            };
            let typed_event = TypedMaskedInputEvent {
                client: self.id.clone(),
                reserved_index: input.reserved_index,
                input_ordinal: input.input_ordinal,
                share_type: input.share_type,
                masked_input: input.masked_input,
            };

            d.masked_input_events.push((now, legacy_event.clone()));
            d.typed_masked_input_events.push((now, typed_event.clone()));

            let sinks = std::mem::take(&mut d.masked_input_sinks);
            for sink in sinks {
                let json = to_json_raw_value(&legacy_event).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.masked_input_sinks.push(sink);
                }
            }

            let typed_sinks = std::mem::take(&mut d.typed_masked_input_sinks);
            for sink in typed_sinks {
                let json = to_json_raw_value(&typed_event).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.typed_masked_input_sinks.push(sink);
                }
            }
        }

        Ok(())
    }

    async fn sub_reserved_indices(
        &self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_reserved_indices(pending, timestamp).await
    }

    async fn sub_masked_inputs(
        &self,
        pending: PendingSubscriptionSink,
        timestamp: u64,
    ) -> SubscriptionResult {
        let mut d = self.d.lock().await;

        d.subscribe_masked_inputs(pending, timestamp).await
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

        let typed_reservation = if let Some(slot) = d.typed_input_slots.get(i as usize) {
            if slot.client != self.id {
                return Err(ErrorObjectOwned::owned(
                    ErrorCode::ServerError(UnauthorizedClientIo as i32).code(),
                    format!(
                        "Client {:?} cannot reserve typed input index {}, which belongs to {:?}",
                        self.id, i, slot.client
                    ),
                    None::<()>,
                ));
            }
            Some(TypedMaskReservation {
                client: self.id.clone(),
                reserved_index: i,
                input_ordinal: slot.input_ordinal,
                share_type: slot.share_type,
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
        d.reserved_index_events.push((
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event.clone(),
        ));
        if let Some(typed_reservation) = typed_reservation.clone() {
            d.typed_reserved_index_events.push((
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                typed_reservation.clone(),
            ));
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
        if let Some(typed_reservation) = typed_reservation {
            let typed_sinks = std::mem::take(&mut d.typed_reserved_index_sinks);
            for sink in typed_sinks {
                let json = to_json_raw_value(&typed_reservation).expect("failed convert to JSON");
                if sink.send(json).await.is_ok() {
                    d.typed_reserved_index_sinks.push(sink);
                } else {
                    eprintln!("coordinator typed reserved-index subscriber disconnected");
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
    addr: Option<String>,
    timestamp: Option<u64>,
    _marker: std::marker::PhantomData<C>,
}

/// The exterior wrapper of the coordinator, which implements the `Coordinator` trait.
/// Can be used by either an RPC client (MPC node or MPC client) or the RPC server (the
/// coordinator). Therefore, some values are optional.
pub struct OffChainCoordinatorClient<F: FftField, S: ShareBound<F>> {
    rpc_coord: Option<Client>,
    timestamp: Option<u64>,
    t: u64,
    n_outputs: Option<u64>,
    key_der: Option<Vec<u8>>,
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
        _t: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_server_data = Arc::new(Mutex::new(shared));
        crate::rpc::start_coord::<C>(addr, port, cert_der, key_der, rpc_server_data.clone())
            .await?;
        Ok(Self {
            addr: Some(String::from(addr)),
            timestamp: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            _marker: std::marker::PhantomData,
        })
    }

    pub fn get_addr(&self) -> String {
        self.addr.clone().expect("Coordinator server not started")
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp.expect("Coordinator server not started")
    }
}

impl<F: FftField, S: ShareBound<F>> OffChainCoordinatorClient<F, S> {
    pub async fn start_rpc_client_from_cert(
        addr: &str,
        port: u16,
        timestamp: u64,
        t: u64,
        n_outputs: u64,
        client_cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
    ) -> Result<Self, CoordinatorError> {
        Self::start_rpc_client(
            addr,
            port,
            timestamp,
            t,
            n_outputs,
            client_cert.cert.der().to_vec(),
            client_cert.signing_key.serialize_der(),
        )
        .await
    }

    pub async fn start_rpc_client(
        addr: &str,
        port: u16,
        timestamp: u64,
        t: u64,
        n_outputs: u64,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> Result<Self, CoordinatorError> {
        let rpc_coord =
            crate::self_signed_certs::setup_client(addr, port, cert_der, key_der.clone()).await?;

        Ok(Self {
            rpc_coord: Some(rpc_coord),
            timestamp: Some(timestamp),
            t,
            n_outputs: Some(n_outputs),
            key_der: Some(key_der),
            _phantom: std::marker::PhantomData,
        })
    }

    pub async fn trigger_round(&self, round: Round) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::transition(self.rpc(), round)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        Ok(())
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp.expect("Coordinator server not started")
    }

    fn rpc(&self) -> &Client {
        self.rpc_coord.as_ref().expect("client not started")
    }

    pub async fn get_client_io_schema(&self) -> Result<BoundClientIoSchema, CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::get_client_io_schema(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    pub async fn reserve_mask_indices(
        &self,
        count: u64,
    ) -> Result<Vec<TypedMaskReservation>, CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::reserve_mask_indices(self.rpc(), count)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    pub async fn submit_masked_inputs(
        &self,
        masked_inputs: Vec<TypedMaskedInput<S::ValueType>>,
    ) -> Result<(), CoordinatorError> {
        CoordinatorRPCBaseClient::<F, S>::submit_masked_inputs(self.rpc(), masked_inputs)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    pub async fn wait_for_typed_indices(
        &self,
        n_inputs: u64,
    ) -> Result<Vec<TypedMaskReservation>, CoordinatorError> {
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_typed_reserved_indices(
            self.rpc(),
            self.get_timestamp(),
        )
        .await
        .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let mut reservations = Vec::with_capacity(n_inputs as usize);
        for _ in 0..n_inputs {
            if let Some(Ok(reservation)) = sub.next().await {
                reservations.push(reservation);
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before typed reserved-index event could be received"
                        .to_string(),
                ));
            }
        }
        reservations.sort_by_key(|reservation| reservation.input_ordinal);
        Ok(reservations)
    }

    pub async fn wait_for_typed_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> Result<Vec<TypedOutputShare<S>>, CoordinatorError> {
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_typed_masked_inputs(
            self.rpc(),
            self.get_timestamp(),
        )
        .await
        .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let mut inputs = Vec::with_capacity(n_inputs as usize);
        for _ in 0..n_inputs {
            if let Some(Ok(event)) = sub.next().await {
                let i = event.reserved_index as usize;
                let mask_share = &mask_shares[i];
                let input = S::compute_masked_input(event.masked_input.value, mask_share)
                    .map_err(|_| CoordinatorError::ShareError)?;
                inputs.push(TypedOutputShare {
                    output_ordinal: event.input_ordinal,
                    share_type: event.share_type,
                    share: input,
                });
            } else {
                return Err(CoordinatorError::JSONError(
                    "Subscription ended before typed masked-input event could be received"
                        .to_string(),
                ));
            }
        }
        inputs.sort_by_key(|input| input.output_ordinal);
        Ok(inputs)
    }

    pub async fn send_typed_output_shares(
        &self,
        client_id: ClientIdentity,
        key: Vec<u8>,
        envelope: TypedOutputShareEnvelope<S>,
    ) -> Result<(), CoordinatorError> {
        let client_pk = <KemImpl as Kem>::PublicKey::from_bytes(&key)
            .map_err(|_| CoordinatorError::ParsingPublicKeyFailed)?;
        let output_shares_bytes = serialize_typed_output_envelope(&envelope)?;

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

        CoordinatorRPCBaseClient::<F, S>::send_output_shares(self.rpc(), client_id, c)
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))
    }

    pub async fn obtain_typed_outputs(&self) -> Result<Vec<TypedClearOutput>, CoordinatorError>
    where
        F: PrimeField,
        S: ShareBound<F, ValueType = F>,
    {
        let schema = self.get_client_io_schema().await?;
        let mut sub = CoordinatorRPCBaseClient::<F, S>::obtain_output_shares(self.rpc())
            .await
            .map_err(|e| CoordinatorError::JSONError(e.to_string()))?;

        let client_sk = {
            let der_bytes = self.key_der.clone().unwrap();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk)
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        while let Some(Ok(enc_output_shares)) = sub.next().await {
            if enc_output_shares.len() < S::min_shares(self.t as usize) {
                continue;
            }

            let mut output_share_sets = Vec::new();
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
                let envelope: TypedOutputShareEnvelope<S> =
                    deserialize_typed_output_envelope(&output_shares_bytes)?;

                if envelope.schema_hash != schema.schema_hash
                    || envelope.outputs.len() != schema.outputs.len()
                {
                    continue;
                }
                if envelope
                    .outputs
                    .iter()
                    .enumerate()
                    .any(|(ordinal, output)| {
                        output.output_ordinal as usize != ordinal
                            || schema.outputs[ordinal] != output.share_type
                    })
                {
                    continue;
                }
                output_share_sets.push(envelope.outputs);
            }

            let mut outputs = Vec::new();
            for (ordinal, share_type) in schema.outputs.iter().copied().enumerate() {
                let shares_i: Vec<_> = output_share_sets
                    .iter()
                    .map(|shares| shares[ordinal].share.clone())
                    .collect();
                if shares_i.len() < S::min_shares(self.t as usize) {
                    continue;
                }
                if let Ok((_, output_i)) =
                    S::recover_secret(&shares_i, (4 * self.t + 1) as usize, self.t as usize)
                {
                    outputs.push(TypedClearOutput {
                        output_ordinal: ordinal as u64,
                        share_type,
                        value: decode_clear_output(share_type, output_i)?,
                    });
                }
            }
            if outputs.len() == schema.outputs.len() {
                return Ok(outputs);
            }
        }

        Err(CoordinatorError::JSONError(
            "Output shares subscription ended before enough typed output shares could be obtained"
                .to_string(),
        ))
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
        let mut sub = CoordinatorRPCBaseClient::<F, S>::sub_reserved_indices(
            self.rpc(),
            self.get_timestamp(),
        )
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
        let mut sub =
            CoordinatorRPCBaseClient::<F, S>::sub_masked_inputs(self.rpc(), self.get_timestamp())
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
        let mut sub =
            CoordinatorRPCBaseClient::<F, S>::sub_round(self.rpc(), round, self.get_timestamp())
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
            let der_bytes = self.key_der.clone().unwrap();
            let parsed_secret_key = SecretKey::from_pkcs8_der(&der_bytes)
                .map_err(|_| CoordinatorError::ParsingDERAsPKCS8Failed)?;
            let raw_sk = parsed_secret_key.to_bytes();

            <KemImpl as Kem>::PrivateKey::from_bytes(&raw_sk)
                .map_err(|_| CoordinatorError::ParsingPrivateKeyFailed)?
        };

        // Try to decrypt and reconstruct outputs until it succeeds.
        while let Some(Ok(enc_output_shares)) = sub.next().await {
            if enc_output_shares.len() < S::min_shares(self.t as usize) {
                continue;
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
                    match S::recover_secret(&shares_i, (4 * self.t + 1) as usize, self.t as usize) {
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
            if outputs.len() == self.n_outputs.unwrap() as usize {
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
