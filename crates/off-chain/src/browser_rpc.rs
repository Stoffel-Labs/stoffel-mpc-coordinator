//! Capability-authenticated, browser-only RPC surfaces.
//! Only protocol artifacts cross these interfaces.

use crate::{node_rpc::NodeRPCServerInternal, CoordinatorRPCServerSharedBase};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{error::ErrorCode, ErrorObjectOwned},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::UNIX_EPOCH};
use stoffel_mpc_coordinator_shared::{
    browser_capability::{
        BrowserCapabilityClaims, BrowserCapabilityVerifier, ReplayKey, VerifiedBrowserCapability,
    },
    Round, ShareBound,
};
use tokio::sync::Mutex;

const AUTH: i32 = 20;
const STATE: i32 = 21;
const REPLAY: i32 = 22;

/// Canonical bytes represented as a base64url JSON string, rather than a numeric JSON field value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedBytes(pub String);

impl SerializedBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }
    pub fn decode(&self) -> RpcResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.0)
            .map_err(|_| err(AUTH, "invalid serialized protocol bytes"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserInputReservation {
    pub input_start_index: u64,
    pub input_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserMaskShare {
    pub reserved_index: u64,
    pub share: SerializedBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserEncryptedOutputShare {
    pub encapsulated_key: SerializedBytes,
    pub ciphertext: SerializedBytes,
}

/// Deliberately excludes all administration, party transition, and reset methods.
#[rpc(server, client)]
pub trait BrowserCoordinatorRPC {
    #[method(name = "browser_reserve_input_range")]
    async fn reserve_input_range(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<BrowserInputReservation>;

    #[method(name = "browser_submit_masked_inputs")]
    async fn submit_masked_inputs(
        &self,
        capability: String,
        origin: String,
        masked_inputs: Vec<SerializedBytes>,
    ) -> RpcResult<()>;

    #[method(name = "browser_obtain_output_shares")]
    async fn obtain_output_shares(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<Option<Vec<BrowserEncryptedOutputShare>>>;
}

/// A node never accepts a client identity or range supplied separately from the capability.
#[rpc(server, client)]
pub trait BrowserNodeRPC {
    #[method(name = "browser_obtain_mask_shares")]
    async fn obtain_mask_shares(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<Option<Vec<BrowserMaskShare>>>;
}

#[derive(Clone)]
enum ReplayState {
    Reserved(BrowserCapabilityClaims),
    Submitted(BrowserCapabilityClaims, Vec<SerializedBytes>),
}

struct MutationState {
    entries: HashMap<ReplayKey, ReplayState>,
    slots: HashMap<(String, String, u8), Vec<u8>>,
    capacity: usize,
}

pub struct BrowserCoordinatorServer<F: FftField, S: ShareBound<F>> {
    shared: Arc<Mutex<CoordinatorRPCServerSharedBase<S::ValueType>>>,
    verifier: BrowserCapabilityVerifier,
    mutations: Arc<Mutex<MutationState>>,
    marker: PhantomData<F>,
}

impl<F: FftField, S: ShareBound<F>> Clone for BrowserCoordinatorServer<F, S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            verifier: self.verifier.clone(),
            mutations: self.mutations.clone(),
            marker: PhantomData,
        }
    }
}

impl<F: FftField, S: ShareBound<F>> BrowserCoordinatorServer<F, S> {
    pub fn new(
        shared: Arc<Mutex<CoordinatorRPCServerSharedBase<S::ValueType>>>,
        verifier: BrowserCapabilityVerifier,
        replay_capacity: usize,
    ) -> Self {
        Self {
            shared,
            verifier,
            mutations: Arc::new(Mutex::new(MutationState {
                entries: HashMap::new(),
                slots: HashMap::new(),
                capacity: replay_capacity.max(1),
            })),
            marker: PhantomData,
        }
    }

    fn verify(&self, token: &str, origin: &str) -> RpcResult<VerifiedBrowserCapability> {
        self.verifier
            .verify(token, origin, now())
            .map_err(|_| err(AUTH, "capability verification failed"))
    }
}

pub struct BrowserNodeServer<F: FftField, S: ShareBound<F>> {
    shared: Arc<Mutex<NodeRPCServerInternal<F, S>>>,
    verifier: BrowserCapabilityVerifier,
}

impl<F: FftField, S: ShareBound<F>> Clone for BrowserNodeServer<F, S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            verifier: self.verifier.clone(),
        }
    }
}

impl<F: FftField, S: ShareBound<F>> BrowserNodeServer<F, S> {
    pub fn new(
        shared: Arc<Mutex<NodeRPCServerInternal<F, S>>>,
        verifier: BrowserCapabilityVerifier,
    ) -> Self {
        Self { shared, verifier }
    }
}

fn now() -> u64 {
    UNIX_EPOCH.elapsed().unwrap_or_default().as_secs()
}
fn err(code: i32, message: &'static str) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::ServerError(code).code(), message, None::<()>)
}
fn indices(c: &BrowserCapabilityClaims) -> std::ops::Range<u64> {
    c.input_start_index..c.input_start_index + c.input_count
}

impl MutationState {
    fn bind_slot(&mut self, c: &VerifiedBrowserCapability) -> RpcResult<()> {
        let key = (
            c.claims.room_id.clone(),
            c.claims.session_id.clone(),
            c.claims.client_slot,
        );
        match self.slots.get(&key) {
            Some(id) if id != &c.client_identity => {
                Err(err(AUTH, "capability slot is already bound"))
            }
            Some(_) => Ok(()),
            None => {
                self.slots.insert(key, c.client_identity.clone());
                Ok(())
            }
        }
    }
}

#[async_trait]
impl<F: FftField, S: ShareBound<F>> BrowserCoordinatorRPCServer for BrowserCoordinatorServer<F, S> {
    async fn reserve_input_range(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<BrowserInputReservation> {
        let c = self.verify(&capability, &origin)?;
        let answer = BrowserInputReservation {
            input_start_index: c.claims.input_start_index,
            input_count: c.claims.input_count,
        };
        let mut mutations = self.mutations.lock().await;
        if let Some(prior) = mutations.entries.get(&c.replay_key) {
            return match prior {
                ReplayState::Reserved(claims) | ReplayState::Submitted(claims, _)
                    if claims == &c.claims =>
                {
                    Ok(answer)
                }
                _ => Err(err(REPLAY, "conflicting capability replay")),
            };
        }
        if mutations.entries.len() >= mutations.capacity {
            return Err(err(REPLAY, "browser replay cache is full"));
        }
        mutations.bind_slot(&c)?;

        let mut d = self.shared.lock().await;
        if d.round != Round::InputMaskReservation {
            return Err(err(STATE, "coordinator is not reserving inputs"));
        }
        let end = c.claims.input_start_index + c.claims.input_count;
        if end as usize > d.reserved_indices.len() {
            return Err(err(AUTH, "capability input range is out of bounds"));
        }
        // Validate the entire assigned range before changing any index (atomic reservation).
        for i in indices(&c.claims) {
            if d.input_assignments.get(i as usize).map(|a| &a.client) != Some(&c.client_identity)
                || d.reserved_indices[i as usize].is_some()
            {
                return Err(err(AUTH, "capability range is not assigned to this client"));
            }
        }
        for i in indices(&c.claims) {
            d.browser_reserve_index(c.client_identity.clone(), i)
                .await?;
        }
        mutations
            .entries
            .insert(c.replay_key, ReplayState::Reserved(c.claims));
        Ok(answer)
    }

    async fn submit_masked_inputs(
        &self,
        capability: String,
        origin: String,
        masked_inputs: Vec<SerializedBytes>,
    ) -> RpcResult<()> {
        let c = self.verify(&capability, &origin)?;
        if masked_inputs.len() as u64 != c.claims.input_count {
            return Err(err(AUTH, "masked input count does not match capability"));
        }
        let mut mutations = self.mutations.lock().await;
        match mutations.entries.get(&c.replay_key) {
            Some(ReplayState::Submitted(claims, prior)) if claims == &c.claims => {
                return if prior == &masked_inputs {
                    Ok(())
                } else {
                    Err(err(REPLAY, "conflicting masked-input replay"))
                };
            }
            Some(ReplayState::Reserved(claims)) if claims == &c.claims => {}
            Some(_) => return Err(err(REPLAY, "conflicting capability replay")),
            None => return Err(err(STATE, "input range has not been reserved")),
        }

        let mut values = Vec::with_capacity(masked_inputs.len());
        for input in &masked_inputs {
            let bytes = input.decode()?;
            let value = S::ValueType::deserialize_compressed(bytes.as_slice())
                .map_err(|_| err(AUTH, "invalid canonical masked field bytes"))?;
            let mut canonical = Vec::new();
            value
                .serialize_compressed(&mut canonical)
                .map_err(|_| err(AUTH, "invalid canonical masked field bytes"))?;
            if canonical != bytes {
                return Err(err(AUTH, "masked field bytes are not canonical"));
            }
            values.push(value);
        }

        let mut d = self.shared.lock().await;
        if d.round != Round::InputCollection {
            return Err(err(STATE, "coordinator is not collecting inputs"));
        }
        // Validate all ownership/state before committing any value.
        for i in indices(&c.claims) {
            if d.reserved_indices[i as usize].as_ref() != Some(&c.client_identity)
                || d.masked_inputs[i as usize].is_some()
            {
                return Err(err(AUTH, "capability does not own an unsubmitted range"));
            }
        }
        for (offset, value) in values.into_iter().enumerate() {
            d.browser_submit_input(
                c.client_identity.clone(),
                c.claims.input_start_index + offset as u64,
                value,
            )
            .await?;
        }
        mutations.entries.insert(
            c.replay_key,
            ReplayState::Submitted(c.claims, masked_inputs),
        );
        Ok(())
    }

    async fn obtain_output_shares(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<Option<Vec<BrowserEncryptedOutputShare>>> {
        let c = self.verify(&capability, &origin)?;
        if !c.claims.can_obtain_output {
            return Err(err(AUTH, "capability does not authorize output"));
        }
        // Polling is deliberately read-only and does not consume or insert a ReplayKey.
        let d = self.shared.lock().await;
        let shares = d.browser_output_shares(&c.client_identity);
        if shares.len() < S::min_shares(d.browser_threshold()) {
            return Ok(None);
        }
        Ok(Some(
            shares
                .into_iter()
                .map(|(enc, ciphertext)| BrowserEncryptedOutputShare {
                    encapsulated_key: SerializedBytes::from_bytes(&enc),
                    ciphertext: SerializedBytes::from_bytes(&ciphertext),
                })
                .collect(),
        ))
    }
}

#[async_trait]
impl<F: FftField, S: ShareBound<F>> BrowserNodeRPCServer for BrowserNodeServer<F, S> {
    async fn obtain_mask_shares(
        &self,
        capability: String,
        origin: String,
    ) -> RpcResult<Option<Vec<BrowserMaskShare>>> {
        let c = self
            .verifier
            .verify(&capability, &origin, now())
            .map_err(|_| err(AUTH, "capability verification failed"))?;
        let d = self.shared.lock().await;
        let Some(shares) = d.browser_mask_shares(&c.client_identity, indices(&c.claims))? else {
            return Ok(None);
        };
        Ok(Some(
            shares
                .into_iter()
                .map(|(reserved_index, bytes)| BrowserMaskShare {
                    reserved_index,
                    share: SerializedBytes::from_bytes(&bytes),
                })
                .collect(),
        ))
    }
}
