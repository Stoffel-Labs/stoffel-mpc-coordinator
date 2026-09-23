//! Polling JSON-RPC methods for browser clients, served over ordinary server-authenticated TLS
//! (see `stoffel_mpc_coordinator_shared::rpc::start_coord_browser_tls`) instead of the mutual
//! TLS the rest of this crate uses.
//!
//! The native transport authenticates a client once per connection, at the TLS handshake, by
//! requiring and verifying a client certificate. A browser's `WebSocket` API has no equivalent:
//! there is no way for page script to present a TLS client certificate. So instead, every
//! method here takes a `SignedBrowserRequest` and authenticates it individually, at the
//! application layer: the browser signs `method || execution_id || nonce || sha256(body)` with
//! a P-256 keypair it fully controls (see the `stoffel-wasm-client` crate), and `authenticate`
//! verifies that signature and rejects any reused nonce. The resulting `ClientIdentity` is
//! exactly the same kind of value the native path derives from a certificate -- the DER-encoded
//! public key -- so it plugs directly into the same `CoordinatorRPCServerConnectionBase`/
//! `CoordinatorRPCServerSharedBase` state the native transport uses. Confidentiality and server
//! authentication come from the TLS layer underneath, same as any ordinary `wss://` site;
//! client authentication comes from this module instead of from the handshake.

use crate::{
    node_rpc::NodeRPCServerInternal, AssignedMaskShare, ClientIdentity, CoordinatorRPCBaseServer,
    CoordinatorRPCServerConnectionBase, CoordinatorRPCServerSharedBase, Round,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonrpsee::{
    core::RpcResult,
    server::{Methods, RpcModule},
    types::ErrorObjectOwned,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use stoffel_mpc_coordinator_shared::ExecutionId;
use tokio::sync::Mutex;

const AUTH_DOMAIN: &[u8] = b"stoffel-browser-rpc-auth-v1";
const AUTH_ERROR: i32 = -32050;
const BAD_BODY: i32 = -32602;

#[derive(Clone, Debug, Deserialize)]
struct SignedBrowserRequest {
    public_key: Vec<u8>,
    nonce: u64,
    signature: Vec<u8>,
    body: Vec<u8>,
    /// Present for the WebAuthn session-key path (see `WebauthnBindings`
    /// below): `public_key` above is then the freshly-generated ephemeral
    /// key that actually produced `signature`, not a registered identity in
    /// its own right - `session_token` is what `authenticate` looks up to
    /// find which registered identity that ephemeral key was bound to.
    /// Absent (the original, unmodified behavior) for the native
    /// `from_pkcs8` path, where the signing key *is* the identity directly.
    #[serde(default)]
    session_token: Option<String>,
}

/// One WebAuthn assertion (the response of a `navigator.credentials.get()`
/// call), in the byte layout the browser client library sends: raw bytes
/// exactly as the corresponding `AuthenticatorAssertionResponse` fields,
/// with no base64 encoding needed over the JSON-RPC transport (`Vec<u8>`
/// already round-trips as a plain byte array, same convention as
/// `SignedBrowserRequest`'s other byte fields).
#[derive(Clone, Debug, Deserialize)]
struct WebauthnAssertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    /// DER-encoded ECDSA-P256-SHA256, per the WebAuthn spec - unlike the
    /// raw `r || s` this file's own `SignedBrowserRequest` signatures use.
    signature: Vec<u8>,
}

/// Request body for `browser_bind_webauthn_identity` - see its handler for
/// the full ceremony this authorizes.
#[derive(Clone, Debug, Deserialize)]
struct BindWebauthnIdentity {
    execution_id: ExecutionId,
    assertion: WebauthnAssertion,
    /// The freshly-generated, non-extractable ECDSA key that will sign
    /// every subsequent `browser_*` request for this session.
    ecdsa_public_key: Vec<u8>,
    /// The freshly-generated, non-extractable ECDH key output shares will
    /// be HPKE-encrypted to for this session.
    ecdh_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
struct WebauthnBindingResponse {
    session_token: String,
    /// The registered identity the WebAuthn assertion resolved to - not
    /// otherwise learnable by the browser client (it only knows its own
    /// WebAuthn credential, not which roster entry it matched). Needed so
    /// the same client can bind to each *node* it talks to directly too
    /// (`browser_bind_webauthn_identity` on the node side, see
    /// `BindWebauthnIdentityToNode`'s doc) - each node's `WebauthnBindings`
    /// is independent of the coordinator's, and unlike the coordinator, a
    /// node has no roster of its own to resolve this from a scan.
    client_identity: ClientIdentity,
}

#[derive(Clone, Debug)]
pub(crate) struct WebauthnBinding {
    pub(crate) client_identity: ClientIdentity,
    pub(crate) ecdsa_public_key: Vec<u8>,
    pub(crate) ecdh_public_key: Vec<u8>,
}

/// Session-scoped WebAuthn identity bindings - one WebAuthn ceremony (see
/// `browser_bind_webauthn_identity`) authorizes a freshly-generated
/// ephemeral key pair to act as a registered identity for every subsequent
/// signed request that presents the returned `session_token`
/// (`SignedBrowserRequest::session_token`, checked in `authenticate`).
/// Deliberately not scoped to one execution id: the bound identity itself
/// is what's checked against each execution's own admitted roster
/// downstream (`output_clients.contains`/`input_slot_client`, unchanged),
/// so one binding is reusable across every execution the session
/// subsequently interacts with. Scoped to this coordinator process's
/// lifetime for now; an idle-timeout eviction policy is a reasonable
/// future addition, not implemented yet.
///
/// `pub(crate)`, not private to this module: `CoordinatorRPCServerSharedBase`
/// (in `lib.rs`) holds a `webauthn_bindings: Arc<Mutex<WebauthnBindings>>` -
/// the *same* instance `coordinator_browser_methods` below populates - so
/// that `send_output_shares`'s `resolve_output_encryption_key` can read a
/// client's session-bound `ecdh_public_key` too. A party is a separate
/// process from the coordinator (see that method's doc), so this can't be
/// solved by just handing it a reference; the RPC method is what a party
/// actually calls, but it needs somewhere shared to read from once it's on
/// the coordinator side of that call.
#[derive(Default)]
pub(crate) struct WebauthnBindings {
    by_token: HashMap<String, WebauthnBinding>,
    /// Kept in sync with `by_token`, keyed the other way - a client
    /// re-binding (e.g. after a tab close/reload) overwrites the previous
    /// entry here, which is the desired behavior: encrypt future output to
    /// whichever session the client's browser currently actually holds the
    /// private half of, not a stale earlier one.
    by_client_identity: HashMap<ClientIdentity, WebauthnBinding>,
}

impl WebauthnBindings {
    fn insert(&mut self, binding: WebauthnBinding) -> String {
        loop {
            let mut token_bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut token_bytes);
            let token = URL_SAFE_NO_PAD.encode(token_bytes);
            if let Entry::Vacant(entry) = self.by_token.entry(token.clone()) {
                self.by_client_identity
                    .insert(binding.client_identity.clone(), binding.clone());
                entry.insert(binding);
                return token;
            }
        }
    }

    /// The session-bound ECDH public key output shares should be
    /// HPKE-encrypted to for `client_id`, if a WebAuthn binding exists for
    /// it - see `resolve_output_encryption_key`'s doc for the fallback
    /// when this returns `None`.
    pub(crate) fn resolve_ecdh_public_key(&self, client_id: &ClientIdentity) -> Option<Vec<u8>> {
        self.by_client_identity
            .get(client_id)
            .map(|binding| binding.ecdh_public_key.clone())
    }

    fn get(&self, token: &str) -> Option<&WebauthnBinding> {
        self.by_token.get(token)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct BrowserCall {
    execution_id: ExecutionId,
    request: SignedBrowserRequest,
}

#[derive(Clone, Debug, Deserialize)]
struct MaskRange {
    start: u64,
    count: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct MaskedInputBatch {
    reserved_indices: Vec<u64>,
    masked_inputs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
struct BrowserExecutionStatus {
    round: Round,
    input_indices: Vec<u64>,
    total_inputs: u64,
    reserved_inputs: u64,
    submitted_inputs: u64,
    total_clients: u64,
    submitted_clients: u64,
    own_input_reserved: bool,
    own_input_submitted: bool,
    output_ready: bool,
}

#[derive(Default)]
struct NonceBook {
    latest: HashMap<(ExecutionId, ClientIdentity), u64>,
}

impl NonceBook {
    fn accept(
        &mut self,
        execution_id: ExecutionId,
        identity: &ClientIdentity,
        nonce: u64,
    ) -> RpcResult<()> {
        let key = (execution_id, identity.clone());
        if self
            .latest
            .get(&key)
            .is_some_and(|latest| nonce <= *latest)
        {
            return Err(auth_error("request nonce was already used"));
        }
        self.latest.insert(key, nonce);
        Ok(())
    }
}

struct CoordinatorBrowserState {
    coordinator: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    nonces: Mutex<NonceBook>,
    /// The *same* instance as `coordinator`'s own `webauthn_bindings` field
    /// (an `Arc` clone, not a separate table) - see that field's doc.
    bindings: Arc<Mutex<WebauthnBindings>>,
    /// SHA-256 of the relying party ID (the site's own hostname) - checked
    /// against `authenticatorData`'s `rpIdHash` on every WebAuthn bind.
    rp_id_hash: [u8; 32],
    /// Checked against `clientDataJSON.origin` on every WebAuthn bind.
    origin: String,
}

struct NodeBrowserState {
    node: Arc<Mutex<NodeRPCServerInternal>>,
    nonces: Mutex<NonceBook>,
    bindings: Mutex<WebauthnBindings>,
    rp_id_hash: [u8; 32],
    origin: String,
}

/// Request body for a node's own `browser_bind_webauthn_identity`. Unlike
/// the coordinator's version, a node has no independently-held admission
/// roster to scan candidates from (`NodeRPCExecutionState` only tracks
/// index-to-client assignments as they happen, not a roster known up
/// front - see its doc). The browser already learned its own registered
/// identity from the coordinator's own bind response, so it's supplied
/// directly here - safely, since acceptance is still gated purely by the
/// WebAuthn assertion actually verifying against this exact claimed key,
/// not by trusting the claim itself.
#[derive(Clone, Debug, Deserialize)]
struct BindWebauthnIdentityToNode {
    client_identity: ClientIdentity,
    assertion: WebauthnAssertion,
    ecdsa_public_key: Vec<u8>,
    ecdh_public_key: Vec<u8>,
}

/// Builds the coordinator-side browser methods (`browser_execution_status`, `browser_round`,
/// `browser_reserve_mask_indices`, `browser_submit_masked_inputs`, `browser_output_shares`,
/// `browser_bind_webauthn_identity`), bound to the same shared coordinator state the native mTLS
/// transport uses. Pass the result to `stoffel_mpc_coordinator_shared::rpc::start_coord_browser_tls`.
///
/// `rp_id` is the WebAuthn relying party ID - the site's own hostname, e.g. `vote.example.com`,
/// exactly as it appears in the URL bar for every page that calls `navigator.credentials.get()`/
/// `create()`. The expected origin (`clientDataJSON.origin`, e.g. `https://vote.example.com`) is
/// derived from it as `https://{rp_id}`; pass a full custom origin string as `rp_id` is not
/// sufficient for deployments needing a non-default port or scheme (not expected in practice,
/// since WebAuthn requires a secure context - HTTPS - anyway).
pub async fn coordinator_browser_methods(
    coordinator: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    rp_id: &str,
) -> Methods {
    // Share `coordinator`'s own webauthn_bindings, not a fresh table - see
    // CoordinatorRPCServerSharedBase::webauthn_bindings's doc for why: a
    // party resolving a client's session-bound encryption key (via
    // `resolve_output_encryption_key`) needs to see the exact same bindings
    // this listener's `browser_bind_webauthn_identity` creates.
    let bindings = coordinator.lock().await.webauthn_bindings.clone();
    let state = Arc::new(CoordinatorBrowserState {
        coordinator,
        nonces: Mutex::new(NonceBook::default()),
        bindings,
        rp_id_hash: Sha256::digest(rp_id.as_bytes()).into(),
        origin: format!("https://{rp_id}"),
    });
    let mut module = RpcModule::new(state);

    module
        .register_async_method::<RpcResult<BrowserExecutionStatus>, _, _>(
            "browser_execution_status",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_execution_status", &call, &state.nonces, &state.bindings)
                        .await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_execution_status(call.execution_id, &identity)
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<Round>, _, _>(
            "browser_round",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                authenticate("browser_round", &call, &state.nonces, &state.bindings).await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_round(call.execution_id)
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<()>, _, _>(
            "browser_reserve_mask_indices",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity = authenticate(
                    "browser_reserve_mask_indices",
                    &call,
                    &state.nonces,
                    &state.bindings,
                )
                .await?;
                let indices: Vec<u64> = parse_body(&call.request.body)?;
                CoordinatorRPCServerConnectionBase::new(state.coordinator.clone(), identity)
                    .reserve_mask_indices(call.execution_id, indices)
                    .await
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<()>, _, _>(
            "browser_submit_masked_inputs",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity = authenticate(
                    "browser_submit_masked_inputs",
                    &call,
                    &state.nonces,
                    &state.bindings,
                )
                .await?;
                let batch: MaskedInputBatch = parse_body(&call.request.body)?;
                CoordinatorRPCServerConnectionBase::new(state.coordinator.clone(), identity)
                    .submit_masked_inputs(
                        call.execution_id,
                        batch.masked_inputs,
                        batch.reserved_indices,
                    )
                    .await
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<Option<Vec<(Vec<u8>, Vec<u8>)>>>, _, _>(
            "browser_output_shares",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity =
                    authenticate("browser_output_shares", &call, &state.nonces, &state.bindings)
                        .await?;
                state
                    .coordinator
                    .lock()
                    .await
                    .browser_output_shares(call.execution_id, &identity)
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<WebauthnBindingResponse>, _, _>(
            "browser_bind_webauthn_identity",
            |params, state, _| async move {
                let call: BindWebauthnIdentity = params.one()?;
                let coordinator = state.coordinator.lock().await;
                let execution = coordinator
                    .executions
                    .get(&call.execution_id)
                    .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;

                // A WebAuthn assertion binds to one specific already-known credential - this
                // is not a "try every roster entry" scan (that pattern is reserved for cases
                // with no other way to establish which identity is claimed): the assertion's
                // signature can only ever verify against the exact credential's public key,
                // so trying a candidate that isn't it just fails verification harmlessly.
                // Every distinct identity admitted anywhere in this execution's roster
                // (input-assigned or output-authorized) is a legitimate candidate, since
                // registration's own public key doubles as that identity's roster entry
                // (see the design plan's §5) - exactly the same raw SEC1 bytes the native
                // from_pkcs8 path already uses `ClientIdentity` for.
                let candidates = execution
                    .input_assignments
                    .iter()
                    .filter_map(|slot| execution.input_slot_client(slot))
                    .chain(execution.output_clients.iter())
                    .collect::<std::collections::HashSet<_>>();

                let challenge = webauthn_bind_challenge(&call.ecdsa_public_key, &call.ecdh_public_key);
                let client_identity = candidates
                    .into_iter()
                    .find(|candidate| {
                        verify_webauthn_assertion(
                            &call.assertion,
                            candidate,
                            &state.rp_id_hash,
                            &state.origin,
                            &challenge,
                        )
                        .is_ok()
                    })
                    .cloned()
                    .ok_or_else(|| auth_error("WebAuthn assertion did not match any registered identity admitted for this execution"))?;
                drop(coordinator);

                let session_token = state.bindings.lock().await.insert(WebauthnBinding {
                    client_identity: client_identity.clone(),
                    ecdsa_public_key: call.ecdsa_public_key,
                    ecdh_public_key: call.ecdh_public_key,
                });
                Ok(WebauthnBindingResponse {
                    session_token,
                    client_identity,
                })
            },
        )
        .expect("method name is unique");

    module.into()
}

/// Builds the node-side browser methods (`browser_assigned_mask_shares`,
/// `browser_bind_webauthn_identity`), bound to the same shared node state the native mTLS
/// transport uses. Pass the result to `stoffel_mpc_coordinator_shared::rpc::start_coord_browser_tls`.
/// `rp_id` - see `coordinator_browser_methods`'s doc; must be the same value passed there.
pub fn node_browser_methods(node: Arc<Mutex<NodeRPCServerInternal>>, rp_id: &str) -> Methods {
    let state = Arc::new(NodeBrowserState {
        node,
        nonces: Mutex::new(NonceBook::default()),
        bindings: Mutex::new(WebauthnBindings::default()),
        rp_id_hash: Sha256::digest(rp_id.as_bytes()).into(),
        origin: format!("https://{rp_id}"),
    });
    let mut module = RpcModule::new(state);

    module
        .register_async_method::<RpcResult<Option<Vec<AssignedMaskShare>>>, _, _>(
            "browser_assigned_mask_shares",
            |params, state, _| async move {
                let call: BrowserCall = params.one()?;
                let identity = authenticate(
                    "browser_assigned_mask_shares",
                    &call,
                    &state.nonces,
                    &state.bindings,
                )
                .await?;
                let range: MaskRange = parse_body(&call.request.body)?;
                let execution = state
                    .node
                    .lock()
                    .await
                    .execution_state(call.execution_id)
                    .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
                let result = execution
                    .lock()
                    .await
                    .assigned_mask_shares_for_client(&identity, range.start, range.count)
                    .map_err(|error| rpc_error(-32051, error.to_string()))?;
                Ok(result)
            },
        )
        .expect("method name is unique");

    module
        .register_async_method::<RpcResult<WebauthnBindingResponse>, _, _>(
            "browser_bind_webauthn_identity",
            |params, state, _| async move {
                let call: BindWebauthnIdentityToNode = params.one()?;
                let challenge =
                    webauthn_bind_challenge(&call.ecdsa_public_key, &call.ecdh_public_key);
                verify_webauthn_assertion(
                    &call.assertion,
                    &call.client_identity,
                    &state.rp_id_hash,
                    &state.origin,
                    &challenge,
                )
                .map_err(|_| {
                    auth_error("WebAuthn assertion did not verify against the claimed identity")
                })?;
                let session_token = state.bindings.lock().await.insert(WebauthnBinding {
                    client_identity: call.client_identity.clone(),
                    ecdsa_public_key: call.ecdsa_public_key,
                    ecdh_public_key: call.ecdh_public_key,
                });
                Ok(WebauthnBindingResponse {
                    session_token,
                    client_identity: call.client_identity,
                })
            },
        )
        .expect("method name is unique");

    module.into()
}

impl CoordinatorRPCServerSharedBase {
    fn browser_execution_status(
        &self,
        execution_id: ExecutionId,
        client: &ClientIdentity,
    ) -> RpcResult<BrowserExecutionStatus> {
        let execution = self
            .executions
            .get(&execution_id)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
        let input_indices = execution
            .input_assignments
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                (execution.input_slot_client(slot) == Some(client)).then_some(index as u64)
            })
            .collect::<Vec<_>>();
        let authorized_for_output = execution.output_clients.contains(client);
        if input_indices.is_empty() && !authorized_for_output {
            return Err(rpc_error(
                -32012,
                "client is not assigned an input or authorized for output",
            ));
        }
        let own_input_reserved = !input_indices.is_empty()
            && input_indices
                .iter()
                .all(|index| execution.reserved_indices[*index as usize].as_ref() == Some(client));
        let own_input_submitted = !input_indices.is_empty()
            && input_indices
                .iter()
                .all(|index| execution.masked_inputs[*index as usize].is_some());
        let output_share_count = execution
            .output_shares
            .keys()
            .filter(|(candidate, _)| candidate == client)
            .count();
        let assigned_clients = execution
            .input_assignments
            .iter()
            .filter_map(|slot| execution.input_slot_client(slot).cloned())
            .collect::<std::collections::HashSet<_>>();
        let submitted_clients = assigned_clients
            .iter()
            .filter(|candidate| {
                execution
                    .input_assignments
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| execution.input_slot_client(slot) == Some(*candidate))
                    .all(|(index, _)| execution.masked_inputs[index].is_some())
            })
            .count() as u64;
        Ok(BrowserExecutionStatus {
            round: execution.round,
            input_indices,
            total_inputs: execution.registration.n_inputs,
            reserved_inputs: execution
                .reserved_indices
                .iter()
                .filter(|owner| owner.is_some())
                .count() as u64,
            submitted_inputs: execution
                .masked_inputs
                .iter()
                .filter(|input| input.is_some())
                .count() as u64,
            total_clients: assigned_clients.len() as u64,
            submitted_clients,
            own_input_reserved,
            own_input_submitted,
            output_ready: authorized_for_output
                && output_share_count >= execution.registration.min_output_shares as usize,
        })
    }

    fn browser_round(&self, execution_id: ExecutionId) -> RpcResult<Round> {
        self.executions
            .get(&execution_id)
            .map(|execution| execution.round)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))
    }

    fn browser_output_shares(
        &self,
        execution_id: ExecutionId,
        client: &ClientIdentity,
    ) -> RpcResult<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
        let execution = self
            .executions
            .get(&execution_id)
            .ok_or_else(|| rpc_error(-32016, "execution is not registered"))?;
        if !execution.output_clients.contains(client) {
            return Err(rpc_error(-32012, "client is not authorized for output"));
        }
        let shares = execution
            .output_shares
            .iter()
            .filter(|((candidate, _), _)| candidate == client)
            .map(|(_, shares)| shares.clone())
            .collect::<Vec<_>>();
        if shares.len() < execution.registration.min_output_shares as usize {
            return Ok(None);
        }
        Ok(Some(shares))
    }
}

/// Verifies a `SignedBrowserRequest` and resolves it to a `ClientIdentity`.
///
/// Two paths, selected by whether `session_token` is present:
///
/// - **Absent** (the original, unmodified native `from_pkcs8` path): the
///   signing key *is* the identity directly, exactly as before - byte-for-
///   byte identical behavior to the pre-WebAuthn implementation.
/// - **Present** (the WebAuthn session-key path): `public_key` is a
///   freshly-generated ephemeral key, not an identity in its own right.
///   `session_token` is looked up in `bindings` to find which registered
///   identity that ephemeral key was authorized (via one WebAuthn
///   ceremony - see `browser_bind_webauthn_identity`) to act as; the
///   signature still verifies against the ephemeral `public_key` exactly
///   as in the native path, but the *returned* identity is the bound
///   registered one, not the ephemeral key itself - which is what lets
///   this plug into the existing roster checks
///   (`output_clients.contains`/`input_slot_client`) completely unchanged.
///   The signed message additionally covers `session_token` itself, so a
///   captured `{session_token, signature}` pair can't be replayed against
///   a different request (nonce/body/method are already covered below,
///   same as the native path - the token is folded in on top of that).
async fn authenticate(
    method: &str,
    call: &BrowserCall,
    nonces: &Mutex<NonceBook>,
    bindings: &Mutex<WebauthnBindings>,
) -> RpcResult<ClientIdentity> {
    let key = VerifyingKey::from_sec1_bytes(&call.request.public_key)
        .map_err(|_| auth_error("invalid P-256 public key"))?;
    let signature = Signature::from_slice(&call.request.signature)
        .map_err(|_| auth_error("invalid P-256 signature"))?;
    let message = authentication_message(
        method,
        call.execution_id,
        call.request.nonce,
        &call.request.body,
        call.request.session_token.as_deref(),
    );
    key.verify(&message, &signature)
        .map_err(|_| auth_error("request signature did not verify"))?;

    let identity = match &call.request.session_token {
        None => call.request.public_key.clone(),
        Some(token) => {
            let bindings = bindings.lock().await;
            let binding = bindings
                .get(token)
                .ok_or_else(|| auth_error("unknown or expired session token"))?;
            if binding.ecdsa_public_key != call.request.public_key {
                return Err(auth_error(
                    "session token is not bound to this signing key",
                ));
            }
            binding.client_identity.clone()
        }
    };

    nonces
        .lock()
        .await
        .accept(call.execution_id, &identity, call.request.nonce)?;
    Ok(identity)
}

fn authentication_message(
    method: &str,
    execution_id: ExecutionId,
    nonce: u64,
    body: &[u8],
    session_token: Option<&str>,
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut message = Vec::with_capacity(
        AUTH_DOMAIN.len() + method.len() + execution_id.as_bytes().len() + body_hash.len() + 10,
    );
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(execution_id.as_bytes());
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&body_hash);
    // Folded in *after* everything the native path already signs, so a
    // request with no session_token (the native path) produces byte-for-
    // byte the same message as before - this field is purely additive.
    if let Some(token) = session_token {
        message.extend_from_slice(token.as_bytes());
    }
    message
}

/// The challenge a WebAuthn bind ceremony's assertion must cover -
/// deliberately *not* a server-issued, per-attempt-random challenge (there
/// is no earlier round trip to issue one from: the bind RPC is a single
/// request). Instead it's derived from the exact ephemeral keys being
/// bound, so the assertion cryptographically commits to *those specific
/// keys* - without this, a captured assertion (e.g. an earlier legitimate
/// bind that somehow leaked) could be replayed alongside a *different*,
/// attacker-chosen key pair, binding the attacker's own keys to the
/// victim's identity. Public inputs, not secret ones - this only needs to
/// be unpredictable in the sense of "tied to this specific request," not
/// secret.
fn webauthn_bind_challenge(ecdsa_public_key: &[u8], ecdh_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"stoffel-browser-webauthn-bind-v1");
    hasher.update(ecdsa_public_key);
    hasher.update(ecdh_public_key);
    hasher.finalize().into()
}

/// Verifies one WebAuthn assertion against one candidate registered public
/// key. Deliberately minimal/hand-rolled rather than a full WebAuthn relying
/// party library: this coordinator only ever needs to verify the assertion
/// half of the ceremony (registration/attestation happens client-side, with
/// the result handed to the operator's registration endpoint - see the
/// design plan's §1), and only for ES256/P-256 credentials.
fn verify_webauthn_assertion(
    assertion: &WebauthnAssertion,
    candidate_public_key: &[u8],
    expected_rp_id_hash: &[u8; 32],
    expected_origin: &str,
    expected_challenge: &[u8; 32],
) -> Result<(), ()> {
    let client_data: serde_json::Value =
        serde_json::from_slice(&assertion.client_data_json).map_err(|_| ())?;
    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(());
    }
    if client_data.get("origin").and_then(|v| v.as_str()) != Some(expected_origin) {
        return Err(());
    }
    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(())?;
    let challenge = URL_SAFE_NO_PAD.decode(challenge_b64).map_err(|_| ())?;
    if challenge != expected_challenge {
        return Err(());
    }

    // authenticatorData layout (fixed, per the WebAuthn spec):
    // rpIdHash(32) || flags(1) || signCount(4) || ...(extensions, if any).
    if assertion.authenticator_data.len() < 37 {
        return Err(());
    }
    let rp_id_hash = &assertion.authenticator_data[0..32];
    if rp_id_hash != expected_rp_id_hash {
        return Err(());
    }
    let flags = assertion.authenticator_data[32];
    const USER_PRESENT: u8 = 0x01;
    const USER_VERIFIED: u8 = 0x04;
    if flags & USER_PRESENT == 0 || flags & USER_VERIFIED == 0 {
        return Err(());
    }

    // The assertion signs authenticatorData || SHA-256(clientDataJSON), with
    // a DER-encoded signature - both differ from this file's own raw-bytes/
    // raw-r||s conventions used elsewhere, since this half of the ceremony
    // is produced by the browser's WebAuthn implementation, not this
    // system's own signing code.
    let key = VerifyingKey::from_sec1_bytes(candidate_public_key).map_err(|_| ())?;
    let signature = Signature::from_der(&assertion.signature).map_err(|_| ())?;
    let client_data_hash = Sha256::digest(&assertion.client_data_json);
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + client_data_hash.len());
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    key.verify(&signed, &signature).map_err(|_| ())
}

fn parse_body<T: DeserializeOwned>(body: &[u8]) -> RpcResult<T> {
    serde_json::from_slice(body)
        .map_err(|error| rpc_error(BAD_BODY, format!("invalid signed request body: {error}")))
}

fn auth_error(message: impl Into<String>) -> ErrorObjectOwned {
    rpc_error(AUTH_ERROR, message)
}

fn rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, message.into(), None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionRegistration, InputAssignment, InputClientRange};
    use p256::ecdsa::{signature::Signer, SigningKey};

    fn execution_id() -> ExecutionId {
        ExecutionId::from_bytes([7; 32])
    }

    const TEST_RP_ID: &str = "vote.example.com";
    const TEST_ORIGIN: &str = "https://vote.example.com";

    fn test_rp_id_hash() -> [u8; 32] {
        Sha256::digest(TEST_RP_ID.as_bytes()).into()
    }

    /// Builds a well-formed, correctly-signed WebAuthn assertion for
    /// `signing_key`/`challenge`, with `user_present`/`user_verified` flags
    /// set - the shape `navigator.credentials.get()` would actually
    /// produce, so `verify_webauthn_assertion`'s happy path is exercised
    /// against something realistic rather than hand-waved bytes.
    fn make_assertion(signing_key: &SigningKey, challenge: &[u8; 32]) -> WebauthnAssertion {
        make_assertion_with_flags(signing_key, challenge, TEST_ORIGIN, true, true)
    }

    fn make_assertion_with_flags(
        signing_key: &SigningKey,
        challenge: &[u8; 32],
        origin: &str,
        user_present: bool,
        user_verified: bool,
    ) -> WebauthnAssertion {
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        })
        .to_string()
        .into_bytes();

        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&test_rp_id_hash());
        let mut flags = 0u8;
        if user_present {
            flags |= 0x01;
        }
        if user_verified {
            flags |= 0x04;
        }
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes()); // signCount

        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&client_data_hash);
        let signature: Signature = signing_key.sign(&signed);

        WebauthnAssertion {
            authenticator_data,
            client_data_json,
            signature: signature.to_der().to_bytes().to_vec(),
        }
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32].into()).expect("valid scalar")
    }

    #[test]
    fn authentication_message_folds_in_the_session_token_without_changing_the_native_path() {
        let native = authentication_message("browser_round", execution_id(), 4, b"body", None);
        let with_token =
            authentication_message("browser_round", execution_id(), 4, b"body", Some("tok"));
        assert_ne!(native, with_token);
        // The native (no-session-token) path is untouched - identical bytes
        // to what this function has always produced, so existing signed
        // requests from the from_pkcs8 path keep verifying unchanged.
        let native_again = authentication_message("browser_round", execution_id(), 4, b"body", None);
        assert_eq!(native, native_again);
        assert!(native.ends_with(&Sha256::digest(b"body")[..]));
    }

    #[test]
    fn webauthn_bind_challenge_is_deterministic_and_key_specific() {
        let a = webauthn_bind_challenge(b"ecdsa-key-a", b"ecdh-key-a");
        let a_again = webauthn_bind_challenge(b"ecdsa-key-a", b"ecdh-key-a");
        let b = webauthn_bind_challenge(b"ecdsa-key-b", b"ecdh-key-a");
        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }

    #[test]
    fn verify_webauthn_assertion_accepts_a_well_formed_assertion() {
        let signing_key = test_signing_key();
        let public_key = VerifyingKey::from(&signing_key).to_sec1_bytes().to_vec();
        let challenge = webauthn_bind_challenge(b"ecdsa-pub", b"ecdh-pub");
        let assertion = make_assertion(&signing_key, &challenge);
        assert!(verify_webauthn_assertion(
            &assertion,
            &public_key,
            &test_rp_id_hash(),
            TEST_ORIGIN,
            &challenge,
        )
        .is_ok());
    }

    #[test]
    fn verify_webauthn_assertion_rejects_a_signature_from_a_different_key() {
        let signing_key = test_signing_key();
        let other_key = SigningKey::from_bytes(&[11u8; 32].into()).unwrap();
        let other_public_key = VerifyingKey::from(&other_key).to_sec1_bytes().to_vec();
        let challenge = webauthn_bind_challenge(b"ecdsa-pub", b"ecdh-pub");
        let assertion = make_assertion(&signing_key, &challenge);
        // Verifying against a candidate that did NOT produce this
        // assertion must fail - this is exactly what makes trying multiple
        // roster candidates in browser_bind_webauthn_identity safe: a wrong
        // candidate can never spuriously succeed.
        assert!(verify_webauthn_assertion(
            &assertion,
            &other_public_key,
            &test_rp_id_hash(),
            TEST_ORIGIN,
            &challenge,
        )
        .is_err());
    }

    #[test]
    fn verify_webauthn_assertion_rejects_a_mismatched_challenge() {
        let signing_key = test_signing_key();
        let public_key = VerifyingKey::from(&signing_key).to_sec1_bytes().to_vec();
        let bound_challenge = webauthn_bind_challenge(b"ecdsa-pub", b"ecdh-pub");
        let different_challenge = webauthn_bind_challenge(b"attacker-ecdsa", b"attacker-ecdh");
        // Simulates an attacker replaying a captured, otherwise-valid
        // assertion alongside their own choice of ephemeral keys - this is
        // exactly the substitution attack binding the challenge to the
        // specific submitted keys exists to prevent.
        let assertion = make_assertion(&signing_key, &bound_challenge);
        assert!(verify_webauthn_assertion(
            &assertion,
            &public_key,
            &test_rp_id_hash(),
            TEST_ORIGIN,
            &different_challenge,
        )
        .is_err());
    }

    #[test]
    fn verify_webauthn_assertion_rejects_wrong_rp_id_hash_wrong_origin_and_missing_flags() {
        let signing_key = test_signing_key();
        let public_key = VerifyingKey::from(&signing_key).to_sec1_bytes().to_vec();
        let challenge = webauthn_bind_challenge(b"ecdsa-pub", b"ecdh-pub");
        let wrong_rp_id_hash = Sha256::digest(b"attacker.example.com").into();

        let assertion = make_assertion(&signing_key, &challenge);
        assert!(verify_webauthn_assertion(
            &assertion,
            &public_key,
            &wrong_rp_id_hash,
            TEST_ORIGIN,
            &challenge,
        )
        .is_err());

        let wrong_origin_assertion = make_assertion_with_flags(
            &signing_key,
            &challenge,
            "https://attacker.example.com",
            true,
            true,
        );
        assert!(verify_webauthn_assertion(
            &wrong_origin_assertion,
            &public_key,
            &test_rp_id_hash(),
            TEST_ORIGIN,
            &challenge,
        )
        .is_err());

        let not_user_verified =
            make_assertion_with_flags(&signing_key, &challenge, TEST_ORIGIN, true, false);
        assert!(verify_webauthn_assertion(
            &not_user_verified,
            &public_key,
            &test_rp_id_hash(),
            TEST_ORIGIN,
            &challenge,
        )
        .is_err());
    }

    #[tokio::test]
    async fn authenticate_resolves_the_bound_identity_for_a_session_token() {
        let signing_key = test_signing_key();
        let ecdsa_public_key = VerifyingKey::from(&signing_key)
            .to_sec1_bytes()
            .to_vec();
        let stable_identity: ClientIdentity = vec![42];
        let mut bindings = WebauthnBindings::default();
        let token = bindings.insert(WebauthnBinding {
            client_identity: stable_identity.clone(),
            ecdsa_public_key: ecdsa_public_key.clone(),
            ecdh_public_key: vec![7],
        });
        let bindings = Mutex::new(bindings);
        let nonces = Mutex::new(NonceBook::default());

        let message = authentication_message(
            "browser_round",
            execution_id(),
            1,
            b"",
            Some(token.as_str()),
        );
        let signature: Signature = signing_key.sign(&message);
        let call = BrowserCall {
            execution_id: execution_id(),
            request: SignedBrowserRequest {
                public_key: ecdsa_public_key,
                nonce: 1,
                signature: signature.to_bytes().to_vec(),
                body: Vec::new(),
                session_token: Some(token),
            },
        };

        let resolved = authenticate("browser_round", &call, &nonces, &bindings)
            .await
            .expect("valid session-bound request");
        assert_eq!(resolved, stable_identity);
    }

    #[tokio::test]
    async fn authenticate_rejects_a_signing_key_that_does_not_match_the_bound_token() {
        let bound_key = test_signing_key();
        let bound_public_key = VerifyingKey::from(&bound_key).to_sec1_bytes().to_vec();
        let attacker_key = SigningKey::from_bytes(&[13u8; 32].into()).unwrap();
        let attacker_public_key = VerifyingKey::from(&attacker_key).to_sec1_bytes().to_vec();

        let mut bindings = WebauthnBindings::default();
        let token = bindings.insert(WebauthnBinding {
            client_identity: vec![42],
            ecdsa_public_key: bound_public_key,
            ecdh_public_key: vec![7],
        });
        let bindings = Mutex::new(bindings);
        let nonces = Mutex::new(NonceBook::default());

        // Attacker holds a valid key of their own and signs correctly with
        // it, but presents someone else's session_token - the mismatch
        // between the bound key and the actual signer must be caught.
        let message = authentication_message(
            "browser_round",
            execution_id(),
            1,
            b"",
            Some(token.as_str()),
        );
        let signature: Signature = attacker_key.sign(&message);
        let call = BrowserCall {
            execution_id: execution_id(),
            request: SignedBrowserRequest {
                public_key: attacker_public_key,
                nonce: 1,
                signature: signature.to_bytes().to_vec(),
                body: Vec::new(),
                session_token: Some(token),
            },
        };

        assert!(authenticate("browser_round", &call, &nonces, &bindings)
            .await
            .is_err());
    }

    fn coordinator_with_two_browser_clients(
        client_a: ClientIdentity,
        client_b: ClientIdentity,
    ) -> CoordinatorRPCServerSharedBase {
        let mut coordinator =
            CoordinatorRPCServerSharedBase::new(3, 1, vec![vec![10], vec![11], vec![12]])
                .expect("valid topology");
        coordinator
            .register_execution(ExecutionRegistration {
                execution_id: execution_id(),
                program_hash: [9; 32],
                n_inputs: 2,
                output_clients: vec![client_a.clone(), client_b.clone()],
                input_assignment: InputAssignment {
                    clients: vec![client_a, client_b],
                    ranges: vec![
                        InputClientRange {
                            client_index: 0,
                            count: 1,
                        },
                        InputClientRange {
                            client_index: 1,
                            count: 1,
                        },
                    ],
                },
                min_output_shares: 3,
            })
            .expect("register execution");
        coordinator
            .executions
            .get_mut(&execution_id())
            .expect("execution")
            .round = Round::InputMaskReservation;
        coordinator
    }

    #[test]
    fn request_nonces_are_independent_between_executions() {
        let identity = vec![20];
        let first = ExecutionId::from_bytes([1; 32]);
        let second = ExecutionId::from_bytes([2; 32]);
        let mut nonces = NonceBook::default();

        nonces.accept(first, &identity, 1).expect("first request");
        nonces
            .accept(second, &identity, 1)
            .expect("same nonce in a different execution");
        assert!(nonces.accept(first, &identity, 1).is_err());
        nonces.accept(first, &identity, 2).expect("next request");
    }

    #[tokio::test]
    async fn two_browser_clients_are_bound_to_distinct_input_slots() {
        let client_a = vec![20];
        let client_b = vec![21];
        let shared = Arc::new(Mutex::new(coordinator_with_two_browser_clients(
            client_a.clone(),
            client_b.clone(),
        )));

        let a = CoordinatorRPCServerConnectionBase::new(shared.clone(), client_a.clone());
        let b = CoordinatorRPCServerConnectionBase::new(shared.clone(), client_b.clone());
        assert!(a
            .reserve_mask_indices(execution_id(), vec![1])
            .await
            .is_err());
        a.reserve_mask_indices(execution_id(), vec![0])
            .await
            .expect("Client A reserves its slot");
        b.reserve_mask_indices(execution_id(), vec![1])
            .await
            .expect("Client B reserves its slot");

        let coordinator = shared.lock().await;
        let a_status = coordinator
            .browser_execution_status(execution_id(), &client_a)
            .expect("Client A status");
        let b_status = coordinator
            .browser_execution_status(execution_id(), &client_b)
            .expect("Client B status");
        assert_eq!(a_status.input_indices, vec![0]);
        assert_eq!(b_status.input_indices, vec![1]);
        assert_eq!(a_status.reserved_inputs, 2);
        assert!(a_status.own_input_reserved);
        assert!(b_status.own_input_reserved);
        assert!(coordinator
            .browser_execution_status(execution_id(), &vec![99])
            .is_err());
    }
}
