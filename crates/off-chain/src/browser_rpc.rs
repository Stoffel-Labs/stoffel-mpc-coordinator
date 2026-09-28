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
    /// WebAuthn's `credential.rawId` - optional (older cached browser sessions predate
    /// this field), used as a fast-path lookup key into `CoordinatorBrowserState`'s
    /// `credential_id_index` before falling back to the roster scan. Empty means "no
    /// index lookup, go straight to the scan," same as a genuinely absent field would.
    #[serde(default)]
    credential_id: Vec<u8>,
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
/// `by_token` is deliberately not scoped to one execution id: the bound
/// identity itself is what's checked against each execution's own admitted
/// roster downstream (`output_clients.contains`/`input_slot_client`,
/// unchanged), so one binding is reusable across every execution the
/// session subsequently interacts with. Scoped to this coordinator
/// process's lifetime for now; an idle-timeout eviction policy is a
/// reasonable future addition, not implemented yet.
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
    /// Kept in sync with `by_token`, keyed by `(execution_id,
    /// client_identity)` rather than identity alone - unlike `by_token`,
    /// this one *is* execution-scoped, deliberately, and has to be: the
    /// same registered identity can legitimately bind into several
    /// different concurrently-running executions, each with its own
    /// ephemeral ECDH key, and each execution's later output-encryption
    /// lookup needs *its own* key back, not whichever execution that
    /// identity happened to bind into most recently. (Keying by identity
    /// alone here previously meant two elections sharing a voter could
    /// silently steal each other's output-encryption target - the second
    /// bind's key would overwrite the first's, and the first election
    /// would go on to encrypt output for a key the voter's first tab never
    /// held the private half of, breaking decryption client-side with a
    /// generic WebCrypto `OperationError`.) A same-execution rebind (e.g.
    /// after a tab close/reload, reusing the same cached ephemeral keys)
    /// still just overwrites its own entry with an identical value, so
    /// that case is unaffected.
    by_execution_and_client_identity: HashMap<(ExecutionId, ClientIdentity), WebauthnBinding>,
}

impl WebauthnBindings {
    /// `execution_id` is `None` for the party-side call site specifically:
    /// a party's own `WebauthnBindings` instance never has
    /// `resolve_ecdh_public_key` called against it (only the coordinator's
    /// does, via `resolve_output_encryption_key` - see the struct doc), so
    /// there's nothing to scope there and no `ExecutionId` to thread
    /// through `BindWebauthnIdentityToNode`'s wire format for it.
    fn insert(&mut self, execution_id: Option<ExecutionId>, binding: WebauthnBinding) -> String {
        loop {
            let mut token_bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut token_bytes);
            let token = URL_SAFE_NO_PAD.encode(token_bytes);
            if let Entry::Vacant(entry) = self.by_token.entry(token.clone()) {
                if let Some(execution_id) = execution_id {
                    self.by_execution_and_client_identity
                        .insert((execution_id, binding.client_identity.clone()), binding.clone());
                }
                entry.insert(binding);
                return token;
            }
        }
    }

    /// The session-bound ECDH public key output shares for `execution_id`
    /// should be HPKE-encrypted to for `client_id`, if a WebAuthn binding
    /// exists for that exact pair - see `resolve_output_encryption_key`'s
    /// doc for the fallback when this returns `None`.
    pub(crate) fn resolve_ecdh_public_key(
        &self,
        execution_id: ExecutionId,
        client_id: &ClientIdentity,
    ) -> Option<Vec<u8>> {
        self.by_execution_and_client_identity
            .get(&(execution_id, client_id.clone()))
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

/// Params for `browser_round` - deliberately just the execution id, no
/// `SignedBrowserRequest` wrapper. See that method's registration for why
/// it's the one `browser_*` RPC that doesn't require authentication.
#[derive(Clone, Debug, Deserialize)]
struct PublicRoundQuery {
    execution_id: ExecutionId,
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
    /// Global, static credential-ID -> registered-public-key catalog, loaded once at
    /// startup from files already synced to this coordinator (see `load_credential_id_index`).
    /// Lets `browser_bind_webauthn_identity` look a claimed credential up directly instead
    /// of scanning every roster-admitted candidate - see that handler for the roster
    /// re-check this index's global (not per-execution) scope still requires.
    credential_id_index: HashMap<Vec<u8>, ClientIdentity>,
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

/// Loads the coordinator's global credential-ID -> registered-public-key catalog from two
/// already-synced directories: `client_credential_id_dir` holds one `{client_name}.id` file
/// per registered voter (raw WebAuthn `credential.rawId` bytes - see
/// `materialize-registered-clients`), and `client_cert_dir` holds the matching
/// `{client_name}.crt` (the same raw SEC1 public key file StoffelVM's `StandingClientCatalog`
/// already loads party-side). A missing `client_credential_id_dir` yields an empty index, not
/// an error - the coordinator falls back to its existing roster-scan for every client in that
/// case, so nothing breaks for a deployment that hasn't materialized any `.id` files yet. A
/// `.id` file with no matching `.crt` is skipped, not fatal, for the same reason.
fn load_credential_id_index(
    client_cert_dir: &std::path::Path,
    client_credential_id_dir: &std::path::Path,
) -> std::io::Result<HashMap<Vec<u8>, ClientIdentity>> {
    let mut index = HashMap::new();

    let entries = match std::fs::read_dir(client_credential_id_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(index),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("id") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let credential_id = std::fs::read(&path)?;

        let cert_path = client_cert_dir.join(format!("{stem}.crt"));
        let public_key = match std::fs::read(&cert_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };

        index.insert(credential_id, public_key);
    }

    Ok(index)
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
///
/// `client_credential_id_dirs`, if given, is `(client_cert_dir, client_credential_id_dir)` -
/// see `load_credential_id_index`. `None` (or any I/O error loading it) just falls back to an
/// empty index, logged via `tracing::warn!` rather than failing startup - every bind still
/// works via the existing roster scan either way.
pub async fn coordinator_browser_methods(
    coordinator: Arc<Mutex<CoordinatorRPCServerSharedBase>>,
    rp_id: &str,
    client_credential_id_dirs: Option<(&std::path::Path, &std::path::Path)>,
) -> Methods {
    // Share `coordinator`'s own webauthn_bindings, not a fresh table - see
    // CoordinatorRPCServerSharedBase::webauthn_bindings's doc for why: a
    // party resolving a client's session-bound encryption key (via
    // `resolve_output_encryption_key`) needs to see the exact same bindings
    // this listener's `browser_bind_webauthn_identity` creates.
    let bindings = coordinator.lock().await.webauthn_bindings.clone();
    let credential_id_index = match client_credential_id_dirs {
        Some((client_cert_dir, client_credential_id_dir)) => {
            match load_credential_id_index(client_cert_dir, client_credential_id_dir) {
                Ok(index) => index,
                Err(error) => {
                    tracing::warn!(
                        "failed to load the credential-ID index from {}: {error} - \
                         falling back to the roster scan for every bind",
                        client_credential_id_dir.display(),
                    );
                    HashMap::new()
                }
            }
        }
        None => HashMap::new(),
    };
    let state = Arc::new(CoordinatorBrowserState {
        coordinator,
        nonces: Mutex::new(NonceBook::default()),
        bindings,
        rp_id_hash: Sha256::digest(rp_id.as_bytes()).into(),
        origin: format!("https://{rp_id}"),
        credential_id_index,
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

    // Intentionally unauthenticated, unlike every other browser_* method here - it
    // returns only the coarse Round an execution is in (Idle/.../ProgramFinished), no
    // per-client fields, no vote content. Anyone who already has the execution_id (e.g.
    // from the vote link) has strictly more access elsewhere in this system's trust
    // model already, so this doesn't grant a new privilege. Exists so a page with no
    // WebAuthn-bound identity of its own (e.g. the operator's start.js) can still tell
    // when an execution it started has finished. Confirmed unused by any current JS
    // client before removing its auth requirement.
    module
        .register_async_method::<RpcResult<Round>, _, _>(
            "browser_round",
            |params, state, _| async move {
                let call: PublicRoundQuery = params.one()?;
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

                // Fast path: `credential_id_index` is a *global* catalog (every registered
                // voter, across every execution), so a hit there still has to be re-checked
                // against *this* execution's roster before it means anything - unlike a
                // candidate found via the scan below, which is only ever drawn from the
                // roster in the first place. Falls through to the full scan whenever this
                // doesn't produce a match: an empty `call.credential_id` (older cached
                // sessions predate that field), a credential not yet in the index (registered
                // before this feature existed), an indexed key not on this roster, or an
                // indexed key that's on the roster but whose assertion somehow doesn't verify.
                let indexed_match = (!call.credential_id.is_empty())
                    .then(|| state.credential_id_index.get(&call.credential_id))
                    .flatten()
                    .filter(|candidate| candidates.contains(*candidate))
                    .filter(|candidate| {
                        verify_webauthn_assertion(
                            &call.assertion,
                            candidate,
                            &state.rp_id_hash,
                            &state.origin,
                            &challenge,
                        )
                        .is_ok()
                    })
                    .cloned();

                let client_identity = match indexed_match {
                    Some(client_identity) => client_identity,
                    None => candidates
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
                        .ok_or_else(|| auth_error("WebAuthn assertion did not match any registered identity admitted for this execution"))?,
                };
                drop(coordinator);

                let session_token = state.bindings.lock().await.insert(
                    Some(call.execution_id),
                    WebauthnBinding {
                        client_identity: client_identity.clone(),
                        ecdsa_public_key: call.ecdsa_public_key,
                        ecdh_public_key: call.ecdh_public_key,
                    },
                );
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
                // None: a party's own WebauthnBindings never has resolve_ecdh_public_key
                // called against it - see the struct's doc.
                let session_token = state.bindings.lock().await.insert(
                    None,
                    WebauthnBinding {
                        client_identity: call.client_identity.clone(),
                        ecdsa_public_key: call.ecdsa_public_key,
                        ecdh_public_key: call.ecdh_public_key,
                    },
                );
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

    /// Creates two uniquely-named, empty temp directories - (cert_dir, credential_id_dir) -
    /// for `load_credential_id_index` tests. No `tempfile` crate dependency: a nanosecond
    /// timestamp under `std::env::temp_dir()` is unique enough for this file's own test run.
    fn temp_catalog_dirs(test_name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("stoffel-coord-test-{test_name}-{unique}"));
        let cert_dir = base.join("cert_dir");
        let credential_id_dir = base.join("credential_id_dir");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::create_dir_all(&credential_id_dir).unwrap();
        (cert_dir, credential_id_dir)
    }

    #[test]
    fn load_credential_id_index_builds_map_from_matching_cert_and_id_files() {
        let (cert_dir, credential_id_dir) = temp_catalog_dirs("builds-map");
        std::fs::write(cert_dir.join("alice.crt"), [0x04u8; 65]).unwrap();
        std::fs::write(credential_id_dir.join("alice.id"), b"alice-credential-id").unwrap();

        let index = load_credential_id_index(&cert_dir, &credential_id_dir).unwrap();

        assert_eq!(index.len(), 1);
        assert_eq!(
            index.get(b"alice-credential-id".as_slice()),
            Some(&vec![0x04u8; 65])
        );
    }

    #[test]
    fn load_credential_id_index_skips_id_files_with_no_matching_cert() {
        let (cert_dir, credential_id_dir) = temp_catalog_dirs("skips-unmatched");
        std::fs::write(credential_id_dir.join("alice.id"), b"alice-credential-id").unwrap();

        let index = load_credential_id_index(&cert_dir, &credential_id_dir).unwrap();

        assert!(index.is_empty());
    }

    #[test]
    fn load_credential_id_index_returns_empty_for_a_missing_directory() {
        let (cert_dir, credential_id_dir) = temp_catalog_dirs("missing-dir");
        std::fs::remove_dir(&credential_id_dir).unwrap();

        let index = load_credential_id_index(&cert_dir, &credential_id_dir).unwrap();

        assert!(index.is_empty());
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
        let token = bindings.insert(
            Some(execution_id()),
            WebauthnBinding {
                client_identity: stable_identity.clone(),
                ecdsa_public_key: ecdsa_public_key.clone(),
                ecdh_public_key: vec![7],
            },
        );
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
        let token = bindings.insert(
            Some(execution_id()),
            WebauthnBinding {
                client_identity: vec![42],
                ecdsa_public_key: bound_public_key,
                ecdh_public_key: vec![7],
            },
        );
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

    /// Builds the params jsonrpsee's `Methods::call` needs for
    /// `browser_bind_webauthn_identity`, matching the browser client's own wire shape
    /// exactly (see `BindWebauthnIdentity`/`WebauthnAssertion`) - constructed as raw JSON
    /// since neither struct derives `Serialize` (they're wire-*input* types only).
    fn bind_params(
        assertion: &WebauthnAssertion,
        ecdsa_public_key: &[u8],
        ecdh_public_key: &[u8],
        credential_id: &[u8],
    ) -> serde_json::Value {
        serde_json::json!({
            "execution_id": execution_id().as_bytes(),
            "assertion": {
                "authenticator_data": assertion.authenticator_data,
                "client_data_json": assertion.client_data_json,
                "signature": assertion.signature,
            },
            "ecdsa_public_key": ecdsa_public_key,
            "ecdh_public_key": ecdh_public_key,
            "credential_id": credential_id,
        })
    }

    #[tokio::test]
    async fn bind_uses_the_credential_id_index_for_an_on_roster_identity() {
        let signing_key = test_signing_key();
        let on_roster_public_key = VerifyingKey::from(&signing_key).to_sec1_bytes().to_vec();
        let shared = Arc::new(Mutex::new(coordinator_with_two_browser_clients(
            on_roster_public_key.clone(),
            vec![21],
        )));

        let (cert_dir, credential_id_dir) = temp_catalog_dirs("indexed-hit-accepted");
        std::fs::write(cert_dir.join("voter.crt"), &on_roster_public_key).unwrap();
        std::fs::write(credential_id_dir.join("voter.id"), b"voter-credential-id").unwrap();

        let methods =
            coordinator_browser_methods(shared, TEST_RP_ID, Some((&cert_dir, &credential_id_dir)))
                .await;

        let ecdsa_public_key = b"ecdsa-pub".to_vec();
        let ecdh_public_key = b"ecdh-pub".to_vec();
        let challenge = webauthn_bind_challenge(&ecdsa_public_key, &ecdh_public_key);
        let assertion = make_assertion(&signing_key, &challenge);
        let params = bind_params(
            &assertion,
            &ecdsa_public_key,
            &ecdh_public_key,
            b"voter-credential-id",
        );

        // WebauthnBindingResponse only derives Serialize (it's an output-only wire type,
        // the server never parses one back in) - a plain Value avoids adding a
        // test-only Deserialize derive to a production type just for this.
        let response: serde_json::Value = methods
            .call("browser_bind_webauthn_identity", (params,))
            .await
            .expect("an indexed, on-roster credential must be able to bind");
        let resolved_identity: Vec<u8> = serde_json::from_value(response["client_identity"].clone())
            .expect("client_identity field");
        assert_eq!(resolved_identity, on_roster_public_key);
    }

    #[tokio::test]
    async fn bind_rejects_a_globally_indexed_credential_not_on_this_executions_roster() {
        // Registered somewhere on this deployment (has a credential-ID index entry) but
        // never admitted to *this* execution's roster - the exact scenario the roster
        // re-check after an index hit exists to catch (see the handler's own comment).
        let intruder_signing_key = SigningKey::from_bytes(&[77u8; 32].into()).unwrap();
        let intruder_public_key = VerifyingKey::from(&intruder_signing_key)
            .to_sec1_bytes()
            .to_vec();
        let shared = Arc::new(Mutex::new(coordinator_with_two_browser_clients(
            vec![20],
            vec![21],
        )));

        let (cert_dir, credential_id_dir) = temp_catalog_dirs("off-roster-rejected");
        std::fs::write(cert_dir.join("intruder.crt"), &intruder_public_key).unwrap();
        std::fs::write(credential_id_dir.join("intruder.id"), b"intruder-credential-id").unwrap();

        let methods =
            coordinator_browser_methods(shared, TEST_RP_ID, Some((&cert_dir, &credential_id_dir)))
                .await;

        let ecdsa_public_key = b"ecdsa-pub".to_vec();
        let ecdh_public_key = b"ecdh-pub".to_vec();
        let challenge = webauthn_bind_challenge(&ecdsa_public_key, &ecdh_public_key);
        let assertion = make_assertion(&intruder_signing_key, &challenge);
        let params = bind_params(
            &assertion,
            &ecdsa_public_key,
            &ecdh_public_key,
            b"intruder-credential-id",
        );

        let result: Result<serde_json::Value, _> = methods
            .call("browser_bind_webauthn_identity", (params,))
            .await;
        assert!(
            result.is_err(),
            "a globally-indexed but off-roster identity must not be able to bind, got {result:?}",
        );
    }

    #[test]
    fn resolve_ecdh_public_key_is_scoped_by_execution_not_just_identity() {
        let mut bindings = WebauthnBindings::default();
        let identity: ClientIdentity = vec![42];
        let exec_a = ExecutionId::from_bytes([1; 32]);
        let exec_b = ExecutionId::from_bytes([2; 32]);

        // The same registered voter binds into two different, concurrently-running
        // executions - this is exactly the "several elections at once" scenario that used
        // to silently let the second bind steal the first execution's output-encryption
        // target, since the old by_client_identity map was keyed by identity alone.
        bindings.insert(
            Some(exec_a),
            WebauthnBinding {
                client_identity: identity.clone(),
                ecdsa_public_key: vec![0xA1],
                ecdh_public_key: vec![0xA; 65],
            },
        );
        bindings.insert(
            Some(exec_b),
            WebauthnBinding {
                client_identity: identity.clone(),
                ecdsa_public_key: vec![0xB1],
                ecdh_public_key: vec![0xB; 65],
            },
        );

        assert_eq!(
            bindings.resolve_ecdh_public_key(exec_a, &identity),
            Some(vec![0xA; 65]),
            "execution A must still resolve its own key, not execution B's",
        );
        assert_eq!(
            bindings.resolve_ecdh_public_key(exec_b, &identity),
            Some(vec![0xB; 65]),
            "execution B must resolve its own key",
        );
    }

    #[test]
    fn insert_without_an_execution_id_does_not_populate_the_secondary_index() {
        let mut bindings = WebauthnBindings::default();
        let identity: ClientIdentity = vec![42];
        let exec_a = ExecutionId::from_bytes([1; 32]);

        // The party-side call site - see insert()'s own doc for why None is correct there.
        bindings.insert(
            None,
            WebauthnBinding {
                client_identity: identity.clone(),
                ecdsa_public_key: vec![0xA1],
                ecdh_public_key: vec![0xA; 65],
            },
        );

        assert_eq!(bindings.resolve_ecdh_public_key(exec_a, &identity), None);
    }
}
