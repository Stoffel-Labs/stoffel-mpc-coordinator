# Changelog

## 0.3.0 - Unreleased

The coordinator is now the only roster, admission and execution-identity authority: it serves one
fixed node roster for its lifetime, mints every execution's identity itself and publishes its
executions down to the roster, and every client joins an execution by per-execution admission
instead of being fixed in a registration or a node allowlist. This release is not published or
tagged yet.

### Breaking changes

`0.2.0` and `0.3.0` peers do not interoperate in either direction, and no compatibility shim is
offered. Upgrade coordinators, nodes and clients together.

- **Transport.** Every client-side connection pins its server: `setup_client` takes
  `&ServerPin` (`ServerPin::Exact(SpkiDer)` for the coordinator, `ServerPin::RosterNode` for a
  node RPC listener) and returns `PinnedClient`; a server presenting another key fails with
  `ServerPinMismatch`. `SelfSignedServerVerifier`, which accepted any server certificate, is
  deleted, so an unpinned `0.2.0` client cannot be built. Every listener and client is TLS 1.3
  only. Listeners refuse caller certificates with trailing bytes, unsupported key algorithms or
  non-canonical key encodings, and bound connections before and after the handshake.
- **Roster.** `CoordinatorRPCServerSharedBase::new(NodeRoster, SpkiDer)` and
  `new_for_execution(NodeRoster, SpkiDer, ExecutionRequest) -> (Self, RegisteredExecution)`
  replace `new(n, t, initial_mpc_nodes)` and
  `new_for_execution(execution_id, prog_hash, n, t, ...)`.
  `NodeRoster` is built from full certificate DER and a threshold; `n` is the number
  of certificates. Nodes are held in ascending SPKI order, so the `designated_party` events name
  is the lowest-SPKI node, not the operator's first node.
- **Topology.** `NodeRoster` refuses `t = 0` (`RosterError::ZeroThreshold`), which `0.2.0`
  accepted, and keeps the `n >= 2t + 1` bound as `RosterError::ThresholdTooLarge`. Reconstruction
  now also depends on the backend through `ShareBound::min_parties`: HoneyBadger
  (`RobustShare`) needs `n >= 3t + 1`, AVSS still needs `n >= 2t + 1`. A HoneyBadger off-chain
  client's `associate_client` refuses a roster with `2t + 1 <= n < 3t + 1` with
  `CoordinatorError::TopologyUnsupportedByBackend { n, t, required }` before sending the
  association, so a HoneyBadger deployment of that size, which `0.2.0` accepted, is now refused.
- **Registration.** The operator's half of a registration is the new `ExecutionRequest`
  `{ program_hash, entry, client_slots: ClientSlotTable, admission: AdmissionPolicy,
  deadlines: Option<ExecutionDeadlines> }`, which carries no identity;
  `ExecutionRegistration` becomes `{ execution_id, request }`, the minted identity bound to that
  request. It loses `n_inputs`, `output_clients`, `input_assignment` and `min_output_shares`, and
  the node-facing `register_execution` RPC is deleted: a node no longer registers an execution
  upwards, and the roster learns each registration from the new `sub_executions` subscription,
  which publishes `ExecutionRegistration` as its payload. An operator registers either in the
  coordinator's process or through the new `submit_execution` RPC below.
  `CoordinatorRPCServerSharedBase::register_execution(ExecutionRequest)` mints the identity and
  returns `RegisteredExecution { execution_id, registration_nonce }`, refusing with
  `CoordinatorError::Registration(RegistrationError)`. `open` admission requires deadlines, and
  an empty or over-long `entry` is `RegistrationError::EmptyEntry` / `EntryTooLong`
  (`MAX_ENTRY_NAME_BYTES`).
- **Operators.** The identities allowed to tell a coordinator what to run are a new, separate
  authorization class: `CoordinatorRPCServerSharedBase::with_operators(Vec<ClientIdentity>)`,
  fixed at startup and **empty by default**, so a coordinator configured without one accepts no
  submission. Two RPCs are gated on it, `submit_execution(ExecutionRequest) ->
  RegisteredExecution` and `abort_execution(ExecutionId)`, refused to anyone else with
  `RpcRefusal::NotOperator` (code 42); a refused submission carries the typed
  `RegistrationError` under `RegistrationRefused` (code 43). Being a roster node does not make an
  identity an operator: a node is trusted to *run* executions, not to choose them.
  `abort_execution` marks the execution aborted while its nodes are still running it and
  publishes `ExecutionNotice::Cancel` to the roster, with the new `AbortReason::OperatorRequest`
  — the only abort reason an identity rather than the clock produces. Aborting twice is accepted
  and publishes no second cancellation, and aborting an execution this coordinator does not have
  is `ExecutionNotFound`.
- **Execution identity.** `ExecutionId::new` (and `Default`) draws a nonzero identity from
  `ring::rand::SystemRandom`. Nothing outside the coordinator supplies an `ExecutionId` for a new
  execution any more.
- **Pre-registered clients.** `AdmissionPolicy::PreRegistered` holds
  `Vec<PreRegisteredClient { identity, client_slot }>` instead of `Vec<ClientIdentity>` bound by
  position: an entry names the slot it owns, so its position is free to be the execution-local
  client ordinal a node numbers its clients by, and the two need not agree. The slots named must
  be the table's slots exactly once (`PreRegisteredSlotOutOfRange`,
  `DuplicatePreRegisteredSlot`), and `UnsupportedPreRegisteredKey` and
  `DuplicatePreRegisteredClient` name a `client_slot` rather than a `client_index`.
- **Clients.** A client must `associate_client` before reserving. A reservation must name
  exactly the admitted input range (codes 31, 32), and a submission must cover that range in one
  `submit_masked_inputs(first_index, inputs, signature)` call signed by the client's key. A
  `0.2.0` client that chooses its own index window fails. Output delivery follows admissions,
  not `output_clients`: `send_output_shares` takes a `ClientIndex` and a signed `SealedOutput`,
  and `obtain_output_shares` yields one `SealedOutputShares` per node.
- **Subscriptions.** Every subscription and `sub_round` is gated on roster membership or
  admission, and `InputCollection` (and the zero-input skip) waits for every slot to be bound.
- **Rounds and events.** `Round` gains the terminal `Aborted`; `Event` gains
  `ExecutionAborted`, and `Event::MaskedInputEvent` carries one `MaskedInputSubmission`.
- **Shutdown and retention.** `request_shutdown` is deleted; a one-off coordinator drains once
  the retirement quorum has acknowledged a terminal round
  (`CoordinatorRPCServerSharedBase::watch_for_retirement_quorum` replaces
  `watch_for_shutdown_request`). An execution with output slots is removed
  `DEFAULT_OUTPUT_RETENTION` (60 s, `with_output_retention`) after unanimous retirement instead
  of at once.
- **Server API.** `OffChainCoordinatorServer::start_coord`, `start_coord_from_cert` and
  `start_coord_one_off` drop the unused `t` parameter, take `RpcServerLimits`, require
  `Internal = CoordinatorRPCServerSharedBase`, refuse a certificate whose key is not the state's
  served key, and own the deadline sweeper. `coord_shared::rpc::start_coord` takes
  `RpcServerLimits`, and `RPCServerConnection` gains `capacity_class` (with a default).
- **Client API.** `OffChainCoordinatorClient::start_rpc_client_for_execution(addr, port,
  coordinator: &SpkiDer, expected_roster_digest: Option<RosterDigest>, execution_id, cert_der,
  key_der)` replaces `(addr, port, t, n_parties, n_outputs, execution_id, cert_der, key_der)`;
  `n` and `t` come from the fetched roster. The off-chain
  `NodeRPCClient::start_rpc_client_for_execution` and the on-chain
  `NodeRPCClient::start_rpc_client` and `NodeRPCClient::start_rpc_client_from_cert` take
  `&NodeRoster` instead of `n` and `t`, and both on-chain constructors return
  `Result<Self, CoordinatorError>` instead of `Self`; the on-chain `receive_mask` takes the input
  index.
- **`CoordinatorError`** (not `#[non_exhaustive]`) changes shape: `MaskReconstructionFailed(usize)`
  becomes `MaskReconstructionFailed { index: u64 }`, naming the input index rather than a share
  count, and 18 variants are added: `ServerPinMismatch { address }`,
  `ServerCertificateMismatch`, `DuplicateNodeIdentity { address }`,
  `TooManyNodeAddresses { given, n }`, `UnexpectedRosterDigest { served, expected }`,
  `NotAssociated`, `TopologyUnsupportedByBackend { n, t, required }`,
  `SealedOutputsExceedBound { client_index, bytes, max }`, `OutputReconstructionFailed { output }`,
  `RoundNotProposable { round }`, `ExecutionAborted { execution_id, reason }`, the transparent
  wrappers `Pin(PinError)`, `Roster(RosterError)`, `Admission(AdmissionError)`,
  `Submission(SubmissionError)`, `Registration(RegistrationError)` and
  `Signature(SignatureError)`, and `Refused { refusal: RpcRefusal, message }` for refusal codes
  without typed `data`. Exhaustive matches and positional `MaskReconstructionFailed` constructors
  or patterns no longer compile, and its serialized form changes. No variant is removed.
- **`ShareBound`** gains `min_parties`, `share_id_of_position`, `share_id`, `share_degree`,
  `serialized_share_len` and `reconstruct`; shares are reconstructed by roster position.
- **Node RPC listener.** The unassigned `add_reserved_index_for_execution` and
  `add_reserved_indices_for_execution` are deleted. `OffChainNodeRPCServerError` gains
  `RangeNotAssignedToCaller = 3`, and `NodeRPCError` gains `ReservationsSealed`.
- **Error codes.** `CoordinatorRPCBaseError` retires, never to be reused, 1
  (`NotDesignatedParty`), 3 (`IndexOutOfBounds`), 4 (`BadID`), 7 (`IndexAlreadyReserved`), 11
  (`SendingFailed`), 13 (`MismatchedBatchLengths`), 15 (`UnauthorizedClientIo`), 17
  (`ExecutionAlreadyRegistered`), 18 (`ShutdownNotAccepted`) and 19 (`EmptyBatch`); adds 20
  (`AssociationClosed`), 21 (`CapacityExhausted`), 22 (`SlotOutOfRange`), 23 (`SlotTaken`), 24
  (`NotPreRegistered`), 25 (`PreRegisteredSlotMismatch`), 29 (`UnsupportedClientKey`), 30
  (`AlreadyAssociated`), 31 (`NotAdmitted`), 32 (`ReservationOutsideAdmission`), 33
  (`AdmissionsNotFrozen`), 35 (`ExecutionAborted`), 36 (`MaskedInputTooLarge`), 37
  (`SubmissionOutsideAdmission`), 38 (`BadMaskedInputSignature`), 39 (`SealedOutputTooLarge`), 40
  (`BadOutputSignature`) and 41 (`RateLimited`). 26, 27 and 28 are retired and never reused; 34
  is not allocated. Refusals carry their typed error as JSON-RPC error `data`.
- **`run-coord`.** `--initial-mpc-nodes` becomes `--node-certs <cert.der,...>`; `--n`,
  `--n-inputs`, `--output-clients`, `--backend` and `--execution-id` are removed;
  `--one-off <hash>,<execution-id>` becomes a boolean `--one-off` beside exactly one of
  `--program` or `--hash`. The coordinator mints its execution's identity and prints it as
  `Minted execution <id> (registration nonce <nonce>)`. A new `--entry <name>` (default `main`)
  names the function nodes call in the program. The execution is registered at startup in both
  modes, since a standing coordinator can no longer accept remote registrations. Client slots
  come from the program manifest (whose `client_slot`s must be `0..k`) or
  `--client-io <inputs>:<outputs>,...`, and admission from `--admission pre-registered|open`
  (default `pre-registered`) with `--client-certs` or `--client-bindings <slot>=<cert>,...`,
  either of which pre-registers in slot order.
  A non-empty flag the chosen admission does not read, and every registration error, exits 2.

### Added

- Added coordinator-minted execution identities: `ExecutionId::new` draws a nonzero 256-bit identity from `ring::rand::SystemRandom`, `register_execution` takes an id-free `ExecutionRequest` and returns the `RegisteredExecution` it minted, and `ExecutionRegistration` binds the two.
- Added the node-only `sub_executions` subscription, which publishes every execution the coordinator wants the roster to run. A subscription opens with a snapshot of every execution the coordinator still wants that node to run, as `ExecutionNotice::Prepare`, in registration order, closed by `ExecutionNotice::SnapshotComplete`, then streams later `Prepare` and `Cancel` notices; an execution registered before a node subscribed is never missed and never published twice on one subscription. The snapshot is authoritative in both directions within one run of the coordinator, so a node stops every instance *that run* admitted and the snapshot does not name — which is how it recovers a `Cancel` that an ended stream could not deliver. `ExecutionNotice::SnapshotComplete` carries a `CoordinatorIncarnation`, drawn afresh whenever the coordinator's state is constructed, and that is what bounds the reconciliation: this coordinator keeps its executions in memory only, so a restarted one's first snapshot names nothing, and a node reconciling its whole live set against it would abort every execution in flight on the roster. An instance an earlier incarnation admitted keeps running and is reported as kept; a new coordinator that wants one stopped names it in a `Cancel`, which needs no incarnation to act on. It is per node: an execution the subscriber has not itself acknowledged is still published to it after the retirement quorum and in a terminal round, so the healthy straggler the round history is kept alive for is never told to stop. `Cancel` carries the execution's `ExecutionOutcome` and is published while an aborted execution is still live. Publication never awaits a socket, so one stalled node neither blocks a registration nor delays another node; a subscriber whose queue fills has its stream closed and resubscribes. `CoordinatorLink::subscribe_executions` is the typed client.
- Added `ExecutionRequest::entry` and `run-coord --entry <name>` (default `main`): the function a node calls in the registered program, bounded by `MAX_ENTRY_NAME_BYTES`.
- Added the coordinator node roster (`NodeRoster`) with a byte-exact blake3 digest, served unchanged for the process lifetime by the `get_node_roster` RPC to any mTLS caller, rate limited per caller identity on its own token bucket (`ROSTER_READ_BURST` = 64, `ROSTER_READS_PER_MINUTE` = 240). The roster has a larger bucket than `get_execution_summary` and a separate one, because reading it is not a request a caller chooses to make: every link opened to the coordinator fetches and verifies the roster once, a client opens two links per execution and a node reopens its link whenever the connection under its subscription ends, so on a summary-sized bucket the binding constraint was the number of concurrent links rather than any abuse.
- Added `CoordinatorLink`, which connects to a pinned coordinator and fetches and verifies the roster once.
- Added connection limits for every listener (`RpcServerLimits`): pending-handshake bounds in total and per source, a handshake timeout, per-identity and per-class connection pools, and an idle timeout for unreserved connections. `max_connections_per_identity` defaults to 64, sized in concurrent executions rather than in callers: a client opens two connections per execution and a node holds one per execution plus its execution stream, and a smaller cap refused honest concurrency as a bare connection reset.
- Added per-execution client admission: a registration fixes a `ClientSlotTable` (each slot's input range and output rights) and an `AdmissionPolicy` — `PreRegistered` or `Open` — and clients bind slots late with the `associate_client` RPC, keyed on their mTLS identity. Association is idempotent for an identical request and refuses with typed `AdmissionError`s, returned as JSON-RPC error `data` under stable codes. A `PreRegistered` entry is a `PreRegisteredClient` naming the slot it owns, so a registration may list its clients in the order a node numbers them rather than in slot order.
- Added `get_execution_summary` (rate limited per caller identity, on its own bucket: `SUMMARY_READ_BURST` = 64, `SUMMARY_READS_PER_MINUTE` = 60 — the burst is sized for the executions one identity may be starting at once, since a client reads the summary once per connection it opens, and the refill is what throttles polling) and the node-only `get_client_admissions`, which serves the admission set frozen when input collection begins; `admitted_reservations` derives the mask-share reservations every node registers from it.
- Added client signatures over masked inputs and node signatures over sealed outputs (`signing` module), verified by the coordinator and by their receivers; output shares now arrive one node per message and are reconstructed by roster position.
- Added association and input deadlines with a deadline sweeper owned by every listener start, the terminal `Round::Aborted`, `Event::ExecutionAborted`, bounded memory of ended executions, and output retention after unanimous retirement.
- Added `OffChainCoordinatorConnection`, the connection type embedders serve.
- Added `NodeRPCServer::register_admitted_reservations_for_execution`, which registers an execution's complete admitted reservation set and seals it: later registrations fail with `NodeRPCError::ReservationsSealed`, and a mask request that can no longer complete (its caller holds no reservation, or an index in its range is unreserved) is dropped if parked and refused with `RangeNotAssignedToCaller` (3) afterwards.

### Changed

- Every client connection now pins its server key (`ServerPin`): the coordinator by its exact key, node RPC listeners by roster membership. A server presenting another key fails with `ServerPinMismatch`. `SelfSignedServerVerifier` is removed.
- Every listener and client is TLS 1.3 only, and every certificate identity goes through one derivation that refuses trailing bytes, unsupported key algorithms and non-canonical key encodings.
- `CoordinatorRPCServerSharedBase` is built from a `NodeRoster` and the served key, and every listener start refuses a certificate for another key.
- Node RPC clients attribute each mask share to the roster position of the node that served it and reconstruct by position.
- The node RPC listener never awaits a caller's socket while holding an execution's state lock, sends completed mask answers on their own tasks bounded by the subscription send timeout, and no longer lets a parked mask subscription keep a retired execution's state alive: retirement closes parked streams.
- `ClientIdentity` moved to the shared crate and is re-exported from the off-chain crate.
- `ExecutionRegistration` loses `n_inputs`, `output_clients`, `input_assignment` and `min_output_shares`, and becomes the minted `execution_id` bound to an `ExecutionRequest`. Registration is in-process only — the `register_execution` RPC is gone — and `register_execution` mints the identity and returns it with the registration nonce after ordered, typed checks (`RegistrationError`). `ExecutionRegistration` is now the payload `sub_executions` publishes to the roster.
- Reservations and submissions must cover exactly the caller's admitted range in one call; submissions carry the first index and a signature. Output delivery, reservation and submission streams and `sub_round` are gated on node membership or admission, and no subscription or broadcast awaits a send while holding the coordinator state mutex.
- One-off coordinators drain once the retirement quorum has acknowledged a terminal round (`watch_for_retirement_quorum`), instead of on a designated party's shutdown request.
- `run-coord` registers its execution at startup in both modes, prints the identity the coordinator minted for it, and takes `--program` or `--hash`, `--entry`, `--node-certs`, `--client-io`, `--admission`, `--client-certs`, `--client-bindings`, the deadline flags and `--max-connections`.

### Removed

- Removed `run-coord --execution-id`: the coordinator mints the identity.
- Removed the `register_execution`, `request_shutdown`, `available_input_masks`, `reserve_mask_index`, `submit_masked_input`, `sub_assigned_reserved_indices` and `sub_assigned_masked_inputs` RPC methods, `InputAssignment`, `InputClientRange`, `InputSlotAssignment`, `AssignedMaskedInputEvent`, and the node listener's unassigned `add_reserved_index(es)_for_execution`.
- Retired error codes 1, 3, 4, 7, 11, 13, 15, 17, 18, 19, 26, 27 and 28.

## 0.2.0 - 2026-08-28

### Added

- Added strict 256-bit execution identifiers for isolating coordinator runs.
- Added persistent and concurrent off-chain executions, including one-off registration and clean shutdown after `ProgramFinished`.
- Added batched input-mask reservation and masked-input submission APIs.
- Added voting-based round transitions so execution control no longer depends on one designated party.

### Changed

- Centralized package metadata and dependency versions in the workspace manifest.
- Updated the coordinator libraries to the 0.1.1 Stoffel networking, VM types, and MPC protocol crates.
- Reduced repeated client-certificate traffic and bound preprocessing masks to exact client input ranges.
- Documented the split workspace, published packages, and 0.2.0 installation paths.

### Fixed

- Fixed duplicate connections, completed subscriptions, straggling parties, and concurrent execution cleanup from blocking other coordinator work.
- Fixed input-share requests being rejected incorrectly and drained stale messages before execution state is reused.
- Made test crypto-provider initialization idempotent when another dependency has already installed Rustls's process-wide provider.

## 0.1.0 - 2026-06-22

### Added

- Initial release-prep metadata for the `stoffel-mpc-coordinator` crate.
- Coordinator trait and round model for Stoffel MPC protocol execution.
- Off-chain coordinator over secure JSON-RPC with mutual TLS.
- On-chain coordinator integration with the Stoffel coordinator smart contract via Alloy.
- Support for HoneyBadger `RobustShare` and Feldman/Shamir verifiable shares through the `ShareBound` abstraction.
- Test/deployment binaries for contract deployment, local coordinator startup, and identity generation.

### Known limitations

- crates.io publishing is blocked until the pinned Stoffel Solidity SDK binding crates are published or removed from the public dependency graph.
