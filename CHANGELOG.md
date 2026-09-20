# Changelog

## 0.3.0 - Unreleased

The coordinator is now the only roster and admission authority: it serves one fixed node roster
for its lifetime, and every client joins an execution by per-execution admission instead of
being fixed in a registration or a node allowlist. This release is not published or tagged yet.

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
  `new_for_execution(NodeRoster, SpkiDer, ExecutionRegistration)` replace
  `new(n, t, initial_mpc_nodes)` and `new_for_execution(execution_id, prog_hash, n, t, ...)`.
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
- **Registration.** `ExecutionRegistration` loses `n_inputs`, `output_clients`,
  `input_assignment` and `min_output_shares`, gains `client_slots: ClientSlotTable`,
  `admission: AdmissionPolicy` and `deadlines: Option<ExecutionDeadlines>`, and no longer
  crosses the wire: the `register_execution` RPC is deleted and registration happens in the
  coordinator's process. `CoordinatorRPCServerSharedBase::register_execution` returns the
  `RegistrationNonce`, refusing with `CoordinatorError::Registration(RegistrationError)`. `open` and `invitation` admission require deadlines.
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
  (`NotPreRegistered`), 25 (`PreRegisteredSlotMismatch`), 26 (`InvitationRequired`), 27
  (`InvitationRejected`), 28 (`UnexpectedInvitation`), 29 (`UnsupportedClientKey`), 30
  (`AlreadyAssociated`), 31 (`NotAdmitted`), 32 (`ReservationOutsideAdmission`), 33
  (`AdmissionsNotFrozen`), 35 (`ExecutionAborted`), 36 (`MaskedInputTooLarge`), 37
  (`SubmissionOutsideAdmission`), 38 (`BadMaskedInputSignature`), 39 (`SealedOutputTooLarge`), 40
  (`BadOutputSignature`) and 41 (`RateLimited`). 34 is not allocated. Refusals carry their typed
  error as JSON-RPC error `data`.
- **`run-coord`.** `--initial-mpc-nodes` becomes `--node-certs <cert.der,...>`; `--n`,
  `--n-inputs`, `--output-clients` and `--backend` are removed; `--one-off <hash>,<execution-id>`
  becomes a boolean `--one-off` beside the required `--execution-id` and exactly one of
  `--program` or `--hash`. The execution is registered at startup in both modes, since a standing
  coordinator can no longer accept remote registrations. Client slots come from the program
  manifest (whose `client_slot`s must be `0..k`) or `--client-io <inputs>:<outputs>,...`, and
  admission from `--admission pre-registered|open|invitation` (default `pre-registered`) with
  `--client-certs` or `--client-bindings <slot>=<cert>,...`, or `--invitation-issuer-cert`.
  A non-empty flag the chosen admission does not read, and every registration error, exits 2.

### Added

- Added the coordinator node roster (`NodeRoster`) with a byte-exact blake3 digest, served unchanged for the process lifetime by the `get_node_roster` RPC to any mTLS caller, rate limited per caller identity.
- Added `CoordinatorLink`, which connects to a pinned coordinator and fetches and verifies the roster once.
- Added connection limits for every listener (`RpcServerLimits`): pending-handshake bounds in total and per source, a handshake timeout, per-identity and per-class connection pools, and an idle timeout for unreserved connections.
- Added per-execution client admission: an in-process `ExecutionRegistration` fixes a `ClientSlotTable` (each slot's input range and output rights) and an `AdmissionPolicy` — `PreRegistered`, `Open` or `Invitation` — and clients bind slots late with the `associate_client` RPC, keyed on their mTLS identity. Association is idempotent for an identical request and refuses with typed `AdmissionError`s, returned as JSON-RPC error `data` under stable codes.
- Added signed invitations (`SignedInvitation`, bound to one registration nonce, program, roster, slot and expiry) and the `issue-invitation` binary.
- Added `get_execution_summary` (rate limited with `get_node_roster`) and the node-only `get_client_admissions`, which serves the admission set frozen when input collection begins; `admitted_reservations` derives the mask-share reservations every node registers from it.
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
- `ExecutionRegistration` loses `n_inputs`, `output_clients`, `input_assignment` and `min_output_shares` and no longer crosses the wire; registration is in-process only and `register_execution` returns the registration nonce after ordered, typed checks (`RegistrationError`).
- Reservations and submissions must cover exactly the caller's admitted range in one call; submissions carry the first index and a signature. Output delivery, reservation and submission streams and `sub_round` are gated on node membership or admission, and no subscription or broadcast awaits a send while holding the coordinator state mutex.
- One-off coordinators drain once the retirement quorum has acknowledged a terminal round (`watch_for_retirement_quorum`), instead of on a designated party's shutdown request.
- `run-coord` registers its execution at startup in both modes and takes `--execution-id`, `--program` or `--hash`, `--node-certs`, `--client-io`, `--admission`, `--client-certs`, `--client-bindings`, `--invitation-issuer-cert`, the deadline flags and `--max-connections`.

### Removed

- Removed the `register_execution`, `request_shutdown`, `available_input_masks`, `reserve_mask_index`, `submit_masked_input`, `sub_assigned_reserved_indices` and `sub_assigned_masked_inputs` RPC methods, `InputAssignment`, `InputClientRange`, `InputSlotAssignment`, `AssignedMaskedInputEvent`, and the node listener's unassigned `add_reserved_index(es)_for_execution`.
- Retired error codes 1, 3, 4, 7, 11, 13, 15, 17, 18 and 19.

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
