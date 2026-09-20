# Stoffel MPC Coordinator Libraries

`stoffel-mpc-coordinator` provides coordinator primitives for Stoffel MPC workflows. It manages the full protocol lifecycle: preprocessing, input-mask reservation, input collection, MPC execution, and output distribution.

The workspace contains these libraries:

- [`stoffel-mpc-coordinator-shared`](https://crates.io/crates/stoffel-mpc-coordinator-shared): shared coordinator traits, execution identifiers, protocol rounds, RPC utilities, and test helpers.
- [`stoffel-mpc-coordinator-off-chain`](https://crates.io/crates/stoffel-mpc-coordinator-off-chain): secure JSON-RPC coordination over mutual TLS for local or non-chain deployments.
- `stoffel-mpc-coordinator-on-chain`: Ethereum smart-contract coordination via Alloy and the Stoffel Solidity bindings; currently workspace-only.
- `stoffel-mpc-coordinator-bins`: deployment and local-development binaries; currently workspace-only.

## Installation

Add the off-chain coordinator library with:

```toml
[dependencies]
stoffel-mpc-coordinator-off-chain = "0.3.0"
```

The shared crate is pulled in automatically. Depend on `stoffel-mpc-coordinator-shared = "0.3.0"` directly when implementing against transport-independent coordinator traits and types.

## Package status

Version `0.3.0` publishes the shared and off-chain libraries. It is a breaking release: `0.2.0` and `0.3.0` peers do not interoperate, and the changes are listed in [`CHANGELOG.md`](CHANGELOG.md). The on-chain and binary crates remain excluded from crates.io because they depend on pinned Stoffel Solidity SDK binding crates from Git.

## Deploying the coordinator

Start Anvil using `anvil`.

Install a mock on-chain coordinator with
`DEPLOY_SK='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' cargo run --bin deploy-contract -- --eth-node-addr ws://127.0.0.1:8545 --program program.stflb --t 1 --initial-mpc-nodes 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65 --output-clients 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`.
Deployment derives the program hash, input count, and MPC backend threshold from the compiled program manifest.

For the off-chain coordinator, generate identities using `cargo run --bin generate-ids -- ids 2 5` (output directory `ids`, 2 clients, 5 nodes).
Every program invocation needs one nonzero 256-bit execution ID shared by its coordinator, MPC
nodes, and clients. The commands below use
`0000000000000000000000000000000000000000000000000000000000000001` as a readable example;
use a freshly generated value (for example, `openssl rand -hex 32`) for each real invocation.
Then run the off-chain coordinator. It registers exactly one execution at startup — its program,
its client slot table and its admission policy — and nothing can register an execution remotely:

`cargo run --bin run-coord -- --execution-id 0000000000000000000000000000000000000000000000000000000000000001 --program program.stflb --server-cert ids/pub/coord.crt --server-key ids/priv/coord.der --t 1 --node-certs ids/pub/nodes/node0.crt,ids/pub/nodes/node1.crt,ids/pub/nodes/node2.crt,ids/pub/nodes/node3.crt,ids/pub/nodes/node4.crt --client-bindings 0=ids/pub/clients/client0.crt`

With `--program`, the client slots come from the program's IO manifest (its `client_slot`s must be
`0..k`), and the registration hash is `program_hash_of` the program bytes; `--hash <64-hex>`
registers a hash instead, with the slots given as `--client-io <inputs>:<outputs>,…`.
`--one-off` drains and exits once the retirement quorum of nodes has acknowledged the execution in
a terminal round; omit it for a standing coordinator.

Client admission is chosen per execution with `--admission`:

- `pre-registered` (the default) binds one client certificate to each slot, from
  `--client-certs <certs>` in slot order or `--client-bindings <slot>=<cert>,…`.
- `open` lets any certificate holder bind a free slot, first come, first served. Use it only where
  reaching the coordinator is already access-controlled.
- `invitation` admits only the invitee of a `SignedInvitation` from `--invitation-issuer-cert`,
  in the slot the invitation names. Invitations are signed with
  `cargo run --bin issue-invitation -- --coordinator <host:port> --coord-cert <cert> --execution-id <64-hex> --expect-program-hash <64-hex> --issuer-key <pkcs8.der> --invitee-cert <cert> --client-index <slot> --valid-for-secs <secs> --out invitation.json`.

`open` and `invitation` require `--association-deadline-secs` and `--input-deadline-secs`: an
execution whose slots are not all bound, or whose masked inputs are not all submitted, by then is
aborted.

## Library overview

This library is generic over the share type used by the underlying MPC protocol.

## Share Types

The coordinator is parameterized as `<F: FftField, S: ShareBound<F>>`, where `S` is the share type used throughout the protocol. `ShareBound<F>` bundles the constraints the coordinator places on a share:

- **`SecretSharingScheme<F>`**: exposes secret reconstruction (`recover_secret`) and share generation (`compute_shares`).
- **`CanonicalSerialize` / `CanonicalDeserialize`**: shares are transmitted as compressed bytes over JSON-RPC.
- **`Clone`, `Send`, `'static`**: required for use across async Tokio tasks.

Two concrete share types are provided. Off-chain startup selects between them from the running
program manifest when `--program` is provided:

| Manifest backend | Share type | Description |
|---|---|---|
| `honeybadger` | `RobustShare<F>` | Plain Shamir share used by HoneyBadger MPC |
| `avss` | `FeldmanShamirShare<F, G>` | Shamir share with group-element commitments for verifiable secret sharing |

To add a new share type, implement `ShareBound<F>` for it, paying particular attention to `compute_masked_input`, which subtracts a mask share from a masked input while preserving any per-share metadata.

## Protocol Rounds

Every protocol execution traverses these rounds in order:

```
Idle → Preprocessing → InputMaskReservation → InputCollection → MPCExecution → OutputDistribution → ProgramFinished
```

A voting mechanism drives all round transitions. Clients and nodes subscribe to round notifications and receive them to stay in sync.

## The `Coordinator` Trait

Both on-chain and off-chain coordinators implement `Coordinator<F, S>`, which exposes:

- **Transitioning methods**: `start_preprocessing`, `reserve_input_masks`, `collect_inputs`, `start_mpc`, `send_output`, `finalize`, `reset_coord`
- **Node methods**: `wait_for_round`, `wait_for_indices`, `wait_for_inputs`, `send_output_shares`
- **Client methods**: `reserve_mask_index`, `send_masked_input`, `obtain_outputs`

## On-Chain Coordinator

`on_chain::OnChainCoordinator<P, F, S>` integrates with the `StoffelCoordinator` Ethereum smart contract via [Alloy](https://alloy.rs). Key behaviors:

- **Role management**: contract events and calls assign roles (party, designated party) to nodes.
- **Index reservation**: clients reserve input-mask indices via contract calls; the coordinator tracks ownership through `ReservedInputEvent` events.
- **Client authentication**: clients sign a nonce with their Ethereum private key; nodes verify the signature against the Ethereum address registered in the contract, binding the client's TLS identity to its Ethereum identity.
- **Input collection**: clients submit masked inputs (`x + m`) to the contract; nodes listen for `MaskedInputEvent` and compute a share of the unmasked input by subtracting their mask share.
- **Output distribution**: output shares are HPKE-encrypted for each client and delivered via the contract.

Client identities are Ethereum `Address` values. The on-chain node-side RPC server (`on_chain::node_rpc::NodeRPCServer`) watches for `ReservedInputEvent` from the contract to learn which client holds which mask index, then serves the corresponding mask share to the authenticated client.

## Off-Chain Coordinator

The off-chain coordinator operates over JSON-RPC (WebSockets) with mutual TLS, without any blockchain dependency. It consists of two components:

- **`OffChainCoordinatorServer<C>`**: the coordinator RPC server. It is generic over the connection type `C: RPCServerConnection<Internal = CoordinatorRPCServerSharedBase>`, so developers can extend per-connection state. `OffChainCoordinatorConnection` is the ready-to-use implementation embedders serve.
- **`OffChainCoordinatorClient<F, S>`**: the RPC client used by both MPC nodes and MPC clients to communicate with the coordinator.

Key behaviors:

- **Node roster**: the coordinator is built from a `NodeRoster` of node certificates and serves it unchanged for its lifetime through `get_node_roster`. Nodes and clients connect with `CoordinatorLink`, which pins the coordinator's key and fetches and verifies the roster once.
- **Round management**: parties trigger transitions by calling `transition(Round)` over RPC; all subscribers receive the corresponding event. An execution that misses its association or input deadline ends in the terminal `Round::Aborted`.
- **Registration and admission**: an execution is registered in the coordinator's process with a client slot table and an admission policy (`PreRegistered`, `Open` or `Invitation`). Clients bind a slot with `associate_client`, keyed on their mTLS identity; node transport never lists client certificates.
- **Index reservation and input**: an admitted client reserves exactly its slot's input range during `InputMaskReservation`, and submits all of its masked inputs in one call signed with its certificate key. Reservations are broadcast to `sub_reserved_indices` subscribers, including MPC nodes.
- **Mask-share distribution**: each MPC node runs a `node_rpc::NodeRPCServer`, registers the admitted reservations it fetched with `get_client_admissions`, and delivers each mask share only to the certificate that holds its index. The client pins every node by roster membership, attributes each share to the node's roster position, and reconstructs the mask locally.
- **Output distribution**: MPC nodes HPKE-seal their output shares under the admitted client's P-256 public key, sign them, and call `send_output_shares`; the client's `obtain_output_shares` subscription receives one `SealedOutputShares` per node.
- **Bound VM IO layout**: `.stflb` bytecode can carry a client IO manifest built from `ClientStore.take_share*` and client-output calls. `run-coord --program` turns its `client_slot`s into the registration's slot table: each slot's input count fixes its input range, and its output count its output rights. Scalar IO types stay with the SDK/VM manifest and are not interpreted by the coordinator. On-chain contracts/events do not yet carry this layout metadata; equivalent Solidity support is deferred.
- **Authentication**: all connections use TLS 1.3 with mutual authentication, and every client-side connection pins its server's key. The coordinator identifies a caller by its certificate's public key.
- **Late-subscriber safety**: events and submissions recorded before a subscription opens are replayed to it, in order, before it parks for live items.

### Extending the coordinator

The off-chain coordinator is split into two RPC trait layers:

1. **`StoffelCoordinatorRPC`**: the developer-facing interface containing only the round-transition methods (`start_preprocessing`, `reserve_input_masks`, etc.). Implement this on a custom connection type to embed application logic into each transition.
2. **`CoordinatorRPCBase<F, S>`**: pre-implemented by the library, covering index reservation, input submission, output distribution, and all subscriptions.

## Common Features

- **HPKE encryption**: output shares are encrypted.
- **Threshold**: secret reconstruction requires `2t + 1` shares; both the coordinator and clients enforce this before forwarding or accepting outputs.
- **Testing utilities**: `self_signed_certs` provides `server_cert()` / `client_cert()` helpers. `setup_test()` ensures a default `rustls` crypto provider is available before tests create TLS connections.
