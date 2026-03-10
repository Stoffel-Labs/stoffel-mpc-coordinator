# Deploying the coordinator

Start Anvil using `anvil`.

Install a mock on-chain coordinator with `cargo run --bin deploy-contract -- --eth-node-addr ws://127.0.0.1:8545 --sk 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --hash 0000000000000000000000000000000000000000000000000000000000000000 --designated-party 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --n 5 --t 1 --n-inputs 2 --initial-mpc-nodes 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65`.

Run the off-chain coordinator with `cargo run --bin run-coord -- --hash 0000000000000000000000000000000000000000000000000000000000000000 --server-cert ids/server_cert.crt --server-key ids/server_key.der --n 5 --t 1 --n-inputs 2 --initial-mpc-nodes ids/nodes/cert0.crt,ids/nodes/cert1.crt,ids/nodes/cert2.crt,ids/nodes/cert3.crt,ids/nodes/cert4.crt`.

To then execute a sample MPC program that adds two numbers using the deployed coordinator, use the `task-coord` branch in the Stoffel VM and run `docker compose build --ssh default` to build the Docker images (SSH is needed since the Solidity SDK is a private repository that we fetch via SSH). To run the computation, use `docker compose up`.

# Stoffel MPC Coordinator Library

This library provides a robust, privacy-preserving multi-party computation (MPC) coordinator, supporting both on-chain (Ethereum-based) and off-chain (local/RPC-based) deployments. It manages the full MPC workflow: input masking, collection, preprocessing, computation, and output distribution, with strong security and authentication guarantees.

## On-Chain Coordinator

The on-chain coordinator (`on_chain::OnChainCoordinator`) integrates tightly with an Ethereum smart contract (see `FakeCoordinator`). Its responsibilities and workflow include:

- **Role Management**: Uses Ethereum events and contract calls to assign roles (e.g., party, designated party) to nodes, ensuring only authorized parties participate.
- **Index Reservation**: Clients reserve input mask indices via contract calls. The coordinator listens for `ReservedInputEvent` events to track which client owns which index.
- **Client Authentication**: Clients authenticate by signing nonces; nodes verify these signatures via the smart contract, ensuring Sybil resistance and accountability.
- **Input Masking and Collection**: Each client submits a masked input (input + mask share) to the contract. The coordinator listens for `MaskedInputEvent` events and reconstructs the original input using robust secret sharing.
- **Preprocessing and MPC Rounds**: The coordinator triggers and tracks protocol rounds (preprocessing, input collection, MPC, output) via contract calls and event listeners, ensuring all parties are synchronized.
- **Output Distribution**: Output shares are encrypted for each client using HPKE (Hybrid Public Key Encryption) and sent via the contract. Clients retrieve and decrypt their shares, reconstructing the final output.
- **Security**: All communication is authenticated and encrypted. The contract enforces protocol rules and provides an auditable log of all actions.

## Off-Chain Coordinator

The off-chain coordinator (`off_chain::OffChainCoordinator`) provides similar functionality but operates entirely over secure RPC, without blockchain dependency. Its workflow includes:

- **Round Management**: Protocol rounds (preprocessing, input mask reservation, input collection, MPC, output) are managed via RPC methods and event subscriptions. The designated party triggers round transitions.
- **Index Reservation**: Clients request input mask indices from the coordinator via RPC. The coordinator assigns indices and broadcasts `ReservedInputEvent` events to all interested parties.
- **Input Masking and Collection**: Clients submit masked inputs to the coordinator, which verifies and records them. Events are broadcast to notify all parties of new masked inputs.
- **Mask Share Distribution**: Nodes distribute mask shares to clients via secure, certificate-authenticated RPC subscriptions. Clients collect enough shares to reconstruct their mask.
- **Output Distribution**: Output shares are encrypted for each client using HPKE and distributed via RPC. Clients subscribe to receive their shares and reconstruct the output once enough shares are collected.
- **Authentication and Security**: All RPC communication uses mutual TLS with self-signed certificates. Custom verifiers allow for flexible trust models in local or test environments.
- **Event System**: The coordinator serializes and broadcasts events for all protocol transitions, ensuring all parties remain synchronized even if events are triggered before or after subscriptions.

## Common Features

- **Coordinator Trait**: Both coordinators implement a common trait, abstracting the MPC workflow and allowing for interchangeable use in applications.
- **Node RPC**: Both on-chain and off-chain coordinators use a secure RPC layer for communication between clients and nodes, supporting subscriptions, authentication, and share distribution.
- **Testing**: The library includes comprehensive tests for both modes, simulating full protocol runs, event ordering, and error handling.

