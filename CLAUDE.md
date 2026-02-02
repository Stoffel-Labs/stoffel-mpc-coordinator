# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based deployment tool for the Stoffel MPC Coordinator. It deploys the `FakeCoordinator` smart contract to an Ethereum network (typically Anvil for local testing) and initializes it with MPC configuration parameters. The coordinator orchestrates Multi-Party Computation across distributed parties.

## Development Commands

```bash
# Build
cargo build
cargo build --release

# Run deployment (requires Anvil running)
cargo run --bin deploy-coordinator -- \
  --eth-node-addr ws://127.0.0.1:8545 \
  --sk <PRIVATE_KEY> \
  --hash <256_BIT_HEX_HASH> \
  --designated-party <ETH_ADDRESS> \
  --initial-mpc-nodes <ADDR1>,<ADDR2>,... \
  --n <NUM_PARTIES> \
  --t <THRESHOLD>

# Start local Ethereum testnet
anvil
```

## CLI Arguments

| Argument | Description |
|----------|-------------|
| `--eth-node-addr` | WebSocket URL to Ethereum node (e.g., `ws://127.0.0.1:8545`) |
| `--sk` | Private key for signing deployment transaction |
| `--hash` | 256-bit hash as hex string (64 chars, no 0x prefix) |
| `--designated-party` | Ethereum address of the designated party |
| `--initial-mpc-nodes` | Comma-separated list of MPC node addresses |
| `--n` | Number of MPC parties |
| `--t` | MPC threshold (must satisfy `n >= 3t + 1` for HoneyBadger) |

## Architecture

```
src/deploy-coordinator/bin/main.rs
├── Args struct (Clap CLI parsing)
├── connect_to_eth_node() - WebSocket provider with wallet
└── main() - Deploy FakeCoordinator contract
```

The binary:
1. Parses CLI arguments via Clap
2. Connects to Ethereum node via WebSocket with wallet signing
3. Deploys `FakeCoordinator` contract with MPC parameters
4. Outputs the deployed contract address

## Dependencies

- **stoffel-solidity-bindings** (private, `test-coord` branch): Rust bindings to Stoffel smart contracts
- **alloy**: Ethereum interaction library (provider, wallet, contract deployment)
- **clap**: CLI argument parsing

## Integration with Stoffel Ecosystem

After deploying the coordinator:
1. Use the `feature/cspl-vm-builtins` branch in StoffelVM (contains all C-SPL VM builtins)
2. Build Docker images: `docker compose build --ssh default` (SSH required for private Solidity SDK)
3. Run MPC computation: `docker compose up`

## VM Builtins (from feature/cspl-vm-builtins)

The coordinator integrates with StoffelVM builtins for C-SPL operations:
- `ClientStore.take_bytes(idx)`, `ClientStore.take_int(idx)` - Client input retrieval
- `Ristretto_add`, `Ristretto_sub`, `Ristretto_mul`, etc. - Elliptic curve operations
- `hash_sha256`, `concat_bytes`, `int_to_bytes` - Cryptographic utilities
- `Scalar_lagrange_simple`, `Scalar_lagrange_at_zero` - Secret sharing operations
