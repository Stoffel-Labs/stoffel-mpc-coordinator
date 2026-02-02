# Deploying the coordinator

Start Anvil using `anvil`.

Run `cargo run --bin deploy-coordinator -- --eth-node-addr ws://127.0.0.1:8545 --sk 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --hash 0000000000000000000000000000000000000000000000000000000000000000 --designated-party 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --n 5 --t 1`.

To then execute a sample MPC program that adds two numbers using the deployed coordinator, use the `feature/cspl-vm-builtins` branch in the Stoffel VM and run `docker compose build --ssh default` to build the Docker images (SSH is needed since the Solidity SDK is a private repository that we fetch via SSH). To run the computation, use `docker compose up`.

## C-SPL VM Builtins

The `feature/cspl-vm-builtins` branch contains all 11 VM builtins required for C-SPL operations:
- Client input: `ClientStore.take_bytes`, `ClientStore.take_int`
- Elliptic curve: `Ristretto_add`, `Ristretto_sub`, `Ristretto_mul`, `Ristretto_base_mul`
- Cryptographic: `hash_sha256`, `concat_bytes`, `int_to_bytes`
- Secret sharing: `Scalar_lagrange_simple`, `Scalar_lagrange_at_zero`
