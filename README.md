# Deploying the coordinator

Start Anvil using `anvil`.

Run `cargo run --bin deploy-contract -- --eth-node-addr ws://127.0.0.1:8545 --sk 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --hash 0000000000000000000000000000000000000000000000000000000000000000 --designated-party 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --n 5 --t 1 --n-inputs 2 --initial-mpc-nodes 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906,0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65`.

To then execute a sample MPC program that adds two numbers using the deployed coordinator, use the `task-coord` branch in the Stoffel VM and run `docker compose build --ssh default` to build the Docker images (SSH is needed since the Solidity SDK is a private repository that we fetch via SSH). To run the computation, use `docker compose up`.
