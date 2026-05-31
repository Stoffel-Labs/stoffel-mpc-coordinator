use alloy::{
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};
use alloy_primitives::{Address, FixedBytes, U256};
use clap::Parser;
use std::{env, str::FromStr};
use stoffel_mpc_coordinator::{
    tests::fake_coord::{AvssShareType, FakeShareValueType, HoneyBadgerShareType},
    ShareBound,
};
use stoffel_solidity_bindings_test::fake_coordinator::FakeCoordinator;
use stoffel_vm_types::compiled_binary::MpcBackend;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The WebSocket address of an Ethereum node to connect to.
    #[arg(long)]
    eth_node_addr: String,

    /// The hash of the MPC program.
    #[arg(long)]
    hash: String,

    /// The Ethereum addresses of the initial MPC nodes.
    #[arg(long, value_delimiter=',', num_args=1..)]
    initial_mpc_nodes: Vec<String>,

    /// The Ethereum address of the clients, which will receive the outputs of the MPC program.
    #[arg(long, value_delimiter=',', num_args=1..)]
    output_clients: Vec<String>,

    /// The threshold value `t`.
    #[arg(long)]
    t: u32,

    /// The number of inputs for the MPC program.
    #[arg(long)]
    n_inputs: u32,

    /// The compiled Stoffel program whose manifest determines the MPC backend.
    #[arg(long)]
    program: Option<String>,
}

async fn connect_to_eth_node(addr: &str, sk: &str) -> impl Provider + Clone {
    let ws = WsConnect::new(addr);
    let wallet = EthereumWallet::from(PrivateKeySigner::from_str(sk).expect("invalid private key"));

    ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(ws)
        .await
        .expect("could not connect to Anvil via WebSockets")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let sk = env::var("DEPLOY_SK").expect("DEPLOY_SK environment variable not set");
    let provider = connect_to_eth_node(&args.eth_node_addr, &sk).await;

    let t = args.t;
    let hash = FixedBytes::from_str(&args.hash).expect("invalid hash");
    let initial_mpc_nodes: Vec<Address> = args
        .initial_mpc_nodes
        .iter()
        .map(|s| Address::from_str(s).expect("invalid initial MPC node address"))
        .collect();
    let output_clients: Vec<Address> = args
        .output_clients
        .iter()
        .map(|s| Address::from_str(s).expect("invalid output client address"))
        .collect();
    let n_inputs = U256::from(args.n_inputs);
    let backend = args
        .program
        .as_deref()
        .map(|path| {
            stoffel_vm_types::compiled_binary::utils::load_from_file(path)
                .expect("failed to load Stoffel bytecode")
                .client_io_manifest
                .mpc_backend
        })
        .unwrap_or(MpcBackend::HoneyBadger);
    let threshold = match backend {
        MpcBackend::HoneyBadger => U256::from(<HoneyBadgerShareType as ShareBound<
            FakeShareValueType,
        >>::min_shares(t as usize)),
        MpcBackend::Avss => {
            U256::from(<AvssShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize))
        }
    };

    let contract = match FakeCoordinator::deploy(
        provider.clone(),
        hash,
        U256::from(t),
        initial_mpc_nodes,
        n_inputs,
        output_clients,
        threshold,
    )
    .await
    {
        Ok(contract) => contract,
        Err(e) => {
            eprintln!("Failed to deploy contract: {}", e);
            if let Some(decoded_err) =
                e.as_decoded_interface_error::<FakeCoordinator::FakeCoordinatorErrors>()
            {
                println!("Decoded error: {:?}", decoded_err);
            }
            return;
        }
    };

    println!("{}", contract.address());
}
