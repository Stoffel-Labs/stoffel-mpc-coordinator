use alloy::{
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
    network::EthereumWallet                  
};
use alloy_primitives::{U256, FixedBytes, Address};
use stoffel_solidity_bindings::fake_coordinator::FakeCoordinator;
use std::str::FromStr;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    eth_node_addr: String,

    #[arg(long)]
    sk: String,

    #[arg(long)]
    hash: String,

    #[arg(long)]
    designated_party: String,

    #[arg(long, value_delimiter=',', num_args=1..)]
    initial_mpc_nodes: Vec<String>,

    #[arg(long)]
    n: u32,

    #[arg(long)]
    t: u32,

    #[arg(long)]
    n_inputs: u32,
}

async fn connect_to_eth_node(addr: &str, sk: &str) -> impl Provider + Clone {
    let ws = WsConnect::new(addr);
    let wallet = EthereumWallet::from(PrivateKeySigner::from_str(sk).expect("invalid private key"));
    
    ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(ws).await.expect("could not connect to Anvil via WebSockets")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let provider = connect_to_eth_node(&args.eth_node_addr, &args.sk).await;

    let n = U256::from(args.n);
    let t = U256::from(args.t);
    let hash = FixedBytes::from_str(&args.hash).expect("invalid hash");
    let designated_party = Address::from_str(&args.designated_party).expect("invalid designated party address");
    let initial_mpc_nodes: Vec<Address> = args.initial_mpc_nodes.iter()
        .map(|s| Address::from_str(s).expect("invalid initial MPC node address"))
        .collect();
    let n_inputs = U256::from(args.n_inputs);

    let contract = match FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes, n_inputs).await {
        Ok(contract) => contract,
        Err(e) => {
            eprintln!("Failed to deploy contract: {}", e);
            if let Some(decoded_err) = e.as_decoded_interface_error::<FakeCoordinator::FakeCoordinatorErrors>() {
                println!("Decoded error: {:?}", decoded_err);
            } 
            return;
        }
    };

    println!("{}", contract.address());
}
