use std::fs;
use clap::Parser;
use x509_parser::prelude::*;
use stoffel_mpc_coordinator::off_chain::{OffChainCoordinatorServer, FakeCoordinatorConnection, CoordinatorRPCServerSharedBase, FakeValueType};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hash: String,

    #[arg(long, value_delimiter=',', num_args=1..)]
    initial_mpc_nodes: Vec<String>,

    #[arg(long)]
    server_cert: String,

    #[arg(long)]
    server_key: String,


    #[arg(long)]
    n: u64,

    #[arg(long)]
    t: u64,

    #[arg(long)]
    n_inputs: u64,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();

    let n = args.n;
    let t = args.t;
    let hash: [u8; 32] = {
        let h = hex::decode(args.hash).expect("invalid hash");
        h.try_into().expect("hash should be 32 bytes")
    };

    let public_keys = args.initial_mpc_nodes.iter().map(|cert_file| {
        let cert_der = fs::read(cert_file).expect("could not read certificate file");
        let (_remainder, parsed_cert) = X509Certificate::from_der(&cert_der)
            .expect("Failed to parse X.509 certificate DER");
        parsed_cert.public_key()
            .subject_public_key.data.as_ref().to_vec()
    }).collect();

    let server_cert_der = fs::read(args.server_cert).unwrap();
    let server_key_der = fs::read(args.server_key).unwrap();
    
    let addr = "127.0.0.1";
    let port = 31415;
    let server_state = CoordinatorRPCServerSharedBase::<FakeValueType>::new(hash, n, t, public_keys, args.n_inputs);
    let coord = OffChainCoordinatorServer::<FakeCoordinatorConnection>::start_coord(server_state, addr, port, t, server_cert_der, server_key_der).await;
    let timestamp = coord.get_timestamp();

    println!("Listening on {}:{}", addr, port);
    println!("Timestamp: {}", timestamp);

    tokio::time::sleep(tokio::time::Duration::MAX).await;
}
