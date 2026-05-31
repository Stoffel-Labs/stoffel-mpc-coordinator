use clap::Parser;
use std::fs;
use stoffel_mpc_coordinator::off_chain::OffChainCoordinatorServer;
use stoffel_mpc_coordinator::rpc::RPCServerConnection;
use stoffel_mpc_coordinator::tests::fake_coord::off_chain::{
    AvssCoordinatorConnection, FakeCoordinatorConnection, FakeCoordinatorRPCServerSharedBase,
};
use stoffel_vm_types::compiled_binary::MpcBackend;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hash: String,

    #[arg(long, required=true, value_delimiter=',', num_args=1..)]
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

    #[arg(long, required=true, value_delimiter=',', num_args=1..)]
    output_clients: Vec<String>,

    #[arg(long)]
    program: Option<String>,

    #[arg(long, value_delimiter=',', num_args=0..)]
    client_bindings: Vec<String>,

    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
}

async fn run_coord<C>(
    server_state: FakeCoordinatorRPCServerSharedBase,
    addr: &str,
    port: u16,
    t: u64,
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
) where
    C: RPCServerConnection<Internal = FakeCoordinatorRPCServerSharedBase>,
{
    let coord = OffChainCoordinatorServer::<C>::start_coord(
        server_state,
        addr,
        port,
        t,
        server_cert_der,
        server_key_der,
    )
    .await
    .expect("failed to start coordinator");
    let timestamp = coord.get_timestamp();

    println!("Listening on {}:{}", addr, port);
    println!("Timestamp: {}", timestamp);

    tokio::time::sleep(tokio::time::Duration::MAX).await;
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

    let parse_public_keys = |cert_files: &[String]| -> Vec<Vec<u8>> {
        cert_files
            .iter()
            .map(|cert_file| {
                let cert_der = fs::read(cert_file).expect("could not read certificate file");
                let (_remainder, parsed_cert) = X509Certificate::from_der(&cert_der)
                    .expect("Failed to parse X.509 certificate DER");
                parsed_cert
                    .public_key()
                    .subject_public_key
                    .data
                    .as_ref()
                    .to_vec()
            })
            .collect()
    };

    let public_keys = parse_public_keys(&args.initial_mpc_nodes);
    let output_client_keys = parse_public_keys(&args.output_clients);
    let binding_keys = |bindings: &[String]| -> Vec<(u64, Vec<u8>)> {
        bindings
            .iter()
            .map(|binding| {
                let (slot, cert_file) = binding
                    .split_once('=')
                    .expect("client binding must be formatted as <client_slot>=<cert>");
                let slot = slot.parse::<u64>().expect("invalid client slot");
                let key = parse_public_keys(&[cert_file.to_string()])
                    .into_iter()
                    .next()
                    .expect("binding key");
                (slot, key)
            })
            .collect()
    };

    let server_cert_der = fs::read(args.server_cert).unwrap();
    let server_key_der = fs::read(args.server_key).unwrap();

    let addr = args.addr.as_str();
    let port = 31415;
    let (mpc_backend, server_state) = if let Some(program_path) = args.program {
        let binary = stoffel_vm_types::compiled_binary::utils::load_from_file(program_path)
            .expect("failed to load Stoffel bytecode");
        let mpc_backend = binary.client_io_manifest.mpc_backend;
        let client_bindings = if args.client_bindings.is_empty() {
            let mut schemas = binary.client_io_manifest.clients.clone();
            schemas.sort_by_key(|schema| schema.client_slot);
            assert_eq!(
                schemas.len(),
                output_client_keys.len(),
                "without --client-bindings, --output-clients must match manifest client count"
            );
            schemas
                .into_iter()
                .zip(output_client_keys)
                .map(|(schema, key)| (schema.client_slot, key))
                .collect()
        } else {
            binding_keys(&args.client_bindings)
        };
        (
            mpc_backend,
            FakeCoordinatorRPCServerSharedBase::new_with_client_io_manifest(
                hash,
                n,
                t,
                public_keys,
                binary.client_io_manifest,
                client_bindings,
            )
            .expect("failed to bind client IO manifest"),
        )
    } else {
        (
            MpcBackend::HoneyBadger,
            FakeCoordinatorRPCServerSharedBase::new(
                hash,
                n,
                t,
                public_keys,
                args.n_inputs,
                output_client_keys,
            ),
        )
    };
    match mpc_backend {
        MpcBackend::HoneyBadger => {
            run_coord::<FakeCoordinatorConnection>(
                server_state,
                addr,
                port,
                t,
                server_cert_der,
                server_key_der,
            )
            .await;
        }
        MpcBackend::Avss => {
            run_coord::<AvssCoordinatorConnection>(
                server_state,
                addr,
                port,
                t,
                server_cert_der,
                server_key_der,
            )
            .await;
        }
    }
}
