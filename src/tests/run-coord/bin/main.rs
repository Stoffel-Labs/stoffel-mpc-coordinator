use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use stoffel_mpc_coordinator::off_chain::CoordinatorRPCServerSharedBase;
use stoffel_mpc_coordinator::off_chain::{
    ClientIdentity, InputAssignment, InputSlotAssignment, OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator::rpc::RPCServerConnection;
use stoffel_mpc_coordinator::tests::fake_coord::off_chain::{
    AvssCoordinatorConnection, HoneyBadgerCoordinatorConnection,
};
use stoffel_mpc_coordinator::tests::fake_coord::{AvssValueType, HoneyBadgerValueType};
use stoffel_mpc_coordinator::CoordinatorError;
use stoffel_vm_types::compiled_binary::{ClientIoManifest, ClientIoSchema, MpcBackend};
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
    n_inputs: Option<u64>,

    #[arg(long, required=true, value_delimiter=',', num_args=1..)]
    output_clients: Vec<String>,

    #[arg(long)]
    program: Option<String>,

    #[arg(long, value_delimiter=',', num_args=0..)]
    client_bindings: Vec<String>,

    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
}

type InputAssignmentBuildResult = (InputAssignment, Vec<ClientIdentity>);

fn build_input_assignment(
    manifest: ClientIoManifest,
    bindings: Vec<(u64, ClientIdentity)>,
) -> Result<InputAssignmentBuildResult, CoordinatorError> {
    let mut by_slot: HashMap<u64, ClientIoSchema> = HashMap::new();
    for schema in manifest.clients {
        let client_slot = schema.client_slot;
        if by_slot.insert(client_slot, schema).is_some() {
            return Err(CoordinatorError::JSONError(format!(
                "Duplicate client_slot {client_slot} in client IO manifest"
            )));
        }
    }

    let mut bound_clients = Vec::new();
    for (client_slot, client) in bindings {
        let schema = by_slot.remove(&client_slot).ok_or_else(|| {
            CoordinatorError::JSONError(format!(
                "No client IO manifest entry for bound client_slot {client_slot}"
            ))
        })?;
        bound_clients.push((
            client,
            client_slot,
            schema.inputs.len() as u64,
            schema.outputs.len() as u64,
        ));
    }

    if !by_slot.is_empty() {
        let mut unbound_slots = by_slot.keys().copied().collect::<Vec<_>>();
        unbound_slots.sort_unstable();
        return Err(CoordinatorError::JSONError(format!(
            "Client IO manifest slots are not bound to off-chain identities: {unbound_slots:?}"
        )));
    }

    let mut seen_clients = std::collections::HashSet::new();
    let mut input_slots = Vec::new();
    let mut output_clients = Vec::new();
    for (client, _client_slot, input_count, output_count) in bound_clients {
        if !seen_clients.insert(client.clone()) {
            return Err(CoordinatorError::JSONError(
                "Client identity is bound to multiple client IO slots".to_string(),
            ));
        }
        if output_count > 0 {
            output_clients.push(client.clone());
        }
        for input_ordinal in 0..input_count {
            input_slots.push(InputSlotAssignment {
                client: client.clone(),
                label: input_ordinal,
            });
        }
    }

    Ok((InputAssignment { input_slots }, output_clients))
}

async fn run_coord<T: CanonicalSerialize + CanonicalDeserialize + Clone, C>(
    server_state: CoordinatorRPCServerSharedBase<T>,
    addr: &str,
    port: u16,
    t: u64,
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
) where
    C: RPCServerConnection<Internal = CoordinatorRPCServerSharedBase<T>>,
{
    let _coord = OffChainCoordinatorServer::<C>::start_coord(
        server_state,
        addr,
        port,
        t,
        server_cert_der,
        server_key_der,
    )
    .await
    .expect("failed to start coordinator");
    println!("Listening on {}:{}", addr, port);

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
                let cert_der = fs::read(cert_file)
                    .unwrap_or_else(|_| panic!("could not read certificate file {cert_file}"));
                let (_remainder, parsed_cert) = X509Certificate::from_der(&cert_der)
                    .unwrap_or_else(|_| {
                        panic!("Failed to parse X.509 certificate DER {cert_file}")
                    });
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
        let (input_assignment, output_clients) =
            build_input_assignment(binary.client_io_manifest, client_bindings)
                .expect("failed to bind client IO manifest");
        let n_inputs = input_assignment.input_slots.len() as u64;
        let server_state = CoordinatorRPCServerSharedBase::new_with_input_assignment(
            hash,
            n,
            t,
            public_keys,
            n_inputs,
            output_clients,
            input_assignment,
        )
        .expect("failed to configure bound client IO");
        (mpc_backend, server_state)
    } else {
        let n_inputs = args
            .n_inputs
            .expect("--n-inputs is required when --program is not provided");
        (
            MpcBackend::HoneyBadger,
            CoordinatorRPCServerSharedBase::new(
                hash,
                n,
                t,
                public_keys,
                n_inputs,
                output_client_keys,
            ),
        )
    };
    match mpc_backend {
        MpcBackend::HoneyBadger => {
            run_coord::<HoneyBadgerValueType, HoneyBadgerCoordinatorConnection>(
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
            run_coord::<AvssValueType, AvssCoordinatorConnection>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_vm_types::{
        compiled_binary::{MpcBackend, MpcCurve},
        core_types::ShareType,
    };

    #[test]
    fn input_assignment_ignores_scalar_share_types() {
        let int_manifest = ClientIoManifest {
            mpc_backend: MpcBackend::HoneyBadger,
            mpc_curve: MpcCurve::Bls12_381,
            clients: vec![ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::default_secret_int()],
                outputs: vec![ShareType::default_secret_int()],
            }],
            ..Default::default()
        };
        let bool_manifest = ClientIoManifest {
            mpc_backend: MpcBackend::Avss,
            mpc_curve: MpcCurve::Ed25519,
            clients: vec![ClientIoSchema {
                client_slot: 0,
                inputs: vec![ShareType::try_secret_int(1).expect("valid bool share type")],
                outputs: vec![ShareType::try_secret_int(1).expect("valid bool share type")],
            }],
            ..Default::default()
        };

        let client = vec![7, 8, 9];
        let (int_layout, int_outputs) =
            build_input_assignment(int_manifest, vec![(0, client.clone())]).unwrap();
        let (bool_layout, bool_outputs) =
            build_input_assignment(bool_manifest, vec![(0, client.clone())]).unwrap();

        assert_eq!(int_layout.input_slots[0].client, client);
        assert_eq!(int_layout.input_slots[0].label, 0);
        assert_eq!(int_layout.input_slots.len(), bool_layout.input_slots.len());
        assert_eq!(int_outputs, bool_outputs);
    }
}
