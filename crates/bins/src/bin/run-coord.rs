use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem};
use std::collections::{HashMap, HashSet};
use std::fs;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    AvssCoordinatorConnection, HoneyBadgerCoordinatorConnection,
};
use stoffel_mpc_coordinator_off_chain::{
    ClientIdentity, CoordinatorRPCServerSharedBase, InputAssignment, InputSlotAssignment,
    OffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_shared::rpc::RPCServerConnection;
use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    AvssShareType, AvssShareValueType, AvssValueType, HoneyBadgerShareType,
    HoneyBadgerShareValueType, HoneyBadgerValueType,
};
use stoffel_mpc_coordinator_shared::{CoordinatorError, ShareBound};
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

    #[arg(long, value_delimiter=',', num_args=1..)]
    output_clients: Vec<String>,

    #[arg(long)]
    program: Option<String>,

    #[arg(long, value_delimiter=',', num_args=0..)]
    client_bindings: Vec<String>,

    /// Bind a manifest slot to a base64url-encoded raw P-256 HPKE public key.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    browser_client_bindings: Vec<String>,

    #[arg(long, default_value = "127.0.0.1")]
    addr: String,
}

type InputAssignmentBuildResult = (InputAssignment, Vec<ClientIdentity>);
type BrowserHpkePublicKey = <DhP256HkdfSha256 as Kem>::PublicKey;

fn parse_browser_client_binding(binding: &str) -> Result<(u64, ClientIdentity), String> {
    let (slot, encoded_key) = binding.split_once('=').ok_or_else(|| {
        "browser client binding must be formatted as <client_slot>=<base64url-public-key>"
            .to_string()
    })?;
    let slot = slot
        .parse::<u64>()
        .map_err(|_| format!("invalid browser client slot {slot:?}"))?;
    let key = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| format!("invalid base64url HPKE public key for client slot {slot}"))?;
    BrowserHpkePublicKey::from_bytes(&key)
        .map_err(|_| format!("invalid P-256 HPKE public key for client slot {slot}"))?;
    Ok((slot, key))
}

fn combine_explicit_client_bindings(
    certificate_bindings: Vec<(u64, ClientIdentity)>,
    browser_bindings: &[String],
) -> Result<Vec<(u64, ClientIdentity)>, String> {
    let browser_bindings = browser_bindings
        .iter()
        .map(|binding| parse_browser_client_binding(binding))
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen_slots = HashMap::<u64, &'static str>::new();
    let mut bindings = Vec::with_capacity(certificate_bindings.len() + browser_bindings.len());

    for (source, source_bindings) in [
        ("certificate", certificate_bindings),
        ("browser", browser_bindings),
    ] {
        for (slot, identity) in source_bindings {
            if let Some(previous_source) = seen_slots.insert(slot, source) {
                let kind = if previous_source == source {
                    "duplicate"
                } else {
                    "conflicting"
                };
                return Err(format!(
                    "{kind} client binding for slot {slot} ({previous_source} and {source})"
                ));
            }
            bindings.push((slot, identity));
        }
    }

    Ok(bindings)
}

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

    let mut seen_clients = HashSet::new();
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

async fn run_coord<
    T: CanonicalSerialize + CanonicalDeserialize + Clone + Send,
    C,
    F: FftField,
    S: ShareBound<F, ValueType = T>,
>(
    server_state: CoordinatorRPCServerSharedBase<T>,
    addr: &str,
    port: u16,
    t: u64,
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
) where
    C: RPCServerConnection<Internal = CoordinatorRPCServerSharedBase<T>>,
{
    let browser_config =
        stoffel_mpc_coordinator_off_chain::browser_config::BrowserRpcConfig::from_env()
            .expect("invalid browser RPC configuration");
    let mut coord = OffChainCoordinatorServer::<C>::start_coord(
        server_state,
        addr,
        port,
        t,
        server_cert_der,
        server_key_der,
    )
    .await
    .expect("failed to start coordinator");
    if let Some(config) = browser_config.as_ref() {
        coord
            .start_browser_rpc::<F, S>(config)
            .await
            .expect("failed to start browser coordinator RPC");
        println!(
            "Browser WSS listening on {}:{}",
            addr, config.coordinator_port
        );
    }
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
        let client_bindings =
            if args.client_bindings.is_empty() && args.browser_client_bindings.is_empty() {
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
                combine_explicit_client_bindings(
                    binding_keys(&args.client_bindings),
                    &args.browser_client_bindings,
                )
                .expect("invalid explicit client bindings")
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
            run_coord::<
                HoneyBadgerValueType,
                HoneyBadgerCoordinatorConnection,
                HoneyBadgerShareValueType,
                HoneyBadgerShareType,
            >(server_state, addr, port, t, server_cert_der, server_key_der)
            .await;
        }
        MpcBackend::Avss => {
            run_coord::<
                AvssValueType,
                AvssCoordinatorConnection,
                AvssShareValueType,
                AvssShareType,
            >(
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
    use hpke::Serializable;
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

    fn browser_public_key(seed: u8) -> (String, ClientIdentity) {
        let (_, public_key) = DhP256HkdfSha256::derive_keypair(&[seed; 32]);
        let raw = public_key.to_bytes().to_vec();
        (URL_SAFE_NO_PAD.encode(&raw), raw)
    }

    #[test]
    fn parses_raw_browser_hpke_public_key_binding() {
        let (encoded, raw) = browser_public_key(7);

        assert_eq!(
            parse_browser_client_binding(&format!("2={encoded}")),
            Ok((2, raw))
        );
    }

    #[test]
    fn browser_bindings_do_not_require_certificate_output_clients() {
        let (encoded, _) = browser_public_key(7);
        let args = Args::try_parse_from([
            "run-coord",
            "--hash",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--initial-mpc-nodes",
            "node.crt",
            "--server-cert",
            "coord.crt",
            "--server-key",
            "coord.der",
            "--n",
            "3",
            "--t",
            "1",
            "--program",
            "program.stflb",
            "--browser-client-bindings",
            &format!("0={encoded}"),
        ])
        .expect("browser-only bindings should parse");

        assert!(args.output_clients.is_empty());
        assert_eq!(args.browser_client_bindings.len(), 1);
    }

    #[test]
    fn rejects_private_and_malformed_browser_binding_values() {
        let encoded_private_value = URL_SAFE_NO_PAD.encode([7_u8; 32]);

        assert!(
            parse_browser_client_binding(&format!("0={encoded_private_value}"))
                .unwrap_err()
                .contains("invalid P-256 HPKE public key")
        );
        assert!(parse_browser_client_binding("0=not+base64url").is_err());
        assert!(parse_browser_client_binding("0").is_err());
    }

    #[test]
    fn rejects_duplicate_and_conflicting_explicit_bindings() {
        let (first, _) = browser_public_key(1);
        let (second, _) = browser_public_key(2);

        let duplicate = combine_explicit_client_bindings(
            Vec::new(),
            &[format!("0={first}"), format!("0={second}")],
        )
        .unwrap_err();
        assert!(duplicate.contains("duplicate client binding for slot 0"));

        let conflict =
            combine_explicit_client_bindings(vec![(0, vec![4, 5, 6])], &[format!("0={first}")])
                .unwrap_err();
        assert!(conflict.contains("conflicting client binding for slot 0"));
    }
}
