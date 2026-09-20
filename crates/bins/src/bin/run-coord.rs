//! Runs an off-chain coordinator that registers exactly one execution at startup.
//!
//! Registration is in-process and operator-only: this binary is where the operator fixes the
//! execution's program, its client slot table and its admission policy. Standing mode keeps
//! serving after the execution finishes; `--one-off` drains once the retirement quorum of a
//! terminal round has acknowledged it, and exits.

use clap::{ArgGroup, Parser, ValueEnum};
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use stoffel_mpc_coordinator_off_chain::{
    CoordinatorRPCServerSharedBase, ExecutionRegistration, OffChainCoordinatorConnection,
    OffChainCoordinatorServer, OneOffShutdownConfig, DEFAULT_ONE_OFF_SHUTDOWN_GRACE,
};
use stoffel_mpc_coordinator_shared::rpc::{caller_identity, RpcServerLimits};
use stoffel_mpc_coordinator_shared::{
    program_hash_of, AdmissionPolicy, ClientIdentity, ClientSlotSpec, ClientSlotTable,
    CoordinatorError, ExecutionDeadlines, ExecutionId, InvitationIssuer, NodeCertificateDer,
    NodeRoster, PinError, RegistrationError, RosterError, SpkiDer, UnixSeconds,
};
use stoffel_vm_types::compiled_binary::{ClientIoManifest, CompiledBinary};

/// `--admission`: which `AdmissionPolicy` the registration carries. Never defaults to `open`.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
enum AdmissionKind {
    /// One client certificate per slot, fixed at startup (`--client-certs` or
    /// `--client-bindings`).
    #[default]
    PreRegistered,
    /// Any certificate holder binds a free slot, first come, first served. Requires deadlines.
    Open,
    /// Only the invitee of a `SignedInvitation` from `--invitation-issuer-cert`, in the slot it
    /// names. Requires deadlines.
    Invitation,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(ArgGroup::new("program_binding").required(true).args(["program", "hash"])))]
struct Args {
    /// Drain and exit once the retirement quorum has acknowledged the execution in a terminal
    /// round. Omit for a standing coordinator.
    #[arg(long)]
    one_off: bool,

    /// Maximum time a one-off coordinator waits, once draining, for the execution to be removed.
    #[arg(long, default_value_t = DEFAULT_ONE_OFF_SHUTDOWN_GRACE.as_secs())]
    one_off_shutdown_grace_secs: u64,

    /// The execution registered at startup, 64 hexadecimal characters, nonzero.
    #[arg(long, value_parser = parse_nonzero_execution_id)]
    execution_id: ExecutionId,

    /// Compiled program: registers `program_hash_of(bytes)`, and the manifest's client slots.
    #[arg(long)]
    program: Option<String>,

    /// The program hash, 64 hexadecimal characters, for registering without the bytes.
    #[arg(long, value_parser = parse_program_hash)]
    hash: Option<[u8; 32]>,

    /// Roster node certificates (DER), comma-separated.
    #[arg(long, required = true, value_delimiter = ',', num_args = 1..)]
    node_certs: Vec<String>,

    /// The corruption threshold of the node roster.
    #[arg(long)]
    t: u64,

    /// The coordinator's certificate (DER). Clients and nodes pin its key.
    #[arg(long)]
    server_cert: String,

    /// The coordinator's private key (PKCS#8 DER), matching `--server-cert`.
    #[arg(long)]
    server_key: String,

    /// One `<inputs>:<outputs>` client slot per entry, in slot order. Refused with `--program`,
    /// whose manifest supplies the slots. Empty is the same as absent.
    #[arg(long)]
    client_io: Option<String>,

    /// How clients are admitted to the execution's slots.
    #[arg(long, value_enum, default_value_t = AdmissionKind::PreRegistered)]
    admission: AdmissionKind,

    /// `pre-registered` only: one client certificate per slot, in slot order, comma-separated.
    #[arg(long)]
    client_certs: Option<String>,

    /// `pre-registered` only: `<client_slot>=<cert>` entries, comma-separated.
    #[arg(long)]
    client_bindings: Option<String>,

    /// `invitation` only: the invitation issuer's certificate.
    #[arg(long)]
    invitation_issuer_cert: Option<String>,

    /// Seconds after startup by which every slot must be bound.
    #[arg(long)]
    association_deadline_secs: Option<u64>,

    /// Seconds after startup by which every masked input must be submitted.
    #[arg(long)]
    input_deadline_secs: Option<u64>,

    /// Maximum established connections; the other connection limits keep their defaults.
    #[arg(long, default_value_t = RpcServerLimits::default().max_connections)]
    max_connections: usize,

    /// Listen address.
    #[arg(long, default_value = "127.0.0.1")]
    addr: String,

    /// Listen port.
    #[arg(long, default_value_t = 31415)]
    port: u16,
}

/// Why `run-coord` refuses to start. Every variant exits 2.
#[derive(Debug, thiserror::Error)]
enum RunCoordError {
    #[error("could not read {path}: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("{path} is not a Stoffel program: {reason}")]
    NotAProgram { path: String, reason: String },
    #[error("certificate {path} is refused: {source}")]
    Certificate { path: String, source: PinError },
    #[error("invalid node roster: {0}")]
    Roster(#[from] RosterError),
    #[error("invalid registration: {0}")]
    Registration(#[from] RegistrationError),
    #[error("client IO manifest slots are not contiguous from 0")]
    NonContiguousManifestSlots,
    #[error(
        "--client-io is refused with --program: the program's manifest supplies the client slots"
    )]
    ClientIoWithProgram,
    #[error("invalid --client-io entry {entry:?}: expected <inputs>:<outputs>")]
    InvalidClientIo { entry: String },
    #[error("invalid --client-bindings entry {entry:?}: expected <client_slot>=<cert>")]
    InvalidClientBinding { entry: String },
    #[error("--client-bindings names slot {slot} twice")]
    DuplicateClientBinding { slot: u64 },
    #[error("--client-bindings names slot {slot}, but the registration has {slots} slots")]
    ClientBindingOutOfRange { slot: u64, slots: usize },
    #[error("--client-bindings leaves slot {slot} unbound")]
    UnboundClientSlot { slot: usize },
    #[error("--client-certs and --client-bindings are exclusive")]
    ClientCertsAndBindings,
    #[error("{flag} is not read under --admission {admission:?}")]
    UnusedFlag {
        flag: &'static str,
        admission: AdmissionKind,
    },
    #[error("--admission invitation requires --invitation-issuer-cert")]
    MissingIssuer,
    #[error(
        "--association-deadline-secs and --input-deadline-secs are given together or not at all"
    )]
    PartialDeadlines,
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
}

fn parse_nonzero_execution_id(value: &str) -> Result<ExecutionId, String> {
    let execution_id = value.parse::<ExecutionId>()?;
    if execution_id.is_zero() {
        return Err("execution ID must be nonzero".to_string());
    }
    Ok(execution_id)
}

fn parse_program_hash(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid program hash: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "a program hash is 32 bytes (64 hexadecimal characters)".to_string())
}

/// `None` for an absent or empty flag value, otherwise its comma-separated entries.
fn entries(value: &Option<String>) -> Option<Vec<String>> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| value.split(',').map(str::to_string).collect())
}

fn read(path: &str) -> Result<Vec<u8>, RunCoordError> {
    fs::read(Path::new(path)).map_err(|error| RunCoordError::Unreadable {
        path: path.to_string(),
        reason: error.to_string(),
    })
}

fn identity_of_certificate(path: &str) -> Result<ClientIdentity, RunCoordError> {
    caller_identity(&read(path)?).map_err(|source| RunCoordError::Certificate {
        path: path.to_string(),
        source,
    })
}

fn spki_of_certificate(path: &str) -> Result<SpkiDer, RunCoordError> {
    SpkiDer::from_certificate_der(&read(path)?).map_err(|source| RunCoordError::Certificate {
        path: path.to_string(),
        source,
    })
}

/// One slot per manifest client, in `client_slot` order; the slots must be exactly `0..k`.
fn client_slots_from_manifest(
    manifest: &ClientIoManifest,
) -> Result<ClientSlotTable, RunCoordError> {
    let mut schemas = manifest.clients.iter().collect::<Vec<_>>();
    schemas.sort_by_key(|schema| schema.client_slot);
    if schemas
        .iter()
        .enumerate()
        .any(|(position, schema)| schema.client_slot != position as u64)
    {
        return Err(RunCoordError::NonContiguousManifestSlots);
    }
    Ok(ClientSlotTable::new(
        schemas
            .into_iter()
            .map(|schema| ClientSlotSpec {
                input_count: schema.inputs.len() as u64,
                output_count: schema.outputs.len() as u64,
            })
            .collect(),
    ))
}

fn client_slots_from_flag(client_io: &[String]) -> Result<ClientSlotTable, RunCoordError> {
    client_io
        .iter()
        .map(|entry| {
            let invalid = || RunCoordError::InvalidClientIo {
                entry: entry.clone(),
            };
            let (inputs, outputs) = entry.split_once(':').ok_or_else(invalid)?;
            Ok(ClientSlotSpec {
                input_count: inputs.parse().map_err(|_| invalid())?,
                output_count: outputs.parse().map_err(|_| invalid())?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(ClientSlotTable::new)
}

fn pre_registered_clients(
    args: &Args,
    slots: &ClientSlotTable,
) -> Result<Vec<ClientIdentity>, RunCoordError> {
    match (entries(&args.client_certs), entries(&args.client_bindings)) {
        (Some(_), Some(_)) => Err(RunCoordError::ClientCertsAndBindings),
        (Some(certs), None) => certs
            .iter()
            .map(|path| identity_of_certificate(path))
            .collect(),
        (None, Some(bindings)) => {
            let mut clients: Vec<Option<ClientIdentity>> = vec![None; slots.slots().len()];
            for entry in bindings {
                let invalid = || RunCoordError::InvalidClientBinding {
                    entry: entry.clone(),
                };
                let (slot, path) = entry.split_once('=').ok_or_else(invalid)?;
                let slot = slot.parse::<u64>().map_err(|_| invalid())?;
                let bound = clients.get_mut(slot as usize).ok_or(
                    RunCoordError::ClientBindingOutOfRange {
                        slot,
                        slots: slots.slots().len(),
                    },
                )?;
                if bound.is_some() {
                    return Err(RunCoordError::DuplicateClientBinding { slot });
                }
                *bound = Some(identity_of_certificate(path)?);
            }
            clients
                .into_iter()
                .enumerate()
                .map(|(slot, client)| client.ok_or(RunCoordError::UnboundClientSlot { slot }))
                .collect()
        }
        (None, None) => Ok(Vec::new()),
    }
}

/// The node roster, the served key and the one registration the flags describe. Refuses a
/// non-empty flag the chosen admission does not read.
fn registration_from_args(
    args: &Args,
    now: UnixSeconds,
) -> Result<(NodeRoster, SpkiDer, ExecutionRegistration), RunCoordError> {
    let node_certificates = args
        .node_certs
        .iter()
        .map(|path| read(path).map(NodeCertificateDer::from_der))
        .collect::<Result<Vec<_>, _>>()?;
    let node_roster = NodeRoster::new(args.t, node_certificates)?;
    let server_spki = spki_of_certificate(&args.server_cert)?;

    let (program_hash, client_slots) = match (&args.program, args.hash) {
        (Some(path), _) => {
            if entries(&args.client_io).is_some() {
                return Err(RunCoordError::ClientIoWithProgram);
            }
            let bytes = read(path)?;
            let binary = CompiledBinary::deserialize(&mut bytes.as_slice()).map_err(|error| {
                RunCoordError::NotAProgram {
                    path: path.clone(),
                    reason: format!("{error:?}"),
                }
            })?;
            (
                program_hash_of(&bytes),
                client_slots_from_manifest(&binary.client_io_manifest)?,
            )
        }
        (None, Some(hash)) => (
            hash,
            entries(&args.client_io)
                .map(|client_io| client_slots_from_flag(&client_io))
                .transpose()?
                .unwrap_or_default(),
        ),
        (None, None) => unreachable!("clap requires exactly one of --program and --hash"),
    };

    let unused = |flag: &'static str, value: &Option<String>| match entries(value) {
        Some(_) => Err(RunCoordError::UnusedFlag {
            flag,
            admission: args.admission,
        }),
        None => Ok(()),
    };
    let admission = match args.admission {
        AdmissionKind::PreRegistered => {
            unused("--invitation-issuer-cert", &args.invitation_issuer_cert)?;
            AdmissionPolicy::PreRegistered {
                clients: pre_registered_clients(args, &client_slots)?,
            }
        }
        AdmissionKind::Open => {
            unused("--client-certs", &args.client_certs)?;
            unused("--client-bindings", &args.client_bindings)?;
            unused("--invitation-issuer-cert", &args.invitation_issuer_cert)?;
            AdmissionPolicy::Open
        }
        AdmissionKind::Invitation => {
            unused("--client-certs", &args.client_certs)?;
            unused("--client-bindings", &args.client_bindings)?;
            let issuer = args
                .invitation_issuer_cert
                .as_deref()
                .filter(|path| !path.is_empty())
                .ok_or(RunCoordError::MissingIssuer)?;
            AdmissionPolicy::Invitation {
                issuer: InvitationIssuer::new(spki_of_certificate(issuer)?),
            }
        }
    };

    let deadlines = match (args.association_deadline_secs, args.input_deadline_secs) {
        (Some(association), Some(input)) => Some(ExecutionDeadlines {
            association: UnixSeconds(now.0.saturating_add(association)),
            input: UnixSeconds(now.0.saturating_add(input)),
        }),
        (None, None) => None,
        _ => return Err(RunCoordError::PartialDeadlines),
    };

    let registration = ExecutionRegistration {
        execution_id: args.execution_id,
        program_hash,
        client_slots,
        admission,
        deadlines,
    };
    registration.validate(&node_roster, &server_spki, now)?;
    Ok((node_roster, server_spki, registration))
}

async fn run(args: Args) -> Result<(), RunCoordError> {
    let (node_roster, server_spki, registration) =
        registration_from_args(&args, UnixSeconds::now())?;
    let server_cert_der = read(&args.server_cert)?;
    let server_key_der = read(&args.server_key)?;
    println!("Node roster digest: {}", node_roster.digest());

    let execution_id = registration.execution_id;
    let mut state = CoordinatorRPCServerSharedBase::new(node_roster, server_spki);
    let nonce = state.register_execution(registration)?;
    println!("Registered execution {execution_id} (registration nonce {nonce})");

    let limits = RpcServerLimits {
        max_connections: args.max_connections,
        ..RpcServerLimits::default()
    };
    if args.one_off {
        println!(
            "Listening on {}:{} (one-off execution {execution_id})",
            args.addr, args.port
        );
        OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord_one_off(
            state,
            &args.addr,
            args.port,
            server_cert_der,
            server_key_der,
            OneOffShutdownConfig {
                execution_id,
                grace: std::time::Duration::from_secs(args.one_off_shutdown_grace_secs),
            },
            limits,
        )
        .await?;
        println!("Execution {execution_id} drained, exiting");
    } else {
        let _coordinator = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
            state,
            &args.addr,
            args.port,
            server_cert_der,
            server_key_der,
            limits,
        )
        .await?;
        println!("Listening on {}:{}", args.addr, args.port);
        std::future::pending::<()>().await;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    println!(
        "Executing: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stoffel_mpc_coordinator_shared::ClientIndex;
    use stoffel_vm_types::{
        compiled_binary::{ClientIoSchema, MpcBackend, MpcCurve},
        core_types::ShareType,
    };

    /// A directory of minted certificates: four nodes, a coordinator and two clients.
    struct Fixture {
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "run-coord-{name}-{}-{}",
                std::process::id(),
                hex::encode(program_hash_of(name.as_bytes()))
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            for file in [
                "node0", "node1", "node2", "node3", "server", "client0", "client1",
            ] {
                let certified = rcgen::generate_simple_self_signed(vec![file.to_string()]).unwrap();
                fs::write(dir.join(format!("{file}.crt")), certified.cert.der()).unwrap();
                fs::write(
                    dir.join(format!("{file}.key")),
                    certified.signing_key.serialize_der(),
                )
                .unwrap();
            }
            Self { dir }
        }

        fn path(&self, file: &str) -> String {
            self.dir.join(file).to_string_lossy().into_owned()
        }

        fn base_args(&self) -> Vec<String> {
            vec![
                "run-coord".to_string(),
                "--execution-id".to_string(),
                "07".repeat(32),
                "--node-certs".to_string(),
                ["node0", "node1", "node2", "node3"]
                    .map(|node| self.path(&format!("{node}.crt")))
                    .join(","),
                "--t".to_string(),
                "1".to_string(),
                "--server-cert".to_string(),
                self.path("server.crt"),
                "--server-key".to_string(),
                self.path("server.key"),
            ]
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn parse(arguments: Vec<String>) -> Result<Args, clap::Error> {
        Args::try_parse_from(arguments)
    }

    #[test]
    fn client_slots_ignore_scalar_share_types() {
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

        let int_slots = client_slots_from_manifest(&int_manifest).unwrap();
        let bool_slots = client_slots_from_manifest(&bool_manifest).unwrap();
        assert_eq!(int_slots, bool_slots);
        assert_eq!(
            int_slots.slots(),
            &[ClientSlotSpec {
                input_count: 1,
                output_count: 1
            }]
        );

        let gapped = ClientIoManifest {
            clients: vec![
                ClientIoSchema {
                    client_slot: 0,
                    inputs: vec![ShareType::default_secret_int()],
                    outputs: vec![],
                },
                ClientIoSchema {
                    client_slot: 2,
                    inputs: vec![ShareType::default_secret_int()],
                    outputs: vec![],
                },
            ],
            ..Default::default()
        };
        assert!(matches!(
            client_slots_from_manifest(&gapped),
            Err(RunCoordError::NonContiguousManifestSlots)
        ));
    }

    #[test]
    fn execution_id_validation_rejects_zero() {
        assert!(parse_nonzero_execution_id(&"00".repeat(32)).is_err());
        let execution_id = ExecutionId::from_bytes([7; 32]);
        assert_eq!(
            parse_nonzero_execution_id(&execution_id.to_string()).unwrap(),
            execution_id,
        );
    }

    #[test]
    fn run_coord_registers_its_execution_at_startup_in_both_modes() {
        let fixture = Fixture::new("modes");
        let now = UnixSeconds::now();
        let hash = "ab".repeat(32);
        let pre_registered = |one_off: bool| {
            let mut arguments = fixture.base_args();
            arguments.extend([
                "--hash".to_string(),
                hash.clone(),
                "--client-io".to_string(),
                "1:1,2:0".to_string(),
                "--client-certs".to_string(),
                format!(
                    "{},{}",
                    fixture.path("client0.crt"),
                    fixture.path("client1.crt")
                ),
            ]);
            if one_off {
                arguments.push("--one-off".to_string());
            }
            parse(arguments).unwrap()
        };

        let standing = pre_registered(false);
        let one_off = pre_registered(true);
        assert!(!standing.one_off);
        assert!(one_off.one_off);
        let (roster, _, standing_registration) = registration_from_args(&standing, now).unwrap();
        let (_, _, one_off_registration) = registration_from_args(&one_off, now).unwrap();
        assert_eq!(standing_registration, one_off_registration);
        assert_eq!(roster.n(), 4);
        assert_eq!(standing_registration.program_hash, [0xab; 32]);
        assert_eq!(standing_registration.client_slots.capacity(), 2);
        assert_eq!(standing_registration.client_slots.n_inputs(), 3);
        assert_eq!(
            standing_registration
                .client_slots
                .input_range(ClientIndex(1))
                .unwrap()
                .start,
            1
        );
        let AdmissionPolicy::PreRegistered { clients } = &standing_registration.admission else {
            panic!("the default admission is pre-registered");
        };
        assert_eq!(
            clients[1],
            identity_of_certificate(&fixture.path("client1.crt")).unwrap()
        );

        // Open with deadlines relative to startup.
        let mut open = fixture.base_args();
        open.extend(
            [
                "--hash",
                &hash,
                "--client-io",
                "1:1",
                "--admission",
                "open",
                "--association-deadline-secs",
                "30",
                "--input-deadline-secs",
                "60",
                "--client-certs",
                "",
            ]
            .map(str::to_string),
        );
        let (_, _, registration) =
            registration_from_args(&parse(open.clone()).unwrap(), now).unwrap();
        assert_eq!(registration.admission, AdmissionPolicy::Open);
        assert_eq!(
            registration.deadlines,
            Some(ExecutionDeadlines {
                association: UnixSeconds(now.0 + 30),
                input: UnixSeconds(now.0 + 60)
            })
        );

        // A non-empty flag the admission does not read is refused, not ignored.
        let mut with_certs = open.clone();
        let position = with_certs.iter().rposition(|arg| arg.is_empty()).unwrap();
        with_certs[position] = fixture.path("client0.crt");
        assert!(matches!(
            registration_from_args(&parse(with_certs).unwrap(), now),
            Err(RunCoordError::UnusedFlag {
                flag: "--client-certs",
                ..
            })
        ));

        // Open without deadlines is a registration error; pre-registered without certificates
        // for its slots is refused rather than admitting anyone.
        let mut no_deadlines = fixture.base_args();
        no_deadlines.extend(
            ["--hash", &hash, "--client-io", "1:1", "--admission", "open"].map(str::to_string),
        );
        assert!(matches!(
            registration_from_args(&parse(no_deadlines).unwrap(), now),
            Err(RunCoordError::Registration(
                RegistrationError::DeadlinesRequired
            ))
        ));
        let mut no_certs = fixture.base_args();
        no_certs.extend(["--hash", &hash, "--client-io", "1:1"].map(str::to_string));
        assert!(matches!(
            registration_from_args(&parse(no_certs).unwrap(), now),
            Err(RunCoordError::Registration(
                RegistrationError::PreRegisteredCountMismatch {
                    slots: 1,
                    clients: 0
                }
            ))
        ));

        // --program and --hash are exclusive, and one of them is required.
        let mut both = fixture.base_args();
        both.extend(["--hash", &hash, "--program", "program.stfbin"].map(str::to_string));
        assert!(parse(both).is_err());
        assert!(parse(fixture.base_args()).is_err());

        // The removed flags are unknown.
        for removed in [
            ["--backend", "avss"],
            ["--min-output-shares", "3"],
            ["--n", "4"],
            ["--n-inputs", "1"],
        ] {
            let mut arguments = fixture.base_args();
            arguments.extend(["--hash", &hash].map(str::to_string));
            arguments.extend(removed.map(str::to_string));
            let error = parse(arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{removed:?} must be an unknown flag"
            );
        }
    }
}
