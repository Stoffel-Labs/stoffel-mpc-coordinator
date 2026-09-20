//! Signs one invitation to one slot of one `Invitation`-gated execution.
//!
//! The issuer is an admission authority inside the coordinator's trust boundary; no node's
//! operator may run it. It reads the pinned coordinator's roster and the execution's summary,
//! and refuses to sign — exit 2, nothing written — for another program, another issuer, an
//! execution past association, or a slot the execution does not have.

use clap::Parser;
use std::fs;
use std::process::ExitCode;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::HoneyBadgerOffChainCoordinatorClient;
use stoffel_mpc_coordinator_off_chain::ExecutionSummary;
use stoffel_mpc_coordinator_shared::{
    AdmissionPolicyKind, ClientIndex, CoordinatorError, ExecutionId, Invitation,
    InvitationSigningError, PinError, Round, SignedInvitation, SpkiDer, UnixSeconds,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The coordinator, `<host>:<port>`.
    #[arg(long)]
    coordinator: String,

    /// The coordinator's certificate (DER); the connection is pinned to its key.
    #[arg(long)]
    coord_cert: String,

    #[arg(long, value_parser = parse_execution_id)]
    execution_id: ExecutionId,

    /// The program the invitation vouches for, 64 hexadecimal characters.
    #[arg(long, value_parser = parse_hash)]
    expect_program_hash: [u8; 32],

    /// The issuer's PKCS#8 P-256 key (DER).
    #[arg(long)]
    issuer_key: String,

    /// The invitee's certificate (DER).
    #[arg(long)]
    invitee_cert: String,

    /// The slot the invitation binds.
    #[arg(long)]
    client_index: u32,

    #[arg(long)]
    valid_for_secs: u64,

    /// Where the `SignedInvitation` JSON is written.
    #[arg(long)]
    out: String,
}

/// Why no invitation was signed. Every variant exits 2.
#[derive(Debug, thiserror::Error)]
enum IssueError {
    #[error("could not read {path}: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("certificate {path} is refused: {source}")]
    Certificate { path: String, source: PinError },
    #[error("--coordinator must be <host>:<port>, got {0:?}")]
    InvalidCoordinatorAddress(String),
    #[error(
        "execution {execution_id} runs program {served}, not --expect-program-hash {expected}"
    )]
    WrongProgram {
        execution_id: ExecutionId,
        served: String,
        expected: String,
    },
    #[error("execution {execution_id} is not invitation-gated")]
    NotInvitationGated { execution_id: ExecutionId },
    #[error("execution {execution_id} names another invitation issuer")]
    AnotherIssuer { execution_id: ExecutionId },
    #[error("execution {execution_id} is past association: it is in round {round:?}")]
    PastAssociation {
        execution_id: ExecutionId,
        round: Round,
    },
    #[error(
        "execution {execution_id} has {capacity} client slots; slot {client_index} does not exist"
    )]
    ClientIndexOutOfRange {
        execution_id: ExecutionId,
        client_index: ClientIndex,
        capacity: u32,
    },
    #[error("could not write {path}: {reason}")]
    Unwritable { path: String, reason: String },
    #[error(transparent)]
    Signing(#[from] InvitationSigningError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
}

fn parse_execution_id(value: &str) -> Result<ExecutionId, String> {
    value.parse()
}

fn parse_hash(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|error| format!("invalid program hash: {error}"))?
        .try_into()
        .map_err(|_| "a program hash is 32 bytes (64 hexadecimal characters)".to_string())
}

fn read(path: &str) -> Result<Vec<u8>, IssueError> {
    fs::read(path).map_err(|error| IssueError::Unreadable {
        path: path.to_string(),
        reason: error.to_string(),
    })
}

fn spki_of_certificate(path: &str) -> Result<SpkiDer, IssueError> {
    SpkiDer::from_certificate_der(&read(path)?).map_err(|source| IssueError::Certificate {
        path: path.to_string(),
        source,
    })
}

/// Everything the summary must show before this issuer signs.
fn check_summary(
    summary: &ExecutionSummary,
    expected_program_hash: &[u8; 32],
    issuer_point: &[u8],
    client_index: ClientIndex,
) -> Result<(), IssueError> {
    let execution_id = summary.execution_id;
    if summary.program_hash != *expected_program_hash {
        return Err(IssueError::WrongProgram {
            execution_id,
            served: hex::encode(summary.program_hash),
            expected: hex::encode(expected_program_hash),
        });
    }
    let AdmissionPolicyKind::Invitation { issuer } = &summary.admission else {
        return Err(IssueError::NotInvitationGated { execution_id });
    };
    if issuer.spki().client_identity() != issuer_point {
        return Err(IssueError::AnotherIssuer { execution_id });
    }
    if !matches!(
        summary.round,
        Round::Idle | Round::Preprocessing | Round::InputMaskReservation
    ) {
        return Err(IssueError::PastAssociation {
            execution_id,
            round: summary.round,
        });
    }
    let capacity = summary.client_slots.capacity();
    if client_index.0 >= capacity {
        return Err(IssueError::ClientIndexOutOfRange {
            execution_id,
            client_index,
            capacity,
        });
    }
    Ok(())
}

async fn run(args: &Args) -> Result<(), IssueError> {
    let (host, port) = args
        .coordinator
        .rsplit_once(':')
        .and_then(|(host, port)| Some((host, port.parse::<u16>().ok()?)))
        .ok_or_else(|| IssueError::InvalidCoordinatorAddress(args.coordinator.clone()))?;
    let coordinator = spki_of_certificate(&args.coord_cert)?;
    let issuer_key = read(&args.issuer_key)?;
    let issuer_point = SignedInvitation::issuer_public_point(&issuer_key)?;
    let invitee = spki_of_certificate(&args.invitee_cert)?.client_identity();
    let client_index = ClientIndex(args.client_index);

    // A certificate minted for this call only: the issuer's own key never authenticates here.
    let caller = rcgen::generate_simple_self_signed(vec!["stoffel-invitation-issuer".to_string()])
        .map_err(|error| CoordinatorError::TlsConfigError(error.to_string()))?;
    let client = HoneyBadgerOffChainCoordinatorClient::start_rpc_client_for_execution(
        host,
        port,
        &coordinator,
        None,
        args.execution_id,
        caller.cert.der().to_vec(),
        caller.signing_key.serialize_der(),
    )
    .await?;
    let summary = client.get_execution_summary().await?;
    check_summary(
        &summary,
        &args.expect_program_hash,
        &issuer_point,
        client_index,
    )?;

    let not_after = UnixSeconds::now().0.saturating_add(args.valid_for_secs);
    let signed = SignedInvitation::sign(
        Invitation {
            execution_id: args.execution_id,
            registration_nonce: summary.registration_nonce,
            program_hash: summary.program_hash,
            roster_digest: client.node_roster().digest(),
            not_after: UnixSeconds(not_after),
            invitee,
            client_index,
        },
        &issuer_key,
    )?;
    let json = serde_json::to_vec_pretty(&signed).expect("invitations serialize to JSON");
    fs::write(&args.out, json).map_err(|error| IssueError::Unwritable {
        path: args.out.clone(),
        reason: error.to_string(),
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");
    let args = Args::parse();
    match run(&args).await {
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
    use stoffel_mpc_coordinator_off_chain::{
        CoordinatorRPCServerSharedBase, ExecutionRegistration, OffChainCoordinatorConnection,
        OffChainCoordinatorServer,
    };
    use stoffel_mpc_coordinator_shared::rpc::RpcServerLimits;
    use stoffel_mpc_coordinator_shared::{
        AdmissionPolicy, ClientSlotSpec, ClientSlotTable, ExecutionDeadlines, InvitationIssuer,
        NodeCertificateDer, NodeRoster,
    };

    #[tokio::test]
    async fn issue_invitation_requires_a_slot_and_refuses_one_past_capacity() {
        stoffel_mpc_coordinator_shared::setup_test();
        let dir = std::env::temp_dir().join(format!("issue-invitation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = |file: &str| dir.join(file).to_string_lossy().into_owned();

        let mint = || rcgen::generate_simple_self_signed(vec!["test".to_string()]).unwrap();
        let nodes = (0..4).map(|_| mint()).collect::<Vec<_>>();
        let coordinator = mint();
        let issuer = mint();
        let invitee = mint();
        fs::write(path("coord.crt"), coordinator.cert.der()).unwrap();
        fs::write(path("issuer.key"), issuer.signing_key.serialize_der()).unwrap();
        fs::write(path("invitee.crt"), invitee.cert.der()).unwrap();

        let execution_id = ExecutionId::from_bytes([0x61; 32]);
        let program_hash = [0x62; 32];
        let now = UnixSeconds::now();
        let roster = NodeRoster::new(
            1,
            nodes
                .iter()
                .map(|node| NodeCertificateDer::from_der(node.cert.der().to_vec()))
                .collect(),
        )
        .unwrap();
        let state = CoordinatorRPCServerSharedBase::new_for_execution(
            roster,
            SpkiDer::from_certificate_der(coordinator.cert.der()).unwrap(),
            ExecutionRegistration {
                execution_id,
                program_hash,
                client_slots: ClientSlotTable::new(vec![ClientSlotSpec {
                    input_count: 1,
                    output_count: 1,
                }]),
                admission: AdmissionPolicy::Invitation {
                    issuer: InvitationIssuer::new(
                        SpkiDer::from_certificate_der(issuer.cert.der()).unwrap(),
                    ),
                },
                deadlines: Some(ExecutionDeadlines {
                    association: UnixSeconds(now.0 + 600),
                    input: UnixSeconds(now.0 + 1200),
                }),
            },
        )
        .unwrap();
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let _server = OffChainCoordinatorServer::<OffChainCoordinatorConnection>::start_coord(
            state,
            "127.0.0.1",
            port,
            coordinator.cert.der().to_vec(),
            coordinator.signing_key.serialize_der(),
            RpcServerLimits::default(),
        )
        .await
        .unwrap();

        let arguments = |client_index: Option<&str>, out: &str| {
            let mut arguments = vec![
                "issue-invitation".to_string(),
                "--coordinator".to_string(),
                format!("127.0.0.1:{port}"),
                "--coord-cert".to_string(),
                path("coord.crt"),
                "--execution-id".to_string(),
                execution_id.to_string(),
                "--expect-program-hash".to_string(),
                hex::encode(program_hash),
                "--issuer-key".to_string(),
                path("issuer.key"),
                "--invitee-cert".to_string(),
                path("invitee.crt"),
                "--valid-for-secs".to_string(),
                "300".to_string(),
                "--out".to_string(),
                path(out),
            ];
            if let Some(client_index) = client_index {
                arguments.extend(["--client-index".to_string(), client_index.to_string()]);
            }
            arguments
        };

        let missing = Args::try_parse_from(arguments(None, "missing.json")).unwrap_err();
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let past_capacity = Args::try_parse_from(arguments(Some("1"), "past.json")).unwrap();
        assert!(matches!(
            run(&past_capacity).await,
            Err(IssueError::ClientIndexOutOfRange {
                capacity: 1,
                client_index: ClientIndex(1),
                ..
            })
        ));
        assert!(
            !dir.join("past.json").exists(),
            "a refused invitation writes nothing"
        );

        let valid = Args::try_parse_from(arguments(Some("0"), "valid.json")).unwrap();
        run(&valid).await.unwrap();
        let signed: SignedInvitation =
            serde_json::from_slice(&fs::read(dir.join("valid.json")).unwrap()).unwrap();
        assert_eq!(signed.invitation.client_index, ClientIndex(0));
        assert_eq!(signed.invitation.program_hash, program_hash);
        assert_eq!(
            signed.invitation.invitee,
            SpkiDer::from_certificate_der(invitee.cert.der())
                .unwrap()
                .client_identity()
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
