use ark_bls12_381::Fr;
use ark_std::test_rng;
use jsonrpsee::async_client::Client;
use jsonrpsee::core::client::{ClientT, SubscriptionClientT};
use jsonrpsee::core::RpcResult;
use jsonrpsee::rpc_params;
use jsonrpsee::RpcModule;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator_off_chain::node_rpc::{
    execution_state_probe, parked_mask_requests, OffChainNodeRPCClient,
};
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    AvssNodeRPCClient, HoneyBadgerCoordinatorRPCServerSharedBase, HoneyBadgerNodeRPCClient,
    HoneyBadgerNodeRPCServer, HoneyBadgerOffChainCoordinatorClient,
    HoneyBadgerOffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_off_chain::{
    admitted_reservations, AssignedMaskReservation, CoordinatorLink, CoordinatorRPCBaseClient,
    CoordinatorRPCServerSharedBase, DeliveryHooks, Event, ExecutionRegistration, ExecutionSummary,
    OneOffShutdownConfig, PausePoint, SealedOutput, SealedOutputShares,
    DEFAULT_MAX_CONCURRENT_EXECUTIONS, DEFAULT_MAX_ENDED_EXECUTIONS, SUMMARY_READ_BURST,
};
use stoffel_mpc_coordinator_shared::rpc::{RPCServerConnection, RpcServerLimits};
use stoffel_mpc_coordinator_shared::self_signed_certs::{client_cert, server_cert, setup_client};
use stoffel_mpc_coordinator_shared::tests::fake_coord::{AvssShareType, HoneyBadgerShareType};
use stoffel_mpc_coordinator_shared::NodeRPCError;
use stoffel_mpc_coordinator_shared::{
    masked_inputs_signing_bytes, sealed_output_signing_bytes, sign_with_pkcs8, AbortReason,
    AdmissionError, AdmissionPolicy, AdmissionPolicyKind, AssociationRequest, ClientAdmission,
    ClientIndex, ClientSlotSpec, ClientSlotTable, Coordinator, CoordinatorError,
    ExecutionDeadlines, ExecutionOutcome, InputRange, Invitation, InvitationIssuer,
    InvitationRejection, KeyAlgorithm, NodeCertificateDer, NodeRoster, NodeRosterWire,
    OutputRights, RegistrationError, RegistrationNonce, RosterDigest, RosterError, RpcRefusal,
    ServerPin, ShareBound, SignedInvitation, SpkiDer, SubmissionError, UnixSeconds,
    MAX_MASKED_INPUT_BYTES, MAX_SEALED_OUTPUT_BYTES,
};
use stoffel_mpc_coordinator_shared::{ExecutionId, Round};
use stoffelmpc_mpc::common::SecretSharingScheme;
use tokio::sync::{Barrier, Mutex};

type Certified = Arc<rcgen::CertifiedKey<rcgen::KeyPair>>;
type HbClient = HoneyBadgerOffChainCoordinatorClient;
type AvssClient =
    stoffel_mpc_coordinator_off_chain::tests::fake_coord::AvssOffChainCoordinatorClient;

const ADDR: &str = "127.0.0.1";

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Proposes `round` from every party.
///
/// Round transitions require a quorum of proposals, so a test that drives the protocol by hand
/// has to speak for the roster rather than for a single leader — exactly as each node does in a
/// real deployment once it has finished its own work for the round.
async fn propose_round(coords: &[HbClient], round: Round) {
    for coord in coords {
        coord.trigger_round(round).await.unwrap();
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind((ADDR, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn execution(byte: u8) -> ExecutionId {
    ExecutionId::from_bytes([byte; 32])
}

fn cert_parts(cert: &Certified) -> (Vec<u8>, Vec<u8>) {
    (cert.cert.der().to_vec(), cert.signing_key.serialize_der())
}

fn spki_of(cert: &Certified) -> SpkiDer {
    SpkiDer::from_certificate_der(cert.cert.der()).unwrap()
}

fn identity_of(cert: &Certified) -> Vec<u8> {
    cert.signing_key.public_key_raw().to_vec()
}

fn ed25519_cert() -> Certified {
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["ed25519-client".to_string()])
        .unwrap()
        .self_signed(&signing_key)
        .unwrap();
    Arc::new(rcgen::CertifiedKey { cert, signing_key })
}

/// `count` node certificates in canonical roster order, so `certs[i]` is roster position `i`.
fn node_certs(count: usize) -> Vec<Certified> {
    let mut certs = (0..count).map(|_| server_cert()).collect::<Vec<_>>();
    certs.sort_by_key(spki_of);
    certs
}

fn roster_of(t: u64, certs: &[Certified]) -> NodeRoster {
    NodeRoster::new(
        t,
        certs
            .iter()
            .map(|cert| NodeCertificateDer::from_der(cert.cert.der().to_vec()))
            .collect(),
    )
    .unwrap()
}

fn slot(input_count: u64, output_count: u64) -> ClientSlotSpec {
    ClientSlotSpec {
        input_count,
        output_count,
    }
}

fn range(start: u64, count: u64) -> InputRange {
    InputRange {
        start,
        count: NonZeroU64::new(count).unwrap(),
    }
}

fn receive(output_count: u64) -> OutputRights {
    OutputRights::Receive {
        output_count: NonZeroU64::new(output_count).unwrap(),
    }
}

/// Deadlines `association` and `input` seconds from now.
fn deadlines_in(association: u64, input: u64) -> Option<ExecutionDeadlines> {
    let now = UnixSeconds::now().0;
    Some(ExecutionDeadlines {
        association: UnixSeconds(now + association),
        input: UnixSeconds(now + input),
    })
}

fn registration(
    execution_id: ExecutionId,
    slots: Vec<ClientSlotSpec>,
    admission: AdmissionPolicy,
    deadlines: Option<ExecutionDeadlines>,
) -> ExecutionRegistration {
    ExecutionRegistration {
        execution_id,
        program_hash: [1; 32],
        client_slots: ClientSlotTable::new(slots),
        admission,
        deadlines,
    }
}

/// A registration with no client slots.
fn empty_registration(execution_id: ExecutionId) -> ExecutionRegistration {
    registration(
        execution_id,
        vec![],
        AdmissionPolicy::PreRegistered { clients: vec![] },
        None,
    )
}

/// An `Open` registration whose deadlines are far away.
fn open_registration(
    execution_id: ExecutionId,
    slots: Vec<ClientSlotSpec>,
) -> ExecutionRegistration {
    registration(
        execution_id,
        slots,
        AdmissionPolicy::Open,
        deadlines_in(600, 1200),
    )
}

fn pre_registered(
    execution_id: ExecutionId,
    slots: Vec<ClientSlotSpec>,
    clients: &[&Certified],
) -> ExecutionRegistration {
    registration(
        execution_id,
        slots,
        AdmissionPolicy::PreRegistered {
            clients: clients.iter().map(|cert| identity_of(cert)).collect(),
        },
        None,
    )
}

fn coordinator_state(
    t: u64,
    nodes: &[Certified],
    coordinator: &Certified,
    registration: ExecutionRegistration,
) -> HoneyBadgerCoordinatorRPCServerSharedBase {
    HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
        roster_of(t, nodes),
        spki_of(coordinator),
        registration,
    )
    .unwrap()
}

async fn start_coordinator(
    state: HoneyBadgerCoordinatorRPCServerSharedBase,
    port: u16,
    coordinator: &Certified,
) -> HoneyBadgerOffChainCoordinatorServer {
    HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        ADDR,
        port,
        coordinator.clone(),
        RpcServerLimits::default(),
    )
    .await
    .unwrap()
}

async fn start_node_server(
    execution_id: ExecutionId,
    port: u16,
    cert: Certified,
) -> HoneyBadgerNodeRPCServer {
    let (cert_der, key_der) = cert_parts(&cert);
    HoneyBadgerNodeRPCServer::start_for_execution(ADDR, port, execution_id, cert_der, key_der)
        .await
        .unwrap()
}

async fn start_node_client(
    execution_id: ExecutionId,
    roster: &NodeRoster,
    addrs: Vec<(String, u16)>,
    cert: Certified,
) -> Result<HoneyBadgerNodeRPCClient, CoordinatorError> {
    let (cert_der, key_der) = cert_parts(&cert);
    HoneyBadgerNodeRPCClient::start_rpc_client_for_execution(
        roster,
        addrs,
        execution_id,
        cert_der,
        key_der,
    )
    .await
}

async fn start_coord_client(
    execution_id: ExecutionId,
    port: u16,
    coordinator: &Certified,
    cert: Certified,
) -> HbClient {
    let (cert_der, key_der) = cert_parts(&cert);
    HbClient::start_rpc_client_for_execution(
        ADDR,
        port,
        &spki_of(coordinator),
        None,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap()
}

async fn connect_all(
    execution_id: ExecutionId,
    port: u16,
    coordinator: &Certified,
    certs: &[Certified],
) -> Vec<HbClient> {
    let mut clients = Vec::new();
    for cert in certs {
        clients.push(start_coord_client(execution_id, port, coordinator, cert.clone()).await);
    }
    clients
}

/// A raw pinned JSON-RPC connection to the coordinator.
async fn raw_client(port: u16, coordinator: &Certified, cert: &Certified) -> Client {
    let (cert_der, key_der) = cert_parts(cert);
    setup_client(
        ADDR,
        port,
        cert_der,
        key_der,
        &ServerPin::Exact(spki_of(coordinator)),
    )
    .await
    .unwrap()
    .client
}

fn open_request() -> AssociationRequest {
    AssociationRequest {
        slot: None,
        invitation: None,
    }
}

fn slot_request(index: u32) -> AssociationRequest {
    AssociationRequest {
        slot: Some(ClientIndex(index)),
        invitation: None,
    }
}

fn admission_error(result: Result<impl std::fmt::Debug, CoordinatorError>) -> AdmissionError {
    match result {
        Err(CoordinatorError::Admission(error)) => error,
        other => panic!("expected an admission error, got {other:?}"),
    }
}

fn submission_error(result: Result<impl std::fmt::Debug, CoordinatorError>) -> SubmissionError {
    match result {
        Err(CoordinatorError::Submission(error)) => error,
        other => panic!("expected a submission error, got {other:?}"),
    }
}

fn refusal_of(result: Result<impl std::fmt::Debug, CoordinatorError>) -> RpcRefusal {
    match result {
        Err(CoordinatorError::Refused { refusal, .. }) => refusal,
        other => panic!("expected an untyped refusal, got {other:?}"),
    }
}

/// The typed admission error in a failed raw call's `data`.
fn raw_admission_error<T: std::fmt::Debug>(
    result: Result<T, jsonrpsee::core::client::Error>,
) -> AdmissionError {
    match result {
        Err(jsonrpsee::core::client::Error::Call(error)) => {
            serde_json::from_str(error.data().expect("admission refusals carry data").get())
                .unwrap()
        }
        other => panic!("expected a refused call, got {other:?}"),
    }
}

/// The JSON-RPC error code of a failed raw call.
fn call_code<T: std::fmt::Debug>(result: Result<T, jsonrpsee::core::client::Error>) -> i32 {
    match result {
        Err(jsonrpsee::core::client::Error::Call(error)) => error.code(),
        other => panic!("expected a refused call, got {other:?}"),
    }
}

/// Masked inputs and a valid client signature for `inputs` at `first_index`.
fn signed_submission(
    execution_id: ExecutionId,
    nonce: RegistrationNonce,
    client_index: ClientIndex,
    first_index: u64,
    inputs: Vec<Vec<u8>>,
    signer: &Certified,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let bytes =
        masked_inputs_signing_bytes(execution_id, nonce, client_index, first_index, &inputs);
    let signature = sign_with_pkcs8(
        KeyAlgorithm::EcdsaP256,
        &signer.signing_key.serialize_der(),
        &bytes,
    )
    .unwrap();
    (inputs, signature)
}

/// A node's sealed output for `client_index`, signed for `position`.
fn signed_output(
    execution_id: ExecutionId,
    nonce: RegistrationNonce,
    client_index: ClientIndex,
    position: u32,
    ciphertext: Vec<u8>,
    signer: &Certified,
) -> SealedOutput {
    let encapsulated_key = vec![position as u8; 65];
    let bytes = sealed_output_signing_bytes(
        execution_id,
        nonce,
        client_index,
        position,
        &encapsulated_key,
        &ciphertext,
    );
    SealedOutput {
        signature: sign_with_pkcs8(
            KeyAlgorithm::EcdsaP256,
            &signer.signing_key.serialize_der(),
            &bytes,
        )
        .unwrap(),
        encapsulated_key,
        ciphertext,
    }
}

/// A three-node (`t = 1`) coordinator serving `registration`, with a client connection per node.
struct Harness {
    server: HoneyBadgerOffChainCoordinatorServer,
    coordinator: Certified,
    nodes: Vec<Certified>,
    coords: Vec<HbClient>,
    port: u16,
    execution_id: ExecutionId,
}

impl Harness {
    async fn start(registration: ExecutionRegistration) -> Self {
        Self::start_with(4, registration, |state| state).await
    }

    async fn start_with(
        n: usize,
        registration: ExecutionRegistration,
        configure: impl FnOnce(CoordinatorRPCServerSharedBase) -> CoordinatorRPCServerSharedBase,
    ) -> Self {
        stoffel_mpc_coordinator_shared::setup_test();
        let nodes = node_certs(n);
        let coordinator = server_cert();
        let execution_id = registration.execution_id;
        let state = configure(coordinator_state(1, &nodes, &coordinator, registration));
        let port = free_port();
        let server = start_coordinator(state, port, &coordinator).await;
        let coords = connect_all(execution_id, port, &coordinator, &nodes).await;
        Self {
            server,
            coordinator,
            nodes,
            coords,
            port,
            execution_id,
        }
    }

    async fn client(&self, cert: &Certified) -> HbClient {
        start_coord_client(
            self.execution_id,
            self.port,
            &self.coordinator,
            cert.clone(),
        )
        .await
    }

    async fn raw(&self, cert: &Certified) -> Client {
        raw_client(self.port, &self.coordinator, cert).await
    }

    async fn advance(&self, round: Round) {
        propose_round(&self.coords, round).await;
        self.coords[0].wait_for_round(round).await.unwrap();
    }

    async fn nonce(&self) -> RegistrationNonce {
        self.server
            .state()
            .lock()
            .await
            .registration_nonce(self.execution_id)
            .unwrap()
    }

    async fn round(&self) -> Option<Round> {
        self.server.state().lock().await.round(self.execution_id)
    }
}

// ---------------------------------------------------------------------------------------------
// Rosters, listeners and node legs (retargeted onto registrations)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_node_does_not_deny_the_mask() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n = 4;
    let t = 1;
    let nodes = node_certs(n);
    let roster = roster_of(t as u64, &nodes);
    let execution_id = execution(0x78);
    let client = client_cert();
    let reservation = AssignedMaskReservation {
        client: identity_of(&client),
        reserved_index: 0,
        input_ordinal: 0,
    };
    let mask = Fr::from(4321);
    let shares = HoneyBadgerShareType::compute_shares(mask, n, t, None, &mut test_rng()).unwrap();

    // Position 0 never starts a listener; positions 1..n are the 2t+1 live nodes.
    let mut addrs = vec![(ADDR.to_string(), free_port())];
    let mut servers = Vec::new();
    for (position, node) in nodes.iter().enumerate().skip(1) {
        let port = free_port();
        let server = start_node_server(execution_id, port, node.clone()).await;
        server
            .add_assigned_reserved_index_for_execution(execution_id, reservation.clone())
            .await
            .unwrap();
        server
            .add_mask_share_for_execution(execution_id, 0, &shares[position])
            .await
            .unwrap();
        addrs.push((ADDR.to_string(), port));
        servers.push(server);
    }

    // The unreachable address is listed first so that a constructor collecting every
    // connection with `?` would fail on it before reaching any live node.
    let rpc_client = start_node_client(execution_id, &roster, addrs, client)
        .await
        .expect("an unreachable node is dropped, not fatal to the client");
    let masks = tokio::time::timeout(
        Duration::from_secs(10),
        rpc_client.receive_assigned_masks(0, 1),
    )
    .await
    .expect("the 2t+1 reachable legs must suffice")
    .expect("the mask reconstructs from the reachable legs");
    assert_eq!(masks, vec![mask]);
}

/// Retargeted: roster validity lives in `NodeRoster::new` (see coord-shared's
/// `node_roster_rejects_empty_zero_threshold_duplicate_and_undersized_rosters`); what a
/// coordinator state can still refuse is the registration it is built with.
#[test]
fn rejects_invalid_mpc_rosters() {
    let certs = node_certs(3);
    let certificates = |certs: &[Certified]| {
        certs
            .iter()
            .map(|cert| NodeCertificateDer::from_der(cert.cert.der().to_vec()))
            .collect::<Vec<_>>()
    };
    assert_eq!(NodeRoster::new(1, vec![]), Err(RosterError::Empty));
    assert_eq!(
        NodeRoster::new(1, certificates(&certs[..2])),
        Err(RosterError::ThresholdTooLarge { n: 2, t: 1 })
    );
    let mut duplicated = certificates(&certs[..2]);
    duplicated.push(duplicated[0].clone());
    assert_eq!(
        NodeRoster::new(1, duplicated),
        Err(RosterError::DuplicateKey {
            first: 0,
            second: 2
        })
    );
    assert_eq!(
        NodeRoster::new(0, certificates(&certs)),
        Err(RosterError::ZeroThreshold)
    );

    let coordinator = server_cert();
    assert!(matches!(
        HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
            roster_of(1, &certs),
            spki_of(&coordinator),
            empty_registration(ExecutionId::from_bytes([0; 32])),
        ),
        Err(CoordinatorError::Registration(
            RegistrationError::ZeroExecutionId
        ))
    ));
    assert!(
        HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
            roster_of(1, &certs),
            spki_of(&coordinator),
            empty_registration(ExecutionId::from_bytes([1; 32])),
        )
        .is_ok()
    );
}

#[tokio::test]
async fn one_listener_isolates_and_retires_concurrent_executions() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let port = free_port();
    let first_id = execution(0x31);
    let second_id = execution(0x32);
    let state = CoordinatorRPCServerSharedBase::new(roster_of(1, &nodes), spki_of(&coordinator));
    let server = start_coordinator(state, port, &coordinator).await;
    // Registration is in-process: the operator registers through the listener's state.
    for (execution_id, program_hash) in [(first_id, [0x41; 32]), (second_id, [0x42; 32])] {
        server
            .state()
            .lock()
            .await
            .register_execution(ExecutionRegistration {
                program_hash,
                ..empty_registration(execution_id)
            })
            .unwrap();
    }
    let first = connect_all(first_id, port, &coordinator, &nodes).await;
    let second = connect_all(second_id, port, &coordinator, &nodes).await;

    // n = 3, t = 1: two proposals form the transition quorum.
    propose_round(&first[..2], Round::Preprocessing).await;
    first[0].wait_for_round(Round::Preprocessing).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            second[0].wait_for_round(Round::Preprocessing),
        )
        .await
        .is_err(),
        "a transition for one execution must not wake another"
    );
    propose_round(&second[..2], Round::Preprocessing).await;
    second[0]
        .wait_for_round(Round::Preprocessing)
        .await
        .unwrap();

    propose_round(&first[..2], Round::MPCExecution).await;
    propose_round(&first[..2], Round::OutputDistribution).await;
    propose_round(&first[..2], Round::ProgramFinished).await;
    first[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();
    for client in &first {
        client.retire_execution().await.unwrap();
    }
    assert!(first[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .is_err());
    second[0]
        .wait_for_round(Round::Preprocessing)
        .await
        .unwrap();
}

#[tokio::test]
async fn start_client_server() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(5);
    let coordinator = server_cert();
    let port = free_port();
    let t = 1;
    let execution_id = execution(0x45);
    let server_state = coordinator_state(
        t,
        &nodes,
        &coordinator,
        open_registration(execution_id, vec![slot(1, 0)]),
    );
    let _coord = start_coordinator(server_state, port, &coordinator).await;

    let client = start_coord_client(execution_id, port, &coordinator, client_cert()).await;
    assert_eq!(client.node_roster(), &roster_of(t, &nodes));
}

#[tokio::test]
async fn coordinator_shutdown_closes_connections_and_releases_port() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let port = free_port();
    let execution_id = execution(0x46);
    let state = || coordinator_state(1, &nodes, &coordinator, empty_registration(execution_id));
    let server = start_coordinator(state(), port, &coordinator).await;
    let client = start_coord_client(execution_id, port, &coordinator, nodes[0].clone()).await;

    client.trigger_round(Round::Preprocessing).await.unwrap();
    server.shutdown().await;
    let disconnected = tokio::time::timeout(
        Duration::from_secs(1),
        client.trigger_round(Round::InputMaskReservation),
    )
    .await
    .expect("client RPC did not finish after server shutdown");
    assert!(disconnected.is_err());

    let replacement = start_coordinator(state(), port, &coordinator).await;
    replacement.shutdown().await;
}

#[tokio::test]
async fn dropping_node_server_closes_connections_and_releases_port() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let roster = roster_of(1, &nodes);
    let port = free_port();
    let execution_id = execution(0x47);
    let server = start_node_server(execution_id, port, nodes[1].clone()).await;
    let client = start_node_client(
        execution_id,
        &roster,
        vec![(ADDR.to_string(), port)],
        client_cert(),
    )
    .await
    .unwrap();

    drop(server);
    let disconnected =
        tokio::time::timeout(Duration::from_secs(1), client.receive_assigned_masks(0, 1))
            .await
            .expect("node RPC did not finish after server drop");
    assert!(disconnected.is_err());

    let replacement = start_node_server(execution_id, port, nodes[1].clone()).await;
    replacement.shutdown().await;
}

// Fakes event triggering.
#[tokio::test]
async fn trigger_pp() {
    stoffel_mpc_coordinator_shared::setup_test();

    // event triggered BEFORE waiting for the event
    {
        let mut certs = node_certs(5);
        let coordinator = server_cert();
        let port = free_port();
        let execution_id = execution(0x48);
        let server_state =
            coordinator_state(1, &certs, &coordinator, empty_registration(execution_id));
        let _coord = start_coordinator(server_state, port, &coordinator).await;

        let node0 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
        let node1 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
        let node2 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;

        // n = 5, t = 1, so three parties must propose the round before it is applied.
        for node in [&node0, &node1, &node2] {
            node.trigger_round(Round::Preprocessing).await.unwrap();
        }

        if tokio::time::timeout(
            Duration::from_millis(500),
            node1.wait_for_round(Round::Preprocessing),
        )
        .await
        .is_err()
        {
            panic!();
        }
    }

    // event triggered AFTER waiting for the event
    {
        let mut certs = node_certs(5);
        let coordinator = server_cert();
        let port = free_port();
        let execution_id = execution(0x49);
        let server_state =
            coordinator_state(1, &certs, &coordinator, empty_registration(execution_id));
        let _coord = start_coordinator(server_state, port, &coordinator).await;
        let barrier = Arc::new(Barrier::new(2));

        let node0 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
        let node1 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
        let node2 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;

        tokio::spawn({
            let barrier = barrier.clone();
            async move {
                if tokio::time::timeout(
                    Duration::from_millis(500),
                    node1.wait_for_round(Round::Preprocessing),
                )
                .await
                .is_err()
                {
                    panic!();
                }
                barrier.wait().await;
            }
        });

        // node1 is only waiting, so the quorum of three is formed by the other parties.
        let node3 = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
        for node in [&node0, &node2, &node3] {
            node.trigger_round(Round::Preprocessing).await.unwrap();
        }
        barrier.wait().await;
    }
}

#[tokio::test]
async fn transition_needs_a_quorum_and_ignores_which_parties_form_it() {
    stoffel_mpc_coordinator_shared::setup_test();

    let mut certs = node_certs(5);
    let coordinator = server_cert();
    let port = free_port();
    let execution_id = execution(0x51);
    let server_state = coordinator_state(1, &certs, &coordinator, empty_registration(execution_id));
    let _coord = start_coordinator(server_state, port, &coordinator).await;

    // Deliberately never propose from certs[0] — the party at roster position 0, which used to be
    // the sole proposer. It only observes: subscriptions are for nodes and admitted clients.
    let observer = start_coord_client(execution_id, port, &coordinator, certs.remove(0)).await;
    let mut proposers = Vec::new();
    for cert in certs {
        proposers.push(start_coord_client(execution_id, port, &coordinator, cert).await);
    }

    // Two of five parties is below the quorum of three, so nothing may happen yet.
    for proposer in &proposers[..2] {
        proposer.trigger_round(Round::Preprocessing).await.unwrap();
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            observer.wait_for_round(Round::Preprocessing),
        )
        .await
        .is_err(),
        "a sub-quorum of proposals must not advance the round"
    );

    // The third proposal completes the quorum without party 0 ever participating.
    proposers[2]
        .trigger_round(Round::Preprocessing)
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_millis(2_000),
        observer.wait_for_round(Round::Preprocessing),
    )
    .await
    .expect("quorum of non-designated parties must advance the round")
    .unwrap();

    // The remaining party is simply late; its proposal must not be an error.
    proposers[3]
        .trigger_round(Round::Preprocessing)
        .await
        .expect("a proposal for an already-applied round is late, not invalid");
}

#[tokio::test]
async fn mpc_execution_waits_for_every_masked_input() {
    // Two input slots, so one client can leave the other empty.
    let first = client_cert();
    let second = client_cert();
    let execution_id = execution(0x53);
    let harness = Harness::start(pre_registered(
        execution_id,
        vec![slot(1, 0), slot(1, 0)],
        &[&first, &second],
    ))
    .await;
    let mut clients = [harness.client(&first).await, harness.client(&second).await];
    for (position, client) in clients.iter_mut().enumerate() {
        client
            .associate_client(slot_request(position as u32))
            .await
            .unwrap();
    }

    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    clients[0].reserve_mask_indices(&[0]).await.unwrap();
    clients[1].reserve_mask_indices(&[1]).await.unwrap();
    harness.advance(Round::InputCollection).await;
    clients[0].send_masked_input(Fr::from(7), 0).await.unwrap();

    // Every party proposes MPCExecution while slot 1 is still empty. A malicious proposer that
    // reached this point would be running the program on a censored input set.
    propose_round(&harness.coords, Round::MPCExecution).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            harness.coords[0].wait_for_round(Round::MPCExecution),
        )
        .await
        .is_err(),
        "MPCExecution must not begin while an input slot is unfilled"
    );

    // The proposals are held, not discarded: completing the inputs releases the round without
    // any party having to propose it again.
    clients[1].send_masked_input(Fr::from(9), 1).await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(2_000),
        harness.coords[0].wait_for_round(Round::MPCExecution),
    )
    .await
    .expect("the final input must release the held transition")
    .unwrap();
}

#[tokio::test]
async fn retirement_drains_healthy_stragglers_without_pinning_capacity() {
    stoffel_mpc_coordinator_shared::setup_test();

    let certs = node_certs(5);
    let coordinator = server_cert();
    let public_keys = certs.iter().map(identity_of).collect::<Vec<_>>();
    let execution_id = execution(0x52);
    let mut state = coordinator_state(1, &certs, &coordinator, empty_registration(execution_id));

    // Four of five parties acknowledge; the fifth is faulty or partitioned and never will.
    for public_key in public_keys.iter().take(4) {
        state.retire_execution(execution_id, public_key).unwrap();
    }

    assert!(
        state.is_retired(execution_id),
        "n - t acknowledgements must make the execution reclaimable"
    );
    assert!(
        state.round(execution_id).is_some(),
        "round history must remain available to a healthy straggler"
    );

    // A genuinely absent party cannot pin admission forever. Fill every remaining slot, then
    // prove the next registration compacts the only quorum-retired execution.
    let numbered = |number: usize| {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&(number as u64).to_be_bytes());
        empty_registration(ExecutionId::from_bytes(bytes))
    };
    for number in 1..DEFAULT_MAX_CONCURRENT_EXECUTIONS {
        state.register_execution(numbered(number)).unwrap();
    }
    state
        .register_execution(numbered(DEFAULT_MAX_CONCURRENT_EXECUTIONS))
        .expect("capacity pressure must compact a quorum-retired execution");
    assert!(
        state.round(execution_id).is_none(),
        "capacity reclamation must release the complete execution state"
    );

    // The straggler's eventual acknowledgement still drains the bounded tombstone.
    state
        .retire_execution(execution_id, &public_keys[4])
        .expect("a late acknowledgement must not fail");
    assert!(
        !state.is_retired(execution_id),
        "unanimity must forget the execution entirely"
    );
    state
        .retire_execution(execution_id, &public_keys[0])
        .expect("acknowledging a forgotten execution must be a no-op, not an error");
}

// A client that abandons a still-pending `receive_assigned_mask_shares` subscription (e.g. it
// already obtained enough shares from other nodes and moved on to the next input) must not have
// its next request to the same node mistakenly rejected just because the stale sink is still
// registered.
#[tokio::test]
async fn resubscribing_for_assigned_mask_shares_supersedes_stale_request() {
    stoffel_mpc_coordinator_shared::setup_test();

    let port = free_port();
    let execution_id = execution(0x70);

    let node_cert = server_cert();
    let node = start_node_server(execution_id, port, node_cert.clone()).await;

    let requester_cert = client_cert();
    let requester_id = identity_of(&requester_cert);
    let (cert_der, key_der) = cert_parts(&requester_cert);
    let client = setup_client(
        ADDR,
        port,
        cert_der,
        key_der,
        &ServerPin::Exact(spki_of(&node_cert)),
    )
    .await
    .unwrap()
    .client;

    // Index 0 isn't assigned to anyone yet, so this subscription stays pending, registered as
    // this client's outstanding request. Kept alive (not dropped) for the rest of the test, so
    // no unsubscribe is ever sent for it.
    let _stale_sub =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&client, execution_id, 0, 1)
            .await
            .unwrap();

    // The client moves on to the next input before the first request resolves.
    let mut sub = OffChainNodeRPCClient::receive_assigned_mask_shares(&client, execution_id, 1, 1)
        .await
        .expect("a new request from the same client must supersede the stale one, not be rejected");

    node.add_assigned_reserved_index_for_execution(
        execution_id,
        AssignedMaskReservation {
            client: requester_id,
            reserved_index: 1,
            input_ordinal: 0,
        },
    )
    .await
    .unwrap();
    node.add_mask_share_for_execution(execution_id, 1, &Fr::from(7))
        .await
        .unwrap();

    let assigned_shares = tokio::time::timeout(Duration::from_secs(1), sub.next())
        .await
        .expect("assigned share must be delivered to the superseding subscription")
        .expect("subscription must remain open")
        .expect("assigned share must deserialize");
    assert_eq!(assigned_shares.len(), 1);
    assert_eq!(assigned_shares[0].reserved_index, 1);
}

#[tokio::test]
async fn get_node_roster_is_served_to_a_caller_no_configuration_names() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(4);
    let coordinator = server_cert();
    let roster = roster_of(1, &nodes);
    let execution_id = execution(0x71);
    let state = coordinator_state(1, &nodes, &coordinator, empty_registration(execution_id));
    let port = free_port();
    let server = start_coordinator(state, port, &coordinator).await;

    // A certificate minted here: not a node, not an output client, never registered.
    let stranger = client_cert();
    let (cert_der, key_der) = cert_parts(&stranger);
    let link = CoordinatorLink::connect(
        ADDR,
        port,
        &spki_of(&coordinator),
        Some(roster.digest()),
        cert_der,
        key_der,
    )
    .await
    .expect("any mTLS caller reads the roster");
    assert_eq!(link.node_roster(), &roster);
    assert_eq!(link.own_spki(), &spki_of(&stranger));

    // A node reads the same roster.
    let (cert_der, key_der) = cert_parts(&nodes[2]);
    let node_link =
        CoordinatorLink::connect(ADDR, port, &spki_of(&coordinator), None, cert_der, key_der)
            .await
            .unwrap();
    assert_eq!(node_link.node_roster(), &roster);
    assert_eq!(
        server.state().lock().await.node_roster(),
        link.node_roster()
    );
}

#[tokio::test]
async fn the_node_roster_is_identical_across_calls_for_the_process_lifetime() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let roster = roster_of(1, &nodes);
    let execution_id = execution(0x72);
    let state = coordinator_state(1, &nodes, &coordinator, empty_registration(execution_id));
    let port = free_port();
    let server = start_coordinator(state, port, &coordinator).await;
    let reader = raw_client(port, &coordinator, &client_cert()).await;

    let first = CoordinatorRPCBaseClient::get_node_roster(&reader)
        .await
        .unwrap();
    let first_json = wire_fingerprint(&first);

    // Protocol activity — registrations and transitions — leaves the roster untouched.
    let coords = connect_all(execution_id, port, &coordinator, &nodes).await;
    server
        .state()
        .lock()
        .await
        .register_execution(empty_registration(execution(0x73)))
        .unwrap();
    propose_round(&coords, Round::Preprocessing).await;
    coords[0]
        .wait_for_round(Round::Preprocessing)
        .await
        .unwrap();

    for _ in 0..3 {
        let again = CoordinatorRPCBaseClient::get_node_roster(&reader)
            .await
            .unwrap();
        assert_eq!(wire_fingerprint(&again), first_json);
        assert_eq!(NodeRoster::try_from(again).unwrap(), roster);
    }
    assert_eq!(
        NodeRoster::try_from(first).unwrap().digest(),
        roster.digest()
    );
}

fn wire_fingerprint(wire: &NodeRosterWire) -> String {
    let certificates = wire
        .node_certificates
        .iter()
        .map(|certificate| format!("{:02x?}", certificate.as_bytes()))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}|{}|{}|{}", wire.n, wire.t, wire.digest, certificates)
}

#[tokio::test]
async fn roster_reads_are_rate_limited_per_caller_identity() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let state = CoordinatorRPCServerSharedBase::new(roster_of(1, &nodes), spki_of(&coordinator));
    let port = free_port();
    let _server = start_coordinator(state, port, &coordinator).await;

    let reader = client_cert();
    let first = raw_client(port, &coordinator, &reader).await;
    for _ in 0..SUMMARY_READ_BURST {
        CoordinatorRPCBaseClient::get_node_roster(&first)
            .await
            .unwrap();
    }
    let limited = CoordinatorRPCBaseClient::get_node_roster(&first).await;
    assert_eq!(
        call_code(limited),
        41,
        "an empty bucket answers RateLimited"
    );

    // Reconnecting does not refill the bucket; another identity has its own.
    let reconnected = raw_client(port, &coordinator, &reader).await;
    assert!(CoordinatorRPCBaseClient::get_node_roster(&reconnected)
        .await
        .is_err());
    let other = raw_client(port, &coordinator, &client_cert()).await;
    CoordinatorRPCBaseClient::get_node_roster(&other)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_coordinator_link_refuses_another_coordinator_key_and_an_unexpected_digest() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let state = CoordinatorRPCServerSharedBase::new(roster_of(1, &nodes), spki_of(&coordinator));
    let port = free_port();
    let _server = start_coordinator(state, port, &coordinator).await;

    let (cert_der, key_der) = cert_parts(&client_cert());
    let impostor = server_cert();
    let refused = CoordinatorLink::connect(
        ADDR,
        port,
        &spki_of(&impostor),
        None,
        cert_der.clone(),
        key_der.clone(),
    )
    .await;
    assert!(
        matches!(refused, Err(CoordinatorError::ServerPinMismatch { .. })),
        "a coordinator presenting another key is a pin mismatch, got {:?}",
        refused.err()
    );

    let expected = RosterDigest::from_bytes([7; 32]);
    let unexpected = CoordinatorLink::connect(
        ADDR,
        port,
        &spki_of(&coordinator),
        Some(expected),
        cert_der,
        key_der,
    )
    .await;
    match unexpected {
        Err(CoordinatorError::UnexpectedRosterDigest {
            served,
            expected: reported,
        }) => {
            assert_eq!(served, roster_of(1, &nodes).digest());
            assert_eq!(reported, expected);
        }
        other => panic!("expected UnexpectedRosterDigest, got {:?}", other.err()),
    }
}

/// A coordinator that serves a fixed, possibly tampered, roster wire value.
struct TamperedRosterConnection {
    wire: Arc<Mutex<NodeRosterWire>>,
}

impl RPCServerConnection for TamperedRosterConnection {
    type Internal = NodeRosterWire;

    fn new(internal: Arc<Mutex<Self::Internal>>, _id: Vec<u8>) -> Self {
        Self { wire: internal }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut module = RpcModule::new(self);
        module
            .register_async_method("get_node_roster", |_, connection, _| async move {
                RpcResult::Ok(connection.wire.lock().await.clone())
            })
            .unwrap();
        module
    }
}

#[tokio::test]
async fn a_served_roster_with_a_wrong_digest_is_refused_with_a_typed_error() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let mut wire = roster_of(1, &nodes).to_wire();
    let mut digest = *wire.digest.as_bytes();
    digest[31] ^= 0xff;
    wire.digest = RosterDigest::from_bytes(digest);

    let port = free_port();
    let (server_der, server_key) = cert_parts(&coordinator);
    let _server = stoffel_mpc_coordinator_shared::rpc::start_coord::<TamperedRosterConnection>(
        ADDR,
        port,
        server_der,
        server_key,
        Arc::new(Mutex::new(wire)),
        RpcServerLimits::default(),
    )
    .await
    .unwrap();

    let (cert_der, key_der) = cert_parts(&client_cert());
    let refused =
        CoordinatorLink::connect(ADDR, port, &spki_of(&coordinator), None, cert_der, key_der).await;
    assert!(
        matches!(
            refused,
            Err(CoordinatorError::Roster(RosterError::DigestMismatch))
        ),
        "expected Roster(DigestMismatch), got {:?}",
        refused.err()
    );
}

#[tokio::test]
async fn a_listener_refuses_state_for_a_certificate_it_does_not_serve() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let coordinator = server_cert();
    let other = server_cert();
    let execution_id = execution(0x74);
    let port = free_port();
    let state = || coordinator_state(1, &nodes, &coordinator, empty_registration(execution_id));

    let from_cert = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state(),
        ADDR,
        port,
        other.clone(),
        RpcServerLimits::default(),
    )
    .await;
    assert!(matches!(
        from_cert.err(),
        Some(CoordinatorError::ServerCertificateMismatch)
    ));

    let (other_der, other_key) = cert_parts(&other);
    let standing = HoneyBadgerOffChainCoordinatorServer::start_coord(
        state(),
        ADDR,
        port,
        other_der.clone(),
        other_key.clone(),
        RpcServerLimits::default(),
    )
    .await;
    assert!(matches!(
        standing.err(),
        Some(CoordinatorError::ServerCertificateMismatch)
    ));

    let one_off = HoneyBadgerOffChainCoordinatorServer::start_coord_one_off(
        state(),
        ADDR,
        port,
        other_der,
        other_key,
        OneOffShutdownConfig {
            execution_id,
            grace: Duration::from_millis(10),
        },
        RpcServerLimits::default(),
    )
    .await;
    assert!(matches!(
        one_off,
        Err(CoordinatorError::ServerCertificateMismatch)
    ));

    let unparseable = HoneyBadgerOffChainCoordinatorServer::start_coord(
        state(),
        ADDR,
        port,
        vec![0x30, 0x00],
        cert_parts(&coordinator).1,
        RpcServerLimits::default(),
    )
    .await;
    assert!(matches!(unparseable.err(), Some(CoordinatorError::Pin(_))));

    // Nothing was bound.
    std::net::TcpListener::bind((ADDR, port)).expect("no refused start binds its port");
}

#[tokio::test]
async fn a_node_rpc_client_drops_impostor_and_duplicate_legs_without_failing() {
    stoffel_mpc_coordinator_shared::setup_test();

    let nodes = node_certs(3);
    let roster = roster_of(1, &nodes);
    let execution_id = execution(0x75);
    let member_port = free_port();
    let _member = start_node_server(execution_id, member_port, nodes[0].clone()).await;
    let outsider_port = free_port();
    let _outsider = start_node_server(execution_id, outsider_port, server_cert()).await;

    let outsider = start_node_client(
        execution_id,
        &roster,
        vec![
            (ADDR.to_string(), member_port),
            (ADDR.to_string(), outsider_port),
        ],
        client_cert(),
    )
    .await;
    // The impostor is refused its leg, not granted one — but it does not take the client
    // down with it, or any single roster member could deny every client its masks.
    let outsider = outsider.expect("an impostor leg is dropped, not fatal");
    assert_eq!(
        outsider.leg_count(),
        1,
        "only the genuine roster member's leg is kept"
    );

    let duplicated = start_node_client(
        execution_id,
        &roster,
        vec![
            (ADDR.to_string(), member_port),
            (ADDR.to_string(), member_port),
        ],
        client_cert(),
    )
    .await;
    let duplicated = duplicated.expect("a duplicate leg is dropped, not fatal");
    assert_eq!(
        duplicated.leg_count(),
        1,
        "one member answering twice yields one leg, not an error"
    );

    let too_many = start_node_client(
        execution_id,
        &roster,
        (0..4).map(|_| (ADDR.to_string(), member_port)).collect(),
        client_cert(),
    )
    .await;
    assert!(matches!(
        too_many,
        Err(CoordinatorError::TooManyNodeAddresses { given: 4, n: 3 })
    ));
}

#[tokio::test]
async fn masks_reconstruct_by_roster_position_and_ignore_relabelled_shares() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n = 4;
    let t = 1;
    let nodes = node_certs(n);
    let roster = roster_of(t as u64, &nodes);
    let execution_id = execution(0x76);
    let client = client_cert();
    let reservation = AssignedMaskReservation {
        client: identity_of(&client),
        reserved_index: 0,
        input_ordinal: 0,
    };
    let mask = Fr::from(99);
    let shares = HoneyBadgerShareType::compute_shares(mask, n, t, None, &mut test_rng()).unwrap();

    let mut ports = Vec::new();
    let mut servers = Vec::new();
    for (position, node) in nodes.iter().enumerate() {
        let port = free_port();
        let server = start_node_server(execution_id, port, node.clone()).await;
        server
            .add_assigned_reserved_index_for_execution(execution_id, reservation.clone())
            .await
            .unwrap();
        // Position 3 relabels its share with position 0's id; it must contribute nothing.
        let share = if position == 3 {
            let mut relabelled = shares[3].clone();
            relabelled.id = 0;
            relabelled
        } else {
            shares[position].clone()
        };
        server
            .add_mask_share_for_execution(execution_id, 0, &share)
            .await
            .unwrap();
        ports.push(port);
        servers.push(server);
    }

    // Listing the relabelling node first changes nothing: shares are bound to positions, not
    // to arrival order.
    let addrs = [3, 0, 1, 2]
        .map(|position| (ADDR.to_string(), ports[position]))
        .to_vec();
    let rpc_client = start_node_client(execution_id, &roster, addrs, client.clone())
        .await
        .unwrap();
    assert_eq!(
        rpc_client.receive_assigned_masks(0, 1).await.unwrap(),
        vec![mask]
    );

    // With the relabelling node and one honest node only, nothing is conclusive.
    let addrs = [3, 0]
        .map(|position| (ADDR.to_string(), ports[position]))
        .to_vec();
    let rpc_client = start_node_client(execution_id, &roster, addrs, client)
        .await
        .unwrap();
    assert!(matches!(
        rpc_client.receive_assigned_masks(0, 1).await,
        Err(CoordinatorError::MaskReconstructionFailed { index: 0 })
    ));
}

/// A hostile admitted client parks, before any reservation is registered, a range covering
/// another client's indices on every node. Registration must still succeed on every node, the
/// honest client must still reconstruct its masks, and only the hostile request fails.
#[tokio::test]
async fn a_parked_cross_slot_range_cannot_block_registration_or_other_clients_masks() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n = 4;
    let t = 1;
    let nodes = node_certs(n);
    let roster = roster_of(t as u64, &nodes);
    let execution_id = execution(0x7a);
    let honest = client_cert();
    let hostile = client_cert();
    // The hostile client holds index 0; the honest client holds indices 1 and 2.
    let reservations = vec![
        AssignedMaskReservation {
            client: identity_of(&hostile),
            reserved_index: 0,
            input_ordinal: 0,
        },
        AssignedMaskReservation {
            client: identity_of(&honest),
            reserved_index: 1,
            input_ordinal: 0,
        },
        AssignedMaskReservation {
            client: identity_of(&honest),
            reserved_index: 2,
            input_ordinal: 1,
        },
    ];
    let masks = [Fr::from(7), Fr::from(11), Fr::from(13)];
    let shares = masks
        .iter()
        .map(|mask| {
            HoneyBadgerShareType::compute_shares(*mask, n, t, None, &mut test_rng()).unwrap()
        })
        .collect::<Vec<_>>();

    let mut ports = Vec::new();
    let mut servers = Vec::new();
    let mut hostile_subscriptions = Vec::new();
    for node in &nodes {
        let port = free_port();
        let server = start_node_server(execution_id, port, node.clone()).await;
        let (cert_der, key_der) = cert_parts(&hostile);
        let raw = setup_client(
            ADDR,
            port,
            cert_der,
            key_der,
            &ServerPin::Exact(spki_of(node)),
        )
        .await
        .unwrap()
        .client;
        // Parks: nothing is registered yet, so the node cannot tell the range is not its own.
        let subscription =
            OffChainNodeRPCClient::receive_assigned_mask_shares(&raw, execution_id, 0, 3)
                .await
                .unwrap();
        assert_eq!(parked_mask_requests(&server, execution_id).await, 1);
        hostile_subscriptions.push((raw, subscription));
        ports.push(port);
        servers.push(server);
    }

    // The honest client parks its own range on every node before registration too.
    let addrs = ports
        .iter()
        .map(|port| (ADDR.to_string(), *port))
        .collect::<Vec<_>>();
    let rpc_client = start_node_client(execution_id, &roster, addrs, honest.clone())
        .await
        .unwrap();
    let honest_masks = tokio::spawn(async move { rpc_client.receive_assigned_masks(1, 2).await });
    for server in &servers {
        for _ in 0..50 {
            if parked_mask_requests(server, execution_id).await == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(parked_mask_requests(server, execution_id).await, 2);
    }

    for (position, server) in servers.iter().enumerate() {
        server
            .add_assigned_reserved_indices_for_execution(execution_id, reservations.clone())
            .await
            .expect("a hostile parked range never fails registration");
        // The hostile request names index 1, which is not its caller's: it is dropped, and
        // the honest request stays parked until its shares arrive.
        assert_eq!(parked_mask_requests(server, execution_id).await, 1);
        let position_shares = shares
            .iter()
            .map(|per_mask| per_mask[position].clone())
            .collect::<Vec<_>>();
        let batch = position_shares
            .iter()
            .enumerate()
            .map(|(i, share)| (i as u64, share))
            .collect::<Vec<_>>();
        server
            .add_mask_shares_for_execution(execution_id, &batch)
            .await
            .expect("mask shares are added after a hostile parked range");
        assert_eq!(parked_mask_requests(server, execution_id).await, 0);
    }

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), honest_masks)
            .await
            .expect("the honest client is answered")
            .unwrap()
            .unwrap(),
        vec![masks[1], masks[2]]
    );

    // Every hostile stream ends without an answer.
    for (_raw, mut subscription) in hostile_subscriptions {
        assert!(
            tokio::time::timeout(Duration::from_secs(2), subscription.next())
                .await
                .expect("the refused request's stream ends")
                .is_none()
        );
    }

    // Once registered, the same cross-slot range is refused outright, and the hostile client's
    // own index is still served.
    let (cert_der, key_der) = cert_parts(&hostile);
    let raw = setup_client(
        ADDR,
        ports[0],
        cert_der,
        key_der,
        &ServerPin::Exact(spki_of(&nodes[0])),
    )
    .await
    .unwrap()
    .client;
    assert!(
        OffChainNodeRPCClient::receive_assigned_mask_shares(&raw, execution_id, 0, 3)
            .await
            .is_err()
    );
    assert_eq!(parked_mask_requests(&servers[0], execution_id).await, 0);
    let mut own = OffChainNodeRPCClient::receive_assigned_mask_shares(&raw, execution_id, 0, 1)
        .await
        .unwrap();
    let answer = own.next().await.unwrap().unwrap();
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].reserved_index, 0);
}

/// A refused registration batch leaves nothing behind, so the corrected batch still lands.
#[tokio::test]
async fn a_refused_registration_batch_registers_nothing() {
    stoffel_mpc_coordinator_shared::setup_test();

    let execution_id = execution(0x7b);
    let node = server_cert();
    let server = start_node_server(execution_id, free_port(), node).await;
    let client = client_cert();
    let reservation = |reserved_index, input_ordinal| AssignedMaskReservation {
        client: identity_of(&client),
        reserved_index,
        input_ordinal,
    };

    // Index 1 appears twice in one batch.
    assert!(matches!(
        server
            .add_assigned_reserved_indices_for_execution(
                execution_id,
                vec![reservation(0, 0), reservation(1, 1), reservation(1, 2)],
            )
            .await,
        Err(NodeRPCError::IndexAlreadyAdded)
    ));
    server
        .add_assigned_reserved_indices_for_execution(
            execution_id,
            vec![reservation(0, 0), reservation(1, 1)],
        )
        .await
        .expect("nothing from the refused batch was registered");

    let share = HoneyBadgerShareType::compute_shares(Fr::from(5), 4, 1, None, &mut test_rng())
        .unwrap()
        .remove(0);
    assert!(matches!(
        server
            .add_mask_shares_for_execution(execution_id, &[(0, &share), (0, &share)])
            .await,
        Err(NodeRPCError::IndexAlreadyAdded)
    ));
    server
        .add_mask_shares_for_execution(execution_id, &[(0, &share), (1, &share)])
        .await
        .expect("nothing from the refused share batch was recorded");
}

/// Opens a raw node RPC connection as `cert`, pinned to `node`.
async fn raw_node_client(port: u16, node: &Certified, cert: &Certified) -> Client {
    let (cert_der, key_der) = cert_parts(cert);
    setup_client(
        ADDR,
        port,
        cert_der,
        key_der,
        &ServerPin::Exact(spki_of(node)),
    )
    .await
    .unwrap()
    .client
}

/// Waits until `server` holds `expected` parked mask requests for `execution_id`.
async fn wait_for_parked_mask_requests(
    server: &HoneyBadgerNodeRPCServer,
    execution_id: ExecutionId,
    expected: usize,
) {
    for _ in 0..100 {
        if parked_mask_requests(server, execution_id).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(parked_mask_requests(server, execution_id).await, expected);
}

/// A parked mask subscription keeps nothing of its execution alive: retiring the execution
/// frees its state and closes the parked caller's stream, even while the caller stays
/// connected.
#[tokio::test]
async fn retiring_an_execution_closes_its_parked_mask_subscriptions_and_frees_its_state() {
    stoffel_mpc_coordinator_shared::setup_test();

    let execution_id = execution(0x7c);
    let node = server_cert();
    let port = free_port();
    let server = start_node_server(execution_id, port, node.clone()).await;
    let client = client_cert();
    let raw = raw_node_client(port, &node, &client).await;
    let mut subscription =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&raw, execution_id, 0, 1)
            .await
            .unwrap();
    wait_for_parked_mask_requests(&server, execution_id, 1).await;
    let probe = execution_state_probe(&server, execution_id).await.unwrap();
    assert!(!probe.is_dropped());

    assert!(server.retire_execution(execution_id).await);

    assert!(
        tokio::time::timeout(Duration::from_secs(2), subscription.next())
            .await
            .expect("retirement closes the parked stream")
            .is_none_or(|item| item.is_err())
    );
    for _ in 0..100 {
        if probe.is_dropped() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        probe.is_dropped(),
        "no parked subscription keeps a retired execution's state alive"
    );
    // The client is still connected; only its subscription ended.
    assert!(raw.is_connected());
}

/// Sealing the admitted reservations drops every parked request that can no longer complete —
/// from an identity holding no reservation, or over an index no one holds — and refuses such a
/// request at subscribe time afterwards, while an owner's request is still answered.
#[tokio::test]
async fn sealing_reservations_drops_and_refuses_requests_that_can_never_complete() {
    stoffel_mpc_coordinator_shared::setup_test();

    let execution_id = execution(0x7d);
    let node = server_cert();
    let port = free_port();
    let server = start_node_server(execution_id, port, node.clone()).await;
    let owner = client_cert();
    let partial_owner = client_cert();
    let unreserved = client_cert();
    let reservations = vec![
        AssignedMaskReservation {
            client: identity_of(&owner),
            reserved_index: 0,
            input_ordinal: 0,
        },
        AssignedMaskReservation {
            client: identity_of(&owner),
            reserved_index: 1,
            input_ordinal: 1,
        },
        AssignedMaskReservation {
            client: identity_of(&partial_owner),
            reserved_index: 2,
            input_ordinal: 0,
        },
    ];

    // Before registration, none of the three can be told apart from an honest request.
    let owner_raw = raw_node_client(port, &node, &owner).await;
    let mut owner_subscription =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&owner_raw, execution_id, 0, 2)
            .await
            .unwrap();
    let partial_raw = raw_node_client(port, &node, &partial_owner).await;
    // Index 3 is never reserved.
    let mut partial_subscription =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&partial_raw, execution_id, 2, 2)
            .await
            .unwrap();
    let unreserved_raw = raw_node_client(port, &node, &unreserved).await;
    // Index 5 is never reserved either, and its caller holds nothing.
    let mut unreserved_subscription =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&unreserved_raw, execution_id, 5, 1)
            .await
            .unwrap();
    wait_for_parked_mask_requests(&server, execution_id, 3).await;

    server
        .register_admitted_reservations_for_execution(execution_id, reservations)
        .await
        .unwrap();
    assert_eq!(parked_mask_requests(&server, execution_id).await, 1);
    for subscription in [&mut partial_subscription, &mut unreserved_subscription] {
        assert!(
            tokio::time::timeout(Duration::from_secs(2), subscription.next())
                .await
                .expect("a request that can never complete is closed at sealing")
                .is_none_or(|item| item.is_err())
        );
    }

    // Afterwards the same requests are refused outright, and nothing is parked for them.
    assert!(OffChainNodeRPCClient::receive_assigned_mask_shares(
        &unreserved_raw,
        execution_id,
        5,
        1
    )
    .await
    .is_err());
    assert!(
        OffChainNodeRPCClient::receive_assigned_mask_shares(&partial_raw, execution_id, 2, 2)
            .await
            .is_err()
    );
    assert_eq!(parked_mask_requests(&server, execution_id).await, 1);

    // Nothing can be registered after sealing, incrementally or by sealing again.
    let late = AssignedMaskReservation {
        client: identity_of(&unreserved),
        reserved_index: 5,
        input_ordinal: 0,
    };
    assert!(matches!(
        server
            .add_assigned_reserved_index_for_execution(execution_id, late.clone())
            .await,
        Err(NodeRPCError::ReservationsSealed)
    ));
    assert!(matches!(
        server
            .register_admitted_reservations_for_execution(execution_id, vec![late])
            .await,
        Err(NodeRPCError::ReservationsSealed)
    ));

    // The owner's parked request is still answered once its shares arrive.
    let shares = [Fr::from(3), Fr::from(4), Fr::from(5)].map(|mask| {
        HoneyBadgerShareType::compute_shares(mask, 4, 1, None, &mut test_rng())
            .unwrap()
            .remove(0)
    });
    let batch = shares
        .iter()
        .enumerate()
        .map(|(i, share)| (i as u64, share))
        .collect::<Vec<_>>();
    server
        .add_mask_shares_for_execution(execution_id, &batch)
        .await
        .unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(2), owner_subscription.next())
        .await
        .expect("the owner is answered")
        .unwrap()
        .unwrap();
    assert_eq!(
        answer
            .iter()
            .map(|share| share.reserved_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    // The partial owner's own index is still served.
    let mut own =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&partial_raw, execution_id, 2, 1)
            .await
            .unwrap();
    assert_eq!(own.next().await.unwrap().unwrap()[0].reserved_index, 2);
}

#[tokio::test]
async fn a_leg_that_refuses_the_subscription_does_not_deny_the_mask() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n = 4;
    let t = 1;
    let nodes = node_certs(n);
    let roster = roster_of(t as u64, &nodes);
    let execution_id = execution(0x77);
    let client = client_cert();
    let reservation = AssignedMaskReservation {
        client: identity_of(&client),
        reserved_index: 0,
        input_ordinal: 0,
    };
    let mask = Fr::from(1234);
    let shares = HoneyBadgerShareType::compute_shares(mask, n, t, None, &mut test_rng()).unwrap();

    let mut ports = Vec::new();
    let mut servers = Vec::new();
    for (position, node) in nodes.iter().enumerate() {
        let port = free_port();
        let server = start_node_server(execution_id, port, node.clone()).await;
        server
            .add_assigned_reserved_index_for_execution(execution_id, reservation.clone())
            .await
            .unwrap();
        server
            .add_mask_share_for_execution(execution_id, 0, &shares[position])
            .await
            .unwrap();
        ports.push(port);
        servers.push(server);
    }

    // Position 0 retires the execution, so it rejects the subscription with ExecutionNotFound.
    // It is listed first so that a sequential subscribe loop would fail before reaching any
    // honest leg.
    assert!(servers[0].retire_execution(execution_id).await);

    let addrs = (0..n)
        .map(|position| (ADDR.to_string(), ports[position]))
        .collect::<Vec<_>>();
    let rpc_client = start_node_client(execution_id, &roster, addrs, client)
        .await
        .unwrap();
    let masks = tokio::time::timeout(
        Duration::from_secs(10),
        rpc_client.receive_assigned_masks(0, 1),
    )
    .await
    .expect("the 2t+1 answering legs must suffice without waiting on the refusing leg")
    .expect("a refusing leg contributes nothing but does not fail the call");
    assert_eq!(masks, vec![mask]);
}

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn registration_checks_state_in_order_and_never_evicts_for_a_refused_one() {
    stoffel_mpc_coordinator_shared::setup_test();
    let nodes = node_certs(4);
    let coordinator = server_cert();
    let mut state =
        CoordinatorRPCServerSharedBase::new(roster_of(1, &nodes), spki_of(&coordinator));

    // An identical registration of a live execution answers its nonce, even past its
    // association deadline, when validating it again would fail with `DeadlineElapsed`.
    let live = registration(
        execution(0x81),
        vec![slot(1, 0)],
        AdmissionPolicy::Open,
        deadlines_in(1, 600),
    );
    let nonce = state.register_execution(live.clone()).unwrap();
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert!(matches!(
        live.validate(state.node_roster(), state.server_spki(), UnixSeconds::now()),
        Err(RegistrationError::DeadlineElapsed { .. })
    ));
    assert_eq!(state.register_execution(live.clone()).unwrap(), nonce);

    // A different registration of the live id conflicts.
    assert!(matches!(
        state.register_execution(ExecutionRegistration {
            program_hash: [2; 32],
            ..live.clone()
        }),
        Err(CoordinatorError::Registration(
            RegistrationError::ConflictingRegistration { .. }
        ))
    ));

    // An ended id is retired, whatever the registration.
    let ended = empty_registration(execution(0x82));
    state.register_execution(ended.clone()).unwrap();
    for node in &nodes {
        state
            .retire_execution(ended.execution_id, &identity_of(node))
            .unwrap();
    }
    assert_eq!(state.round(ended.execution_id), None);
    assert!(matches!(
        state.register_execution(ended),
        Err(CoordinatorError::Registration(
            RegistrationError::ExecutionIdRetired { .. }
        ))
    ));

    // At capacity, with one evictable execution, a registration that fails `validate` is
    // refused and evicts nothing.
    let numbered = |number: usize| {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(number as u64).to_be_bytes());
        empty_registration(ExecutionId::from_bytes(bytes))
    };
    for number in 1..DEFAULT_MAX_CONCURRENT_EXECUTIONS {
        state.register_execution(numbered(number)).unwrap();
    }
    let evictable = numbered(1).execution_id;
    for node in nodes.iter().take(3) {
        state
            .retire_execution(evictable, &identity_of(node))
            .unwrap();
    }
    assert!(state.is_retired(evictable));
    assert!(matches!(
        state.register_execution(ExecutionRegistration {
            program_hash: [0; 32],
            ..numbered(DEFAULT_MAX_CONCURRENT_EXECUTIONS)
        }),
        Err(CoordinatorError::Registration(
            RegistrationError::ZeroProgramHash
        ))
    ));
    assert!(
        state.round(evictable).is_some(),
        "a refused registration never evicts"
    );
    state
        .register_execution(numbered(DEFAULT_MAX_CONCURRENT_EXECUTIONS))
        .unwrap();
    assert_eq!(state.round(evictable), None);

    // With nothing evictable, capacity is reached.
    assert!(matches!(
        state.register_execution(numbered(DEFAULT_MAX_CONCURRENT_EXECUTIONS + 1)),
        Err(CoordinatorError::Registration(
            RegistrationError::ExecutionCapacityReached { .. }
        ))
    ));
}

#[tokio::test]
async fn deleted_methods_are_not_rpc_methods() {
    let harness = Harness::start(empty_registration(execution(0x83))).await;
    let raw = harness.raw(&harness.nodes[0]).await;
    const METHOD_NOT_FOUND: i32 = -32601;
    for method in [
        "register_execution",
        "request_shutdown",
        "available_input_masks",
        "reserve_mask_index",
        "submit_masked_input",
    ] {
        let result = ClientT::request::<serde_json::Value, _>(&raw, method, rpc_params![]).await;
        assert_eq!(call_code(result), METHOD_NOT_FOUND, "{method}");
    }
    for (method, unsubscribe) in [
        (
            "sub_assigned_reserved_indices",
            "unsub_assigned_reserved_indices",
        ),
        ("sub_assigned_masked_inputs", "unsub_assigned_masked_inputs"),
    ] {
        let result = SubscriptionClientT::subscribe::<serde_json::Value, _>(
            &raw,
            method,
            rpc_params![],
            unsubscribe,
        )
        .await;
        assert_eq!(call_code(result), METHOD_NOT_FOUND, "{method}");
    }
}

#[tokio::test]
async fn summary_reads_are_rate_limited_per_identity() {
    let execution_id = execution(0x84);
    let harness = Harness::start(open_registration(execution_id, vec![slot(1, 0)])).await;
    let reader = client_cert();
    let raw = harness.raw(&reader).await;

    // Both read methods draw on one bucket.
    for call in 0..SUMMARY_READ_BURST {
        if call % 2 == 0 {
            CoordinatorRPCBaseClient::get_execution_summary(&raw, execution_id)
                .await
                .unwrap();
        } else {
            CoordinatorRPCBaseClient::get_node_roster(&raw)
                .await
                .unwrap();
        }
    }
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::get_execution_summary(&raw, execution_id).await),
        41
    );
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::get_node_roster(&raw).await),
        41
    );

    // Another identity is unaffected.
    let other = harness.raw(&client_cert()).await;
    let summary = CoordinatorRPCBaseClient::get_execution_summary(&other, execution_id)
        .await
        .unwrap();
    assert_eq!(summary.admission, AdmissionPolicyKind::Open);

    // A token returns after a second.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    CoordinatorRPCBaseClient::get_execution_summary(&raw, execution_id)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn pre_registered_admission_binds_only_the_registered_identities() {
    let first = client_cert();
    let second = client_cert();
    let execution_id = execution(0x85);
    let harness = Harness::start(pre_registered(
        execution_id,
        vec![slot(2, 1), slot(1, 0)],
        &[&first, &second],
    ))
    .await;

    let mut first_client = harness.client(&first).await;
    let admission = first_client.associate_client(open_request()).await.unwrap();
    assert_eq!(
        admission,
        ClientAdmission {
            execution_id,
            client_index: ClientIndex(0),
            input_range: Some(range(0, 2)),
            output_rights: receive(1),
        }
    );
    assert_eq!(first_client.admission(), Some(&admission));

    let mut stranger = harness.client(&client_cert()).await;
    assert_eq!(
        admission_error(stranger.associate_client(open_request()).await),
        AdmissionError::NotPreRegistered { execution_id }
    );

    let mut second_client = harness.client(&second).await;
    assert_eq!(
        admission_error(second_client.associate_client(slot_request(0)).await),
        AdmissionError::PreRegisteredSlotMismatch {
            registered: ClientIndex(1),
            requested: ClientIndex(0),
        }
    );
    let admission = second_client
        .associate_client(slot_request(1))
        .await
        .unwrap();
    assert_eq!(admission.input_range, Some(range(2, 1)));
    assert_eq!(admission.output_rights, OutputRights::None);

    // Pre-registered identities are bound clients from the start; a stranger is not.
    let state = harness.server.state();
    let state = state.lock().await;
    assert_eq!(
        state.capacity_class(&identity_of(&first)),
        stoffel_mpc_coordinator_shared::rpc::CapacityClass::BoundClient
    );
    assert_eq!(
        state.capacity_class(&identity_of(&client_cert())),
        stoffel_mpc_coordinator_shared::rpc::CapacityClass::Unreserved
    );
}

#[tokio::test]
async fn open_admission_binds_disjoint_ranges_first_come_first_served() {
    let execution_id = execution(0x86);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(2, 0), slot(3, 1), slot(1, 0)],
    ))
    .await;
    let certs = (0..4).map(|_| client_cert()).collect::<Vec<_>>();
    let mut clients = Vec::new();
    for cert in &certs {
        clients.push(harness.client(cert).await);
    }

    let explicit = clients[0].associate_client(slot_request(1)).await.unwrap();
    assert_eq!(explicit.client_index, ClientIndex(1));
    assert_eq!(explicit.input_range, Some(range(2, 3)));
    assert_eq!(explicit.output_rights, receive(1));

    let lowest_free = clients[1].associate_client(open_request()).await.unwrap();
    assert_eq!(lowest_free.client_index, ClientIndex(0));
    assert_eq!(lowest_free.input_range, Some(range(0, 2)));

    assert_eq!(
        admission_error(clients[2].associate_client(slot_request(1)).await),
        AdmissionError::SlotTaken {
            execution_id,
            requested: ClientIndex(1)
        }
    );
    let last = clients[2].associate_client(open_request()).await.unwrap();
    assert_eq!(last.client_index, ClientIndex(2));
    assert_eq!(last.input_range, Some(range(5, 1)));

    assert_eq!(
        admission_error(clients[3].associate_client(slot_request(3)).await),
        AdmissionError::SlotOutOfRange {
            execution_id,
            requested: ClientIndex(3),
            slots: 3
        }
    );

    // The ranges partition [0, n_inputs).
    let mut covered = [lowest_free, explicit, last]
        .iter()
        .filter_map(|admission| admission.input_range)
        .flat_map(|range| range.start..range.end())
        .collect::<Vec<_>>();
    covered.sort_unstable();
    assert_eq!(covered, (0..6).collect::<Vec<_>>());
}

#[tokio::test]
async fn open_admission_refuses_association_past_capacity() {
    let execution_id = execution(0x87);
    let harness = Harness::start(open_registration(execution_id, vec![slot(1, 1)])).await;
    let mut first = harness.client(&client_cert()).await;
    first.associate_client(open_request()).await.unwrap();
    let mut second = harness.client(&client_cert()).await;
    assert_eq!(
        admission_error(second.associate_client(open_request()).await),
        AdmissionError::CapacityExhausted {
            execution_id,
            capacity: 1
        }
    );
    assert!(second.admission().is_none());
}

#[tokio::test]
async fn associate_client_is_idempotent_for_an_identical_request_and_refuses_a_different_one() {
    let execution_id = execution(0x88);
    // An output-only slot, so the rounds run without inputs; removal follows unanimity at once.
    let harness = Harness::start_with(
        4,
        open_registration(execution_id, vec![slot(0, 1)]),
        |state| state.with_output_retention(Duration::ZERO),
    )
    .await;
    let cert = client_cert();
    let mut client = harness.client(&cert).await;
    let admission = client.associate_client(open_request()).await.unwrap();

    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    harness.advance(Round::InputCollection).await;
    // A restarted client presenting the identical request, in a later round.
    let mut restarted = harness.client(&cert).await;
    assert_eq!(
        restarted.associate_client(open_request()).await.unwrap(),
        admission
    );
    assert_eq!(
        admission_error(restarted.associate_client(slot_request(0)).await),
        AdmissionError::AlreadyAssociated {
            execution_id,
            admission: admission.clone()
        }
    );

    // Once the execution is removed, there is nothing to answer from.
    harness.advance(Round::MPCExecution).await;
    harness.advance(Round::OutputDistribution).await;
    harness.advance(Round::ProgramFinished).await;
    for coord in &harness.coords {
        coord.retire_execution().await.unwrap();
    }
    for _ in 0..100 {
        if harness.round().await.is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        refusal_of(restarted.associate_client(open_request()).await),
        RpcRefusal::ExecutionNotFound
    );
}

#[tokio::test]
async fn association_closes_when_input_collection_begins() {
    let execution_id = execution(0x89);
    let harness = Harness::start(open_registration(execution_id, vec![slot(1, 0)])).await;
    harness
        .client(&client_cert())
        .await
        .associate_client(open_request())
        .await
        .unwrap();
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    harness.advance(Round::InputCollection).await;

    let mut late = harness.client(&client_cert()).await;
    assert_eq!(
        admission_error(late.associate_client(open_request()).await),
        AdmissionError::AssociationClosed {
            execution_id,
            current: Round::InputCollection
        }
    );
}

/// An invitation from `issuer` for `invitee` to `client_index` of the harness's execution.
async fn invitation_for(
    harness: &Harness,
    issuer: &Certified,
    invitee: &Certified,
    client_index: u32,
) -> SignedInvitation {
    let invitation = Invitation {
        execution_id: harness.execution_id,
        registration_nonce: harness.nonce().await,
        program_hash: [1; 32],
        roster_digest: roster_of(1, &harness.nodes).digest(),
        not_after: UnixSeconds(UnixSeconds::now().0 + 300),
        invitee: identity_of(invitee),
        client_index: ClientIndex(client_index),
    };
    SignedInvitation::sign(invitation, &issuer.signing_key.serialize_der()).unwrap()
}

fn invitation_registration(
    execution_id: ExecutionId,
    issuer: &Certified,
    slots: Vec<ClientSlotSpec>,
) -> ExecutionRegistration {
    registration(
        execution_id,
        slots,
        AdmissionPolicy::Invitation {
            issuer: InvitationIssuer::new(spki_of(issuer)),
        },
        deadlines_in(600, 1200),
    )
}

fn with_invitation(invitation: SignedInvitation) -> AssociationRequest {
    AssociationRequest {
        slot: None,
        invitation: Some(invitation),
    }
}

#[tokio::test]
async fn invitation_admission_accepts_a_valid_invitation_and_refuses_every_forgery() {
    let issuer = client_cert();
    let execution_id = execution(0x8a);
    let harness = Harness::start(invitation_registration(
        execution_id,
        &issuer,
        vec![slot(1, 1), slot(1, 0)],
    ))
    .await;
    let invitee = client_cert();
    let mut client = harness.client(&invitee).await;
    let valid = invitation_for(&harness, &issuer, &invitee, 0).await;

    assert_eq!(
        admission_error(client.associate_client(open_request()).await),
        AdmissionError::InvitationRequired { execution_id }
    );

    let resign = |mutate: &dyn Fn(&mut Invitation)| {
        let mut invitation = valid.invitation.clone();
        mutate(&mut invitation);
        SignedInvitation::sign(invitation, &issuer.signing_key.serialize_der()).unwrap()
    };
    let now = UnixSeconds::now().0;
    let other_invitee = client_cert();
    let mut bad_signature = valid.clone();
    bad_signature.invitation.not_after = UnixSeconds(now + 301);
    let forgeries = [
        (
            resign(&|invitation| invitation.execution_id = execution(0x8b)),
            InvitationRejection::WrongExecution,
        ),
        (
            resign(&|invitation| {
                invitation.registration_nonce = RegistrationNonce::from_bytes([9; 32])
            }),
            InvitationRejection::WrongRegistration,
        ),
        (
            resign(&|invitation| invitation.program_hash = [2; 32]),
            InvitationRejection::WrongProgram,
        ),
        (
            resign(&|invitation| invitation.roster_digest = RosterDigest::from_bytes([3; 32])),
            InvitationRejection::WrongRoster,
        ),
        (
            resign(&|invitation| invitation.not_after = UnixSeconds(now - 10)),
            InvitationRejection::Expired {
                not_after: UnixSeconds(now - 10),
                now: UnixSeconds::now(),
            },
        ),
        (
            resign(&|invitation| invitation.invitee = identity_of(&other_invitee)),
            InvitationRejection::WrongInvitee,
        ),
        (bad_signature, InvitationRejection::BadSignature),
        (
            SignedInvitation::sign(
                valid.invitation.clone(),
                &client_cert().signing_key.serialize_der(),
            )
            .unwrap(),
            InvitationRejection::BadSignature,
        ),
    ];
    // Raw calls: the client library reads the (rate-limited) summary before every association.
    let raw = harness.raw(&invitee).await;
    for (forgery, expected) in forgeries {
        let refused = CoordinatorRPCBaseClient::associate_client(
            &raw,
            execution_id,
            with_invitation(forgery),
        )
        .await;
        match raw_admission_error(refused) {
            AdmissionError::InvitationRejected {
                reason: InvitationRejection::Expired { not_after, .. },
            } => assert!(
                matches!(expected, InvitationRejection::Expired { not_after: expected_not_after, .. } if expected_not_after == not_after)
            ),
            AdmissionError::InvitationRejected { reason } => assert_eq!(reason, expected),
            other => panic!("expected InvitationRejected({expected:?}), got {other:?}"),
        }
    }

    let admission = client
        .associate_client(with_invitation(valid.clone()))
        .await
        .unwrap();
    assert_eq!(admission.client_index, ClientIndex(0));
    assert_eq!(admission.output_rights, receive(1));
    // The identical request again is the idempotent case, not a replay.
    assert_eq!(
        client
            .associate_client(with_invitation(valid))
            .await
            .unwrap(),
        admission
    );

    // An invitation presented to an `Open` execution is refused, not ignored.
    let open_id = execution(0x8c);
    harness
        .server
        .state()
        .lock()
        .await
        .register_execution(open_registration(open_id, vec![slot(1, 0)]))
        .unwrap();
    let mut open_client =
        start_coord_client(open_id, harness.port, &harness.coordinator, invitee.clone()).await;
    let invitation = invitation_for(&harness, &issuer, &invitee, 0).await;
    assert_eq!(
        admission_error(
            open_client
                .associate_client(with_invitation(invitation))
                .await
        ),
        AdmissionError::UnexpectedInvitation {
            execution_id: open_id
        }
    );
}

#[tokio::test]
async fn an_invitation_for_an_earlier_registration_of_the_same_id_is_refused() {
    let issuer = client_cert();
    let invitee = client_cert();
    let execution_id = execution(0x8d);
    let registration = invitation_registration(execution_id, &issuer, vec![slot(1, 0)]);
    let first = Harness::start(registration.clone()).await;
    let old_invitation = invitation_for(&first, &issuer, &invitee, 0).await;
    let old_nonce = first.nonce().await;

    // The coordinator restarts with the same roster, key, id and registration.
    let Harness {
        server,
        coordinator,
        nodes,
        ..
    } = first;
    server.shutdown().await;
    let state = coordinator_state(1, &nodes, &coordinator, registration);
    let port = free_port();
    let restarted = start_coordinator(state, port, &coordinator).await;
    let new_nonce = restarted
        .state()
        .lock()
        .await
        .registration_nonce(execution_id)
        .unwrap();
    assert_ne!(old_nonce, new_nonce, "a new registration draws a new nonce");

    let mut client = start_coord_client(execution_id, port, &coordinator, invitee).await;
    assert_eq!(
        admission_error(
            client
                .associate_client(with_invitation(old_invitation))
                .await
        ),
        AdmissionError::InvitationRejected {
            reason: InvitationRejection::WrongRegistration
        }
    );
}

#[tokio::test]
async fn an_invitation_binds_only_the_slot_it_names() {
    let issuer = client_cert();
    let execution_id = execution(0x8e);
    // Slot 0 is input-only, slot 1 receives outputs.
    let harness = Harness::start(invitation_registration(
        execution_id,
        &issuer,
        vec![slot(1, 0), slot(0, 1)],
    ))
    .await;
    let input_invitee = client_cert();
    let output_invitee = client_cert();
    let mut input_client = harness.client(&input_invitee).await;
    let for_slot_0 = invitation_for(&harness, &issuer, &input_invitee, 0).await;

    assert_eq!(
        admission_error(
            input_client
                .associate_client(AssociationRequest {
                    slot: Some(ClientIndex(1)),
                    invitation: Some(for_slot_0.clone()),
                })
                .await
        ),
        AdmissionError::InvitationRejected {
            reason: InvitationRejection::SlotMismatch {
                invited: ClientIndex(0),
                requested: ClientIndex(1)
            }
        }
    );
    let admission = input_client
        .associate_client(with_invitation(for_slot_0))
        .await
        .unwrap();
    assert_eq!(admission.client_index, ClientIndex(0));
    assert_eq!(admission.output_rights, OutputRights::None);

    // Slot 1 is still there for the invitation that names it.
    let mut output_client = harness.client(&output_invitee).await;
    let for_slot_1 = invitation_for(&harness, &issuer, &output_invitee, 1).await;
    let admission = output_client
        .associate_client(with_invitation(for_slot_1))
        .await
        .unwrap();
    assert_eq!(admission.client_index, ClientIndex(1));
    assert_eq!(admission.output_rights, receive(1));
}

#[tokio::test]
async fn an_output_slot_refuses_a_key_output_shares_cannot_be_sealed_to() {
    let execution_id = execution(0x8f);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(1, 1), slot(1, 0)],
    ))
    .await;
    let ed = ed25519_cert();
    let mut client = harness.client(&ed).await;
    // The lowest free slot receives outputs, which cannot be sealed to an Ed25519 key.
    assert_eq!(
        admission_error(client.associate_client(open_request()).await),
        AdmissionError::UnsupportedClientKey {
            client_index: ClientIndex(0)
        }
    );
    // An input-only slot takes it.
    let admission = client.associate_client(slot_request(1)).await.unwrap();
    assert_eq!(admission.client_index, ClientIndex(1));
}

#[tokio::test]
async fn a_reservation_must_name_exactly_the_admitted_range() {
    let execution_id = execution(0x90);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(2, 0), slot(0, 1)],
    ))
    .await;
    let mut inputs = harness.client(&client_cert()).await;
    let mut outputs = harness.client(&client_cert()).await;
    let mut stranger = harness.client(&client_cert()).await;
    inputs.associate_client(slot_request(0)).await.unwrap();
    outputs.associate_client(slot_request(1)).await.unwrap();

    harness.advance(Round::Preprocessing).await;
    assert_eq!(
        refusal_of(inputs.reserve_mask_indices(&[0, 1]).await),
        RpcRefusal::WrongRound
    );
    harness.advance(Round::InputMaskReservation).await;

    assert_eq!(
        admission_error(stranger.reserve_mask_indices(&[0, 1]).await),
        AdmissionError::NotAdmitted { execution_id }
    );
    let admitted = Some(range(0, 2));
    // Retargets `reserve_mask_indices_rejects_empty_batch`: an empty batch is not the range.
    for indices in [&[][..], &[0], &[1, 0], &[0, 1, 2], &[1, 2]] {
        assert_eq!(
            admission_error(inputs.reserve_mask_indices(indices).await),
            AdmissionError::ReservationOutsideAdmission { admitted },
            "{indices:?}"
        );
    }
    assert_eq!(
        admission_error(outputs.reserve_mask_indices(&[0]).await),
        AdmissionError::ReservationOutsideAdmission { admitted: None }
    );
    inputs.reserve_mask_indices(&[0, 1]).await.unwrap();
    // Retargets `client_may_only_call_reserve_mask_indices_once`.
    assert_eq!(
        refusal_of(inputs.reserve_mask_indices(&[0, 1]).await),
        RpcRefusal::ClientAlreadyReserved
    );
}

#[tokio::test]
async fn a_submission_must_cover_the_admitted_range_once_within_bounds_and_signed() {
    let execution_id = execution(0x91);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(2, 0), slot(0, 1), slot(1, 0)],
    ))
    .await;
    let submitter = client_cert();
    let output_only = client_cert();
    let unreserved = client_cert();
    let mut submitter_client = harness.client(&submitter).await;
    for (cert, index) in [(&submitter, 0), (&output_only, 1), (&unreserved, 2)] {
        let mut client = harness.client(cert).await;
        client.associate_client(slot_request(index)).await.unwrap();
    }
    submitter_client
        .associate_client(slot_request(0))
        .await
        .unwrap();
    let nonce = harness.nonce().await;

    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    submitter_client
        .reserve_mask_indices(&[0, 1])
        .await
        .unwrap();
    harness.advance(Round::InputCollection).await;

    // The client library refuses, without a call, to submit before associating or outside the
    // admitted range.
    let unassociated = harness.client(&client_cert()).await;
    assert!(matches!(
        unassociated.send_masked_input(Fr::from(1), 0).await,
        Err(CoordinatorError::NotAssociated)
    ));
    assert_eq!(
        submission_error(submitter_client.send_masked_input(Fr::from(1), 0).await),
        SubmissionError::SubmissionOutsideAdmission {
            admitted: Some(range(0, 2))
        }
    );

    let node_raw = harness.raw(&harness.nodes[1]).await;
    let mut events = CoordinatorRPCBaseClient::sub_masked_inputs(&node_raw, execution_id)
        .await
        .unwrap();

    let submit = |cert: &Certified, first_index: u64, inputs: Vec<Vec<u8>>, signature: Vec<u8>| {
        let cert = cert.clone();
        let harness = &harness;
        async move {
            let raw = harness.raw(&cert).await;
            CoordinatorRPCBaseClient::submit_masked_inputs(
                &raw,
                execution_id,
                first_index,
                inputs,
                signature,
            )
            .await
        }
    };
    let signed = |cert: &Certified, index: u32, first: u64, inputs: Vec<Vec<u8>>| {
        signed_submission(execution_id, nonce, ClientIndex(index), first, inputs, cert)
    };

    // Not reserved.
    let (inputs, signature) = signed(&unreserved, 2, 3, vec![vec![1; 32]]);
    assert_eq!(
        call_code(submit(&unreserved, 3, inputs, signature).await),
        6
    );
    // An input-less slot, a partial range and another start.
    let (inputs, signature) = signed(&output_only, 1, 2, vec![vec![1; 32]]);
    assert_eq!(
        call_code(submit(&output_only, 2, inputs, signature).await),
        37
    );
    let (inputs, signature) = signed(&submitter, 0, 0, vec![vec![1; 32]]);
    assert_eq!(
        call_code(submit(&submitter, 0, inputs, signature).await),
        37
    );
    let (inputs, signature) = signed(&submitter, 0, 1, vec![vec![1; 32], vec![2; 32]]);
    assert_eq!(
        call_code(submit(&submitter, 1, inputs, signature).await),
        37
    );
    // One byte past the per-input bound.
    let (inputs, signature) = signed(
        &submitter,
        0,
        0,
        vec![vec![1; 32], vec![2; MAX_MASKED_INPUT_BYTES as usize + 1]],
    );
    let refused = submit(&submitter, 0, inputs, signature).await;
    let Err(jsonrpsee::core::client::Error::Call(error)) = refused else {
        panic!("expected MaskedInputTooLarge, got {refused:?}");
    };
    assert_eq!(error.code(), 36);
    assert_eq!(
        serde_json::from_str::<SubmissionError>(error.data().unwrap().get()).unwrap(),
        SubmissionError::MaskedInputTooLarge {
            reserved_index: 1,
            len: MAX_MASKED_INPUT_BYTES + 1,
            max: MAX_MASKED_INPUT_BYTES
        }
    );
    // Signed by another key, or over another nonce.
    let accepted_inputs = vec![vec![1; 32], vec![2; MAX_MASKED_INPUT_BYTES as usize]];
    let (inputs, signature) = signed(&output_only, 0, 0, accepted_inputs.clone());
    assert_eq!(
        call_code(submit(&submitter, 0, inputs, signature).await),
        38
    );
    let (inputs, signature) = signed_submission(
        execution_id,
        RegistrationNonce::from_bytes([7; 32]),
        ClientIndex(0),
        0,
        accepted_inputs.clone(),
        &submitter,
    );
    assert_eq!(
        call_code(submit(&submitter, 0, inputs, signature).await),
        38
    );

    // Exactly the range, 64-byte inputs, signed: accepted, once.
    let (inputs, signature) = signed(&submitter, 0, 0, accepted_inputs.clone());
    submit(&submitter, 0, inputs.clone(), signature.clone())
        .await
        .unwrap();
    assert_eq!(
        call_code(submit(&submitter, 0, inputs.clone(), signature.clone()).await),
        5
    );

    // The node receives the submission byte for byte, signature included.
    let event = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Event::MaskedInputEvent { submission } = event else {
        panic!("expected a MaskedInputEvent, got {event:?}");
    };
    assert_eq!(submission.client, identity_of(&submitter));
    assert_eq!(submission.first_index, 0);
    assert_eq!(submission.masked_inputs, inputs);
    assert_eq!(submission.signature, signature);
}

#[tokio::test]
async fn every_event_subscription_refuses_an_unadmitted_certificate() {
    let execution_id = execution(0x92);
    let harness = Harness::start(open_registration(execution_id, vec![slot(1, 0)])).await;
    let stranger = harness.raw(&client_cert()).await;
    assert_eq!(
        call_code(
            CoordinatorRPCBaseClient::sub_round(&stranger, execution_id, Round::Preprocessing)
                .await
        ),
        31
    );
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::sub_reserved_indices(&stranger, execution_id).await),
        10
    );
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::sub_masked_inputs(&stranger, execution_id).await),
        10
    );

    // An admitted client may wait for rounds, but not read other clients' reservations.
    let admitted_cert = client_cert();
    harness
        .client(&admitted_cert)
        .await
        .associate_client(open_request())
        .await
        .unwrap();
    let admitted = harness.raw(&admitted_cert).await;
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::sub_reserved_indices(&admitted, execution_id).await),
        10
    );
    let _waiting =
        CoordinatorRPCBaseClient::sub_round(&admitted, execution_id, Round::Preprocessing)
            .await
            .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        harness
            .server
            .state()
            .lock()
            .await
            .parked_round_subscriptions(execution_id, Round::Preprocessing),
        1,
        "only the admitted client's subscription is parked"
    );
}

#[tokio::test]
async fn parked_subscriptions_are_bounded_per_caller_and_pruned_when_closed() {
    let execution_id = execution(0x93);
    let harness = Harness::start(empty_registration(execution_id)).await;
    let node = harness.raw(&harness.nodes[0]).await;
    let parked = || async {
        harness
            .server
            .state()
            .lock()
            .await
            .parked_round_subscriptions(execution_id, Round::Preprocessing)
    };
    let wait_parked = |expected: usize| async move {
        for _ in 0..100 {
            if parked().await == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "expected {expected} parked subscriptions, have {}",
            parked().await
        );
    };

    let mut subscriptions = Vec::new();
    for count in 1..=4 {
        subscriptions.push(
            CoordinatorRPCBaseClient::sub_round(&node, execution_id, Round::Preprocessing)
                .await
                .unwrap(),
        );
        wait_parked(count).await;
    }
    // A fifth from the same identity drops that identity's oldest, whose stream ends.
    subscriptions.push(
        CoordinatorRPCBaseClient::sub_round(&node, execution_id, Round::Preprocessing)
            .await
            .unwrap(),
    );
    wait_parked(4).await;
    let oldest = subscriptions.remove(0);
    let mut oldest = oldest;
    assert!(tokio::time::timeout(Duration::from_secs(2), oldest.next())
        .await
        .expect("the dropped subscription's stream ends")
        .is_none());

    // Closed sinks are dropped before parking: two unsubscribed, one parked by another node.
    drop(subscriptions.remove(0));
    drop(subscriptions.remove(0));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let other = harness.raw(&harness.nodes[1]).await;
    let _other = CoordinatorRPCBaseClient::sub_round(&other, execution_id, Round::Preprocessing)
        .await
        .unwrap();
    wait_parked(3).await;

    // The node RPC listener keeps one request per identity and prunes closed ones.
    let node_cert = server_cert();
    let port = free_port();
    let listener = start_node_server(execution_id, port, node_cert.clone()).await;
    let pin = ServerPin::Exact(spki_of(&node_cert));
    let first_cert = client_cert();
    let (cert_der, key_der) = cert_parts(&first_cert);
    let first = setup_client(ADDR, port, cert_der, key_der, &pin)
        .await
        .unwrap()
        .client;
    let pending = OffChainNodeRPCClient::receive_assigned_mask_shares(&first, execution_id, 0, 1)
        .await
        .unwrap();
    assert_eq!(parked_mask_requests(&listener, execution_id).await, 1);
    drop(pending);
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (cert_der, key_der) = cert_parts(&client_cert());
    let second = setup_client(ADDR, port, cert_der, key_der, &pin)
        .await
        .unwrap()
        .client;
    let _pending = OffChainNodeRPCClient::receive_assigned_mask_shares(&second, execution_id, 0, 1)
        .await
        .unwrap();
    assert_eq!(
        parked_mask_requests(&listener, execution_id).await,
        1,
        "the closed request is pruned before the new one is inserted"
    );
}

// ---------------------------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn sealed_outputs_are_bounded_signed_and_delivered_one_node_per_message() {
    let output_cert = client_cert();
    let execution_id = execution(0x94);
    let harness = Harness::start(pre_registered(
        execution_id,
        vec![slot(0, 1)],
        &[&output_cert],
    ))
    .await;
    let nonce = harness.nonce().await;
    let node_raw =
        futures_util::future::join_all(harness.nodes.iter().map(|node| harness.raw(node))).await;
    let output_raw = harness.raw(&output_cert).await;
    let slot0 = ClientIndex(0);
    let send = |node: usize, client_index: ClientIndex, sealed: SealedOutput| {
        CoordinatorRPCBaseClient::send_output_shares(
            &node_raw[node],
            execution_id,
            client_index,
            sealed,
        )
    };
    let item = |position: u32, signer: usize, ciphertext: Vec<u8>| {
        signed_output(
            execution_id,
            nonce,
            slot0,
            position,
            ciphertext,
            &harness.nodes[signer],
        )
    };

    // Unknown executions and non-nodes are refused; so is a slot without output rights.
    assert!(
        CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution(0x95))
            .await
            .is_err()
    );
    assert_eq!(
        call_code(
            CoordinatorRPCBaseClient::send_output_shares(
                &output_raw,
                execution_id,
                slot0,
                item(0, 0, vec![1])
            )
            .await
        ),
        10
    );
    assert_eq!(
        call_code(send(0, ClientIndex(1), item(0, 0, vec![1])).await),
        12
    );

    let mut waiter = CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id)
        .await
        .unwrap();

    // One byte past the bound; signatures over another position, or by another node.
    assert_eq!(
        call_code(
            send(
                0,
                slot0,
                item(0, 0, vec![0; MAX_SEALED_OUTPUT_BYTES as usize + 1])
            )
            .await
        ),
        39
    );
    assert_eq!(call_code(send(0, slot0, item(1, 0, vec![1])).await), 40);
    assert_eq!(call_code(send(0, slot0, item(0, 1, vec![1])).await), 40);

    // Accepted items arrive one per message, with the sender's position.
    send(0, slot0, item(0, 0, vec![0xa0])).await.unwrap();
    assert_eq!(call_code(send(0, slot0, item(0, 0, vec![0xa1])).await), 8);
    let first = tokio::time::timeout(Duration::from_secs(2), waiter.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.node_position, 0);
    assert_eq!(first.sealed.ciphertext, vec![0xa0]);
    send(2, slot0, item(2, 2, vec![0xa2])).await.unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), waiter.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(second.node_position, 2);

    // A second live waiter is refused; after unsubscribing, a new one replays both items.
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id).await),
        9
    );
    drop(waiter);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut replay = CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id)
        .await
        .unwrap();
    let mut positions = Vec::new();
    for _ in 0..2 {
        let item: SealedOutputShares = tokio::time::timeout(Duration::from_secs(2), replay.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        positions.push(item.node_position);
    }
    assert_eq!(positions, vec![0, 2]);
}

/// Seals `plaintext` to `client` exactly as a node does.
fn seal_to(execution_id: ExecutionId, client: &Certified, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use hpke::{
        aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256, Deserializable, Kem, OpModeS,
        Serializable,
    };
    use rand::SeedableRng;
    let public_key =
        <DhP256HkdfSha256 as Kem>::PublicKey::from_bytes(&identity_of(client)).unwrap();
    let mut info = b"StoffelOutputShareEncryption".to_vec();
    info.extend_from_slice(execution_id.as_bytes());
    let (encapsulated_key, ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256, _>(
            &OpModeS::Base,
            &public_key,
            &info,
            plaintext,
            b"",
            &mut rand::rngs::StdRng::from_os_rng(),
        )
        .unwrap();
    (encapsulated_key.to_bytes().to_vec(), ciphertext)
}

/// A coordinator that serves a fixed roster, summary and admission, and relays a fixed list of
/// output items — as a malicious relay could.
struct RelayConnection {
    state: Arc<Mutex<RelayState>>,
}

struct RelayState {
    roster: NodeRosterWire,
    summary: ExecutionSummary,
    admission: ClientAdmission,
    items: Vec<SealedOutputShares>,
}

impl RPCServerConnection for RelayConnection {
    type Internal = RelayState;

    fn new(internal: Arc<Mutex<Self::Internal>>, _id: Vec<u8>) -> Self {
        Self { state: internal }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut module = RpcModule::new(self);
        module
            .register_async_method("get_node_roster", |_, relay, _| async move {
                RpcResult::Ok(relay.state.lock().await.roster.clone())
            })
            .unwrap();
        module
            .register_async_method("get_execution_summary", |_, relay, _| async move {
                RpcResult::Ok(relay.state.lock().await.summary.clone())
            })
            .unwrap();
        module
            .register_async_method("associate_client", |_, relay, _| async move {
                RpcResult::Ok(relay.state.lock().await.admission.clone())
            })
            .unwrap();
        module
            .register_subscription(
                "sub_obtain_output_shares",
                "sub_obtain_output_shares",
                "unsub_obtain_output_shares",
                |_, pending, relay, _| async move {
                    let items = relay.state.lock().await.items.clone();
                    let sink = pending.accept().await?;
                    for item in items {
                        sink.send(jsonrpsee::core::to_json_raw_value(&item).unwrap())
                            .await?;
                    }
                    std::future::pending::<()>().await;
                    jsonrpsee::core::SubscriptionResult::Ok(())
                },
            )
            .unwrap();
        module
    }
}

#[tokio::test]
async fn a_client_reconstructs_despite_a_relabelled_or_corrupted_node_share() {
    stoffel_mpc_coordinator_shared::setup_test();
    let mut rng = test_rng();

    // AVSS through the node RPC legs, n = 3, t = 1: position 2 serves a share off its own
    // commitments, and the other two reconstruct.
    let nodes = node_certs(3);
    let roster = roster_of(1, &nodes);
    let execution_id = execution(0x96);
    let client = client_cert();
    let mask = Fr::from(777);
    let ids = [1, 2, 3];
    let shares = AvssShareType::compute_shares(mask, 3, 1, Some(&ids), &mut rng).unwrap();
    let mut addrs = Vec::new();
    let mut servers = Vec::new();
    for (position, node) in nodes.iter().enumerate() {
        let port = free_port();
        let server = start_node_server(execution_id, port, node.clone()).await;
        server
            .add_assigned_reserved_index_for_execution(
                execution_id,
                AssignedMaskReservation {
                    client: identity_of(&client),
                    reserved_index: 0,
                    input_ordinal: 0,
                },
            )
            .await
            .unwrap();
        let mut share = shares[position].clone();
        if position == 2 {
            share.feldmanshare.share[0] += Fr::from(1u64);
        }
        server
            .add_mask_share_for_execution(execution_id, 0, &share)
            .await
            .unwrap();
        addrs.push((ADDR.to_string(), port));
        servers.push(server);
    }
    let (cert_der, key_der) = cert_parts(&client);
    let avss_client = AvssNodeRPCClient::start_rpc_client_for_execution(
        &roster,
        addrs,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap();
    assert_eq!(
        avss_client.receive_assigned_masks(0, 1).await.unwrap(),
        vec![mask]
    );

    // HoneyBadger outputs through a relaying coordinator, n = 4, t = 1.
    let nodes = node_certs(4);
    let roster = roster_of(1, &nodes);
    let execution_id = execution(0x97);
    let coordinator = server_cert();
    let output = Fr::from(31_415);
    let output_shares = HoneyBadgerShareType::compute_shares(output, 4, 1, None, &mut rng).unwrap();
    let nonce = RegistrationNonce::from_bytes([5; 32]);
    let slot0 = ClientIndex(0);
    let sealed_item = |position: usize, signer: usize, plaintext: &[u8]| {
        let (encapsulated_key, ciphertext) = seal_to(execution_id, &client, plaintext);
        let bytes = sealed_output_signing_bytes(
            execution_id,
            nonce,
            slot0,
            position as u32,
            &encapsulated_key,
            &ciphertext,
        );
        SealedOutputShares {
            node_position: position as u32,
            sealed: SealedOutput {
                signature: sign_with_pkcs8(
                    KeyAlgorithm::EcdsaP256,
                    &nodes[signer].signing_key.serialize_der(),
                    &bytes,
                )
                .unwrap(),
                encapsulated_key,
                ciphertext,
            },
        }
    };
    let serialized = |position: usize| {
        let mut bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(
            &vec![output_shares[position].clone()],
            &mut bytes,
        )
        .unwrap();
        bytes
    };
    let mut undecryptable = sealed_item(2, 2, &serialized(2));
    undecryptable.sealed.ciphertext[0] ^= 0xff;
    let bytes = sealed_output_signing_bytes(
        execution_id,
        nonce,
        slot0,
        2,
        &undecryptable.sealed.encapsulated_key,
        &undecryptable.sealed.ciphertext,
    );
    undecryptable.sealed.signature = sign_with_pkcs8(
        KeyAlgorithm::EcdsaP256,
        &nodes[2].signing_key.serialize_der(),
        &bytes,
    )
    .unwrap();
    let mut out_of_range = sealed_item(1, 1, &serialized(1));
    out_of_range.node_position = 9;
    let items = vec![
        // Position 1's share under position 1, but signed by node 3.
        sealed_item(1, 3, &serialized(1)),
        out_of_range,
        // Signed by position 2, but its ciphertext does not decrypt.
        undecryptable,
        sealed_item(0, 0, &serialized(0)),
        sealed_item(3, 3, &serialized(3)),
        sealed_item(1, 1, &serialized(1)),
    ];
    let admission = ClientAdmission {
        execution_id,
        client_index: slot0,
        input_range: None,
        output_rights: receive(1),
    };
    let relay = RelayState {
        roster: roster.to_wire(),
        summary: ExecutionSummary {
            execution_id,
            registration_nonce: nonce,
            program_hash: [1; 32],
            client_slots: ClientSlotTable::new(vec![slot(0, 1)]),
            admission: AdmissionPolicyKind::Open,
            deadlines: deadlines_in(600, 1200),
            round: Round::OutputDistribution,
        },
        admission: admission.clone(),
        items,
    };
    let port = free_port();
    let (server_der, server_key) = cert_parts(&coordinator);
    let _relay = stoffel_mpc_coordinator_shared::rpc::start_coord::<RelayConnection>(
        ADDR,
        port,
        server_der,
        server_key,
        Arc::new(Mutex::new(relay)),
        RpcServerLimits::default(),
    )
    .await
    .unwrap();
    let mut output_client =
        start_coord_client(execution_id, port, &coordinator, client.clone()).await;
    assert_eq!(
        output_client
            .associate_client(open_request())
            .await
            .unwrap(),
        admission
    );
    let outputs = tokio::time::timeout(Duration::from_secs(5), output_client.obtain_outputs())
        .await
        .expect("positions 0, 3 and 1 reconstruct without waiting for more")
        .unwrap();
    assert_eq!(outputs, vec![output]);
}

#[tokio::test]
async fn a_honeybadger_client_refuses_an_undersized_roster_before_associating() {
    use stoffel_mpc_coordinator_shared::rpc::CapacityClass;
    // n = 3, t = 1: HoneyBadger needs 3t + 1 = 4 nodes, AVSS 2t + 1 = 3.
    let execution_id = execution(0x98);
    let harness = Harness::start_with(
        3,
        open_registration(execution_id, vec![slot(1, 0)]),
        |state| state,
    )
    .await;
    let hb_cert = client_cert();
    let mut hb = harness.client(&hb_cert).await;
    assert!(matches!(
        hb.associate_client(open_request()).await,
        Err(CoordinatorError::TopologyUnsupportedByBackend {
            n: 3,
            t: 1,
            required: 4
        })
    ));
    assert_eq!(
        harness
            .server
            .state()
            .lock()
            .await
            .capacity_class(&identity_of(&hb_cert)),
        CapacityClass::Unreserved,
        "the refused client holds no binding"
    );
    let (cert_der, key_der) = cert_parts(&client_cert());
    let mut avss = AvssClient::start_rpc_client_for_execution(
        ADDR,
        harness.port,
        &spki_of(&harness.coordinator),
        None,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap();
    assert_eq!(
        avss.associate_client(open_request())
            .await
            .unwrap()
            .client_index,
        ClientIndex(0)
    );

    // AVSS over BLS12-381 at t = 41: 1,024 outputs seal past MAX_SEALED_OUTPUT_BYTES.
    let execution_id = execution(0x99);
    let t = 41;
    let nodes = node_certs(2 * t + 1);
    let coordinator = server_cert();
    let state = coordinator_state(
        t as u64,
        &nodes,
        &coordinator,
        open_registration(execution_id, vec![slot(0, 1_024)]),
    );
    let port = free_port();
    let server = start_coordinator(state, port, &coordinator).await;
    let big_cert = client_cert();
    let (cert_der, key_der) = cert_parts(&big_cert);
    let mut big = AvssClient::start_rpc_client_for_execution(
        ADDR,
        port,
        &spki_of(&coordinator),
        None,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap();
    let share_len = <AvssShareType as ShareBound<Fr>>::serialized_share_len(t);
    assert!(matches!(
        big.associate_client(open_request()).await,
        Err(CoordinatorError::SealedOutputsExceedBound { client_index: ClientIndex(0), bytes, max })
            if bytes == 8 + 1_024 * share_len as u64 + 16 && max == MAX_SEALED_OUTPUT_BYTES
    ));
    assert_eq!(
        server
            .state()
            .lock()
            .await
            .capacity_class(&identity_of(&big_cert)),
        CapacityClass::Unreserved
    );
}

// ---------------------------------------------------------------------------------------------
// Rounds
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn input_collection_is_held_until_every_slot_is_bound() {
    let execution_id = execution(0x9a);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(1, 0), slot(0, 1)],
    ))
    .await;
    let mut inputs = harness.client(&client_cert()).await;
    inputs.associate_client(open_request()).await.unwrap();
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    inputs.reserve_mask_indices(&[0]).await.unwrap();

    // Every node proposes InputCollection while the output-only slot is unbound.
    propose_round(&harness.coords, Round::InputCollection).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(harness.round().await, Some(Round::InputMaskReservation));

    // The proposals are recorded; the round applies inside the binding association.
    let mut outputs = harness.client(&client_cert()).await;
    outputs.associate_client(open_request()).await.unwrap();
    assert_eq!(harness.round().await, Some(Round::InputCollection));
}

#[tokio::test]
async fn round_skips_require_an_empty_slot_table() {
    // An execution with inputs cannot skip the input rounds.
    let client = client_cert();
    let with_inputs = Harness::start(pre_registered(
        execution(0x9b),
        vec![slot(1, 0)],
        &[&client],
    ))
    .await;
    with_inputs.advance(Round::Preprocessing).await;
    propose_round(&with_inputs.coords, Round::MPCExecution).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(with_inputs.round().await, Some(Round::Preprocessing));

    // An execution with an output slot takes the input skip but not the output skip.
    let output_client = client_cert();
    let with_outputs = Harness::start(pre_registered(
        execution(0x9c),
        vec![slot(0, 1)],
        &[&output_client],
    ))
    .await;
    with_outputs.advance(Round::Preprocessing).await;
    with_outputs.advance(Round::MPCExecution).await;
    propose_round(&with_outputs.coords, Round::ProgramFinished).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(with_outputs.round().await, Some(Round::MPCExecution));
    with_outputs.advance(Round::OutputDistribution).await;
    // The held ProgramFinished proposals apply once OutputDistribution has.
    with_outputs.coords[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();

    // Retargets `zero_input_execution_skips_input_rounds`: no slots, both skips apply.
    let empty = Harness::start(empty_registration(execution(0x9d))).await;
    for coord in &empty.coords {
        coord.start_preprocessing().await.unwrap();
    }
    for coord in &empty.coords {
        coord.start_mpc().await.unwrap();
    }
    empty.coords[0]
        .wait_for_round(Round::MPCExecution)
        .await
        .unwrap();
    for coord in &empty.coords {
        coord.finalize().await.unwrap();
    }
    empty.coords[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Deadlines, aborts and ended executions
// ---------------------------------------------------------------------------------------------

/// Waits until `harness`'s execution is in `round`, or panics after `within`.
async fn wait_for_state_round(harness: &Harness, round: Option<Round>, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if harness.round().await == round {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected round {round:?}, have {:?}", harness.round().await);
}

fn aborted_reason(result: Result<impl std::fmt::Debug, CoordinatorError>) -> AbortReason {
    match result {
        Err(CoordinatorError::ExecutionAborted { reason, .. }) => reason,
        other => panic!("expected ExecutionAborted, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unbound_slot_at_the_association_deadline_aborts_the_execution() {
    let execution_id = execution(0x9e);
    let registration = registration(
        execution_id,
        vec![slot(1, 0)],
        AdmissionPolicy::Open,
        deadlines_in(2, 600),
    );
    let deadline = registration.deadlines.unwrap().association;
    let harness = Harness::start(registration.clone()).await;
    let node_raw = harness.raw(&harness.nodes[0]).await;
    let mut waiter =
        CoordinatorRPCBaseClient::sub_round(&node_raw, execution_id, Round::InputCollection)
            .await
            .unwrap();

    wait_for_state_round(&harness, Some(Round::Aborted), Duration::from_secs(5)).await;
    let expected = AbortReason::AssociationDeadline {
        deadline,
        unbound_slots: 1,
    };
    let event = tokio::time::timeout(Duration::from_secs(2), waiter.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        event,
        Event::ExecutionAborted {
            reason: expected.clone()
        }
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), waiter.next())
            .await
            .unwrap()
            .is_none(),
        "the stream ends after the abort"
    );

    // Later calls answer 35 with the reason; the summary still answers, round Aborted.
    assert_eq!(
        aborted_reason(harness.coords[0].trigger_round(Round::Preprocessing).await),
        expected
    );
    let mut late = harness.client(&client_cert()).await;
    assert_eq!(
        aborted_reason(late.associate_client(open_request()).await),
        expected
    );
    assert_eq!(
        harness.coords[1]
            .get_execution_summary()
            .await
            .unwrap()
            .round,
        Round::Aborted
    );

    // Evictable without any acknowledgement; its id is then retired.
    let state = harness.server.state();
    let mut state = state.lock().await;
    let numbered = |number: usize| {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(number as u64).to_be_bytes());
        empty_registration(ExecutionId::from_bytes(bytes))
    };
    for number in 1..=DEFAULT_MAX_CONCURRENT_EXECUTIONS {
        state.register_execution(numbered(number)).unwrap();
    }
    assert_eq!(state.round(execution_id), None);
    assert_eq!(
        state.ended_outcome(execution_id),
        Some(ExecutionOutcome::Aborted(expected))
    );
    assert!(matches!(
        state.register_execution(registration),
        Err(CoordinatorError::Registration(
            RegistrationError::ExecutionIdRetired { .. }
        ))
    ));
}

#[tokio::test]
async fn a_one_off_coordinator_aborts_at_the_association_deadline_and_drains() {
    stoffel_mpc_coordinator_shared::setup_test();
    let nodes = node_certs(4);
    let coordinator = server_cert();
    let execution_id = execution(0x9f);
    let state = coordinator_state(
        1,
        &nodes,
        &coordinator,
        registration(
            execution_id,
            vec![slot(1, 0)],
            AdmissionPolicy::Open,
            deadlines_in(2, 600),
        ),
    );
    let port = free_port();
    let (cert_der, key_der) = cert_parts(&coordinator);
    let server = tokio::spawn(HoneyBadgerOffChainCoordinatorServer::start_coord_one_off(
        state,
        ADDR,
        port,
        cert_der,
        key_der,
        OneOffShutdownConfig {
            execution_id,
            grace: Duration::from_secs(10),
        },
        RpcServerLimits::default(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let coords = connect_all(execution_id, port, &coordinator, &nodes).await;

    let reason = aborted_reason(coords[0].wait_for_round(Round::InputCollection).await);
    assert!(matches!(
        reason,
        AbortReason::AssociationDeadline {
            unbound_slots: 1,
            ..
        }
    ));
    assert_eq!(
        aborted_reason(coords[1].trigger_round(Round::Preprocessing).await),
        reason
    );
    assert!(!server.is_finished());

    // Every node acknowledges the abort; the drain completes well within its grace.
    for coord in &coords {
        coord.retire_execution().await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("the one-off coordinator drains after the nodes acknowledge the abort")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_missing_input_at_the_input_deadline_aborts_the_execution() {
    let client = client_cert();
    let execution_id = execution(0xa0);
    let registration = registration(
        execution_id,
        vec![slot(1, 0)],
        AdmissionPolicy::PreRegistered {
            clients: vec![identity_of(&client)],
        },
        deadlines_in(1, 3),
    );
    let deadline = registration.deadlines.unwrap().input;
    let harness = Harness::start(registration).await;
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    harness.advance(Round::InputCollection).await;

    let reason = aborted_reason(
        tokio::time::timeout(
            Duration::from_secs(6),
            harness.coords[0].wait_for_masked_input_submissions(1),
        )
        .await
        .expect("the input deadline ends the wait"),
    );
    assert_eq!(
        reason,
        AbortReason::InputDeadline {
            deadline,
            missing_inputs: 1
        }
    );
}

#[tokio::test]
async fn an_input_deadline_with_every_input_present_does_not_abort() {
    let client_cert = client_cert();
    let execution_id = execution(0xa1);
    let registration = registration(
        execution_id,
        vec![slot(1, 0)],
        AdmissionPolicy::PreRegistered {
            clients: vec![identity_of(&client_cert)],
        },
        deadlines_in(2, 3),
    );
    let input_deadline = registration.deadlines.unwrap().input;
    let harness = Harness::start(registration).await;
    let mut client = harness.client(&client_cert).await;
    client.associate_client(open_request()).await.unwrap();
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    client.reserve_mask_indices(&[0]).await.unwrap();
    harness.advance(Round::InputCollection).await;
    client.send_masked_input(Fr::from(5), 0).await.unwrap();
    assert!(
        UnixSeconds::now() < input_deadline,
        "submitted before the deadline"
    );

    // The deadline passes before any node proposes MPCExecution.
    while std::time::SystemTime::now() < input_deadline.as_system_time() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(harness.round().await, Some(Round::InputCollection));
    harness.advance(Round::MPCExecution).await;
}

#[tokio::test]
async fn an_abort_reaches_sinks_a_broadcast_holds_and_subscriptions_between_accept_and_parking() {
    // An input deadline fires while a submission's broadcast holds the delivery guard.
    let submitter = client_cert();
    let absent = client_cert();
    let execution_id = execution(0xa2);
    let broadcast = PausePoint::new();
    let registration = registration(
        execution_id,
        vec![slot(1, 0), slot(1, 0)],
        AdmissionPolicy::PreRegistered {
            clients: vec![identity_of(&submitter), identity_of(&absent)],
        },
        deadlines_in(2, 3),
    );
    let input_deadline = registration.deadlines.unwrap().input;
    let hooks = DeliveryHooks {
        during_masked_input_broadcast: Some(broadcast.clone()),
        ..DeliveryHooks::default()
    };
    let harness = Harness::start_with(4, registration, move |mut state| {
        state.set_delivery_hooks(hooks);
        state
    })
    .await;
    let mut client = harness.client(&submitter).await;
    client.associate_client(open_request()).await.unwrap();
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    client.reserve_mask_indices(&[0]).await.unwrap();
    harness.advance(Round::InputCollection).await;

    let mut subscribers = Vec::new();
    for node in &harness.nodes[..2] {
        let raw = harness.raw(node).await;
        let subscription = CoordinatorRPCBaseClient::sub_masked_inputs(&raw, execution_id)
            .await
            .unwrap();
        subscribers.push((raw, subscription));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let submission = tokio::spawn(async move { client.send_masked_input(Fr::from(8), 0).await });
    broadcast.reached().await;
    while std::time::SystemTime::now() < input_deadline.as_system_time() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        harness.round().await,
        Some(Round::InputCollection),
        "the sweeper waits for the broadcast's delivery guard"
    );
    broadcast.resume();
    submission.await.unwrap().unwrap();

    for (_, subscription) in &mut subscribers {
        let first = tokio::time::timeout(Duration::from_secs(3), subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(first, Event::MaskedInputEvent { .. }));
        let second = tokio::time::timeout(Duration::from_secs(3), subscription.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            second,
            Event::ExecutionAborted {
                reason: AbortReason::InputDeadline {
                    missing_inputs: 1,
                    ..
                }
            }
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(2), subscription.next())
                .await
                .unwrap()
                .is_none(),
            "the sink was dropped, not re-parked"
        );
    }

    // A subscription paused between `accept` and its re-lock receives the abort.
    let accepted = PausePoint::new();
    let hooks = DeliveryHooks {
        after_subscription_accept: Some(accepted.clone()),
        ..DeliveryHooks::default()
    };
    let execution_id = execution(0xa3);
    let harness = Harness::start_with(
        4,
        registration_with_deadline(execution_id, 2),
        move |mut state| {
            state.set_delivery_hooks(hooks);
            state
        },
    )
    .await;
    let raw = harness.raw(&harness.nodes[0]).await;
    let mut subscription =
        CoordinatorRPCBaseClient::sub_round(&raw, execution_id, Round::InputCollection)
            .await
            .unwrap();
    accepted.reached().await;
    wait_for_state_round(&harness, Some(Round::Aborted), Duration::from_secs(5)).await;
    accepted.resume();
    let event = tokio::time::timeout(Duration::from_secs(3), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        event,
        Event::ExecutionAborted {
            reason: AbortReason::AssociationDeadline { .. }
        }
    ));
    assert_eq!(
        harness
            .server
            .state()
            .lock()
            .await
            .parked_round_subscriptions(execution_id, Round::InputCollection),
        0
    );
}

/// An `Open` registration of one input slot whose association deadline is `seconds` away.
fn registration_with_deadline(execution_id: ExecutionId, seconds: u64) -> ExecutionRegistration {
    registration(
        execution_id,
        vec![slot(1, 0)],
        AdmissionPolicy::Open,
        deadlines_in(seconds, 600),
    )
}

#[tokio::test]
async fn an_ended_execution_stays_refused_after_unanimous_retirement() {
    let execution_id = execution(0xa4);
    let registration = registration_with_deadline(execution_id, 2);
    let harness = Harness::start(registration.clone()).await;
    wait_for_state_round(&harness, Some(Round::Aborted), Duration::from_secs(5)).await;
    for coord in &harness.coords {
        coord.retire_execution().await.unwrap();
    }
    assert_eq!(harness.round().await, None);
    let reason = aborted_reason(harness.coords[0].get_execution_summary().await);
    assert!(matches!(reason, AbortReason::AssociationDeadline { .. }));
    harness.coords[0]
        .retire_execution()
        .await
        .expect("acknowledging an ended execution stays a success");
    assert!(matches!(
        harness
            .server
            .state()
            .lock()
            .await
            .register_execution(registration),
        Err(CoordinatorError::Registration(
            RegistrationError::ExecutionIdRetired { .. }
        ))
    ));

    // A normal finish.
    let finished_id = execution(0xa5);
    harness
        .server
        .state()
        .lock()
        .await
        .register_execution(empty_registration(finished_id))
        .unwrap();
    let finished = connect_all(
        finished_id,
        harness.port,
        &harness.coordinator,
        &harness.nodes,
    )
    .await;
    propose_round(&finished, Round::Preprocessing).await;
    propose_round(&finished, Round::MPCExecution).await;
    propose_round(&finished, Round::ProgramFinished).await;
    finished[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();
    for coord in &finished {
        coord.retire_execution().await.unwrap();
    }
    assert_eq!(
        refusal_of(finished[0].get_execution_summary().await),
        RpcRefusal::ExecutionNotFound
    );
    assert!(matches!(
        harness
            .server
            .state()
            .lock()
            .await
            .register_execution(empty_registration(finished_id)),
        Err(CoordinatorError::Registration(
            RegistrationError::ExecutionIdRetired { .. }
        ))
    ));

    // The memory is bounded: once DEFAULT_MAX_ENDED_EXECUTIONS later executions have ended,
    // the oldest id may be registered again.
    let nodes = node_certs(4);
    let mut state =
        CoordinatorRPCServerSharedBase::new(roster_of(1, &nodes), spki_of(&server_cert()));
    let numbered = |number: usize| {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(number as u64 + 1).to_be_bytes());
        empty_registration(ExecutionId::from_bytes(bytes))
    };
    let end = |state: &mut CoordinatorRPCServerSharedBase, number: usize| {
        let registration = numbered(number);
        state.register_execution(registration.clone()).unwrap();
        for node in &nodes {
            state
                .retire_execution(registration.execution_id, &identity_of(node))
                .unwrap();
        }
    };
    for number in 0..DEFAULT_MAX_ENDED_EXECUTIONS {
        end(&mut state, number);
    }
    assert!(state.register_execution(numbered(0)).is_err());
    end(&mut state, DEFAULT_MAX_ENDED_EXECUTIONS);
    assert_eq!(state.ended_outcome(numbered(0).execution_id), None);
    assert_eq!(
        state.ended_outcome(numbered(1).execution_id),
        Some(ExecutionOutcome::Finished)
    );
    state
        .register_execution(numbered(0))
        .expect("the forgotten id registers again");
}

#[tokio::test]
async fn the_retirement_watch_wakes_on_every_path_that_changes_it() {
    // The quorum's last acknowledgement in ProgramFinished.
    let execution_id = execution(0xa6);
    let harness = Harness::start(empty_registration(execution_id)).await;
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::MPCExecution).await;
    harness.advance(Round::ProgramFinished).await;
    let watch = tokio::spawn(CoordinatorRPCServerSharedBase::watch_for_retirement_quorum(
        harness.server.state(),
        execution_id,
    ));
    for coord in &harness.coords[..2] {
        coord.retire_execution().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!watch.is_finished(), "two of the quorum of three");
    harness.coords[2].retire_execution().await.unwrap();
    tokio::time::timeout(Duration::from_millis(500), watch)
        .await
        .expect("the quorum's last acknowledgement wakes the watch")
        .unwrap();

    // An abort once the quorum has already acknowledged.
    let execution_id = execution(0xa7);
    let harness = Harness::start(registration_with_deadline(execution_id, 2)).await;
    for coord in &harness.coords[..3] {
        coord.retire_execution().await.unwrap();
    }
    let watch = tokio::spawn(CoordinatorRPCServerSharedBase::watch_for_retirement_quorum(
        harness.server.state(),
        execution_id,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !watch.is_finished(),
        "acknowledgements outside a terminal round"
    );
    tokio::time::timeout(Duration::from_secs(5), watch)
        .await
        .expect("the abort wakes the watch")
        .unwrap();

    // A removal by unanimity before the watcher first looked.
    let execution_id = execution(0xa8);
    let harness = Harness::start(empty_registration(execution_id)).await;
    for coord in &harness.coords {
        coord.retire_execution().await.unwrap();
    }
    tokio::time::timeout(
        Duration::from_millis(500),
        CoordinatorRPCServerSharedBase::watch_for_retirement_quorum(
            harness.server.state(),
            execution_id,
        ),
    )
    .await
    .expect("an absent execution resolves at once");
}

#[tokio::test]
async fn a_removal_during_output_delivery_does_not_panic() {
    let output_cert = client_cert();
    let execution_id = execution(0xa9);
    let relock = PausePoint::new();
    let hooks = DeliveryHooks {
        before_output_relock: Some(relock.clone()),
        ..DeliveryHooks::default()
    };
    let harness = Harness::start_with(
        4,
        pre_registered(execution_id, vec![slot(0, 1)], &[&output_cert]),
        move |mut state| {
            state.set_delivery_hooks(hooks);
            state.with_output_retention(Duration::ZERO)
        },
    )
    .await;
    let nonce = harness.nonce().await;
    let output_raw = harness.raw(&output_cert).await;
    let _waiter = CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let node_raw = Arc::new(harness.raw(&harness.nodes[0]).await);
    let sealed = signed_output(
        execution_id,
        nonce,
        ClientIndex(0),
        0,
        vec![1, 2, 3],
        &harness.nodes[0],
    );
    let sending = tokio::spawn({
        let node_raw = node_raw.clone();
        async move {
            CoordinatorRPCBaseClient::send_output_shares(
                &*node_raw,
                execution_id,
                ClientIndex(0),
                sealed,
            )
            .await
        }
    });
    relock.reached().await;

    // Every node retires; with no retention the sweeper removes the execution at once.
    for coord in &harness.coords {
        coord.retire_execution().await.unwrap();
    }
    wait_for_state_round(&harness, None, Duration::from_secs(2)).await;
    relock.resume();
    sending
        .await
        .expect("the connection task did not panic")
        .expect("the call is answered");
    CoordinatorRPCBaseClient::get_node_roster(&*node_raw)
        .await
        .expect("the connection still serves calls");
}

#[tokio::test]
async fn a_refused_subscription_decodes_to_a_typed_error() {
    let output_cert = client_cert();
    let execution_id = execution(0xaa);
    let harness = Harness::start(registration(
        execution_id,
        vec![slot(0, 1), slot(1, 0)],
        AdmissionPolicy::Open,
        deadlines_in(2, 600),
    ))
    .await;
    let mut output_client = harness.client(&output_cert).await;
    output_client
        .associate_client(slot_request(0))
        .await
        .unwrap();
    assert_eq!(
        refusal_of(output_client.wait_for_indices(1).await),
        RpcRefusal::NotParty
    );

    wait_for_state_round(&harness, Some(Round::Aborted), Duration::from_secs(5)).await;
    for result in [
        harness.coords[0].wait_for_indices(1).await.map(|_| ()),
        harness.coords[1]
            .wait_for_round(Round::InputCollection)
            .await,
        output_client.obtain_outputs().await.map(|_| ()),
    ] {
        assert!(matches!(
            aborted_reason(result),
            AbortReason::AssociationDeadline {
                unbound_slots: 1,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn client_admissions_are_node_only_and_frozen() {
    let client_cert = client_cert();
    let execution_id = execution(0xab);
    let harness = Harness::start(open_registration(execution_id, vec![slot(2, 0)])).await;
    let mut client = harness.client(&client_cert).await;
    client.associate_client(open_request()).await.unwrap();

    assert_eq!(
        refusal_of(client.get_client_admissions().await),
        RpcRefusal::NotParty
    );
    let mut node = harness.client(&harness.nodes[0]).await;
    assert_eq!(
        admission_error(node.get_client_admissions().await),
        AdmissionError::AdmissionsNotFrozen {
            execution_id,
            current: Round::Idle
        }
    );

    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;
    harness.advance(Round::InputCollection).await;
    let set = node.get_client_admissions().await.unwrap();
    assert_eq!(set.execution_id, execution_id);
    assert_eq!(set.records.len(), 1);
    assert_eq!(set.records[0].client, identity_of(&client_cert));
    assert_eq!(set.records[0].input_range, Some(range(0, 2)));
    assert_eq!(
        admitted_reservations(&set),
        vec![
            AssignedMaskReservation {
                client: identity_of(&client_cert),
                reserved_index: 0,
                input_ordinal: 0
            },
            AssignedMaskReservation {
                client: identity_of(&client_cert),
                reserved_index: 1,
                input_ordinal: 1
            },
        ]
    );
}

#[tokio::test]
async fn one_off_coordinator_drains_after_the_retirement_quorum_of_a_terminal_round() {
    stoffel_mpc_coordinator_shared::setup_test();

    // Acknowledgements before ProgramFinished do not start the drain.
    let certs = node_certs(5);
    let coordinator = server_cert();
    let port = free_port();
    let execution_id = execution(0xac);
    let state = coordinator_state(1, &certs, &coordinator, empty_registration(execution_id));
    let (cert_der, key_der) = cert_parts(&coordinator);
    let server_task = tokio::spawn(HoneyBadgerOffChainCoordinatorServer::start_coord_one_off(
        state,
        ADDR,
        port,
        cert_der,
        key_der,
        OneOffShutdownConfig {
            execution_id,
            grace: Duration::from_secs(2),
        },
        RpcServerLimits::default(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let coords = connect_all(execution_id, port, &coordinator, &certs).await;
    for coord in coords.iter().take(4) {
        coord.retire_execution().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server_task.is_finished(),
        "a quorum of early acknowledgements must not start the drain mid-execution"
    );

    // A quorum of low-latency parties drives the execution to completion while the fifth party
    // has not yet observed MPCExecution. This is the ordering from the multi-region failure log.
    for round in [
        Round::Preprocessing,
        Round::MPCExecution,
        Round::OutputDistribution,
        Round::ProgramFinished,
    ] {
        for coord in coords.iter().take(3) {
            coord.trigger_round(round).await.unwrap();
        }
    }
    coords[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();
    assert!(
        !server_task.is_finished(),
        "n - t acknowledgements must not discard one-off round history"
    );

    tokio::time::timeout(
        Duration::from_secs(1),
        coords[4].wait_for_round(Round::MPCExecution),
    )
    .await
    .expect("slow party must receive the already-completed MPCExecution round")
    .expect("one-off coordinator must remain connected for terminal replay");

    assert!(
        !server_task.is_finished(),
        "the coordinator must not close before every live party acknowledges"
    );
    coords[4].retire_execution().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("coordinator must close promptly after unanimous acknowledgement")
        .expect("one-off coordinator task must not panic")
        .expect("one-off coordinator must shut down cleanly");

    // The grace bounds a missing party.
    let nodes = node_certs(3);
    let coordinator = server_cert();
    let port = free_port();
    let execution_id = execution(0xad);
    let state = coordinator_state(1, &nodes, &coordinator, empty_registration(execution_id));
    let (cert_der, key_der) = cert_parts(&coordinator);
    let server_task = tokio::spawn(HoneyBadgerOffChainCoordinatorServer::start_coord_one_off(
        state,
        ADDR,
        port,
        cert_der,
        key_der,
        OneOffShutdownConfig {
            execution_id,
            grace: Duration::from_millis(100),
        },
        RpcServerLimits::default(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let coords = connect_all(execution_id, port, &coordinator, &nodes[..2]).await;
    for round in [
        Round::Preprocessing,
        Round::MPCExecution,
        Round::OutputDistribution,
        Round::ProgramFinished,
    ] {
        propose_round(&coords, round).await;
    }
    coords[0]
        .wait_for_round(Round::ProgramFinished)
        .await
        .unwrap();
    for coord in &coords {
        coord.retire_execution().await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), server_task)
        .await
        .expect("missing retirement acknowledgement must only delay shutdown by the grace period")
        .expect("one-off coordinator task must not panic")
        .expect("one-off coordinator must shut down cleanly after its grace period");
}

#[tokio::test]
async fn unanimous_retirement_keeps_outputs_for_the_retention_window() {
    let output_cert = client_cert();
    let execution_id = execution(0xae);
    let harness = Harness::start_with(
        4,
        pre_registered(execution_id, vec![slot(0, 1)], &[&output_cert]),
        |state| state.with_output_retention(Duration::from_secs(1)),
    )
    .await;
    let nonce = harness.nonce().await;
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::MPCExecution).await;
    harness.advance(Round::OutputDistribution).await;
    for (position, node) in harness.nodes.iter().enumerate() {
        let raw = harness.raw(node).await;
        CoordinatorRPCBaseClient::send_output_shares(
            &raw,
            execution_id,
            ClientIndex(0),
            signed_output(
                execution_id,
                nonce,
                ClientIndex(0),
                position as u32,
                vec![position as u8],
                node,
            ),
        )
        .await
        .unwrap();
    }
    harness.advance(Round::ProgramFinished).await;
    for coord in &harness.coords {
        coord.retire_execution().await.unwrap();
    }

    // Subscribing after every node retired still receives every node's item.
    let output_raw = harness.raw(&output_cert).await;
    let mut late = CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id)
        .await
        .unwrap();
    let mut positions = Vec::new();
    for _ in 0..4 {
        let item: SealedOutputShares = tokio::time::timeout(Duration::from_secs(2), late.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        positions.push(item.node_position);
    }
    assert_eq!(positions, vec![0, 1, 2, 3]);
    drop(late);

    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        call_code(CoordinatorRPCBaseClient::obtain_output_shares(&output_raw, execution_id).await),
        16
    );
}

// ---------------------------------------------------------------------------------------------
// Delivery discipline
// ---------------------------------------------------------------------------------------------

/// Reserves `admission`'s whole input range.
async fn reserve(client: &mut HbClient, admission: &ClientAdmission) {
    let range = admission.input_range.unwrap();
    let indices = (range.start..range.end()).collect::<Vec<_>>();
    client.reserve_mask_indices(&indices).await.unwrap();
}

/// A pinned WebSocket connection that sends one JSON-RPC request and then never reads, so the
/// coordinator's queue for it fills and stays full. Dropping the value closes the connection.
async fn stalled_subscriber(
    port: u16,
    coordinator: &Certified,
    cert: &Certified,
    method: &str,
    params: serde_json::Value,
) -> impl Send {
    use jsonrpsee::core::client::TransportSenderT;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use stoffel_mpc_coordinator_shared::self_signed_certs::PinnedServerVerifier;

    let (cert_der, key_der) = cert_parts(cert);
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier::new(ServerPin::Exact(
            spki_of(coordinator),
        ))))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .unwrap();
    let tcp = tokio::net::TcpStream::connect((ADDR, port)).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(ADDR).unwrap().to_owned(), tcp)
        .await
        .unwrap();
    let (mut sender, receiver) =
        jsonrpsee::client_transport::ws::WsTransportClientBuilder::default()
            .build_with_stream(
                url::Url::parse(&format!("wss://{ADDR}:{port}/")).unwrap(),
                tls,
            )
            .await
            .unwrap();
    sender
        .send(
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                .to_string(),
        )
        .await
        .unwrap();
    (sender, receiver)
}

#[tokio::test]
async fn no_subscriber_holds_the_state_mutex_or_another_subscriber() {
    // 64 slots of 16,384 inputs: every reservation event is about 131 KB, so a subscriber that
    // never reads falls `message_buffer_capacity` (16) messages behind well before the end.
    const SLOTS: usize = 64;
    const INPUTS_PER_SLOT: u64 = 16_384;
    let execution_id = execution(0xb0);
    let harness = Harness::start(open_registration(
        execution_id,
        vec![slot(INPUTS_PER_SLOT, 0); SLOTS],
    ))
    .await;
    let other_id = execution(0xb1);
    harness
        .server
        .state()
        .lock()
        .await
        .register_execution(open_registration(other_id, vec![slot(1, 0)]))
        .unwrap();

    let mut clients = Vec::new();
    for _ in 0..SLOTS {
        let mut client = harness.client(&client_cert()).await;
        let admission = client.associate_client(open_request()).await.unwrap();
        clients.push((client, admission));
    }
    harness.advance(Round::Preprocessing).await;
    harness.advance(Round::InputMaskReservation).await;

    // Live: a stalled node subscriber and a reading one are parked before any reservation.
    let _stalled = stalled_subscriber(
        harness.port,
        &harness.coordinator,
        &harness.nodes[0],
        "sub_reserved_indices",
        serde_json::json!([execution_id]),
    )
    .await;
    let reader = harness.raw(&harness.nodes[1]).await;
    let mut live = CoordinatorRPCBaseClient::sub_reserved_indices(&reader, execution_id)
        .await
        .unwrap();
    for _ in 0..100 {
        if harness
            .server
            .state()
            .lock()
            .await
            .parked_reservation_subscriptions(execution_id)
            == 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The first half is reserved; a third subscriber joins while the rest are reserved, so its
    // replay overlaps live broadcasts.
    for (client, admission) in clients.iter_mut().take(SLOTS / 2) {
        reserve(client, admission).await;
    }
    let overlapping_reader = harness.raw(&harness.nodes[2]).await;
    let overlapping_subscribe =
        CoordinatorRPCBaseClient::sub_reserved_indices(&overlapping_reader, execution_id);
    let reserve_rest = async {
        for (client, admission) in clients.iter_mut().skip(SLOTS / 2) {
            reserve(client, admission).await;
        }
    };
    let (overlapping, ()) = tokio::join!(overlapping_subscribe, reserve_rest);
    let mut overlapping = overlapping.unwrap();

    let expected = clients
        .iter()
        .map(|(_, admission)| admission.input_range.unwrap().start)
        .collect::<Vec<_>>();
    for stream in [&mut live, &mut overlapping] {
        let mut starts = Vec::new();
        for _ in 0..SLOTS {
            let event = tokio::time::timeout(Duration::from_secs(10), stream.next())
                .await
                .expect("a reading subscriber receives every event")
                .unwrap()
                .unwrap();
            let Event::ReservedInputEvent {
                reserved_indices, ..
            } = event
            else {
                panic!("expected a ReservedInputEvent, got {event:?}");
            };
            assert_eq!(reserved_indices.len() as u64, INPUTS_PER_SLOT);
            starts.push(reserved_indices[0]);
        }
        let mut sorted = starts.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, expected, "every event exactly once");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), stream.next())
                .await
                .is_err(),
            "and nothing twice"
        );
    }
    assert_eq!(
        harness
            .server
            .state()
            .lock()
            .await
            .parked_reservation_subscriptions(execution_id),
        2,
        "the stalled subscriber failed its try_send and was dropped; the readers stay parked"
    );

    // Replay: a new stalled subscriber of the full history holds only itself.
    let _stalled_replay = stalled_subscriber(
        harness.port,
        &harness.coordinator,
        &harness.nodes[3],
        "sub_reserved_indices",
        serde_json::json!([execution_id]),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let roster_reader = harness.raw(&client_cert()).await;
    let started = std::time::Instant::now();
    CoordinatorRPCBaseClient::associate_client(&roster_reader, other_id, open_request())
        .await
        .unwrap();
    let associated = started.elapsed();
    CoordinatorRPCBaseClient::get_node_roster(&roster_reader)
        .await
        .unwrap();
    let read = started.elapsed() - associated;
    assert!(
        associated < Duration::from_millis(100) && read < Duration::from_millis(100),
        "a replay stalled on its subscriber delayed associate_client by {associated:?} and get_node_roster by {read:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------------------------

/// One node's whole coordinated run: provision masks, reserve, agree on nothing but the frozen
/// admission set, release masks against it, unmask verified submissions, and send each output
/// client its input plus `offset`, sealed and signed.
async fn run_node(
    mut coord: HbClient,
    node_rpc: HoneyBadgerNodeRPCServer,
    mask_shares: Vec<HoneyBadgerShareType>,
    offset: Fr,
) -> Result<(), CoordinatorError> {
    let execution_id = coord.execution_id();
    let summary = coord.get_execution_summary().await?;
    let n_inputs = summary.client_slots.n_inputs();
    let provisioned = mask_shares
        .iter()
        .enumerate()
        .map(|(index, share)| (index as u64, share))
        .collect::<Vec<_>>();
    node_rpc
        .add_mask_shares_for_execution(execution_id, &provisioned)
        .await
        .unwrap();

    coord.start_preprocessing().await?;
    coord.wait_for_round(Round::Preprocessing).await?;
    coord.reserve_input_masks().await?;
    coord.wait_for_round(Round::InputMaskReservation).await?;
    let reserved = coord.wait_for_indices(n_inputs).await?;
    coord.collect_inputs().await?;
    coord.wait_for_round(Round::InputCollection).await?;

    let set = coord.get_client_admissions().await?;
    let reservations = admitted_reservations(&set);
    for record in &set.records {
        let range = record.input_range.unwrap();
        assert_eq!(
            reserved[&record.client],
            (range.start..range.end()).collect::<Vec<_>>(),
            "every reservation matches the agreed range"
        );
    }
    node_rpc
        .register_admitted_reservations_for_execution(execution_id, reservations)
        .await
        .unwrap();

    // The trait's `wait_for_inputs` verifies every client's signature before unmasking.
    let inputs = coord.wait_for_inputs(n_inputs, mask_shares).await?;
    coord.start_mpc().await?;
    coord.wait_for_round(Round::MPCExecution).await?;
    coord.send_output().await?;
    coord.wait_for_round(Round::OutputDistribution).await?;
    for record in &set.records {
        if let OutputRights::Receive { .. } = record.output_rights {
            let mut share = inputs[&record.client][0].clone();
            share.share[0] += offset;
            coord
                .send_output_shares(record.client.clone(), record.client.clone(), vec![share])
                .await?;
        }
    }
    coord.finalize().await?;
    coord.wait_for_round(Round::ProgramFinished).await?;
    coord.retire_execution().await
}

/// One client's whole run: associate, reserve, reconstruct the mask by position, submit a
/// signed range, and reconstruct the output from signed per-node items.
async fn run_client(
    mut coord: HbClient,
    request: AssociationRequest,
    node_rpc_addrs: Vec<(String, u16)>,
    cert: Certified,
    input: Fr,
) -> Result<(ClientAdmission, Vec<Fr>), CoordinatorError> {
    let admission = coord.associate_client(request).await?;
    let range = admission.input_range.unwrap();
    coord.wait_for_round(Round::InputMaskReservation).await?;
    coord
        .reserve_mask_indices(&(range.start..range.end()).collect::<Vec<_>>())
        .await?;
    let node_client = start_node_client(
        coord.execution_id(),
        coord.node_roster(),
        node_rpc_addrs,
        cert,
    )
    .await?;
    let mask = node_client
        .receive_assigned_masks(range.start, range.count.get())
        .await?
        .remove(0);
    coord.wait_for_round(Round::InputCollection).await?;
    coord
        .send_masked_inputs(&[(range.start, input + mask)])
        .await?;
    coord.wait_for_round(Round::OutputDistribution).await?;
    let outputs = coord.obtain_outputs().await?;
    Ok((admission, outputs))
}

/// Drives one execution: `n` nodes with threshold `t`, of which `active` run a coordinator
/// client and a node RPC listener, and one client whose input is 1337.
async fn run_end_to_end(
    n: usize,
    active: usize,
    registration_of: impl FnOnce(&Certified) -> ExecutionRegistration,
) {
    stoffel_mpc_coordinator_shared::setup_test();
    let t = 1;
    let certs = node_certs(n);
    let coordinator = server_cert();
    let client = client_cert();
    let registration = registration_of(&client);
    let execution_id = registration.execution_id;
    let state = coordinator_state(t as u64, &certs, &coordinator, registration);
    let port = free_port();
    let _server = start_coordinator(state, port, &coordinator).await;

    let mask = Fr::from(42);
    let mask_shares =
        HoneyBadgerShareType::compute_shares(mask, n, t, None, &mut test_rng()).unwrap();
    let mut node_rpc_addrs = Vec::new();
    let mut nodes = tokio::task::JoinSet::new();
    for (position, cert) in certs.iter().enumerate().take(active) {
        let rpc_port = free_port();
        let node_rpc = start_node_server(execution_id, rpc_port, cert.clone()).await;
        node_rpc_addrs.push((ADDR.to_string(), rpc_port));
        let coord = start_coord_client(execution_id, port, &coordinator, cert.clone()).await;
        nodes.spawn(run_node(
            coord,
            node_rpc,
            vec![mask_shares[position].clone()],
            Fr::from(5),
        ));
    }

    let client_coord = start_coord_client(execution_id, port, &coordinator, client.clone()).await;
    let (admission, outputs) = tokio::time::timeout(
        Duration::from_secs(30),
        run_client(
            client_coord,
            open_request(),
            node_rpc_addrs,
            client,
            Fr::from(1337),
        ),
    )
    .await
    .expect("the client finishes")
    .unwrap();
    assert_eq!(admission.client_index, ClientIndex(0));
    assert_eq!(outputs, vec![Fr::from(1342)]);
    while let Some(node) = nodes.join_next().await {
        node.unwrap().unwrap();
    }
}

// Goes through one entire program execution, calling all needed coordinator methods.
#[tokio::test]
async fn end_to_end() {
    run_end_to_end(5, 3, |client| {
        pre_registered(execution(0x50), vec![slot(1, 1)], &[client])
    })
    .await;
}

#[tokio::test]
async fn end_to_end_fake_coord() {
    run_end_to_end(5, 3, |client| {
        pre_registered(execution(0x52), vec![slot(1, 1)], &[client])
    })
    .await;
}

#[tokio::test]
async fn open_admission_end_to_end_with_a_client_minted_at_test_time() {
    stoffel_mpc_coordinator_shared::setup_test();
    let n = 4;
    let t = 1;
    let certs = node_certs(n);
    let coordinator = server_cert();
    let execution_id = execution(0xb2);
    let registration = open_registration(execution_id, vec![slot(1, 1)]);
    let state = coordinator_state(t as u64, &certs, &coordinator, registration.clone());
    let port = free_port();
    let _server = start_coordinator(state, port, &coordinator).await;

    let mask_shares =
        HoneyBadgerShareType::compute_shares(Fr::from(99), n, t, None, &mut test_rng()).unwrap();
    let mut node_rpc_addrs = Vec::new();
    let mut nodes = tokio::task::JoinSet::new();
    for (position, cert) in certs.iter().enumerate() {
        let rpc_port = free_port();
        let node_rpc = start_node_server(execution_id, rpc_port, cert.clone()).await;
        node_rpc_addrs.push((ADDR.to_string(), rpc_port));
        let coord = start_coord_client(execution_id, port, &coordinator, cert.clone()).await;
        nodes.spawn(run_node(
            coord,
            node_rpc,
            vec![mask_shares[position].clone()],
            Fr::from(5),
        ));
    }

    // Only now is the client's certificate minted: it cannot appear in any registration field.
    let client = client_cert();
    let identity = identity_of(&client);
    let AdmissionPolicy::Open = &registration.admission else {
        panic!("the registration is open");
    };
    assert!(!format!("{registration:?}").contains(&format!("{identity:?}")));

    let client_coord = start_coord_client(execution_id, port, &coordinator, client.clone()).await;
    let summary = client_coord.get_execution_summary().await.unwrap();
    assert_eq!(summary.admission, AdmissionPolicyKind::Open);
    assert!(summary.deadlines.is_some());

    let (admission, outputs) = tokio::time::timeout(
        Duration::from_secs(30),
        run_client(
            client_coord,
            open_request(),
            node_rpc_addrs,
            client,
            Fr::from(42),
        ),
    )
    .await
    .expect("the client finishes")
    .unwrap();
    assert_eq!(
        admission,
        ClientAdmission {
            execution_id,
            client_index: ClientIndex(0),
            input_range: Some(range(0, 1)),
            output_rights: receive(1),
        }
    );
    assert_eq!(outputs, vec![Fr::from(47)]);
    while let Some(node) = nodes.join_next().await {
        node.unwrap().unwrap();
    }
}
