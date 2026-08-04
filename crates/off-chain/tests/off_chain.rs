use ark_bls12_381::Fr;
use ark_std::test_rng;
use std::sync::Arc;
use stoffel_mpc_coordinator_off_chain::tests::fake_coord::{
    HoneyBadgerCoordinatorRPCServerSharedBase, HoneyBadgerNodeRPCClient, HoneyBadgerNodeRPCServer,
    HoneyBadgerOffChainCoordinatorClient, HoneyBadgerOffChainCoordinatorServer,
};
use stoffel_mpc_coordinator_off_chain::node_rpc::OffChainNodeRPCClient;
use stoffel_mpc_coordinator_off_chain::{
    AssignedMaskReservation, CoordinatorRPCBaseClient, ExecutionRegistration, InputAssignment,
};
use stoffel_mpc_coordinator_shared::self_signed_certs::{client_cert, server_cert};
use stoffel_mpc_coordinator_shared::tests::fake_coord::{
    HoneyBadgerShareType, HoneyBadgerShareValueType,
};
use stoffel_mpc_coordinator_shared::{Coordinator, ShareBound};
use stoffel_mpc_coordinator_shared::{ExecutionId, Round};
use stoffelmpc_mpc::common::SecretSharingScheme;
use tokio::sync::Barrier;

fn sample_ids(n: usize) -> Vec<usize> {
    (1..=n).collect()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

fn execution(byte: u8) -> ExecutionId {
    ExecutionId::from_bytes([byte; 32])
}

fn cert_parts(cert: &Arc<rcgen::CertifiedKey<rcgen::KeyPair>>) -> (Vec<u8>, Vec<u8>) {
    (cert.cert.der().to_vec(), cert.signing_key.serialize_der())
}

fn coordinator_state(
    execution_id: ExecutionId,
    n: u64,
    t: u64,
    nodes: Vec<Vec<u8>>,
    n_inputs: u64,
    output_clients: Vec<Vec<u8>>,
) -> HoneyBadgerCoordinatorRPCServerSharedBase {
    HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
        execution_id,
        [1; 32],
        n,
        t,
        nodes,
        n_inputs,
        output_clients,
        InputAssignment::default(),
    )
    .unwrap()
}

async fn start_node_server(
    execution_id: ExecutionId,
    addr: &str,
    port: u16,
    cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
) -> HoneyBadgerNodeRPCServer {
    let (cert_der, key_der) = cert_parts(&cert);
    HoneyBadgerNodeRPCServer::start_for_execution(addr, port, execution_id, cert_der, key_der)
        .await
        .unwrap()
}

async fn start_node_client(
    execution_id: ExecutionId,
    n: usize,
    t: usize,
    addrs: Vec<(String, u16)>,
    cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
) -> HoneyBadgerNodeRPCClient {
    let (cert_der, key_der) = cert_parts(&cert);
    HoneyBadgerNodeRPCClient::start_rpc_client_for_execution(
        n,
        t,
        addrs,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap()
}

async fn start_coord_client(
    execution_id: ExecutionId,
    addr: &str,
    port: u16,
    t: u64,
    n_parties: u64,
    n_outputs: u64,
    cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
) -> HoneyBadgerOffChainCoordinatorClient {
    let (cert_der, key_der) = cert_parts(&cert);
    HoneyBadgerOffChainCoordinatorClient::start_rpc_client_for_execution(
        addr,
        port,
        t,
        n_parties,
        n_outputs,
        execution_id,
        cert_der,
        key_der,
    )
    .await
    .unwrap()
}

#[test]
fn rejects_invalid_mpc_rosters() {
    let build = |execution_id, n, t, nodes| {
        HoneyBadgerCoordinatorRPCServerSharedBase::new_for_execution(
            execution_id,
            [1; 32],
            n,
            t,
            nodes,
            0,
            vec![],
            InputAssignment::default(),
        )
    };

    let valid_execution = ExecutionId::from_bytes([1; 32]);
    assert!(build(valid_execution, 1, 0, vec![]).is_err());
    assert!(build(valid_execution, 2, 1, vec![vec![1]]).is_err());
    assert!(build(valid_execution, 2, 1, vec![vec![1], vec![1]]).is_err());
    assert!(build(valid_execution, 1, 1, vec![vec![1]]).is_err());
    assert!(build(ExecutionId::from_bytes([0; 32]), 1, 0, vec![vec![1]]).is_err());
}

#[tokio::test]
async fn one_listener_isolates_and_retires_concurrent_executions() {
    stoffel_mpc_coordinator_shared::setup_test();

    let node_cert = client_cert();
    let node_id = node_cert.signing_key.public_key_raw().to_vec();
    let addr = "127.0.0.1";
    let port = free_port();
    let first_id = execution(0x31);
    let second_id = execution(0x32);
    let state = HoneyBadgerCoordinatorRPCServerSharedBase::new(1, 0, vec![node_id]).unwrap();
    let _server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        addr,
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    let first = start_coord_client(first_id, addr, port, 0, 1, 0, node_cert.clone()).await;
    let second = start_coord_client(second_id, addr, port, 0, 1, 0, node_cert).await;
    for (client, execution_id, program_hash) in [
        (&first, first_id, [0x41; 32]),
        (&second, second_id, [0x42; 32]),
    ] {
        client
            .register_execution(ExecutionRegistration {
                execution_id,
                program_hash,
                n_inputs: 0,
                output_clients: vec![],
                input_assignment: InputAssignment::default(),
                min_output_shares: 1,
            })
            .await
            .unwrap();
    }

    first.start_preprocessing().await.unwrap();
    first.wait_for_round(Round::Preprocessing).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            second.wait_for_round(Round::Preprocessing),
        )
        .await
        .is_err(),
        "a transition for one execution must not wake another"
    );
    second.start_preprocessing().await.unwrap();
    second.wait_for_round(Round::Preprocessing).await.unwrap();

    first.start_mpc().await.unwrap();
    first.send_output().await.unwrap();
    first.finalize().await.unwrap();
    first.retire_execution().await.unwrap();
    assert!(first.wait_for_round(Round::ProgramFinished).await.is_err());
    second.wait_for_round(Round::Preprocessing).await.unwrap();
}

#[tokio::test]
async fn start_client_server() {
    stoffel_mpc_coordinator_shared::setup_test();

    let certs = (0..7).map(|_| server_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let addr = "127.0.0.1";
    let port = 12345;
    let t = 1;
    let execution_id = execution(0x45);
    let server_state = coordinator_state(execution_id, 5, t, public_keys[..5].to_vec(), 1, vec![]);
    let _coord = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        addr,
        port,
        t,
        server_cert(),
    )
    .await
    .unwrap();

    let _ = start_coord_client(execution_id, addr, port, 1, 5, 1, client_cert()).await;
}

#[tokio::test]
async fn coordinator_shutdown_closes_connections_and_releases_port() {
    stoffel_mpc_coordinator_shared::setup_test();

    let cert = client_cert();
    let public_key = cert.signing_key.public_key_raw().to_vec();
    let addr = "127.0.0.1";
    let port = free_port();
    let execution_id = execution(0x46);
    let state = coordinator_state(execution_id, 1, 0, vec![public_key.clone()], 0, vec![]);
    let server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        addr,
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    let client = start_coord_client(execution_id, addr, port, 0, 1, 0, cert).await;

    client.trigger_round(Round::Preprocessing).await.unwrap();
    server.shutdown().await;
    let disconnected = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.trigger_round(Round::InputMaskReservation),
    )
    .await
    .expect("client RPC did not finish after server shutdown");
    assert!(disconnected.is_err());

    let replacement_state = coordinator_state(execution_id, 1, 0, vec![public_key], 0, vec![]);
    let replacement = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        replacement_state,
        addr,
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    replacement.shutdown().await;
}

#[tokio::test]
async fn dropping_node_server_closes_connections_and_releases_port() {
    stoffel_mpc_coordinator_shared::setup_test();

    let addr = "127.0.0.1";
    let port = free_port();
    let execution_id = execution(0x47);
    let server = start_node_server(execution_id, addr, port, server_cert()).await;
    let client = start_node_client(
        execution_id,
        1,
        0,
        vec![(addr.to_string(), port)],
        client_cert(),
    )
    .await;

    drop(server);
    let disconnected = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        client.receive_assigned_masks(0, 1),
    )
    .await
    .expect("node RPC did not finish after server drop");
    assert!(disconnected.is_err());

    let replacement = start_node_server(execution_id, addr, port, server_cert()).await;
    replacement.shutdown().await;
}

// Fakes event triggering.
#[tokio::test]
async fn trigger_pp() {
    stoffel_mpc_coordinator_shared::setup_test();

    // event triggered BEFORE waiting for the event
    {
        let mut certs = (0..5).map(|_| server_cert()).collect::<Vec<_>>();
        let public_keys = certs
            .iter()
            .map(|c| c.signing_key.public_key_raw().to_vec())
            .collect::<Vec<_>>();

        let addr = "127.0.0.1";
        let port = 12346;
        let t = 1;
        let execution_id = execution(0x48);
        let server_state = coordinator_state(execution_id, 5, t, public_keys, 1, vec![]);
        let _coord = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
            server_state,
            addr,
            port,
            t,
            server_cert(),
        )
        .await
        .unwrap();

        let node0 = start_coord_client(execution_id, addr, port, 1, 5, 1, certs.remove(0)).await;
        let node1 = start_coord_client(execution_id, addr, port, 1, 5, 1, certs.remove(0)).await;

        node0.trigger_round(Round::Preprocessing).await.unwrap();

        if tokio::time::timeout(
            std::time::Duration::from_millis(500),
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
        let mut certs = (0..5).map(|_| server_cert()).collect::<Vec<_>>();
        let public_keys = certs
            .iter()
            .map(|c| c.signing_key.public_key_raw().to_vec())
            .collect::<Vec<_>>();

        let addr = "127.0.0.1";
        let port = 12347;
        let t = 1;
        let execution_id = execution(0x49);
        let server_state = coordinator_state(execution_id, 5, t, public_keys, 1, vec![]);
        let _coord = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
            server_state,
            addr,
            port,
            t,
            server_cert(),
        )
        .await
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));

        let node0 = start_coord_client(execution_id, addr, port, 1, 5, 1, certs.remove(0)).await;
        let node1 = start_coord_client(execution_id, addr, port, 1, 5, 1, certs.remove(0)).await;

        tokio::spawn({
            let barrier = barrier.clone();
            async move {
                if tokio::time::timeout(
                    std::time::Duration::from_millis(500),
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

        node0.trigger_round(Round::Preprocessing).await.unwrap();
        barrier.wait().await;
    }
}

#[tokio::test]
async fn zero_input_execution_skips_input_rounds() {
    stoffel_mpc_coordinator_shared::setup_test();
    let cert = client_cert();
    let execution_id = execution(0x4a);
    let state = coordinator_state(
        execution_id,
        1,
        0,
        vec![cert.signing_key.public_key_raw().to_vec()],
        0,
        vec![],
    );
    let port = free_port();
    let _server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        "127.0.0.1",
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    let node = start_coord_client(execution_id, "127.0.0.1", port, 0, 1, 0, cert).await;

    node.start_preprocessing().await.unwrap();
    node.start_mpc().await.unwrap();
    node.wait_for_round(Round::MPCExecution).await.unwrap();
}

#[tokio::test]
async fn reserve_mask_indices_rejects_empty_batch() {
    stoffel_mpc_coordinator_shared::setup_test();
    let cert = client_cert();
    let execution_id = execution(0x4c);
    let state = coordinator_state(
        execution_id,
        1,
        0,
        vec![cert.signing_key.public_key_raw().to_vec()],
        2,
        vec![],
    );
    let port = free_port();
    let _server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        "127.0.0.1",
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    let mut node = start_coord_client(execution_id, "127.0.0.1", port, 0, 1, 0, cert).await;

    node.start_preprocessing().await.unwrap();
    node.wait_for_round(Round::Preprocessing).await.unwrap();
    node.reserve_input_masks().await.unwrap();
    node.wait_for_round(Round::InputMaskReservation)
        .await
        .unwrap();

    node.reserve_mask_indices(&[])
        .await
        .expect_err("an empty batch of indices does not make sense and must be rejected");
}

#[tokio::test]
async fn client_may_only_call_reserve_mask_indices_once() {
    stoffel_mpc_coordinator_shared::setup_test();
    let cert = client_cert();
    let execution_id = execution(0x4d);
    let state = coordinator_state(
        execution_id,
        1,
        0,
        vec![cert.signing_key.public_key_raw().to_vec()],
        2,
        vec![],
    );
    let port = free_port();
    let _server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        state,
        "127.0.0.1",
        port,
        0,
        server_cert(),
    )
    .await
    .unwrap();
    let mut node = start_coord_client(execution_id, "127.0.0.1", port, 0, 1, 0, cert).await;

    node.start_preprocessing().await.unwrap();
    node.wait_for_round(Round::Preprocessing).await.unwrap();
    node.reserve_input_masks().await.unwrap();
    node.wait_for_round(Round::InputMaskReservation)
        .await
        .unwrap();

    node.reserve_mask_indices(&[0])
        .await
        .expect("first reservation call must succeed");

    node.reserve_mask_indices(&[1]).await.expect_err(
        "a second reservation call from the same client must be rejected, even though index 1 \
         is still free",
    );
}

// Goes through one entire program execution, calling all needed coordinator methods.
#[tokio::test]
async fn end_to_end() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n = 5;
    let t = 1;
    let n_nodes =
        <HoneyBadgerShareType as ShareBound<HoneyBadgerShareValueType>>::min_shares(t as usize);
    let node_rpc_addrs: Vec<(String, u16)> = (0..n_nodes)
        .map(|i| ("127.0.0.1".to_string(), 12349u16 + i as u16))
        .collect();

    let certs = (0..7).map(|_| client_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);
    let coord_addr = "127.0.0.1";
    let coord_port = 12348;
    let execution_id = execution(0x50);
    let server_state = coordinator_state(
        execution_id,
        n,
        t,
        public_keys[..n as usize].to_vec(),
        1,
        vec![public_keys[5].clone()],
    );
    let _coord = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        coord_addr,
        coord_port,
        t,
        server_cert(),
    )
    .await
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));

    // MPC node (designated party), also RPC client
    tokio::spawn({
        let barrier = barrier.clone();

        let mut coords: Vec<HoneyBadgerOffChainCoordinatorClient> = Vec::new();
        for cert in certs.iter().take(n_nodes) {
            let coord =
                start_coord_client(execution_id, coord_addr, coord_port, 1, n, 1, cert.clone())
                    .await;
            coords.push(coord);
        }

        // simulate min_shares(t) = n_nodes RPC nodes for client authentication; we just have one
        // node here, but we use 3 RPC nodes to make the process work
        let mut rng = test_rng();
        let ids = sample_ids(n as usize);
        let mask_shares = HoneyBadgerShareType::compute_shares(
            correct_mask,
            n as usize,
            t as usize,
            Some(&ids),
            &mut rng,
        )
        .unwrap();
        let output_shares = HoneyBadgerShareType::compute_shares(
            correct_output,
            n as usize,
            t as usize,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let mut node_rpcs = Vec::new();
        for i in 0..n_nodes {
            let node_rpc = start_node_server(
                execution_id,
                &node_rpc_addrs[i].0,
                node_rpc_addrs[i].1,
                certs[i].clone(),
            )
            .await;

            node_rpc
                .add_mask_share_for_execution(execution_id, 0, &mask_shares[i])
                .await
                .unwrap();
            node_rpcs.push(node_rpc);
        }

        async move {
            coords[0].trigger_round(Round::Preprocessing).await.unwrap();
            coords[0]
                .wait_for_round(Round::Preprocessing)
                .await
                .unwrap();
            coords[0]
                .trigger_round(Round::InputMaskReservation)
                .await
                .unwrap();
            coords[0]
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();
            let client_to_indices = coords[0].wait_for_indices(1).await.unwrap(); // called by node
            for (c, indices) in &client_to_indices {
                println!("NODE: client {:?} reserved indices {:?}", c, indices);
                for node_rpc in node_rpcs.iter_mut() {
                    // just received by one node here, but in reality would be received by
                    // all nodes, so we simulate this here for more nodes
                    node_rpc
                        .add_reserved_indices_for_execution(execution_id, c.to_vec(), indices.clone())
                        .await
                        .unwrap();
                }
            }

            coords[0]
                .trigger_round(Round::InputCollection)
                .await
                .unwrap();
            coords[0]
                .wait_for_round(Round::InputCollection)
                .await
                .unwrap();
            let client_to_masked_input = coords[0]
                .wait_for_inputs(1, vec![mask_shares[0].clone()])
                .await
                .unwrap();
            for (c, masked_inputs) in client_to_masked_input {
                for masked_input in masked_inputs {
                    println!(
                        "NODE: client {:?} submitted masked input {:?}",
                        c, masked_input
                    );
                }
            }
            coords[0].trigger_round(Round::MPCExecution).await.unwrap();
            coords[0].wait_for_round(Round::MPCExecution).await.unwrap();
            coords[0]
                .trigger_round(Round::OutputDistribution)
                .await
                .unwrap();
            coords[0]
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            for (i, coord) in coords.iter_mut().enumerate() {
                coord
                    .send_output_shares(
                        public_keys[5].clone(),
                        public_keys[5].clone(),
                        vec![output_shares[i].clone()],
                    )
                    .await
                    .unwrap();
            }
            coords[0]
                .trigger_round(Round::ProgramFinished)
                .await
                .unwrap();

            barrier.wait().await;
        }
    });

    // MPC client, also RPC client
    tokio::spawn({
        let barrier = barrier.clone();
        let cert = certs[5].clone();
        let mut coord =
            start_coord_client(execution_id, coord_addr, coord_port, 1, n, 1, cert.clone()).await;
        let rpc_client = start_node_client(
            execution_id,
            n as usize,
            t as usize,
            node_rpc_addrs.clone(),
            cert,
        )
        .await;
        async move {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();

            coord
                .reserve_mask_indices(&[0])
                .await
                .expect("obtaining mask indices failed");
            println!("CLIENT: obtained index 0");

            let mask = rpc_client
                .receive_assigned_masks(0, 1)
                .await
                .unwrap()
                .remove(0);
            assert_eq!(mask, correct_mask);

            coord.wait_for_round(Round::InputCollection).await.unwrap();

            let masked_input = mask + Fr::from(1337);
            coord
                .send_masked_input(Fr::from(masked_input), 0)
                .await
                .unwrap();

            coord.wait_for_round(Round::MPCExecution).await.unwrap();
            coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            let outputs = coord.obtain_outputs().await.unwrap();
            println!("CLIENT: obtained outputs {:?}", outputs);
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0], correct_output);

            barrier.wait().await;
        }
    });

    barrier.wait().await;
}

#[tokio::test]
async fn end_to_end_fake_coord() {
    stoffel_mpc_coordinator_shared::setup_test();

    let n: usize = 5;
    let t = 1u64;
    let n_nodes =
        <HoneyBadgerShareType as ShareBound<HoneyBadgerShareValueType>>::min_shares(t as usize);
    let node_rpc_addrs: Vec<(String, u16)> = (0..n_nodes)
        .map(|i| ("127.0.0.1".to_string(), 12353u16 + i as u16))
        .collect();

    let certs = (0..7).map(|_| client_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);

    let coord_addr = "127.0.0.1";
    let coord_port = 12352;
    let execution_id = execution(0x52);
    let server_state = coordinator_state(
        execution_id,
        5,
        t,
        public_keys[..n].to_vec(),
        1,
        vec![public_keys[5].clone()],
    );
    let _coord = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        coord_addr,
        coord_port,
        t,
        server_cert(),
    )
    .await
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));

    // MPC node (designated party), also RPC client
    tokio::spawn({
        let barrier = barrier.clone();

        let mut coords = Vec::new();
        for cert in certs.iter().take(n_nodes) {
            let coord = start_coord_client(
                execution_id,
                coord_addr,
                coord_port,
                1,
                n as u64,
                1,
                cert.clone(),
            )
            .await;
            coords.push(coord);
        }

        // simulate min_shares(t) = n_nodes RPC nodes for client authentication; we just have one
        // node here, but we use 3 RPC nodes to make the process work
        let mut rng = test_rng();
        let ids = sample_ids(n);
        let mask_shares =
            HoneyBadgerShareType::compute_shares(correct_mask, n, t as usize, Some(&ids), &mut rng)
                .unwrap();
        let output_shares = HoneyBadgerShareType::compute_shares(
            correct_output,
            n,
            t as usize,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let mut node_rpcs = Vec::new();
        for i in 0..n_nodes {
            let node_rpc = start_node_server(
                execution_id,
                &node_rpc_addrs[i].0,
                node_rpc_addrs[i].1,
                certs[i].clone(),
            )
            .await;

            node_rpc
                .add_mask_share_for_execution(execution_id, 0, &mask_shares[i])
                .await
                .unwrap();
            node_rpcs.push(node_rpc);
        }

        async move {
            coords[0].start_preprocessing().await.unwrap();
            coords[0]
                .wait_for_round(Round::Preprocessing)
                .await
                .unwrap();
            coords[0].reserve_input_masks().await.unwrap();
            coords[0]
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();
            let client_to_indices = coords[0].wait_for_indices(1).await.unwrap(); // called by node
            for (c, indices) in &client_to_indices {
                println!("NODE: client {:?} reserved indices {:?}", c, indices);
                for node_rpc in node_rpcs.iter_mut() {
                    // just received by one node here, but in reality would be received by
                    // all nodes, so we simulate this here for more nodes
                    node_rpc
                        .add_reserved_indices_for_execution(execution_id, c.to_vec(), indices.clone())
                        .await
                        .unwrap();
                }
            }

            coords[0].collect_inputs().await.unwrap();
            coords[0]
                .wait_for_round(Round::InputCollection)
                .await
                .unwrap();
            let client_to_masked_input = coords[0]
                .wait_for_inputs(1, vec![mask_shares[0].clone()])
                .await
                .unwrap();
            for (c, masked_inputs) in client_to_masked_input {
                for masked_input in masked_inputs {
                    println!(
                        "NODE: client {:?} submitted masked input {:?}",
                        c, masked_input
                    );
                }
            }
            coords[0].start_mpc().await.unwrap();
            coords[0].wait_for_round(Round::MPCExecution).await.unwrap();
            coords[0].send_output().await.unwrap();
            coords[0]
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            for (i, coord) in coords.iter_mut().enumerate() {
                coord
                    .send_output_shares(
                        public_keys[5].clone(),
                        public_keys[5].clone(),
                        vec![output_shares[i].clone()],
                    )
                    .await
                    .unwrap();
            }
            coords[0].finalize().await.unwrap();

            barrier.wait().await;
        }
    });

    // MPC client, also RPC client
    tokio::spawn({
        let barrier = barrier.clone();
        let cert = certs[5].clone();
        let mut coord = start_coord_client(
            execution_id,
            coord_addr,
            coord_port,
            1,
            n as u64,
            1,
            cert.clone(),
        )
        .await;
        let rpc_client =
            start_node_client(execution_id, n, t as usize, node_rpc_addrs.clone(), cert).await;
        async move {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();

            coord
                .reserve_mask_indices(&[0])
                .await
                .expect("obtaining mask indices failed");
            println!("CLIENT: obtained index 0");

            let mask = rpc_client
                .receive_assigned_masks(0, 1)
                .await
                .unwrap()
                .remove(0);
            assert_eq!(mask, correct_mask);

            coord.wait_for_round(Round::InputCollection).await.unwrap();

            let masked_input = mask + Fr::from(1337);
            coord
                .send_masked_input(Fr::from(masked_input), 0)
                .await
                .unwrap();

            coord.wait_for_round(Round::MPCExecution).await.unwrap();
            coord
                .wait_for_round(Round::OutputDistribution)
                .await
                .unwrap();
            let outputs = coord.obtain_outputs().await.unwrap();
            println!("CLIENT: obtained outputs {:?}", outputs);
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0], correct_output);

            barrier.wait().await;
        }
    });

    barrier.wait().await;
}

#[tokio::test]
async fn output_waiters_receive_threshold_and_later_share_snapshots() {
    stoffel_mpc_coordinator_shared::setup_test();

    let execution_id = ExecutionId::from_bytes([0x65; 32]);
    let node_certs = [client_cert(), client_cert(), client_cert(), client_cert()];
    let node_ids = node_certs
        .iter()
        .map(|cert| cert.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();
    let output_cert = client_cert();
    let output_id = output_cert.signing_key.public_key_raw().to_vec();
    let addr = "127.0.0.1";
    let port = 12365;
    let server_state = coordinator_state(execution_id, 4, 1, node_ids, 0, vec![output_id.clone()]);
    let _server = HoneyBadgerOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        addr,
        port,
        1,
        server_cert(),
    )
    .await
    .unwrap();
    let node_rpcs = futures_util::future::join_all(node_certs.into_iter().map(|node_cert| {
        stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
            addr,
            port,
            node_cert.cert.der().to_vec(),
            node_cert.signing_key.serialize_der(),
        )
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let output_rpc = stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(
        addr,
        port,
        output_cert.cert.der().to_vec(),
        output_cert.signing_key.serialize_der(),
    )
    .await
    .unwrap();

    assert!(CoordinatorRPCBaseClient::obtain_output_shares(
        &output_rpc,
        ExecutionId::from_bytes([0x66; 32]),
    )
    .await
    .is_err());

    let mut waiter_a = CoordinatorRPCBaseClient::obtain_output_shares(&output_rpc, execution_id)
        .await
        .unwrap();
    let outputs = [
        (vec![1], vec![11]),
        (vec![2], vec![22]),
        (vec![3], vec![33]),
        (vec![4], vec![44]),
    ];
    assert!(CoordinatorRPCBaseClient::send_output_shares(
        &node_rpcs[0],
        execution_id,
        vec![0xff],
        outputs[0].clone(),
    )
    .await
    .is_err());
    CoordinatorRPCBaseClient::send_output_shares(
        &node_rpcs[0],
        execution_id,
        output_id.clone(),
        outputs[0].clone(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), waiter_a.next())
            .await
            .is_err(),
        "one share must not satisfy a t=1 output threshold"
    );

    CoordinatorRPCBaseClient::send_output_shares(
        &node_rpcs[1],
        execution_id,
        output_id.clone(),
        outputs[1].clone(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), waiter_a.next())
            .await
            .is_err(),
        "two shares must not satisfy the robust t=1 output threshold"
    );

    CoordinatorRPCBaseClient::send_output_shares(
        &node_rpcs[2],
        execution_id,
        output_id.clone(),
        outputs[2].clone(),
    )
    .await
    .unwrap();
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(1), waiter_a.next())
        .await
        .expect("threshold snapshot must be delivered")
        .expect("subscription must remain open")
        .expect("threshold snapshot must deserialize");
    assert_eq!(snapshot.len(), 3);
    assert!(outputs[..3].iter().all(|output| snapshot.contains(output)));

    CoordinatorRPCBaseClient::send_output_shares(
        &node_rpcs[3],
        execution_id,
        output_id,
        outputs[3].clone(),
    )
    .await
    .unwrap();
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(1), waiter_a.next())
        .await
        .expect("additional-share snapshot must be delivered")
        .expect("subscription must remain open after threshold delivery")
        .expect("additional-share snapshot must deserialize");
    assert_eq!(snapshot.len(), 4);
    assert!(outputs.iter().all(|output| snapshot.contains(output)));
}

// A client that abandons a still-pending `receive_assigned_mask_shares` subscription (e.g. it
// already obtained enough shares from other nodes and moved on to the next input) must not have
// its next request to the same node mistakenly rejected just because the stale sink is still
// registered.
#[tokio::test]
async fn resubscribing_for_assigned_mask_shares_supersedes_stale_request() {
    stoffel_mpc_coordinator_shared::setup_test();

    let addr = "127.0.0.1";
    let port = free_port();
    let execution_id = execution(0x70);

    let node = start_node_server(execution_id, addr, port, server_cert()).await;

    let requester_cert = client_cert();
    let requester_id = requester_cert.signing_key.public_key_raw().to_vec();
    let (cert_der, key_der) = cert_parts(&requester_cert);
    let client =
        stoffel_mpc_coordinator_shared::self_signed_certs::setup_client(addr, port, cert_der, key_der)
            .await
            .unwrap();

    // Index 0 isn't assigned to anyone yet, so this subscription stays pending, registered as
    // this client's outstanding request. Kept alive (not dropped) for the rest of the test, so
    // no unsubscribe is ever sent for it.
    let _stale_sub =
        OffChainNodeRPCClient::receive_assigned_mask_shares(&client, execution_id, 0, 1)
            .await
            .unwrap();

    // The client moves on to the next input before the first request resolves. Before the fix,
    // this would be rejected with "already requested assigned mask shares" purely because the
    // stale subscription above is still registered.
    let mut sub = OffChainNodeRPCClient::receive_assigned_mask_shares(&client, execution_id, 1, 1)
        .await
        .expect("a new request from the same client must supersede the stale one, not be rejected");

    node.add_assigned_reserved_index_for_execution(
        execution_id,
        AssignedMaskReservation {
            client: requester_id,
            reserved_index: 1,
            input_ordinal: 1,
        },
    )
    .await
    .unwrap();
    node.add_mask_share_for_execution(execution_id, 1, &Fr::from(7))
        .await
        .unwrap();

    let assigned_shares = tokio::time::timeout(std::time::Duration::from_secs(1), sub.next())
        .await
        .expect("assigned share must be delivered to the superseding subscription")
        .expect("subscription must remain open")
        .expect("assigned share must deserialize");
    assert_eq!(assigned_shares.len(), 1);
    assert_eq!(assigned_shares[0].reserved_index, 1);
}
