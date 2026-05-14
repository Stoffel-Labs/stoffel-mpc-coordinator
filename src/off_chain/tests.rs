use super::*;
use crate::self_signed_certs::{client_cert, server_cert};
use ark_bls12_381::Fr;
use ark_std::test_rng;
use tokio::sync::Barrier;
use crate::fake_coord::{off_chain::{FakeOffChainCoordinatorServer, FakeOffChainCoordinatorClient, FakeCoordinatorRPCServerSharedBase, FakeNodeRPCClient, FakeNodeRPCServer}, FakeShareType};
use stoffelmpc_mpc::common::SecretSharingScheme;

fn sample_ids(n: usize) -> Vec<usize> {
    (1..=n).collect()
}

#[tokio::test]
async fn start_client_server() {
    crate::setup_test();

    let certs = (0..7).map(|_| server_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let addr = "127.0.0.1";
    let port = 12345;
    let t = 1;
    let server_state = FakeCoordinatorRPCServerSharedBase::new([0u8; 32], 5, t, public_keys, 1, vec![]);
    let coord = FakeOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        addr,
        port,
        t,
        server_cert(),
    )
    .await
    .unwrap();
    let timestamp = coord.get_timestamp();

    let _ = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
        addr,
        port,
        timestamp,
        1,
        1,
        client_cert(),
    )
    .await
    .unwrap();
}

// Fakes event triggering.
#[tokio::test]
async fn trigger_pp() {
    crate::setup_test();

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
        let server_state =
            FakeCoordinatorRPCServerSharedBase::new([0u8; 32], 5, t, public_keys, 1, vec![]);
        let coord =
            FakeOffChainCoordinatorServer::start_coord_from_cert(
                server_state,
                addr,
                port,
                t,
                server_cert(),
            )
            .await
            .unwrap();
        let timestamp = coord.get_timestamp();

        let node0 = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            addr,
            port,
            timestamp,
            1,
            1,
            certs.remove(0),
        )
        .await
        .unwrap();
        let node1 = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            addr,
            port,
            timestamp,
            1,
            1,
            certs.remove(0),
        )
        .await
        .unwrap();

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
        let server_state =
            FakeCoordinatorRPCServerSharedBase::new([0u8; 32], 5, t, public_keys, 1, vec![]);
        let coord =
            FakeOffChainCoordinatorServer::start_coord_from_cert(
                server_state,
                addr,
                port,
                t,
                server_cert(),
            )
            .await
            .unwrap();
        let timestamp = coord.get_timestamp();
        let barrier = Arc::new(Barrier::new(2));

        let node0 = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            addr,
            port,
            timestamp,
            1,
            1,
            certs.remove(0),
        )
        .await
        .unwrap();
        let node1 = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            addr,
            port,
            timestamp,
            1,
            1,
            certs.remove(0),
        )
        .await
        .unwrap();

        tokio::spawn({
            let barrier = barrier.clone();
            async move {
                if tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    node1.trigger_round(Round::Preprocessing),
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

// Goes through one entire program execution, calling all needed coordinator methods.
#[tokio::test]
async fn end_to_end() {
    crate::setup_test();

    let node_rpc_addrs = vec![
        ("127.0.0.1".to_string(), 12349),
        ("127.0.0.1".to_string(), 12350),
        ("127.0.0.1".to_string(), 12351),
    ];

    let certs = (0..7).map(|_| client_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);

    let n = 5;
    let t = 1;
    let coord_addr = "127.0.0.1";
    let coord_port = 12348;
    let server_state = FakeCoordinatorRPCServerSharedBase::new(
        [0u8; 32],
        n,
        t,
        public_keys.clone(),
        1,
        vec![public_keys[5].clone()],
    );
    let coord = FakeOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        coord_addr,
        coord_port,
        t,
        server_cert(),
    )
    .await
    .unwrap();
    let timestamp = coord.get_timestamp();
    let barrier = Arc::new(Barrier::new(3));

    // MPC node (designated party), also RPC client
    tokio::spawn({
        let barrier = barrier.clone();

        let mut coords: Vec<FakeOffChainCoordinatorClient> = Vec::new();
        for i in 0..3 {
            let coord = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
                coord_addr,
                coord_port,
                timestamp,
                1,
                1,
                certs[i].clone(),
            )
            .await
            .unwrap();
            coords.push(coord);
        }

        // simulate 2 * t + 1 = 3 RPC nodes for client authentication; we just have one
        // node here, but we use 3 RPC nodes to make the process work
        let mut rng = test_rng();
        let ids = sample_ids(n as usize);
        let mask_shares = FakeShareType::compute_shares(
            correct_mask,
            n as usize,
            t as usize,
            Some(&ids),
            &mut rng,
        )
        .unwrap();
        let output_shares = FakeShareType::compute_shares(
            correct_output,
            n as usize,
            t as usize,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let mut node_rpcs = Vec::new();
        for i in 0..3 {
            let mut node_rpc = FakeNodeRPCServer::start_from_cert(
                &node_rpc_addrs[i].0,
                node_rpc_addrs[i].1,
                certs[i].clone(),
            )
            .await
            .unwrap();

            node_rpc.add_mask_share(0, &mask_shares[i]).await.unwrap();
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
            for (c, i) in &client_to_indices {
                println!("NODE: client {:?} reserved index {:?}", c, i);
                for node_rpc in node_rpcs.iter_mut() {
                    // just received by one node here, but in reality would be received by
                    // all nodes, so we simulate this here for more nodes
                    node_rpc.add_reserved_index(c.to_vec(), *i).await.unwrap();
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
                    #[cfg(not(feature = "avss"))]
                    println!(
                        "NODE: client {:?} submitted masked input {}",
                        c, masked_input.share[0]
                    );
                    #[cfg(feature = "avss")]
                    println!(
                        "NODE: client {:?} submitted masked input {}",
                        c, masked_input.feldmanshare.share[0]
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
        let mut coord = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            coord_addr,
            coord_port,
            timestamp,
            1,
            1,
            cert.clone(),
        )
        .await
        .unwrap();
        let rpc_client = FakeNodeRPCClient::start_rpc_client_from_cert(
            t as usize,
            node_rpc_addrs.clone(),
            cert.clone(),
        )
        .await
        .unwrap();
        async move {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();

            coord
                .reserve_mask_index(0)
                .await
                .expect("obtaining mask indices failed");
            println!("CLIENT: obtained index 0");

            let mask = rpc_client.receive_mask().await.unwrap();
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
    crate::setup_test();

    let node_rpc_addrs = vec![
        ("127.0.0.1".to_string(), 12353),
        ("127.0.0.1".to_string(), 12354),
        ("127.0.0.1".to_string(), 12355),
    ];

    let certs = (0..7).map(|_| client_cert()).collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);

    let n: usize = 5;
    let coord_addr = "127.0.0.1";
    let coord_port = 12352;
    let t = 1;
    let server_state = FakeCoordinatorRPCServerSharedBase::new(
        [0u8; 32],
        5,
        t,
        public_keys.clone(),
        1,
        vec![public_keys[5].clone()],
    );
    let coord = FakeOffChainCoordinatorServer::start_coord_from_cert(
        server_state,
        coord_addr,
        coord_port,
        t,
        server_cert(),
    )
    .await
    .unwrap();
    let timestamp = coord.get_timestamp();
    let barrier = Arc::new(Barrier::new(3));

    // MPC node (designated party), also RPC client
    tokio::spawn({
        let barrier = barrier.clone();

        let mut coords = Vec::new();
        for i in 0..3 {
            let coord = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
                coord_addr,
                coord_port,
                timestamp,
                1,
                1,
                certs[i].clone(),
            )
            .await
            .unwrap();
            coords.push(coord);
        }

        // simulate 2 * t + 1 = 3 RPC nodes for client authentication; we just have one
        // node here, but we use 3 RPC nodes to make the process work
        let mut rng = test_rng();
        let ids = sample_ids(n);
        let mask_shares =
            FakeShareType::compute_shares(correct_mask, n, t as usize, Some(&ids), &mut rng)
                .unwrap();
        let output_shares =
            FakeShareType::compute_shares(correct_output, n, t as usize, Some(&ids), &mut rng)
                .unwrap();

        let mut node_rpcs = Vec::new();
        for i in 0..3 {
            let mut node_rpc = FakeNodeRPCServer::start_from_cert(
                &node_rpc_addrs[i].0,
                node_rpc_addrs[i].1,
                certs[i].clone(),
            )
            .await
            .unwrap();

            node_rpc
                .add_mask_share(0, &mask_shares[i].clone())
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
            for (c, i) in &client_to_indices {
                println!("NODE: client {:?} reserved index {:?}", c, i);
                for node_rpc in node_rpcs.iter_mut() {
                    // just received by one node here, but in reality would be received by
                    // all nodes, so we simulate this here for more nodes
                    node_rpc.add_reserved_index(c.to_vec(), *i).await.unwrap();
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
                    #[cfg(not(feature = "avss"))]
                    println!(
                        "NODE: client {:?} submitted masked input {}",
                        c, masked_input.share[0]
                    );
                    #[cfg(feature = "avss")]
                    println!(
                        "NODE: client {:?} submitted masked input {}",
                        c, masked_input.feldmanshare.share[0]
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
        let mut coord = FakeOffChainCoordinatorClient::start_rpc_client_from_cert(
            coord_addr,
            coord_port,
            timestamp,
            1,
            1,
            cert.clone(),
        )
        .await
        .unwrap();
        let rpc_client = FakeNodeRPCClient::start_rpc_client_from_cert(
            t as usize,
            node_rpc_addrs.clone(),
            cert.clone(),
        )
        .await
        .unwrap();
        async move {
            coord.wait_for_round(Round::Preprocessing).await.unwrap();
            coord
                .wait_for_round(Round::InputMaskReservation)
                .await
                .unwrap();

            coord
                .reserve_mask_index(0)
                .await
                .expect("obtaining mask indices failed");
            println!("CLIENT: obtained index 0");

            let mask = rpc_client.receive_mask().await.unwrap();
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
async fn stop_rpc_server() {
    // TODO: try using stop_tx
}
