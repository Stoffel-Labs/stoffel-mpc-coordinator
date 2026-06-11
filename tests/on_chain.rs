use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::providers::{Provider, WalletProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy_primitives::{address, Address, FixedBytes, U256};
use ark_bls12_381::Fr;
use ark_std::test_rng;
use std::str::FromStr;
use stoffel_mpc_coordinator::on_chain::{generate_client_sig, ws_connect, OnChainCoordinator};
use stoffel_mpc_coordinator::tests::fake_coord::{
    on_chain::{FakeNodeRPCClient, FakeNodeRPCServer, FakeOnChainCoordinator},
    FakeShareType, FakeShareValueType, FakeValueType,
};
use stoffel_mpc_coordinator::ShareBound;
use stoffel_mpc_coordinator::{Coordinator, Round};
use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator;
use stoffel_solidity_bindings::stoffel_coordinator::StoffelCoordinator::StoffelCoordinatorInstance;
use stoffel_solidity_bindings_test::fake_coordinator::FakeCoordinator;
use stoffelmpc_mpc::common::SecretSharingScheme;
use tokio::time::{timeout, Duration};

static SK: [&str; 10] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];

static ACC: [Address; 10] = [
    address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
    address!("0x90F79bf6EB2c4f870365E785982E1f101E93b906"),
    address!("0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"),
    address!("0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"),
    address!("0x976EA74026E726554dB657fA54763abd0C3a0aa9"),
    address!("0x14dC79964da2C08b23698B3D3cc7Ca32193d9955"),
    address!("0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f"),
    address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"),
];

fn sample_ids(n: usize) -> Vec<usize> {
    (1..=n).collect()
}

fn spawn_anvil() -> AnvilInstance {
    Anvil::new().spawn()
}

async fn run_node_round<P: Provider + WalletProvider + Clone + 'static>(
    coords: &mut [FakeOnChainCoordinator<P>],
    node_rpcs: &mut [FakeNodeRPCServer<P>],
    mask_shares: Vec<FakeShareType>,
    output_shares: Vec<FakeShareType>,
    client_addr: Address,
    public_key: Vec<u8>,
) {
    for (i, node_rpc) in node_rpcs.iter_mut().enumerate() {
        node_rpc
            .add_mask_share(0, mask_shares[i].clone())
            .await
            .unwrap();
    }
    coords[0].trigger_round(Round::Preprocessing).await.unwrap();
    let _ = coords[0].wait_for_round(Round::Preprocessing).await;
    coords[0]
        .trigger_round(Round::InputMaskReservation)
        .await
        .unwrap();
    let _ = coords[0].wait_for_round(Round::InputMaskReservation).await;
    let client_to_index = coords[0].wait_for_indices(1).await.unwrap();
    assert_eq!(client_to_index.len(), 1);
    assert!(client_to_index.contains_key(&client_addr));
    for (c, indices) in client_to_index {
        for i in indices {
            println!("NODE: client {:?} reserved index {:?}", c, i);
            for node_rpc in node_rpcs.iter_mut() {
                node_rpc.add_reserved_index(c, i).await.unwrap();
            }
        }
    }
    coords[0]
        .trigger_round(Round::InputCollection)
        .await
        .unwrap();
    let _ = coords[0].wait_for_round(Round::InputCollection).await;
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
    let _ = coords[0].wait_for_round(Round::MPCExecution).await;
    coords[0]
        .trigger_round(Round::OutputDistribution)
        .await
        .unwrap();
    let _ = coords[0].wait_for_round(Round::OutputDistribution).await;
    for node_rpc in node_rpcs.iter() {
        let authenticated = node_rpc.ids_and_addrs().await;
        assert_eq!(authenticated.len(), 1);
        let client_public_key = &authenticated
            .iter()
            .find(|(_, addr)| *addr == client_addr)
            .expect("client address not found")
            .0;
        assert_eq!(public_key, *client_public_key);
    }
    for (i, coord) in coords.iter_mut().enumerate() {
        coord
            .send_output_shares(
                client_addr,
                public_key.clone(),
                vec![output_shares[i].clone()],
            )
            .await
            .unwrap();
    }
    coords[0]
        .trigger_round(Round::ProgramFinished)
        .await
        .unwrap();
}

async fn run_client_round<P: Provider + WalletProvider + Clone + 'static>(
    coord: &mut FakeOnChainCoordinator<P>,
    rpc_client: &FakeNodeRPCClient,
    client_addr: Address,
    client_sk: &str,
    correct_mask: FakeValueType,
    correct_output: FakeValueType,
) {
    let _ = coord.wait_for_round(Round::Preprocessing).await;
    let _ = coord.wait_for_round(Round::InputMaskReservation).await;
    coord
        .reserve_mask_index(0)
        .await
        .expect("obtaining mask indices failed");
    println!("CLIENT: obtained index 0");
    let base_nonce = coord.base_nonce().await;
    let signer = PrivateKeySigner::from_str(client_sk).unwrap();
    let sig = generate_client_sig(base_nonce, 0, signer)
        .await
        .expect("generating client signature failed");
    let mask = rpc_client
        .receive_mask(sig.into(), client_addr)
        .await
        .unwrap();
    assert_eq!(mask, correct_mask);
    let _ = coord.wait_for_round(Round::InputCollection).await;
    let masked_input = mask + FakeValueType::from(1337);
    coord.send_masked_input(masked_input, 0).await.unwrap();
    let _ = coord.wait_for_round(Round::MPCExecution).await;
    let _ = coord.wait_for_round(Round::OutputDistribution).await;
    let outputs = coord.obtain_outputs().await.unwrap();
    println!("CLIENT: obtained outputs {:?}", outputs);
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0], correct_output);
}

#[tokio::test]
pub async fn coord_creation_block() {
    let anvil = spawn_anvil();
    let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
    let t = 1u64;
    let threshold =
        U256::from(<FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize));
    let hash =
        FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("invalid hash");
    let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
    let n_inputs = U256::from(1);

    let fake_instance = FakeCoordinator::deploy(
        provider.clone(),
        hash,
        U256::from(t),
        initial_mpc_nodes.clone(),
        n_inputs,
        vec![],
        threshold,
    )
    .await
    .expect("deployment failed");
    let coord_instance = StoffelCoordinator::new(*fake_instance.address(), provider.clone());
    let coord = FakeOnChainCoordinator::new(coord_instance, 5, t, 1, None).await;
    assert_eq!(coord.contract_block, 1);
}

#[tokio::test]
pub async fn event_listening() {
    // event triggered BEFORE waiting for the event
    {
        let anvil = spawn_anvil();
        let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
        let t = 1;
        let threshold =
            U256::from(<FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize));
        let hash = FixedBytes::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("invalid hash");
        let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
        let n_inputs = U256::from(1);

        let fake_instance = FakeCoordinator::deploy(
            provider.clone(),
            hash,
            U256::from(t),
            initial_mpc_nodes.clone(),
            n_inputs,
            vec![],
            U256::from(threshold),
        )
        .await
        .expect("deployment failed");
        let coord_instance = StoffelCoordinator::new(*fake_instance.address(), provider.clone());
        let coord = FakeOnChainCoordinator::new(coord_instance, 5, t, 1, None).await;

        coord.trigger_round(Round::Preprocessing).await.unwrap();
        coord.wait_for_round(Round::Preprocessing).await.unwrap();
    }

    // event triggered AFTER waiting for the event
    {
        let anvil = spawn_anvil();
        let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
        let t = 1;
        let threshold =
            U256::from(<FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize));
        let hash = FixedBytes::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("invalid hash");
        let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
        let n_inputs = U256::from(1);

        let fake_instance = FakeCoordinator::deploy(
            provider.clone(),
            hash,
            U256::from(t),
            initial_mpc_nodes.clone(),
            n_inputs,
            vec![],
            U256::from(threshold),
        )
        .await
        .expect("deployment failed");
        let coord_instance = StoffelCoordinator::new(*fake_instance.address(), provider.clone());
        let coord = FakeOnChainCoordinator::new(coord_instance, 5, t, 1, None).await;

        tokio::spawn({
            let coord = coord.clone();
            async move {
                if timeout(
                    Duration::from_millis(500),
                    coord.wait_for_round(Round::Preprocessing),
                )
                .await
                .is_err()
                {
                    panic!();
                }
            }
        });

        coord.trigger_round(Round::Preprocessing).await.unwrap();
    }
}

#[tokio::test]
pub async fn start_node_rpc() {
    stoffel_mpc_coordinator::setup_test();

    let node_rpc_addrs = vec![
        ("127.0.0.1".to_string(), 12348),
        ("127.0.0.1".to_string(), 12349),
        ("127.0.0.1".to_string(), 12350),
    ];
    let anvil = spawn_anvil();
    let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
    let n = 5;
    let t = 1;
    let threshold = U256::from(<FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t));
    let hash =
        FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("invalid hash");
    let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
    let n_inputs = U256::from(1);

    let contract = FakeCoordinator::deploy(
        provider.clone(),
        hash,
        U256::from(t),
        initial_mpc_nodes.clone(),
        n_inputs,
        vec![],
        threshold,
    )
    .await
    .expect("deployment failed");

    // simulate 2 * t + 1 = 3 nodes that have received valid signatures from a client
    let mut node_rpcs = Vec::new();
    for i in 0..node_rpc_addrs.len() {
        let provider = ws_connect(&anvil.ws_endpoint(), SK[i]).await;
        let instance = StoffelCoordinatorInstance::new(*contract.address(), provider.clone());

        let node_rpc = FakeNodeRPCServer::start_from_cert(
            &node_rpc_addrs[i].0,
            node_rpc_addrs[i].1,
            instance.clone(),
            stoffel_mpc_coordinator::self_signed_certs::server_cert(),
        )
        .await;
        node_rpcs.push(node_rpc);
    }
    let _ = FakeNodeRPCClient::start_rpc_client_from_cert(
        n,
        t,
        node_rpc_addrs.clone(),
        stoffel_mpc_coordinator::self_signed_certs::client_cert(),
    )
    .await;
}

#[tokio::test]
pub async fn end_to_end() {
    stoffel_mpc_coordinator::setup_test();

    let certs = (0..7)
        .map(|_| stoffel_mpc_coordinator::self_signed_certs::client_cert())
        .collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);

    let n = 5;
    let t = 1u64;
    let n_nodes = <FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize);
    let node_rpc_addrs: Vec<(String, u16)> = (0..n_nodes)
        .map(|i| ("127.0.0.1".to_string(), 12351u16 + i as u16))
        .collect();
    let anvil = spawn_anvil();
    let hash =
        FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("invalid hash");
    let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
    let n_inputs = U256::from(1);

    let provider = ws_connect(&anvil.ws_endpoint(), SK[9]).await;
    let contract = FakeCoordinator::deploy(
        provider.clone(),
        hash,
        U256::from(t),
        initial_mpc_nodes.clone(),
        n_inputs,
        vec![ACC[5]],
        U256::from(n_nodes),
    )
    .await
    .expect("deployment failed");

    let mut instances = Vec::new();
    for sk in SK.iter().take(n_nodes) {
        let p = ws_connect(&anvil.ws_endpoint(), sk).await;
        instances.push(StoffelCoordinatorInstance::new(*contract.address(), p));
    }

    let mut coords = Vec::new();
    for instance in instances.iter().take(n_nodes) {
        coords.push(FakeOnChainCoordinator::new(instance.clone(), n as u64, 1, 1, None).await);
    }

    let mut rng = test_rng();
    let ids = sample_ids(n);
    let mask_shares =
        FakeShareType::compute_shares(correct_mask, n, t as usize, Some(&ids), &mut rng).unwrap();
    let output_shares =
        FakeShareType::compute_shares(correct_output, n, t as usize, Some(&ids), &mut rng).unwrap();

    let mut node_rpcs = Vec::new();
    for i in 0..n_nodes {
        let node_rpc = FakeNodeRPCServer::start_from_cert(
            &node_rpc_addrs[i].0,
            node_rpc_addrs[i].1,
            instances[i].clone(),
            certs[i].clone(),
        )
        .await;
        node_rpcs.push(node_rpc);
    }

    let client_provider = ws_connect(&anvil.ws_endpoint(), SK[5]).await;
    let client_instance = StoffelCoordinatorInstance::new(*contract.address(), client_provider);
    let mut client_coord = FakeOnChainCoordinator::new(
        client_instance,
        n as u64,
        t,
        1,
        Some(certs[5].signing_key.serialize_der()),
    )
    .await;
    let rpc_client = FakeNodeRPCClient::start_rpc_client_from_cert(
        n,
        t as usize,
        node_rpc_addrs.clone(),
        certs[5].clone(),
    )
    .await;

    tokio::join!(
        run_node_round(
            &mut coords,
            &mut node_rpcs,
            mask_shares,
            output_shares[..n_nodes].to_vec(),
            ACC[5],
            public_keys[5].clone()
        ),
        run_client_round(
            &mut client_coord,
            &rpc_client,
            ACC[5],
            SK[5],
            correct_mask,
            correct_output
        )
    );
}

#[tokio::test]
pub async fn reset_and_rerun() {
    stoffel_mpc_coordinator::setup_test();

    let certs = (0..7)
        .map(|_| stoffel_mpc_coordinator::self_signed_certs::client_cert())
        .collect::<Vec<_>>();
    let public_keys = certs
        .iter()
        .map(|c| c.signing_key.public_key_raw().to_vec())
        .collect::<Vec<_>>();

    let correct_mask = Fr::from(42);
    let correct_output = Fr::from(31415);

    let n = 5;
    let t = 1u64;
    let n_nodes = <FakeShareType as ShareBound<FakeShareValueType>>::min_shares(t as usize);
    let node_rpc_addrs: Vec<(String, u16)> = (0..n_nodes)
        .map(|i| ("127.0.0.1".to_string(), 12354u16 + i as u16))
        .collect();
    let anvil = spawn_anvil();
    let hash =
        FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .expect("invalid hash");
    let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
    let n_inputs = U256::from(1);

    let provider = ws_connect(&anvil.ws_endpoint(), SK[9]).await;
    let contract = FakeCoordinator::deploy(
        provider.clone(),
        hash,
        U256::from(t),
        initial_mpc_nodes.clone(),
        n_inputs,
        vec![ACC[5]],
        U256::from(n_nodes),
    )
    .await
    .expect("deployment failed");

    let mut instances = Vec::new();
    for sk in SK.iter().take(n_nodes) {
        let p = ws_connect(&anvil.ws_endpoint(), sk).await;
        instances.push(StoffelCoordinatorInstance::new(*contract.address(), p));
    }

    let mut coords = Vec::new();
    for instance in instances.iter().take(n_nodes) {
        coords.push(OnChainCoordinator::new(instance.clone(), n as u64, 1, 1, None).await);
    }

    let mut rng = test_rng();

    let mut node_rpcs = Vec::new();
    for i in 0..n_nodes {
        let node_rpc = FakeNodeRPCServer::start_from_cert(
            &node_rpc_addrs[i].0,
            node_rpc_addrs[i].1,
            instances[i].clone(),
            certs[i].clone(),
        )
        .await;
        node_rpcs.push(node_rpc);
    }

    let client_provider = ws_connect(&anvil.ws_endpoint(), SK[5]).await;
    let client_instance = StoffelCoordinatorInstance::new(*contract.address(), client_provider);
    let mut client_coord = FakeOnChainCoordinator::new(
        client_instance,
        n as u64,
        t,
        1,
        Some(certs[5].signing_key.serialize_der()),
    )
    .await;
    let rpc_client = FakeNodeRPCClient::start_rpc_client_from_cert(
        n,
        t as usize,
        node_rpc_addrs.clone(),
        certs[5].clone(),
    )
    .await;

    // Round 1
    let ids = sample_ids(n);
    let mask_shares =
        FakeShareType::compute_shares(correct_mask, n, t as usize, Some(&ids), &mut rng).unwrap();
    let output_shares =
        FakeShareType::compute_shares(correct_output, n, t as usize, Some(&ids), &mut rng).unwrap();
    tokio::join!(
        run_node_round(
            &mut coords,
            &mut node_rpcs,
            mask_shares,
            output_shares[..n_nodes].to_vec(),
            ACC[5],
            public_keys[5].clone()
        ),
        run_client_round(
            &mut client_coord,
            &rpc_client,
            ACC[5],
            SK[5],
            correct_mask,
            correct_output
        )
    );

    // Reset: on-chain reset, then update local state on all coordinators and node RPCs
    coords[0].reset_coord().await.unwrap();
    for coord in coords.iter_mut() {
        coord.reset().await.unwrap();
    }
    client_coord.reset().await.unwrap();
    for node_rpc in node_rpcs.iter_mut() {
        node_rpc.reset().await;
    }

    // Round 2
    let ids = sample_ids(n);
    let mask_shares2 =
        FakeShareType::compute_shares(correct_mask, n, t as usize, Some(&ids), &mut rng).unwrap();
    let output_shares2 =
        FakeShareType::compute_shares(correct_output, n, t as usize, Some(&ids), &mut rng).unwrap();
    tokio::join!(
        run_node_round(
            &mut coords,
            &mut node_rpcs,
            mask_shares2,
            output_shares2[..n_nodes].to_vec(),
            ACC[5],
            public_keys[5].clone()
        ),
        run_client_round(
            &mut client_coord,
            &rpc_client,
            ACC[5],
            SK[5],
            correct_mask,
            correct_output
        )
    );
}
