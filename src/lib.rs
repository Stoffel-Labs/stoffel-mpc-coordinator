use std::future::Future;
use ark_bls12_381::Fr;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use jsonrpsee::core::ClientError;

pub trait Coordinator {
    fn trigger_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn init_input_masks(&mut self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input_mask_init(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn obtain_mask_indices(&mut self, n_indices: usize) -> impl Future<Output = Result<Vec<usize>, CoordinatorError>>;
    fn send_masked_input(&self, masked_input: Fr, i: usize) -> impl Future<Output = Result<(), CoordinatorError>>;
    //fn wait_for_masked_inputs(&self, n_clients: usize) -> impl Future<Output = Result<HashMap<usize, Vec<Fr>>, CoordinatorError>>;
    fn trigger_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
   // fn wait_for_indices(&self, n_clients: usize) -> impl Future<Output = Result<HashMap<usize, usize>, CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
}

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorError {
    #[error("The index {0:?} is already reserved.")]
    IndexAlreadyReserved(usize),
    #[error("The masked input for index {0:?} has already been sent.")]
    MaskedInputAlreadySent(usize),
}

pub mod on_chain {
    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, BigInteger};
    use stoffelnet::network_utils::{ClientId};
    use alloy::{
        sol_types::SolValue,
        providers::{Provider, ProviderBuilder, WsConnect},
        signers::local::PrivateKeySigner,
        network::EthereumWallet,
        signers::Signer
    };
    use alloy_primitives::{U256, Address, Signature, Bytes, Keccak256};
    use stoffel_solidity_bindings::{
        fake_coordinator::FakeCoordinator::{InputMaskReservationStarted, MaskedInputEvent, ReservedInputEvent},
        fake_coordinator::FakeCoordinator::FakeCoordinatorInstance,
        fake_coordinator::FakeCoordinator
    };
    use futures_util::stream::StreamExt;
    use serde::{Serialize, Deserialize};
    use std::collections::HashMap;
    use super::{Coordinator, CoordinatorError};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ClientSig {
        pub client_id: ClientId,
        pub i: U256,
        pub sig: Vec<u8>,
    }
    
    
    #[derive(Clone)]
    pub struct OnChainCoordinator<P: Provider> {
        coord: FakeCoordinatorInstance<P>,
        contract_block: u64,
        initial_mpc_nodes: Vec<Address>
    }
    
    fn u256_to_u64(x: U256) -> Option<u64> {
        match x.try_into() {
            Ok(n) => Some(n),
            Err(_) => None
        }
    }

    // lossless: Fr elements always fit into 256 bits
    fn fr_to_u256(x: Fr) -> U256 {
        let bytes = x.into_bigint().to_bytes_le();
        U256::from_le_slice(&bytes)
    }
    
    fn u256_to_fr(x: U256) -> Option<Fr> {
        let r = {
            let r = <Fr as PrimeField>::MODULUS;
            let r_bytes = r.to_bytes_le();
            U256::from_le_slice(&r_bytes)
        };
    
        if x >= r {
            return None;
        }
    
        let bytes = x.to_le_bytes::<32>();
        Some(Fr::from_le_bytes_mod_order(&bytes))
    }
    
    pub async fn generate_client_sig(i: U256, signer: PrivateKeySigner) -> Signature {
        let hash = {
            let mut hasher = Keccak256::new();
            hasher.update(i.abi_encode());
            hasher.finalize()
        };
        signer.sign_message(hash.as_slice()).await.expect("signing failed")
    }
    
    pub async fn setup_node(addr: String, wallet_sk: PrivateKeySigner) -> impl Provider + Clone {
        let ws = WsConnect::new(addr.clone());
        let wallet = EthereumWallet::from(wallet_sk);

        match ProviderBuilder::new().wallet(wallet).connect_ws(ws).await {
            Ok(p) => { p }
            Err(e) => {
                panic!("could not connect to Ethereum node at {} via WebSockets: {}", addr.clone(), e);
            }
        }
    }
    
    pub async fn setup_mock_coord(eth: impl Provider + Clone, contract_addr: Address, initial_mpc_nodes: Vec<Address>) -> OnChainCoordinator<impl Provider + Clone> {
        let coord_instance = FakeCoordinator::new(contract_addr, eth.clone());
        OnChainCoordinator::new(coord_instance, initial_mpc_nodes).await
    }
    
    impl<P: Provider> OnChainCoordinator<P> {
        pub async fn new(coord: FakeCoordinatorInstance<P>, initial_mpc_nodes: Vec<Address>) -> Self {
            let contract_block = Self::coord_creation_block(&coord).await;
            Self { coord, contract_block, initial_mpc_nodes }
        }
    
        async fn coord_creation_block(coord: &FakeCoordinatorInstance<P>) -> u64 {
                let x = coord.creationBlock().call().await.expect("sending TX failed");
                u256_to_u64(x).expect("impossible bug: block number does not fit into u64")
        }
    
        pub async fn verify_client_sig(&self, client_sig: ClientSig) -> Option<Address> {
            let hash = {
                let mut hasher = Keccak256::new();
                hasher.update(client_sig.i.abi_encode());
                hasher.finalize()
            };
            let sig = Signature::try_from(client_sig.sig.as_slice()).expect("invalid sig");
            let addr = sig.recover_address_from_msg(hash).expect("recovery failed");
        
            if self.coord.authenticateClient(client_sig.i, addr, Bytes::from(client_sig.sig))
                .call().await.expect("sending TX failed") {
                    Some(addr)
            } else {
                None
            }
        }

        pub async fn grant_roles(&self) -> Result<(), CoordinatorError> {
            assert!(self.initial_mpc_nodes.len() == 5);
        
            let PARTY_ROLE = {
                let builder = self.coord.PARTY_ROLE();
                builder.call().await.expect("sending TX failed")
            };
            let DESIGNATED_PARTY_ROLE = {
                let builder = self.coord.DESIGNATED_PARTY_ROLE();
                builder.call().await.expect("sending TX failed")
            };
        
            // grant party roles
            for i in 0..self.initial_mpc_nodes.len() {
                let builder = self.coord.grantRole(PARTY_ROLE, self.initial_mpc_nodes[i]);
                let result = builder.send().await;
                match result {
                    Ok(r) => {
                        r.watch().await.expect("TX failed");
                    }
                    Err(e) => {
                        panic!();
                    }
                }
                builder.send().await.expect("sending TX failed").watch().await.expect("TX failed");
                println!("Granted party role to {}", self.initial_mpc_nodes[i]);
            }

            Ok(())
        }
    
        pub async fn wait_for_indices(&self, n_clients: usize) -> Result<HashMap<Address, U256>, CoordinatorError> {
            let mut addr_to_i: HashMap<Address, U256> = HashMap::new();
            
            // spawn thread to receive all ReservedInputEvents
            let mut events = self.coord
                .ReservedInputEvent_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
            
            while let Some(Ok((ReservedInputEvent { client, reservedIndex }, _))) = events.next().await {
                addr_to_i.insert(client, reservedIndex);
                eprintln!("[party] Recorded reserved mask index {} for client address {:?}",
                         reservedIndex, client);
                if addr_to_i.len() == n_clients {
                    break;
                }
            }
    
            Ok(addr_to_i)
        }

        pub async fn wait_for_masked_inputs(&self, n_clients: usize) -> Result<HashMap<Address, Vec<Fr>>, CoordinatorError> {
            let mut events = self.coord
                .MaskedInputEvent_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            let mut masked_inputs: HashMap<Address, Vec<Fr>> = HashMap::new();
            for _ in 0..n_clients {
                if let Some(Ok((MaskedInputEvent { client, maskedInput, reservedIndex }, _))) = events.next().await {
                    let masked_input = match u256_to_fr(maskedInput) {
                        Some(v) => v,
                        None => {
                            panic!();
                        }
                    };
                    masked_inputs.insert(client, vec![masked_input]);
                } else {
                    panic!();
                }
            }
            Ok(masked_inputs)
        }
    }
    
    impl<P: Provider> Coordinator for OnChainCoordinator<P> {
        async fn trigger_input(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.collectInputs();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    let err = e.as_decoded_error::<FakeCoordinator::NotAtRound>().unwrap();
                    println!("{:?}", err);
                    panic!();
                }
            }
        }
        
        async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .InputMaskReservationStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.startPreprocessing();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    let err = e.as_decoded_error::<FakeCoordinator::NotAnExistingParty>().unwrap();
                    println!("No such account {}", err.account);
                    panic!();
                }
            }
        }
        
        async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .PreprocessingStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
            let builder = self.coord.reserveInputMasks();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    panic!();
                    //let err = e.as_decoded_error::<FakeCoordinator::NotAnExistingParty>().unwrap();
                    //println!("No such account {}", err.account);
                }
            }
        }
        
        async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .InputMaskReservationStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((InputMaskReservationStarted { executor, timeOfExecution }, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn obtain_mask_indices(&mut self, n_indices: usize) -> Result<Vec<usize>, CoordinatorError> {
            let indices = {
                let indices = self.coord.obtainInputMasks(fr_to_u256(Fr::from(n_indices as u128))).call().await.expect("sending TX failed");
                indices.iter().map(|index| u256_to_u64(*index).unwrap() as usize).collect()
            };

            Ok(indices)
        }
        
        async fn send_masked_input(&self, masked_input: Fr, i: usize) -> Result<(), CoordinatorError> {
            let builder = self.coord.submitMaskedInput(fr_to_u256(masked_input), fr_to_u256(Fr::from(i as u128)));
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    panic!();
                }
            }
        }
        
        async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.startMPC();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(e) => {
                    panic!();
                }
            }
        }
        
        async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .MPCStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }
        
        async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.sendOutputs();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(_) => {
                    panic!();
                }
            }
        }
        
        async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
            let mut events = self.coord
                .OutputSendingStarted_filter()
                .from_block(self.contract_block)
                .watch()
                .await.unwrap().into_stream();
        
            if let Some(Ok((_, _))) = events.next().await {
                Ok(())
            } else {
                panic!();
            }
        }

        async fn finalize(&self) -> Result<(), CoordinatorError> {
            let builder = self.coord.finalize();
            let result = builder.send().await;
            match result {
                Ok(r) => {
                    r.watch().await.expect("TX failed");
                    Ok(())
                }
                Err(_) => {
                    panic!();
                }
            }
        }
    }
    
    #[cfg(test)]
    mod tests {
        use super::*;
        use alloy::signers::local::PrivateKeySigner;
        use ark_bls12_381::Fr;
        use alloy::{
            node_bindings::{Anvil, AnvilInstance},
            providers::{Provider, ProviderBuilder, WsConnect},
            network::EthereumWallet,
        };
        use alloy_primitives::{Address, U256, FixedBytes, address};
        use std::str::FromStr;
        use stoffel_solidity_bindings::{
            fake_coordinator::FakeCoordinator,
        };
        use tokio::time::{timeout, Duration};
        use rand::Rng;
    
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
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
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
            address!("0xa0Ee7A142d267C1f36714E4a8F75612F20a79720")
        ];
    
        fn spawn_anvil() -> AnvilInstance {
            Anvil::new().spawn()
        }
        
        async fn ws_connect(ws_addr: &str, key: &str) -> impl Provider + Clone {
            let ws = WsConnect::new(ws_addr);
            let wallet = EthereumWallet::from(PrivateKeySigner::from_str(key).expect("invalid private key"));
        
            ProviderBuilder::new()
                .wallet(wallet)
                .connect_ws(ws).await.expect("could not connect to Anvil via WebSockets")
        }
    
        #[tokio::test]
        pub async fn sig_gen_onchain() {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            let n = U256::from(5);
            let t = U256::from(1);
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
            let coord = OnChainCoordinator::new(coord_instance, initial_mpc_nodes).await;
    
            let sk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let signer = PrivateKeySigner::from_str(sk).unwrap();
            let i = U256::from(42u64);
    
            // Generate signature
            let sig = generate_client_sig(i, signer.clone()).await;
    
            let client_sig = ClientSig {
                client_id: 1,
                i,
                sig: sig.as_bytes().to_vec(),
            };
    
            match coord.verify_client_sig(client_sig).await {
                Some(addr) => {
                    let expected_addr = signer.address();
                    assert_eq!(addr, expected_addr);
                }
                None => {
                    panic!("signature verification failed");
                }
            }
        }
    
        #[test]
        pub fn fr_u256_conversion() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let n: u64 = rng.random();
                let fr = Fr::from(n);
                let u = fr_to_u256(fr);
                let fr2 = u256_to_fr(u);
                assert!(fr2.is_some());
                assert_eq!(fr, fr2.unwrap());
            }
        }
    
        #[test]
        pub fn u64_u256_conversion() {
            let mut rng = rand::rng();
            for _ in 0..100 {
                let n1: u64 = rng.random();
                let n1_u256 = U256::from(n1);
                let n2 = u256_to_u64(n1_u256);
                assert!(n2.is_some());
                assert_eq!(n1, n2.unwrap());
            }
        }

        #[tokio::test]
        pub async fn coord_creation_block() {
            let anvil = spawn_anvil();
            let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
            let n = U256::from(5);
            let t = U256::from(1);
            let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
            let designated_party = ACC[0];
            let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
            let n_inputs = U256::from(1);
    
            let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
            let coord = OnChainCoordinator::new(coord_instance, initial_mpc_nodes).await;
            assert_eq!(coord.contract_block, 1);
        }
    
        #[tokio::test]
        pub async fn event_listening() {
            // event triggered BEFORE waiting for the event
            {
                let anvil = spawn_anvil();
                let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
                let n = U256::from(5);
                let t = U256::from(1);
                let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
                let designated_party = ACC[0];
                let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
                let n_inputs = U256::from(1);
    
                let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
                let coord = OnChainCoordinator::new(coord_instance, initial_mpc_nodes).await;
    
                coord.trigger_pp().await;
                coord.wait_for_pp().await;
            }
    
            // event triggered AFTER waiting for the event
            {
                let anvil = spawn_anvil();
                let provider = ws_connect(&anvil.ws_endpoint(), SK[0]).await;
                let n = U256::from(5);
                let t = U256::from(1);
                let hash = FixedBytes::from_str("0000000000000000000000000000000000000000000000000000000000000000").expect("invalid hash");
                let designated_party = ACC[0];
                let initial_mpc_nodes: Vec<Address> = ACC[0..5].to_vec();
                let n_inputs = U256::from(1);
    
                let coord_instance = FakeCoordinator::deploy(provider.clone(), hash, n, t, designated_party, initial_mpc_nodes.clone(), n_inputs).await.expect("deployment failed");
                let coord = OnChainCoordinator::new(coord_instance, initial_mpc_nodes).await;
    
                tokio::spawn({
                    let coord = coord.clone();
                    async move {
                        if timeout(Duration::from_millis(500), coord.wait_for_pp()).await.is_err() {
                            panic!();
                        }
                    }
                });
                    
                coord.trigger_pp().await;
            }
        }
    }
}

pub mod off_chain {
    use ark_bls12_381::Fr;
    use ark_ff::FftField;
    use jsonrpsee::{core::{SubscriptionResult, RpcResult, to_json_raw_value}, proc_macros::rpc, PendingSubscriptionSink, SubscriptionSink, server::{ServerHandle, ServerBuilder}, ws_client::*};
    use crate::{Coordinator, CoordinatorError};
    use events::*;
    use serde::{Serializer, Deserializer, Deserialize, Serialize};
    use ark_serialize::{Compress, Validate};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex;
    use async_trait::async_trait;

    #[derive(Clone, Debug)]
    pub struct FieldElement<T: FftField> {
        value: T
    }

    impl<'d, T: FftField> Deserialize<'d> for FieldElement<T> {
        fn deserialize<D>(deserializer: D) -> Result<FieldElement<T>, D::Error>
        where
            D: Deserializer<'d>
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            T::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
                .map(|value| FieldElement::<T> { value }).map_err(serde::de::Error::custom)
        }
    }

    impl<T: FftField> Serialize for FieldElement<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = Vec::new();
            self.value.serialize_with_mode(&mut bytes, Compress::Yes)
                .map_err(serde::ser::Error::custom)?;
            
            serializer.serialize_bytes(&bytes)
        }
    }

    pub mod events {
        use ark_bls12_381::Fr;
        use serde::{Serialize, Deserialize};
        use super::FieldElement;
        use downcast_rs::{Downcast, impl_downcast};
        use dyn_clone::{DynClone, clone_trait_object};
    //    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    //    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    //    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    //    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    //    event CoordinatorInitialized(address coordinator, uint256 timeofInitialization, uint256 creationBlock, address designatedParty);
    //    event InitializeStoffelAccessControl(uint256 nParties, uint256 t, address initializer);

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ExecutionDone {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct IndexBufferEvent {
            pub total_indices: usize,
            pub designated_party: usize
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct InputCollectionStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct InputMaskReservationStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct MPCStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct MaskedInputEvent {
            pub client: usize,
            pub masked_input: FieldElement<Fr>,
            pub reserved_index: usize
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct OutputSendingStarted {
            //address executor
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct OutputsPublished {
            //bytes32 stoffelProgramHash
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct PreprocessingStarted {
            pub designated_party: usize
            //uint256 timeOfExecution
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ReservedInputEvent {
            pub client: usize,
            pub reserved_index: usize
        }
    
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ClientInputMaskReservationEvent {
            //address executor;
            //uint256 timeOfExecution
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct ClientOutputCollection {
            //address executor
            //uint256 timeOfExecution
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct CoordinatorInitialized {
            //address coordinator
            //uint256 timeofInitialization;
            pub creation_block: u64,
            pub designated_party: usize
        }
        
        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct PreprocessingRoundExecuted {
            //address designatedParty
            //uint256 timeOfExecution
        }

        pub trait TransitionEvent : Downcast + DynClone + Send { }
        impl_downcast!(TransitionEvent);
        clone_trait_object!(TransitionEvent);
    
        impl TransitionEvent for ExecutionDone { }
        impl TransitionEvent for InputCollectionStarted { }
        impl TransitionEvent for InputMaskReservationStarted { }
        impl TransitionEvent for MPCStarted { }
        impl TransitionEvent for OutputSendingStarted { }
        impl TransitionEvent for PreprocessingStarted { }
        impl TransitionEvent for CoordinatorInitialized { }
    }
    
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub enum Round {
        Idle,
        Preprocessing,
        InputMaskReservation,
        InputCollection,
        MPC,
        Output
    }
    
    #[rpc(server, client)]
    pub trait CoordinatorRPC {
    //        function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
    //        function DESIGNATED_PARTY_ROLE() external view returns (bytes32);
    //        function PARTY_ROLE() external view returns (bytes32);
    // function creationTime() external view returns (uint256);
    // function getRoleAdmin(bytes32 role) external view returns (bytes32);
    // function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    // function getRoleMemberCount(bytes32 role) external view returns (uint256);
    // function getRoleMembers(bytes32 role) external view returns (address[] memory);
    // function grantRole(bytes32 role, address account) external;
    // function hasRole(bytes32 role, address account) external view returns (bool);
    // function isDesignatedParty(address account) external view returns (bool);
    // function isParty(address account) external view returns (bool);
    // function owner() external view returns (address);
    // function renounceOwnership() external;
    // function renounceRole(bytes32 role, address account) external;
    // function resetAccessControl(uint256 t, address[] memory initialMPCNodes) external;
    // function resetInputManager(uint256 nIndicesToReserve) external;
    // function revokeRole(bytes32 role, address account) external;
    // function round() external view returns (StoffelCoordinator.Round);
    // function setPublicOutputs(bytes memory publicOutputs) external;
    // function shareReceived(address from, address to) external;
    // function supportsInterface(bytes4 interfaceId) external view returns (bool);
    // function transferOwnership(address newOwner) external;
    // constructor(bytes32 stoffelProgramHash, uint256 n, uint256 t, address designatedParty, address[] initialMPCNodes, uint256 nInputs);
    
        #[subscription(name = "sub_collect_input", unsubscribe = "unsub_collect_inputs", item = InputCollectionStarted)]
        async fn sub_collect_inputs(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "auth_client")]
        async fn auth_client(&self, nonce: u64, client: usize, sig: Vec<u8>) -> RpcResult<bool>;
    
        #[method(name = "available_input_masks")]
        async fn available_input_masks(&self) -> RpcResult<usize>;
    
        #[method(name = "obtain_input_masks")]
        async fn obtain_mask_indices(&self, n_indices: usize, cid: usize) -> RpcResult<Vec<usize>>;

        #[subscription(name = "sub_reserve_input_masks", unsubscribe = "unsub_reserve_input_masks", item = InputMaskReservationStarted)]
        async fn sub_reserve_input_masks(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "reset")]
        async fn reset(&self, prog_hash: [u8; 32], n: usize, t: usize, initial_mpc_nodes: Vec<usize>, n_inputs: usize);
    
        #[subscription(name = "sub_send_outputs", unsubscribe = "unsub_send_outputs", item = OutputSendingStarted)]
        async fn sub_send_outputs(&self, timestamp: u64) -> SubscriptionResult;
    
        #[subscription(name = "sub_start_mpc", unsubscribe = "unsub_start_mpc", item = MPCStarted)]
        async fn sub_start_mpc(&self, timestamp: u64) -> SubscriptionResult;
    
        #[subscription(name = "sub_start_pp", unsubscribe = "unsub_start_pp", item = PreprocessingStarted)]
        async fn sub_start_pp(&self, timestamp: u64) -> SubscriptionResult;
    
        #[method(name = "submit_masked_input")]
        async fn submit_masked_input(&self, masked_input: FieldElement<Fr>, reserved_index: usize, cid: usize) -> RpcResult<()>;

        #[subscription(name = "sub_reserved_indices", unsubscribe = "unsub_reserved_indices", item = ReservedInputEvent)]
        async fn sub_reserved_indices(&self, timestamp: u64) -> SubscriptionResult;

        #[subscription(name = "sub_masked_inputs", unsubscribe = "unsub_masked_inputs", item = MaskedInputEvent)]
        async fn sub_masked_inputs(&self, timestamp: u64) -> SubscriptionResult;

        #[method(name = "transition")]
        async fn transition(&self, cid: usize, next_round: Round) -> RpcResult<()>;
    }

    #[derive(Clone)]
    struct CoordinatorRPCServerImpl(Arc<Mutex<CoordinatorRPCServerImplInternal>>);

    #[derive(Clone)]
    struct CoordinatorRPCServerImplInternal {
        // contains the sinks of clients, which subscribed to the transition to the given round
        sinks: HashMap<Round, Vec<SubscriptionSink>>,
        trans_events: HashMap<Round, Vec<(u64, Box<dyn TransitionEvent>)>>,
        reserved_index_events: Vec<(u64, ReservedInputEvent)>,
        reserved_index_sinks: Vec<SubscriptionSink>,
        masked_input_events: Vec<(u64, MaskedInputEvent)>,
        masked_input_sinks: Vec<SubscriptionSink>,
        next_i: usize,
        reserved_indices: Vec<Option<usize>>,
        input_masks: Vec<Option<Fr>>,
        round: Round,
        prog_hash: [u8; 32],
        n: usize,
        t: usize,
        mpc_nodes: Option<Vec<usize>>,
    }

    impl CoordinatorRPCServerImplInternal {
        async fn subscribe_oneshot<E: TransitionEvent + Serialize>(&mut self, pending: PendingSubscriptionSink, timestamp: u64, round: Round) -> SubscriptionResult {
            let sink = pending.accept().await?;

            {
                let events = &self.trans_events[&round];
                let index = events.partition_point(|e| e.0 < timestamp);

                // check if there is an event since the coordinator was reset the last time
                if index != events.len() {
                    let event = *events[index].1.clone().downcast::<E>().map_err(|_| "BUG: Downcasting failed").unwrap();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();

                    return Ok(());
                }
            }


            self.sinks.get_mut(&round).expect(&format!("BUG: {:?} must be present!", round)).push(sink);
            Ok(())
        }

        async fn subscribe_reserved_indices(&mut self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let sink = pending.accept().await?;

            let events = &self.reserved_index_events;
            let index = events.partition_point(|e| e.0 < timestamp);

            // check if there are events since the coordinator was reset the last time
            if index != events.len() {
                // send all such events
                for i in index..events.len() {
                    let event = events[i].1.clone();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                return Ok(());
            }

            self.reserved_index_sinks.push(sink);
            Ok(())
        }

        async fn subscribe_masked_inputs(&mut self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let sink = pending.accept().await?;

            let events = &self.masked_input_events;
            let index = events.partition_point(|e| e.0 < timestamp);

            // check if there are events since the coordinator was reset the last time
            if index != events.len() {
                // send all such events
                for i in index..events.len() {
                    let event = events[i].1.clone();
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                return Ok(());
            }

            self.masked_input_sinks.push(sink);
            Ok(())
        }

        async fn transition<E: TransitionEvent + Serialize>(&mut self, event: E, round: Round) -> Result<(), CoordinatorError> {
            if self.round != round_before(round) {
                panic!();
            }

            let sinks = self.sinks.get_mut(&round).expect(&format!("BUG: {:?} must be present!", round));

            // broadcast event to all subscribed RPC clients
            for sink in sinks.iter() {
                let json = to_json_raw_value(&event).expect("failed convert to JSON");
                sink.send(json).await.unwrap();
            }

            // clear all subscribed RPC clients
            sinks.clear();

            // add event to event history
            self.trans_events
                .get_mut(&round)
                .expect(&format!("BUG: {:?} must be present!", round))
                .push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), Box::new(event)));

            self.round = round;

            Ok(())
        }
    }

    impl CoordinatorRPCServerImpl {
        pub fn new(prog_hash: [u8; 32], n: usize, t: usize, initial_mpc_nodes: Vec<usize>, n_inputs: usize) -> Self {
            Self(Arc::new(Mutex::new(CoordinatorRPCServerImplInternal {
                sinks: HashMap::from([
                    (Round::Idle, vec![]),
                    (Round::Preprocessing, vec![]),
                    (Round::InputMaskReservation, vec![]),
                    (Round::InputCollection, vec![]),
                    (Round::MPC, vec![]),
                    (Round::Output, vec![])
                ]),
                trans_events: HashMap::from([
                    (Round::Idle, vec![]),
                    (Round::Preprocessing, vec![]),
                    (Round::InputMaskReservation, vec![]),
                    (Round::InputCollection, vec![]),
                    (Round::MPC, vec![]),
                    (Round::Output, vec![])
                ]),
                reserved_index_events: vec![],
                reserved_index_sinks: vec![],
                masked_input_events: vec![],
                masked_input_sinks: vec![],
                next_i: 0,
                reserved_indices: vec![None; n_inputs],
                input_masks: vec![None; n_inputs],
                round: Round::Idle,
                prog_hash,
                n,
                t,
                mpc_nodes: Some(initial_mpc_nodes)
            })))
        }
    }

    fn round_before(current: Round) -> Round {
        match current {
            Round::Idle => Round::Output,
            Round::Preprocessing => Round::Idle,
            Round::InputMaskReservation => Round::Preprocessing,
            Round::InputCollection => Round::InputMaskReservation,
            Round::MPC => Round::InputCollection,
            Round::Output => Round::MPC
        }
    }

    fn next_round(current: Round) -> Round {
        match current {
            Round::Idle => Round::Preprocessing,
            Round::Preprocessing => Round::InputMaskReservation,
            Round::InputMaskReservation => Round::InputCollection,
            Round::InputCollection => Round::MPC,
            Round::MPC => Round::Output,
            Round::Output => Round::Idle
        }
    }

    #[async_trait]
    impl CoordinatorRPCServer for CoordinatorRPCServerImpl {
        async fn sub_collect_inputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            d.subscribe_oneshot::<InputCollectionStarted>(pending, timestamp, Round::InputCollection).await
        }

        async fn auth_client(&self, nonce: u64, client: usize, sig: Vec<u8>) -> RpcResult<bool> {
            Ok(true)
        }

        async fn available_input_masks(&self) -> RpcResult<usize> {
            let d = self.0.lock().await;

            Ok(d.input_masks.len() - d.next_i)
        }

        async fn sub_reserve_input_masks(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            d.subscribe_oneshot::<InputMaskReservationStarted>(pending, timestamp, Round::InputMaskReservation).await
        }

        async fn reset(&self, prog_hash: [u8; 32], n: usize, t: usize, initial_mpc_nodes: Vec<usize>, n_inputs: usize) {
            let mut d = self.0.lock().await;

            if d.round != Round::Idle {
                panic!();
            }

            d.round = Round::Idle;
            d.next_i = 0;
            d.input_masks = vec![None; n_inputs];
            d.reserved_indices = vec![None; n_inputs];
            d.prog_hash = prog_hash;
            d.n = n;
            d.t = t;
            d.mpc_nodes = Some(initial_mpc_nodes);
        }

        async fn sub_send_outputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            d.subscribe_oneshot::<OutputSendingStarted>(pending, timestamp, Round::Output).await
        }

        async fn sub_start_mpc(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            d.subscribe_oneshot::<MPCStarted>(pending, timestamp, Round::MPC).await
        }

        async fn sub_start_pp(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            d.subscribe_oneshot::<PreprocessingStarted>(pending, timestamp, Round::Preprocessing).await
        }

        async fn submit_masked_input(&self, masked_input: FieldElement<Fr>, reserved_index: usize, cid: usize) -> RpcResult<()> {
            let mut d = self.0.lock().await;

            if d.round != Round::InputCollection {
                panic!();
            }

            if reserved_index >= d.input_masks.len() {
                panic!();
            }

            match d.reserved_indices[reserved_index] {
                Some(other_cid) => {
                    if other_cid != cid {
                        panic!();
                    }
                    if d.input_masks[reserved_index].is_some() {
                        panic!();
                    }
                    d.input_masks[reserved_index] = Some(masked_input.value);

                    let event = MaskedInputEvent { client: cid, masked_input, reserved_index };
                    for sink in d.masked_input_sinks.clone().iter() {
                        let json = to_json_raw_value(&event).expect("failed convert to JSON");
                        sink.send(json).await.unwrap();
                    }
                    d.masked_input_events.push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), event));
                }
                None => {
                    panic!();
                }
            }

            Ok(())
        }

        async fn sub_reserved_indices(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            if d.round != Round::InputMaskReservation {
                panic!();
            }

            d.subscribe_reserved_indices(pending, timestamp).await
        }

        async fn sub_masked_inputs(&self, pending: PendingSubscriptionSink, timestamp: u64) -> SubscriptionResult {
            let mut d = self.0.lock().await;

            if d.round != Round::InputCollection {
                panic!();
            }

            d.subscribe_masked_inputs(pending, timestamp).await
        }

        async fn obtain_mask_indices(&self, n_indices: usize, cid: usize) -> RpcResult<Vec<usize>> {
            let mut d = self.0.lock().await;

            if d.round != Round::InputMaskReservation {
                panic!();
            }

            if d.next_i + n_indices > d.input_masks.len() {
                panic!();
            }

            for i in d.next_i..d.next_i + n_indices {
                d.reserved_indices[i] = Some(cid);

                let event = ReservedInputEvent { client: cid, reserved_index: i };

                // broadcast reserved index to all subscribed RPC clients
                for sink in d.reserved_index_sinks.clone().iter() {
                    let json = to_json_raw_value(&event).expect("failed convert to JSON");
                    sink.send(json).await.unwrap();
                }

                d.reserved_index_events.push((SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), event));
            }

            let indices = (d.next_i..(d.next_i + n_indices)).collect();
            d.next_i += n_indices;

            Ok(indices)
        }

        async fn transition(&self, cid: usize, next_round: Round) -> RpcResult<()> {
            let mut d = self.0.lock().await;

            if cid != d.mpc_nodes.clone().expect("BUG: mpc nodes must be set!")[0] {
                panic!();
            }

            match next_round {
                Round::Idle => d.transition(ExecutionDone { }, next_round).await.unwrap(),
                Round::Preprocessing => d.transition(PreprocessingStarted { designated_party: cid }, next_round).await.unwrap(),
                Round::InputMaskReservation => d.transition(InputMaskReservationStarted { }, next_round).await.unwrap(),
                Round::InputCollection => d.transition(InputCollectionStarted { }, next_round).await.unwrap(),
                Round::MPC => d.transition(MPCStarted { }, next_round).await.unwrap(),
                Round::Output => d.transition(OutputSendingStarted { }, next_round).await.unwrap()
            };

            Ok(())
        }
    }

    struct OffChainCoordinator {
        rpc_server: Option<CoordinatorRPCServerImpl>,
        rpc_coord: Option<WsClient>,
        addr: Option<String>,
        server_handle: Option<ServerHandle>,
        timestamp: Option<u64>,
        cid: Option<usize>
    }

    impl OffChainCoordinator {
        pub async fn start_coord(port: u16, prog_hash: [u8; 32], n: usize, t: usize, initial_mpc_nodes: Vec<usize>, n_inputs: usize) -> Self {
            let rpc_server = CoordinatorRPCServerImpl::new(prog_hash, n, t, initial_mpc_nodes.clone(), n_inputs);
            let server = ServerBuilder::default().build(format!("127.0.0.1:{}", port)).await.unwrap();
            let addr = server.local_addr().unwrap();
            let server_handle = server.start(rpc_server.clone().into_rpc());

            Self {
                rpc_server: Some(rpc_server),
                rpc_coord: None,
                addr: Some(format!("ws://{}", addr)),
                server_handle: Some(server_handle),
                timestamp: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
                cid: None
            }
        }

        pub async fn start_client(addr: String, timestamp: u64, cid: usize) -> Self {
            let rpc_coord = Some(WsClientBuilder::default().build(&addr).await.unwrap());

            Self {
                rpc_server: None,
                rpc_coord,
                addr: None,
                server_handle: None,
                timestamp: Some(timestamp),
                cid: Some(cid)
             }
        }

        pub fn get_addr(&self) -> String {
            self.addr.clone().expect("Coordinator server not started")
        }

        pub fn get_timestamp(&self) -> u64 {
            self.timestamp.expect("Coordinator server not started")
        }

        pub async fn wait_for_indices(&self, n_clients: usize) -> Result<HashMap<usize, usize>, CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_reserved_indices(self.get_timestamp()).await.unwrap();

            let mut map = HashMap::new();

            for _ in 0..n_clients {
                let ReservedInputEvent { client, reserved_index } = sub.next().await.unwrap().unwrap();
                map.insert(client, reserved_index);
            }

            Ok(map)
        }

        pub async fn wait_for_masked_inputs(&self, n_clients: usize) -> Result<HashMap<usize, Vec<Fr>>, CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_masked_inputs(self.get_timestamp()).await.unwrap();

            let mut map = HashMap::new();

            for _ in 0..n_clients {
                let MaskedInputEvent { client, masked_input, reserved_index } = sub.next().await.unwrap().unwrap();
                map.insert(client, vec![masked_input.value]);
            }

            Ok(map)
        }
    }
    
    impl Coordinator for OffChainCoordinator {
        async fn trigger_input(&self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::InputCollection).await.unwrap();

            Ok(())
        }

        async fn wait_for_input(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_collect_inputs(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn trigger_pp(&self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::Preprocessing).await.unwrap();

            Ok(())
        }

        async fn wait_for_pp(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_start_pp(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn init_input_masks(&mut self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::InputMaskReservation).await.unwrap();

            Ok(())
        }

        async fn wait_for_input_mask_init(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_reserve_input_masks(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn send_masked_input(&self, masked_input: Fr, i: usize) -> Result<(), CoordinatorError> {
            self.rpc_coord.as_ref().expect("client not started").submit_masked_input(FieldElement { value: masked_input }, i, self.cid.unwrap()).await.unwrap();

            Ok(())
        }


        async fn trigger_mpc(&self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::MPC).await.unwrap();

            Ok(())
        }

        async fn wait_for_mpc(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_start_mpc(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn trigger_outputs(&self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::Output).await.unwrap();

            Ok(())
        }

        async fn wait_for_outputs(&self) -> Result<(), CoordinatorError> {
            let mut sub = self.rpc_coord.as_ref().expect("client not started").sub_send_outputs(self.get_timestamp()).await.unwrap();
            let event = sub.next().await.unwrap().unwrap();

            Ok(())
        }

        async fn obtain_mask_indices(&mut self, n_indices: usize) -> Result<Vec<usize>, CoordinatorError> {
            let indices = self.rpc_coord.as_ref().expect("client not started").obtain_mask_indices(n_indices, self.cid.unwrap()).await.unwrap();

            Ok(indices)
        }

        async fn finalize(&self) -> Result<(), CoordinatorError> {
            let _ = self.rpc_coord.as_ref().expect("client not started").transition(self.cid.unwrap(), Round::Idle).await.unwrap();

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::sync::Barrier;

        #[tokio::test]
        async fn start_client_server() {
            let coord = OffChainCoordinator::start_coord(12345, [0u8; 32], 5, 1, vec![0, 1, 2, 3, 4], 2).await;
            let addr = coord.get_addr();
            let timestamp = coord.get_timestamp();
            let _ = OffChainCoordinator::start_client(addr, timestamp, 0).await;
        }

        #[tokio::test]
        async fn trigger_pp() {
            // event triggered BEFORE waiting for the event
            {
                let coord = OffChainCoordinator::start_coord(12346, [0u8; 32], 5, 1, vec![0, 1, 2, 3, 4], 2).await;
                let addr = coord.get_addr();
                let timestamp = coord.get_timestamp();

                let node0 = OffChainCoordinator::start_client(addr.clone(), timestamp, 0).await;
                let node1 = OffChainCoordinator::start_client(addr, timestamp, 1).await;

                node0.trigger_pp().await.unwrap();

                if tokio::time::timeout(std::time::Duration::from_millis(500), node1.wait_for_pp()).await.is_err() {
                    panic!();
                }
            }

            // event triggered AFTER waiting for the event
            {
                let coord = OffChainCoordinator::start_coord(12347, [0u8; 32], 5, 1, vec![0, 1, 2, 3, 4], 2).await;
                let addr = coord.get_addr();
                let timestamp = coord.get_timestamp();
                let barrier = Arc::new(Barrier::new(2));

                let node0 = OffChainCoordinator::start_client(addr.clone(), timestamp, 0).await;
                let node1 = OffChainCoordinator::start_client(addr.clone(), timestamp, 1).await;

                tokio::spawn({
                    let barrier = barrier.clone();
                    async move {
                        if tokio::time::timeout(std::time::Duration::from_millis(500), node1.wait_for_pp()).await.is_err() {
                            panic!();
                        }
                        barrier.wait().await;
                    }
                });

                node0.trigger_pp().await.unwrap();
                barrier.wait().await;
            }
        }

        #[tokio::test]
        async fn end_to_end() {
            let coord = OffChainCoordinator::start_coord(12348, [0u8; 32], 5, 1, vec![0, 1, 2, 3, 4], 2).await;
            let addr = coord.get_addr();
            let timestamp = coord.get_timestamp();
            let cid: usize = 0;
            let barrier = Arc::new(Barrier::new(3));

            // MPC client, also RPC client
            tokio::spawn({
                let barrier = barrier.clone();
                let mut client = OffChainCoordinator::start_client(addr.clone(), timestamp, cid).await;
                async move {
                    let _ = client.wait_for_pp().await;
                    let _ = client.wait_for_input_mask_init().await;
                    let indices = client.obtain_mask_indices(1).await.unwrap();
                    for i in indices {
                        println!("CLIENT: obtained index {}", i);
                    }
                    let _ = client.wait_for_input().await;
                    client.send_masked_input(Fr::from(42), 0).await.unwrap();
                    client.wait_for_masked_inputs(1).await.unwrap();
                    let _ = client.wait_for_mpc().await;
                    let _ = client.wait_for_outputs().await;

                    barrier.wait().await;
                }
            });

            // MPC node (designated party), also RPC client
            tokio::spawn({
                let barrier = barrier.clone();
                let mut node = OffChainCoordinator::start_client(addr.clone(), timestamp, cid).await;
                async move {
                    node.trigger_pp().await.unwrap();
                    let _ = node.wait_for_pp().await;
                    node.init_input_masks().await.unwrap();
                    let _ = node.wait_for_input_mask_init().await;
                    let client_to_index = node.wait_for_indices(1).await.unwrap();  // called by node
                    for (c, i) in client_to_index {
                        println!("NODE: client {} reserved index {}", c, i);
                    }
                    node.trigger_input().await.unwrap();
                    let _ = node.wait_for_input().await;
                    let client_to_masked_input = node.wait_for_masked_inputs(1).await.unwrap();
                    for (c, masked_inputs) in client_to_masked_input {
                        for masked_input in masked_inputs {
                            println!("NODE: client {} submitted masked input {}", c, masked_input);
                        }
                    }
                    node.trigger_mpc().await.unwrap();
                    let _ = node.wait_for_mpc().await;
                    node.trigger_outputs().await.unwrap();
                    let _ = node.wait_for_outputs().await;
                    node.finalize().await.unwrap();

                    barrier.wait().await;
                }
            });

            barrier.wait().await;
        }

        #[tokio::test]
        async fn auth_client() {
            // TODO
        }
    }
}
