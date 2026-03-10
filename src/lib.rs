pub mod self_signed_certs;
pub mod rpc;
pub mod on_chain;
pub mod off_chain;

use std::future::Future;
use ark_bls12_381::Fr;
use thiserror::Error;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use std::sync::Once;

pub trait Coordinator {
    type ClientIdentity;

    fn trigger_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn init_input_masks(&mut self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_pp(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_input_mask_init(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn obtain_mask_indices(&mut self, n_indices: u64) -> impl Future<Output = Result<Vec<u64>, CoordinatorError>>;
    fn send_masked_input(&self, masked_input: Fr, i: u64) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_inputs(&self, n_clients: u64, mask_shares: Vec<RobustShare<Fr>>) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<RobustShare<Fr>>>, CoordinatorError>>;
    fn trigger_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn trigger_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_outputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn wait_for_indices(&self, n_clients: u64) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, u64>, CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<Fr>, CoordinatorError>>;
    fn send_output_shares(&self, client_id: Self::ClientIdentity, key: Vec<u8>, output_shares: Vec<RobustShare<Fr>>) -> impl Future<Output = Result<(), CoordinatorError>>;
}

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorError {
    #[error("The index {0:?} is already reserved.")]
    IndexAlreadyReserved(usize),
    #[error("The masked input for index {0:?} has already been sent.")]
    MaskedInputAlreadySent(usize),
    #[error("Mask reconstruction from {0:?} shares failed.")]
    MaskReconstructionFailed(usize),
    #[error("Interaction with Ethereum blockchain failed: {0}")]
    EthereumError(String),
    #[error("U256 value out of range for Fr")]
    U256ToFrError,
    #[error("U256 value out of range for u64")]
    U256ToU64Error,
    #[error("U64 value out of range for usize")]
    U64ToUsizeError,
    #[error("Parsing DER-encoded key as PKCS#8 failed")]
    ParsingDERAsPKCS8Failed,
    #[error("Parsing private key failed")]
    ParsingPrivateKeyFailed,
    #[error("Deserialization failed")]
    DeserializationError,
    #[error("Serialization failed")]
    SerializationError,
    #[error("Parsing public key failed")]
    ParsingPublicKeyFailed,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("JSON error: {0}")]
    JSONError(String),
    #[error("Subscription error: {0}")]
    SubscriptionError(String),
    #[error("Parsing an encapsulated key failed")]
    ParsingEncapsulatedKeyFailed
}

#[derive(Error, Clone, Debug)]
pub enum NodeRPCError {
    #[error("Index already added")]
    IndexAlreadyAdded,
    #[error("JSON error")]
    JSONError,
    #[error("Serialization error")]
    SerializationError,
}

static INIT: Once = Once::new();
pub fn setup_test() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}
