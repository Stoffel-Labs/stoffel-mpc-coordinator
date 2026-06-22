// The coordinator is generic over the share type `S` used to represent shares in the underlying
// MPC protocol. Concretely, `S` must implement `ShareBound`, which is `SecretSharingScheme` from
// mpc-protocols plus some additional bounds to make the code work.
// Every struct and trait in this library that touches shares is parametrized as `<F: FftField, S: ShareBound<F>>`;
// the generic type `F` comes directly from the definition of `SecretSharingScheme`.
//
// Two share types are already contained and can be selected by choosing the concrete `S`
// at coordinator startup:
//
// * **`RobustShare<F>`**: the plain Shamir share used by HoneyBadger MPC.
// * **`FeldmanShamirShare<F, G>`**: a Shamir share augmented with group elements that
// enable verifiable secret sharing.

/// Self-signed certificates used for tests.
pub mod self_signed_certs;

/// Things related to JSON-RPC interfaces.
pub mod rpc;

/// Things for testing the coordinator when deployed, using Docker, for example.
pub mod tests;

use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Once;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::share::ShareError;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use thiserror::Error;

pub trait ShareBound<F: FftField>:
    SecretSharingScheme<F, SecretType = Self::ValueType>
    + CanonicalSerialize
    + CanonicalDeserialize
    + Clone
    + Send
    + 'static
{
    type ValueType: CanonicalSerialize + CanonicalDeserialize + Clone + Send;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError>;

    fn min_shares(t: usize) -> usize;
}

impl<F: FftField> ShareBound<F> for RobustShare<F> {
    type ValueType = Self::SecretType;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError> {
        Ok(RobustShare::new(
            input - mask_share.share[0],
            mask_share.id,
            mask_share.degree,
        ))
    }

    fn min_shares(t: usize) -> usize {
        2 * t + 1
    }
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> ShareBound<F> for FeldmanShamirShare<F, G> {
    type ValueType = Self::SecretType;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError> {
        let neg_mask_share = (mask_share.clone() * (-F::one()))?;
        neg_mask_share + input
    }

    fn min_shares(t: usize) -> usize {
        t + 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Round {
    Idle,
    Preprocessing,
    InputMaskReservation,
    InputCollection,
    MPCExecution,
    OutputDistribution,
    ProgramFinished,
}

pub fn round_before(current: Round) -> Option<Round> {
    match current {
        Round::Idle => None,
        Round::Preprocessing => Some(Round::Idle),
        Round::InputMaskReservation => Some(Round::Preprocessing),
        Round::InputCollection => Some(Round::InputMaskReservation),
        Round::MPCExecution => Some(Round::InputCollection),
        Round::OutputDistribution => Some(Round::MPCExecution),
        Round::ProgramFinished => Some(Round::OutputDistribution),
    }
}

pub trait Coordinator<F: FftField, S: ShareBound<F>> {
    type ClientIdentity;

    fn start_preprocessing(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn reserve_input_masks(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn collect_inputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn start_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn send_output(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn wait_for_round(&self, round: Round) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn reserve_mask_index(&mut self, i: u64) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<S>>, CoordinatorError>>;

    fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<u64>>, CoordinatorError>>;

    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<S::ValueType>, CoordinatorError>>;

    fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn reset_coord(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
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
    ParsingEncapsulatedKeyFailed,
    #[error("Cannot transition to Idle round")]
    CannotTransitionToIdle,
    #[error("Calculating a share failed")]
    ShareError,
    #[error("Failed to bind to address {0}")]
    BindError(String),
    #[error("Failed to connect: {0}")]
    ConnectError(String),
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),
}

#[derive(Error, Clone, Debug)]
pub enum NodeRPCError {
    #[error("Index already added")]
    IndexAlreadyAdded,
    #[error("Index not added")]
    IndexNotAdded,
    #[error("JSON error")]
    JSONError,
    #[error("Serialization error")]
    SerializationError,
    #[error("Ethereum error: {0}")]
    EthereumError(String),
    #[error("Authentication failed for client with TLS identity {0:?}")]
    AuthenticationFailed(Vec<u8>),
}

static INIT: Once = Once::new();

pub fn setup_test() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}
