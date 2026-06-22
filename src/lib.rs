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

/// The on-chain coordinator.
#[cfg(feature = "on-chain")]
pub mod on_chain;

/// The off-chain coordinator.
#[cfg(feature = "off-chain")]
pub mod off_chain;

/// Things for testing the coordinator when deployed, using Docker, for example.
/// This goes one step further towards actual deployment than the unit tests or the integration
/// tests in `tests/`.
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

/// Bundles the constraints that the coordinator places on a share type.
///
/// Any share type that the coordinator operates on must satisfy these bounds:
///
/// * `SecretSharingScheme<F>`: the type is a secret share over `F` and exposes secret
///   reconstruction (`recover_secret`) and share generation (`compute_shares`).
/// * `CanonicalSerialize` / `CanonicalDeserialize`: shares are sent over JSON-RPC as
///   compressed bytes, so they must be (de-)serializable via `ark-serialize`.
/// * `Clone`, `Send`, `'static`: required for sharing across async tasks and Tokio threads.
///
/// The associated type `ValueType` is the plaintext type that the share scheme
/// produces upon reconstruction — typically the field element type `F` itself.
///
/// # Input masking
///
/// The key operation that differs between share types is `compute_masked_input`.
/// During the input-collection phase an MPC client sends a masked input `x + m` (where `x` is the
/// private input and `m` is the preprocessing mask), and each MPC node holds a share `m_i` of
/// the mask `m`. The node turns the client's masked input into a share of the *unmasked* input by
/// computing `(x + m) - m_i`, i.e. a share of `x`. Share types differ in how the represented
/// values are stored, so this step is implemented differently.
///
/// # Adding a new share type
///
/// Implement this trait for the new share type and make sure the `compute_masked_input` method
/// correctly subtracts the mask share from the masked input while carrying over any per-share
/// metadata.
pub trait ShareBound<F: FftField>:
    SecretSharingScheme<F, SecretType = Self::ValueType>
    + CanonicalSerialize
    + CanonicalDeserialize
    + Clone
    + Send
    + 'static
{
    /// The plaintext type reconstructed from shares — typically the field element `F`.
    /// Essentially `SecretType` from `SecretSharingScheme`, but with more trait bounds.
    type ValueType: CanonicalSerialize + CanonicalDeserialize + Clone + Send;

    /// Given a masked input `input = x + m` and this node's share `mask_share` of the mask `m`,
    /// computes a share of the unmasked input `x`.
    ///
    /// The result is a share of `x = input - m`, constructed by subtracting the share's field
    /// value from `input`. All share metadata (ID, degree, and for Feldman shares the commitment
    /// vector) is copied from `mask_share`.
    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError>;

    /// Returns the minimum number of shares required to reconstruct a secret given threshold `t`.
    fn min_shares(t: usize) -> usize;
}

/// `ShareBound` implementation for plain HoneyBadger MPC shares.
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

/// The rounds that the execution of an instance traverses.
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

/// Returns the round before `current`.
fn round_before(current: Round) -> Option<Round> {
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

/// The interface to the coordinator that MPC clients and MPC nodes interact with.
///
/// Both the on-chain (`on_chain::OnChainCoordinator`) and off-chain
/// (`off_chain::OffChainCoordinatorClient`) coordinators implement this trait. Concrete
/// implementations may expose additional methods beyond what is defined here.
///
/// The type parameter `S: ShareBound<F>` determines the share type used throughout the protocol.
/// Changing `S` (e.g. from `RobustShare` to `FeldmanShamirShare`) transparently switches the
/// serialisation format of shares sent over the wire and the masking computation performed on
/// MPC nodes — no changes to the coordinator logic are required.
pub trait Coordinator<F: FftField, S: ShareBound<F>> {
    type ClientIdentity;

    fn start_preprocessing(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn reserve_input_masks(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn collect_inputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn start_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn send_output(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Blocking-waits for round `round` to be triggered.
    fn wait_for_round(&self, round: Round) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Used by MPC clients to obtain the index `i`.
    fn reserve_mask_index(&mut self, i: u64) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Used by MPC clients to send their masked input `masked_input` for the previously reserved index `i` via
    /// `obtain_mask_indices`.
    fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Used by MPC nodes to wait for masked inputs by `n_inputs`.
    /// For a masked input at index `i`, the node knows a mask share `mask_shares[i]` and by
    /// subtracting `mask_shares[i]` from the masked input, the node obtains a share of the unmasked input.
    /// These shares of unmasked inputs are returned, along with the clients that have supplied them.
    /// `mask_shares` is indexed by the reserved mask indices. When a client reserves multiple
    /// indices, its returned shares are ordered by the reserved index.
    fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<S>>, CoordinatorError>>;

    /// Used by MPC nodes to wait for indices to be reserved by `n_inputs`. Once reserved, the
    /// indices and the reserving clients are returned.
    fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<u64>>, CoordinatorError>>;

    /// Called by MPC clients to obtain the private outputs for that client.
    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<S::ValueType>, CoordinatorError>>;

    /// Called by MPC nodes to send the encrypted output shares `output_shares` for a client, which
    /// the coordinator knows under the identity `client_id`. The shares are encrypted under the
    /// public key `key`.
    fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Called by the designated party to reset the coordinator, so the program can be
    /// executed again again.
    fn reset_coord(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
}

/// Errors returned by the coordinator interface. Some are specific to whether the coordinator is
/// on- or off-chain.
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

/// Initializes the cryptography environment for tests.
pub fn setup_test() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}
