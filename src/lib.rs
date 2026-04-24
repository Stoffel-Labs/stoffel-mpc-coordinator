// This is the coordinator library's entry point.

/// Self-signed certificates used for tests.
pub mod self_signed_certs;

/// TODO
pub mod rpc;

/// The on-chain coordinator. Gated behind the `on-chain` feature so
/// downstream consumers that only need the off-chain surface can opt
/// out of the Solidity + alloy dep tree.
#[cfg(feature = "on-chain")]
pub mod on_chain;

/// The off-chain coordinator.
pub mod off_chain;

use ark_ff::FftField;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Once;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use thiserror::Error;

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
/// While these functions are implemented for both on- and off-chain coordinators, the concrete
/// coordinators may provided extended functionality.
pub trait Coordinator<F: FftField> {
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
        masked_input: F,
        i: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Used by MPC nodes to wait for masked inputs by `n_clients`. TODO: this is hardcoded to one input per client!
    /// For a masked input at index `i`, the node knows a mask share `mask_shares[i]` and by
    /// subtracting `mask_shares[i]` from the masked input, the node obtains a share of the unmasked input.
    /// These shares of unmasked inputs are returned, along with the clients that have supplied them.
    /// `mask_shares` is indexed by the reserved mask indices. The returned vector of shares for a
    /// given client is indexed by TODO: should be indexed by sth like input IDs, but we currently
    /// do not have that.
    fn wait_for_inputs(
        &self,
        n_clients: u64,
        mask_shares: Vec<RobustShare<F>>,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<RobustShare<F>>>, CoordinatorError>>;

    /// Used by MPC nodes to wait for indices to be reserved by `n_clients`. Once reserved, the
    /// indices and the reserving clients are returned.
    fn wait_for_indices(
        &self,
        n_clients: u64,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<u64>>, CoordinatorError>>;

    /// Called by MPC clients to obtain the private outputs for that client.
    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<F>, CoordinatorError>>;

    /// Called by MPC nodes to send the encrypted output shares `output_shares` for a client, which
    /// the coordinator knows under the identity `client_id`. The shares are encrypted under the
    /// public key `key`.
    fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<RobustShare<F>>,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Called by the designated party to reset the coordinator, so another program can be
    /// executed.
    fn reset_coord(
        &self,
        prog_hash: [u8; 32],
        t: u64,
        initial_mpc_nodes: Vec<Self::ClientIdentity>,
        n_inputs: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Called by an MPC party to publish a raw byte output for this computation.
    ///
    /// Unlike [`Coordinator::send_output_shares`], which carries encrypted
    /// shares keyed by client identity, this method carries a single
    /// plaintext byte payload indexed by `party_id`. It exists to support
    /// protocols (notably ADKG) whose output is a group element rather
    /// than a vector of scalar field elements — and so does not fit
    /// [`Coordinator::obtain_outputs`]'s `Vec<F>` shape.
    ///
    /// The default impl returns [`CoordinatorError::NotImplemented`]; concrete
    /// coordinators extend it with a real RPC round-trip when they need
    /// to support raw-byte outputs.
    fn submit_raw_output(
        &self,
        _party_id: usize,
        _bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), CoordinatorError>> {
        async {
            Err(CoordinatorError::NotImplemented(
                "submit_raw_output is not implemented for this coordinator".into(),
            ))
        }
    }

    /// Collect the raw byte outputs previously published via
    /// [`Coordinator::submit_raw_output`], indexed by party.
    ///
    /// Returns one entry per party in ascending `party_id` order; for
    /// protocols where every party publishes the same value (e.g. the
    /// aggregate public key at the end of ADKG) the caller asserts that
    /// all entries are byte-identical before consuming the first.
    ///
    /// The default impl returns [`CoordinatorError::NotImplemented`].
    fn obtain_raw_outputs(&self) -> impl Future<Output = Result<Vec<Vec<u8>>, CoordinatorError>> {
        async {
            Err(CoordinatorError::NotImplemented(
                "obtain_raw_outputs is not implemented for this coordinator".into(),
            ))
        }
    }
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
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

#[derive(Error, Clone, Debug)]
pub enum NodeRPCError {
    #[error("Index already added")]
    IndexAlreadyAdded,
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
