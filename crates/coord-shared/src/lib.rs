// The coordinator is generic over the share type `S` used to represent shares in the underlying
// MPC protocol. Concretely, `S` must implement `ShareBound`, which is `stoffelcrypto`'s
// `SecretSharingScheme` plus some additional bounds to make the code work.
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

/// Server pins and the certificate-to-key derivation every identity check uses.
pub mod pin;

/// The coordinator's node roster, its digest and its receiver check.
pub mod roster;

/// Client slots, admission policies, invitations and the admission errors.
pub mod admission;

/// Client signatures over masked inputs and node signatures over sealed outputs.
pub mod signing;

/// Things for testing the coordinator when deployed, using Docker, for example.
pub mod tests;

use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::sync::Once;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::share::shamir::Shamirshare;
use stoffelmpc_mpc::common::share::ShareError;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use thiserror::Error;

pub use admission::{
    program_hash_of, AbortReason, AdmissionError, AdmissionPolicy, AdmissionPolicyKind,
    AssociationRequest, ClientAdmission, ClientAdmissionRecord, ClientAdmissionSet, ClientIndex,
    ClientSlotSpec, ClientSlotTable, ExecutionDeadlines, ExecutionOutcome, InputRange, Invitation,
    InvitationContext, InvitationIssuer, InvitationRejection, InvitationSigningError, OutputRights,
    RegistrationError, RegistrationNonce, SignedInvitation, SubmissionError, UnixSeconds,
    MAX_CLIENT_SLOTS, MAX_INPUTS, MAX_INPUTS_PER_SLOT, MAX_MASKED_INPUT_BYTES,
    MAX_OUTPUTS_PER_SLOT, MAX_SEALED_OUTPUT_BYTES,
};
pub use pin::{KeyAlgorithm, PinError, RosterKeys, ServerPin, SpkiDer};
pub use roster::{
    NodeCertificateDer, NodeRoster, NodeRosterWire, RosterDigest, RosterDigestParseError,
    RosterError,
};
pub use signing::{
    masked_inputs_signing_bytes, sealed_output_signing_bytes, sign_with_pkcs8,
    verify_identity_signature, SignatureError,
};

/// An MPC party's identity towards the off-chain coordinator and the node RPC listeners: the
/// `subject_public_key` BIT STRING of its certificate. It is also the HPKE key output shares
/// are sealed to, so its form cannot change without changing output encryption. Only
/// canonical encodings are ever derived (`SpkiDer::client_identity`), so its length names its
/// algorithm: 65 bytes is a P-256 point, 32 an Ed25519 key.
pub type ClientIdentity = Vec<u8>;

/// Uniquely identifies one MPC program invocation.
///
/// A program hash is deliberately not used as the execution identity: two invocations of the
/// same program must be able to overlap without sharing coordinator or node state. The all-zero
/// value is reserved and rejected by persistent/concurrent RPC paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionId([u8; 32]);

impl ExecutionId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ExecutionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(format!(
                "execution ID must contain exactly 64 hexadecimal characters, got {}",
                value.len()
            ));
        }
        let bytes = hex::decode(value).map_err(|error| format!("invalid execution ID: {error}"))?;
        Ok(Self(
            bytes.try_into().expect("validated execution ID length"),
        ))
    }
}

#[cfg(test)]
mod execution_id_tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_strict_and_stable() {
        let id = ExecutionId::from_bytes([0xab; 32]);
        let encoded = id.to_string();
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.parse::<ExecutionId>().unwrap(), id);
        assert!("ab".parse::<ExecutionId>().is_err());
        assert!(format!("{}z", &encoded[..63])
            .parse::<ExecutionId>()
            .is_err());
    }
}

/// One share, attributed to the roster position of the node that served it.
#[derive(Clone, Debug)]
pub struct PositionedShare<S> {
    pub position: usize,
    pub share: S,
}

/// The outcome of one reconstruction attempt over the shares received so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reconstruction<V> {
    /// Correct whenever at most `t` of the positions supplied corrupt shares.
    Secret(V),
    /// Not conclusive yet; more positions may make it so.
    Pending,
}

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

    /// Smallest `n` this backend reconstructs at: HoneyBadger `3t + 1`, AVSS `2t + 1`.
    fn min_parties(t: usize) -> usize;

    /// The share id roster position `position` holds: HoneyBadger `position`, AVSS
    /// `position + 1`.
    fn share_id_of_position(position: usize) -> usize;

    fn share_id(&self) -> usize;

    fn share_degree(&self) -> usize;

    /// `CanonicalSerialize` length of one share at degree `t`, compressed.
    fn serialized_share_len(t: usize) -> usize;

    /// At most one share per position; the caller refuses a second.
    ///
    /// Every share whose `share_id()` is not `share_id_of_position(position)`, or whose
    /// `share_degree()` is not `t`, is ignored before the backend-specific decision.
    fn reconstruct(
        shares: &[PositionedShare<Self>],
        n: usize,
        t: usize,
    ) -> Reconstruction<Self::ValueType>;
}

/// The shares of `shares` that sit at their position's id with degree `t`.
fn position_bound_shares<F: FftField, S: ShareBound<F>>(
    shares: &[PositionedShare<S>],
    t: usize,
) -> impl Iterator<Item = &S> {
    shares
        .iter()
        .filter(move |positioned| {
            positioned.share.share_id() == S::share_id_of_position(positioned.position)
                && positioned.share.share_degree() == t
        })
        .map(|positioned| &positioned.share)
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

    fn min_parties(t: usize) -> usize {
        3 * t + 1
    }

    fn share_id_of_position(position: usize) -> usize {
        position
    }

    fn share_id(&self) -> usize {
        self.id
    }

    fn share_degree(&self) -> usize {
        self.degree
    }

    fn serialized_share_len(t: usize) -> usize {
        RobustShare::new(F::zero(), 0, t).serialized_size(Compress::Yes)
    }

    /// Robust decoding over every position-bound share, once at least `2t + 1` are present.
    /// A success needs `2t + 1` shares on one degree-`t` polynomial, at least `t + 1` of them
    /// honest, and `t + 1` honest points fix the polynomial.
    fn reconstruct(
        shares: &[PositionedShare<Self>],
        n: usize,
        t: usize,
    ) -> Reconstruction<Self::ValueType> {
        let remaining = position_bound_shares::<F, Self>(shares, t)
            .cloned()
            .collect::<Vec<_>>();
        if remaining.len() < Self::min_shares(t) {
            return Reconstruction::Pending;
        }
        match Self::recover_secret(&remaining, n, t) {
            Ok((_, secret)) => Reconstruction::Secret(secret),
            Err(_) => Reconstruction::Pending,
        }
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

    fn min_parties(t: usize) -> usize {
        2 * t + 1
    }

    fn share_id_of_position(position: usize) -> usize {
        position + 1
    }

    fn share_id(&self) -> usize {
        self.feldmanshare.id
    }

    fn share_degree(&self) -> usize {
        self.feldmanshare.degree
    }

    fn serialized_share_len(t: usize) -> usize {
        FeldmanShamirShare::<F, G> {
            feldmanshare: Shamirshare::new(F::zero(), 1, t),
            commitments: vec![G::zero(); t + 1],
        }
        .serialized_size(Compress::Yes)
    }

    /// Groups position-bound shares by the commitment vector each presents, ignores a share
    /// that does not verify against its own commitments, and interpolates the first group
    /// with `t + 1` verified members. An honest node presents the honest vector, so a vector
    /// only the at most `t` corrupt nodes present never gathers `t + 1` members.
    fn reconstruct(
        shares: &[PositionedShare<Self>],
        n: usize,
        t: usize,
    ) -> Reconstruction<Self::ValueType> {
        let mut groups: Vec<(Vec<u8>, Vec<Self>)> = Vec::new();
        for share in position_bound_shares::<F, Self>(shares, t) {
            if !feldman_share_verifies(share, t) {
                continue;
            }
            let mut commitments = Vec::new();
            if share
                .commitments
                .serialize_compressed(&mut commitments)
                .is_err()
            {
                continue;
            }
            match groups.iter_mut().find(|(key, _)| *key == commitments) {
                Some((_, members)) => members.push(share.clone()),
                None => groups.push((commitments, vec![share.clone()])),
            }
        }
        for (_, members) in groups {
            if members.len() >= Self::min_shares(t) {
                if let Ok((_, secret)) = Self::recover_secret(&members, n, t) {
                    return Reconstruction::Secret(secret);
                }
            }
        }
        Reconstruction::Pending
    }
}

/// `share · G == Σⱼ commitmentsⱼ · idʲ` over the share's own `t + 1` commitments.
fn feldman_share_verifies<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: &FeldmanShamirShare<F, G>,
    t: usize,
) -> bool {
    if share.commitments.len() != t + 1 {
        return false;
    }
    let id = F::from(share.feldmanshare.id as u64);
    let mut power = F::one();
    let mut expected = G::zero();
    for commitment in &share.commitments {
        expected += *commitment * power;
        power *= id;
    }
    G::generator() * share.feldmanshare.share[0] == expected
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
    /// Terminal: the coordinator aborted the execution at one of its deadlines. No quorum
    /// reaches it and no proposal targets it; only the deadline sweeper enters it.
    Aborted,
}

/// The position of a round in the fixed protocol order. Rounds only ever advance, so this
/// lets a coordinator recognise a proposal for a round it has already passed.
pub fn round_index(round: Round) -> u8 {
    match round {
        Round::Idle => 0,
        Round::Preprocessing => 1,
        Round::InputMaskReservation => 2,
        Round::InputCollection => 3,
        Round::MPCExecution => 4,
        Round::OutputDistribution => 5,
        Round::ProgramFinished => 6,
        Round::Aborted => 7,
    }
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
        Round::Aborted => None,
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

    /// Reserves several input-mask indices in one call. The default implementation just calls
    /// `reserve_mask_index` in a loop, so implementors get this for free; `off-chain` overrides
    /// it with a single round trip, since reserving indices one at a time is what makes clients
    /// with many inputs blow past the RPC timeout under load.
    fn reserve_mask_indices(
        &mut self,
        indices: &[u64],
    ) -> impl Future<Output = Result<(), CoordinatorError>> {
        async move {
            for &i in indices {
                self.reserve_mask_index(i).await?;
            }
            Ok(())
        }
    }

    fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Submits several masked inputs in one call. The default implementation just calls
    /// `send_masked_input` in a loop, so implementors get this for free; `off-chain` overrides
    /// it with a single round trip, for the same reason `reserve_mask_indices` overrides
    /// `reserve_mask_index`: submitting inputs one at a time is what makes clients with many
    /// inputs blow past the RPC timeout under load.
    fn send_masked_inputs(
        &self,
        inputs: &[(u64, S::ValueType)],
    ) -> impl Future<Output = Result<(), CoordinatorError>> {
        async move {
            for (i, masked_input) in inputs {
                self.send_masked_input(masked_input.clone(), *i).await?;
            }
            Ok(())
        }
    }

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
}

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorError {
    #[error("The index {0:?} is already reserved.")]
    IndexAlreadyReserved(usize),
    #[error("The masked input for index {0:?} has already been sent.")]
    MaskedInputAlreadySent(usize),
    #[error("The mask for index {index} could not be reconstructed from the node shares.")]
    MaskReconstructionFailed { index: u64 },
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
    /// The server at `address` presented a key its pin does not admit. Never retried: this
    /// is the wrong server, not a missing one.
    #[error("the server at {address} presented a key its pin does not admit")]
    ServerPinMismatch { address: String },
    /// A listener was asked to serve state built for another certificate's key.
    #[error("the listener certificate's key is not the key the coordinator state was built for")]
    ServerCertificateMismatch,
    /// Two node RPC addresses answered as the same roster member.
    #[error("the node RPC server at {address} answered as a roster member another address already answered as")]
    DuplicateNodeIdentity { address: String },
    #[error("{given} node RPC addresses were given, but the roster has {n} nodes")]
    TooManyNodeAddresses { given: usize, n: u64 },
    #[error("the coordinator served roster {served}, not the expected {expected}")]
    UnexpectedRosterDigest {
        served: RosterDigest,
        expected: RosterDigest,
    },
    /// An off-chain client submitted, or asked for outputs, before `associate_client`
    /// succeeded.
    #[error("this client has not associated with the execution")]
    NotAssociated,
    #[error(
        "this backend needs at least {required} nodes for threshold {t}, and the roster has {n}"
    )]
    TopologyUnsupportedByBackend { n: u64, t: u64, required: u64 },
    #[error("client slot {client_index}'s outputs seal to {bytes} bytes under this backend, above the {max}-byte bound")]
    SealedOutputsExceedBound {
        client_index: ClientIndex,
        bytes: u64,
        max: u64,
    },
    #[error("output {output} could not be reconstructed from the node items received")]
    OutputReconstructionFailed { output: u64 },
    #[error("round {round:?} cannot be proposed or waited for")]
    RoundNotProposable { round: Round },
    #[error("execution {execution_id} was aborted by the coordinator: {reason}")]
    ExecutionAborted {
        execution_id: ExecutionId,
        reason: AbortReason,
    },
    #[error(transparent)]
    Pin(#[from] PinError),
    #[error(transparent)]
    Roster(#[from] RosterError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error(transparent)]
    Submission(#[from] SubmissionError),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// A refusal whose code carries no typed error.
    #[error("the coordinator refused the call ({refusal:?}): {message}")]
    Refused {
        refusal: RpcRefusal,
        message: String,
    },
}

/// The coordinator refusal codes without a typed error in their `data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcRefusal {
    WrongRound,
    MaskedInputAlreadySubmitted,
    IndexNotReserved,
    OutputSharesAlreadySent,
    OutputSharesAlreadyRequested,
    NotParty,
    ClientAlreadyReserved,
    ExecutionNotFound,
    RateLimited,
}

#[derive(Error, Clone, Debug)]
pub enum NodeRPCError {
    #[error("Execution is not registered or is ambiguous")]
    ExecutionNotFound,
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
    /// The execution's admitted reservations are already registered; no reservation can be
    /// added after them.
    #[error("Reservations are sealed for this execution")]
    ReservationsSealed,
}

static INIT: Once = Once::new();

pub fn setup_test() {
    INIT.call_once(|| {
        // Installing a crypto provider is process-global. Another dependency may
        // have installed one before this helper runs, which is already a valid
        // test setup and must not poison the initializer.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod share_bound_tests {
    use super::*;
    use crate::tests::fake_coord::{AvssShareGroupType, AvssShareType, HoneyBadgerShareType};
    use ark_bls12_381::Fr;
    use ark_ec::PrimeGroup;
    use ark_ff::Field;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    fn positioned<S: Clone>(shares: &[S]) -> Vec<PositionedShare<S>> {
        shares
            .iter()
            .enumerate()
            .map(|(position, share)| PositionedShare {
                position,
                share: share.clone(),
            })
            .collect()
    }

    #[test]
    fn share_bound_positions_parties_and_sizes_match_the_backends() {
        for t in [1usize, 2, 5] {
            assert_eq!(
                <HoneyBadgerShareType as ShareBound<Fr>>::min_parties(t),
                3 * t + 1
            );
            assert_eq!(<AvssShareType as ShareBound<Fr>>::min_parties(t), 2 * t + 1);
        }
        for position in [0usize, 1, 4] {
            assert_eq!(
                <HoneyBadgerShareType as ShareBound<Fr>>::share_id_of_position(position),
                position
            );
            assert_eq!(
                <AvssShareType as ShareBound<Fr>>::share_id_of_position(position),
                position + 1
            );
        }

        // The ids the backends' own share generation hands party `p`.
        let mut rng = test_rng();
        let n = 16;
        let t = 5;
        let robust =
            HoneyBadgerShareType::compute_shares(Fr::from(3u64), n, t, None, &mut rng).unwrap();
        for (position, share) in robust.iter().enumerate() {
            assert_eq!(
                share.share_id(),
                <HoneyBadgerShareType as ShareBound<Fr>>::share_id_of_position(position)
            );
            assert_eq!(share.share_degree(), t);
        }
        let ids = (0..n)
            .map(<AvssShareType as ShareBound<Fr>>::share_id_of_position)
            .collect::<Vec<_>>();
        let feldman =
            AvssShareType::compute_shares(Fr::from(3u64), n, t, Some(&ids), &mut rng).unwrap();

        assert_eq!(
            <HoneyBadgerShareType as ShareBound<Fr>>::serialized_share_len(t),
            robust[0].serialized_size(Compress::Yes)
        );
        assert_eq!(
            <HoneyBadgerShareType as ShareBound<Fr>>::serialized_share_len(t),
            48
        );
        assert_eq!(
            <AvssShareType as ShareBound<Fr>>::serialized_share_len(t),
            feldman[0].serialized_size(Compress::Yes)
        );
        assert_eq!(
            <AvssShareType as ShareBound<Fr>>::serialized_share_len(t),
            344
        );
    }

    #[test]
    fn reconstruction_excludes_relabelled_resized_and_corrupted_shares() {
        let mut rng = test_rng();
        let secret = Fr::from(42u64);

        // HoneyBadger, n = 4, t = 1.
        let (n, t) = (4, 1);
        let shares = HoneyBadgerShareType::compute_shares(secret, n, t, None, &mut rng).unwrap();
        let honest = positioned(&shares);
        assert_eq!(
            HoneyBadgerShareType::reconstruct(&honest, n, t),
            Reconstruction::Secret(secret)
        );

        let mut relabelled = honest.clone();
        relabelled[3].share.id = 2;
        assert_eq!(
            HoneyBadgerShareType::reconstruct(&relabelled, n, t),
            Reconstruction::Secret(secret),
            "a share carrying another position's id is ignored, and the other three reconstruct"
        );

        let mut resized = honest.clone();
        resized[0].share.degree = 0;
        assert_eq!(
            HoneyBadgerShareType::reconstruct(&resized, n, t),
            Reconstruction::Secret(secret)
        );

        let mut corrupted = honest.clone();
        corrupted[1].share.share[0] += Fr::from(1u64);
        assert_eq!(
            HoneyBadgerShareType::reconstruct(&corrupted, n, t),
            Reconstruction::Secret(secret),
            "one wrong value among four still reconstructs the right secret"
        );

        assert_eq!(
            HoneyBadgerShareType::reconstruct(&honest[..2], n, t),
            Reconstruction::Pending
        );

        // AVSS, n = 3, t = 1: ids are position + 1.
        let (n, t) = (3, 1);
        let ids = [1, 2, 3];
        let shares = AvssShareType::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();
        let honest = positioned(&shares);
        assert_eq!(
            AvssShareType::reconstruct(&honest, n, t),
            Reconstruction::Secret(secret)
        );

        // A share off its own commitments is ignored; the honest two still reconstruct.
        let mut off_commitments = honest.clone();
        off_commitments[0].share.feldmanshare.share[0] += Fr::from(1u64);
        assert_eq!(
            AvssShareType::reconstruct(&off_commitments, n, t),
            Reconstruction::Secret(secret)
        );
        assert_eq!(
            AvssShareType::reconstruct(&off_commitments[..2], n, t),
            Reconstruction::Pending
        );

        // A corrupt node at position 0 presents consistent commitments of its own design,
        // chosen so that honest position 1's share also verifies against them. Its vector
        // never gathers t + 1 presenters, because position 1 presented the honest vector.
        let honest_share_1 = shares[1].feldmanshare.share[0];
        let forged_secret = Fr::rand(&mut rng);
        // f(x) = a0 + a1 x with f(2) = honest_share_1 and f(0) = forged_secret.
        let a0 = forged_secret;
        let a1 = (honest_share_1 - a0) * Fr::from(2u64).inverse().unwrap();
        let forged_commitments = vec![
            AvssShareGroupType::generator() * a0,
            AvssShareGroupType::generator() * a1,
        ];
        let forged_value = a0 + a1;
        let mut with_forgery = honest.clone();
        with_forgery[0].share =
            AvssShareType::new(forged_value, 1, t, forged_commitments.clone()).unwrap();
        let accepted_honest_share =
            AvssShareType::new(honest_share_1, 2, t, forged_commitments).unwrap();
        assert!(feldman_share_verifies(&accepted_honest_share, t));
        assert_eq!(
            AvssShareType::reconstruct(&with_forgery, n, t),
            Reconstruction::Secret(secret)
        );
        assert_eq!(
            AvssShareType::reconstruct(&with_forgery[..2], n, t),
            Reconstruction::Pending,
            "the forged vector has one presenter, the honest vector one: nothing is conclusive"
        );
    }
}
