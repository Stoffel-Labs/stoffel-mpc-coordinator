//! Client admission: which client slots an execution has, who may bind them, and how.
//!
//! A registration fixes an execution's program, its slot table and its admission policy once
//! and for all. The table is the program's shape — slot `i` owns a fixed input range and fixed
//! output rights — and names nobody. Identities are the only late part: a client binds a slot
//! with `associate_client`, under the execution's `AdmissionPolicy`, and the binding is never
//! removed or moved. Every node reads the same frozen `ClientAdmissionSet` once the set can no
//! longer change, so every node applies the same release rule to the same data.

use crate::pin::KeyAlgorithm;
use crate::{ClientIdentity, ExecutionId, Round};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::num::NonZeroU64;
use std::time::{SystemTime, UNIX_EPOCH};

/// Client slots one registration may declare.
pub const MAX_CLIENT_SLOTS: u32 = 16_384;
/// Inputs one client slot may own.
pub const MAX_INPUTS_PER_SLOT: u64 = 32_768;
/// Outputs one client slot may receive.
pub const MAX_OUTPUTS_PER_SLOT: u64 = 1_024;
/// Inputs one registration may declare over all of its slots.
pub const MAX_INPUTS: u64 = 1 << 20;
/// One masked input's encoding. Every `ShareBound::ValueType` in use is a 32-byte compressed
/// scalar; 64 leaves room for a wider field without re-measuring the wire bounds.
pub const MAX_MASKED_INPUT_BYTES: u64 = 64;
/// One node's sealed output ciphertext for one client.
pub const MAX_SEALED_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;

/// The domain separator of `program_hash_of`, shared byte for byte with the VM's
/// `program_id_from_bytes`.
const PROGRAM_HASH_DOMAIN: &[u8] = b"stoffel-program-v1";

/// `blake3::Hasher::new()`, `update(b"stoffel-program-v1")`, `update(program_bytes)`,
/// `finalize()` — byte for byte the VM's `program_id_from_bytes`.
pub fn program_hash_of(program_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROGRAM_HASH_DOMAIN);
    hasher.update(program_bytes);
    *hasher.finalize().as_bytes()
}

/// A slot's position in its registration's `ClientSlotTable`, which is the program's
/// `client_slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientIndex(pub u32);

impl fmt::Display for ClientIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Seconds since the Unix epoch, on the coordinator's clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixSeconds(pub u64);

impl UnixSeconds {
    /// The current time, truncated to whole seconds.
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0),
        )
    }

    /// The `SystemTime` this value names.
    pub fn as_system_time(self) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(self.0)
    }
}

impl fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDeadlines {
    /// Every slot is bound by then, or the execution is aborted.
    pub association: UnixSeconds,
    /// Every masked input is submitted by then, or the execution is aborted.
    pub input: UnixSeconds,
}

/// 32 bytes the coordinator draws from `ring::rand::SystemRandom` when it registers an
/// execution. Not secret: it names one registration of one `ExecutionId`, so a restart or a
/// later registration of the same id orphans every signed submission and sealed output of the
/// earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RegistrationNonce([u8; 32]);

impl RegistrationNonce {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Draws a fresh nonce from the operating system's random source.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        // `SystemRandom` reads the OS source (getrandom); it fails only when the kernel has no
        // random source at all, in which case no key in this process could be trusted either.
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("the operating system random source is unavailable");
        Self(bytes)
    }
}

impl fmt::Display for RegistrationNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The shape of one client slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSlotSpec {
    pub input_count: u64,
    pub output_count: u64,
}

/// One entry per client slot. The position is the slot's `ClientIndex`, which is the program's
/// `client_slot` (`ClientIoSchema::client_slot`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientSlotTable(Vec<ClientSlotSpec>);

impl ClientSlotTable {
    pub fn new(slots: Vec<ClientSlotSpec>) -> Self {
        Self(slots)
    }

    pub fn slots(&self) -> &[ClientSlotSpec] {
        &self.0
    }

    /// The rows of the registration table that need neither a roster nor a policy. Nodes and
    /// clients run it on a served `ExecutionSummary` as well.
    pub fn check_bounds(&self) -> Result<(), RegistrationError> {
        let slots = self.0.len() as u64;
        if slots > u64::from(MAX_CLIENT_SLOTS) {
            return Err(RegistrationError::TooManyClientSlots {
                slots,
                max: MAX_CLIENT_SLOTS,
            });
        }
        for (index, slot) in self.indexed() {
            if slot.input_count == 0 && slot.output_count == 0 {
                return Err(RegistrationError::EmptyClientSlot {
                    client_index: index,
                });
            }
        }
        for (index, slot) in self.indexed() {
            if slot.input_count > MAX_INPUTS_PER_SLOT {
                return Err(RegistrationError::TooManyInputsInSlot {
                    client_index: index,
                    input_count: slot.input_count,
                    max: MAX_INPUTS_PER_SLOT,
                });
            }
        }
        for (index, slot) in self.indexed() {
            if slot.output_count > MAX_OUTPUTS_PER_SLOT {
                return Err(RegistrationError::TooManyOutputsInSlot {
                    client_index: index,
                    output_count: slot.output_count,
                    max: MAX_OUTPUTS_PER_SLOT,
                });
            }
        }
        let n_inputs = self.n_inputs();
        if n_inputs > MAX_INPUTS {
            return Err(RegistrationError::TooManyInputs {
                n_inputs,
                max: MAX_INPUTS,
            });
        }
        Ok(())
    }

    /// The number of slots. Meaningful once `check_bounds` has passed.
    pub fn capacity(&self) -> u32 {
        u32::try_from(self.0.len()).unwrap_or(u32::MAX)
    }

    /// Every slot's input count, summed. Meaningful once `check_bounds` has passed.
    pub fn n_inputs(&self) -> u64 {
        self.0
            .iter()
            .fold(0u64, |sum, slot| sum.saturating_add(slot.input_count))
    }

    /// Slot `i` owns `[sum of input_count over slots j < i, + input_count_i)`; `None` when its
    /// input count is 0 or the slot does not exist.
    pub fn input_range(&self, slot: ClientIndex) -> Option<InputRange> {
        let position = slot.0 as usize;
        let spec = self.0.get(position)?;
        let count = NonZeroU64::new(spec.input_count)?;
        let start = self.0[..position]
            .iter()
            .fold(0u64, |sum, earlier| sum.saturating_add(earlier.input_count));
        Some(InputRange { start, count })
    }

    /// `Receive` for a slot with outputs, `None` for one without or a slot that does not exist.
    pub fn output_rights(&self, slot: ClientIndex) -> OutputRights {
        match self
            .0
            .get(slot.0 as usize)
            .and_then(|spec| NonZeroU64::new(spec.output_count))
        {
            Some(output_count) => OutputRights::Receive { output_count },
            None => OutputRights::None,
        }
    }

    pub fn has_output_slots(&self) -> bool {
        self.0.iter().any(|slot| slot.output_count > 0)
    }

    fn indexed(&self) -> impl Iterator<Item = (ClientIndex, &ClientSlotSpec)> {
        self.0
            .iter()
            .enumerate()
            .map(|(position, slot)| (ClientIndex(position as u32), slot))
    }
}

/// A slot's contiguous block of global input indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRange {
    pub start: u64,
    pub count: NonZeroU64,
}

impl InputRange {
    /// One past the last index; saturates, which a table that passed `check_bounds` never does.
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.count.get())
    }

    /// Whether `indices` is exactly this range, ascending.
    pub fn is_exactly(&self, indices: &[u64]) -> bool {
        indices.len() as u64 == self.count.get()
            && indices
                .iter()
                .enumerate()
                .all(|(offset, index)| Some(*index) == self.start.checked_add(offset as u64))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputRights {
    None,
    Receive { output_count: NonZeroU64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicy {
    /// `clients[i]` is bound to slot `i` at registration.
    PreRegistered { clients: Vec<ClientIdentity> },
    /// Any certificate holder may bind a free slot, first come, first served. The slot table is
    /// the capacity. Use it only where association is already access-controlled: anyone who can
    /// reach the coordinator can bind every slot.
    Open,
}

/// What a non-node may learn about the policy: never the pre-registered identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPolicyKind {
    PreRegistered,
    Open,
}

impl AdmissionPolicy {
    pub fn kind(&self) -> AdmissionPolicyKind {
        match self {
            Self::PreRegistered { .. } => AdmissionPolicyKind::PreRegistered,
            Self::Open => AdmissionPolicyKind::Open,
        }
    }

    /// The policy rows of the registration table, in table order: the `PreRegistered` rows.
    /// `slots` must already have passed `check_bounds`.
    pub fn check(&self, slots: &ClientSlotTable) -> Result<(), RegistrationError> {
        match self {
            Self::PreRegistered { clients } => {
                if clients.len() != slots.slots().len() {
                    return Err(RegistrationError::PreRegisteredCountMismatch {
                        slots: slots.slots().len() as u64,
                        clients: clients.len() as u64,
                    });
                }
                for (position, (client, slot)) in clients.iter().zip(slots.slots()).enumerate() {
                    let supported = match KeyAlgorithm::of_client_identity(client) {
                        Some(KeyAlgorithm::EcdsaP256) => true,
                        Some(KeyAlgorithm::Ed25519) => slot.output_count == 0,
                        None => false,
                    };
                    if !supported {
                        return Err(RegistrationError::UnsupportedPreRegisteredKey {
                            client_index: ClientIndex(position as u32),
                        });
                    }
                }
                let mut seen = HashSet::with_capacity(clients.len());
                for (position, client) in clients.iter().enumerate() {
                    if !seen.insert(client) {
                        return Err(RegistrationError::DuplicatePreRegisteredClient {
                            client_index: ClientIndex(position as u32),
                        });
                    }
                }
                Ok(())
            }
            Self::Open => Ok(()),
        }
    }

    /// The deadline rows of the registration table, in table order.
    pub fn check_deadlines(
        &self,
        deadlines: Option<ExecutionDeadlines>,
        now: UnixSeconds,
    ) -> Result<(), RegistrationError> {
        let Some(deadlines) = deadlines else {
            return match self {
                Self::PreRegistered { .. } => Ok(()),
                Self::Open => Err(RegistrationError::DeadlinesRequired),
            };
        };
        if deadlines.association > deadlines.input {
            return Err(RegistrationError::DeadlinesOutOfOrder {
                association: deadlines.association,
                input: deadlines.input,
            });
        }
        for deadline in [deadlines.association, deadlines.input] {
            if deadline <= now {
                return Err(RegistrationError::DeadlineElapsed { deadline, now });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociationRequest {
    /// `None` binds the lowest-numbered free slot under `Open`.
    pub slot: Option<ClientIndex>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmission {
    pub execution_id: ExecutionId,
    pub client_index: ClientIndex,
    pub input_range: Option<InputRange>,
    pub output_rights: OutputRights,
}

/// A `ClientAdmission` without its `execution_id`, which the set carries once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmissionRecord {
    pub client: ClientIdentity,
    pub client_index: ClientIndex,
    pub input_range: Option<InputRange>,
    pub output_rights: OutputRights,
}

impl ClientAdmissionRecord {
    pub fn admission(&self, execution_id: ExecutionId) -> ClientAdmission {
        ClientAdmission {
            execution_id,
            client_index: self.client_index,
            input_range: self.input_range,
            output_rights: self.output_rights,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientAdmissionSet {
    pub execution_id: ExecutionId,
    /// One record per slot, ascending `client_index`.
    pub records: Vec<ClientAdmissionRecord>,
}

impl ClientAdmissionSet {
    /// The record naming `client`, if any.
    pub fn record_of(&self, client: &ClientIdentity) -> Option<&ClientAdmissionRecord> {
        self.records.iter().find(|record| record.client == *client)
    }
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionError {
    #[error("execution {execution_id} no longer binds new clients: it is in round {current:?}")]
    AssociationClosed {
        execution_id: ExecutionId,
        current: Round,
    },
    #[error("every one of the {capacity} client slots of execution {execution_id} is bound")]
    CapacityExhausted {
        execution_id: ExecutionId,
        capacity: u32,
    },
    #[error("execution {execution_id} has {slots} client slots; slot {requested} does not exist")]
    SlotOutOfRange {
        execution_id: ExecutionId,
        requested: ClientIndex,
        slots: u32,
    },
    #[error("client slot {requested} of execution {execution_id} is bound to another client")]
    SlotTaken {
        execution_id: ExecutionId,
        requested: ClientIndex,
    },
    #[error("execution {execution_id} admits only pre-registered clients, and this is not one")]
    NotPreRegistered { execution_id: ExecutionId },
    #[error("this client is pre-registered for slot {registered}, not slot {requested}")]
    PreRegisteredSlotMismatch {
        registered: ClientIndex,
        requested: ClientIndex,
    },
    #[error(
        "client slot {client_index} receives outputs, which can be sealed only to a P-256 key"
    )]
    UnsupportedClientKey { client_index: ClientIndex },
    #[error("this client already holds slot {} of execution {execution_id} under another request", admission.client_index)]
    AlreadyAssociated {
        execution_id: ExecutionId,
        admission: ClientAdmission,
    },
    #[error("this client holds no admission to execution {execution_id}")]
    NotAdmitted { execution_id: ExecutionId },
    #[error("a reservation must name exactly the admitted input range {admitted:?}")]
    ReservationOutsideAdmission { admitted: Option<InputRange> },
    #[error(
        "the admissions of execution {execution_id} are not frozen yet: it is in round {current:?}"
    )]
    AdmissionsNotFrozen {
        execution_id: ExecutionId,
        current: Round,
    },
    #[error("this client has no output rights in execution {execution_id}")]
    NoOutputRights { execution_id: ExecutionId },
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionError {
    #[error(
        "the masked input for index {reserved_index} is {len} bytes, above the {max}-byte bound"
    )]
    MaskedInputTooLarge {
        reserved_index: u64,
        len: u64,
        max: u64,
    },
    #[error("a submission must cover exactly the admitted input range {admitted:?}")]
    SubmissionOutsideAdmission { admitted: Option<InputRange> },
    #[error("the masked inputs' signature does not verify against the submitting client's key")]
    BadMaskedInputSignature,
    #[error("the sealed output is {len} bytes, above the {max}-byte bound")]
    SealedOutputTooLarge { len: u64, max: u64 },
    #[error("the sealed output's signature does not verify against the sending node's key")]
    BadOutputSignature,
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    #[error(
        "{unbound_slots} client slots were still unbound at the association deadline {deadline}"
    )]
    AssociationDeadline {
        deadline: UnixSeconds,
        unbound_slots: u32,
    },
    /// `missing_inputs` is never 0.
    #[error("{missing_inputs} masked inputs were still missing at the input deadline {deadline}")]
    InputDeadline {
        deadline: UnixSeconds,
        missing_inputs: u64,
    },
}

/// How an execution this process no longer serves ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    Finished,
    Aborted(AbortReason),
}

/// Returned in-process by `register_execution` and `new_for_execution`; never on the wire.
#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistrationError {
    #[error("the execution ID must be nonzero")]
    ZeroExecutionId,
    #[error("the program hash must be nonzero")]
    ZeroProgramHash,
    #[error("{slots} client slots exceed the bound of {max}")]
    TooManyClientSlots { slots: u64, max: u32 },
    #[error("client slot {client_index} has neither inputs nor outputs")]
    EmptyClientSlot { client_index: ClientIndex },
    #[error("client slot {client_index} has {input_count} inputs, above the bound of {max}")]
    TooManyInputsInSlot {
        client_index: ClientIndex,
        input_count: u64,
        max: u64,
    },
    #[error("client slot {client_index} has {output_count} outputs, above the bound of {max}")]
    TooManyOutputsInSlot {
        client_index: ClientIndex,
        output_count: u64,
        max: u64,
    },
    #[error("the registration has {n_inputs} inputs, above the bound of {max}")]
    TooManyInputs { n_inputs: u64, max: u64 },
    #[error("{clients} pre-registered clients were given for {slots} client slots")]
    PreRegisteredCountMismatch { slots: u64, clients: u64 },
    #[error("the client pre-registered for slot {client_index} has a key this slot cannot use")]
    UnsupportedPreRegisteredKey { client_index: ClientIndex },
    #[error("the client pre-registered for slot {client_index} is pre-registered for an earlier slot too")]
    DuplicatePreRegisteredClient { client_index: ClientIndex },
    #[error("open admission requires association and input deadlines")]
    DeadlinesRequired,
    #[error("the association deadline {association} is after the input deadline {input}")]
    DeadlinesOutOfOrder {
        association: UnixSeconds,
        input: UnixSeconds,
    },
    #[error("the deadline {deadline} is not later than coordinator time {now}")]
    DeadlineElapsed {
        deadline: UnixSeconds,
        now: UnixSeconds,
    },
    #[error("execution {execution_id} is already registered with a different registration")]
    ConflictingRegistration { execution_id: ExecutionId },
    #[error("execution {execution_id} has ended and its ID cannot be registered again yet")]
    ExecutionIdRetired { execution_id: ExecutionId },
    #[error("the coordinator already serves {capacity} live executions and none is evictable")]
    ExecutionCapacityReached { capacity: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::test_certificates::{ed25519_certificate, p256_certificate};
    use crate::pin::SpkiDer;

    fn spki_of(certified: &rcgen::CertifiedKey<rcgen::KeyPair>) -> SpkiDer {
        SpkiDer::from_certificate_der(certified.cert.der()).unwrap()
    }

    fn slot(input_count: u64, output_count: u64) -> ClientSlotSpec {
        ClientSlotSpec {
            input_count,
            output_count,
        }
    }

    #[test]
    fn program_hash_of_matches_the_shared_golden_vector() {
        assert_eq!(
            hex::encode(program_hash_of(b"stoffel golden program")),
            "fe9f7bf29eff22b4631f8468a32aff7761e78aba67a0ba19724779f0768179ee"
        );
    }

    #[test]
    fn a_slot_table_partitions_the_input_space() {
        let table = ClientSlotTable::new(vec![slot(2, 0), slot(0, 1), slot(3, 2)]);
        table.check_bounds().unwrap();
        assert_eq!(table.capacity(), 3);
        assert_eq!(table.n_inputs(), 5);
        assert_eq!(
            table.input_range(ClientIndex(0)),
            Some(InputRange {
                start: 0,
                count: NonZeroU64::new(2).unwrap()
            })
        );
        assert_eq!(table.input_range(ClientIndex(1)), None);
        assert_eq!(
            table.input_range(ClientIndex(2)),
            Some(InputRange {
                start: 2,
                count: NonZeroU64::new(3).unwrap()
            })
        );
        assert_eq!(table.input_range(ClientIndex(3)), None);
        assert_eq!(table.output_rights(ClientIndex(0)), OutputRights::None);
        assert_eq!(
            table.output_rights(ClientIndex(2)),
            OutputRights::Receive {
                output_count: NonZeroU64::new(2).unwrap()
            }
        );
        assert!(table.has_output_slots());
        assert!(!ClientSlotTable::new(vec![slot(1, 0)]).has_output_slots());

        let range = table.input_range(ClientIndex(2)).unwrap();
        assert!(range.is_exactly(&[2, 3, 4]));
        assert!(!range.is_exactly(&[2, 3]));
        assert!(!range.is_exactly(&[3, 4, 5]));
        assert!(!range.is_exactly(&[2, 4, 3]));
    }

    #[test]
    fn registration_refuses_missing_or_disordered_deadlines_and_non_canonical_clients() {
        let now = UnixSeconds(1_000);
        let deadlines = |association, input| {
            Some(ExecutionDeadlines {
                association: UnixSeconds(association),
                input: UnixSeconds(input),
            })
        };
        let open = AdmissionPolicy::Open;
        assert_eq!(
            open.check_deadlines(None, now),
            Err(RegistrationError::DeadlinesRequired)
        );
        assert_eq!(open.check_deadlines(deadlines(1_001, 1_002), now), Ok(()));
        let pre = AdmissionPolicy::PreRegistered { clients: vec![] };
        assert_eq!(pre.check_deadlines(None, now), Ok(()));
        assert_eq!(
            pre.check_deadlines(deadlines(1_010, 1_005), now),
            Err(RegistrationError::DeadlinesOutOfOrder {
                association: UnixSeconds(1_010),
                input: UnixSeconds(1_005)
            })
        );
        assert_eq!(
            pre.check_deadlines(deadlines(1_000, 1_005), now),
            Err(RegistrationError::DeadlineElapsed {
                deadline: UnixSeconds(1_000),
                now
            })
        );
        assert_eq!(pre.check_deadlines(deadlines(1_001, 1_001), now), Ok(()));

        let p256_client = spki_of(&p256_certificate()).client_identity();
        let ed_client = spki_of(&ed25519_certificate()).client_identity();
        let slots = ClientSlotTable::new(vec![slot(1, 1), slot(1, 0)]);

        let compressed = vec![0x02; 33];
        let check =
            |clients: Vec<ClientIdentity>| AdmissionPolicy::PreRegistered { clients }.check(&slots);
        assert_eq!(
            check(vec![compressed, p256_client.clone()]),
            Err(RegistrationError::UnsupportedPreRegisteredKey {
                client_index: ClientIndex(0)
            })
        );
        assert_eq!(
            check(vec![ed_client.clone(), p256_client.clone()]),
            Err(RegistrationError::UnsupportedPreRegisteredKey {
                client_index: ClientIndex(0)
            }),
            "an output slot needs a key output shares can be sealed to"
        );
        assert_eq!(check(vec![p256_client.clone(), ed_client]), Ok(()));
        assert_eq!(
            check(vec![p256_client.clone()]),
            Err(RegistrationError::PreRegisteredCountMismatch {
                slots: 2,
                clients: 1
            })
        );
        assert_eq!(
            check(vec![p256_client.clone(), p256_client]),
            Err(RegistrationError::DuplicatePreRegisteredClient {
                client_index: ClientIndex(1)
            })
        );
    }

    #[test]
    fn registration_bounds_keep_every_response_under_the_wire_limit() {
        const TEN_MIB: usize = 10 * 1024 * 1024;

        // The slot bounds, and one past each.
        let at_bounds =
            ClientSlotTable::new(vec![
                slot(MAX_INPUTS_PER_SLOT / 2, MAX_OUTPUTS_PER_SLOT);
                MAX_CLIENT_SLOTS as usize
            ]);
        assert_eq!(
            at_bounds.check_bounds(),
            Err(RegistrationError::TooManyInputs {
                n_inputs: u64::from(MAX_CLIENT_SLOTS) * MAX_INPUTS_PER_SLOT / 2,
                max: MAX_INPUTS
            })
        );
        let mut exact = vec![slot(0, MAX_OUTPUTS_PER_SLOT); MAX_CLIENT_SLOTS as usize];
        for spec in exact
            .iter_mut()
            .take((MAX_INPUTS / MAX_INPUTS_PER_SLOT) as usize)
        {
            spec.input_count = MAX_INPUTS_PER_SLOT;
        }
        let exact = ClientSlotTable::new(exact);
        assert_eq!(exact.check_bounds(), Ok(()));
        assert_eq!(exact.n_inputs(), MAX_INPUTS);

        let mut too_many_slots = exact.slots().to_vec();
        too_many_slots.push(slot(0, 1));
        assert_eq!(
            ClientSlotTable::new(too_many_slots).check_bounds(),
            Err(RegistrationError::TooManyClientSlots {
                slots: u64::from(MAX_CLIENT_SLOTS) + 1,
                max: MAX_CLIENT_SLOTS
            })
        );
        assert_eq!(
            ClientSlotTable::new(vec![slot(MAX_INPUTS_PER_SLOT + 1, 0)]).check_bounds(),
            Err(RegistrationError::TooManyInputsInSlot {
                client_index: ClientIndex(0),
                input_count: MAX_INPUTS_PER_SLOT + 1,
                max: MAX_INPUTS_PER_SLOT
            })
        );
        assert_eq!(
            ClientSlotTable::new(vec![slot(1, MAX_OUTPUTS_PER_SLOT + 1)]).check_bounds(),
            Err(RegistrationError::TooManyOutputsInSlot {
                client_index: ClientIndex(0),
                output_count: MAX_OUTPUTS_PER_SLOT + 1,
                max: MAX_OUTPUTS_PER_SLOT
            })
        );
        assert_eq!(
            ClientSlotTable::new(vec![slot(1, 0), slot(0, 0)]).check_bounds(),
            Err(RegistrationError::EmptyClientSlot {
                client_index: ClientIndex(1)
            })
        );

        // The largest admission set: every number at its largest, every identity a 65-byte
        // point of 0xff bytes.
        let record = ClientAdmissionRecord {
            client: vec![0xff; 65],
            client_index: ClientIndex(MAX_CLIENT_SLOTS - 1),
            input_range: Some(InputRange {
                start: MAX_INPUTS - 1,
                count: NonZeroU64::new(MAX_INPUTS_PER_SLOT).unwrap(),
            }),
            output_rights: OutputRights::Receive {
                output_count: NonZeroU64::new(MAX_OUTPUTS_PER_SLOT).unwrap(),
            },
        };
        let set = ClientAdmissionSet {
            execution_id: ExecutionId::from_bytes([0xff; 32]),
            records: vec![record; MAX_CLIENT_SLOTS as usize],
        };
        let set_len = serde_json::to_vec(&set).unwrap().len();
        assert!(set_len <= 6_389_918, "admission set is {set_len} bytes");
        assert!(set_len < TEN_MIB);

        let table_len = serde_json::to_vec(&ClientSlotTable::new(vec![
            slot(
                MAX_INPUTS_PER_SLOT,
                MAX_OUTPUTS_PER_SLOT
            );
            MAX_CLIENT_SLOTS as usize
        ]))
        .unwrap()
        .len();
        assert!(table_len <= 688_129, "slot table is {table_len} bytes");
    }
}
