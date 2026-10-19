//! The node roster: the coordinator's fixed, verified membership of MPC nodes.
//!
//! The coordinator is the only roster authority. It builds one `NodeRoster` at startup and
//! serves it unchanged for its whole lifetime; nodes and clients fetch it once, over a
//! connection pinned to the coordinator's key, and verify it on receipt. Every
//! `NodeRoster` value is canonical and verified — there is no way to hold an unchecked one.

use crate::pin::{PinError, SpkiDer};
use crate::ClientIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// The blake3 key-derivation context of the roster digest.
const ROSTER_DIGEST_CONTEXT: &str = "stoffel-coordinator-node-roster-v1";

/// Unverified bytes: a certificate is checked when a `NodeRoster` is built from it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeCertificateDer(Vec<u8>);

impl NodeCertificateDer {
    pub fn from_der(der: Vec<u8>) -> Self {
        Self(der)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RosterDigest([u8; 32]);

impl RosterDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hexadecimal, 64 characters: what every message and flag shows.
impl fmt::Display for RosterDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Exactly 64 hexadecimal characters, either case; `--expect-roster-digest` parses with it.
impl FromStr for RosterDigest {
    type Err = RosterDigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let length = value.chars().count();
        if length != 64 {
            return Err(RosterDigestParseError::WrongLength { length });
        }
        if let Some(position) = value.chars().position(|c| !c.is_ascii_hexdigit()) {
            return Err(RosterDigestParseError::NotHex { position });
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(value, &mut bytes)
            .expect("64 ASCII hexadecimal characters decode to 32 bytes");
        Ok(Self(bytes))
    }
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterDigestParseError {
    #[error("expected 64 hexadecimal characters, got {length}")]
    WrongLength { length: usize },
    #[error("character {position} is not hexadecimal")]
    NotHex { position: usize },
}

/// Every value is canonical and verified: the fields are private, and deserializing
/// goes through `TryFrom<NodeRosterWire>`, which runs the full receiver check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NodeRosterWire", into = "NodeRosterWire")]
pub struct NodeRoster {
    n: u64,
    t: u64,
    node_certificates: Vec<NodeCertificateDer>,
    digest: RosterDigest,
    /// Derived from `node_certificates` when the roster is built; strictly ascending.
    spkis: Vec<SpkiDer>,
}

/// The roster as it crosses the wire, before verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeRosterWire {
    pub n: u64,
    pub t: u64,
    pub node_certificates: Vec<NodeCertificateDer>,
    pub digest: RosterDigest,
}

impl NodeRoster {
    /// Coordinator side: certificates in any order in, canonical order out.
    pub fn new(t: u64, certificates: Vec<NodeCertificateDer>) -> Result<Self, RosterError> {
        let n = certificates.len() as u64;
        check_shape(n, t, certificates.len())?;
        let spkis = derive_spkis(&certificates)?;

        let mut order = (0..certificates.len()).collect::<Vec<_>>();
        order.sort_by(|a, b| spkis[*a].cmp(&spkis[*b]));
        if let Some(pair) = order
            .windows(2)
            .find(|pair| spkis[pair[0]] == spkis[pair[1]])
        {
            return Err(RosterError::DuplicateKey {
                first: pair[0].min(pair[1]),
                second: pair[0].max(pair[1]),
            });
        }
        check_unique_identities(order.iter().map(|index| (*index, &spkis[*index])))?;

        let mut slots = certificates.into_iter().map(Some).collect::<Vec<_>>();
        let node_certificates = order
            .iter()
            .map(|index| slots[*index].take().expect("each index sorted once"))
            .collect::<Vec<_>>();
        let spkis = order
            .iter()
            .map(|index| spkis[*index].clone())
            .collect::<Vec<_>>();
        let digest = roster_digest(n, t, &spkis);
        Ok(Self {
            n,
            t,
            node_certificates,
            digest,
            spkis,
        })
    }

    pub fn n(&self) -> u64 {
        self.n
    }

    pub fn t(&self) -> u64 {
        self.t
    }

    pub fn digest(&self) -> RosterDigest {
        self.digest
    }

    /// Canonical order, which is party-index order.
    pub fn node_certificates(&self) -> &[NodeCertificateDer] {
        &self.node_certificates
    }

    pub fn node_spkis(&self) -> Vec<SpkiDer> {
        self.spkis.clone()
    }

    /// Coordinator identity form, same order; this is the coordinator's `mpc_nodes`.
    pub fn node_identities(&self) -> Vec<ClientIdentity> {
        self.spkis.iter().map(SpkiDer::client_identity).collect()
    }

    pub fn position_of(&self, spki: &SpkiDer) -> Option<usize> {
        self.spkis.binary_search(spki).ok()
    }

    pub fn to_wire(&self) -> NodeRosterWire {
        NodeRosterWire {
            n: self.n,
            t: self.t,
            node_certificates: self.node_certificates.clone(),
            digest: self.digest,
        }
    }
}

impl From<NodeRoster> for NodeRosterWire {
    fn from(roster: NodeRoster) -> Self {
        Self {
            n: roster.n,
            t: roster.t,
            node_certificates: roster.node_certificates,
            digest: roster.digest,
        }
    }
}

/// Receiver side: the full check, in order, never re-sorting.
impl TryFrom<NodeRosterWire> for NodeRoster {
    type Error = RosterError;

    fn try_from(wire: NodeRosterWire) -> Result<Self, Self::Error> {
        check_shape(wire.n, wire.t, wire.node_certificates.len())?;
        let spkis = derive_spkis(&wire.node_certificates)?;
        if let Some(index) = (1..spkis.len()).find(|index| spkis[index - 1] >= spkis[*index]) {
            return Err(RosterError::NotCanonical { index });
        }
        check_unique_identities(spkis.iter().enumerate())?;
        if roster_digest(wire.n, wire.t, &spkis) != wire.digest {
            return Err(RosterError::DigestMismatch);
        }
        Ok(Self {
            n: wire.n,
            t: wire.t,
            node_certificates: wire.node_certificates,
            digest: wire.digest,
            spkis,
        })
    }
}

/// `Empty`, `ZeroThreshold`, `CountMismatch` and `ThresholdTooLarge`, in that order.
fn check_shape(n: u64, t: u64, certificates: usize) -> Result<(), RosterError> {
    if certificates == 0 {
        return Err(RosterError::Empty);
    }
    if t == 0 {
        return Err(RosterError::ZeroThreshold);
    }
    if n != certificates as u64 {
        return Err(RosterError::CountMismatch { n, certificates });
    }
    let too_large = t
        .checked_mul(2)
        .and_then(|double| double.checked_add(1))
        .is_none_or(|minimum| n < minimum);
    if too_large {
        return Err(RosterError::ThresholdTooLarge { n, t });
    }
    Ok(())
}

fn derive_spkis(certificates: &[NodeCertificateDer]) -> Result<Vec<SpkiDer>, RosterError> {
    certificates
        .iter()
        .enumerate()
        .map(|(index, certificate)| {
            SpkiDer::from_certificate_der(certificate.as_bytes())
                .map_err(|reason| RosterError::UnparseableCertificate { index, reason })
        })
        .collect()
}

/// Refuses two certificates whose `subject_public_key` BIT STRINGs are equal. `pairs` carries
/// each certificate's index as the caller reports it.
fn check_unique_identities<'a>(
    pairs: impl Iterator<Item = (usize, &'a SpkiDer)>,
) -> Result<(), RosterError> {
    let mut seen: HashMap<ClientIdentity, usize> = HashMap::new();
    for (index, spki) in pairs {
        if let Some(first) = seen.insert(spki.client_identity(), index) {
            return Err(RosterError::DuplicateKey {
                first: first.min(index),
                second: first.max(index),
            });
        }
    }
    Ok(())
}

/// The byte-exact roster digest, over keys rather than certificate bytes.
fn roster_digest(n: u64, t: u64, spkis: &[SpkiDer]) -> RosterDigest {
    let mut hasher = blake3::Hasher::new_derive_key(ROSTER_DIGEST_CONTEXT);
    hasher.update(&n.to_le_bytes());
    hasher.update(&t.to_le_bytes());
    for spki in spkis {
        hasher.update(&(spki.as_bytes().len() as u64).to_le_bytes());
        hasher.update(spki.as_bytes());
    }
    RosterDigest(*hasher.finalize().as_bytes())
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RosterError {
    #[error("the node roster is empty")]
    Empty,
    /// `t == 0`: every single node could reconstruct every client mask.
    #[error("the roster threshold is zero, so a single node could reconstruct every secret")]
    ZeroThreshold,
    #[error("node certificate {index} is refused: {reason}")]
    UnparseableCertificate { index: usize, reason: PinError },
    /// Two certificates share an SPKI, or share a `subject_public_key` BIT STRING. With the
    /// canonical layouts of `SpkiDer`, either means the same key.
    #[error("node certificates {first} and {second} carry the same key")]
    DuplicateKey { first: usize, second: usize },
    /// `n < 2t + 1`.
    #[error("a roster of {n} nodes cannot have threshold {t}: at least 2t + 1 nodes are required")]
    ThresholdTooLarge { n: u64, t: u64 },
    #[error("the roster declares {n} nodes but carries {certificates} certificates")]
    CountMismatch { n: u64, certificates: usize },
    #[error("node certificate {index} is out of canonical (ascending SPKI) order")]
    NotCanonical { index: usize },
    #[error("the served roster digest does not match its contents")]
    DigestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::test_certificates::{p256_certificate, with_spki};

    const GOLDEN_DIGEST: &str = "da7fa2fee0f97aaef9e77aa8534a2be721fbaf3ab26a52b5c2fd560f41a8e00d";

    fn shipped_node_certificates() -> Vec<NodeCertificateDer> {
        [
            include_bytes!("../tests/fixtures/ids/nodes/cert0.crt").as_slice(),
            include_bytes!("../tests/fixtures/ids/nodes/cert1.crt").as_slice(),
            include_bytes!("../tests/fixtures/ids/nodes/cert2.crt").as_slice(),
            include_bytes!("../tests/fixtures/ids/nodes/cert3.crt").as_slice(),
            include_bytes!("../tests/fixtures/ids/nodes/cert4.crt").as_slice(),
        ]
        .into_iter()
        .map(|der| NodeCertificateDer::from_der(der.to_vec()))
        .collect()
    }

    fn fresh_certificates(count: usize) -> Vec<NodeCertificateDer> {
        (0..count)
            .map(|_| NodeCertificateDer::from_der(p256_certificate().cert.der().to_vec()))
            .collect()
    }

    #[test]
    fn node_roster_golden_vector_matches_the_shipped_node_certificates() {
        let shipped = shipped_node_certificates();
        let roster = NodeRoster::new(1, shipped.clone()).unwrap();
        assert_eq!(roster.n(), 5);
        assert_eq!(roster.t(), 1);
        let expected_order = [3, 0, 1, 2, 4].map(|index| shipped[index].clone());
        assert_eq!(roster.node_certificates(), expected_order.as_slice());
        assert!(roster
            .node_spkis()
            .iter()
            .all(|spki| spki.as_bytes().len() == 91));
        assert_eq!(roster.digest().to_string(), GOLDEN_DIGEST);
        for (position, spki) in roster.node_spkis().iter().enumerate() {
            assert_eq!(roster.position_of(spki), Some(position));
        }
    }

    #[test]
    fn the_digest_is_deterministic_and_matches_a_hand_computation() {
        let certificates = fresh_certificates(4);
        let first = NodeRoster::new(1, certificates.clone()).unwrap();
        let mut reversed = certificates.clone();
        reversed.reverse();
        let second = NodeRoster::new(1, reversed).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.digest(), second.digest());

        // Computed here from the layout alone, independently of `roster_digest`.
        let mut spkis = certificates
            .iter()
            .map(|certificate| {
                use x509_parser::prelude::{FromDer, X509Certificate};
                let (_, parsed) = X509Certificate::from_der(certificate.as_bytes()).unwrap();
                parsed.public_key().raw.to_vec()
            })
            .collect::<Vec<_>>();
        spkis.sort();
        let mut layout = Vec::new();
        layout.extend_from_slice(&4u64.to_le_bytes());
        layout.extend_from_slice(&1u64.to_le_bytes());
        for spki in &spkis {
            layout.extend_from_slice(&(spki.len() as u64).to_le_bytes());
            layout.extend_from_slice(spki);
        }
        let by_hand = blake3::derive_key("stoffel-coordinator-node-roster-v1", &layout);
        assert_eq!(first.digest().as_bytes(), &by_hand);

        // The digest covers keys and the threshold, not certificate bytes.
        let other_threshold = NodeRoster::new(2, fresh_certificates(5)).unwrap();
        assert_ne!(other_threshold.digest(), first.digest());
    }

    #[test]
    fn node_roster_rejects_empty_zero_threshold_duplicate_and_undersized_rosters() {
        assert_eq!(NodeRoster::new(1, vec![]), Err(RosterError::Empty));
        assert_eq!(
            NodeRoster::new(0, fresh_certificates(3)),
            Err(RosterError::ZeroThreshold)
        );
        assert_eq!(
            NodeRoster::new(1, fresh_certificates(2)),
            Err(RosterError::ThresholdTooLarge { n: 2, t: 1 })
        );
        assert_eq!(
            NodeRoster::new(u64::MAX, fresh_certificates(3)),
            Err(RosterError::ThresholdTooLarge { n: 3, t: u64::MAX })
        );

        let mut duplicated = fresh_certificates(3);
        duplicated.push(duplicated[1].clone());
        assert_eq!(
            NodeRoster::new(1, duplicated),
            Err(RosterError::DuplicateKey {
                first: 1,
                second: 3
            })
        );

        // The same key re-issued in another certificate is the same SPKI and BIT STRING.
        let certified = p256_certificate();
        let reissued = rcgen::CertificateParams::new(vec!["reissued".to_string()])
            .unwrap()
            .self_signed(&certified.signing_key)
            .unwrap();
        assert_ne!(certified.cert.der().to_vec(), reissued.der().to_vec());
        let mut same_key = fresh_certificates(2);
        same_key.insert(
            0,
            NodeCertificateDer::from_der(certified.cert.der().to_vec()),
        );
        same_key.push(NodeCertificateDer::from_der(reissued.der().to_vec()));
        assert_eq!(
            NodeRoster::new(1, same_key),
            Err(RosterError::DuplicateKey {
                first: 0,
                second: 3
            })
        );

        // A second, compressed encoding of a member's key is refused before it could collide.
        let point = certified.signing_key.public_key_raw().to_vec();
        let public_key = p256::PublicKey::from_sec1_bytes(&point).unwrap();
        let compressed =
            p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&public_key, true);
        let mut compressed_spki = vec![0x30, 0x39];
        compressed_spki.extend_from_slice(&[
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00,
        ]);
        compressed_spki.extend_from_slice(compressed.as_bytes());
        let mut with_compressed = fresh_certificates(2);
        with_compressed.push(NodeCertificateDer::from_der(certified.cert.der().to_vec()));
        with_compressed.push(NodeCertificateDer::from_der(with_spki(
            certified.cert.der(),
            &compressed_spki,
        )));
        assert_eq!(
            NodeRoster::new(1, with_compressed),
            Err(RosterError::UnparseableCertificate {
                index: 3,
                reason: PinError::NonCanonicalPublicKey {
                    algorithm: crate::pin::KeyAlgorithm::EcdsaP256
                }
            })
        );
    }

    #[test]
    fn a_served_roster_out_of_order_or_with_a_wrong_digest_is_refused_with_a_typed_error() {
        let roster = NodeRoster::new(1, fresh_certificates(4)).unwrap();
        assert_eq!(NodeRoster::try_from(roster.to_wire()), Ok(roster.clone()));

        let mut out_of_order = roster.to_wire();
        out_of_order.node_certificates.swap(1, 2);
        assert_eq!(
            NodeRoster::try_from(out_of_order),
            Err(RosterError::NotCanonical { index: 2 })
        );

        let mut repeated = roster.to_wire();
        repeated.node_certificates[2] = repeated.node_certificates[1].clone();
        assert_eq!(
            NodeRoster::try_from(repeated),
            Err(RosterError::NotCanonical { index: 2 })
        );

        let mut wrong_digest = roster.to_wire();
        let mut bytes = *wrong_digest.digest.as_bytes();
        bytes[0] ^= 1;
        wrong_digest.digest = RosterDigest::from_bytes(bytes);
        assert_eq!(
            NodeRoster::try_from(wrong_digest),
            Err(RosterError::DigestMismatch)
        );

        let mut other_threshold = roster.to_wire();
        other_threshold.n = 4;
        other_threshold.t = 1;
        other_threshold.node_certificates.pop();
        assert_eq!(
            NodeRoster::try_from(other_threshold),
            Err(RosterError::CountMismatch {
                n: 4,
                certificates: 3
            })
        );

        let mut zero = roster.to_wire();
        zero.t = 0;
        assert_eq!(NodeRoster::try_from(zero), Err(RosterError::ZeroThreshold));

        let mut empty = roster.to_wire();
        empty.node_certificates.clear();
        assert_eq!(NodeRoster::try_from(empty), Err(RosterError::Empty));

        // Deserializing a `NodeRoster` runs the same check.
        let json = serde_json::to_string(&roster).unwrap();
        assert_eq!(serde_json::from_str::<NodeRoster>(&json).unwrap(), roster);
        let mut tampered = roster.to_wire();
        tampered.t = 2;
        tampered.n = 4;
        let json = serde_json::to_string(&tampered).unwrap();
        assert!(serde_json::from_str::<NodeRoster>(&json).is_err());
    }

    #[test]
    fn a_roster_digest_parses_and_displays_as_64_hex() {
        let digest = RosterDigest::from_bytes([0xab; 32]);
        let shown = digest.to_string();
        assert_eq!(shown, "ab".repeat(32));
        assert_eq!(shown.parse::<RosterDigest>(), Ok(digest));
        assert_eq!(shown.to_uppercase().parse::<RosterDigest>(), Ok(digest));
        assert_eq!(
            shown[..63].parse::<RosterDigest>(),
            Err(RosterDigestParseError::WrongLength { length: 63 })
        );
        assert_eq!(
            format!("{shown}a").parse::<RosterDigest>(),
            Err(RosterDigestParseError::WrongLength { length: 65 })
        );
        assert_eq!(
            format!("{}g{}", &shown[..10], &shown[11..]).parse::<RosterDigest>(),
            Err(RosterDigestParseError::NotHex { position: 10 })
        );
        assert_eq!(
            GOLDEN_DIGEST.parse::<RosterDigest>().unwrap().to_string(),
            GOLDEN_DIGEST
        );

        let certificate = NodeCertificateDer::from_der(vec![1, 2, 3]);
        assert_eq!(certificate.as_bytes(), &[1, 2, 3]);
    }
}
