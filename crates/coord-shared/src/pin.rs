//! Server pins and the one certificate-to-key derivation every identity check uses.
//!
//! A pin authenticates a *key*, never a certificate chain: the coordinator and every node
//! present self-signed certificates, so the only thing a caller can meaningfully check is
//! that the server proved possession of a key it already expected. Every certificate this
//! crate handles — server pins, roster certificates and RPC callers — goes through
//! [`SpkiDer::from_certificate_der`], so two identities compare equal exactly when they are
//! the same key.

use crate::roster::NodeRoster;
use crate::ClientIdentity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};
use x509_parser::prelude::{FromDer, X509Certificate};

/// DER of the P-256 `AlgorithmIdentifier` (`id-ecPublicKey`, `prime256v1`) followed by the
/// header of a 66-byte BIT STRING with zero unused bits.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
/// Length of an uncompressed SEC1 P-256 point.
const P256_POINT_LEN: usize = 65;
/// DER of the Ed25519 `AlgorithmIdentifier` (no parameters) followed by the header of a
/// 33-byte BIT STRING with zero unused bits.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// Length of an Ed25519 public key.
const ED25519_KEY_LEN: usize = 32;

/// DER SubjectPublicKeyInfo: exactly `X509Certificate::public_key().raw`, the bytes
/// stoffelnet authorizes against — never the inner BIT STRING.
/// Always in the canonical layout of its algorithm, so two values are equal exactly when
/// they are the same key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpkiDer(Vec<u8>);

/// The only key algorithms any certificate in this system may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// `id-ecPublicKey` (1.2.840.10045.2.1) with `namedCurve` `prime256v1` (1.2.840.10045.3.1.7).
    EcdsaP256,
    /// `id-Ed25519` (1.3.101.112).
    Ed25519,
}

impl KeyAlgorithm {
    /// The algorithm a canonical `ClientIdentity` names: 65 bytes starting `0x04` is
    /// `EcdsaP256`, 32 bytes is `Ed25519`, anything else `None`.
    pub fn of_client_identity(identity: &[u8]) -> Option<Self> {
        match identity.len() {
            P256_POINT_LEN if identity[0] == 0x04 => Some(Self::EcdsaP256),
            ED25519_KEY_LEN => Some(Self::Ed25519),
            _ => None,
        }
    }

    fn canonical_prefix(self) -> &'static [u8] {
        match self {
            Self::EcdsaP256 => &P256_SPKI_PREFIX,
            Self::Ed25519 => &ED25519_SPKI_PREFIX,
        }
    }
}

impl SpkiDer {
    /// The one derivation. Refuses unparseable input, trailing bytes after the
    /// certificate, any key algorithm other than `KeyAlgorithm`'s, and any encoding of an
    /// admitted key other than its canonical layout.
    pub fn from_certificate_der(cert_der: &[u8]) -> Result<Self, PinError> {
        let (remainder, certificate) = X509Certificate::from_der(cert_der).map_err(|error| {
            PinError::UnparseableCertificate {
                reason: error.to_string(),
            }
        })?;
        if !remainder.is_empty() {
            return Err(PinError::TrailingBytes {
                trailing: remainder.len(),
            });
        }

        let public_key = certificate.public_key();
        let algorithm = &public_key.algorithm;
        let key_algorithm = if algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let named_curve = algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.clone().oid().ok());
            match named_curve {
                Some(curve) if curve == OID_EC_P256 => KeyAlgorithm::EcdsaP256,
                Some(curve) => {
                    return Err(PinError::UnsupportedKeyAlgorithm {
                        algorithm: format!("{} with named curve {}", algorithm.algorithm, curve),
                    })
                }
                None => {
                    return Err(PinError::UnsupportedKeyAlgorithm {
                        algorithm: format!("{} without a named curve", algorithm.algorithm),
                    })
                }
            }
        } else if algorithm.algorithm == OID_SIG_ED25519 {
            KeyAlgorithm::Ed25519
        } else {
            return Err(PinError::UnsupportedKeyAlgorithm {
                algorithm: algorithm.algorithm.to_id_string(),
            });
        };

        let raw = public_key.raw;
        let non_canonical = PinError::NonCanonicalPublicKey {
            algorithm: key_algorithm,
        };
        let key = raw
            .strip_prefix(key_algorithm.canonical_prefix())
            .ok_or_else(|| non_canonical.clone())?;
        let canonical = match key_algorithm {
            KeyAlgorithm::EcdsaP256 => {
                key.len() == P256_POINT_LEN
                    && key[0] == 0x04
                    && p256::PublicKey::from_sec1_bytes(key).is_ok()
            }
            KeyAlgorithm::Ed25519 => key.len() == ED25519_KEY_LEN,
        };
        if !canonical {
            return Err(non_canonical);
        }
        Ok(Self(raw.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        if self.0.starts_with(&P256_SPKI_PREFIX) {
            KeyAlgorithm::EcdsaP256
        } else {
            KeyAlgorithm::Ed25519
        }
    }

    /// The coordinator identity form of the same key (`subject_public_key.data`).
    pub fn client_identity(&self) -> ClientIdentity {
        self.0[self.key_algorithm().canonical_prefix().len()..].to_vec()
    }
}

/// Which server keys a caller accepts. No variant accepts every key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerPin {
    /// The coordinator: exactly one key.
    Exact(SpkiDer),
    /// A node RPC listener: any one member of the node roster.
    RosterNode(RosterKeys),
}

/// Non-empty by construction: the field is private and the only constructor is
/// `ServerPin::roster_node`, which reads a verified `NodeRoster`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterKeys(BTreeSet<SpkiDer>);

impl ServerPin {
    pub fn roster_node(roster: &NodeRoster) -> Self {
        Self::RosterNode(RosterKeys(roster.node_spkis().into_iter().collect()))
    }

    pub fn admits(&self, spki: &SpkiDer) -> bool {
        match self {
            Self::Exact(pinned) => pinned == spki,
            Self::RosterNode(RosterKeys(members)) => members.contains(spki),
        }
    }
}

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinError {
    #[error("not a DER X.509 certificate: {reason}")]
    UnparseableCertificate { reason: String },
    #[error("{trailing} bytes follow the certificate")]
    TrailingBytes { trailing: usize },
    #[error("key algorithm {algorithm} is not ECDSA P-256 or Ed25519")]
    UnsupportedKeyAlgorithm { algorithm: String },
    #[error("the {algorithm:?} public key is not in its canonical SubjectPublicKeyInfo encoding")]
    NonCanonicalPublicKey { algorithm: KeyAlgorithm },
}

/// Certificate surgery shared by this crate's tests: builds certificates whose
/// SubjectPublicKeyInfo is a chosen byte string, which no certificate generator will emit.
#[cfg(test)]
pub(crate) mod test_certificates {
    /// Reads one DER header at `offset`, returning `(content_start, content_len)`.
    fn der_header(bytes: &[u8], offset: usize) -> (usize, usize) {
        let first = bytes[offset + 1];
        if first & 0x80 == 0 {
            return (offset + 2, first as usize);
        }
        let octets = (first & 0x7f) as usize;
        let len = bytes[offset + 2..offset + 2 + octets]
            .iter()
            .fold(0usize, |len, byte| (len << 8) | *byte as usize);
        (offset + 2 + octets, len)
    }

    fn der_sequence(content: &[u8]) -> Vec<u8> {
        let mut out = vec![0x30];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let octets = len.to_be_bytes();
            let significant = octets.iter().skip_while(|byte| **byte == 0).copied();
            let significant = significant.collect::<Vec<_>>();
            out.push(0x80 | significant.len() as u8);
            out.extend(significant);
        }
        out.extend_from_slice(content);
        out
    }

    /// `cert_der` with its SubjectPublicKeyInfo replaced by `new_spki`, lengths re-encoded.
    /// The signature no longer verifies, which the derivation never checks.
    pub(crate) fn with_spki(cert_der: &[u8], new_spki: &[u8]) -> Vec<u8> {
        use x509_parser::prelude::{FromDer, X509Certificate};
        let (_, certificate) = X509Certificate::from_der(cert_der).unwrap();
        let old_spki = certificate.public_key().raw.to_vec();

        let (outer_start, outer_len) = der_header(cert_der, 0);
        let (tbs_start, tbs_len) = der_header(cert_der, outer_start);
        let tbs_content = &cert_der[tbs_start..tbs_start + tbs_len];
        let tail = &cert_der[tbs_start + tbs_len..outer_start + outer_len];

        let position = tbs_content
            .windows(old_spki.len())
            .position(|window| window == old_spki.as_slice())
            .expect("the SPKI is part of the TBS certificate");
        let mut new_tbs_content = tbs_content[..position].to_vec();
        new_tbs_content.extend_from_slice(new_spki);
        new_tbs_content.extend_from_slice(&tbs_content[position + old_spki.len()..]);

        let mut outer_content = der_sequence(&new_tbs_content);
        outer_content.extend_from_slice(tail);
        der_sequence(&outer_content)
    }

    pub(crate) fn p256_certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec!["pin-test".to_string()]).unwrap()
    }

    pub(crate) fn ed25519_certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["pin-test".to_string()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        rcgen::CertifiedKey { cert, signing_key }
    }
}

#[cfg(test)]
mod tests {
    use super::test_certificates::{ed25519_certificate, p256_certificate, with_spki};
    use super::*;

    fn spki(prefix: &[u8], key: &[u8]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        out.extend_from_slice(key);
        out
    }

    #[test]
    fn a_pin_is_the_full_spki_of_its_certificate() {
        let certified = p256_certificate();
        let cert_der = certified.cert.der().to_vec();
        let (_, parsed) = X509Certificate::from_der(&cert_der).unwrap();
        let pin = SpkiDer::from_certificate_der(&cert_der).unwrap();
        assert_eq!(pin.as_bytes(), parsed.public_key().raw);
        assert_ne!(
            pin.as_bytes(),
            parsed.public_key().subject_public_key.data.as_ref()
        );
        assert_eq!(pin.as_bytes().len(), 91);
        assert_eq!(pin.key_algorithm(), KeyAlgorithm::EcdsaP256);
        assert_eq!(
            pin.client_identity(),
            parsed.public_key().subject_public_key.data.to_vec()
        );
        assert_eq!(
            pin.client_identity(),
            certified.signing_key.public_key_raw().to_vec()
        );

        let mut trailing = cert_der.clone();
        trailing.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            SpkiDer::from_certificate_der(&trailing),
            Err(PinError::TrailingBytes { trailing: 3 })
        );
        assert!(matches!(
            SpkiDer::from_certificate_der(&cert_der[..cert_der.len() - 1]),
            Err(PinError::UnparseableCertificate { .. })
        ));

        // The point of the accepted P-256 certificate, re-encoded.
        let point = certified.signing_key.public_key_raw().to_vec();
        let p256_algorithm = &P256_SPKI_PREFIX[2..23];

        // RSA (rsaEncryption with NULL parameters and an arbitrary key body).
        let rsa = rsa_spki();
        // P-384 (secp384r1) with a 97-byte point.
        let p384 = [
            &[0x30, 0x76, 0x30, 0x10, 0x06, 0x07][..],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            &[0x03, 0x62, 0x00, 0x04],
            &[0x11; 96],
        ]
        .concat();
        // id-ecPublicKey with explicit (non-OID) curve parameters and the same point.
        let explicit = [
            &[0x30, 0x5d, 0x30, 0x17, 0x06, 0x07][..],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            &[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
            ],
            &[0x03, 0x42, 0x00],
            &point,
        ]
        .concat();
        assert_eq!(
            SpkiDer::from_certificate_der(&with_spki(&cert_der, &rsa)),
            Err(PinError::UnsupportedKeyAlgorithm {
                algorithm: "1.2.840.113549.1.1.1".to_string()
            })
        );
        for unsupported in [rsa, p384, explicit] {
            assert!(
                matches!(
                    SpkiDer::from_certificate_der(&with_spki(&cert_der, &unsupported)),
                    Err(PinError::UnsupportedKeyAlgorithm { .. })
                ),
                "{unsupported:02x?} must be refused as an unsupported algorithm"
            );
        }
        // Non-canonical encodings of the same P-256 key.
        let p256 = p256::PublicKey::from_sec1_bytes(&point).unwrap();
        let compressed = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&p256, true);
        let compressed = compressed.as_bytes().to_vec();
        assert_eq!(compressed.len(), 33);
        let mut hybrid = point.clone();
        hybrid[0] = 0x06 | (point[64] & 1);
        let mut off_curve = point.clone();
        off_curve[64] ^= 0x01;
        let sequence_with = |key: &[u8]| {
            let bit_string_len = key.len() + 1;
            let mut out = vec![0x30, (p256_algorithm.len() + 2 + bit_string_len) as u8];
            out.extend_from_slice(p256_algorithm);
            out.extend_from_slice(&[0x03, bit_string_len as u8, 0x00]);
            out.extend_from_slice(key);
            out
        };
        let re_encodings = [
            sequence_with(&compressed),
            sequence_with(&hybrid),
            sequence_with(&off_curve),
        ];
        for re_encoding in re_encodings {
            assert_ne!(re_encoding, pin.as_bytes());
            assert_eq!(
                SpkiDer::from_certificate_der(&with_spki(&cert_der, &re_encoding)),
                Err(PinError::NonCanonicalPublicKey {
                    algorithm: KeyAlgorithm::EcdsaP256
                })
            );
        }

        // Ed25519 is accepted in its canonical form.
        let ed = ed25519_certificate();
        let ed_der = ed.cert.der().to_vec();
        let ed_pin = SpkiDer::from_certificate_der(&ed_der).unwrap();
        assert_eq!(ed_pin.key_algorithm(), KeyAlgorithm::Ed25519);
        assert_eq!(ed_pin.as_bytes().len(), 44);
        let ed_key = ed_pin.client_identity();
        assert_eq!(ed_key, ed.signing_key.public_key_raw().to_vec());

        // ... and refused with a NULL parameter, or at 31 or 33 bytes.
        let with_null = [
            &[
                0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00,
            ][..],
            &[0x03, 0x21, 0x00],
            &ed_key,
        ]
        .concat();
        let short = [
            &[0x30, 0x29][..],
            &ED25519_SPKI_PREFIX[2..9],
            &[0x03, 0x20, 0x00],
            &ed_key[..31],
        ]
        .concat();
        let long = [
            &[0x30, 0x2b][..],
            &ED25519_SPKI_PREFIX[2..9],
            &[0x03, 0x22, 0x00],
            &ed_key,
            &[0x00],
        ]
        .concat();
        assert_eq!(spki(&ED25519_SPKI_PREFIX, &ed_key), ed_pin.as_bytes());
        for re_encoding in [with_null, short, long] {
            assert_ne!(re_encoding, ed_pin.as_bytes());
            assert_eq!(
                SpkiDer::from_certificate_der(&with_spki(&ed_der, &re_encoding)),
                Err(PinError::NonCanonicalPublicKey {
                    algorithm: KeyAlgorithm::Ed25519
                })
            );
        }
    }

    fn rsa_spki() -> Vec<u8> {
        [
            &[0x30, 0x1c, 0x30, 0x0d][..],
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
            ],
            &[0x03, 0x0b, 0x00],
            &[0x30, 0x08, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x01, 0x03],
        ]
        .concat()
    }

    #[test]
    fn a_client_identity_names_its_algorithm_by_length() {
        let mut p256 = vec![0x04];
        p256.extend_from_slice(&[7; 64]);
        assert_eq!(
            KeyAlgorithm::of_client_identity(&p256),
            Some(KeyAlgorithm::EcdsaP256)
        );
        assert_eq!(
            KeyAlgorithm::of_client_identity(&[9; 32]),
            Some(KeyAlgorithm::Ed25519)
        );
        let mut hybrid = p256.clone();
        hybrid[0] = 0x06;
        assert_eq!(KeyAlgorithm::of_client_identity(&hybrid), None);
        assert_eq!(KeyAlgorithm::of_client_identity(&[2; 33]), None);
        assert_eq!(KeyAlgorithm::of_client_identity(&[]), None);
    }

    #[test]
    fn a_pin_admits_only_its_keys() {
        let first = SpkiDer::from_certificate_der(p256_certificate().cert.der()).unwrap();
        let second = SpkiDer::from_certificate_der(p256_certificate().cert.der()).unwrap();
        let pin = ServerPin::Exact(first.clone());
        assert!(pin.admits(&first));
        assert!(!pin.admits(&second));
    }
}
