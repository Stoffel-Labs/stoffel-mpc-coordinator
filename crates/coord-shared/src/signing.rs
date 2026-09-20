//! Signatures that keep the coordinator out of the integrity of client inputs and outputs.
//!
//! A client signs its slot's masked inputs with its certificate key, and a node signs every
//! sealed output it sends with its own. Both messages bind the execution, its registration
//! nonce and the slot, so the coordinator that relays them can neither alter them nor replay
//! them into another registration of the same `ExecutionId`.

use crate::admission::{ClientIndex, RegistrationNonce};
use crate::pin::KeyAlgorithm;
use crate::{ClientIdentity, ExecutionId};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ED25519,
};
use serde::{Deserialize, Serialize};

const MASKED_INPUTS_DOMAIN: &[u8] = b"stoffel-masked-inputs-v1";
const SEALED_OUTPUT_DOMAIN: &[u8] = b"stoffel-sealed-output-v1";

#[derive(thiserror::Error, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureError {
    #[error("the key is not a supported key of the named algorithm")]
    UnsupportedKey,
    #[error("signing failed")]
    SigningFailed,
    #[error("the signature does not verify")]
    BadSignature,
}

/// Signs `message` with a PKCS#8 key: ECDSA P-256 / SHA-256 with an ASN.1 DER signature, or
/// Ed25519.
pub fn sign_with_pkcs8(
    algorithm: KeyAlgorithm,
    pkcs8: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    match algorithm {
        KeyAlgorithm::EcdsaP256 => {
            let random = SystemRandom::new();
            let key_pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &random)
                    .map_err(|_| SignatureError::UnsupportedKey)?;
            key_pair
                .sign(&random, message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| SignatureError::SigningFailed)
        }
        KeyAlgorithm::Ed25519 => {
            let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
                .map_err(|_| SignatureError::UnsupportedKey)?;
            Ok(key_pair.sign(message).as_ref().to_vec())
        }
    }
}

/// Verifies `signature` over `message` against a canonical `ClientIdentity`, taking the
/// algorithm from `KeyAlgorithm::of_client_identity`.
pub fn verify_identity_signature(
    identity: &ClientIdentity,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let algorithm: &dyn ring::signature::VerificationAlgorithm =
        match KeyAlgorithm::of_client_identity(identity) {
            Some(KeyAlgorithm::EcdsaP256) => &ECDSA_P256_SHA256_ASN1,
            Some(KeyAlgorithm::Ed25519) => &ED25519,
            None => return Err(SignatureError::UnsupportedKey),
        };
    UnparsedPublicKey::new(algorithm, identity)
        .verify(message, signature)
        .map_err(|_| SignatureError::BadSignature)
}

/// ```text
/// b"stoffel-masked-inputs-v1"                    24 bytes, ASCII, no terminator
/// execution_id                                   32 bytes
/// registration_nonce                             32 bytes
/// client_index as u32                             4 bytes little-endian
/// first_index as u64                              8 bytes little-endian
/// masked_inputs.len() as u64                      8 bytes little-endian
/// per masked input, ascending index:
///     len as u64                                  8 bytes little-endian
///     bytes                                       len bytes
/// ```
pub fn masked_inputs_signing_bytes(
    execution_id: ExecutionId,
    registration_nonce: RegistrationNonce,
    client_index: ClientIndex,
    first_index: u64,
    masked_inputs: &[Vec<u8>],
) -> Vec<u8> {
    let inputs_len = masked_inputs
        .iter()
        .map(|input| 8 + input.len())
        .sum::<usize>();
    let mut bytes =
        Vec::with_capacity(MASKED_INPUTS_DOMAIN.len() + 2 * 32 + 4 + 8 + 8 + inputs_len);
    bytes.extend_from_slice(MASKED_INPUTS_DOMAIN);
    bytes.extend_from_slice(execution_id.as_bytes());
    bytes.extend_from_slice(registration_nonce.as_bytes());
    bytes.extend_from_slice(&client_index.0.to_le_bytes());
    bytes.extend_from_slice(&first_index.to_le_bytes());
    bytes.extend_from_slice(&(masked_inputs.len() as u64).to_le_bytes());
    for input in masked_inputs {
        bytes.extend_from_slice(&(input.len() as u64).to_le_bytes());
        bytes.extend_from_slice(input);
    }
    bytes
}

/// ```text
/// b"stoffel-sealed-output-v1"                 24 bytes, ASCII, no terminator
/// execution_id                                32 bytes
/// registration_nonce                          32 bytes
/// client_index as u32                          4 bytes little-endian
/// node_position as u32                         4 bytes little-endian
/// encapsulated_key.len() as u64, encapsulated_key
/// ciphertext.len() as u64, ciphertext
/// ```
pub fn sealed_output_signing_bytes(
    execution_id: ExecutionId,
    registration_nonce: RegistrationNonce,
    client_index: ClientIndex,
    node_position: u32,
    encapsulated_key: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        SEALED_OUTPUT_DOMAIN.len() + 2 * 32 + 8 + 16 + encapsulated_key.len() + ciphertext.len(),
    );
    bytes.extend_from_slice(SEALED_OUTPUT_DOMAIN);
    bytes.extend_from_slice(execution_id.as_bytes());
    bytes.extend_from_slice(registration_nonce.as_bytes());
    bytes.extend_from_slice(&client_index.0.to_le_bytes());
    bytes.extend_from_slice(&node_position.to_le_bytes());
    bytes.extend_from_slice(&(encapsulated_key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(encapsulated_key);
    bytes.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    bytes.extend_from_slice(ciphertext);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::test_certificates::{ed25519_certificate, p256_certificate};
    use crate::pin::SpkiDer;

    #[test]
    fn masked_input_and_sealed_output_signatures_have_the_documented_layout_and_bind_every_field() {
        let execution_id = ExecutionId::from_bytes([0x01; 32]);
        let nonce = RegistrationNonce::from_bytes([0x02; 32]);
        let inputs = vec![vec![0xaa; 3], vec![0xbb; 2]];

        let masked = masked_inputs_signing_bytes(execution_id, nonce, ClientIndex(5), 7, &inputs);
        let mut expected = b"stoffel-masked-inputs-v1".to_vec();
        assert_eq!(expected.len(), 24);
        expected.extend_from_slice(&[0x01; 32]);
        expected.extend_from_slice(&[0x02; 32]);
        expected.extend_from_slice(&5u32.to_le_bytes());
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(&3u64.to_le_bytes());
        expected.extend_from_slice(&[0xaa; 3]);
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(&[0xbb; 2]);
        assert_eq!(masked, expected);

        let sealed = sealed_output_signing_bytes(
            execution_id,
            nonce,
            ClientIndex(5),
            3,
            &[0xcc; 4],
            &[0xdd; 6],
        );
        let mut expected = b"stoffel-sealed-output-v1".to_vec();
        assert_eq!(expected.len(), 24);
        expected.extend_from_slice(&[0x01; 32]);
        expected.extend_from_slice(&[0x02; 32]);
        expected.extend_from_slice(&5u32.to_le_bytes());
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(&[0xcc; 4]);
        expected.extend_from_slice(&6u64.to_le_bytes());
        expected.extend_from_slice(&[0xdd; 6]);
        assert_eq!(sealed, expected);

        let p256 = p256_certificate();
        let ed = ed25519_certificate();
        for (certified, algorithm) in [
            (&p256, KeyAlgorithm::EcdsaP256),
            (&ed, KeyAlgorithm::Ed25519),
        ] {
            let identity = SpkiDer::from_certificate_der(certified.cert.der())
                .unwrap()
                .client_identity();
            let pkcs8 = certified.signing_key.serialize_der();

            let signature = sign_with_pkcs8(algorithm, &pkcs8, &masked).unwrap();
            assert_eq!(
                verify_identity_signature(&identity, &masked, &signature),
                Ok(())
            );
            let variants = [
                masked_inputs_signing_bytes(
                    execution_id,
                    RegistrationNonce::from_bytes([0x03; 32]),
                    ClientIndex(5),
                    7,
                    &inputs,
                ),
                masked_inputs_signing_bytes(execution_id, nonce, ClientIndex(6), 7, &inputs),
                masked_inputs_signing_bytes(execution_id, nonce, ClientIndex(5), 8, &inputs),
                masked_inputs_signing_bytes(
                    execution_id,
                    nonce,
                    ClientIndex(5),
                    7,
                    &[vec![0xaa; 3], vec![0xbb, 0xbc]],
                ),
            ];
            for variant in variants {
                assert_eq!(
                    verify_identity_signature(&identity, &variant, &signature),
                    Err(SignatureError::BadSignature)
                );
            }

            let signature = sign_with_pkcs8(algorithm, &pkcs8, &sealed).unwrap();
            assert_eq!(
                verify_identity_signature(&identity, &sealed, &signature),
                Ok(())
            );
            let variants = [
                sealed_output_signing_bytes(
                    execution_id,
                    nonce,
                    ClientIndex(5),
                    4,
                    &[0xcc; 4],
                    &[0xdd; 6],
                ),
                sealed_output_signing_bytes(
                    execution_id,
                    nonce,
                    ClientIndex(5),
                    3,
                    &[0xcc; 5],
                    &[0xdd; 6],
                ),
                sealed_output_signing_bytes(
                    execution_id,
                    nonce,
                    ClientIndex(5),
                    3,
                    &[0xcc; 4],
                    &[0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xde],
                ),
            ];
            for variant in variants {
                assert_eq!(
                    verify_identity_signature(&identity, &variant, &signature),
                    Err(SignatureError::BadSignature)
                );
            }
        }

        // A signature from another key fails, and a key of the wrong algorithm cannot sign.
        let other = p256_certificate();
        let other_identity = SpkiDer::from_certificate_der(other.cert.der())
            .unwrap()
            .client_identity();
        let signature = sign_with_pkcs8(
            KeyAlgorithm::EcdsaP256,
            &p256.signing_key.serialize_der(),
            &masked,
        )
        .unwrap();
        assert_eq!(
            verify_identity_signature(&other_identity, &masked, &signature),
            Err(SignatureError::BadSignature)
        );
        assert_eq!(
            sign_with_pkcs8(
                KeyAlgorithm::EcdsaP256,
                &ed.signing_key.serialize_der(),
                &masked
            ),
            Err(SignatureError::UnsupportedKey)
        );
        assert_eq!(
            verify_identity_signature(&vec![0x02; 33], &masked, &signature),
            Err(SignatureError::UnsupportedKey)
        );
    }
}
