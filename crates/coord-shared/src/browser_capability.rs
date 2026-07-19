//! Verification for signed browser MPC capability tokens.
//!
//! The token format is `base64url(canonical JSON).base64url(Ed25519 signature)`, with no
//! padding in either component. This module only handles public verification keys; token issuance
//! and replay storage belong elsewhere.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hpke::{kem::DhP256HkdfSha256, Deserializable, Kem};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The only capability token version understood by this module.
pub const CAPABILITY_TOKEN_VERSION: u8 = 1;

/// The coordinator's current client identity representation.
pub type ClientIdentity = Vec<u8>;
type BrowserHpkePublicKey = <DhP256HkdfSha256 as Kem>::PublicKey;

/// Claims in their canonical serialization order.
///
/// `browser_hpke_public_key` is base64url without padding. Struct field order is intentionally part
/// of the signed format; map-shaped claims are not accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserCapabilityClaims {
    pub version: u8,
    pub issuer: String,
    pub audience: String,
    pub room_id: String,
    pub session_id: String,
    pub client_slot: u8,
    pub input_start_index: u64,
    pub input_count: u64,
    pub can_obtain_output: bool,
    pub browser_hpke_public_key: String,
    pub allowed_origin: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

impl BrowserCapabilityClaims {
    /// Serialize claims exactly as they must appear in the signed payload.
    pub fn canonical_payload(&self) -> Result<Vec<u8>, CapabilityTokenError> {
        serde_json::to_vec(self).map_err(|_| CapabilityTokenError::InvalidClaims)
    }
}

/// A verified capability and values suitable for coordinator authorization/replay checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBrowserCapability {
    pub claims: BrowserCapabilityClaims,
    pub client_identity: ClientIdentity,
    pub replay_key: ReplayKey,
}

/// Issuer-scoped nonce used by an external replay cache.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    pub issuer: String,
    pub nonce: String,
}

/// Public configuration for capability verification.
#[derive(Clone, Debug)]
pub struct BrowserCapabilityVerifier {
    trusted_issuer: String,
    trusted_issuer_public_key: Vec<u8>,
    audience: String,
    clock_skew_seconds: u64,
}

impl BrowserCapabilityVerifier {
    /// Configure a verifier with a raw 32-byte Ed25519 issuer public key.
    pub fn new(
        trusted_issuer: impl Into<String>,
        trusted_issuer_public_key: impl AsRef<[u8]>,
        audience: impl Into<String>,
        clock_skew_seconds: u64,
    ) -> Result<Self, CapabilityTokenError> {
        let trusted_issuer_public_key = trusted_issuer_public_key.as_ref();
        if trusted_issuer_public_key.len() != 32 {
            return Err(CapabilityTokenError::InvalidIssuerPublicKey);
        }

        Ok(Self {
            trusted_issuer: trusted_issuer.into(),
            trusted_issuer_public_key: trusted_issuer_public_key.to_vec(),
            audience: audience.into(),
            clock_skew_seconds,
        })
    }

    /// Verify a token against the request's exact `Origin` value and a Unix timestamp in seconds.
    pub fn verify(
        &self,
        token: &str,
        request_origin: &str,
        now: u64,
    ) -> Result<VerifiedBrowserCapability, CapabilityTokenError> {
        let mut components = token.split('.');
        let payload_component = components
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(CapabilityTokenError::MalformedToken)?;
        let signature_component = components
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(CapabilityTokenError::MalformedToken)?;
        if components.next().is_some() {
            return Err(CapabilityTokenError::MalformedToken);
        }

        let payload = URL_SAFE_NO_PAD
            .decode(payload_component)
            .map_err(|_| CapabilityTokenError::MalformedToken)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_component)
            .map_err(|_| CapabilityTokenError::MalformedToken)?;

        UnparsedPublicKey::new(&ED25519, &self.trusted_issuer_public_key)
            .verify(&payload, &signature)
            .map_err(|_| CapabilityTokenError::InvalidSignature)?;

        let claims: BrowserCapabilityClaims =
            serde_json::from_slice(&payload).map_err(|_| CapabilityTokenError::InvalidClaims)?;
        if claims.canonical_payload()? != payload {
            return Err(CapabilityTokenError::NonCanonicalPayload);
        }

        if claims.version != CAPABILITY_TOKEN_VERSION {
            return Err(CapabilityTokenError::UnsupportedVersion);
        }
        if claims.issuer != self.trusted_issuer {
            return Err(CapabilityTokenError::WrongIssuer);
        }
        if claims.audience != self.audience {
            return Err(CapabilityTokenError::WrongAudience);
        }
        if claims.allowed_origin != request_origin {
            return Err(CapabilityTokenError::WrongOrigin);
        }
        if claims.client_slot > 2 {
            return Err(CapabilityTokenError::InvalidClientSlot);
        }
        if claims.input_count == 0 {
            return Err(CapabilityTokenError::ZeroInputCount);
        }
        claims
            .input_start_index
            .checked_add(claims.input_count)
            .ok_or(CapabilityTokenError::InputRangeOverflow)?;

        if claims.issued_at > now.saturating_add(self.clock_skew_seconds) {
            return Err(CapabilityTokenError::IssuedInFuture);
        }
        if claims.expires_at.saturating_add(self.clock_skew_seconds) < now {
            return Err(CapabilityTokenError::Expired);
        }

        let client_identity = URL_SAFE_NO_PAD
            .decode(&claims.browser_hpke_public_key)
            .map_err(|_| CapabilityTokenError::InvalidHpkePublicKey)?;
        BrowserHpkePublicKey::from_bytes(&client_identity)
            .map_err(|_| CapabilityTokenError::InvalidHpkePublicKey)?;
        if claims.nonce.is_empty() {
            return Err(CapabilityTokenError::InvalidNonce);
        }

        let replay_key = ReplayKey {
            issuer: claims.issuer.clone(),
            nonce: claims.nonce.clone(),
        };
        Ok(VerifiedBrowserCapability {
            claims,
            client_identity,
            replay_key,
        })
    }
}

/// Capability verification failures. Variants deliberately contain no token or key material.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CapabilityTokenError {
    #[error("malformed capability token")]
    MalformedToken,
    #[error("invalid capability claims")]
    InvalidClaims,
    #[error("capability payload is not canonical")]
    NonCanonicalPayload,
    #[error("invalid issuer public key")]
    InvalidIssuerPublicKey,
    #[error("invalid capability signature")]
    InvalidSignature,
    #[error("unsupported capability token version")]
    UnsupportedVersion,
    #[error("capability issuer does not match")]
    WrongIssuer,
    #[error("capability audience does not match")]
    WrongAudience,
    #[error("capability origin does not match")]
    WrongOrigin,
    #[error("invalid client slot")]
    InvalidClientSlot,
    #[error("input count must be nonzero")]
    ZeroInputCount,
    #[error("input range overflows")]
    InputRangeOverflow,
    #[error("capability token is not yet valid")]
    IssuedInFuture,
    #[error("capability token has expired")]
    Expired,
    #[error("invalid browser HPKE public key")]
    InvalidHpkePublicKey,
    #[error("invalid capability nonce")]
    InvalidNonce,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Serializable;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const NOW: u64 = 1_700_000_000;
    const ORIGIN: &str = "https://app.example";
    const ISSUER: &str = "stoffel-auth";
    const AUDIENCE: &str = "coordinator-1";

    fn key_pair() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn claims() -> BrowserCapabilityClaims {
        let (_, browser_public_key) = DhP256HkdfSha256::derive_keypair(&[7_u8; 32]);
        BrowserCapabilityClaims {
            version: CAPABILITY_TOKEN_VERSION,
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            room_id: "room-7".into(),
            session_id: "session-9".into(),
            client_slot: 1,
            input_start_index: 8,
            input_count: 3,
            can_obtain_output: true,
            browser_hpke_public_key: URL_SAFE_NO_PAD.encode(browser_public_key.to_bytes()),
            allowed_origin: ORIGIN.into(),
            issued_at: NOW - 30,
            expires_at: NOW + 60,
            nonce: "unique-token-nonce".into(),
        }
    }

    fn sign(key_pair: &Ed25519KeyPair, claims: &BrowserCapabilityClaims) -> String {
        let payload = claims.canonical_payload().unwrap();
        let signature = key_pair.sign(&payload);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn verifier(key_pair: &Ed25519KeyPair) -> BrowserCapabilityVerifier {
        BrowserCapabilityVerifier::new(ISSUER, key_pair.public_key().as_ref(), AUDIENCE, 5).unwrap()
    }

    #[test]
    fn verifies_valid_token_and_derives_stable_identity_and_replay_key() {
        let key_pair = key_pair();
        let token = sign(&key_pair, &claims());
        let verifier = verifier(&key_pair);

        let first = verifier.verify(&token, ORIGIN, NOW).unwrap();
        let second = verifier.verify(&token, ORIGIN, NOW).unwrap();

        let expected_identity = URL_SAFE_NO_PAD
            .decode(claims().browser_hpke_public_key)
            .unwrap();
        assert_eq!(first.client_identity, expected_identity);
        assert_eq!(first.client_identity, second.client_identity);
        assert_eq!(first.replay_key, second.replay_key);
        assert_eq!(first.replay_key.issuer, ISSUER);
        assert_eq!(first.replay_key.nonce, "unique-token-nonce");
    }

    #[test]
    fn rejects_tampered_payload_and_signature() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        let token = sign(&key_pair, &claims());
        let (payload, signature) = token.split_once('.').unwrap();

        let mut payload_bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        payload_bytes[0] ^= 1;
        let tampered_payload = format!("{}.{}", URL_SAFE_NO_PAD.encode(payload_bytes), signature);
        assert_eq!(
            verifier.verify(&tampered_payload, ORIGIN, NOW),
            Err(CapabilityTokenError::InvalidSignature)
        );

        let mut signature_bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        signature_bytes[0] ^= 1;
        let tampered_signature = format!("{}.{}", payload, URL_SAFE_NO_PAD.encode(signature_bytes));
        assert_eq!(
            verifier.verify(&tampered_signature, ORIGIN, NOW),
            Err(CapabilityTokenError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_wrong_audience_and_origin() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        let mut wrong_audience = claims();
        wrong_audience.audience = "node-2".into();
        assert_eq!(
            verifier.verify(&sign(&key_pair, &wrong_audience), ORIGIN, NOW),
            Err(CapabilityTokenError::WrongAudience)
        );
        assert_eq!(
            verifier.verify(&sign(&key_pair, &claims()), "https://evil.example", NOW),
            Err(CapabilityTokenError::WrongOrigin)
        );
    }

    #[test]
    fn rejects_expired_and_future_tokens_outside_skew() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        let mut expired = claims();
        expired.expires_at = NOW - 6;
        assert_eq!(
            verifier.verify(&sign(&key_pair, &expired), ORIGIN, NOW),
            Err(CapabilityTokenError::Expired)
        );

        let mut future = claims();
        future.issued_at = NOW + 6;
        assert_eq!(
            verifier.verify(&sign(&key_pair, &future), ORIGIN, NOW),
            Err(CapabilityTokenError::IssuedInFuture)
        );
    }

    #[test]
    fn rejects_zero_input_count_and_overflowed_range() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        let mut zero = claims();
        zero.input_count = 0;
        assert_eq!(
            verifier.verify(&sign(&key_pair, &zero), ORIGIN, NOW),
            Err(CapabilityTokenError::ZeroInputCount)
        );

        let mut overflow = claims();
        overflow.input_start_index = u64::MAX;
        overflow.input_count = 1;
        assert_eq!(
            verifier.verify(&sign(&key_pair, &overflow), ORIGIN, NOW),
            Err(CapabilityTokenError::InputRangeOverflow)
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_a_p256_hpke_public_key() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        let mut invalid = claims();
        invalid.browser_hpke_public_key = URL_SAFE_NO_PAD.encode([9, 8, 7, 6]);

        assert_eq!(
            verifier.verify(&sign(&key_pair, &invalid), ORIGIN, NOW),
            Err(CapabilityTokenError::InvalidHpkePublicKey)
        );
    }

    #[test]
    fn rejects_malformed_tokens_and_noncanonical_claims() {
        let key_pair = key_pair();
        let verifier = verifier(&key_pair);
        for token in ["", "one", "one.two.three", ".signature", "payload."] {
            assert_eq!(
                verifier.verify(token, ORIGIN, NOW),
                Err(CapabilityTokenError::MalformedToken)
            );
        }

        let canonical = claims().canonical_payload().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        let noncanonical = serde_json::to_vec_pretty(&value).unwrap();
        let signature = key_pair.sign(&noncanonical);
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(noncanonical),
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        );
        assert_eq!(
            verifier.verify(&token, ORIGIN, NOW),
            Err(CapabilityTokenError::NonCanonicalPayload)
        );
    }
}
