//! Input mask retrieval endpoint for MPC clients
//!
//! This module implements the GET /mpc/masks endpoint that allows
//! MPC clients to retrieve their reserved input masks. These masks
//! are used in the Stoffel MPC protocol to blind client inputs.
//!
//! Security:
//! - Requests must be signed by the client's Ed25519 key
//! - Timestamps must be recent (within 30 seconds)
//! - Clients can only retrieve masks they reserved
//! - Each mask can only be retrieved once

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::AppState;
use crate::types::ApiError;

/// Storage for reserved input masks
#[derive(Clone, Default)]
pub struct MaskStore {
    /// Maps (coordinator_pda, index) -> MaskEntry
    masks: Arc<RwLock<HashMap<(String, u32), MaskEntry>>>,
}

/// A reserved input mask entry
#[derive(Clone)]
pub struct MaskEntry {
    /// The mask value (typically 32 bytes)
    pub mask_value: Vec<u8>,
    /// Client who reserved this mask
    pub client_id: String,
    /// Whether the mask has been retrieved
    pub retrieved: bool,
    /// When the mask was reserved
    pub reserved_at: u64,
}

/// Query parameters for mask retrieval
#[derive(Debug, Deserialize)]
pub struct MaskQuery {
    /// Request timestamp (Unix seconds)
    pub timestamp: u64,
    /// Ed25519 signature over: timestamp || coordinator_pda || index
    pub signature: String,
    /// Client's public key (hex encoded)
    pub client_pubkey: String,
}

/// Response containing the mask value
#[derive(Debug, Serialize)]
pub struct MaskResponse {
    /// The mask value (base64 encoded)
    pub mask_value: String,
    /// Mask index
    pub index: u32,
    /// Coordinator PDA
    pub coordinator_pda: String,
}

impl MaskStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a mask for a client
    pub async fn reserve_mask(
        &self,
        coordinator_pda: &str,
        index: u32,
        client_id: &str,
        mask_value: Vec<u8>,
    ) -> Result<(), String> {
        let mut masks = self.masks.write().await;
        let key = (coordinator_pda.to_string(), index);

        if masks.contains_key(&key) {
            return Err("Mask already reserved at this index".to_string());
        }

        masks.insert(
            key,
            MaskEntry {
                mask_value,
                client_id: client_id.to_string(),
                retrieved: false,
                reserved_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        );

        Ok(())
    }

    /// Retrieve a mask (marks it as retrieved)
    pub async fn retrieve_mask(
        &self,
        coordinator_pda: &str,
        index: u32,
        client_id: &str,
    ) -> Result<Vec<u8>, MaskError> {
        let mut masks = self.masks.write().await;
        let key = (coordinator_pda.to_string(), index);

        match masks.get_mut(&key) {
            Some(entry) => {
                if entry.client_id != client_id {
                    return Err(MaskError::NotOwner);
                }
                if entry.retrieved {
                    return Err(MaskError::AlreadyRetrieved);
                }
                entry.retrieved = true;
                Ok(entry.mask_value.clone())
            }
            None => Err(MaskError::NotFound),
        }
    }

    /// Check if a mask exists without retrieving it
    pub async fn mask_exists(&self, coordinator_pda: &str, index: u32) -> bool {
        let masks = self.masks.read().await;
        masks.contains_key(&(coordinator_pda.to_string(), index))
    }
}

/// Errors that can occur during mask operations
#[derive(Debug)]
pub enum MaskError {
    NotFound,
    NotOwner,
    AlreadyRetrieved,
    InvalidSignature,
    StaleTimestamp,
    InvalidCoordinatorPda,
}

/// Verify Ed25519 signature
///
/// TODO: Implement actual Ed25519 verification using ed25519-dalek
fn verify_signature(
    message: &[u8],
    signature: &str,
    public_key: &str,
) -> Result<(), MaskError> {
    // Placeholder - will be implemented with ed25519-dalek
    // For now, reject obviously invalid signatures
    if signature.is_empty() || public_key.is_empty() {
        return Err(MaskError::InvalidSignature);
    }

    // Decode signature from hex
    let _sig_bytes = hex::decode(signature).map_err(|_| MaskError::InvalidSignature)?;
    let _pk_bytes = hex::decode(public_key).map_err(|_| MaskError::InvalidSignature)?;

    // TODO: Actual verification
    // let public_key = ed25519_dalek::PublicKey::from_bytes(&pk_bytes)?;
    // let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes)?;
    // public_key.verify(message, &signature)?;

    Ok(())
}

/// Check if timestamp is recent (within 30 seconds)
fn validate_timestamp(timestamp: u64) -> Result<(), MaskError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let max_age = 30; // seconds
    if now.saturating_sub(timestamp) > max_age {
        return Err(MaskError::StaleTimestamp);
    }
    if timestamp > now + 5 {
        // Allow 5 second clock skew into future
        return Err(MaskError::StaleTimestamp);
    }

    Ok(())
}

/// GET /mpc/masks/{coordinator_pda}/{index}
///
/// Retrieve a reserved input mask for MPC computation.
///
/// The request must be signed by the client that reserved the mask.
/// Each mask can only be retrieved once.
pub async fn get_mask(
    State(_state): State<AppState>,
    Path((coordinator_pda, index)): Path<(String, u32)>,
    Query(query): Query<MaskQuery>,
) -> Result<Json<MaskResponse>, (StatusCode, Json<ApiError>)> {
    // Validate coordinator PDA format (base58 Solana address)
    if coordinator_pda.len() < 32 || coordinator_pda.len() > 44 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "INVALID_COORDINATOR_PDA",
                "coordinator_pda must be a valid base58 address",
            )),
        ));
    }

    // Validate timestamp freshness
    validate_timestamp(query.timestamp).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError::new(
                "STALE_TIMESTAMP",
                "Request timestamp is too old (max 30 seconds)",
            )),
        )
    })?;

    // Build message for signature verification: timestamp || coordinator_pda || index
    let mut message = Vec::new();
    message.extend_from_slice(&query.timestamp.to_le_bytes());
    message.extend_from_slice(coordinator_pda.as_bytes());
    message.extend_from_slice(&index.to_le_bytes());

    // Verify signature
    verify_signature(&message, &query.signature, &query.client_pubkey).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError::new(
                "INVALID_SIGNATURE",
                "Request signature is invalid",
            )),
        )
    })?;

    // TODO: Look up mask from store
    // For now, return placeholder
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiError::new(
            "NOT_IMPLEMENTED",
            "Mask retrieval not yet implemented",
        )),
    ))
}

// Hex encoding/decoding utilities
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }

    pub fn _encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // MaskStore Unit Tests
    // ============================================================================

    #[tokio::test]
    async fn test_mask_store_reserve_and_retrieve() {
        let store = MaskStore::new();

        // Reserve a mask
        let result = store
            .reserve_mask("coord123", 0, "client-a", vec![0xAA; 32])
            .await;
        assert!(result.is_ok());

        // Retrieve the mask
        let mask = store.retrieve_mask("coord123", 0, "client-a").await;
        assert!(mask.is_ok());
        assert_eq!(mask.unwrap(), vec![0xAA; 32]);
    }

    #[tokio::test]
    async fn test_mask_store_prevents_duplicate_reservation() {
        let store = MaskStore::new();

        // First reservation succeeds
        let result1 = store
            .reserve_mask("coord123", 0, "client-a", vec![0xAA; 32])
            .await;
        assert!(result1.is_ok());

        // Second reservation at same index fails
        let result2 = store
            .reserve_mask("coord123", 0, "client-b", vec![0xBB; 32])
            .await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_mask_store_retrieval_requires_ownership() {
        let store = MaskStore::new();

        // Client A reserves
        store
            .reserve_mask("coord123", 0, "client-a", vec![0xAA; 32])
            .await
            .unwrap();

        // Client B tries to retrieve - should fail
        let result = store.retrieve_mask("coord123", 0, "client-b").await;
        assert!(matches!(result, Err(MaskError::NotOwner)));
    }

    #[tokio::test]
    async fn test_mask_store_single_retrieval_only() {
        let store = MaskStore::new();

        // Reserve and retrieve once
        store
            .reserve_mask("coord123", 0, "client-a", vec![0xAA; 32])
            .await
            .unwrap();
        let result1 = store.retrieve_mask("coord123", 0, "client-a").await;
        assert!(result1.is_ok());

        // Second retrieval fails
        let result2 = store.retrieve_mask("coord123", 0, "client-a").await;
        assert!(matches!(result2, Err(MaskError::AlreadyRetrieved)));
    }

    #[tokio::test]
    async fn test_mask_store_not_found() {
        let store = MaskStore::new();

        let result = store.retrieve_mask("coord123", 0, "client-a").await;
        assert!(matches!(result, Err(MaskError::NotFound)));
    }

    // ============================================================================
    // Timestamp Validation Tests
    // ============================================================================

    #[test]
    fn test_validate_timestamp_accepts_recent() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(validate_timestamp(now).is_ok());
        assert!(validate_timestamp(now - 10).is_ok());
        assert!(validate_timestamp(now - 29).is_ok());
    }

    #[test]
    fn test_validate_timestamp_rejects_old() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 31 seconds ago is too old
        assert!(validate_timestamp(now - 31).is_err());
        // 60 seconds ago is definitely too old
        assert!(validate_timestamp(now - 60).is_err());
    }

    #[test]
    fn test_validate_timestamp_rejects_future() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 10 seconds in the future is too far
        assert!(validate_timestamp(now + 10).is_err());
    }

    // ============================================================================
    // Signature Validation Tests (Placeholder until real implementation)
    // ============================================================================

    #[test]
    fn test_verify_signature_rejects_empty() {
        let message = b"test message";
        let result = verify_signature(message, "", "pubkey");
        assert!(matches!(result, Err(MaskError::InvalidSignature)));

        let result = verify_signature(message, "signature", "");
        assert!(matches!(result, Err(MaskError::InvalidSignature)));
    }

    #[test]
    fn test_verify_signature_rejects_invalid_hex() {
        let message = b"test message";
        // Invalid hex characters
        let result = verify_signature(message, "gggg", "1234");
        assert!(matches!(result, Err(MaskError::InvalidSignature)));
    }
}

// ============================================================================
// Integration Tests for GET /mpc/masks Endpoint (TDD)
// ============================================================================

#[cfg(test)]
mod endpoint_tests {
    //! Integration tests for the GET /mpc/masks endpoint
    //!
    //! These tests are written BEFORE the endpoint is fully implemented (TDD Red phase).
    //! They document the expected behavior of the masks endpoint.

    use super::*;

    /// Helper to create a valid signature for testing
    fn _create_test_signature(timestamp: u64, coordinator_pda: &str, index: u32) -> String {
        // Build message
        let mut message = Vec::new();
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(coordinator_pda.as_bytes());
        message.extend_from_slice(&index.to_le_bytes());

        // In tests, we'd use a known keypair
        // For now, return placeholder
        "aa".repeat(64) // 64-byte signature as hex
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_returns_mask_for_valid_request() {
        // Setup: Create app state with mask store
        // Reserve mask at index 0 for client

        // Request: GET /mpc/masks/{coord_pda}/0 with valid signature

        // Expect: 200 OK with mask_value bytes
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_rejects_invalid_signature() {
        // Request with bad Ed25519 signature

        // Expect: 401 Unauthorized
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_rejects_stale_timestamp() {
        // Request with timestamp > 30 seconds old

        // Expect: 400 Bad Request with STALE_TIMESTAMP error
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_rejects_unreserved_index() {
        // Request index that wasn't reserved

        // Expect: 404 Not Found
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_rejects_already_retrieved_mask() {
        // Request mask for index already retrieved

        // Expect: 409 Conflict
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_validates_client_ownership() {
        // Client A requests mask reserved by Client B

        // Expect: 403 Forbidden
    }

    #[tokio::test]
    #[ignore = "Endpoint not yet fully implemented"]
    async fn test_masks_endpoint_validates_coordinator_pda_format() {
        // Request with invalid coordinator PDA

        // Expect: 400 Bad Request with INVALID_COORDINATOR_PDA error
    }
}
