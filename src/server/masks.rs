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
#[derive(Debug, Serialize, Deserialize)]
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
    _message: &[u8],
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
    State(state): State<AppState>,
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

    // Use client_pubkey as client_id for ownership verification
    let client_id = &query.client_pubkey;

    // Retrieve mask from store
    match state.mask_store.retrieve_mask(&coordinator_pda, index, client_id).await {
        Ok(mask_value) => {
            // Encode mask as base64 for transport
            let mask_base64 = base64_encode(&mask_value);
            Ok(Json(MaskResponse {
                mask_value: mask_base64,
                index,
                coordinator_pda,
            }))
        }
        Err(MaskError::NotFound) => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError::new(
                "MASK_NOT_FOUND",
                "No mask reserved at this index",
            )),
        )),
        Err(MaskError::NotOwner) => Err((
            StatusCode::FORBIDDEN,
            Json(ApiError::new(
                "NOT_OWNER",
                "Client is not the owner of this mask",
            )),
        )),
        Err(MaskError::AlreadyRetrieved) => Err((
            StatusCode::CONFLICT,
            Json(ApiError::new(
                "ALREADY_RETRIEVED",
                "Mask has already been retrieved",
            )),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError::new(
                "INTERNAL_ERROR",
                "Failed to retrieve mask",
            )),
        )),
    }
}

/// Base64 encode bytes
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
            2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
            1 => (chunk[0] as u32) << 16,
            _ => unreachable!(),
        };

        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
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
// Integration Tests for GET /mpc/masks Endpoint
// ============================================================================

#[cfg(test)]
mod endpoint_tests {
    //! Integration tests for the GET /mpc/masks endpoint

    use super::*;
    use crate::server::{create_router, AppState, MpcConfig};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::util::ServiceExt;

    /// Create test app with mask store
    fn create_test_app() -> axum::Router {
        let state = AppState::new(MpcConfig::default());
        create_router(state)
    }

    /// Create test app and return state for direct manipulation
    fn create_test_app_with_state() -> (axum::Router, AppState) {
        let state = AppState::new(MpcConfig::default());
        let router = create_router(state.clone());
        (router, state)
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Create a valid signature for testing (placeholder - passes validation)
    fn create_test_signature() -> String {
        "aa".repeat(64) // 64-byte hex signature
    }

    /// Create a valid pubkey for testing
    fn create_test_pubkey() -> String {
        "bb".repeat(32) // 32-byte hex pubkey
    }

    /// Valid base58 coordinator PDA (44 chars)
    fn valid_coordinator_pda() -> String {
        "11111111111111111111111111111111".to_string() // 32 chars, valid length
    }

    #[tokio::test]
    async fn test_masks_endpoint_returns_mask_for_valid_request() {
        let (app, state) = create_test_app_with_state();

        let coord_pda = valid_coordinator_pda();
        let client_pubkey = create_test_pubkey();
        let index = 0u32;
        let mask_value = vec![0xAB; 32];

        // Reserve a mask for the test client
        state
            .mask_store
            .reserve_mask(&coord_pda, index, &client_pubkey, mask_value.clone())
            .await
            .unwrap();

        let timestamp = current_timestamp();
        let signature = create_test_signature();

        let uri = format!(
            "/mpc/masks/{}/{}?timestamp={}&signature={}&client_pubkey={}",
            coord_pda, index, timestamp, signature, client_pubkey
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: MaskResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.index, index);
        assert_eq!(resp.coordinator_pda, coord_pda);
        // Verify mask value is base64 encoded
        assert!(!resp.mask_value.is_empty());
    }

    #[tokio::test]
    async fn test_masks_endpoint_rejects_invalid_signature() {
        let app = create_test_app();

        let coord_pda = valid_coordinator_pda();
        let timestamp = current_timestamp();

        // Empty signature should fail
        let uri = format!(
            "/mpc/masks/{}/0?timestamp={}&signature=&client_pubkey={}",
            coord_pda, timestamp, create_test_pubkey()
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_masks_endpoint_rejects_stale_timestamp() {
        let app = create_test_app();

        let coord_pda = valid_coordinator_pda();
        // Timestamp 60 seconds ago
        let stale_timestamp = current_timestamp() - 60;

        let uri = format!(
            "/mpc/masks/{}/0?timestamp={}&signature={}&client_pubkey={}",
            coord_pda, stale_timestamp, create_test_signature(), create_test_pubkey()
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let err: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, "STALE_TIMESTAMP");
    }

    #[tokio::test]
    async fn test_masks_endpoint_rejects_unreserved_index() {
        let app = create_test_app();

        let coord_pda = valid_coordinator_pda();
        let timestamp = current_timestamp();

        // Request index that was never reserved
        let uri = format!(
            "/mpc/masks/{}/999?timestamp={}&signature={}&client_pubkey={}",
            coord_pda, timestamp, create_test_signature(), create_test_pubkey()
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_masks_endpoint_rejects_already_retrieved_mask() {
        let (app, state) = create_test_app_with_state();

        let coord_pda = valid_coordinator_pda();
        let client_pubkey = create_test_pubkey();
        let index = 0u32;

        // Reserve a mask
        state
            .mask_store
            .reserve_mask(&coord_pda, index, &client_pubkey, vec![0xAA; 32])
            .await
            .unwrap();

        // First retrieval (marks as retrieved internally)
        state
            .mask_store
            .retrieve_mask(&coord_pda, index, &client_pubkey)
            .await
            .unwrap();

        let timestamp = current_timestamp();
        let uri = format!(
            "/mpc/masks/{}/{}?timestamp={}&signature={}&client_pubkey={}",
            coord_pda, index, timestamp, create_test_signature(), client_pubkey
        );

        // Second retrieval via endpoint should fail
        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_masks_endpoint_validates_client_ownership() {
        let (app, state) = create_test_app_with_state();

        let coord_pda = valid_coordinator_pda();
        let owner_pubkey = "cc".repeat(32); // Original owner
        let other_pubkey = create_test_pubkey(); // Different client

        // Reserve mask for owner
        state
            .mask_store
            .reserve_mask(&coord_pda, 0, &owner_pubkey, vec![0xAA; 32])
            .await
            .unwrap();

        let timestamp = current_timestamp();

        // Other client tries to retrieve
        let uri = format!(
            "/mpc/masks/{}/0?timestamp={}&signature={}&client_pubkey={}",
            coord_pda, timestamp, create_test_signature(), other_pubkey
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_masks_endpoint_validates_coordinator_pda_format() {
        let app = create_test_app();

        let timestamp = current_timestamp();

        // PDA too short (< 32 chars)
        let uri = format!(
            "/mpc/masks/short/0?timestamp={}&signature={}&client_pubkey={}",
            timestamp, create_test_signature(), create_test_pubkey()
        );

        let response = app
            .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let err: ApiError = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.code, "INVALID_COORDINATOR_PDA");
    }
}
