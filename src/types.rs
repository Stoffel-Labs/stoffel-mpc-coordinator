//! Data types for the MPC Coordinator API

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Types of MPC jobs supported by the coordinator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    /// Transfer encrypted balance between confidential accounts
    ConfidentialTransfer,
    /// Create a new confidential account
    CreateConfidentialAccount,
    /// Recipient claims their confidential account
    ClaimConfidentialAccount,
    /// Wrap an SPL mint as a confidential mint
    WrapMint,
    /// Set/update auditor for a confidential mint
    SetAuditor,
    /// Decrypt a ciphertext using distributed decryption
    DistributedDecrypt,
    /// Generate a zero-knowledge range proof
    GenerateRangeProof,
    /// Generate MPC authorization for a transfer
    AuthorizeTransfer,
}

/// Status of an MPC job in the execution pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Job is waiting in the queue
    Queued,
    /// Job has been assigned to MPC parties
    Assigned,
    /// Preprocessing phase (beaver triples, etc.)
    Preprocessing,
    /// Main MPC execution phase
    Executing,
    /// Collecting signatures from parties
    Signing,
    /// Job completed successfully
    Complete,
    /// Job failed with an error
    Failed,
}

/// Client input for an MPC job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInput {
    /// Client identifier
    pub client_id: String,
    /// Input index
    pub index: u32,
    /// Encrypted or public input data (base64 encoded)
    pub data: String,
    /// Whether this input is secret-shared
    pub is_secret: bool,
}

/// Request to submit a new MPC job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    /// Type of MPC computation to perform
    pub job_type: JobType,
    /// Hash of the Stoffel-Lang program (hex encoded, 32 bytes)
    pub program_hash: String,
    /// Client inputs for the computation
    pub inputs: Vec<ClientInput>,
    /// Idempotency key to prevent duplicate submissions
    pub idempotency_key: String,
    /// Key ID for encryption/decryption
    pub key_id: String,
    /// Client making the request
    pub client_id: String,
    /// Request timestamp (Unix epoch seconds)
    pub request_ts: u64,
}

/// Response after submitting a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubmitResponse {
    /// Unique job identifier
    pub job_id: Uuid,
    /// Initial status (always Queued)
    pub status: JobStatus,
    /// Estimated queue position
    pub queue_position: usize,
}

/// Response when querying job status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatusResponse {
    /// Unique job identifier
    pub job_id: Uuid,
    /// Current job status
    pub status: JobStatus,
    /// Job type
    pub job_type: JobType,
    /// Output data (only present when Complete)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<u8>>,
    /// Error message (only present when Failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// When the job was submitted
    pub submitted_at: DateTime<Utc>,
    /// When the job completed (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Coordinator service status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStatus {
    /// Service health status
    pub healthy: bool,
    /// Number of registered MPC parties
    pub party_count: usize,
    /// Number of jobs in queue
    pub queue_depth: usize,
    /// Number of jobs currently executing
    pub active_jobs: usize,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Information about an MPC party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    /// Party identifier
    pub party_id: String,
    /// Party's public key (hex encoded)
    pub public_key: String,
    /// Party's endpoint URL
    pub endpoint: String,
    /// Whether the party is currently online
    pub online: bool,
    /// When the party registered
    pub registered_at: DateTime<Utc>,
}

/// Request to register as an MPC party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyRegisterRequest {
    /// Party's public key (hex encoded)
    pub public_key: String,
    /// Party's endpoint URL for coordination
    pub endpoint: String,
    /// Stake amount (for slashing)
    #[serde(default)]
    pub stake: u64,
}

/// Response after registering a party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyRegisterResponse {
    /// Assigned party identifier
    pub party_id: String,
    /// Registration successful
    pub registered: bool,
}

/// Aggregated encryption keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysResponse {
    /// Aggregated encryption public key (hex encoded)
    pub encryption_pubkey: String,
    /// Key identifier
    pub key_id: String,
    /// Number of parties contributing to the key
    pub party_count: usize,
    /// Threshold required for decryption
    pub threshold: usize,
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}
