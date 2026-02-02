//! Job handlers for MPC computations
//!
//! This module provides a trait-based system for handling different types
//! of MPC jobs. Each job type has a dedicated handler that knows how to
//! prepare inputs, execute the computation, and format outputs.

mod authorize_transfer;
mod claim_account;
mod confidential_transfer;
mod create_account;
mod distributed_decrypt;
mod range_proof;
mod registry;
mod set_auditor;
mod wrap_mint;

pub use authorize_transfer::AuthorizeTransferHandler;
pub use claim_account::ClaimConfidentialAccountHandler;
pub use confidential_transfer::ConfidentialTransferHandler;
pub use create_account::CreateConfidentialAccountHandler;
pub use distributed_decrypt::DistributedDecryptHandler;
pub use range_proof::GenerateRangeProofHandler;
pub use registry::{HandlerRegistry, get_default_registry};
pub use set_auditor::SetAuditorHandler;
pub use wrap_mint::WrapMintHandler;

use async_trait::async_trait;

use crate::jobs::Job;
use crate::vm::{VmExecutor, Value};
use crate::types::JobType;

/// Result type for handler operations
pub type HandlerResult<T> = Result<T, HandlerError>;

/// Errors that can occur during job handling
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("Input validation failed: {0}")]
    ValidationError(String),

    #[error("VM execution failed: {0}")]
    ExecutionError(String),

    #[error("Output formatting failed: {0}")]
    OutputError(String),

    #[error("Missing required input: {0}")]
    MissingInput(String),

    #[error("Invalid input format: {0}")]
    InvalidFormat(String),
}

/// Trait for job handlers
///
/// Each job type has a dedicated handler that implements this trait.
/// Handlers are responsible for:
/// 1. Validating inputs
/// 2. Preparing the VM execution context
/// 3. Executing the computation
/// 4. Formatting the output
#[async_trait]
pub trait JobHandler: Send + Sync {
    /// Get the job type this handler processes
    fn job_type(&self) -> JobType;

    /// Get the VM entry point function name
    fn entry_point(&self) -> &'static str;

    /// Validate job inputs before execution
    fn validate_inputs(&self, job: &Job) -> HandlerResult<()>;

    /// Prepare VM inputs from job inputs
    fn prepare_inputs(&self, job: &Job) -> HandlerResult<Vec<Value>>;

    /// Execute the job using the VM
    async fn execute(&self, job: &Job, vm: &mut VmExecutor) -> HandlerResult<Vec<u8>> {
        // Default implementation: validate, prepare, execute, format
        self.validate_inputs(job)?;

        let inputs = self.prepare_inputs(job)?;

        let result = if inputs.is_empty() {
            vm.execute(self.entry_point())
        } else {
            vm.execute_with_args(self.entry_point(), &inputs)
        };

        let value = result.map_err(|e| HandlerError::ExecutionError(e.to_string()))?;

        self.format_output(&value)
    }

    /// Format the VM result into output bytes
    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // Default: convert to bytes
        Ok(value.to_bytes())
    }
}

/// Context provided to handlers during execution
pub struct HandlerContext<'a> {
    pub job: &'a Job,
    pub vm: &'a mut VmExecutor,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{JobRequest, ClientInput};

    fn make_test_job(job_type: JobType) -> Job {
        // Create appropriate inputs based on job type
        let inputs = match job_type {
            JobType::CreateConfidentialAccount => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[2u8; 32]),
                    is_secret: false,
                },
            ],
            JobType::ClaimConfidentialAccount => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[2u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[3u8; 32]),
                    is_secret: false,
                },
            ],
            JobType::WrapMint => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[2u8; 32]),
                    is_secret: false,
                },
            ],
            JobType::SetAuditor => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[2u8; 32]),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[3u8; 32]),
                    is_secret: false,
                },
            ],
            JobType::GenerateRangeProof => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &1000u64.to_le_bytes()),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[42u8; 32]),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[64u8]),
                    is_secret: false,
                },
            ],
            _ => vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1, 2, 3, 4]),
                    is_secret: true,
                }
            ],
        };

        let request = JobRequest {
            job_type,
            program_hash: "0x1234".to_string(),
            inputs,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        };
        crate::jobs::Job::from_request(request)
    }

    #[test]
    fn test_handler_error_display() {
        let err = HandlerError::ValidationError("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[tokio::test]
    async fn test_authorize_transfer_handler() {
        let handler = AuthorizeTransferHandler;
        let job = make_test_job(JobType::AuthorizeTransfer);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32); // Mock returns 32 bytes
    }

    #[tokio::test]
    async fn test_confidential_transfer_handler() {
        let handler = ConfidentialTransferHandler;
        let job = make_test_job(JobType::ConfidentialTransfer);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64); // Mock returns 64 bytes
    }

    #[tokio::test]
    async fn test_distributed_decrypt_handler() {
        let handler = DistributedDecryptHandler;
        let job = make_test_job(JobType::DistributedDecrypt);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 48); // Mock returns 48 bytes (BLS)
    }

    #[test]
    fn test_handler_registry() {
        let registry = get_default_registry();

        // Check all handlers are registered
        assert!(registry.get(&JobType::AuthorizeTransfer).is_some());
        assert!(registry.get(&JobType::ConfidentialTransfer).is_some());
        assert!(registry.get(&JobType::DistributedDecrypt).is_some());
        assert!(registry.get(&JobType::CreateConfidentialAccount).is_some());
        assert!(registry.get(&JobType::ClaimConfidentialAccount).is_some());
        assert!(registry.get(&JobType::WrapMint).is_some());
        assert!(registry.get(&JobType::SetAuditor).is_some());
        assert!(registry.get(&JobType::GenerateRangeProof).is_some());
    }

    #[tokio::test]
    async fn test_create_account_handler() {
        let handler = CreateConfidentialAccountHandler;
        let job = make_test_job(JobType::CreateConfidentialAccount);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32); // Mock returns 32 bytes
    }

    #[tokio::test]
    async fn test_claim_account_handler() {
        let handler = ClaimConfidentialAccountHandler;
        let job = make_test_job(JobType::ClaimConfidentialAccount);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64); // Mock returns 64 bytes
    }

    #[tokio::test]
    async fn test_wrap_mint_handler() {
        let handler = WrapMintHandler;
        let job = make_test_job(JobType::WrapMint);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32); // Mock returns 32 bytes
    }

    #[tokio::test]
    async fn test_set_auditor_handler() {
        let handler = SetAuditorHandler;
        let job = make_test_job(JobType::SetAuditor);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64); // Mock returns 64 bytes
    }

    #[tokio::test]
    async fn test_range_proof_handler() {
        let handler = GenerateRangeProofHandler;
        let job = make_test_job(JobType::GenerateRangeProof);
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 672); // Mock returns Bulletproofs size
    }
}
