//! Job handlers for MPC computations
//!
//! This module provides a trait-based system for handling different types
//! of MPC jobs. Each job type has a dedicated handler that knows how to
//! prepare inputs, execute the computation, and format outputs.

mod authorize_transfer;
mod confidential_transfer;
mod distributed_decrypt;
mod registry;

pub use authorize_transfer::AuthorizeTransferHandler;
pub use confidential_transfer::ConfidentialTransferHandler;
pub use distributed_decrypt::DistributedDecryptHandler;
pub use registry::{HandlerRegistry, get_default_registry};

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
        let request = JobRequest {
            job_type,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1, 2, 3, 4]
                    ),
                    is_secret: true,
                }
            ],
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
    }
}
