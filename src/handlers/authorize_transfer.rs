//! Handler for AuthorizeTransfer jobs
//!
//! This handler generates MPC authorization tokens for confidential transfers.
//! The authorization token proves that the transfer is valid without revealing
//! the actual amounts.

use async_trait::async_trait;

use super::{JobHandler, HandlerResult, HandlerError, value_to_bytes};
use crate::jobs::Job;
use crate::types::JobType;
use crate::vm::Value;
use stoffel_vm_types::core_types::ShareType;

// Use inline hex encoding to avoid external dependency
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Handler for generating transfer authorization tokens
pub struct AuthorizeTransferHandler;

impl AuthorizeTransferHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthorizeTransferHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for AuthorizeTransferHandler {
    fn job_type(&self) -> JobType {
        JobType::AuthorizeTransfer
    }

    fn entry_point(&self) -> &'static str {
        "authorize_transfer"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // AuthorizeTransfer requires at least one input (the transfer request)
        if job.inputs.is_empty() {
            return Err(HandlerError::ValidationError(
                "AuthorizeTransfer requires at least one input".to_string()
            ));
        }

        // Check that we have the program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        Ok(())
    }

    fn prepare_inputs(&self, job: &Job) -> HandlerResult<Vec<Value>> {
        // For the mock VM, we don't need to prepare inputs
        // In the real implementation, we would:
        // 1. Decode the client inputs from base64
        // 2. Convert to VM Value types
        // 3. Return the values in the expected order

        let mut values = Vec::new();

        for input in &job.inputs {
            // Decode base64 input data
            let data = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &input.data
            ).map_err(|e| HandlerError::InvalidFormat(
                format!("Failed to decode input {}: {}", input.index, e)
            ))?;

            // Use Share for secret data, String (hex) for public data
            if input.is_secret {
                values.push(Value::Share(ShareType::default_secret_int(), data));
            } else {
                values.push(Value::String(hex_encode(&data)));
            }
        }

        Ok(values)
    }

    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // The output should be a 32-byte authorization token
        let bytes = value_to_bytes(value);

        if bytes.len() != 32 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 32,
                "Unexpected authorization token size"
            );
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{JobRequest, ClientInput};
    use crate::vm::VmExecutor;

    fn make_auth_job() -> Job {
        let request = JobRequest {
            job_type: JobType::AuthorizeTransfer,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[0u8; 32] // Source amount commitment
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // Transfer amount
                    ),
                    is_secret: true,
                },
            ],
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        };
        crate::jobs::Job::from_request(request)
    }

    #[test]
    fn test_handler_job_type() {
        let handler = AuthorizeTransferHandler::new();
        assert_eq!(handler.job_type(), JobType::AuthorizeTransfer);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = AuthorizeTransferHandler::new();
        assert_eq!(handler.entry_point(), "authorize_transfer");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = AuthorizeTransferHandler::new();
        let job = make_auth_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_empty() {
        let handler = AuthorizeTransferHandler::new();
        let request = JobRequest {
            job_type: JobType::AuthorizeTransfer,
            program_hash: "0x1234".to_string(),
            inputs: vec![], // No inputs
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        };
        let job = crate::jobs::Job::from_request(request);

        let result = handler.validate_inputs(&job);
        assert!(result.is_err());
    }

    #[test]
    fn test_prepare_inputs() {
        let handler = AuthorizeTransferHandler::new();
        let job = make_auth_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 2);
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = AuthorizeTransferHandler::new();
        let job = make_auth_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32);
    }
}
