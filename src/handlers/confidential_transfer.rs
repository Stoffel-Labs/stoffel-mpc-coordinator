//! Handler for ConfidentialTransfer jobs
//!
//! This handler executes full confidential transfers, including:
//! 1. Validating the transfer request
//! 2. Updating encrypted balances
//! 3. Generating proofs

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

/// Handler for executing confidential transfers
pub struct ConfidentialTransferHandler;

impl ConfidentialTransferHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConfidentialTransferHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for ConfidentialTransferHandler {
    fn job_type(&self) -> JobType {
        JobType::ConfidentialTransfer
    }

    fn entry_point(&self) -> &'static str {
        "confidential_transfer"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // ConfidentialTransfer requires:
        // - Source account commitment
        // - Destination account commitment
        // - Transfer amount (encrypted)
        // - Authorization token (from AuthorizeTransfer)
        if job.inputs.is_empty() {
            return Err(HandlerError::ValidationError(
                "ConfidentialTransfer requires inputs".to_string()
            ));
        }

        // Check program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        Ok(())
    }

    fn prepare_inputs(&self, job: &Job) -> HandlerResult<Vec<Value>> {
        let mut values = Vec::new();

        for input in &job.inputs {
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
        // The output should be the updated account states and proofs
        // Typically this is 64 bytes (32 bytes each for source and dest)
        let bytes = value_to_bytes(value);

        if bytes.len() < 64 {
            tracing::warn!(
                output_len = bytes.len(),
                expected_min = 64,
                "Transfer output smaller than expected"
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

    fn make_transfer_job() -> Job {
        let request = JobRequest {
            job_type: JobType::ConfidentialTransfer,
            program_hash: "0x5678efgh".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32] // Source commitment
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 32] // Dest commitment
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[4u8; 32] // Auth token
                    ),
                    is_secret: false,
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
        let handler = ConfidentialTransferHandler::new();
        assert_eq!(handler.job_type(), JobType::ConfidentialTransfer);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = ConfidentialTransferHandler::new();
        assert_eq!(handler.entry_point(), "confidential_transfer");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = ConfidentialTransferHandler::new();
        let job = make_transfer_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_empty() {
        let handler = ConfidentialTransferHandler::new();
        let request = JobRequest {
            job_type: JobType::ConfidentialTransfer,
            program_hash: "0x1234".to_string(),
            inputs: vec![],
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
        let handler = ConfidentialTransferHandler::new();
        let job = make_transfer_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 3);
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = ConfidentialTransferHandler::new();
        let job = make_transfer_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64);
    }
}
