//! Handler for DistributedDecrypt jobs
//!
//! This handler performs distributed decryption using threshold cryptography.
//! Each party computes a partial decryption share, and t+1 shares are
//! combined to recover the plaintext.

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

/// Handler for distributed decryption operations
pub struct DistributedDecryptHandler;

impl DistributedDecryptHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for DistributedDecryptHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for DistributedDecryptHandler {
    fn job_type(&self) -> JobType {
        JobType::DistributedDecrypt
    }

    fn entry_point(&self) -> &'static str {
        "partial_decrypt"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // DistributedDecrypt requires:
        // - The ciphertext to decrypt
        if job.inputs.is_empty() {
            return Err(HandlerError::ValidationError(
                "DistributedDecrypt requires ciphertext input".to_string()
            ));
        }

        // First input should be the ciphertext
        let first_input = &job.inputs[0];
        let data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &first_input.data
        ).map_err(|_| HandlerError::InvalidFormat(
            "Invalid ciphertext encoding".to_string()
        ))?;

        // BLS ciphertexts are typically 96 bytes (two G1 points)
        // But we accept any size for flexibility
        if data.is_empty() {
            return Err(HandlerError::ValidationError(
                "Ciphertext cannot be empty".to_string()
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
        // The output is a partial decryption share
        // For BLS, this is a G1 point (48 bytes compressed)
        let bytes = value_to_bytes(value);

        if bytes.len() != 48 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 48,
                "Unexpected partial decryption size (expected BLS G1 point)"
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

    fn make_decrypt_job() -> Job {
        let request = JobRequest {
            job_type: JobType::DistributedDecrypt,
            program_hash: "0xdecrypt".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[5u8; 96] // BLS ciphertext (two G1 points)
                    ),
                    is_secret: false, // Ciphertext is public
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
        let handler = DistributedDecryptHandler::new();
        assert_eq!(handler.job_type(), JobType::DistributedDecrypt);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = DistributedDecryptHandler::new();
        assert_eq!(handler.entry_point(), "partial_decrypt");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = DistributedDecryptHandler::new();
        let job = make_decrypt_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_empty() {
        let handler = DistributedDecryptHandler::new();
        let request = JobRequest {
            job_type: JobType::DistributedDecrypt,
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
    fn test_validate_inputs_empty_ciphertext() {
        let handler = DistributedDecryptHandler::new();
        let request = JobRequest {
            job_type: JobType::DistributedDecrypt,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[] // Empty ciphertext
                    ),
                    is_secret: false,
                },
            ],
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
        let handler = DistributedDecryptHandler::new();
        let job = make_decrypt_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 1);
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = DistributedDecryptHandler::new();
        let job = make_decrypt_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 48); // BLS G1 point
    }
}
