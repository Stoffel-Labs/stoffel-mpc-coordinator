//! Handler for ClaimConfidentialAccount jobs
//!
//! This handler allows recipients to claim confidential accounts
//! that were created for them. The claim process verifies ownership
//! and binds the account to the recipient's decryption key.

use async_trait::async_trait;

use super::{JobHandler, HandlerResult, HandlerError};
use crate::jobs::Job;
use crate::types::JobType;
use crate::vm::Value;

/// Handler for claiming confidential accounts
pub struct ClaimConfidentialAccountHandler;

impl ClaimConfidentialAccountHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClaimConfidentialAccountHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for ClaimConfidentialAccountHandler {
    fn job_type(&self) -> JobType {
        JobType::ClaimConfidentialAccount
    }

    fn entry_point(&self) -> &'static str {
        "claim_account"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // ClaimConfidentialAccount requires 3 inputs: account, recipient, decryption_pubkey
        if job.inputs.len() < 3 {
            return Err(HandlerError::ValidationError(
                "ClaimConfidentialAccount requires 3 inputs (account, recipient, decryption_pubkey)".to_string()
            ));
        }

        // Check that we have the program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        // Validate account input (index 0) - must be 32 bytes
        let account_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[0].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode account input: {}", e)
        ))?;

        if account_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Account must be 32 bytes, got {}", account_data.len())
            ));
        }

        // Validate recipient input (index 1) - must be 32 bytes
        let recipient_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[1].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode recipient input: {}", e)
        ))?;

        if recipient_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Recipient must be 32 bytes, got {}", recipient_data.len())
            ));
        }

        // Validate decryption_pubkey input (index 2) - must be 32 bytes
        let pubkey_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[2].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode decryption_pubkey input: {}", e)
        ))?;

        if pubkey_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Decryption pubkey must be 32 bytes, got {}", pubkey_data.len())
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

            values.push(Value::Bytes(data));
        }

        Ok(values)
    }

    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // The output should be 64 bytes: account address (32) + claim signature (32)
        let bytes = value.to_bytes();

        if bytes.len() != 64 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 64,
                "Unexpected claim output size"
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

    fn make_claim_account_job() -> Job {
        let request = JobRequest {
            job_type: JobType::ClaimConfidentialAccount,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // Account address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32] // Recipient address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 32] // Decryption pubkey
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
        let handler = ClaimConfidentialAccountHandler::new();
        assert_eq!(handler.job_type(), JobType::ClaimConfidentialAccount);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = ClaimConfidentialAccountHandler::new();
        assert_eq!(handler.entry_point(), "claim_account");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = ClaimConfidentialAccountHandler::new();
        let job = make_claim_account_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_pubkey() {
        let handler = ClaimConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::ClaimConfidentialAccount,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32]
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32]
                    ),
                    is_secret: false,
                },
                // Missing decryption_pubkey
            ],
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        };
        let job = crate::jobs::Job::from_request(request);

        let result = handler.validate_inputs(&job);
        assert!(result.is_err());
        match result {
            Err(HandlerError::ValidationError(msg)) => {
                assert!(msg.contains("3 inputs"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_account_size() {
        let handler = ClaimConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::ClaimConfidentialAccount,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 20] // Wrong size
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32]
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 32]
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
        match result {
            Err(HandlerError::ValidationError(msg)) => {
                assert!(msg.contains("Account must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_recipient_size() {
        let handler = ClaimConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::ClaimConfidentialAccount,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32]
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 64] // Wrong size
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 32]
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
        match result {
            Err(HandlerError::ValidationError(msg)) => {
                assert!(msg.contains("Recipient must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_prepare_inputs() {
        let handler = ClaimConfidentialAccountHandler::new();
        let job = make_claim_account_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 3);

        for input in &inputs {
            match input {
                Value::Bytes(bytes) => assert_eq!(bytes.len(), 32),
                _ => panic!("Expected Bytes value"),
            }
        }
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = ClaimConfidentialAccountHandler::new();
        let job = make_claim_account_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        // Register the claim_account mock function
        vm.register_function("claim_account", |_args| {
            Ok(Value::Bytes(vec![0xEE; 64])) // Mock 64-byte output
        });

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64);
    }
}
