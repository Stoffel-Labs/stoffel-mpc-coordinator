//! Handler for CreateConfidentialAccount jobs
//!
//! This handler creates new confidential accounts for C-SPL tokens.
//! It generates the PDA address for the account based on the mint,
//! owner, and optional namespace.

use async_trait::async_trait;

use super::{JobHandler, HandlerResult, HandlerError, value_to_bytes};
use crate::jobs::Job;
use crate::types::JobType;
use crate::vm::Value;

// Use inline hex encoding to avoid external dependency
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Handler for creating confidential accounts
pub struct CreateConfidentialAccountHandler;

impl CreateConfidentialAccountHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for CreateConfidentialAccountHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for CreateConfidentialAccountHandler {
    fn job_type(&self) -> JobType {
        JobType::CreateConfidentialAccount
    }

    fn entry_point(&self) -> &'static str {
        "create_account"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // CreateConfidentialAccount requires at least 2 inputs: mint and owner
        if job.inputs.len() < 2 {
            return Err(HandlerError::ValidationError(
                "CreateConfidentialAccount requires at least 2 inputs (mint, owner)".to_string()
            ));
        }

        // Check that we have the program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        // Validate mint input (index 0) - must be 32 bytes
        let mint_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[0].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode mint input: {}", e)
        ))?;

        if mint_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Mint must be 32 bytes, got {}", mint_data.len())
            ));
        }

        // Validate owner input (index 1) - must be 32 bytes
        let owner_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[1].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode owner input: {}", e)
        ))?;

        if owner_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Owner must be 32 bytes, got {}", owner_data.len())
            ));
        }

        // Validate optional namespace input (index 2) - must be 8 bytes if present
        if job.inputs.len() > 2 {
            let namespace_data = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &job.inputs[2].data
            ).map_err(|e| HandlerError::InvalidFormat(
                format!("Failed to decode namespace input: {}", e)
            ))?;

            if namespace_data.len() != 8 {
                return Err(HandlerError::ValidationError(
                    format!("Namespace must be 8 bytes, got {}", namespace_data.len())
                ));
            }
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

            // Account creation inputs are public (addresses)
            values.push(Value::String(hex_encode(&data)));
        }

        Ok(values)
    }

    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // The output should be a 32-byte account PDA address
        let bytes = value_to_bytes(value);

        if bytes.len() != 32 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 32,
                "Unexpected account address size"
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

    fn make_create_account_job() -> Job {
        let request = JobRequest {
            job_type: JobType::CreateConfidentialAccount,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // Mint address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32] // Owner address
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

    fn make_create_account_job_with_namespace() -> Job {
        let request = JobRequest {
            job_type: JobType::CreateConfidentialAccount,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // Mint address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[2u8; 32] // Owner address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 8] // Namespace
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
        let handler = CreateConfidentialAccountHandler::new();
        assert_eq!(handler.job_type(), JobType::CreateConfidentialAccount);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = CreateConfidentialAccountHandler::new();
        assert_eq!(handler.entry_point(), "create_account");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = CreateConfidentialAccountHandler::new();
        let job = make_create_account_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_with_namespace() {
        let handler = CreateConfidentialAccountHandler::new();
        let job = make_create_account_job_with_namespace();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_owner() {
        let handler = CreateConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::CreateConfidentialAccount,
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
                assert!(msg.contains("at least 2 inputs"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_mint_size() {
        let handler = CreateConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::CreateConfidentialAccount,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 16] // Wrong size - should be 32
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
                assert!(msg.contains("Mint must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_namespace_size() {
        let handler = CreateConfidentialAccountHandler::new();
        let request = JobRequest {
            job_type: JobType::CreateConfidentialAccount,
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
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 16] // Wrong size - should be 8
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
                assert!(msg.contains("Namespace must be 8 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_prepare_inputs() {
        let handler = CreateConfidentialAccountHandler::new();
        let job = make_create_account_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 2);

        match &inputs[0] {
            Value::String(hex_str) => {
                // Hex-encoded 32 bytes = 64 characters
                assert_eq!(hex_str.len(), 64);
            }
            _ => panic!("Expected String value"),
        }
    }

    #[test]
    fn test_prepare_inputs_with_namespace() {
        let handler = CreateConfidentialAccountHandler::new();
        let job = make_create_account_job_with_namespace();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 3);
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = CreateConfidentialAccountHandler::new();
        let job = make_create_account_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32);
    }
}
