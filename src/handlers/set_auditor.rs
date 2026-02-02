//! Handler for SetAuditor jobs
//!
//! This handler sets or updates the auditor for a confidential mint.
//! The auditor can decrypt transfer amounts for compliance purposes.

use async_trait::async_trait;

use super::{JobHandler, HandlerResult, HandlerError};
use crate::jobs::Job;
use crate::types::JobType;
use crate::vm::Value;

/// Handler for setting mint auditors
pub struct SetAuditorHandler;

impl SetAuditorHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for SetAuditorHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for SetAuditorHandler {
    fn job_type(&self) -> JobType {
        JobType::SetAuditor
    }

    fn entry_point(&self) -> &'static str {
        "set_auditor"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // SetAuditor requires 3 inputs: mint, authority, auditor
        if job.inputs.len() < 3 {
            return Err(HandlerError::ValidationError(
                "SetAuditor requires 3 inputs (mint, authority, auditor)".to_string()
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

        // Validate authority input (index 1) - must be 32 bytes
        let authority_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[1].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode authority input: {}", e)
        ))?;

        if authority_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Authority must be 32 bytes, got {}", authority_data.len())
            ));
        }

        // Validate auditor input (index 2) - must be 32 bytes
        let auditor_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[2].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode auditor input: {}", e)
        ))?;

        if auditor_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Auditor must be 32 bytes, got {}", auditor_data.len())
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
        // The output should be 64 bytes: mint address (32) + auditor confirmation (32)
        let bytes = value.to_bytes();

        if bytes.len() != 64 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 64,
                "Unexpected set auditor output size"
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

    fn make_set_auditor_job() -> Job {
        let request = JobRequest {
            job_type: JobType::SetAuditor,
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
                        &[2u8; 32] // Authority address
                    ),
                    is_secret: false,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[3u8; 32] // Auditor address
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
        let handler = SetAuditorHandler::new();
        assert_eq!(handler.job_type(), JobType::SetAuditor);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = SetAuditorHandler::new();
        assert_eq!(handler.entry_point(), "set_auditor");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = SetAuditorHandler::new();
        let job = make_set_auditor_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_auditor() {
        let handler = SetAuditorHandler::new();
        let request = JobRequest {
            job_type: JobType::SetAuditor,
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
                // Missing auditor
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
    fn test_validate_inputs_invalid_mint_size() {
        let handler = SetAuditorHandler::new();
        let request = JobRequest {
            job_type: JobType::SetAuditor,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 16] // Wrong size
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
                assert!(msg.contains("Mint must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_authority_size() {
        let handler = SetAuditorHandler::new();
        let request = JobRequest {
            job_type: JobType::SetAuditor,
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
                        &[2u8; 48] // Wrong size
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
                assert!(msg.contains("Authority must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_auditor_size() {
        let handler = SetAuditorHandler::new();
        let request = JobRequest {
            job_type: JobType::SetAuditor,
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
                        &[3u8; 64] // Wrong size
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
                assert!(msg.contains("Auditor must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_prepare_inputs() {
        let handler = SetAuditorHandler::new();
        let job = make_set_auditor_job();

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
        let handler = SetAuditorHandler::new();
        let job = make_set_auditor_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        // Register the set_auditor mock function
        vm.register_function("set_auditor", |_args| {
            Ok(Value::Bytes(vec![0x11; 64])) // Mock 64-byte output
        });

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 64);
    }
}
