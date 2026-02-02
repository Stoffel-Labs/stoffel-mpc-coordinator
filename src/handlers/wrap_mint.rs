//! Handler for WrapMint jobs
//!
//! This handler wraps an existing SPL mint as a confidential mint.
//! It creates the on-chain confidential mint account that enables
//! confidential transfers for the wrapped token.

use async_trait::async_trait;

use super::{JobHandler, HandlerResult, HandlerError, value_to_bytes};
use crate::jobs::Job;
use crate::types::JobType;
use crate::vm::Value;

// Use inline hex encoding to avoid external dependency
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Handler for wrapping SPL mints as confidential mints
pub struct WrapMintHandler;

impl WrapMintHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for WrapMintHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for WrapMintHandler {
    fn job_type(&self) -> JobType {
        JobType::WrapMint
    }

    fn entry_point(&self) -> &'static str {
        "wrap_mint"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // WrapMint requires at least 2 inputs: spl_mint and authority
        if job.inputs.len() < 2 {
            return Err(HandlerError::ValidationError(
                "WrapMint requires at least 2 inputs (spl_mint, authority)".to_string()
            ));
        }

        // Check that we have the program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        // Validate spl_mint input (index 0) - must be 32 bytes
        let mint_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[0].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode spl_mint input: {}", e)
        ))?;

        if mint_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("SPL mint must be 32 bytes, got {}", mint_data.len())
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

        // Validate optional auditor input (index 2) - must be 32 bytes if present
        if job.inputs.len() > 2 {
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

            // Wrap mint inputs are public (addresses)
            values.push(Value::String(hex_encode(&data)));
        }

        Ok(values)
    }

    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // The output should be a 32-byte confidential mint address
        let bytes = value_to_bytes(value);

        if bytes.len() != 32 {
            tracing::warn!(
                output_len = bytes.len(),
                expected = 32,
                "Unexpected confidential mint address size"
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

    fn make_wrap_mint_job() -> Job {
        let request = JobRequest {
            job_type: JobType::WrapMint,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // SPL mint address
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
            ],
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        };
        crate::jobs::Job::from_request(request)
    }

    fn make_wrap_mint_job_with_auditor() -> Job {
        let request = JobRequest {
            job_type: JobType::WrapMint,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 32] // SPL mint address
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
        let handler = WrapMintHandler::new();
        assert_eq!(handler.job_type(), JobType::WrapMint);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = WrapMintHandler::new();
        assert_eq!(handler.entry_point(), "wrap_mint");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = WrapMintHandler::new();
        let job = make_wrap_mint_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_with_auditor() {
        let handler = WrapMintHandler::new();
        let job = make_wrap_mint_job_with_auditor();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_authority() {
        let handler = WrapMintHandler::new();
        let request = JobRequest {
            job_type: JobType::WrapMint,
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
        let handler = WrapMintHandler::new();
        let request = JobRequest {
            job_type: JobType::WrapMint,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 64] // Wrong size
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
                assert!(msg.contains("SPL mint must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_auditor_size() {
        let handler = WrapMintHandler::new();
        let request = JobRequest {
            job_type: JobType::WrapMint,
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
                        &[3u8; 16] // Wrong size
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
        let handler = WrapMintHandler::new();
        let job = make_wrap_mint_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 2);

        for input in &inputs {
            match input {
                Value::String(hex_str) => {
                    // Hex-encoded 32 bytes = 64 characters
                    assert_eq!(hex_str.len(), 64);
                }
                _ => panic!("Expected String value"),
            }
        }
    }

    #[test]
    fn test_prepare_inputs_with_auditor() {
        let handler = WrapMintHandler::new();
        let job = make_wrap_mint_job_with_auditor();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 3);
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = WrapMintHandler::new();
        let job = make_wrap_mint_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        // Register the wrap_mint mock function
        vm.register_function("wrap_mint", |_args| {
            // Return hex-encoded 32 bytes (64 characters)
            Ok(Value::String("ff".repeat(32)))
        });

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 32);
    }
}
