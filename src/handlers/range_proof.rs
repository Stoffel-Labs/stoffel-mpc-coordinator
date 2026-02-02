//! Handler for GenerateRangeProof jobs
//!
//! This handler generates zero-knowledge range proofs (Bulletproofs)
//! that prove a committed value lies within a specific range without
//! revealing the actual value.

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

/// Handler for generating range proofs
pub struct GenerateRangeProofHandler;

impl GenerateRangeProofHandler {
    /// Create a new handler instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenerateRangeProofHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobHandler for GenerateRangeProofHandler {
    fn job_type(&self) -> JobType {
        JobType::GenerateRangeProof
    }

    fn entry_point(&self) -> &'static str {
        "generate_range_proof"
    }

    fn validate_inputs(&self, job: &Job) -> HandlerResult<()> {
        // GenerateRangeProof requires 3 inputs: value, blinding, bit_range
        if job.inputs.len() < 3 {
            return Err(HandlerError::ValidationError(
                "GenerateRangeProof requires 3 inputs (value, blinding, bit_range)".to_string()
            ));
        }

        // Check that we have the program hash
        if job.program_hash.is_empty() {
            return Err(HandlerError::ValidationError(
                "Program hash is required".to_string()
            ));
        }

        // Validate value input (index 0) - must be 8 bytes (u64)
        let value_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[0].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode value input: {}", e)
        ))?;

        if value_data.len() != 8 {
            return Err(HandlerError::ValidationError(
                format!("Value must be 8 bytes, got {}", value_data.len())
            ));
        }

        // Validate blinding input (index 1) - must be 32 bytes (scalar)
        let blinding_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[1].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode blinding input: {}", e)
        ))?;

        if blinding_data.len() != 32 {
            return Err(HandlerError::ValidationError(
                format!("Blinding must be 32 bytes, got {}", blinding_data.len())
            ));
        }

        // Validate bit_range input (index 2) - must be 1 byte
        let bit_range_data = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &job.inputs[2].data
        ).map_err(|e| HandlerError::InvalidFormat(
            format!("Failed to decode bit_range input: {}", e)
        ))?;

        if bit_range_data.len() != 1 {
            return Err(HandlerError::ValidationError(
                format!("Bit range must be 1 byte, got {}", bit_range_data.len())
            ));
        }

        // Validate bit range is valid (8, 16, 32, or 64)
        let bit_range = bit_range_data[0];
        if ![8, 16, 32, 64].contains(&bit_range) {
            return Err(HandlerError::ValidationError(
                format!("Bit range must be 8, 16, 32, or 64, got {}", bit_range)
            ));
        }

        // Validate that value fits within bit_range
        let value = u64::from_le_bytes(value_data.try_into().unwrap());
        let max_value = match bit_range {
            8 => u8::MAX as u64,
            16 => u16::MAX as u64,
            32 => u32::MAX as u64,
            64 => u64::MAX,
            _ => unreachable!(),
        };

        if value > max_value {
            return Err(HandlerError::ValidationError(
                format!("Value {} exceeds {}-bit range max {}", value, bit_range, max_value)
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

            // Use Share for secret data (value, blinding), String (hex) for public (bit_range)
            if input.is_secret {
                values.push(Value::Share(ShareType::default_secret_int(), data));
            } else {
                values.push(Value::String(hex_encode(&data)));
            }
        }

        Ok(values)
    }

    fn format_output(&self, value: &Value) -> HandlerResult<Vec<u8>> {
        // The output should be ~700 bytes (Bulletproofs range proof)
        // Actual size varies based on the proof type and parameters
        let bytes = value_to_bytes(value);

        // Bulletproofs range proofs are typically 672-768 bytes
        // depending on the number of bits being proven
        if bytes.len() < 100 || bytes.len() > 1000 {
            tracing::warn!(
                output_len = bytes.len(),
                expected_range = "100-1000",
                "Unusual range proof size"
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

    fn make_range_proof_job() -> Job {
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &1000u64.to_le_bytes() // Value to prove
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32] // Blinding factor
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[64u8] // 64-bit range
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

    fn make_range_proof_job_8bit() -> Job {
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234abcd".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &100u64.to_le_bytes() // Value within 8-bit range
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32]
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[8u8] // 8-bit range
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
        let handler = GenerateRangeProofHandler::new();
        assert_eq!(handler.job_type(), JobType::GenerateRangeProof);
    }

    #[test]
    fn test_handler_entry_point() {
        let handler = GenerateRangeProofHandler::new();
        assert_eq!(handler.entry_point(), "generate_range_proof");
    }

    #[test]
    fn test_validate_inputs_success() {
        let handler = GenerateRangeProofHandler::new();
        let job = make_range_proof_job();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_8bit_success() {
        let handler = GenerateRangeProofHandler::new();
        let job = make_range_proof_job_8bit();
        assert!(handler.validate_inputs(&job).is_ok());
    }

    #[test]
    fn test_validate_inputs_missing_bit_range() {
        let handler = GenerateRangeProofHandler::new();
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &1000u64.to_le_bytes()
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32]
                    ),
                    is_secret: true,
                },
                // Missing bit_range
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
    fn test_validate_inputs_invalid_value_size() {
        let handler = GenerateRangeProofHandler::new();
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[1u8; 4] // Wrong size - should be 8
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32]
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[64u8]
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
                assert!(msg.contains("Value must be 8 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_blinding_size() {
        let handler = GenerateRangeProofHandler::new();
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &1000u64.to_le_bytes()
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 16] // Wrong size - should be 32
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[64u8]
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
                assert!(msg.contains("Blinding must be 32 bytes"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_invalid_bit_range() {
        let handler = GenerateRangeProofHandler::new();
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &1000u64.to_le_bytes()
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32]
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[24u8] // Invalid - not 8, 16, 32, or 64
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
                assert!(msg.contains("Bit range must be 8, 16, 32, or 64"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_validate_inputs_value_exceeds_range() {
        let handler = GenerateRangeProofHandler::new();
        let request = JobRequest {
            job_type: JobType::GenerateRangeProof,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &300u64.to_le_bytes() // 300 > 255 (8-bit max)
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 1,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[42u8; 32]
                    ),
                    is_secret: true,
                },
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 2,
                    data: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &[8u8] // 8-bit range
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
                assert!(msg.contains("exceeds"));
                assert!(msg.contains("8-bit range"));
            }
            _ => panic!("Expected ValidationError"),
        }
    }

    #[test]
    fn test_prepare_inputs() {
        let handler = GenerateRangeProofHandler::new();
        let job = make_range_proof_job();

        let inputs = handler.prepare_inputs(&job).unwrap();
        assert_eq!(inputs.len(), 3);

        // Check value (8 bytes) - is_secret: true, so Share
        match &inputs[0] {
            Value::Share(_, bytes) => assert_eq!(bytes.len(), 8),
            _ => panic!("Expected Share value for secret value input"),
        }

        // Check blinding (32 bytes) - is_secret: true, so Share
        match &inputs[1] {
            Value::Share(_, bytes) => assert_eq!(bytes.len(), 32),
            _ => panic!("Expected Share value for secret blinding input"),
        }

        // Check bit_range (1 byte) - is_secret: false, so String
        match &inputs[2] {
            Value::String(hex_str) => {
                // Hex-encoded 1 byte = 2 characters
                assert_eq!(hex_str.len(), 2);
            }
            _ => panic!("Expected String value for public bit_range input"),
        }
    }

    #[tokio::test]
    async fn test_execute() {
        let handler = GenerateRangeProofHandler::new();
        let job = make_range_proof_job();
        let mut vm = VmExecutor::new();
        vm.load_bytecode(b"STFL_mock").unwrap();

        // Register the generate_range_proof mock function
        vm.register_function("generate_range_proof", |_args| {
            // Mock ~700-byte Bulletproofs range proof (hex-encoded = 1344 chars)
            Ok(Value::String("22".repeat(672)))
        });

        let result = handler.execute(&job, &mut vm).await;
        assert!(result.is_ok());

        let output = result.unwrap();
        assert_eq!(output.len(), 672);
    }
}
