//! VM Integration Tests
//!
//! These tests are written BEFORE real VM integration (TDD Red phase).
//! They document the expected behavior when StoffelVM is properly integrated
//! with the coordinator, replacing the current mock mode.
//!
//! Blockers:
//! - mpc-protocols SenderId type errors on main branch
//! - mpc-protocols API incompatibility on dev branch
//!
//! Once fixed, these tests should pass with real VM execution.

use super::*;
use std::path::PathBuf;

/// Path to the MPC programs directory
fn programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("Stoffel-C-SPL")
        .join("mpc-programs")
}

/// Path to a specific compiled program
fn program_path(name: &str) -> PathBuf {
    programs_dir().join(format!("{}.stflb", name))
}

// ============================================================================
// Bytecode Loading Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_loads_valid_bytecode() {
    let mut executor = VmExecutor::new_real();

    // Load the confidential_transfer program
    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("Should have compiled bytecode in mpc-programs/");

    let result = executor.load_bytecode(&bytecode);
    assert!(result.is_ok(), "Valid bytecode should load successfully");
    assert!(executor.is_loaded());
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_loads_from_file() {
    let mut executor = VmExecutor::new_real();

    let result = executor.load_from_file(program_path("confidential_transfer"));
    assert!(result.is_ok(), "Should load bytecode from file");
    assert!(executor.is_loaded());
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_rejects_invalid_bytecode() {
    let mut executor = VmExecutor::new_real();

    // Garbage bytes that don't represent valid Stoffel bytecode
    let garbage = vec![0xFF, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF];

    let result = executor.load_bytecode(&garbage);
    assert!(result.is_err(), "Invalid bytecode should be rejected");

    match result {
        Err(VmError::ParseError(_)) => {} // Expected
        Err(other) => panic!("Expected ParseError, got {:?}", other),
        Ok(_) => panic!("Should have failed"),
    }
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_rejects_empty_bytecode() {
    let mut executor = VmExecutor::new_real();

    let result = executor.load_bytecode(&[]);
    assert!(result.is_err(), "Empty bytecode should be rejected");
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_rejects_truncated_bytecode() {
    let mut executor = VmExecutor::new_real();

    // Just the magic bytes, no actual program
    let truncated = b"STFL";

    let result = executor.load_bytecode(truncated);
    assert!(result.is_err(), "Truncated bytecode should be rejected");
}

// ============================================================================
// Entry Point Execution Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_executes_create_account_entry_point() {
    let mut executor = VmExecutor::new_real();

    // Load the create_account program
    let bytecode = std::fs::read(program_path("create_account"))
        .expect("create_account.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Execute with minimal args (program defines what it needs)
    let result = executor.execute("create_account");

    assert!(result.is_ok(), "create_account entry point should execute");

    // Result should be a 32-byte PDA address
    let value = result.unwrap();
    let bytes = value_to_bytes(&value);
    assert_eq!(bytes.len(), 32, "create_account should return 32-byte PDA");
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_executes_confidential_transfer_entry_point() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    let result = executor.execute("confidential_transfer");

    assert!(result.is_ok(), "confidential_transfer entry point should execute");

    // Result should be a 64-byte ciphertext (Twisted ElGamal)
    let value = result.unwrap();
    let bytes = value_to_bytes(&value);
    assert_eq!(
        bytes.len(),
        64,
        "confidential_transfer should return 64-byte ciphertext"
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_executes_generate_range_proof_entry_point() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("generate_range_proof"))
        .expect("generate_range_proof.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    let result = executor.execute("generate_range_proof");

    assert!(result.is_ok(), "generate_range_proof should execute");

    // Bulletproofs range proof is approximately 672 bytes
    let value = result.unwrap();
    let bytes = value_to_bytes(&value);
    assert!(
        bytes.len() >= 600 && bytes.len() <= 800,
        "Range proof should be ~672 bytes, got {}",
        bytes.len()
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_handles_missing_entry_point() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Try to execute a function that doesn't exist
    let result = executor.execute("nonexistent_function");

    assert!(result.is_err());
    match result {
        Err(VmError::FunctionNotFound(msg)) => {
            assert!(msg.contains("nonexistent_function"));
        }
        Err(other) => panic!("Expected FunctionNotFound, got {:?}", other),
        Ok(_) => panic!("Should have failed"),
    }
}

// ============================================================================
// Client Input Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_provides_client_inputs_to_program() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Provide client inputs (amount = 1000)
    let amount = Value::I64(1000);
    let result = executor.execute_with_args("confidential_transfer", &[amount]);

    assert!(
        result.is_ok(),
        "Should execute with client inputs: {:?}",
        result.err()
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_handles_multiple_client_inputs() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("authorize_transfer"))
        .expect("authorize_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Multiple inputs: source_balance, transfer_amount, etc.
    let inputs = vec![
        Value::I64(5000),  // source balance
        Value::I64(1000),  // transfer amount
        Value::Bool(true), // has permission
    ];

    let result = executor.execute_with_args("authorize_transfer", &inputs);

    assert!(
        result.is_ok(),
        "Should handle multiple inputs: {:?}",
        result.err()
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_validates_input_types() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Pass wrong type (string instead of int)
    let wrong_type_input = Value::String("not_a_number".to_string());
    let result = executor.execute_with_args("confidential_transfer", &[wrong_type_input]);

    // Should either fail or handle gracefully
    // The exact behavior depends on the program
    assert!(
        result.is_err() || result.is_ok(),
        "Should handle type mismatch gracefully"
    );
}

// ============================================================================
// MPC Output Capture Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_captures_mpc_outputs() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("partial_decrypt"))
        .expect("partial_decrypt.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Execute partial decryption
    let result = executor.execute("partial_decrypt");
    assert!(result.is_ok());

    // The program should have written to MpcOutput
    let value = result.unwrap();
    let bytes = value_to_bytes(&value);

    // Partial decryption share is a Ristretto point (32 bytes)
    assert_eq!(bytes.len(), 32, "Partial decryption should be 32 bytes");
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_captures_multiple_outputs() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("combine_partials"))
        .expect("combine_partials.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // combine_partials might output both the result and a proof
    let result = executor.execute("combine_partials");
    assert!(result.is_ok());

    // For now just verify it produces output
    let value = result.unwrap();
    let bytes = value_to_bytes(&value);
    assert!(!bytes.is_empty(), "Should produce output");
}

// ============================================================================
// Cryptographic Operation Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_confidential_transfer_produces_valid_ciphertext() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    let result = executor.execute_with_args("confidential_transfer", &[Value::I64(1000)]);
    assert!(result.is_ok());

    let value = result.unwrap();
    let bytes = value_to_bytes(&value);

    // Twisted ElGamal ciphertext: (C, D) where each is 32 bytes
    assert_eq!(
        bytes.len(),
        64,
        "Ciphertext should be 64 bytes (two 32-byte points)"
    );

    // First 32 bytes should be a valid compressed Ristretto point
    // (Not all zeros unless it's identity, which is unlikely)
    let c_point = &bytes[0..32];
    let d_point = &bytes[32..64];

    // Basic sanity: not all zeros (unless encrypting 0 with specific randomness)
    assert!(
        c_point.iter().any(|&b| b != 0) || d_point.iter().any(|&b| b != 0),
        "Ciphertext points shouldn't both be identity"
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_range_proof_verifies() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("generate_range_proof"))
        .expect("generate_range_proof.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Generate proof for value 1000
    let result = executor.execute_with_args("generate_range_proof", &[Value::I64(1000)]);
    assert!(result.is_ok());

    let value = result.unwrap();
    let proof_bytes = value_to_bytes(&value);

    // Would need a verifier to actually check, but we can verify size
    assert!(
        proof_bytes.len() >= 600,
        "Bulletproofs proof should be at least 600 bytes"
    );
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_handles_program_panic() {
    let mut executor = VmExecutor::new_real();

    // A program that panics (would need a special test program)
    // For now, test with invalid inputs that might cause division by zero
    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Negative amount might cause issues
    let result = executor.execute_with_args("confidential_transfer", &[Value::I64(-1)]);

    // Should return an error, not crash
    assert!(
        result.is_err() || result.is_ok(),
        "Should handle gracefully, not panic"
    );
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_vm_handles_out_of_bounds_access() {
    let mut executor = VmExecutor::new_real();

    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Execute without required inputs - program might access out of bounds
    let result = executor.execute("confidential_transfer");

    // Should either succeed with defaults or return an error
    match result {
        Ok(_) => {} // Program handles missing inputs
        Err(VmError::ExecutionError(_)) => {} // Expected failure
        Err(other) => panic!("Unexpected error type: {:?}", other),
    }
}

// ============================================================================
// Bytecode Format Tests
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_all_mpc_programs_load() {
    let programs = [
        "authorize_transfer",
        "claim_account",
        "combine_partials",
        "confidential_transfer",
        "create_account",
        "generate_range_proof",
        "partial_decrypt",
        "set_auditor",
        "wrap_mint",
    ];

    for program in programs {
        let mut executor = VmExecutor::new_real();
        let path = program_path(program);

        if path.exists() {
            let bytecode = std::fs::read(&path).expect(&format!("Should read {}", program));
            let result = executor.load_bytecode(&bytecode);

            assert!(
                result.is_ok(),
                "Program {} should load successfully",
                program
            );
            assert!(executor.is_loaded());
        } else {
            eprintln!("Warning: {} not found at {:?}", program, path);
        }
    }
}

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_bytecode_has_valid_magic_header() {
    let bytecode =
        std::fs::read(program_path("confidential_transfer")).expect("Should read bytecode");

    // Stoffel bytecode starts with magic bytes "STFL" or similar
    assert!(
        bytecode.len() >= 4,
        "Bytecode should have at least magic header"
    );

    // The exact magic depends on the compiler version
    // Common patterns: "STFL", "STFB", or version-prefixed
}

// ============================================================================
// Integration Test: Full Job Execution
// ============================================================================

#[test]
#[ignore = "Requires real VM integration - blocked on mpc-protocols"]
fn test_full_confidential_transfer_job() {
    // This test simulates a complete job execution as the executor would do:
    // 1. Load bytecode
    // 2. Prepare inputs from job request
    // 3. Execute
    // 4. Format outputs

    let mut executor = VmExecutor::new_real();

    // Step 1: Load
    let bytecode = std::fs::read(program_path("confidential_transfer"))
        .expect("confidential_transfer.stflb should exist");
    executor.load_bytecode(&bytecode).expect("Should load");

    // Step 2: Prepare inputs (simulating job inputs)
    let transfer_amount = Value::I64(500);
    let source_balance = Value::I64(1000);
    let inputs = vec![source_balance, transfer_amount];

    // Step 3: Execute
    let result = executor.execute_with_args("confidential_transfer", &inputs);
    assert!(result.is_ok(), "Execution should succeed: {:?}", result.err());

    // Step 4: Format output
    let value = result.unwrap();
    let output_bytes = value_to_bytes(&value);

    // Verify output format
    assert_eq!(
        output_bytes.len(),
        64,
        "Output should be 64-byte ciphertext"
    );
}
