//! StoffelVM integration for executing MPC programs
//!
//! This module provides a high-level wrapper around the StoffelVM
//! for loading and executing MPC programs within the coordinator.
//!
//! NOTE: Full VM integration is currently blocked on mpc-protocols compatibility.
//! The main branch of mpc-protocols has SenderId type errors, and the dev branch
//! has API changes incompatible with StoffelVM. For now, this module operates
//! in mock mode only, using stoffel-vm-types for Value types.

use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

// Re-export Value from stoffel-vm-types for use in handlers
pub use stoffel_vm_types::core_types::Value;

/// Errors that can occur during VM operations
#[derive(Error, Debug)]
pub enum VmError {
    #[error("Failed to load bytecode from file: {0}")]
    LoadError(String),

    #[error("Failed to parse bytecode: {0}")]
    ParseError(String),

    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    #[error("Execution failed: {0}")]
    ExecutionError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Result type for VM operations
pub type VmResult<T> = Result<T, VmError>;

/// Mock function handler type for testing
type MockHandler = fn(&[Value]) -> VmResult<Value>;

/// High-level wrapper around StoffelVM for MPC program execution
///
/// This executor currently operates in mock mode only until upstream
/// dependencies (mpc-protocols) are fixed.
///
/// Mock mode uses predefined handlers for testing without bytecode.
pub struct VmExecutor {
    /// Loaded program identifier
    loaded_program: Option<String>,
    /// Mock function handlers
    mock_functions: HashMap<String, MockHandler>,
    /// Whether mock mode is enabled (always true for now)
    mock_mode: bool,
}

impl VmExecutor {
    /// Create a new VM executor instance in mock mode
    pub fn new() -> Self {
        let mut executor = Self {
            loaded_program: None,
            mock_functions: HashMap::new(),
            mock_mode: true,
        };
        executor.register_default_mock_functions();
        executor
    }

    /// Create a new VM executor in "real" mode
    ///
    /// NOTE: Real mode is not currently available due to upstream dependency issues.
    /// This will behave the same as mock mode until mpc-protocols compatibility is fixed.
    pub fn new_real() -> Self {
        tracing::warn!(
            "Real VM mode requested but not available - using mock mode. \
             Full VM integration blocked on mpc-protocols compatibility."
        );
        Self::new()
    }

    /// Set mock mode on or off
    ///
    /// NOTE: Currently mock mode is always on until upstream dependencies are fixed.
    pub fn set_mock_mode(&mut self, mock: bool) {
        if !mock {
            tracing::warn!(
                "Cannot disable mock mode - real VM not available. \
                 Full VM integration blocked on mpc-protocols compatibility."
            );
        }
        self.mock_mode = true; // Always mock mode for now
    }

    /// Register default mock functions for testing
    fn register_default_mock_functions(&mut self) {
        // authorize_transfer - returns mock authorization token
        self.mock_functions.insert(
            "authorize_transfer".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xAA; 32]))),
        );

        // partial_decrypt - returns mock decryption share
        self.mock_functions.insert(
            "partial_decrypt".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xBB; 48]))),
        );

        // combine_partials - returns mock combined result
        self.mock_functions.insert(
            "combine_partials".to_string(),
            |_args| Ok(Value::U64(1000)),
        );

        // confidential_transfer - returns mock transfer result
        self.mock_functions.insert(
            "confidential_transfer".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xCC; 64]))),
        );

        // main - generic entry point
        self.mock_functions.insert(
            "main".to_string(),
            |_args| Ok(Value::Unit),
        );

        // create_account - returns mock 32-byte PDA address
        self.mock_functions.insert(
            "create_account".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xDD; 32]))),
        );

        // claim_account - returns mock 64-byte output (address + signature)
        self.mock_functions.insert(
            "claim_account".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xEE; 64]))),
        );

        // wrap_mint - returns mock 32-byte confidential mint address
        self.mock_functions.insert(
            "wrap_mint".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0xFF; 32]))),
        );

        // set_auditor - returns mock 64-byte output (mint + confirmation)
        self.mock_functions.insert(
            "set_auditor".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0x11; 64]))),
        );

        // generate_range_proof - returns mock ~672-byte Bulletproofs proof
        self.mock_functions.insert(
            "generate_range_proof".to_string(),
            |_args| Ok(Value::String(hex::encode(vec![0x22; 672]))),
        );
    }

    /// Load a compiled program from bytecode bytes
    pub fn load_bytecode(&mut self, bytecode: &[u8]) -> VmResult<()> {
        // In mock mode, accept any bytecode with minimal validation
        if bytecode.len() < 4 {
            return Err(VmError::ParseError("Bytecode too short".to_string()));
        }
        self.loaded_program = Some(format!("mock:bytecode:{} bytes", bytecode.len()));
        Ok(())
    }

    /// Load a compiled program from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> VmResult<()> {
        let path_ref = path.as_ref();
        self.loaded_program = Some(path_ref.display().to_string());
        Ok(())
    }

    /// Execute a function by name with no arguments
    pub fn execute(&mut self, function_name: &str) -> VmResult<Value> {
        self.execute_with_args(function_name, &[])
    }

    /// Execute a function with arguments
    pub fn execute_with_args(&mut self, function_name: &str, args: &[Value]) -> VmResult<Value> {
        // Use mock function handlers
        if let Some(handler) = self.mock_functions.get(function_name) {
            return handler(args);
        }
        Err(VmError::FunctionNotFound(format!(
            "Function '{}' not found in mock handlers",
            function_name
        )))
    }

    /// Check if a program has been loaded
    pub fn is_loaded(&self) -> bool {
        self.loaded_program.is_some()
    }

    /// Get the loaded program identifier
    pub fn loaded_program(&self) -> Option<&str> {
        self.loaded_program.as_deref()
    }

    /// Check if running in mock mode
    pub fn is_mock_mode(&self) -> bool {
        self.mock_mode
    }

    /// Register a custom mock function (for testing)
    ///
    /// This method has been renamed from `register_function` for clarity.
    pub fn register_mock_function(&mut self, name: &str, handler: MockHandler) {
        self.mock_functions.insert(name.to_string(), handler);
    }

    /// Register a custom function (alias for register_mock_function)
    ///
    /// Provided for backwards compatibility with existing test code.
    pub fn register_function(&mut self, name: &str, handler: MockHandler) {
        self.register_mock_function(name, handler);
    }
}

impl Default for VmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a VM Value to bytes for output
///
/// This function converts various Value types to their byte representation
/// for use in job outputs.
pub fn value_to_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::I64(n) => n.to_le_bytes().to_vec(),
        Value::I32(n) => n.to_le_bytes().to_vec(),
        Value::I16(n) => n.to_le_bytes().to_vec(),
        Value::I8(n) => (*n as u8).to_le_bytes().to_vec(),
        Value::U8(n) => n.to_le_bytes().to_vec(),
        Value::U16(n) => n.to_le_bytes().to_vec(),
        Value::U32(n) => n.to_le_bytes().to_vec(),
        Value::U64(n) => n.to_le_bytes().to_vec(),
        Value::Float(f) => f.0.to_le_bytes().to_vec(),
        Value::Bool(b) => vec![if *b { 1 } else { 0 }],
        Value::String(s) => {
            // Try to decode as hex first (common for cryptographic outputs)
            hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec())
        }
        Value::Share(_, bytes) => bytes.clone(),
        Value::Unit => vec![],
        // Complex types that can't be directly converted to bytes
        Value::Object(_) | Value::Array(_) | Value::Foreign(_) | Value::Closure(_) => vec![],
    }
}

// Hex encoding/decoding utilities
mod hex {
    pub fn encode(data: Vec<u8>) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_executor_creation() {
        let executor = VmExecutor::new();
        assert!(!executor.is_loaded());
        assert!(executor.loaded_program().is_none());
        assert!(executor.is_mock_mode());
    }

    #[test]
    fn test_vm_executor_real_mode_fallback() {
        // Real mode falls back to mock mode until deps are fixed
        let executor = VmExecutor::new_real();
        assert!(!executor.is_loaded());
        assert!(executor.is_mock_mode());
    }

    #[test]
    fn test_execute_authorize_transfer_mock() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("authorize_transfer").unwrap();

        match result {
            Value::String(hex_str) => {
                let bytes = hex::decode(&hex_str).unwrap();
                assert_eq!(bytes.len(), 32);
                assert!(bytes.iter().all(|&b| b == 0xAA));
            }
            _ => panic!("Expected String result, got {:?}", result),
        }
    }

    #[test]
    fn test_execute_partial_decrypt_mock() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("partial_decrypt").unwrap();

        match result {
            Value::String(hex_str) => {
                let bytes = hex::decode(&hex_str).unwrap();
                assert_eq!(bytes.len(), 48);
            }
            _ => panic!("Expected String result, got {:?}", result),
        }
    }

    #[test]
    fn test_execute_combine_partials_mock() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("combine_partials").unwrap();

        match result {
            Value::U64(amount) => assert_eq!(amount, 1000),
            _ => panic!("Expected U64 result, got {:?}", result),
        }
    }

    #[test]
    fn test_function_not_found() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("nonexistent_function");

        assert!(result.is_err());
        match result {
            Err(VmError::FunctionNotFound(msg)) => {
                assert!(msg.contains("nonexistent_function"));
            }
            _ => panic!("Expected FunctionNotFound error"),
        }
    }

    #[test]
    fn test_load_from_file_mock() {
        let mut executor = VmExecutor::new();

        // In mock mode, any path is accepted
        let result = executor.load_from_file("/mock/path/program.stfbin");
        assert!(result.is_ok());
        assert!(executor.is_loaded());
    }

    #[test]
    fn test_custom_mock_function_registration() {
        let mut executor = VmExecutor::new();

        executor.register_mock_function("double", |args| {
            if let Some(Value::I64(n)) = args.first() {
                Ok(Value::I64(n * 2))
            } else {
                Err(VmError::InvalidInput("Expected I64".to_string()))
            }
        });

        let result = executor.execute_with_args("double", &[Value::I64(21)]).unwrap();
        assert_eq!(result, Value::I64(42));
    }

    #[test]
    fn test_value_to_bytes() {
        assert_eq!(value_to_bytes(&Value::I64(42)), 42i64.to_le_bytes().to_vec());
        assert_eq!(value_to_bytes(&Value::U64(42)), 42u64.to_le_bytes().to_vec());
        assert_eq!(value_to_bytes(&Value::Bool(true)), vec![1]);
        assert_eq!(value_to_bytes(&Value::Bool(false)), vec![0]);
        assert!(value_to_bytes(&Value::Unit).is_empty());

        // Test hex string decoding
        let hex_result = value_to_bytes(&Value::String("aabbcc".to_string()));
        assert_eq!(hex_result, vec![0xaa, 0xbb, 0xcc]);

        // Test non-hex string (falls back to UTF-8 bytes)
        let str_result = value_to_bytes(&Value::String("hello".to_string()));
        assert_eq!(str_result, b"hello".to_vec());
    }

    #[test]
    fn test_set_mock_mode() {
        let mut executor = VmExecutor::new();
        assert!(executor.is_mock_mode());

        // Setting to false should keep mock mode (with warning)
        executor.set_mock_mode(false);
        assert!(executor.is_mock_mode());

        executor.set_mock_mode(true);
        assert!(executor.is_mock_mode());
    }
}
