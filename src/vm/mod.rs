//! StoffelVM integration for executing MPC programs
//!
//! This module provides a high-level wrapper around the StoffelVM
//! for loading and executing MPC programs within the coordinator.
//!
//! NOTE: Currently using mock implementation due to StoffelVM API compatibility
//! issues with mpc-protocols. Once StoffelVM is updated, replace with real VM.

use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

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

/// VM Value type (mock - mirrors stoffel-vm-types Value)
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    I64(i64),
    U64(u64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Unit,
}

impl Value {
    /// Convert value to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Value::I64(n) => n.to_le_bytes().to_vec(),
            Value::U64(n) => n.to_le_bytes().to_vec(),
            Value::Bool(b) => vec![if *b { 1 } else { 0 }],
            Value::String(s) => s.as_bytes().to_vec(),
            Value::Bytes(bytes) => bytes.clone(),
            Value::Unit => vec![],
        }
    }
}

/// Mock VM function for testing
#[derive(Debug, Clone)]
pub struct MockFunction {
    pub name: String,
    pub handler: fn(&[Value]) -> VmResult<Value>,
}

/// High-level wrapper around StoffelVM for MPC program execution
///
/// This is currently a mock implementation that simulates VM behavior
/// for testing the coordinator infrastructure.
pub struct VmExecutor {
    loaded_program: Option<String>,
    functions: HashMap<String, MockFunction>,
    mock_mode: bool,
}

impl VmExecutor {
    /// Create a new VM executor instance
    pub fn new() -> Self {
        let mut executor = Self {
            loaded_program: None,
            functions: HashMap::new(),
            mock_mode: true,
        };
        executor.register_default_functions();
        executor
    }

    /// Register default mock functions for testing
    fn register_default_functions(&mut self) {
        // authorize_transfer - returns mock authorization token
        self.functions.insert(
            "authorize_transfer".to_string(),
            MockFunction {
                name: "authorize_transfer".to_string(),
                handler: |_args| {
                    // Return mock authorization token (32 bytes)
                    Ok(Value::Bytes(vec![0xAA; 32]))
                },
            },
        );

        // partial_decrypt - returns mock decryption share
        self.functions.insert(
            "partial_decrypt".to_string(),
            MockFunction {
                name: "partial_decrypt".to_string(),
                handler: |_args| {
                    // Return mock partial decryption (48 bytes for BLS)
                    Ok(Value::Bytes(vec![0xBB; 48]))
                },
            },
        );

        // combine_partials - returns mock combined result
        self.functions.insert(
            "combine_partials".to_string(),
            MockFunction {
                name: "combine_partials".to_string(),
                handler: |_args| {
                    // Return mock plaintext amount
                    Ok(Value::U64(1000))
                },
            },
        );

        // confidential_transfer - returns mock transfer result
        self.functions.insert(
            "confidential_transfer".to_string(),
            MockFunction {
                name: "confidential_transfer".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0xCC; 64]))
                },
            },
        );

        // main - generic entry point
        self.functions.insert(
            "main".to_string(),
            MockFunction {
                name: "main".to_string(),
                handler: |_args| Ok(Value::Unit),
            },
        );

        // create_account - returns mock 32-byte PDA address
        self.functions.insert(
            "create_account".to_string(),
            MockFunction {
                name: "create_account".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0xDD; 32]))
                },
            },
        );

        // claim_account - returns mock 64-byte output (address + signature)
        self.functions.insert(
            "claim_account".to_string(),
            MockFunction {
                name: "claim_account".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0xEE; 64]))
                },
            },
        );

        // wrap_mint - returns mock 32-byte confidential mint address
        self.functions.insert(
            "wrap_mint".to_string(),
            MockFunction {
                name: "wrap_mint".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0xFF; 32]))
                },
            },
        );

        // set_auditor - returns mock 64-byte output (mint + confirmation)
        self.functions.insert(
            "set_auditor".to_string(),
            MockFunction {
                name: "set_auditor".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0x11; 64]))
                },
            },
        );

        // generate_range_proof - returns mock ~672-byte Bulletproofs proof
        self.functions.insert(
            "generate_range_proof".to_string(),
            MockFunction {
                name: "generate_range_proof".to_string(),
                handler: |_args| {
                    Ok(Value::Bytes(vec![0x22; 672]))
                },
            },
        );
    }

    /// Load a compiled program from bytecode bytes
    pub fn load_bytecode(&mut self, bytecode: &[u8]) -> VmResult<()> {
        // Validate bytecode magic number (STFL)
        if bytecode.len() < 4 {
            return Err(VmError::ParseError("Bytecode too short".to_string()));
        }

        // In mock mode, we accept any bytecode
        if self.mock_mode {
            self.loaded_program = Some(format!("bytecode:{} bytes", bytecode.len()));
            return Ok(());
        }

        // Check for STFL magic bytes
        if &bytecode[0..4] != b"STFL" {
            return Err(VmError::ParseError("Invalid magic bytes".to_string()));
        }

        self.loaded_program = Some(format!("bytecode:{} bytes", bytecode.len()));
        Ok(())
    }

    /// Load a compiled program from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> VmResult<()> {
        let path_ref = path.as_ref();

        // In mock mode, just check if path is reasonable
        if self.mock_mode {
            self.loaded_program = Some(path_ref.display().to_string());
            return Ok(());
        }

        // Real implementation would read the file
        let bytecode = std::fs::read(path_ref)
            .map_err(|e| VmError::LoadError(format!("{}: {}", path_ref.display(), e)))?;

        self.load_bytecode(&bytecode)
    }

    /// Execute a function by name with no arguments
    pub fn execute(&mut self, function_name: &str) -> VmResult<Value> {
        self.execute_with_args(function_name, &[])
    }

    /// Execute a function with arguments
    pub fn execute_with_args(&mut self, function_name: &str, args: &[Value]) -> VmResult<Value> {
        // Look up function
        if let Some(func) = self.functions.get(function_name) {
            (func.handler)(args)
        } else {
            Err(VmError::FunctionNotFound(format!(
                "Function '{}' not found",
                function_name
            )))
        }
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

    /// Register a custom function (for testing)
    pub fn register_function(&mut self, name: &str, handler: fn(&[Value]) -> VmResult<Value>) {
        self.functions.insert(
            name.to_string(),
            MockFunction {
                name: name.to_string(),
                handler,
            },
        );
    }
}

impl Default for VmExecutor {
    fn default() -> Self {
        Self::new()
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
    fn test_execute_authorize_transfer() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("authorize_transfer").unwrap();

        match result {
            Value::Bytes(bytes) => {
                assert_eq!(bytes.len(), 32);
                assert!(bytes.iter().all(|&b| b == 0xAA));
            }
            _ => panic!("Expected Bytes result"),
        }
    }

    #[test]
    fn test_execute_partial_decrypt() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("partial_decrypt").unwrap();

        match result {
            Value::Bytes(bytes) => {
                assert_eq!(bytes.len(), 48);
            }
            _ => panic!("Expected Bytes result"),
        }
    }

    #[test]
    fn test_execute_combine_partials() {
        let mut executor = VmExecutor::new();
        executor.load_bytecode(b"STFL_mock").unwrap();

        let result = executor.execute("combine_partials").unwrap();

        match result {
            Value::U64(amount) => assert_eq!(amount, 1000),
            _ => panic!("Expected U64 result"),
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
    fn test_custom_function_registration() {
        let mut executor = VmExecutor::new();

        executor.register_function("double", |args| {
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
        assert_eq!(Value::I64(42).to_bytes(), 42i64.to_le_bytes().to_vec());
        assert_eq!(Value::Bool(true).to_bytes(), vec![1]);
        assert_eq!(Value::Bool(false).to_bytes(), vec![0]);
        assert_eq!(Value::Bytes(vec![1, 2, 3]).to_bytes(), vec![1, 2, 3]);
        assert!(Value::Unit.to_bytes().is_empty());
    }
}
