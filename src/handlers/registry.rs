//! Handler registry for looking up job handlers by type

use std::collections::HashMap;
use std::sync::Arc;

use crate::types::JobType;
use super::{
    JobHandler,
    AuthorizeTransferHandler,
    ClaimConfidentialAccountHandler,
    ConfidentialTransferHandler,
    CreateConfidentialAccountHandler,
    DistributedDecryptHandler,
    GenerateRangeProofHandler,
    SetAuditorHandler,
    WrapMintHandler,
};

/// Registry for job handlers
///
/// Maps job types to their corresponding handlers. This allows the executor
/// to dynamically dispatch jobs to the appropriate handler.
pub struct HandlerRegistry {
    handlers: HashMap<JobType, Arc<dyn JobHandler>>,
}

impl HandlerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a job type
    pub fn register<H: JobHandler + 'static>(&mut self, handler: H) {
        let job_type = handler.job_type();
        self.handlers.insert(job_type, Arc::new(handler));
    }

    /// Get the handler for a job type
    pub fn get(&self, job_type: &JobType) -> Option<Arc<dyn JobHandler>> {
        self.handlers.get(job_type).cloned()
    }

    /// Check if a handler is registered for a job type
    pub fn has_handler(&self, job_type: &JobType) -> bool {
        self.handlers.contains_key(job_type)
    }

    /// Get all registered job types
    pub fn registered_types(&self) -> Vec<JobType> {
        self.handlers.keys().copied().collect()
    }

    /// Get the number of registered handlers
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a registry with all default handlers registered
pub fn get_default_registry() -> HandlerRegistry {
    let mut registry = HandlerRegistry::new();

    // Register core handlers
    registry.register(AuthorizeTransferHandler::new());
    registry.register(ConfidentialTransferHandler::new());
    registry.register(DistributedDecryptHandler::new());

    // Register additional handlers
    registry.register(CreateConfidentialAccountHandler::new());
    registry.register(ClaimConfidentialAccountHandler::new());
    registry.register(WrapMintHandler::new());
    registry.register(SetAuditorHandler::new());
    registry.register(GenerateRangeProofHandler::new());

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = HandlerRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_register_handler() {
        let mut registry = HandlerRegistry::new();
        registry.register(AuthorizeTransferHandler::new());

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.has_handler(&JobType::AuthorizeTransfer));
    }

    #[test]
    fn test_get_handler() {
        let mut registry = HandlerRegistry::new();
        registry.register(AuthorizeTransferHandler::new());

        let handler = registry.get(&JobType::AuthorizeTransfer);
        assert!(handler.is_some());
        assert_eq!(handler.unwrap().job_type(), JobType::AuthorizeTransfer);
    }

    #[test]
    fn test_get_missing_handler() {
        let registry = HandlerRegistry::new();
        let handler = registry.get(&JobType::AuthorizeTransfer);
        assert!(handler.is_none());
    }

    #[test]
    fn test_default_registry() {
        let registry = get_default_registry();

        // Core handlers
        assert!(registry.has_handler(&JobType::AuthorizeTransfer));
        assert!(registry.has_handler(&JobType::ConfidentialTransfer));
        assert!(registry.has_handler(&JobType::DistributedDecrypt));

        // Additional handlers
        assert!(registry.has_handler(&JobType::CreateConfidentialAccount));
        assert!(registry.has_handler(&JobType::ClaimConfidentialAccount));
        assert!(registry.has_handler(&JobType::WrapMint));
        assert!(registry.has_handler(&JobType::SetAuditor));
        assert!(registry.has_handler(&JobType::GenerateRangeProof));

        assert_eq!(registry.len(), 8);
    }

    #[test]
    fn test_registered_types() {
        let registry = get_default_registry();
        let types = registry.registered_types();

        // Core handlers
        assert!(types.contains(&JobType::AuthorizeTransfer));
        assert!(types.contains(&JobType::ConfidentialTransfer));
        assert!(types.contains(&JobType::DistributedDecrypt));

        // Additional handlers
        assert!(types.contains(&JobType::CreateConfidentialAccount));
        assert!(types.contains(&JobType::ClaimConfidentialAccount));
        assert!(types.contains(&JobType::WrapMint));
        assert!(types.contains(&JobType::SetAuditor));
        assert!(types.contains(&JobType::GenerateRangeProof));
    }
}
