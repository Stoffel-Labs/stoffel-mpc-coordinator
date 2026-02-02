//! Stoffel MPC Coordinator
//!
//! REST API service for coordinating Multi-Party Computation jobs.
//! Handles job submission, status tracking, and result retrieval.

pub mod types;
pub mod jobs;
pub mod server;
pub mod vm;
pub mod executor;

pub use types::*;
pub use jobs::{JobQueue, Job};
pub use server::create_router;
pub use vm::{VmExecutor, VmError, VmResult, Value};
pub use executor::{JobExecutor, ExecutorConfig, ExecutorError};
