//! Stoffel MPC Coordinator
//!
//! REST API service for coordinating Multi-Party Computation jobs.
//! Handles job submission, status tracking, and result retrieval.

pub mod types;
pub mod jobs;
pub mod server;

pub use types::*;
pub use jobs::JobQueue;
pub use server::create_router;
