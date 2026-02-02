//! Job execution pipeline for processing MPC jobs through the VM
//!
//! This module handles the job processing loop, taking jobs from the queue,
//! executing them through StoffelVM, and updating their status.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn, error, debug};

use crate::jobs::{JobQueue, Job};
use crate::types::{JobStatus, JobType};
use crate::vm::{VmExecutor, VmError, value_to_bytes};

/// Configuration for the job executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// How often to poll for new jobs (milliseconds)
    pub poll_interval_ms: u64,
    /// Maximum number of concurrent job executions
    pub max_concurrent_jobs: usize,
    /// Directory containing compiled MPC programs
    pub programs_dir: String,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 100,
            max_concurrent_jobs: 4,
            programs_dir: "./programs".to_string(),
        }
    }
}

/// Maps job types to their corresponding program files
pub fn job_type_to_program(job_type: &JobType) -> &'static str {
    match job_type {
        JobType::AuthorizeTransfer => "authorize_transfer.stfbin",
        JobType::ConfidentialTransfer => "confidential_transfer.stfbin",
        JobType::CreateConfidentialAccount => "create_account.stfbin",
        JobType::ClaimConfidentialAccount => "claim_account.stfbin",
        JobType::WrapMint => "wrap_mint.stfbin",
        JobType::SetAuditor => "set_auditor.stfbin",
        JobType::DistributedDecrypt => "partial_decrypt.stfbin",
        JobType::GenerateRangeProof => "range_proof.stfbin",
    }
}

/// Maps job types to their entry point function names
pub fn job_type_to_entry_point(job_type: &JobType) -> &'static str {
    match job_type {
        JobType::AuthorizeTransfer => "authorize_transfer",
        JobType::ConfidentialTransfer => "confidential_transfer",
        JobType::DistributedDecrypt => "partial_decrypt",
        JobType::CreateConfidentialAccount => "main",
        JobType::ClaimConfidentialAccount => "main",
        JobType::WrapMint => "main",
        JobType::SetAuditor => "main",
        JobType::GenerateRangeProof => "main",
    }
}

/// Job executor that processes jobs from the queue
pub struct JobExecutor {
    job_queue: JobQueue,
    config: ExecutorConfig,
    running: Arc<RwLock<bool>>,
}

impl JobExecutor {
    /// Create a new job executor
    pub fn new(job_queue: JobQueue, config: ExecutorConfig) -> Self {
        Self {
            job_queue,
            config,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Check if the executor is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Stop the executor
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Process the next available job
    /// Returns true if a job was processed, false if queue was empty
    pub async fn process_next_job(&self) -> Result<bool, ExecutorError> {
        // Get next queued job
        let job = match self.job_queue.peek_next().await {
            Some(job) if job.status == JobStatus::Queued => job,
            _ => return Ok(false),
        };

        let job_id = job.id;
        info!(job_id = %job_id, job_type = ?job.job_type, "Processing job");

        // Transition to Assigned
        self.job_queue.update_status(job_id, JobStatus::Assigned).await;

        // Execute the job
        match self.execute_job(&job).await {
            Ok(outputs) => {
                info!(job_id = %job_id, output_len = outputs.len(), "Job completed successfully");
                self.job_queue.complete_job(job_id, outputs).await;
                Ok(true)
            }
            Err(e) => {
                error!(job_id = %job_id, error = %e, "Job execution failed");
                self.job_queue.fail_job(job_id, e.to_string()).await;
                Ok(true)
            }
        }
    }

    /// Execute a single job through the VM
    async fn execute_job(&self, job: &Job) -> Result<Vec<u8>, ExecutorError> {
        // Create VM executor for this job
        let mut vm = VmExecutor::new();

        // Load the appropriate program
        let program_name = job_type_to_program(&job.job_type);
        let program_path = format!("{}/{}", self.config.programs_dir, program_name);

        // Transition to Preprocessing
        self.job_queue.update_status(job.id, JobStatus::Preprocessing).await;

        // Load the program (in mock mode, this always succeeds)
        vm.load_from_file(&program_path)
            .map_err(|e| ExecutorError::ProgramLoad(e.to_string()))?;

        // Log inputs info
        debug!(
            job_id = %job.id,
            input_count = job.inputs.len(),
            "Processing job inputs"
        );

        // Transition to Executing
        self.job_queue.update_status(job.id, JobStatus::Executing).await;

        // Execute the entry point function
        let entry_point = job_type_to_entry_point(&job.job_type);
        let result = vm.execute(entry_point)
            .map_err(|e| ExecutorError::Execution(e.to_string()))?;

        // Transition to Signing (placeholder for MPC signing phase)
        self.job_queue.update_status(job.id, JobStatus::Signing).await;

        // Convert result to bytes
        let output_bytes = value_to_bytes(&result);

        Ok(output_bytes)
    }

    /// Run the executor loop (blocking)
    pub async fn run(&self) {
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        info!(
            poll_interval_ms = self.config.poll_interval_ms,
            programs_dir = %self.config.programs_dir,
            "Starting job executor"
        );

        loop {
            // Check if we should stop
            if !*self.running.read().await {
                info!("Job executor stopping");
                break;
            }

            // Try to process a job
            match self.process_next_job().await {
                Ok(true) => {
                    debug!("Job processed successfully");
                }
                Ok(false) => {
                    // No jobs available, wait before checking again
                    sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
                }
                Err(e) => {
                    warn!(error = %e, "Error processing job");
                    sleep(Duration::from_millis(self.config.poll_interval_ms)).await;
                }
            }
        }
    }

    /// Spawn the executor in a background task
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run().await;
        })
    }
}

/// Errors that can occur during job execution
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("Failed to load program: {0}")]
    ProgramLoad(String),

    #[error("Failed to serialize inputs: {0}")]
    InputSerialization(String),

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("Failed to serialize output: {0}")]
    OutputSerialization(String),

    #[error("VM error: {0}")]
    Vm(#[from] VmError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{JobRequest, ClientInput};
    use base64::Engine;

    fn make_test_request(job_type: JobType) -> JobRequest {
        JobRequest {
            job_type,
            program_hash: "0x1234".to_string(),
            inputs: vec![
                ClientInput {
                    client_id: "client1".to_string(),
                    index: 0,
                    data: base64::engine::general_purpose::STANDARD.encode(&[10, 20, 30]),
                    is_secret: true,
                }
            ],
            idempotency_key: format!("test-{:?}-{}", job_type, uuid::Uuid::new_v4()),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: chrono::Utc::now().timestamp() as u64,
        }
    }

    #[test]
    fn test_job_type_to_program() {
        assert_eq!(
            job_type_to_program(&JobType::AuthorizeTransfer),
            "authorize_transfer.stfbin"
        );
        assert_eq!(
            job_type_to_program(&JobType::DistributedDecrypt),
            "partial_decrypt.stfbin"
        );
    }

    #[test]
    fn test_job_type_to_entry_point() {
        assert_eq!(
            job_type_to_entry_point(&JobType::AuthorizeTransfer),
            "authorize_transfer"
        );
        assert_eq!(
            job_type_to_entry_point(&JobType::ConfidentialTransfer),
            "confidential_transfer"
        );
    }

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert_eq!(config.poll_interval_ms, 100);
        assert_eq!(config.max_concurrent_jobs, 4);
    }

    #[tokio::test]
    async fn test_executor_creation() {
        let queue = JobQueue::new();
        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue, config);

        assert!(!executor.is_running().await);
    }

    #[tokio::test]
    async fn test_executor_stop() {
        let queue = JobQueue::new();
        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue, config);

        // Start and stop
        {
            let mut running = executor.running.write().await;
            *running = true;
        }
        assert!(executor.is_running().await);

        executor.stop().await;
        assert!(!executor.is_running().await);
    }

    #[tokio::test]
    async fn test_process_empty_queue() {
        let queue = JobQueue::new();
        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue, config);

        // Should return Ok(false) when queue is empty
        let result = executor.process_next_job().await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_job_succeeds_with_mock_vm() {
        let queue = JobQueue::new();
        let request = make_test_request(JobType::AuthorizeTransfer);

        // Submit a job
        let (job_id, _, _) = queue.submit(request).await;

        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue.clone(), config);

        // Process should succeed with mock VM
        let result = executor.process_next_job().await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Job was processed

        // Check job is marked as complete
        let job = queue.get(job_id).await.unwrap();
        assert_eq!(job.status, JobStatus::Complete);
        assert!(job.outputs.is_some());

        // Verify output is the mock authorization token (32 bytes of 0xAA)
        let outputs = job.outputs.unwrap();
        assert_eq!(outputs.len(), 32);
        assert!(outputs.iter().all(|&b| b == 0xAA));
    }

    #[tokio::test]
    async fn test_process_partial_decrypt_job() {
        let queue = JobQueue::new();
        let request = make_test_request(JobType::DistributedDecrypt);

        let (job_id, _, _) = queue.submit(request).await;

        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue.clone(), config);

        let result = executor.process_next_job().await;
        assert!(result.is_ok());

        let job = queue.get(job_id).await.unwrap();
        assert_eq!(job.status, JobStatus::Complete);

        // Verify output is the mock partial decryption (48 bytes of 0xBB)
        let outputs = job.outputs.unwrap();
        assert_eq!(outputs.len(), 48);
    }

    #[tokio::test]
    async fn test_queue_depth_decreases_after_completion() {
        let queue = JobQueue::new();
        let request1 = make_test_request(JobType::AuthorizeTransfer);
        let request2 = make_test_request(JobType::ConfidentialTransfer);

        queue.submit(request1).await;
        queue.submit(request2).await;

        assert_eq!(queue.queue_depth().await, 2);

        let config = ExecutorConfig::default();
        let executor = JobExecutor::new(queue.clone(), config);

        // Process first job
        executor.process_next_job().await.unwrap();
        assert_eq!(queue.queue_depth().await, 1);

        // Process second job
        executor.process_next_job().await.unwrap();
        assert_eq!(queue.queue_depth().await, 0);
    }
}
