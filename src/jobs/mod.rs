//! Job queue and state management for MPC computations

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::types::{JobType, JobStatus, JobRequest, ClientInput};

/// Internal representation of a job in the queue
#[derive(Debug, Clone)]
pub struct Job {
    pub id: Uuid,
    pub job_type: JobType,
    pub program_hash: String,
    pub inputs: Vec<ClientInput>,
    pub idempotency_key: String,
    pub key_id: String,
    pub client_id: String,
    pub status: JobStatus,
    pub outputs: Option<Vec<u8>>,
    pub error: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl Job {
    /// Create a new job from a request
    pub fn from_request(request: JobRequest) -> Self {
        Self {
            id: Uuid::new_v4(),
            job_type: request.job_type,
            program_hash: request.program_hash,
            inputs: request.inputs,
            idempotency_key: request.idempotency_key,
            key_id: request.key_id,
            client_id: request.client_id,
            status: JobStatus::Queued,
            outputs: None,
            error: None,
            submitted_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Transition to a new status
    pub fn transition_to(&mut self, status: JobStatus) {
        self.status = status;
        if matches!(status, JobStatus::Complete | JobStatus::Failed) {
            self.completed_at = Some(Utc::now());
        }
    }

    /// Mark job as complete with outputs
    pub fn complete(&mut self, outputs: Vec<u8>) {
        self.outputs = Some(outputs);
        self.transition_to(JobStatus::Complete);
    }

    /// Mark job as failed with error
    pub fn fail(&mut self, error: String) {
        self.error = Some(error);
        self.transition_to(JobStatus::Failed);
    }
}

/// Thread-safe job queue for managing MPC computations
#[derive(Debug, Clone)]
pub struct JobQueue {
    /// All jobs indexed by ID
    jobs: Arc<RwLock<HashMap<Uuid, Job>>>,
    /// Idempotency key to job ID mapping
    idempotency_map: Arc<RwLock<HashMap<String, Uuid>>>,
    /// Queue of job IDs waiting to be processed (FIFO)
    queue: Arc<RwLock<Vec<Uuid>>>,
}

impl JobQueue {
    /// Create a new empty job queue
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            idempotency_map: Arc::new(RwLock::new(HashMap::new())),
            queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Submit a new job to the queue
    /// Returns the existing job if idempotency key matches
    pub async fn submit(&self, request: JobRequest) -> (Uuid, usize, bool) {
        // Check idempotency
        {
            let idempotency_map = self.idempotency_map.read().await;
            if let Some(&existing_id) = idempotency_map.get(&request.idempotency_key) {
                let jobs = self.jobs.read().await;
                if jobs.contains_key(&existing_id) {
                    let queue = self.queue.read().await;
                    let position = queue.iter().position(|&id| id == existing_id).unwrap_or(0);
                    return (existing_id, position, false); // Not new
                }
            }
        }

        // Create new job
        let job = Job::from_request(request.clone());
        let job_id = job.id;

        // Add to stores
        {
            let mut jobs = self.jobs.write().await;
            let mut idempotency_map = self.idempotency_map.write().await;
            let mut queue = self.queue.write().await;

            jobs.insert(job_id, job);
            idempotency_map.insert(request.idempotency_key, job_id);
            queue.push(job_id);

            (job_id, queue.len() - 1, true) // New job
        }
    }

    /// Get a job by ID
    pub async fn get(&self, job_id: Uuid) -> Option<Job> {
        let jobs = self.jobs.read().await;
        jobs.get(&job_id).cloned()
    }

    /// Update a job's status
    pub async fn update_status(&self, job_id: Uuid, status: JobStatus) -> bool {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(&job_id) {
            job.transition_to(status);
            true
        } else {
            false
        }
    }

    /// Mark a job as complete with outputs
    pub async fn complete_job(&self, job_id: Uuid, outputs: Vec<u8>) -> bool {
        let mut jobs = self.jobs.write().await;
        let mut queue = self.queue.write().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.complete(outputs);
            queue.retain(|&id| id != job_id);
            true
        } else {
            false
        }
    }

    /// Mark a job as failed with error
    pub async fn fail_job(&self, job_id: Uuid, error: String) -> bool {
        let mut jobs = self.jobs.write().await;
        let mut queue = self.queue.write().await;

        if let Some(job) = jobs.get_mut(&job_id) {
            job.fail(error);
            queue.retain(|&id| id != job_id);
            true
        } else {
            false
        }
    }

    /// Get the next job in the queue (without removing it)
    pub async fn peek_next(&self) -> Option<Job> {
        let queue = self.queue.read().await;
        if let Some(&job_id) = queue.first() {
            let jobs = self.jobs.read().await;
            jobs.get(&job_id).cloned()
        } else {
            None
        }
    }

    /// Get queue depth (number of pending jobs)
    pub async fn queue_depth(&self) -> usize {
        let queue = self.queue.read().await;
        queue.len()
    }

    /// Get number of active (non-queued, non-complete) jobs
    pub async fn active_count(&self) -> usize {
        let jobs = self.jobs.read().await;
        jobs.values()
            .filter(|j| !matches!(j.status, JobStatus::Queued | JobStatus::Complete | JobStatus::Failed))
            .count()
    }

    /// Get total number of jobs
    pub async fn total_count(&self) -> usize {
        let jobs = self.jobs.read().await;
        jobs.len()
    }
}

impl Default for JobQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::JobType;

    fn make_request(idempotency_key: &str) -> JobRequest {
        JobRequest {
            job_type: JobType::AuthorizeTransfer,
            program_hash: "0x1234".to_string(),
            inputs: vec![],
            idempotency_key: idempotency_key.to_string(),
            key_id: "key1".to_string(),
            client_id: "client1".to_string(),
            request_ts: 12345,
        }
    }

    #[tokio::test]
    async fn test_submit_and_get() {
        let queue = JobQueue::new();
        let request = make_request("test-1");

        let (job_id, position, is_new) = queue.submit(request).await;

        assert!(is_new);
        assert_eq!(position, 0);

        let job = queue.get(job_id).await.unwrap();
        assert_eq!(job.status, JobStatus::Queued);
        assert_eq!(job.job_type, JobType::AuthorizeTransfer);
    }

    #[tokio::test]
    async fn test_idempotency() {
        let queue = JobQueue::new();
        let request1 = make_request("same-key");
        let request2 = make_request("same-key");

        let (job_id1, _, is_new1) = queue.submit(request1).await;
        let (job_id2, _, is_new2) = queue.submit(request2).await;

        assert!(is_new1);
        assert!(!is_new2);
        assert_eq!(job_id1, job_id2);
    }

    #[tokio::test]
    async fn test_complete_job() {
        let queue = JobQueue::new();
        let request = make_request("test-complete");

        let (job_id, _, _) = queue.submit(request).await;
        assert_eq!(queue.queue_depth().await, 1);

        queue.complete_job(job_id, vec![1, 2, 3]).await;

        let job = queue.get(job_id).await.unwrap();
        assert_eq!(job.status, JobStatus::Complete);
        assert_eq!(job.outputs, Some(vec![1, 2, 3]));
        assert_eq!(queue.queue_depth().await, 0);
    }
}
