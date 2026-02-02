//! Axum REST API server for the MPC Coordinator

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;
use chrono::Utc;

use crate::jobs::JobQueue;
use crate::types::*;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Job queue
    pub job_queue: JobQueue,
    /// Registered parties
    pub parties: Arc<RwLock<Vec<PartyInfo>>>,
    /// Service start time
    pub start_time: Instant,
    /// MPC configuration
    pub config: MpcConfig,
}

/// MPC configuration
#[derive(Clone)]
pub struct MpcConfig {
    /// Number of parties required
    pub n_parties: usize,
    /// Threshold for MPC
    pub threshold: usize,
    /// Mock encryption public key (for development)
    pub encryption_pubkey: String,
    /// Key ID
    pub key_id: String,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            n_parties: 4,
            threshold: 1,
            encryption_pubkey: "0x".to_string() + &"00".repeat(32),
            key_id: "default-key-v1".to_string(),
        }
    }
}

impl AppState {
    pub fn new(config: MpcConfig) -> Self {
        Self {
            job_queue: JobQueue::new(),
            parties: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
            config,
        }
    }
}

/// Create the Axum router with all routes
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health and status
        .route("/mpc/status", get(get_status))
        // Job management
        .route("/mpc/jobs", post(submit_job))
        .route("/mpc/jobs/:job_id", get(get_job))
        // Key management
        .route("/mpc/keys", get(get_keys))
        // Party management
        .route("/mpc/parties", get(list_parties))
        .route("/mpc/parties/register", post(register_party))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ============================================================================
// Health & Status
// ============================================================================

/// GET /mpc/status - Get coordinator status
async fn get_status(State(state): State<AppState>) -> Json<CoordinatorStatus> {
    let parties = state.parties.read().await;
    let queue_depth = state.job_queue.queue_depth().await;
    let active_jobs = state.job_queue.active_count().await;

    Json(CoordinatorStatus {
        healthy: true,
        party_count: parties.len(),
        queue_depth,
        active_jobs,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    })
}

// ============================================================================
// Job Management
// ============================================================================

/// POST /mpc/jobs - Submit a new MPC job
async fn submit_job(
    State(state): State<AppState>,
    Json(request): Json<JobRequest>,
) -> Result<(StatusCode, Json<JobSubmitResponse>), (StatusCode, Json<ApiError>)> {
    // Validate request
    if request.program_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("INVALID_REQUEST", "program_hash is required")),
        ));
    }

    if request.idempotency_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("INVALID_REQUEST", "idempotency_key is required")),
        ));
    }

    // Submit to queue
    let (job_id, queue_position, is_new) = state.job_queue.submit(request).await;

    let status_code = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((
        status_code,
        Json(JobSubmitResponse {
            job_id,
            status: JobStatus::Queued,
            queue_position,
        }),
    ))
}

/// GET /mpc/jobs/:job_id - Get job status
async fn get_job(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, (StatusCode, Json<ApiError>)> {
    match state.job_queue.get(job_id).await {
        Some(job) => Ok(Json(JobStatusResponse {
            job_id: job.id,
            status: job.status,
            job_type: job.job_type,
            outputs: job.outputs,
            error: job.error,
            submitted_at: job.submitted_at,
            completed_at: job.completed_at,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ApiError::new("JOB_NOT_FOUND", format!("Job {} not found", job_id))),
        )),
    }
}

// ============================================================================
// Key Management
// ============================================================================

/// GET /mpc/keys - Get aggregated encryption keys
async fn get_keys(State(state): State<AppState>) -> Json<KeysResponse> {
    let parties = state.parties.read().await;

    Json(KeysResponse {
        encryption_pubkey: state.config.encryption_pubkey.clone(),
        key_id: state.config.key_id.clone(),
        party_count: parties.len(),
        threshold: state.config.threshold,
    })
}

// ============================================================================
// Party Management
// ============================================================================

/// GET /mpc/parties - List registered parties
async fn list_parties(State(state): State<AppState>) -> Json<Vec<PartyInfo>> {
    let parties = state.parties.read().await;
    Json(parties.clone())
}

/// POST /mpc/parties/register - Register as an MPC party
async fn register_party(
    State(state): State<AppState>,
    Json(request): Json<PartyRegisterRequest>,
) -> Result<(StatusCode, Json<PartyRegisterResponse>), (StatusCode, Json<ApiError>)> {
    // Validate request
    if request.public_key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("INVALID_REQUEST", "public_key is required")),
        ));
    }

    if request.endpoint.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError::new("INVALID_REQUEST", "endpoint is required")),
        ));
    }

    let mut parties = state.parties.write().await;

    // Check if already registered
    if parties.iter().any(|p| p.public_key == request.public_key) {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError::new("ALREADY_REGISTERED", "Party with this public key is already registered")),
        ));
    }

    // Check if we have room for more parties
    if parties.len() >= state.config.n_parties {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError::new("PARTY_LIMIT_REACHED", format!("Maximum {} parties allowed", state.config.n_parties))),
        ));
    }

    // Generate party ID
    let party_id = format!("party-{}", parties.len() + 1);

    let party_info = PartyInfo {
        party_id: party_id.clone(),
        public_key: request.public_key,
        endpoint: request.endpoint,
        online: true,
        registered_at: Utc::now(),
    };

    parties.push(party_info);

    Ok((
        StatusCode::CREATED,
        Json(PartyRegisterResponse {
            party_id,
            registered: true,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;

    fn create_test_app() -> Router {
        let state = AppState::new(MpcConfig::default());
        create_router(state)
    }

    #[tokio::test]
    async fn test_status_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mpc/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_keys_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mpc/keys")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
