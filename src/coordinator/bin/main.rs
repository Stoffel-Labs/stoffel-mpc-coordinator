//! MPC Coordinator REST API Server
//!
//! Starts an HTTP server that handles MPC job submissions, status queries,
//! party registration, and key management.

use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use stoffel_mpc_coordinator::server::{create_router, AppState, MpcConfig};

#[derive(Parser, Debug)]
#[command(author, version, about = "Stoffel MPC Coordinator Service")]
struct Args {
    /// Host address to bind to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Port to listen on
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Number of MPC parties
    #[arg(long, default_value = "4")]
    n_parties: usize,

    /// MPC threshold
    #[arg(long, default_value = "1")]
    threshold: usize,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("stoffel_mpc_coordinator={},tower_http=debug", args.log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Create MPC configuration
    let config = MpcConfig {
        n_parties: args.n_parties,
        threshold: args.threshold,
        encryption_pubkey: "0x".to_string() + &"00".repeat(32), // Mock key for now
        key_id: "default-key-v1".to_string(),
    };

    // Validate configuration
    if args.n_parties < 3 * args.threshold + 1 {
        eprintln!(
            "Error: Invalid MPC configuration. n_parties ({}) must be >= 3 * threshold ({}) + 1 = {}",
            args.n_parties,
            args.threshold,
            3 * args.threshold + 1
        );
        std::process::exit(1);
    }

    // Create application state
    let state = AppState::new(config);

    // Create router
    let app = create_router(state);

    // Bind to address
    let addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .expect("Invalid address");

    info!("Starting MPC Coordinator on http://{}", addr);
    info!("Configuration: n_parties={}, threshold={}", args.n_parties, args.threshold);
    info!("Endpoints:");
    info!("  GET  /mpc/status           - Service status");
    info!("  POST /mpc/jobs             - Submit MPC job");
    info!("  GET  /mpc/jobs/{{job_id}}    - Get job status");
    info!("  GET  /mpc/keys             - Get encryption keys");
    info!("  GET  /mpc/parties          - List parties");
    info!("  POST /mpc/parties/register - Register party");

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
