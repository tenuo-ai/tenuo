//! Tenuo Control Plane Server
//!
//! This binary runs the central control plane service that:
//! - Issues root warrants
//! - Manages approval workflows
//! - Provides key distribution
//!
//! # Kubernetes Deployment
//!
//! ```yaml
//! apiVersion: apps/v1
//! kind: Deployment
//! metadata:
//!   name: tenuo-control
//! spec:
//!   replicas: 1  # Single instance for simplicity, or HA with shared storage
//!   template:
//!     spec:
//!       containers:
//!       - name: control
//!         image: tenuo/control:latest
//!         env:
//!         - name: TENUO_SECRET_KEY
//!           valueFrom:
//!             secretKeyRef:
//!               name: tenuo-root-key
//!               key: secret_key
//!         ports:
//!         - containerPort: 8080
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tenuo_core::{
    constraints::Pattern,
    crypto::Keypair,
    planes::ControlPlane,
    wire,
};
use tokio::sync::RwLock;

/// Application state
struct AppState {
    control_plane: ControlPlane,
}

/// Request to issue a warrant
#[derive(Debug, Deserialize)]
struct IssueRequest {
    tool: String,
    constraints: std::collections::HashMap<String, String>,
    ttl_seconds: u64,
    #[allow(dead_code)]  // TODO: Pass to warrant builder when session support is added
    session_id: Option<String>,
}

/// Response with issued warrant
#[derive(Debug, Serialize)]
struct IssueResponse {
    warrant_id: String,
    warrant_base64: String,
    expires_at: String,
}

/// Public key response
#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    public_key_hex: String,
    public_key_base64: String,
}

/// Health check response
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load or generate keypair
    let keypair = if let Ok(secret_hex) = std::env::var("TENUO_SECRET_KEY") {
        let bytes = hex::decode(&secret_hex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
        Keypair::from_bytes(&arr)
    } else {
        eprintln!("WARNING: No TENUO_SECRET_KEY set, generating ephemeral keypair");
        eprintln!("         This is fine for development but NOT for production!");
        Keypair::generate()
    };

    let control_plane = ControlPlane::new(keypair);
    let pubkey_hex = hex::encode(control_plane.public_key_bytes());

    eprintln!("Tenuo Control Plane starting...");
    eprintln!("Public Key: {}", pubkey_hex);

    let state = Arc::new(RwLock::new(AppState { control_plane }));

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/public-key", get(get_public_key))
        .route("/v1/warrants", post(issue_warrant))
        .with_state(state);

    let addr = std::env::var("TENUO_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    eprintln!("Listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn get_public_key(State(state): State<Arc<RwLock<AppState>>>) -> Json<PublicKeyResponse> {
    let state = state.read().await;
    let bytes = state.control_plane.public_key_bytes();

    Json(PublicKeyResponse {
        public_key_hex: hex::encode(bytes),
        public_key_base64: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            bytes,
        ),
    })
}

async fn issue_warrant(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    let state = state.read().await;

    // Build constraints
    let mut constraints = Vec::new();
    for (field, pattern) in &req.constraints {
        let p = Pattern::new(pattern).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid pattern for {}: {}", field, e),
            )
        })?;
        constraints.push((field.as_str(), p.into()));
    }

    // Issue warrant
    let warrant = state
        .control_plane
        .issue_warrant(&req.tool, &constraints, Duration::from_secs(req.ttl_seconds))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let warrant_base64 =
        wire::encode_base64(&warrant).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(IssueResponse {
        warrant_id: warrant.id().to_string(),
        warrant_base64,
        expires_at: warrant.expires_at().to_rfc3339(),
    }))
}

