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
use subtle::ConstantTimeEq;
use tenuo::{constraints::Pattern, crypto::SigningKey, planes::ControlPlane, wire};
use tokio::sync::RwLock;

/// Application state
struct AppState {
    control_plane: ControlPlane,
    enrollment_token: String,
    /// Public keys of enrolled agents (allowed to request warrants)
    enrolled_agents: std::collections::HashSet<[u8; 32]>,
}

/// Request to issue a warrant
#[derive(Debug, Deserialize)]
struct IssueRequest {
    tool: String,
    constraints: std::collections::HashMap<String, String>,
    ttl_seconds: u64,
    /// Caller's public key (must be enrolled)
    caller_pubkey_hex: Option<String>,
    /// Signature over "tool:constraints_json" proving caller identity
    signature_hex: Option<String>,
    /// Optional session ID for traceability
    #[serde(rename = "session_id")]
    _session_id: Option<String>,
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
    // Load keypair from environment (required in release builds)
    let keypair = if let Ok(secret_hex) = std::env::var("TENUO_SECRET_KEY") {
        let bytes = hex::decode(&secret_hex)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
        SigningKey::from_bytes(&arr)
    } else {
        // In release builds, fail fast - ephemeral keys break warrant validity on restart
        #[cfg(not(debug_assertions))]
        {
            eprintln!("ERROR: TENUO_SECRET_KEY is required in production.");
            eprintln!("       Generate with: openssl rand -hex 32");
            eprintln!("       Pod restarts with ephemeral keys invalidate all warrants.");
            std::process::exit(1);
        }
        #[cfg(debug_assertions)]
        {
            eprintln!("WARNING: No TENUO_SECRET_KEY set, generating ephemeral keypair");
            eprintln!("         This is fine for development but NOT for production!");
            SigningKey::generate()
        }
    };

    let control_plane = ControlPlane::new(keypair);
    let pubkey_hex = hex::encode(control_plane.public_key_bytes());

    eprintln!("Tenuo Control Plane starting...");
    eprintln!("Public Key: {}", pubkey_hex);

    // Initialize Audit Logger
    let logger = Arc::new(tenuo::audit::StdoutLogger::new());
    tenuo::audit::set_global_logger(logger);
    eprintln!("Audit Logging: Enabled (stdout)");

    // Generate or load Enrollment Token
    let enrollment_token = std::env::var("TENUO_ENROLLMENT_TOKEN")
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    println!("\n==================================================================");
    println!(" ENROLLMENT TOKEN: {} ", enrollment_token);
    println!("==================================================================\n");

    let state = Arc::new(RwLock::new(AppState {
        control_plane,
        enrollment_token: enrollment_token.clone(),
        enrolled_agents: std::collections::HashSet::new(),
    }));

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/public-key", get(get_public_key))
        .route("/v1/warrants", post(issue_warrant))
        .route("/v1/enroll", post(enroll))
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

/// Maximum age for enrollment PoP (prevents replay attacks)
const ENROLLMENT_POP_MAX_AGE_SECS: i64 = 300; // 5 minutes

/// Request to enroll an orchestrator (obtain root warrant)
#[derive(Debug, Deserialize)]
struct EnrollmentRequest {
    /// The enrollment token printed on server startup
    enrollment_token: String,
    /// The public key of the orchestrator (hex encoded)
    public_key_hex: String,
    /// Unix timestamp (seconds) included in PoP signature
    timestamp: i64,
    /// Proof of Possession: signature over "enroll:{public_key_hex}:{timestamp}"
    pop_signature_hex: String,
    /// Tool name for the warrant (default: "manage_infrastructure")
    #[serde(default = "default_tool")]
    tool: String,
    /// Constraints as pattern strings (default: staging-*, wildcard action, 15 replicas max)
    #[serde(default)]
    constraints: Option<std::collections::HashMap<String, String>>,
    /// TTL in seconds (default: 3600)
    #[serde(default = "default_ttl")]
    ttl_seconds: u64,
    /// Max delegation depth (default: 3)
    #[serde(default = "default_max_depth")]
    max_depth: u32,
}

fn default_tool() -> String {
    "manage_infrastructure".to_string()
}
fn default_ttl() -> u64 {
    3600
}
fn default_max_depth() -> u32 {
    3
}

async fn enroll(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<EnrollmentRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    let mut state = state.write().await;

    // 1. Verify Token (constant-time comparison to prevent timing attacks)
    let token_valid: bool = req
        .enrollment_token
        .as_bytes()
        .ct_eq(state.enrollment_token.as_bytes())
        .into();
    if !token_valid {
        // Delay to prevent brute-force (additional mitigation)
        tokio::time::sleep(Duration::from_millis(100)).await;

        tenuo::audit::log_event(
            tenuo::approval::AuditEvent::new(
                tenuo::approval::AuditEventType::EnrollmentFailure,
                "control-plane",
                "unknown",
            )
            .with_details("Invalid enrollment token"),
        );

        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid enrollment token".to_string(),
        ));
    }

    // 2. Verify timestamp freshness (prevents replay attacks)
    let now = chrono::Utc::now().timestamp();
    let age = (now - req.timestamp).abs();
    if age > ENROLLMENT_POP_MAX_AGE_SECS {
        tenuo::audit::log_event(
            tenuo::approval::AuditEvent::new(
                tenuo::approval::AuditEventType::EnrollmentFailure,
                "control-plane",
                "unknown",
            )
            .with_details(format!(
                "Stale PoP timestamp: age={}s, max={}s",
                age, ENROLLMENT_POP_MAX_AGE_SECS
            )),
        );
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "PoP timestamp too old: {}s (max {}s)",
                age, ENROLLMENT_POP_MAX_AGE_SECS
            ),
        ));
    }

    // 3. Verify PoP signature
    let pubkey_bytes = hex::decode(&req.public_key_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid public key hex".to_string(),
        )
    })?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid public key length".to_string(),
        )
    })?;
    let public_key = tenuo::crypto::PublicKey::from_bytes(&pubkey_arr)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let sig_bytes = hex::decode(&req.pop_signature_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid signature length".to_string(),
        )
    })?;
    let signature = tenuo::crypto::Signature::from_bytes(&sig_arr).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid signature format".to_string(),
        )
    })?;

    // PoP message format: "enroll:{public_key_hex}:{timestamp}"
    // This binds the signature to both the key and the time
    let pop_message = format!("enroll:{}:{}", req.public_key_hex, req.timestamp);
    if public_key
        .verify(pop_message.as_bytes(), &signature)
        .is_err()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid Proof of Possession".to_string(),
        ));
    }

    // 3. Issue Root Warrant with configurable constraints
    let constraints: Vec<(&str, tenuo::constraints::Constraint)> =
        if let Some(ref custom) = req.constraints {
            // Use custom constraints from request
            let mut result = Vec::new();
            for (field, pattern) in custom {
                let p = Pattern::new(pattern).map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid pattern for {}: {}", field, e),
                    )
                })?;
                result.push((field.as_str(), p.into()));
            }
            result
        } else {
            // Default constraints
            vec![
                ("cluster", Pattern::new("staging-*").unwrap().into()),
                ("action", tenuo::constraints::Wildcard::new().into()),
                (
                    "replicas",
                    tenuo::constraints::Range::max(15.0).unwrap().into(),
                ),
            ]
        };

    // Issue warrant with full configuration
    let warrant = state
        .control_plane
        .issue_configured_warrant(
            &req.tool,
            &constraints,
            Duration::from_secs(req.ttl_seconds),
            &public_key,
            req.max_depth,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let warrant_base64 = wire::encode_base64(&warrant)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Track enrolled agent
    state.enrolled_agents.insert(public_key.to_bytes());

    tenuo::audit::log_event(
        tenuo::approval::AuditEvent::new(
            tenuo::approval::AuditEventType::EnrollmentSuccess,
            "control-plane",
            "enrollment-token",
        )
        .with_key(warrant.authorized_holder())
        .with_details(format!("Issued root warrant {}", warrant.id()))
        .with_related(vec![warrant.id().to_string()]),
    );

    Ok(Json(IssueResponse {
        warrant_id: warrant.id().to_string(),
        warrant_base64,
        expires_at: warrant.expires_at().to_rfc3339(),
    }))
}

async fn issue_warrant(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    let state = state.read().await;

    // Require enrollment - caller must prove identity
    let caller_key = req.caller_pubkey_hex.as_ref().ok_or((
        StatusCode::UNAUTHORIZED,
        "Missing caller_pubkey_hex".to_string(),
    ))?;
    let caller_bytes: [u8; 32] = hex::decode(caller_key)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Invalid caller public key hex".to_string(),
            )
        })?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Caller key must be 32 bytes".to_string(),
            )
        })?;

    if !state.enrolled_agents.contains(&caller_bytes) {
        return Err((StatusCode::UNAUTHORIZED, "Caller not enrolled".to_string()));
    }

    // Verify PoP signature (caller signs the request body)
    let caller_pubkey = tenuo::crypto::PublicKey::from_bytes(&caller_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let sig_hex = req.signature_hex.as_ref().ok_or((
        StatusCode::UNAUTHORIZED,
        "Missing signature_hex".to_string(),
    ))?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "Signature must be 64 bytes".to_string(),
            )
        })?;
    let signature = tenuo::crypto::Signature::from_bytes(&sig_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature".to_string()))?;

    // Verify signature over tool + constraints (simple PoP)
    let signable = format!(
        "{}:{}",
        req.tool,
        serde_json::to_string(&req.constraints).unwrap_or_default()
    );
    caller_pubkey
        .verify(signable.as_bytes(), &signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid signature".to_string()))?;

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
        .issue_warrant(
            &req.tool,
            &constraints,
            Duration::from_secs(req.ttl_seconds),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let warrant_base64 = wire::encode_base64(&warrant)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tenuo::audit::log_event(
        tenuo::approval::AuditEvent::new(
            tenuo::approval::AuditEventType::WarrantIssued,
            "control-plane",
            "api-request",
        )
        .with_details(format!(
            "Issued warrant {} for tool {}",
            warrant.id(),
            req.tool
        ))
        .with_related(vec![warrant.id().to_string()]),
    );

    Ok(Json(IssueResponse {
        warrant_id: warrant.id().to_string(),
        warrant_base64,
        expires_at: warrant.expires_at().to_rfc3339(),
    }))
}
