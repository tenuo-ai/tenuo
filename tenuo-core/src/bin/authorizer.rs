//! Tenuo Authorizer - Minimal Data Plane
//!
//! A lightweight, embeddable authorizer that can run as:
//! - A sidecar container in Kubernetes
//! - A standalone verification service
//! - An embedded library (just use the tenuo_core crate directly)
//!
//! # Usage
//!
//! As a CLI tool:
//! ```bash
//! # Verify a warrant
//! echo $WARRANT | tenuo-authorizer verify --tool upgrade_cluster --arg cluster=staging-web
//!
//! # Run as a verification server (for sidecars)
//! tenuo-authorizer serve --port 9090 --config gateway.yaml
//! ```
//!
//! # HTTP Server Mode
//!
//! The `serve` command runs an HTTP server that:
//! 1. Matches incoming requests to routes defined in the gateway config
//! 2. Extracts constraint values from path, query, headers, and body
//! 3. Verifies the warrant chain from the `X-Tenuo-Warrant` header
//! 4. Authorizes the action using the extracted constraints
//!
//! # Kubernetes Sidecar Deployment
//!
//! ```yaml
//! apiVersion: apps/v1
//! kind: Deployment
//! spec:
//!   template:
//!     spec:
//!       containers:
//!       - name: app
//!         # Your application
//!       - name: tenuo-authorizer
//!         image: tenuo/authorizer:latest
//!         env:
//!         - name: TENUO_TRUSTED_KEYS
//!           valueFrom:
//!             configMapKeyRef:
//!               name: tenuo-config
//!               key: trusted_keys
//!         ports:
//!         - containerPort: 9090
//!         resources:
//!           limits:
//!             memory: "32Mi"
//!             cpu: "50m"
//! ```

use base64::Engine;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use tenuo::{
    approval::SignedApproval,
    constraints::ConstraintValue,
    crypto::SigningKey,
    extraction::RequestContext,
    gateway_config::{CompiledGatewayConfig, GatewayConfig},
    heartbeat::{
        self, create_audit_channel, ApprovalRecord, AuditEventSender, AuthorizationEvent,
        EnvironmentInfo, HeartbeatConfig, MetricsCollector,
    },
    planes::Authorizer,
    revocation::SignedRevocationList,
    wire, PublicKey,
};

/// Authorizer-specific build number for independent release cycles.
/// Increment this when shipping authorizer-only changes without bumping tenuo crate version.
/// Full version string: `{CARGO_PKG_VERSION}+authz.{AUTHORIZER_BUILD}`
pub const AUTHORIZER_BUILD: u32 = 1;

/// Get the full authorizer version string with build metadata.
pub fn authorizer_version() -> String {
    format!("{}+authz.{}", env!("CARGO_PKG_VERSION"), AUTHORIZER_BUILD)
}

#[derive(Parser)]
#[command(name = "tenuo-authorizer")]
#[command(about = "Tenuo Data Plane Authorizer", long_about = None)]
struct Cli {
    /// Trusted public keys (comma-separated hex strings)
    /// Can also be set via TENUO_TRUSTED_KEYS env var
    #[arg(long, env = "TENUO_TRUSTED_KEYS")]
    trusted_keys: Option<String>,

    /// Path to signed revocation list file (CBOR format)
    /// Can also be set via TENUO_REVOCATION_LIST env var
    #[arg(long, env = "TENUO_REVOCATION_LIST")]
    revocation_list: Option<PathBuf>,

    // === Control Plane Configuration ===
    /// One-token onboarding for Tenuo Cloud.
    /// Base64url-encoded JSON blob generated from the Tenuo Cloud dashboard.
    /// Encodes the control plane endpoint, API key, and optional agent binding.
    /// Explicit TENUO_CONTROL_PLANE_URL / TENUO_API_KEY take precedence when set.
    #[arg(long, env = "TENUO_CONNECT_TOKEN")]
    connect_token: Option<String>,

    /// Control plane URL (enables heartbeat when set with api-key and authorizer-name)
    #[arg(long, env = "TENUO_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,

    /// API key for control plane authentication
    #[arg(long, env = "TENUO_API_KEY")]
    api_key: Option<String>,

    /// Authorizer name for registration with control plane
    #[arg(long, env = "TENUO_AUTHORIZER_NAME")]
    authorizer_name: Option<String>,

    /// Authorizer type (e.g., sidecar, gateway, standalone)
    #[arg(long, env = "TENUO_AUTHORIZER_TYPE", default_value = "sidecar")]
    authorizer_type: String,

    /// Heartbeat interval in seconds
    #[arg(long, env = "TENUO_HEARTBEAT_INTERVAL", default_value = "30")]
    heartbeat_interval: u64,

    /// Audit event batch size (flush when buffer reaches this size)
    #[arg(long, env = "TENUO_AUDIT_BATCH_SIZE", default_value = "100")]
    audit_batch_size: usize,

    /// Audit event flush interval in seconds
    #[arg(long, env = "TENUO_AUDIT_FLUSH_INTERVAL", default_value = "10")]
    audit_flush_interval: u64,

    /// Signing key for cryptographic receipts (hex-encoded 32-byte Ed25519 seed).
    /// When set, events are signed by the authorizer and become non-repudiable receipts.
    /// Generate with: openssl rand -hex 32
    #[arg(long, env = "TENUO_SIGNING_KEY")]
    signing_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as an HTTP authorization server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "9090")]
        port: u16,

        /// Path to gateway configuration YAML file
        #[arg(short, long)]
        config: PathBuf,

        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
    },

    /// Verify and authorize a single warrant (for scripting)
    Verify {
        /// Warrant (base64, or - for stdin)
        #[arg(short, long)]
        warrant: Option<String>,

        /// Tool name to authorize
        #[arg(short, long)]
        tool: String,

        /// Arguments in key=value format
        #[arg(short, long)]
        arg: Vec<String>,

        /// PoP signature (hex-encoded, 64 bytes)
        /// Required for authorization - proves holder possession
        #[arg(short, long)]
        pop: String,

        /// Output format: exit-code, json, or quiet
        #[arg(short, long, default_value = "exit-code")]
        output: String,
    },

    /// Check if a warrant is valid (no authorization, just verification)
    Check {
        /// Warrant (base64, or - for stdin)
        #[arg(short, long)]
        warrant: Option<String>,
    },

    /// Print authorizer info
    Info,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    // Build authorizer from trusted keys and revocation list
    let (authorizer, initial_srl_version) =
        build_authorizer(&cli.trusted_keys, &cli.revocation_list)?;

    match &cli.command {
        Commands::Serve { port, config, bind } => {
            serve_http(authorizer, initial_srl_version, config, bind, *port, &cli).await?;
        }

        Commands::Verify {
            warrant,
            tool,
            arg,
            pop,
            output,
        } => {
            // Read warrant
            let warrant_str = read_warrant(warrant.clone())?;
            let w = wire::decode_base64(&warrant_str)?;

            // Parse arguments
            let mut args = HashMap::new();
            for a in arg {
                let parts: Vec<&str> = a.splitn(2, '=').collect();
                if parts.len() != 2 {
                    return Err(format!("Invalid argument format: {}", a).into());
                }
                args.insert(
                    parts[0].to_string(),
                    ConstraintValue::String(parts[1].to_string()),
                );
            }

            // Parse PoP signature (required)
            let pop_bytes =
                hex::decode(pop).map_err(|_| "Invalid PoP signature: must be hex-encoded")?;
            let pop_arr: [u8; 64] = pop_bytes
                .try_into()
                .map_err(|_| "Invalid PoP signature: must be exactly 64 bytes")?;
            let pop_signature = tenuo::Signature::from_bytes(&pop_arr)
                .map_err(|_| "Invalid PoP signature format")?;

            // Check authorization with PoP (no approvals for CLI mode)
            let result = authorizer.authorize_one(&w, tool, &args, Some(&pop_signature), &[]);

            match output.as_str() {
                "exit-code" => match result {
                    Ok(_) => std::process::exit(0),
                    Err(e) => {
                        eprintln!("Authorization failed: {}", e);
                        std::process::exit(1);
                    }
                },
                "json" => {
                    let json = serde_json::json!({
                        "authorized": result.is_ok(),
                        "error": result.err().map(|e| e.to_string()),
                        "warrant_id": w.id().to_string(),
                        "tool": tool,
                    });
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
                "quiet" => {
                    if result.is_err() {
                        std::process::exit(1);
                    }
                }
                _ => return Err(format!("Unknown output format: {}", output).into()),
            }
        }

        Commands::Check { warrant } => {
            let warrant_str = read_warrant(warrant.clone())?;
            let w = wire::decode_base64(&warrant_str)?;

            // Just verify, don't authorize
            match w.verify(w.issuer()) {
                Ok(()) => {
                    println!("✓ Warrant signature is valid");
                    println!("  ID: {}", w.id());
                    let tools = w.tools();
                    if !tools.is_empty() {
                        println!("  Tools: {}", tools.join(", "));
                    }
                    println!("  Expires: {}", w.expires_at());
                    if w.is_expired() {
                        println!("  ⚠ WARNING: Warrant has EXPIRED");
                        std::process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("✗ Warrant invalid: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Info => {
            println!("Tenuo Authorizer v{}", authorizer_version());
            println!();
            if let Some(keys) = &cli.trusted_keys {
                let count = keys.split(',').filter(|s| !s.is_empty()).count();
                println!("Trusted keys: {} configured", count);
            } else {
                println!("Trusted keys: None (Warning: Will reject all delegated warrants unless keys are provided)");
            }
            if let Some(path) = &cli.revocation_list {
                println!("Revocation list: {}", path.display());
            } else {
                println!("Revocation list: None");
            }
        }
    }

    Ok(())
}

fn build_authorizer(
    trusted_keys: &Option<String>,
    revocation_path: &Option<PathBuf>,
) -> Result<(Authorizer, Option<u64>), Box<dyn std::error::Error>> {
    // Start with a dummy authorizer if no keys provided
    // This still validates signatures, just doesn't check the issuer
    let first_key = if let Some(keys) = trusted_keys {
        let first = keys.split(',').next().unwrap_or("");
        if first.is_empty() {
            return Err("TENUO_TRUSTED_KEYS is empty".into());
        }
        let bytes = hex::decode(first)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
        PublicKey::from_bytes(&arr)?
    } else {
        // For development: create a dummy key
        // In production, TENUO_TRUSTED_KEYS should always be set
        eprintln!("WARNING: No trusted keys configured. Set TENUO_TRUSTED_KEYS for production.");
        let dummy = [0u8; 32];
        PublicKey::from_bytes(&dummy).unwrap_or_else(|_| {
            // Generate a valid but useless key
            tenuo::SigningKey::generate().public_key()
        })
    };

    let mut authorizer = Authorizer::new().with_trusted_root(first_key.clone());

    // Add remaining keys
    if let Some(keys) = trusted_keys {
        for key_hex in keys.split(',').skip(1) {
            if !key_hex.is_empty() {
                let bytes = hex::decode(key_hex)?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
                authorizer.add_trusted_root(PublicKey::from_bytes(&arr)?);
            }
        }
    }

    // Load signed revocation list if provided
    let initial_srl_version = if let Some(path) = revocation_path {
        let srl = load_signed_revocation_list(path)?;
        let version = srl.version();

        // Verify against first trusted key (Control Plane key)
        authorizer.set_revocation_list(srl, &first_key)?;
        eprintln!("Loaded signed revocation list from: {}", path.display());
        Some(version)
    } else {
        None
    };

    Ok((authorizer, initial_srl_version))
}

fn load_signed_revocation_list(
    path: &PathBuf,
) -> Result<SignedRevocationList, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let srl = SignedRevocationList::from_bytes(&bytes)?;
    Ok(srl)
}

fn read_warrant(warrant: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    match warrant {
        Some(w) if w == "-" => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf.trim().to_string())
        }
        Some(w) => Ok(w),
        None => {
            // Try stdin
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf.trim().to_string())
        }
    }
}

// ============================================================================
// HTTP Server Mode
// ============================================================================

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header::HeaderName, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tracing::{debug, error, info, warn};

/// Shared state for the HTTP server
struct AppState {
    authorizer: Arc<tokio::sync::RwLock<Authorizer>>,
    config: CompiledGatewayConfig,
    debug_mode: bool,
    /// Audit event sender (None if control plane not configured)
    audit_tx: Option<AuditEventSender>,
    /// Authorizer ID from control plane registration (for audit events)
    authorizer_id: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Metrics collector (None if control plane not configured)
    metrics: Option<MetricsCollector>,
    /// Process start time for uptime reporting in /status
    started_at: std::time::Instant,
}

/// Structured denial reason for logging
#[derive(Debug, serde::Serialize)]
struct DenyReason {
    level: &'static str,
    event: &'static str,
    reason: String,
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    constraint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual: Option<Value>,
    warrant_id: String,
    request_id: String,
}

impl DenyReason {
    fn new(tool: &str, warrant_id: &str, request_id: &str) -> Self {
        Self {
            level: "warn",
            event: "authorization_denied",
            reason: String::new(),
            tool: tool.to_string(),
            constraint: None,
            expected: None,
            actual: None,
            warrant_id: warrant_id.to_string(),
            request_id: request_id.to_string(),
        }
    }

    fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    fn with_constraint(mut self, name: &str, expected: &str, actual: Value) -> Self {
        self.reason = "constraint_violation".to_string();
        self.constraint = Some(name.to_string());
        self.expected = Some(expected.to_string());
        self.actual = Some(actual);
        self
    }

    /// Format as a human-readable header value
    fn to_header_value(&self) -> String {
        if let (Some(constraint), Some(expected), Some(actual)) =
            (&self.constraint, &self.expected, &self.actual)
        {
            format!(
                "{}: {}={} exceeds {}",
                self.reason, constraint, actual, expected
            )
        } else {
            self.reason.clone()
        }
    }
}

/// Start the HTTP authorization server
async fn serve_http(
    authorizer: Authorizer,
    initial_srl_version: Option<u64>,
    config_path: &PathBuf,
    bind: &str,
    port: u16,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load and compile gateway configuration
    let mut config = GatewayConfig::from_file(config_path)?;

    // Merge trusted keys from env/cli
    if let Some(keys) = &cli.trusted_keys {
        for key in keys.split(',') {
            if !key.trim().is_empty() {
                config.settings.trusted_roots.push(key.trim().to_string());
            }
        }
    }

    let debug_mode = config.settings.debug_mode;
    let compiled = CompiledGatewayConfig::compile(config)?;

    // Resolve TENUO_CONNECT_TOKEN — extract endpoint, api_key, and optional
    // agent_id. Explicit env vars (TENUO_CONTROL_PLANE_URL, TENUO_API_KEY)
    // always win. The full parsed token is kept so the heartbeat loop can
    // call `claim_agent` with the embedded registration secret.
    let (resolved_url, resolved_key, resolved_agent_id, resolved_connect_token) =
        match cli.connect_token.as_deref() {
            Some(token) => match tenuo::connect_token::ConnectToken::parse(token) {
                Ok(ct) => {
                    info!(
                        endpoint = %ct.endpoint,
                        has_agent_id = ct.agent_id.is_some(),
                        "Connect token parsed"
                    );
                    let url = cli.control_plane_url.clone().or(Some(ct.endpoint.clone()));
                    let key = cli.api_key.clone().or(Some(ct.api_key.clone()));
                    let agent_id = ct.agent_id.clone();
                    (url, key, agent_id, Some(ct))
                }
                Err(e) => {
                    error!(error = %e, "TENUO_CONNECT_TOKEN is invalid");
                    std::process::exit(1);
                }
            },
            None => (
                cli.control_plane_url.clone(),
                cli.api_key.clone(),
                None,
                None,
            ),
        };

    // When using a connect token, derive authorizer_name from pod/hostname if
    // not explicitly set. This makes token-only K8s/Docker deployments work
    // without requiring a separate TENUO_AUTHORIZER_NAME env var.
    let resolved_name: Option<String> = cli.authorizer_name.clone().or_else(|| {
        if resolved_connect_token.is_some() {
            // K8s downward API / Docker hostname, in preference order
            std::env::var("POD_NAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| Some("tenuo-authorizer".to_string()))
        } else {
            None
        }
    });

    // Check if control plane is configured
    let control_plane_enabled =
        resolved_url.is_some() && resolved_key.is_some() && resolved_name.is_some();

    eprintln!("┌─────────────────────────────────────────────────────────");
    eprintln!("│ Tenuo Authorizer Server v{}", authorizer_version());
    eprintln!("├─────────────────────────────────────────────────────────");
    eprintln!("│ Listening on: {}:{}", bind, port);
    eprintln!("│ Config: {}", config_path.display());
    if debug_mode {
        eprintln!("│ ⚠️  Debug mode: ENABLED (not for production!)");
    }
    if let Some(version) = initial_srl_version {
        eprintln!("│ Revocation List: v{} (loaded from file)", version);
    }
    if control_plane_enabled {
        eprintln!(
            "│ Control Plane: ENABLED (heartbeat every {}s, SRL sync)",
            cli.heartbeat_interval
        );
    }
    eprintln!("└─────────────────────────────────────────────────────────");
    eprintln!();

    // Wrap authorizer in RwLock for shared access (allows heartbeat to update SRL)
    let shared_authorizer = Arc::new(tokio::sync::RwLock::new(authorizer));

    // Shared authorizer_id (populated after control plane registration)
    let shared_authorizer_id: Arc<tokio::sync::RwLock<Option<String>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    // Parse trusted root key for SRL verification (first key is control plane key)
    let trusted_root = cli.trusted_keys.as_ref().and_then(|keys| {
        let first = keys.split(',').next()?;
        let bytes = hex::decode(first.trim()).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        PublicKey::from_bytes(&arr).ok()
    });

    // Create audit channel, metrics collector, and spawn heartbeat task if control plane is configured
    let (audit_tx, metrics) =
        if let (Some(url), Some(key), Some(name)) = (resolved_url, resolved_key, resolved_name) {
            // Create audit event channel (buffer 1000 events)
            let (tx, rx) = create_audit_channel(1000);

            // Create metrics collector for runtime stats
            let metrics = MetricsCollector::new();

            // If SRL was loaded from file at startup, record its version in metrics
            if let Some(version) = initial_srl_version {
                metrics.record_srl_fetch(true, Some(version)).await;
            }

            // Get environment info from standard env vars; inject agent_id from
            // connect token so the backend can bind this authorizer to the agent.
            let mut environment = EnvironmentInfo::from_env();
            if let Some(ref agent_id) = resolved_agent_id {
                environment
                    .metadata
                    .insert("agent_id".to_string(), agent_id.clone());
            }

            // Parse signing key; auto-generate if not supplied so connect-token
            // onboarding works without any additional key management step.
            let signing_key = match &cli.signing_key {
                Some(hex_key) => match hex::decode(hex_key) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        let key = SigningKey::from_bytes(&arr);
                        info!(
                            public_key = %hex::encode(key.public_key().to_bytes()),
                            "Signing key configured"
                        );
                        key
                    }
                    Ok(bytes) => {
                        error!(
                            got_len = bytes.len(),
                            "TENUO_SIGNING_KEY must be 32 bytes (64 hex chars)"
                        );
                        std::process::exit(1);
                    }
                    Err(e) => {
                        error!(error = %e, "TENUO_SIGNING_KEY must be valid hex");
                        std::process::exit(1);
                    }
                },
                None => {
                    let key = SigningKey::generate();
                    info!(
                        public_key = %hex::encode(key.public_key().to_bytes()),
                        "No TENUO_SIGNING_KEY set — using ephemeral signing key. \
                         Set TENUO_SIGNING_KEY to persist the key across restarts."
                    );
                    key
                }
            };

            let heartbeat_config = HeartbeatConfig {
                control_plane_url: url.clone(),
                api_key: key.clone(),
                authorizer_name: name.clone(),
                authorizer_type: cli.authorizer_type.clone(),
                version: authorizer_version(),
                interval_secs: cli.heartbeat_interval,
                authorizer: Some(shared_authorizer.clone()),
                trusted_root: trusted_root.clone(),
                audit_batch_size: cli.audit_batch_size,
                audit_flush_interval_secs: cli.audit_flush_interval,
                environment,
                metrics: Some(metrics.clone()),
                signing_key,
                id_notify: None,
                agent_id: resolved_agent_id,
                connect_token: resolved_connect_token,
            };

            // Clone shared_authorizer_id for the heartbeat task to update
            let authorizer_id_writer = shared_authorizer_id.clone();
            tokio::spawn(async move {
                heartbeat::start_heartbeat_loop_with_audit_and_id(
                    heartbeat_config,
                    Some(rx),
                    authorizer_id_writer,
                )
                .await;
            });
            info!("Heartbeat, metrics, and audit streaming enabled for control plane");

            (Some(tx), Some(metrics))
        } else {
            (None, None)
        };

    let state = Arc::new(AppState {
        authorizer: shared_authorizer,
        config: compiled,
        debug_mode,
        audit_tx,
        authorizer_id: shared_authorizer_id,
        metrics,
        started_at: std::time::Instant::now(),
    });

    // Build the router
    // Health endpoint first (no auth required) for K8s probes
    // Then catch-all for authorized requests
    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/healthz", axum::routing::get(health_check))
        .route("/ready", axum::routing::get(health_check))
        .route("/status", axum::routing::get(status_handler))
        .fallback(handle_request)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint for Kubernetes probes
/// Returns 200 OK with minimal JSON response
async fn health_check() -> impl axum::response::IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "service": "tenuo-authorizer"
        })),
    )
}

/// Registration and runtime status endpoint.
///
/// Returns the authorizer's control plane registration state and uptime.
/// Useful for debugging K8s deployments and verifying that a connect token
/// was accepted: poll until `cp.status == "registered"`.
///
/// Response shape:
/// ```json
/// {
///   "version": "0.1.0-beta.12",
///   "uptime_secs": 42,
///   "cp": {
///     "enabled": true,
///     "status": "registered",   // "registering" | "registered" | "disabled"
///     "authorizer_id": "tnu_auth_..."  // null while registering
///   }
/// }
/// ```
async fn status_handler(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let cp_enabled = state.audit_tx.is_some();

    let (cp_status, authorizer_id) = if cp_enabled {
        let id = state.authorizer_id.read().await.clone();
        let status = if id.is_some() {
            "registered"
        } else {
            "registering"
        };
        (status, id)
    } else {
        ("disabled", None)
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": uptime_secs,
            "cp": {
                "enabled": cp_enabled,
                "status": cp_status,
                "authorizer_id": authorizer_id,
            }
        })),
    )
}

/// Handle an incoming HTTP request
async fn handle_request(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    // Generate request ID for tracing
    let request_id = format!("req_{}", uuid::Uuid::now_v7().simple());
    let path = uri.path().to_string();

    // 1. Match route
    let route_match = match state.config.match_route(method.as_str(), &path) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "no_route",
                    "message": format!("No route matches {} {}", method, path),
                    "request_id": request_id
                })),
            )
                .into_response();
        }
    };

    // 2. Extract warrant from header
    let warrant_header = &state.config.settings.warrant_header;
    let warrant_b64 = match headers.get(warrant_header) {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_header",
                        "message": format!("Invalid {} header encoding", warrant_header),
                        "request_id": request_id
                    })),
                )
                    .into_response();
            }
        },
        None => {
            warn!(
                request_id = %request_id,
                event = "authorization_denied",
                reason = "missing_warrant",
                "Missing warrant header"
            );

            // Emit audit event for missing warrant (so denials appear in receipts/audit)
            emit_audit_event(
                &state,
                AuthorizationEvent::deny(
                    String::new(), // Filled by emit_audit_event
                    String::new(), // No warrant ID
                    route_match.route.tool.to_string(),
                    "missing_warrant".to_string(),
                    None,
                    0,
                    None,
                    None,
                    0,
                    request_id.clone(),
                    None,
                    None,
                ),
            )
            .await;

            // Record metrics
            if let Some(ref metrics) = state.metrics {
                metrics
                    .record_authorization(
                        false,
                        &route_match.route.tool,
                        0,
                        "",
                        None,
                        Some("missing_warrant"),
                    )
                    .await;
            }

            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing_warrant",
                    "message": format!("Missing {} header", warrant_header),
                    "request_id": request_id
                })),
            )
                .into_response();
        }
    };

    // 3. Decode warrant chain (WarrantStack) or single warrant
    // Best practice: clients send full chain so we can verify independently
    let chain = match decode_warrant_or_chain(&warrant_b64) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                request_id = %request_id,
                event = "authorization_denied",
                reason = "invalid_warrant",
                error = %e,
                "Failed to decode warrant/chain"
            );

            // Emit audit event for invalid warrant
            emit_audit_event(
                &state,
                AuthorizationEvent::deny(
                    String::new(), // Filled by emit_audit_event
                    String::new(), // No warrant ID
                    route_match.route.tool.to_string(),
                    format!("invalid_warrant: {}", e),
                    None,
                    0,
                    None,
                    None,
                    0,
                    request_id.clone(),
                    None,
                    None,
                ),
            )
            .await;

            // Record metrics
            if let Some(ref metrics) = state.metrics {
                metrics
                    .record_authorization(
                        false,
                        &route_match.route.tool,
                        0,
                        "",
                        None,
                        Some("invalid_warrant"),
                    )
                    .await;
            }

            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_warrant",
                    "message": format!("Failed to decode warrant: {}", e),
                    "request_id": request_id
                })),
            )
                .into_response();
        }
    };

    let leaf_warrant = chain.last().unwrap(); // Safe: decode guarantees non-empty
    let warrant_id = leaf_warrant.id().to_string();
    let chain_length = chain.len();

    // Log chain details
    if chain_length > 1 {
        debug!(
            request_id = %request_id,
            warrant_id = %warrant_id,
            chain_length = %chain_length,
            "Received warrant chain"
        );
    } else if leaf_warrant.depth() > 0 {
        warn!(
            request_id = %request_id,
            warrant_id = %warrant_id,
            depth = %leaf_warrant.depth(),
            "Received orphaned delegated warrant (depth > 0) without parent chain. Zero-Trust best practice is to send full WarrantStack."
        );
    }

    // 4. Parse body as JSON (if present)
    let json_body: Value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => Value::Null, // Non-JSON body, use null
        }
    };

    let arguments_json = if json_body.is_null() {
        None
    } else {
        Some(json_body.to_string())
    };

    // 5. Build request context
    let mut http_headers = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            http_headers.insert(name.to_string().to_lowercase(), v.to_string());
        }
    }

    let mut ctx = RequestContext::with_body(json_body.clone());
    ctx.path_params = route_match.path_params.clone();
    ctx.query_params = query;
    ctx.headers = http_headers;

    // 6. Extract constraints
    let extraction_result = match state.config.extract_constraints(&route_match, &ctx) {
        Ok(res) => res,
        Err(e) => {
            warn!(
                request_id = %request_id,
                route = %path,
                event = "authorization_denied",
                reason = "extraction_failed",
                error = %e,
                "Failed to extract constraints from request"
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "extraction_failed",
                    "message": format!("Failed to extract constraints: {}", e),
                    "request_id": request_id
                })),
            )
                .into_response();
        }
    };

    // 6. Check constraints against extraction result
    // (This step verifies that the extracted arguments match the type expected by constraints,
    // although actual validation happens inside authorizer.authorize)

    // 7. Extract and parse PoP signature from header (if present)
    // Supports both base64 (preferred) and hex encoding for backwards compatibility
    let pop_header = &state.config.settings.pop_header;
    let pop_signature: Option<tenuo::Signature> = headers
        .get(pop_header)
        .and_then(|v| v.to_str().ok())
        .and_then(|encoded| {
            // Try base64 first (new standard), then hex (legacy)
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
                .or_else(|_| hex::decode(encoded))
                .ok()?;

            if bytes.len() == 64 {
                let arr: [u8; 64] = bytes.try_into().ok()?;
                tenuo::Signature::from_bytes(&arr).ok()
            } else {
                None
            }
        });

    // 7b. Extract signed approvals from header (if present)
    // Format: base64-encoded CBOR — either a single SignedApproval or array of SignedApproval
    let approval_header = &state.config.settings.approval_header;
    let approvals: Vec<SignedApproval> = match headers
        .get(approval_header)
        .and_then(|v| v.to_str().ok())
    {
        Some(encoded) => {
            let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
            {
                Ok(b) => b,
                Err(_) => {
                    warn!(request_id = %request_id, "Invalid base64 in {} header", approval_header);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "invalid_approvals_header",
                            "message": format!("Could not base64-decode {} header", approval_header),
                            "request_id": request_id
                        })),
                    ).into_response();
                }
            };

            const MAX_APPROVAL_HEADER_BYTES: usize = 65_536;
            if bytes.len() > MAX_APPROVAL_HEADER_BYTES {
                warn!(
                    request_id = %request_id,
                    size = bytes.len(),
                    "Approvals header exceeds size limit"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_approvals_header",
                        "message": format!("{} header too large ({} bytes, max {})", approval_header, bytes.len(), MAX_APPROVAL_HEADER_BYTES),
                        "request_id": request_id
                    })),
                ).into_response();
            }

            // Try array first, then single approval
            if let Ok(vec) = ciborium::de::from_reader::<Vec<SignedApproval>, _>(&bytes[..]) {
                vec
            } else if let Ok(single) = ciborium::de::from_reader::<SignedApproval, _>(&bytes[..]) {
                vec![single]
            } else {
                warn!(request_id = %request_id, "Failed to deserialize CBOR from {} header", approval_header);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_approvals_header",
                        "message": format!("Could not deserialize CBOR from {} header", approval_header),
                        "request_id": request_id
                    })),
                ).into_response();
            }
        }
        None => Vec::new(),
    };

    if !approvals.is_empty() {
        debug!(
            request_id = %request_id,
            count = approvals.len(),
            "Extracted signed approvals from header"
        );
    }

    // 8. Authorize with detailed timing instrumentation
    let total_start = std::time::Instant::now();

    // Phase 1: Lock acquisition
    let lock_start = std::time::Instant::now();
    let authorizer = state.authorizer.read().await;
    let lock_us = lock_start.elapsed().as_micros() as u64;

    // Phase 2: Chain verification + leaf authorization (single atomic call)
    let check_start = std::time::Instant::now();
    let result = authorizer.check_chain(
        &chain,
        &extraction_result.tool,
        &extraction_result.constraints,
        pop_signature.as_ref(),
        &approvals,
    );
    let check_us = check_start.elapsed().as_micros() as u64;

    // Release the lock before building the response
    drop(authorizer);

    // Calculate total and core latency
    let total_us = total_start.elapsed().as_micros() as u64;
    let latency_us = check_us;

    if state.debug_mode {
        info!(
            request_id = %request_id,
            lock_us = %lock_us,
            check_chain_us = %check_us,
            core_us = %latency_us,
            total_us = %total_us,
            chain_depth = %chain.len(),
            "Timing breakdown"
        );
    }

    // Extract chain metadata for audit event
    let chain_depth = leaf_warrant.depth() as u8;
    let root_principal = chain.first().map(|w| hex::encode(w.issuer().to_bytes()));

    // Encode warrant stack for audit event (base64 CBOR)
    let warrant_stack_b64 = encode_warrant_stack_for_audit(&chain);

    match result {
        Ok(ref cvr) => {
            info!(
                request_id = %request_id,
                warrant_id = %warrant_id,
                tool = %extraction_result.tool,
                event = "authorization_success",
                "Request authorized"
            );

            let approval_records = if cvr.verified_approvals.is_empty() {
                None
            } else {
                Some(
                    cvr.verified_approvals
                        .iter()
                        .map(|va| ApprovalRecord {
                            approver_key: hex::encode(va.approver_key),
                            external_id: va.external_id.clone(),
                            approved_at: va.approved_at,
                            expires_at: va.expires_at,
                            request_hash: hex::encode(va.request_hash),
                            signed_approval_cbor_b64: va.signed_approval_cbor_b64.clone(),
                        })
                        .collect(),
                )
            };

            // Emit audit event (if control plane connected)
            emit_audit_event(
                &state,
                AuthorizationEvent::allow(
                    String::new(), // Filled by emit_audit_event
                    warrant_id.clone(),
                    extraction_result.tool.clone(),
                    chain_depth,
                    root_principal.clone(),
                    warrant_stack_b64.clone(),
                    latency_us,
                    request_id.clone(),
                    arguments_json.clone(),
                    approval_records,
                ),
            )
            .await;

            // Record metrics (if control plane connected)
            if let Some(ref metrics) = state.metrics {
                metrics
                    .record_authorization(
                        true,
                        &extraction_result.tool,
                        latency_us,
                        &warrant_id,
                        root_principal.as_deref(),
                        None,
                    )
                    .await;
            }

            (
                StatusCode::OK,
                Json(json!({
                    "authorized": true,
                    "warrant_id": warrant_id,
                    "tool": extraction_result.tool,
                    "request_id": request_id
                })),
            )
                .into_response()
        }
        Err(e) => {
            // Parse the error to extract structured deny reason
            let deny_reason = parse_deny_reason(
                &e,
                &extraction_result.tool,
                &warrant_id,
                &request_id,
                &extraction_result.constraints,
            );

            // Log structured denial
            if let Ok(log_json) = serde_json::to_string(&deny_reason) {
                // Output as structured JSON log
                eprintln!("{}", log_json);
            }

            // Also log with tracing for structured logging systems
            warn!(
                request_id = %request_id,
                warrant_id = %warrant_id,
                tool = %extraction_result.tool,
                event = "authorization_denied",
                reason = %deny_reason.reason,
                constraint = ?deny_reason.constraint,
                expected = ?deny_reason.expected,
                actual = ?deny_reason.actual,
                "Authorization denied"
            );

            // Build response with sanitized error (no internal details)
            let (error_code, error_name, safe_message) = sanitize_error(&e);

            let mut body = json!({
                "authorized": false,
                "error": error_name,        // String name for backwards compatibility
                "error_code": error_code,   // Canonical numeric code (new)
                "message": safe_message,
                "warrant_id": warrant_id,
                "tool": extraction_result.tool,
                "request_id": request_id
            });

            // Enrich approval errors with actionable data so the client
            // (or a K8s controller) can obtain the required signatures.
            match &e {
                tenuo::Error::ApprovalRequired { request, .. } => {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(
                            "request_hash".to_string(),
                            json!(hex::encode(request.request_hash)),
                        );
                        obj.insert(
                            "required_approvals".to_string(),
                            json!(request.min_approvals),
                        );
                        obj.insert("received_approvals".to_string(), json!(0));
                        let keys: Vec<String> = request
                            .required_approvers
                            .iter()
                            .map(|k| hex::encode(k.to_bytes()))
                            .collect();
                        obj.insert("required_approvers".to_string(), json!(keys));
                    }
                }
                tenuo::Error::InsufficientApprovals {
                    required, received, ..
                } => {
                    let request_hash = tenuo::approval::compute_request_hash(
                        &warrant_id,
                        &extraction_result.tool,
                        &extraction_result.constraints,
                        Some(leaf_warrant.authorized_holder()),
                    );
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert("request_hash".to_string(), json!(hex::encode(request_hash)));
                        obj.insert("required_approvals".to_string(), json!(required));
                        obj.insert("received_approvals".to_string(), json!(received));
                        if let Some(approvers) = leaf_warrant.required_approvers() {
                            let keys: Vec<String> = approvers
                                .iter()
                                .map(|k| hex::encode(k.to_bytes()))
                                .collect();
                            obj.insert("required_approvers".to_string(), json!(keys));
                        }
                    }
                }
                _ => {}
            }

            if state.debug_mode {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("debug_error".to_string(), json!(format!("{}", e)));
                    obj.insert("debug_details".to_string(), json!(deny_reason));
                }
            }

            let mut response = (StatusCode::FORBIDDEN, Json(body)).into_response();

            // Add debug header if enabled
            if state.debug_mode {
                if let Ok(header_value) = HeaderValue::from_str(&deny_reason.to_header_value()) {
                    response
                        .headers_mut()
                        .insert(HeaderName::from_static("x-tenuo-deny-reason"), header_value);
                }
            }

            // Emit audit event (if control plane connected)
            emit_audit_event(
                &state,
                AuthorizationEvent::deny(
                    String::new(), // Filled by emit_audit_event
                    warrant_id.clone(),
                    extraction_result.tool.clone(),
                    deny_reason.reason.clone(),
                    deny_reason.constraint.clone(),
                    chain_depth,
                    root_principal.clone(),
                    warrant_stack_b64,
                    latency_us,
                    request_id.clone(),
                    arguments_json,
                    None,
                ),
            )
            .await;

            // Record metrics (if control plane connected)
            if let Some(ref metrics) = state.metrics {
                metrics
                    .record_authorization(
                        false,
                        &extraction_result.tool,
                        latency_us,
                        &warrant_id,
                        root_principal.as_deref(),
                        Some(&deny_reason.reason),
                    )
                    .await;
            }

            response
        }
    }
}

/// Encode a warrant chain as base64 CBOR for audit events.
fn encode_warrant_stack_for_audit(chain: &[tenuo::Warrant]) -> Option<String> {
    if chain.is_empty() {
        return None;
    }

    // Convert slice to WarrantStack and encode
    let stack = wire::WarrantStack(chain.to_vec());
    match wire::encode_stack(&stack) {
        Ok(bytes) => Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
        Err(e) => {
            warn!(error = %e, "Failed to encode warrant stack for audit");
            None
        }
    }
}

/// Emit an audit event to the control plane (if configured).
/// Fills in the authorizer_id from shared state.
async fn emit_audit_event(state: &AppState, mut event: AuthorizationEvent) {
    if let Some(ref tx) = state.audit_tx {
        // Get authorizer_id from shared state
        let authorizer_id = state.authorizer_id.read().await;
        if let Some(ref id) = *authorizer_id {
            event.authorizer_id = id.clone();

            // Extract fields for logging before moving event
            let decision = event.decision;
            let tool = event.tool.clone();

            // Send event (non-blocking, drop if channel is full)
            if let Err(e) = tx.try_send(event) {
                match e {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        warn!(
                            decision = decision,
                            tool = %tool,
                            "Audit event dropped: channel buffer full (high authorization rate or slow control plane)"
                        );
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        debug!("Audit event dropped: channel closed (shutdown in progress)");
                    }
                }
            }
        } else {
            // Authorizer ID not set yet - control plane registration still in progress
            warn!(
                decision = event.decision,
                tool = %event.tool,
                request_id = %event.request_id,
                "Audit event dropped: authorizer not registered with control plane yet (early request)"
            );
        }
    }
}

/// Decode a warrant from base64, supporting both single warrants and WarrantStack.
///
/// Returns the leaf warrant (for authorization) and the chain length.
/// For single warrants, chain_length = 1.
/// For WarrantStack, we verify the chain and return the leaf.
fn decode_warrant_or_chain(b64: &str) -> Result<Vec<tenuo::Warrant>, tenuo::Error> {
    use base64::Engine;

    // First, try to decode as raw bytes (could be CBOR array for stack)
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64.trim()))
        .map_err(|e| tenuo::Error::DeserializationError(format!("Base64 decode failed: {}", e)))?;

    // Try to decode as WarrantStack first (CBOR array)
    if let Ok(stack) = wire::decode_stack(&bytes) {
        let chain = stack.0;
        if chain.is_empty() {
            return Err(tenuo::Error::DeserializationError(
                "Empty warrant stack".into(),
            ));
        }
        return Ok(chain);
    }

    // Fall back to single warrant decode
    let warrant: tenuo::Warrant = ciborium::de::from_reader(&bytes[..])
        .map_err(|e| tenuo::Error::DeserializationError(format!("CBOR decode failed: {}", e)))?;

    Ok(vec![warrant])
}

/// Parse an error into a structured DenyReason
fn parse_deny_reason(
    error: &tenuo::Error,
    tool: &str,
    warrant_id: &str,
    request_id: &str,
    constraints: &HashMap<String, ConstraintValue>,
) -> DenyReason {
    use tenuo::Error;

    let mut deny = DenyReason::new(tool, warrant_id, request_id);

    match error {
        Error::ConstraintNotSatisfied { field, reason } => {
            // Try to extract the actual value from constraints
            let actual = constraints
                .get(field)
                .map(|v| match v {
                    ConstraintValue::String(s) => json!(s),
                    ConstraintValue::Integer(i) => json!(i),
                    ConstraintValue::Float(f) => json!(f),
                    ConstraintValue::Boolean(b) => json!(b),
                    ConstraintValue::List(l) => json!(l),
                    ConstraintValue::Object(o) => json!(o),
                    ConstraintValue::Null => json!(null),
                })
                .unwrap_or(json!(null));

            deny = deny.with_constraint(field, reason, actual);
        }
        Error::WarrantExpired(ts) => {
            deny = deny.with_reason(format!("warrant_expired: {}", ts));
        }
        Error::WarrantRevoked(id) => {
            deny = deny.with_reason(format!("warrant_revoked: {}", id));
        }
        Error::SignatureInvalid(msg) => {
            deny = deny.with_reason(format!("signature_invalid: {}", msg));
        }
        Error::MissingSignature(msg) => {
            deny = deny.with_reason(format!("missing_pop: {}", msg));
        }
        Error::Unauthorized(msg) => {
            deny = deny.with_reason(format!("unauthorized: {}", msg));
        }
        Error::DepthExceeded(current, max) => {
            deny = deny.with_reason(format!("depth_exceeded: {} > {}", current, max));
        }
        Error::ChainVerificationFailed(msg) => {
            deny = deny.with_reason(format!("chain_verification_failed: {}", msg));
        }
        _ => {
            deny = deny.with_reason(format!("{}", error));
        }
    }

    deny
}

/// Sanitize error for external API response.
///
/// Returns (error_code, error_name, message) using canonical error codes
/// from the wire format spec (§Appendix A).
///
/// Maps internal errors to generic codes without leaking implementation details.
fn sanitize_error(error: &tenuo::Error) -> (u16, &'static str, &'static str) {
    let error_code = error.code();
    let name = error_code.name();
    let description = error_code.description();

    // Return canonical code, kebab-case name, and description
    (error_code.code(), name, description)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use tenuo::{
        approval::{compute_request_hash, ApprovalPayload, SignedApproval},
        approval_gate::{encode_approval_gate_map, ApprovalGateMap, ToolApprovalGate},
        constraints::ConstraintSet,
    };
    use tower::ServiceExt;

    const GATEWAY_YAML: &str = r#"
version: "1"
settings:
  debug_mode: true
tools:
  deploy:
    description: "Deploy service"
    constraints:
      service:
        from: path
        path: "service"
        required: true
routes:
  - pattern: "/deploy/{service}"
    method: ["POST"]
    tool: "deploy"
"#;

    /// Build a minimal test app with the given authorizer and gateway YAML.
    fn build_test_app(authorizer: Authorizer) -> Router {
        let config = GatewayConfig::from_yaml(GATEWAY_YAML).unwrap();
        let compiled = CompiledGatewayConfig::compile(config).unwrap();
        let state = Arc::new(AppState {
            authorizer: Arc::new(tokio::sync::RwLock::new(authorizer)),
            config: compiled,
            debug_mode: true,
            audit_tx: None,
            authorizer_id: Arc::new(tokio::sync::RwLock::new(None)),
            metrics: None,
            started_at: std::time::Instant::now(),
        });
        Router::new()
            .route("/health", axum::routing::get(health_check))
            .fallback(handle_request)
            .with_state(state)
    }

    /// Create a warrant with an approval gate requiring 1-of-1 approvals.
    fn create_gated_warrant(
        root_key: &SigningKey,
        approver_key: &tenuo::crypto::PublicKey,
    ) -> tenuo::Warrant {
        let mut gates = ApprovalGateMap::new();
        gates.insert("deploy".to_string(), ToolApprovalGate::whole_tool());

        tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .required_approvers(vec![approver_key.clone()])
            .min_approvals(1)
            .holder(root_key.public_key())
            .extension(
                "tenuo.approval_gates",
                encode_approval_gate_map(&gates).unwrap(),
            )
            .build(root_key)
            .unwrap()
    }

    /// Encode a warrant for the X-Tenuo-Warrant header.
    fn encode_warrant_header(warrant: &tenuo::Warrant) -> String {
        wire::encode_base64(warrant).unwrap()
    }

    /// Encode a PoP signature for the X-Tenuo-PoP header.
    fn encode_pop_header(sig: &tenuo::Signature) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// Create a valid signed approval for the given warrant/tool/args.
    fn create_approval(
        warrant: &tenuo::Warrant,
        tool: &str,
        args: &HashMap<String, ConstraintValue>,
        approver_key: &SigningKey,
    ) -> SignedApproval {
        let request_hash = compute_request_hash(
            &warrant.id().to_string(),
            tool,
            args,
            Some(warrant.authorized_holder()),
        );
        let now = chrono::Utc::now();
        let payload = ApprovalPayload {
            version: 1,
            request_hash,
            nonce: rand::random(),
            external_id: "test-approver@test.com".to_string(),
            approved_at: now.timestamp() as u64,
            expires_at: (now + chrono::Duration::seconds(300)).timestamp() as u64,
            extensions: None,
        };
        SignedApproval::create(payload, approver_key)
    }

    /// CBOR-encode approvals and base64 them for the header.
    fn encode_approvals_header(approvals: &[SignedApproval]) -> String {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(approvals, &mut buf).unwrap();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
    }

    /// Parse a JSON response body.
    async fn parse_body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // ----------------------------------------------------------------
    // Fix #1: ApprovalRequired returns actionable data
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn approval_required_response_includes_actionable_data() {
        let root_key = SigningKey::generate();
        let approver_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let warrant = create_gated_warrant(&root_key, &approver_key.public_key());
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        // Send request WITHOUT approvals header → should get ApprovalRequired with enriched body
        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = parse_body(resp).await;
        assert_eq!(body["error"], "approval-required");
        assert_eq!(body["error_code"], 1707);
        assert!(
            body["request_hash"].is_string(),
            "missing request_hash: {body}"
        );
        assert!(!body["request_hash"].as_str().unwrap().is_empty());
        assert_eq!(body["required_approvals"], 1);
        assert_eq!(body["received_approvals"], 0);
        let approvers = body["required_approvers"]
            .as_array()
            .expect("missing required_approvers");
        assert_eq!(approvers.len(), 1);
        assert_eq!(
            approvers[0].as_str().unwrap(),
            hex::encode(approver_key.public_key().to_bytes())
        );
    }

    #[tokio::test]
    async fn insufficient_approvals_response_includes_actionable_data() {
        let root_key = SigningKey::generate();
        let approver1 = SigningKey::generate();
        let approver2 = SigningKey::generate();
        let wrong_approver = SigningKey::generate();

        // Require 2-of-2 approvals
        let mut gates = ApprovalGateMap::new();
        gates.insert("deploy".to_string(), ToolApprovalGate::whole_tool());
        let warrant = tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .required_approvers(vec![approver1.public_key(), approver2.public_key()])
            .min_approvals(2)
            .holder(root_key.public_key())
            .extension(
                "tenuo.approval_gates",
                encode_approval_gate_map(&gates).unwrap(),
            )
            .build(&root_key)
            .unwrap();

        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        // Send an approval from a wrong approver (not in the trusted set)
        let bad_approval = create_approval(&warrant, "deploy", &args, &wrong_approver);
        let approvals_b64 = encode_approvals_header(&[bad_approval]);

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .header("X-Tenuo-Approvals", &approvals_b64)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = parse_body(resp).await;
        assert!(
            body["request_hash"].is_string(),
            "missing request_hash: {body}"
        );
        assert_eq!(body["required_approvals"], 2);
        let approvers = body["required_approvers"]
            .as_array()
            .expect("missing required_approvers");
        assert_eq!(approvers.len(), 2);
    }

    // ----------------------------------------------------------------
    // Fix #2: Malformed approval header → 400
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn malformed_base64_approval_header_returns_400() {
        let root_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let warrant = tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .holder(root_key.public_key())
            .build(&root_key)
            .unwrap();
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .header("X-Tenuo-Approvals", "!!!not-valid-base64!!!")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = parse_body(resp).await;
        assert_eq!(body["error"], "invalid_approvals_header");
    }

    #[tokio::test]
    async fn malformed_cbor_approval_header_returns_400() {
        let root_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let warrant = tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .holder(root_key.public_key())
            .build(&root_key)
            .unwrap();
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        // Valid base64 but not valid CBOR for SignedApproval
        let garbage_cbor =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"this is not cbor");

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .header("X-Tenuo-Approvals", &garbage_cbor)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = parse_body(resp).await;
        assert_eq!(body["error"], "invalid_approvals_header");
    }

    // ----------------------------------------------------------------
    // Fix #3: Oversized approval header → 400
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn oversized_approval_header_returns_400() {
        let root_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let warrant = tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .holder(root_key.public_key())
            .build(&root_key)
            .unwrap();
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        // 128KB of base64 → decodes to ~96KB, well above the 64KB limit
        let huge_payload = vec![0xA0u8; 128_000];
        let huge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&huge_payload);

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .header("X-Tenuo-Approvals", &huge_b64)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = parse_body(resp).await;
        assert_eq!(body["error"], "invalid_approvals_header");
        assert!(body["message"].as_str().unwrap().contains("too large"));
    }

    // ----------------------------------------------------------------
    // Positive: valid approval flow works end-to-end
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn valid_approval_succeeds() {
        let root_key = SigningKey::generate();
        let approver_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        let warrant = create_gated_warrant(&root_key, &approver_key.public_key());
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();
        let approval = create_approval(&warrant, "deploy", &args, &approver_key);
        let approvals_b64 = encode_approvals_header(&[approval]);

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .header("X-Tenuo-Approvals", &approvals_b64)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = parse_body(resp).await;
        assert_eq!(body["authorized"], true);
    }

    // ----------------------------------------------------------------
    // Absent approval header is fine when no gate is configured
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn no_approval_header_succeeds_without_gate() {
        let root_key = SigningKey::generate();
        let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
        let app = build_test_app(authorizer);

        // Warrant WITHOUT approval gates
        let warrant = tenuo::Warrant::builder()
            .capability("deploy", ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(300))
            .holder(root_key.public_key())
            .build(&root_key)
            .unwrap();
        let args: HashMap<String, ConstraintValue> = [(
            "service".to_string(),
            ConstraintValue::String("api".to_string()),
        )]
        .into();
        let pop = warrant.sign(&root_key, "deploy", &args).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/deploy/api")
            .header("X-Tenuo-Warrant", encode_warrant_header(&warrant))
            .header("X-Tenuo-PoP", encode_pop_header(&pop))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = parse_body(resp).await;
        assert_eq!(body["authorized"], true);
    }
}
