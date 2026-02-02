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
//! 3. Verifies the warrant chain from the `X-Tenuo-Chain` header
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
    constraints::ConstraintValue,
    extraction::RequestContext,
    gateway_config::{CompiledGatewayConfig, GatewayConfig},
    heartbeat::{
        self, create_audit_channel, AuditEventSender, AuthorizationEvent, HeartbeatConfig,
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

    // === Tenuo Cloud Control Plane Configuration ===
    /// Tenuo Cloud control plane URL (enables heartbeat when set with api-key and authorizer-name)
    #[arg(long, env = "TENUO_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,

    /// Tenuo Cloud API key for authentication
    #[arg(long, env = "TENUO_API_KEY")]
    api_key: Option<String>,

    /// Authorizer name for registration with Tenuo Cloud
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
    let cli = Cli::parse();

    // Build authorizer from trusted keys and revocation list
    let authorizer = build_authorizer(&cli.trusted_keys, &cli.revocation_list)?;

    match &cli.command {
        Commands::Serve { port, config, bind } => {
            serve_http(authorizer, config, bind, *port, &cli).await?;
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
            let result = authorizer.check(&w, tool, &args, Some(&pop_signature), &[]);

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
) -> Result<Authorizer, Box<dyn std::error::Error>> {
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
    if let Some(path) = revocation_path {
        let srl = load_signed_revocation_list(path)?;

        // Verify against first trusted key (Control Plane key)
        authorizer.set_revocation_list(srl, &first_key)?;
        eprintln!("Loaded signed revocation list from: {}", path.display());
    }

    Ok(authorizer)
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
use tracing::{debug, info, warn};

/// Shared state for the HTTP server
struct AppState {
    authorizer: Arc<tokio::sync::RwLock<Authorizer>>,
    config: CompiledGatewayConfig,
    debug_mode: bool,
    /// Audit event sender (None if control plane not configured)
    audit_tx: Option<AuditEventSender>,
    /// Authorizer ID from control plane registration (for audit events)
    authorizer_id: Arc<tokio::sync::RwLock<Option<String>>>,
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

    // Check if Tenuo Cloud control plane is configured
    let control_plane_enabled =
        cli.control_plane_url.is_some() && cli.api_key.is_some() && cli.authorizer_name.is_some();

    eprintln!("┌─────────────────────────────────────────────────────────");
    eprintln!("│ Tenuo Authorizer Server v{}", authorizer_version());
    eprintln!("├─────────────────────────────────────────────────────────");
    eprintln!("│ Listening on: {}:{}", bind, port);
    eprintln!("│ Config: {}", config_path.display());
    if debug_mode {
        eprintln!("│ ⚠️  Debug mode: ENABLED (not for production!)");
    }
    if control_plane_enabled {
        eprintln!(
            "│ Tenuo Cloud: ENABLED (heartbeat every {}s, SRL sync)",
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

    // Create audit channel and spawn heartbeat task if control plane is configured
    let audit_tx = if let (Some(url), Some(key), Some(name)) =
        (&cli.control_plane_url, &cli.api_key, &cli.authorizer_name)
    {
        // Create audit event channel (buffer 1000 events)
        let (tx, rx) = create_audit_channel(1000);

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
        info!("Heartbeat and audit streaming enabled for Tenuo Cloud");

        Some(tx)
    } else {
        None
    };

    let state = Arc::new(AppState {
        authorizer: shared_authorizer,
        config: compiled,
        debug_mode,
        audit_tx,
        authorizer_id: shared_authorizer_id,
    });

    // Build the router
    // Health endpoint first (no auth required) for K8s probes
    // Then catch-all for authorized requests
    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/healthz", axum::routing::get(health_check))
        .route("/ready", axum::routing::get(health_check))
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

    // 8. Authorize
    // Start timing for audit event
    let auth_start = std::time::Instant::now();

    // Acquire read lock on authorizer (allows concurrent reads, blocks only during SRL updates)
    let authorizer = state.authorizer.read().await;

    // First, verify the chain (trust anchor -> leaf)
    let verify_result = authorizer.verify_chain(&chain);

    let result = match verify_result {
        Ok(_) => {
            // If chain is valid, authorize the specific action against the leaf
            authorizer.authorize(
                leaf_warrant,
                &extraction_result.tool,
                &extraction_result.constraints,
                pop_signature.as_ref(),
                &[], // No approvals in HTTP mode
            )
        }
        Err(e) => Err(e),
    };

    // Release the lock before building the response
    drop(authorizer);

    // Calculate authorization latency
    let latency_us = auth_start.elapsed().as_micros() as u64;

    // Extract chain metadata for audit event
    let chain_depth = leaf_warrant.depth() as u8;
    let root_principal = chain.first().map(|w| hex::encode(w.issuer().to_bytes()));

    // Encode warrant stack for audit event (base64 CBOR)
    let warrant_stack_b64 = encode_warrant_stack_for_audit(&chain);

    match result {
        Ok(()) => {
            info!(
                request_id = %request_id,
                warrant_id = %warrant_id,
                tool = %extraction_result.tool,
                event = "authorization_success",
                "Request authorized"
            );

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
                ),
            )
            .await;

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
                    root_principal,
                    warrant_stack_b64,
                    latency_us,
                    request_id.clone(),
                ),
            )
            .await;

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
