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

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use tenuo_core::{
    constraints::ConstraintValue,
    extraction::RequestContext,
    gateway_config::{CompiledGatewayConfig, GatewayConfig},
    planes::Authorizer,
    revocation::SignedRevocationList,
    wire, PublicKey,
};

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

    match cli.command {
        Commands::Serve { port, config, bind } => {
            serve_http(authorizer, &config, &bind, port).await?;
        }

        Commands::Verify {
            warrant,
            tool,
            arg,
            output,
        } => {
            // Read warrant
            let warrant_str = read_warrant(warrant)?;
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

            // Check authorization (no approvals for CLI mode)
            let result = authorizer.check(&w, &tool, &args, None, &[]);

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
                        "warrant_id": w.id().as_str(),
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
            let warrant_str = read_warrant(warrant)?;
            let w = wire::decode_base64(&warrant_str)?;

            // Just verify, don't authorize
            match w.verify(w.issuer()) {
                Ok(()) => {
                    println!("✓ Warrant signature is valid");
                    println!("  ID: {}", w.id());
                    if let Some(tools) = w.tools() {
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
            println!("Tenuo Authorizer v{}", env!("CARGO_PKG_VERSION"));
            println!();
            if let Some(keys) = &cli.trusted_keys {
                let count = keys.split(',').filter(|s| !s.is_empty()).count();
                println!("Trusted keys: {} configured", count);
            } else {
                println!("Trusted keys: None (will accept any issuer for delegated warrants)");
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
            tenuo_core::Keypair::generate().public_key()
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
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::any,
    Json, Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;

/// Shared state for the HTTP server
struct AppState {
    authorizer: Authorizer,
    config: CompiledGatewayConfig,
}

/// Start the HTTP authorization server
async fn serve_http(
    authorizer: Authorizer,
    config_path: &PathBuf,
    bind: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load and compile gateway configuration
    let config = GatewayConfig::from_file(config_path)?;
    let compiled = CompiledGatewayConfig::compile(config)?;

    eprintln!("┌─────────────────────────────────────────────────────────");
    eprintln!("│ Tenuo Authorizer Server");
    eprintln!("├─────────────────────────────────────────────────────────");
    eprintln!("│ Listening on: {}:{}", bind, port);
    eprintln!("│ Config: {}", config_path.display());
    eprintln!("└─────────────────────────────────────────────────────────");
    eprintln!();

    let state = Arc::new(AppState {
        authorizer,
        config: compiled,
    });

    // Build the router - catch all requests
    let app = Router::new()
        .route("/{*path}", any(handle_request))
        .route("/", any(handle_request))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", bind, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Handle an incoming HTTP request
async fn handle_request(
    State(state): State<Arc<AppState>>,
    method: Method,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    body: Bytes,
) -> impl IntoResponse {
    let path = format!("/{}", path);

    // 1. Match route
    let route_match = match state.config.match_route(method.as_str(), &path) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": "no_route",
                    "message": format!("No route matches {} {}", method, path)
                })),
            );
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
                        "message": format!("Invalid {} header encoding", warrant_header)
                    })),
                );
            }
        },
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "missing_warrant",
                    "message": format!("Missing {} header", warrant_header)
                })),
            );
        }
    };

    // 3. Decode warrant
    let warrant = match wire::decode_base64(&warrant_b64) {
        Ok(w) => w,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_warrant",
                    "message": format!("Failed to decode warrant: {}", e)
                })),
            );
        }
    };

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

    let mut ctx = RequestContext::with_body(json_body);
    ctx.path_params = route_match.path_params.clone();
    ctx.query_params = query;
    ctx.headers = http_headers;

    // 6. Extract constraints
    let extraction_result = match state.config.extract_constraints(&route_match, &ctx) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "extraction_failed",
                    "message": format!("Failed to extract constraints: {}", e),
                    "field": e.field,
                    "hint": e.hint
                })),
            );
        }
    };

    // 7. Extract and parse PoP signature from header (if present)
    let pop_header = &state.config.settings.pop_header;
    let pop_signature: Option<tenuo_core::Signature> = headers
        .get(pop_header)
        .and_then(|v| v.to_str().ok())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .and_then(|bytes| {
            if bytes.len() == 64 {
                let arr: [u8; 64] = bytes.try_into().ok()?;
                tenuo_core::Signature::from_bytes(&arr).ok()
            } else {
                None
            }
        });

    // 8. Authorize
    let result = state.authorizer.check(
        &warrant,
        &extraction_result.tool,
        &extraction_result.constraints,
        pop_signature.as_ref(),
        &[], // No approvals in HTTP mode
    );

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "authorized": true,
                "warrant_id": warrant.id().as_str(),
                "tool": extraction_result.tool,
            })),
        ),
        Err(e) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "authorized": false,
                "error": "authorization_failed",
                "message": format!("{}", e),
                "warrant_id": warrant.id().as_str(),
                "tool": extraction_result.tool,
            })),
        ),
    }
}
