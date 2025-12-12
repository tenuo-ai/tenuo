//! Tenuo CLI - Developer utilities for key management, warrant issuance, and verification.
//!
//! Implements the CLI specification v0.1.0

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;
use tenuo_core::{
    constraints::{Constraint, ConstraintValue, Exact, OneOf, Pattern, Range, RegexConstraint},
    crypto::{Keypair, PublicKey, Signature},
    extraction::RequestContext,
    gateway_config::GatewayConfig,
    planes::DataPlane,
    warrant::Warrant,
    wire,
};
use chrono::{DateTime, Utc};
// TODO: Implement proper PKCS#8 and SPKI PEM encoding/decoding
// For now, we support hex/base64 keys and simplified PEM (hex-encoded)

#[derive(Parser)]
#[command(name = "tenuo")]
#[command(about = "Agent Capability Flow Control", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Ed25519 keypair for agent identity
    Keygen {
        /// Base name for output files (creates NAME.key and NAME.pub)
        name: Option<String>,
        
        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,
        
        /// Output raw base64 private key only (for CI/CD env vars)
        #[arg(long)]
        raw: bool,
        
        /// Print public key from existing private key
        #[arg(long)]
        show_public: Option<PathBuf>,
    },

    /// Issue a root warrant (equivalent to control-plane issuance)
    Issue {
        /// Path to issuer's private key (PEM)
        #[arg(short = 'k', long = "signing-key", required = true)]
        signing_key: PathBuf,
        
        /// Holder's public key: path to PEM file or base64 string
        #[arg(short = 'h', long = "holder", required = true)]
        holder: String,
        
        /// Comma-separated allowed tools (e.g., search,read_file)
        #[arg(short = 't', long = "tool")]
        tool: Option<String>,
        
        /// Validity duration (default: 5m). Formats: 300s, 10m, 1h
        #[arg(long = "ttl", default_value = "5m")]
        ttl: String,
        
        /// Warrant ID (default: generated)
        #[arg(long = "id")]
        id: Option<String>,
        
        /// Add constraint (repeatable). Format: key=type:value
        #[arg(short = 'c', long = "constraint")]
        constraint: Vec<String>,
        
        /// Add constraint as JSON (for complex values)
        #[arg(long = "constraint-json")]
        constraint_json: Vec<String>,
        
        /// Output as JSON
        #[arg(long)]
        json: bool,
        
        /// Output warrant string only, no decoration
        #[arg(short, long)]
        quiet: bool,
    },

    /// Derive a child warrant with equal or narrower scope
    Attenuate {
        /// Base64 warrant string. Use - to read from stdin.
        warrant: String,
        
        /// Current holder's private key (PEM)
        #[arg(short = 'k', long = "signing-key", required = true)]
        signing_key: PathBuf,
        
        /// Child's public key. If omitted, self-attenuates (same holder).
        #[arg(short = 'h', long = "holder")]
        holder: Option<String>,
        
        /// Subset of tools to retain (must be subset of parent)
        #[arg(short = 't', long = "tool")]
        tool: Option<String>,
        
        /// New TTL (must be <= parent's remaining TTL). Formats: 300s, 10m, 1h
        #[arg(long = "ttl")]
        ttl: Option<String>,
        
        /// Narrowing constraints (must not widen parent's constraints)
        #[arg(short = 'c', long = "constraint")]
        constraint: Vec<String>,
        
        /// Narrowing constraint as JSON
        #[arg(long = "constraint-json")]
        constraint_json: Vec<String>,
        
        /// Output as JSON
        #[arg(long)]
        json: bool,
        
        /// Output warrant string only
        #[arg(short, long)]
        quiet: bool,
    },

    /// Create a proof-of-possession signature over a request payload
    Sign {
        /// Holder's private key (must match warrant's holder)
        #[arg(short = 'k', long = "key", required = true)]
        key: PathBuf,
        
        /// Base64 warrant string
        #[arg(short = 'w', long = "warrant", required = true)]
        warrant: String,
        
        /// Tool name for the request
        #[arg(short = 't', long = "tool", required = true)]
        tool: String,
        
        /// Request body to sign (JSON). Use - to read from stdin.
        payload: String,
        
        /// Output as JSON with warrant, payload hash, and signature
        #[arg(long)]
        json: bool,
        
        /// Output signature only
        #[arg(short, long)]
        quiet: bool,
    },

    /// Full verification: warrant validity + PoP signature + holder binding
    Verify {
        /// Request body that was signed (JSON). Use - to read from stdin.
        payload: String,
        
        /// Base64 warrant string
        #[arg(short = 'w', long = "warrant", required = true)]
        warrant: String,
        
        /// Base64 signature from sign command
        #[arg(short = 's', long = "signature", required = true)]
        signature: String,
        
        /// Tool name for the request
        #[arg(short = 't', long = "tool", required = true)]
        tool: String,
        
        /// Trusted root issuer's public key (PEM or base64). Repeatable.
        #[arg(short = 'i', long = "trusted-issuer")]
        trusted_issuer: Vec<String>,
        
        /// Verify as of specific time (default: now). ISO 8601 format.
        #[arg(long = "at")]
        at: Option<String>,
        
        /// Output detailed JSON result
        #[arg(long)]
        json: bool,
        
        /// Exit code only (0 = valid, 1 = invalid)
        #[arg(short, long)]
        quiet: bool,
    },

    /// Decode and pretty-print a warrant
    Inspect {
        /// Base64 warrant string. Use - to read from stdin.
        warrant: String,
        
        /// Output raw JSON structure
        #[arg(long)]
        json: bool,
        
        /// Verify internal signatures and TTL
        #[arg(long)]
        verify: bool,
        
        /// Show full delegation chain
        #[arg(long)]
        chain: bool,
    },

    /// Test extraction rules against a sample request (dry run)
    Extract {
        /// Path to gateway configuration YAML file
        #[arg(long, short)]
        config: PathBuf,

        /// Sample request JSON (inline or @filename)
        #[arg(long, short)]
        request: String,

        /// HTTP method (default: POST)
        #[arg(long, default_value = "POST")]
        method: String,

        /// Request path (e.g., /api/v1/clusters/prod/scale)
        #[arg(long, short)]
        path: String,

        /// Additional headers as key=value pairs (can be repeated)
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Query parameters as key=value pairs (can be repeated)
        #[arg(long = "query", short = 'q')]
        query: Vec<String>,

        /// Show verbose extraction trace
        #[arg(long, short)]
        verbose: bool,

        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Validate a gateway configuration file
    ValidateConfig {
        /// Path to gateway configuration YAML file
        #[arg(long, short)]
        config: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { name, force, raw, show_public } => {
            handle_keygen(name, force, raw, show_public)?;
        }
        Commands::Issue {
            signing_key,
            holder,
            tool,
            ttl,
            id: _id, // TODO: support custom ID
            constraint,
            constraint_json,
            json,
            quiet,
        } => {
            handle_issue(signing_key, holder, tool, ttl, constraint, constraint_json, json, quiet)?;
        }
        Commands::Attenuate {
            warrant,
            signing_key,
            holder,
            tool,
            ttl,
            constraint,
            constraint_json,
            json,
            quiet,
        } => {
            handle_attenuate(warrant, signing_key, holder, tool, ttl, constraint, constraint_json, json, quiet)?;
        }
        Commands::Sign {
            key,
            warrant,
            tool,
            payload,
            json,
            quiet,
        } => {
            handle_sign(key, warrant, tool, payload, json, quiet)?;
        }
        Commands::Verify {
            payload,
            warrant,
            signature,
            tool,
            trusted_issuer,
            at,
            json,
            quiet,
        } => {
            handle_verify(payload, warrant, signature, tool, trusted_issuer, at, json, quiet)?;
        }
        Commands::Inspect { warrant, json, verify, chain } => {
            handle_inspect(warrant, json, verify, chain)?;
        }
        Commands::Extract {
            config,
            request,
            method,
            path,
            headers,
            query,
            verbose,
            output,
        } => {
            handle_extract(config, request, method, path, headers, query, verbose, output)?;
        }
        Commands::ValidateConfig { config } => {
            handle_validate_config(config)?;
        }
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse duration string (e.g., "300s", "10m", "1h")
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty duration string".to_string());
    }

    let (num_str, unit) = if s.ends_with('s') && !s.ends_with("ms") {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else {
        // Assume seconds if no unit
        (s, "s")
    };

    let num: u64 = num_str.parse().map_err(|_| format!("Invalid number in duration: {}", num_str))?;

    let secs = match unit {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        _ => return Err(format!("Unknown duration unit: {}", unit)),
    };

    Ok(Duration::from_secs(secs))
}

/// Load private key from PEM file or raw bytes
/// TODO: Implement proper PKCS#8 PEM parsing
fn load_private_key(path: &PathBuf) -> Result<Keypair, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let content = content.trim();
    
    // Try PEM first (simplified - extract hex from PEM for now)
    if content.contains("BEGIN PRIVATE KEY") {
        // For v0.1.0, support hex-encoded keys in PEM format
        // Extract hex string between BEGIN/END markers
        let lines: Vec<&str> = content.lines().collect();
        let mut hex_str = String::new();
        let mut in_key = false;
        for line in lines {
            if line.contains("BEGIN") {
                in_key = true;
                continue;
            }
            if line.contains("END") {
                break;
            }
            if in_key {
                hex_str.push_str(line.trim());
            }
        }
        
        if !hex_str.is_empty() {
            if let Ok(bytes) = hex::decode(&hex_str) {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                    return Ok(Keypair::from_bytes(&arr));
                }
            }
        }
        return Err("Could not extract key from PEM (expected hex-encoded 32-byte key)".into());
    }
    
    // Try as hex
    if let Ok(bytes) = hex::decode(content) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(Keypair::from_bytes(&arr));
        }
    }
    
    // Try as base64
    if let Ok(bytes) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        content,
    ) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(Keypair::from_bytes(&arr));
        }
    }
    
    Err("Could not parse private key (expected hex or base64, 32 bytes)".into())
}

/// Load public key from PEM file or base64/hex string
/// TODO: Implement proper SPKI PEM parsing
fn load_public_key(input: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    // Try as file path first
    let path = PathBuf::from(input);
    if path.exists() {
            let content = fs::read_to_string(&path)?;
            let content = content.trim();
            
            // Try PEM (simplified - extract hex from PEM for now)
            if content.contains("BEGIN PUBLIC KEY") {
                // For v0.1.0, support hex-encoded keys in PEM format
                let lines: Vec<&str> = content.lines().collect();
                let mut hex_str = String::new();
                let mut in_key = false;
                for line in lines {
                    if line.contains("BEGIN") {
                        in_key = true;
                        continue;
                    }
                    if line.contains("END") {
                        break;
                    }
                    if in_key {
                        hex_str.push_str(line.trim());
                    }
                }
                
                if !hex_str.is_empty() {
                    if let Ok(bytes) = hex::decode(&hex_str) {
                        if bytes.len() == 32 {
                            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                            return Ok(PublicKey::from_bytes(&arr)?);
                        }
                    }
                }
                return Err("Could not extract key from PEM (expected hex-encoded 32-byte key)".into());
            }
            
            // Try as hex
            if let Ok(bytes) = hex::decode(content) {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                    return Ok(PublicKey::from_bytes(&arr)?);
                }
            }
            
            // Try as base64
            if let Ok(bytes) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                content,
            ) {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                    return Ok(PublicKey::from_bytes(&arr)?);
                }
            }
        }
    }
    
    // Try as base64 string
    if let Ok(bytes) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        input,
    ) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(PublicKey::from_bytes(&arr)?);
        }
    }
    
    // Try as hex string
    if let Ok(bytes) = hex::decode(input) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(PublicKey::from_bytes(&arr)?);
        }
    }
    
    Err(format!("Could not parse public key from: {}", input).into())
}

/// Encode private key to PEM (PKCS#8)
/// Note: This is a simplified implementation. For production, use proper ASN.1 encoding.
fn encode_private_key_pem(keypair: &Keypair) -> String {
    // For now, output hex format until we implement proper PKCS#8 encoding
    // TODO: Implement proper PKCS#8 encoding using pkcs8 crate
    let secret = keypair.secret_key_bytes();
    let hex_str = hex::encode(secret);
    
    // Create a minimal PEM-like structure (not standard, but readable)
    // In production, this should be proper PKCS#8
    format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", hex_str)
}

/// Encode public key to PEM (SPKI)
/// Note: This is a simplified implementation. For production, use proper ASN.1 encoding.
fn encode_public_key_pem(pubkey: &PublicKey) -> String {
    // For now, output hex format until we implement proper SPKI encoding
    // TODO: Implement proper SPKI encoding using spki crate
    let bytes = pubkey.to_bytes();
    let hex_str = hex::encode(bytes);
    
    // Create a minimal PEM-like structure (not standard, but readable)
    // In production, this should be proper SPKI
    format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", hex_str)
}

/// Parse constraint from string format: "key=type:value"
fn parse_constraint(s: &str) -> Result<(String, Constraint), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid constraint format: {}", s));
    }
    
    let key = parts[0].to_string();
    let value_part = parts[1];
    
    let (constraint_type, value) = if let Some(colon_idx) = value_part.find(':') {
        let ctype = &value_part[..colon_idx];
        let val = &value_part[colon_idx + 1..];
        (ctype, val)
    } else {
        // Default to pattern if no type specified
        ("pattern", value_part)
    };
    
    let constraint: Constraint = match constraint_type {
        "exact" => Constraint::Exact(Exact::new(value.to_string())),
        "pattern" => Constraint::Pattern(Pattern::new(value).map_err(|e| e.to_string())?),
        "regex" => Constraint::Regex(RegexConstraint::new(value).map_err(|e| e.to_string())?),
        "range" => {
            // Parse range like "0.8..1.0" or "..100" or "10.."
            let parts: Vec<&str> = value.split("..").collect();
            let min = if parts[0].is_empty() {
                None
            } else {
                Some(parts[0].parse::<f64>().map_err(|_| "Invalid range min")?)
            };
            let max = if parts.len() > 1 && !parts[1].is_empty() {
                Some(parts[1].parse::<f64>().map_err(|_| "Invalid range max")?)
            } else {
                None
            };
            Constraint::Range(Range::new(min, max))
        }
        "oneof" => {
            let values: Vec<String> = value.split(',').map(|s| s.trim().to_string()).collect();
            Constraint::OneOf(OneOf::new(values))
        }
        _ => return Err(format!("Unknown constraint type: {}", constraint_type)),
    };
    
    Ok((key, constraint))
}

/// Parse constraints from JSON string
fn parse_constraint_json(s: &str) -> Result<HashMap<String, Constraint>, Box<dyn std::error::Error>> {
    let json: serde_json::Value = serde_json::from_str(s)?;
    let mut constraints = HashMap::new();
    
    if let Some(obj) = json.as_object() {
        for (key, value) in obj {
            let constraint = json_to_constraint(value)?;
            constraints.insert(key.clone(), constraint);
        }
    }
    
    Ok(constraints)
}

/// Convert JSON value to Constraint
fn json_to_constraint(v: &serde_json::Value) -> Result<Constraint, Box<dyn std::error::Error>> {
    if let Some(obj) = v.as_object() {
        if let Some(exact) = obj.get("exact") {
            return Ok(Constraint::Exact(Exact::new(
                exact.as_str().ok_or("exact must be string")?.to_string(),
            )));
        }
        if let Some(pattern) = obj.get("pattern") {
            return Ok(Constraint::Pattern(Pattern::new(
                pattern.as_str().ok_or("pattern must be string")?,
            )?));
        }
        if let Some(regex) = obj.get("regex") {
            return Ok(Constraint::Regex(RegexConstraint::new(
                regex.as_str().ok_or("regex must be string")?,
            )?));
        }
        if obj.contains_key("min") || obj.contains_key("max") {
            let min = obj.get("min").and_then(|v| v.as_f64());
            let max = obj.get("max").and_then(|v| v.as_f64());
            return Ok(Constraint::Range(Range::new(min, max)));
        }
        if let Some(enum_vals) = obj.get("enum") {
            let values: Vec<String> = enum_vals
                .as_array()
                .ok_or("enum must be array")?
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            return Ok(Constraint::OneOf(OneOf::new(values)));
        }
    }
    
    // If it's a string, treat as pattern
    if let Some(s) = v.as_str() {
        return Ok(Constraint::Pattern(Pattern::new(s)?));
    }
    
    Err("Invalid constraint JSON format".into())
}

/// Read warrant from string or stdin
fn read_warrant(input: &str) -> Result<Warrant, Box<dyn std::error::Error>> {
    let warrant_str = if input == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf.trim().to_string()
    } else {
        input.to_string()
    };
    
    wire::decode_base64(&warrant_str).map_err(|e| e.into())
}

/// Read payload from string or stdin
fn read_payload(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if input == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

// ============================================================================
// Command Handlers
// ============================================================================

fn handle_keygen(
    name: Option<String>,
    force: bool,
    raw: bool,
    show_public: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(pub_path) = show_public {
        // Extract public key from existing private key
        let keypair = load_private_key(&pub_path)?;
        let pubkey = keypair.public_key();
        
        if raw {
            // Output raw base64
            println!("{}", base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                pubkey.to_bytes(),
            ));
        } else {
            // Output PEM
            println!("{}", encode_public_key_pem(&pubkey));
        }
        return Ok(());
    }
    
    let keypair = Keypair::generate();
    let pubkey = keypair.public_key();
    
    if raw {
        // Output raw base64 private key only
        println!("{}", base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            keypair.secret_key_bytes(),
        ));
        return Ok(());
    }
    
    if let Some(base_name) = name {
        let private_path = PathBuf::from(format!("{}.key", base_name));
        let public_path = PathBuf::from(format!("{}.pub", base_name));
        
        if !force {
            if private_path.exists() || public_path.exists() {
                return Err(format!(
                    "Files exist: {}.key or {}.pub. Use --force to overwrite.",
                    base_name, base_name
                ).into());
            }
        }
        
        fs::write(&private_path, encode_private_key_pem(&keypair))?;
        fs::write(&public_path, encode_public_key_pem(&pubkey))?;
        
        eprintln!("Created {}.key and {}.pub", base_name, base_name);
    } else {
        // Output to stdout
        println!("{}", encode_private_key_pem(&keypair));
        eprintln!("{}", encode_public_key_pem(&pubkey));
    }
    
    Ok(())
}

fn handle_issue(
    signing_key: PathBuf,
    holder: String,
    tool: Option<String>,
    ttl: String,
    constraint: Vec<String>,
    constraint_json: Vec<String>,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer_kp = load_private_key(&signing_key)?;
    let holder_pubkey = load_public_key(&holder)?;
    
    let tool_str = tool.as_deref().unwrap_or("*");
    let ttl_duration = parse_duration(&ttl)?;
    
    let mut builder = Warrant::builder()
        .tool(tool_str)
        .ttl(ttl_duration)
        .authorized_holder(holder_pubkey.clone());
    
    // Parse constraints
    for c in constraint {
        let (key, constraint) = parse_constraint(&c)?;
        builder = builder.constraint(key, constraint);
    }
    
    for json_str in constraint_json {
        let constraints = parse_constraint_json(&json_str)?;
        for (key, constraint) in constraints {
            builder = builder.constraint(key, constraint);
        }
    }
    
    let warrant = builder.build(&issuer_kp)?;
    let warrant_b64 = wire::encode_base64(&warrant)?;
    
    if quiet {
        println!("{}", warrant_b64);
    } else if json {
        let info = serde_json::json!({
            "id": warrant.id().as_str(),
            "tool": warrant.tool(),
            "depth": warrant.depth(),
            "expires_at": warrant.expires_at().to_rfc3339(),
            "holder": hex::encode(holder_pubkey.to_bytes()),
            "base64": warrant_b64,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", warrant_b64);
    }
    
    Ok(())
}

fn handle_attenuate(
    warrant: String,
    signing_key: PathBuf,
    holder: Option<String>,
    tool: Option<String>,
    ttl: Option<String>,
    constraint: Vec<String>,
    constraint_json: Vec<String>,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent_warrant = read_warrant(&warrant)?;
    let current_kp = load_private_key(&signing_key)?;
    
    let mut builder = parent_warrant.attenuate();
    
    if let Some(holder_str) = holder {
        let holder_pubkey = load_public_key(&holder_str)?;
        builder = builder.authorized_holder(holder_pubkey);
    }
    
    if let Some(tool_str) = tool {
        builder = builder.tool(&tool_str);
    }
    
    if let Some(ttl_str) = ttl {
        let ttl_duration = parse_duration(&ttl_str)?;
        builder = builder.ttl(ttl_duration);
    }
    
    // Parse constraints
    for c in constraint {
        let (key, constraint) = parse_constraint(&c)?;
        builder = builder.constraint(key, constraint);
    }
    
    for json_str in constraint_json {
        let constraints = parse_constraint_json(&json_str)?;
        for (key, constraint) in constraints {
            builder = builder.constraint(key, constraint);
        }
    }
    
    let child_warrant = builder.build(&current_kp)?;
    let warrant_b64 = wire::encode_base64(&child_warrant)?;
    
    if quiet {
        println!("{}", warrant_b64);
    } else if json {
        let info = serde_json::json!({
            "id": child_warrant.id().as_str(),
            "tool": child_warrant.tool(),
            "depth": child_warrant.depth(),
            "expires_at": child_warrant.expires_at().to_rfc3339(),
            "parent_id": child_warrant.parent_id().map(|id| id.to_string()),
            "base64": warrant_b64,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", warrant_b64);
    }
    
    Ok(())
}

fn handle_sign(
    key: PathBuf,
    warrant: String,
    tool: String,
    payload: String,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = load_private_key(&key)?;
    let warrant_obj = read_warrant(&warrant)?;
    
    // Verify keypair matches warrant's holder
    let holder = warrant_obj.authorized_holder()
        .ok_or("Warrant has no authorized_holder")?;
    
    if keypair.public_key().to_bytes() != holder.to_bytes() {
        return Err("Keypair does not match warrant's authorized_holder".into());
    }
    
    // Read and parse payload as JSON
    let payload_str = if payload == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        payload
    };
    
    let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|e| format!("Payload must be valid JSON: {}", e))?;
    
    // Convert JSON to HashMap<String, ConstraintValue>
    let mut args = HashMap::new();
    if let Some(obj) = payload_json.as_object() {
        for (key, value) in obj {
            let constraint_value = json_to_constraint_value(value)?;
            args.insert(key.clone(), constraint_value);
        }
    } else {
        return Err("Payload JSON must be an object".into());
    }
    
    // Create PoP signature using warrant's method
    let signature = warrant_obj.create_pop_signature(&keypair, &tool, &args)?;
    
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes(),
    );
    
    if quiet {
        println!("{}", sig_b64);
    } else if json {
        let info = serde_json::json!({
            "warrant_id": warrant_obj.id().as_str(),
            "tool": tool,
            "signature": sig_b64,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", sig_b64);
    }
    
    Ok(())
}

/// Convert JSON value to ConstraintValue
fn json_to_constraint_value(v: &serde_json::Value) -> Result<ConstraintValue, Box<dyn std::error::Error>> {
    match v {
        serde_json::Value::String(s) => Ok(ConstraintValue::String(s.clone())),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ConstraintValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(ConstraintValue::Float(f))
            } else {
                Err("Invalid number".into())
            }
        }
        serde_json::Value::Bool(b) => Ok(ConstraintValue::Boolean(*b)),
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<ConstraintValue>, _> = arr.iter().map(json_to_constraint_value).collect();
            Ok(ConstraintValue::List(items?))
        }
        serde_json::Value::Object(_) => {
            // Objects are not directly supported, serialize to string
            Ok(ConstraintValue::String(v.to_string()))
        }
        serde_json::Value::Null => Ok(ConstraintValue::Null),
    }
}

fn handle_verify(
    payload: String,
    warrant: String,
    signature: String,
    tool: String,
    trusted_issuer: Vec<String>,
    at: Option<String>,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let warrant_obj = read_warrant(&warrant)?;
    
    // Decode signature
    let sig_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &signature,
    )?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| "Invalid signature length")?;
    let sig = Signature::from_bytes(&sig_arr)?;
    
    // Parse payload as JSON and convert to args
    let payload_str = if payload == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        payload
    };
    
    let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|e| format!("Payload must be valid JSON: {}", e))?;
    
    let mut args = HashMap::new();
    if let Some(obj) = payload_json.as_object() {
        for (key, value) in obj {
            let constraint_value = json_to_constraint_value(value)?;
            args.insert(key.clone(), constraint_value);
        }
    } else {
        return Err("Payload JSON must be an object".into());
    }
    
    // Verify warrant chain first
    let mut data_plane = DataPlane::new();
    let mut trusted_any = false;
    
    for issuer_str in &trusted_issuer {
        match load_public_key(issuer_str) {
            Ok(pubkey) => {
                data_plane.trust_issuer("cli", pubkey);
                trusted_any = true;
            }
            Err(e) => {
                eprintln!("Warning: Could not load trusted issuer '{}': {}", issuer_str, e);
            }
        }
    }
    
    // Verify warrant chain
    let chain_result = data_plane.verify(&warrant_obj);
    let chain_valid = chain_result.is_ok();
    
    // Check expiration
    let expired = if let Some(at_str) = at {
        let verify_time = DateTime::parse_from_rfc3339(&at_str)
            .map_err(|_| "Invalid timestamp format (use ISO 8601)")?
            .with_timezone(&Utc);
        verify_time > warrant_obj.expires_at()
    } else {
        warrant_obj.is_expired()
    };
    
    if expired {
        if quiet {
            std::process::exit(2);
        }
        eprintln!("❌ INVALID: Warrant has expired");
        eprintln!("Expires at: {}", warrant_obj.expires_at());
        std::process::exit(2);
    }
    
    if !chain_valid {
        if quiet {
            std::process::exit(2);
        }
        if let Err(e) = chain_result {
            eprintln!("❌ INVALID: {}", e);
        }
        std::process::exit(2);
    }
    
    // Verify authorization (includes PoP signature verification)
    let holder = warrant_obj.authorized_holder()
        .ok_or("Warrant has no authorized_holder")?;
    
    match warrant_obj.authorize(&tool, &args, Some(&sig)) {
        Ok(()) => {
            // Authorization successful - PoP signature is valid
        }
        Err(e) => {
            if quiet {
                std::process::exit(2);
            }
            eprintln!("❌ INVALID: {}", e);
            eprintln!();
            eprintln!("Expected:    {}", hex::encode(holder.to_bytes()));
            eprintln!("Signer:      (PoP signature verification failed)");
            std::process::exit(2);
        }
    }
    
    if quiet {
        // Exit code only
        if !trusted_any {
            eprintln!("⚠️  Warning: root issuer not verified (no --trusted-issuer provided)");
        }
        return Ok(());
    }
    
    if json {
        let mut result = serde_json::json!({
            "valid": true,
            "warrant_id": warrant_obj.id().as_str(),
            "holder": hex::encode(holder.to_bytes()),
            "expires_at": warrant_obj.expires_at().to_rfc3339(),
            "tools": warrant_obj.tool(),
            "chain_verified": chain_valid,
            "trusted_root": trusted_any,
        });
        
        // Add constraints
        let mut constraints = serde_json::Map::new();
        for (key, constraint) in warrant_obj.constraints().iter() {
            constraints.insert(key.clone(), serde_json::json!(format!("{:?}", constraint)));
        }
        result["constraints"] = serde_json::Value::Object(constraints);
        
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        if !trusted_any {
            eprintln!("⚠️  VALID (chain only)");
            eprintln!();
            eprintln!("Warning: root issuer not verified (no --trusted-issuer provided)");
            eprintln!();
        } else {
            eprintln!("✅ VALID");
            eprintln!();
        }
        
        eprintln!("Warrant:     {}", warrant_obj.id().as_str());
        eprintln!("Holder:      {} (verified)", hex::encode(holder.to_bytes()));
        
        let remaining = warrant_obj.expires_at() - Utc::now();
        if remaining.num_minutes() > 0 {
            eprintln!("Expires:     in {}m", remaining.num_minutes());
        } else {
            eprintln!("Expires:     in {}s", remaining.num_seconds());
        }
        
        eprintln!("Tools:       [{}]", warrant_obj.tool());
        eprintln!("Constraints:");
        for (key, constraint) in warrant_obj.constraints().iter() {
            eprintln!("  {}: {:?}", key, constraint);
        }
        eprintln!();
        
        eprintln!("Chain:       {} delegations", warrant_obj.depth());
        // TODO: Show chain details
        
        eprintln!("PoP:         ✅ Signature valid, signer matches holder");
    }
    
    Ok(())
}

fn handle_inspect(
    warrant: String,
    json: bool,
    verify: bool,
    chain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let warrant_obj = read_warrant(&warrant)?;
    
    if json {
        let mut info = serde_json::json!({
            "id": warrant_obj.id().as_str(),
            "tool": warrant_obj.tool(),
            "depth": warrant_obj.depth(),
            "expires_at": warrant_obj.expires_at().to_rfc3339(),
            "issuer": hex::encode(warrant_obj.issuer().to_bytes()),
        });
        
        if let Some(holder) = warrant_obj.authorized_holder() {
            info["holder"] = serde_json::json!(hex::encode(holder.to_bytes()));
        }
        
        if let Some(parent) = warrant_obj.parent_id() {
            info["parent_id"] = serde_json::json!(parent.to_string());
        }
        
        if let Some(session) = warrant_obj.session_id() {
            info["session_id"] = serde_json::json!(session);
        }
        
        let mut constraints = serde_json::Map::new();
        for (key, constraint) in warrant_obj.constraints().iter() {
            constraints.insert(key.clone(), serde_json::json!(format!("{:?}", constraint)));
        }
        info["constraints"] = serde_json::Value::Object(constraints);
        
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    
    // Pretty print
    println!("WARRANT: {}", warrant_obj.id().as_str());
    println!("──────────────────────────────────────────────────");
    
    if verify {
        let expired = warrant_obj.is_expired();
        if expired {
            println!("Status:      ❌ EXPIRED");
            let elapsed = Utc::now() - warrant_obj.expires_at();
            if elapsed.num_minutes() > 0 {
                println!("             ({}m ago)", elapsed.num_minutes());
            } else {
                println!("             ({}s ago)", elapsed.num_seconds());
            }
        } else {
            println!("Status:      ✅ ACTIVE");
            let remaining = warrant_obj.expires_at() - Utc::now();
            if remaining.num_minutes() > 0 {
                println!("             (expires in {}m)", remaining.num_minutes());
            } else {
                println!("             (expires in {}s)", remaining.num_seconds());
            }
        }
    } else {
        let expired = warrant_obj.is_expired();
        if expired {
            println!("Status:      ❌ EXPIRED");
        } else {
            println!("Status:      ✅ ACTIVE");
        }
    }
    
    println!("Issuer:      {}", hex::encode(warrant_obj.issuer().to_bytes()));
    if let Some(holder) = warrant_obj.authorized_holder() {
        println!("Holder:      {}", hex::encode(holder.to_bytes()));
    }
    println!("Tools:       [{}]", warrant_obj.tool());
    println!("Constraints:");
    for (key, constraint) in warrant_obj.constraints().iter() {
        println!("  {}: {:?}", key, constraint);
    }
    println!("──────────────────────────────────────────────────");
    
    if chain {
        // TODO: Show full delegation chain
        println!();
        println!("DELEGATION CHAIN:");
        println!("──────────────────────────────────────────────────");
        println!("[0] ROOT");
        println!("    Issuer:  {} (control plane)", hex::encode(warrant_obj.issuer().to_bytes()));
        if let Some(holder) = warrant_obj.authorized_holder() {
            println!("    Holder:  {}", hex::encode(holder.to_bytes()));
        }
        println!("    Tools:   [{}]", warrant_obj.tool());
        println!("    TTL:     {}s", (warrant_obj.expires_at() - warrant_obj.expires_at()).num_seconds());
        println!("──────────────────────────────────────────────────");
    }
    
    Ok(())
}

fn handle_extract(
    config_path: PathBuf,
    request: String,
    method: String,
    path: String,
    headers: Vec<String>,
    query: Vec<String>,
    verbose: bool,
    output: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load config
    let config = GatewayConfig::from_file(&config_path)?;

    // Parse request body
    let body: serde_json::Value = if request.starts_with('@') {
        let file_path = &request[1..];
        let content = fs::read_to_string(file_path)?;
        serde_json::from_str(&content)?
    } else {
        serde_json::from_str(&request)?
    };

    // Parse headers
    let mut header_map = HashMap::new();
    for h in headers {
        if let Some((k, v)) = h.split_once('=') {
            header_map.insert(k.to_lowercase(), v.to_string());
        }
    }

    // Parse query params
    let mut query_map = HashMap::new();
    for q in query {
        if let Some((k, v)) = q.split_once('=') {
            query_map.insert(k.to_string(), v.to_string());
        }
    }

    // Also parse query from path if present
    let (clean_path, path_query) = if let Some(idx) = path.find('?') {
        let (p, q) = path.split_at(idx);
        (p.to_string(), Some(&q[1..]))
    } else {
        (path.clone(), None)
    };

    if let Some(qs) = path_query {
        for pair in qs.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                query_map.insert(k.to_string(), v.to_string());
            }
        }
    }

    // Match route
    let (route, path_params) = config
        .match_route(&method, &clean_path)
        .ok_or_else(|| format!("No route matches {} {}", method, clean_path))?;

    if output == "text" {
        println!();
        println!("┌─────────────────────────────────────────────────────────");
        println!("│ Tenuo Extraction Dry Run");
        println!("├─────────────────────────────────────────────────────────");
        println!("│ Config:  {}", config_path.display());
        println!("│ Request: {} {}", method, path);
        println!("│ Tool:    {}", route.tool);
        println!("└─────────────────────────────────────────────────────────");
        println!();
    }

    // Build context
    let mut ctx = RequestContext::with_body(body.clone());
    ctx.path_params = path_params;
    ctx.query_params = query_map;
    ctx.headers = header_map;

    if verbose && output == "text" {
        println!("📥 Request Context:");
        println!("   Path params:  {:?}", ctx.path_params);
        println!("   Query params: {:?}", ctx.query_params);
        println!("   Headers:      {:?}", ctx.headers);
        let body_preview: String = body.to_string().chars().take(200).collect();
        println!("   Body preview: {}", body_preview);
        println!();
    }

    // Extract constraints
    let result = config.extract_constraints(route, &ctx);

    match output.as_str() {
        "json" => {
            let json_result = match &result {
                Ok(r) => serde_json::json!({
                    "success": true,
                    "tool": r.tool,
                    "constraints": r.constraints.iter()
                        .map(|(k, v)| (k.clone(), format_value(v)))
                        .collect::<HashMap<_, _>>(),
                    "traces": r.traces.iter().map(|t| serde_json::json!({
                        "field": t.field,
                        "source": format!("{:?}", t.source),
                        "path": t.path,
                        "found": t.result.is_some(),
                        "required": t.required,
                        "hint": t.hint,
                    })).collect::<Vec<_>>(),
                }),
                Err(e) => serde_json::json!({
                    "success": false,
                    "error": {
                        "field": e.field,
                        "source": format!("{:?}", e.source),
                        "path": e.path,
                        "hint": e.hint,
                    }
                }),
            };
            println!("{}", serde_json::to_string_pretty(&json_result)?);
        }
        _ => {
            // Text output
            match result {
                Ok(r) => {
                    println!("📋 Extraction Results:\n");
                    println!(
                        "   {:<20} {:<10} {:<25} {:<10} {}",
                        "Field", "Source", "Path", "Required", "Result"
                    );
                    println!("   {}", "─".repeat(85));

                    for trace in &r.traces {
                        let status = if trace.result.is_some() {
                            "✓"
                        } else if trace.required {
                            "✗"
                        } else {
                            "○"
                        };

                        let result_str = match &trace.result {
                            Some(v) => format_value(v),
                            None => "—".to_string(),
                        };

                        println!(
                            "   {} {:<18} {:<10} {:<25} {:<10} {}",
                            status,
                            trace.field,
                            format!("{:?}", trace.source).to_lowercase(),
                            truncate(&trace.path, 25),
                            if trace.required { "yes" } else { "no" },
                            truncate(&result_str, 40)
                        );

                        // Show hint on failure
                        if trace.result.is_none() && trace.hint.is_some() && verbose {
                            println!("      └── 💡 {}", trace.hint.as_ref().unwrap());
                        }
                    }

                    println!();
                    println!("✅ All required fields extracted successfully.\n");

                    println!("📦 Final Constraint Map (for authorization):\n");
                    for (k, v) in &r.constraints {
                        println!("   {}: {}", k, format_value(v));
                    }
                    println!();
                }
                Err(e) => {
                    println!("❌ Extraction failed.\n");
                    println!("   Field:  {}", e.field);
                    println!("   Source: {:?}", e.source);
                    println!("   Path:   {}", e.path);
                    println!("   Hint:   {}", e.hint);
                    println!();
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn handle_validate_config(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validating {}...\n", config_path.display());

    let config = GatewayConfig::from_file(&config_path)?;

    match config.validate() {
        Ok(()) => {
            println!("✅ Configuration is valid.\n");
            println!("Summary:");
            println!("  Tools:  {}", config.tools.len());
            println!("  Routes: {}", config.routes.len());
            println!();
            
            for (name, tool) in &config.tools {
                println!("  Tool '{}':", name);
                println!("    Description: {}", tool.description);
                println!("    Constraints: {}", tool.constraints.len());
                for (field, rule) in &tool.constraints {
                    let req = if rule.required { " (required)" } else { "" };
                    println!("      - {} [{:?}] {}{}", field, rule.from, rule.path, req);
                }
            }
        }
        Err(errors) => {
            println!("❌ Configuration has {} error(s):\n", errors.len());
            for e in errors {
                println!("  • {}: {}", e.location, e.message);
            }
            println!();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn format_value(v: &ConstraintValue) -> String {
    match v {
        ConstraintValue::String(s) => format!("\"{}\"", s),
        ConstraintValue::Integer(i) => i.to_string(),
        ConstraintValue::Float(f) => format!("{:.2}", f),
        ConstraintValue::Boolean(b) => b.to_string(),
        ConstraintValue::List(l) => {
            let items: Vec<String> = l.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        ConstraintValue::Object(_) => "{...}".to_string(),
        ConstraintValue::Null => "null".to_string(),
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
