//! Tenuo CLI - Developer utilities for key management, warrant issuance, and verification.
//!
//! Implements the CLI specification v0.1.0

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use der::asn1::{AnyRef, BitStringRef};
use der::{Decode, Encode, EncodePem};
use pkcs8::{LineEnding, PrivateKeyInfo};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tenuo::{
    constraints::{Constraint, ConstraintValue, Exact, OneOf, Pattern, Range, RegexConstraint},
    crypto::{PublicKey, Signature, SigningKey},
    extraction::RequestContext,
    gateway_config::GatewayConfig,
    planes::DataPlane,
    warrant::{TrustLevel, Warrant, WarrantType},
    wire,
};
// We use the pkcs8/spki crates for standard PEM handling

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
        #[arg(long = "holder", required = true)]
        holder: String,

        /// Warrant type: execution (default) or issuer
        #[arg(long = "type", default_value = "execution")]
        warrant_type: String,

        /// Comma-separated allowed tools (e.g., search,read_file) - required for execution warrants
        #[arg(short = 't', long = "tool")]
        tool: Option<String>,

        /// Comma-separated issuable tools (e.g., read_file,send_email) - required for issuer warrants
        #[arg(long = "issuable-tools")]
        issuable_tools: Option<String>,

        /// Trust ceiling for issuer warrants: external, internal, or system
        #[arg(long = "trust-ceiling")]
        trust_ceiling: Option<String>,

        /// Maximum issue depth for issuer warrants
        #[arg(long = "max-issue-depth")]
        max_issue_depth: Option<u32>,

        /// Trust level (optional): external, internal, or system
        #[arg(long = "trust-level")]
        trust_level: Option<String>,

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

        /// Add constraint bound for issuer warrants (repeatable). Format: key=type:value
        #[arg(long = "constraint-bound")]
        constraint_bound: Vec<String>,

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

        /// Parent warrant issuer's private key (PEM) for chain link signature.
        /// If omitted, assumes parent was signed by the same keypair as signing-key.
        #[arg(long = "parent-key")]
        parent_key: Option<PathBuf>,

        /// Child's public key. If omitted, self-attenuates (same holder).
        #[arg(long = "holder")]
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

        /// Show diff of what changed (tools, constraints, TTL)
        #[arg(long)]
        diff: bool,

        /// Preview only - show what would change without creating warrant
        #[arg(long)]
        preview: bool,
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

        /// Base64 warrant string. Repeatable for chain verification (root to leaf).
        #[arg(short = 'w', long = "warrant", required = true)]
        warrant: Vec<String>,

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
        /// Base64 warrant string. Repeatable for chain inspection.
        warrant: Vec<String>,

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
        Commands::Keygen {
            name,
            force,
            raw,
            show_public,
        } => {
            handle_keygen(name, force, raw, show_public)?;
        }
        Commands::Issue {
            signing_key,
            holder,
            warrant_type,
            tool,
            issuable_tools,
            trust_ceiling,
            max_issue_depth,
            trust_level,
            ttl,
            id,
            constraint,
            constraint_json,
            constraint_bound,
            json,
            quiet,
        } => {
            handle_issue(
                signing_key,
                holder,
                warrant_type,
                tool,
                issuable_tools,
                trust_ceiling,
                max_issue_depth,
                trust_level,
                ttl,
                id,
                constraint,
                constraint_json,
                constraint_bound,
                json,
                quiet,
            )?;
        }
        Commands::Attenuate {
            warrant,
            signing_key,
            parent_key,
            holder,
            tool,
            ttl,
            constraint,
            constraint_json,
            json,
            quiet,
            diff,
            preview,
        } => {
            handle_attenuate(
                warrant,
                signing_key,
                parent_key,
                holder,
                tool,
                ttl,
                constraint,
                constraint_json,
                json,
                quiet,
                diff,
                preview,
            )?;
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
            handle_verify(
                payload,
                warrant,
                signature,
                tool,
                trusted_issuer,
                at,
                json,
                quiet,
            )?;
        }
        Commands::Inspect {
            warrant,
            json,
            verify,
            chain: _,
        } => {
            let mut warrants = Vec::new();
            for w_str in &warrant {
                warrants.push(read_warrant(w_str)?);
            }
            handle_inspect(warrants, json, verify)?;
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
            handle_extract(
                config, request, method, path, headers, query, verbose, output,
            )?;
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
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, "m")
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, "h")
    } else {
        // Assume seconds if no unit
        (s, "s")
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("Invalid number in duration: {}", num_str))?;

    let secs = match unit {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        _ => return Err(format!("Unknown duration unit: {}", unit)),
    };

    Ok(Duration::from_secs(secs))
}

/// Load private key from PEM file or raw bytes
fn load_private_key(path: &PathBuf) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let content = content.trim();

    // Try standard PKCS#8 PEM using pem crate
    if let Ok(pem) = pem::parse(content) {
        if pem.tag() == "PRIVATE KEY" {
            // Decode PrivateKeyInfo from DER
            if let Ok(info) = PrivateKeyInfo::from_der(pem.contents()) {
                if info.algorithm.oid.to_string() == "1.3.101.112" {
                    use der::Decode;
                    if let Ok(octet_string) =
                        <der::asn1::OctetString as Decode>::from_der(info.private_key)
                    {
                        let bytes = octet_string.as_bytes();
                        if bytes.len() == 32 {
                            let arr: [u8; 32] = bytes.try_into()?;
                            return Ok(SigningKey::from_bytes(&arr));
                        }
                    }
                    if info.private_key.len() == 32 {
                        let arr: [u8; 32] = info.private_key.try_into()?;
                        return Ok(SigningKey::from_bytes(&arr));
                    }
                }
            }
        }
    }

    // Try PEM (simplified - extract hex from PEM for now) - BACKWARD COMPATIBILITY
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
                    return Ok(SigningKey::from_bytes(&arr));
                }
            }
        }
        // Don't return error yet, try other formats
    }

    // Try as hex
    if let Ok(bytes) = hex::decode(content) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(SigningKey::from_bytes(&arr));
        }
    }

    // Try as base64
    if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
            return Ok(SigningKey::from_bytes(&arr));
        }
    }

    Err("Could not parse private key (expected PKCS#8 PEM, hex, or base64)".into())
}

/// Load public key from PEM file or base64/hex string
fn load_public_key(input: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    // Try as file path first
    let path = PathBuf::from(input);
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        let content = content.trim();

        // Try standard SPKI PEM using pem crate
        if let Ok(pem) = pem::parse(content) {
            if pem.tag() == "PUBLIC KEY" {
                if let Ok(info) =
                    SubjectPublicKeyInfo::<AnyRef, BitStringRef>::from_der(pem.contents())
                {
                    if info.algorithm.oid.to_string() == "1.3.101.112" {
                        let bytes = info.subject_public_key.as_bytes();
                        if let Some(b) = bytes {
                            if b.len() == 32 {
                                let arr: [u8; 32] = b.try_into()?;
                                return Ok(PublicKey::from_bytes(&arr)?);
                            }
                        }
                    }
                }
            }
        }

        // Try PEM (simplified - extract hex from PEM for now) - BACKWARD COMPATIBILITY
        if content.contains("BEGIN PUBLIC KEY") {
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
                        return Ok(PublicKey::from_bytes(&arr)?);
                    }
                }
            }
            // Don't return error yet, try other formats
        }

        // Try as hex
        if let Ok(bytes) = hex::decode(content) {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                return Ok(PublicKey::from_bytes(&arr)?);
            }
        }

        // Try as base64
        if let Ok(bytes) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content)
        {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "Invalid key length")?;
                return Ok(PublicKey::from_bytes(&arr)?);
            }
        }
    }

    // Try as base64 string (if not a file or file doesn't exist)
    if let Ok(bytes) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input) {
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
fn encode_private_key_pem(keypair: &SigningKey) -> Result<String, Box<dyn std::error::Error>> {
    let secret = keypair.secret_key_bytes();

    // For Ed25519, the private key is an OctetString wrapping the 32-byte seed
    // We need to encode the inner OctetString first
    let octet_string = der::asn1::OctetString::new(secret)
        .map_err(|e| format!("Failed to create OctetString: {:?}", e))?;
    let octet_string_bytes = octet_string
        .to_der()
        .map_err(|e| format!("Failed to encode OctetString: {:?}", e))?;

    let oid = "1.3.101.112"
        .parse()
        .map_err(|e| format!("Failed to parse Ed25519 OID: {:?}", e))?;
    let alg: AlgorithmIdentifier<AnyRef> = AlgorithmIdentifier {
        oid,
        parameters: None,
    };

    let info = PrivateKeyInfo {
        algorithm: alg,
        private_key: &octet_string_bytes,
        public_key: None,
    };

    info.to_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode PEM: {:?}", e).into())
}

/// Encode public key to PEM (SPKI)
fn encode_public_key_pem(pubkey: &PublicKey) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = pubkey.to_bytes();
    let bit_string = BitStringRef::from_bytes(&bytes)
        .map_err(|e| format!("Failed to create BitString: {:?}", e))?;

    let oid = "1.3.101.112"
        .parse()
        .map_err(|e| format!("Failed to parse Ed25519 OID: {:?}", e))?;
    let alg: AlgorithmIdentifier<AnyRef> = AlgorithmIdentifier {
        oid,
        parameters: None,
    };

    let info = SubjectPublicKeyInfo {
        algorithm: alg,
        subject_public_key: bit_string,
    };

    info.to_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to encode PEM: {:?}", e).into())
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
            Constraint::Range(Range::new(min, max).map_err(|e| e.to_string())?)
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
fn parse_constraint_json(
    s: &str,
) -> Result<HashMap<String, Constraint>, Box<dyn std::error::Error>> {
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
            return Ok(Constraint::Range(Range::new(min, max)?));
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

/// Read warrant from string or file path.
///
/// This function intentionally supports both:
/// - Direct base64-encoded warrant strings
/// - File paths containing warrant data (for CLI convenience)
///
/// If the input is a valid file path, the file contents are read.
/// Otherwise, the input is treated as a base64-encoded warrant string.
fn read_warrant(input: &str) -> Result<Warrant, Box<dyn std::error::Error>> {
    let path = Path::new(input);
    let exists = path.exists();
    let content = if exists {
        fs::read_to_string(input)?
    } else {
        input.trim().to_string()
    };

    wire::decode_base64(&content).map_err(|e| e.into())
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
            println!(
                "{}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    pubkey.to_bytes(),
                )
            );
        } else {
            // Output PEM
            println!("{}", encode_public_key_pem(&pubkey)?);
        }
        return Ok(());
    }

    let keypair = SigningKey::generate();
    let pubkey = keypair.public_key();

    if raw {
        // Output raw base64 private key only
        println!(
            "{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                keypair.secret_key_bytes(),
            )
        );
        return Ok(());
    }

    if let Some(base_name) = name {
        let private_path = PathBuf::from(format!("{}.key", base_name));
        let public_path = PathBuf::from(format!("{}.pub", base_name));

        if !force && (private_path.exists() || public_path.exists()) {
            return Err(format!(
                "Files exist: {}.key or {}.pub. Use --force to overwrite.",
                base_name, base_name
            )
            .into());
        }

        fs::write(&private_path, encode_private_key_pem(&keypair)?)?;
        fs::write(&public_path, encode_public_key_pem(&pubkey)?)?;

        eprintln!("Created {}.key and {}.pub", base_name, base_name);
    } else {
        // Output to stdout
        println!("{}", encode_private_key_pem(&keypair)?);
        eprintln!("{}", encode_public_key_pem(&pubkey)?);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_issue(
    signing_key: PathBuf,
    holder: String,
    warrant_type: String,
    tool: Option<String>,
    issuable_tools: Option<String>,
    trust_ceiling: Option<String>,
    max_issue_depth: Option<u32>,
    trust_level: Option<String>,
    ttl: String,
    id: Option<String>,
    constraint: Vec<String>,
    constraint_json: Vec<String>,
    constraint_bound: Vec<String>,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer_kp = load_private_key(&signing_key)?;
    let holder_pubkey = load_public_key(&holder)?;

    let warrant_type_enum = match warrant_type.as_str() {
        "execution" => WarrantType::Execution,
        "issuer" => WarrantType::Issuer,
        _ => {
            return Err(format!(
                "Invalid warrant type: {}. Must be 'execution' or 'issuer'",
                warrant_type
            )
            .into())
        }
    };

    let ttl_duration = parse_duration(&ttl)?;

    let mut builder = Warrant::builder()
        .r#type(warrant_type_enum)
        .ttl(ttl_duration)
        .authorized_holder(holder_pubkey.clone());

    // Set trust level if provided
    if let Some(trust_level_str) = trust_level {
        let level = trust_level_str
            .parse()
            .map_err(|e: String| format!("Invalid trust level: {}", e))?;
        builder = builder.trust_level(level);
    }

    match warrant_type_enum {
        WarrantType::Execution => {
            let tool_str = tool.as_deref().ok_or("Execution warrant requires --tool")?;

            // Parse constraints for execution warrants
            let mut constraint_set = tenuo::constraints::ConstraintSet::new();
            for c in constraint {
                let (key, constraint) = parse_constraint(&c)?;
                constraint_set.insert(key, constraint);
            }

            for json_str in constraint_json {
                let constraints = parse_constraint_json(&json_str)?;
                for (key, constraint) in constraints {
                    constraint_set.insert(key, constraint);
                }
            }

            builder = builder.capability(tool_str, constraint_set);
        }
        WarrantType::Issuer => {
            let issuable_tools_vec: Vec<String> = issuable_tools
                .ok_or("Issuer warrant requires --issuable-tools")?
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            builder = builder.issuable_tools(issuable_tools_vec);

            let ceiling = trust_ceiling
                .ok_or("Issuer warrant requires --trust-ceiling")?
                .parse::<TrustLevel>()
                .map_err(|e| format!("Invalid trust ceiling: {}", e))?;
            builder = builder.trust_ceiling(ceiling);

            if let Some(max_issue) = max_issue_depth {
                builder = builder.max_issue_depth(max_issue);
            }

            // Parse constraint bounds for issuer warrants
            for c in constraint_bound {
                let (key, constraint) = parse_constraint(&c)?;
                builder = builder.constraint_bound(key, constraint);
            }
        }
    }

    if let Some(id_str) = id {
        let warrant_id = tenuo::warrant::WarrantId::from_string(id_str)?;
        builder = builder.id(warrant_id);
    }

    let warrant = builder.build(&issuer_kp)?;
    let warrant_b64 = wire::encode_base64(&warrant)?;

    if quiet {
        println!("{}", warrant_b64);
    } else if json {
        let mut info = serde_json::json!({
            "id": warrant.id().to_string(),
            "type": format!("{:?}", warrant.r#type()).to_lowercase(),
            "depth": warrant.depth(),
            "expires_at": warrant.expires_at().to_rfc3339(),
            "holder": hex::encode(holder_pubkey.to_bytes()),
            "base64": warrant_b64,
        });
        let tools = warrant.tools();
        if !tools.is_empty() {
            info["tools"] = serde_json::Value::Array(
                tools
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            );
        }
        if let Some(issuable_tools) = warrant.issuable_tools() {
            info["issuable_tools"] = serde_json::Value::Array(
                issuable_tools
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            );
        }
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", warrant_b64);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_attenuate(
    warrant: String,
    signing_key: PathBuf,
    parent_key: Option<PathBuf>,
    holder: Option<String>,
    tool: Option<String>,
    ttl: Option<String>,
    constraint: Vec<String>,
    constraint_json: Vec<String>,
    json: bool,
    quiet: bool,
    diff: bool,
    preview: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent_warrant = read_warrant(&warrant)?;
    let current_kp = load_private_key(&signing_key)?;

    // Note: parent_key is now unused - the signing key is the parent's holder
    let _parent_key = parent_key; // Suppress unused warning

    // Collect child constraints for diff/preview
    let mut child_constraints: HashMap<String, Constraint> = HashMap::new();
    let child_ttl_duration = ttl.as_ref().map(|t| parse_duration(t)).transpose()?;

    let mut builder = parent_warrant.attenuate();

    if let Some(holder_str) = &holder {
        let holder_pubkey = load_public_key(holder_str)?;
        builder = builder.authorized_holder(holder_pubkey);
    }

    // Note: Tool handling depends on warrant type
    // For execution warrants, tool narrowing is validated during authorization
    // For issuer warrants, we validate issuable_tools monotonicity
    if let Some(tool_str) = &tool {
        match parent_warrant.r#type() {
            WarrantType::Execution => {
                // Check if tool is allowed
                let parent_tools = parent_warrant.tools();
                let child_tools: Vec<&str> = tool_str.split(',').map(|s| s.trim()).collect();

                if !parent_tools.contains(&"*".to_string()) {
                    for child_tool in &child_tools {
                        if !parent_tools.iter().any(|t| t == *child_tool) {
                            return Err(format!(
                                "Cannot attenuate: tool '{}' not in parent's allowed tools: {:?}",
                                child_tool, parent_tools
                            )
                            .into());
                        }
                    }
                }
            }
            WarrantType::Issuer => {
                // For issuer warrants, tool parameter is ignored (use issuable_tools instead)
                eprintln!("Warning: --tool is ignored for issuer warrants. Use constraint bounds instead.");
            }
        }
    }

    if let Some(ttl_duration) = child_ttl_duration {
        builder = builder.ttl(ttl_duration);
    }

    // Parse constraints
    for c in &constraint {
        let (key, constraint_val) = parse_constraint(c)?;
        child_constraints.insert(key.clone(), constraint_val.clone());
    }

    for json_str in &constraint_json {
        let constraints = parse_constraint_json(json_str)?;
        for (key, constraint_val) in constraints {
            child_constraints.insert(key.clone(), constraint_val.clone());
        }
    }

    // Apply capabilities
    if let Some(ref tool_str) = tool {
        let mut cs = tenuo::constraints::ConstraintSet::new();
        for (k, v) in &child_constraints {
            cs.insert(k.clone(), v.clone());
        }
        builder = builder.capability(tool_str, cs);
    } else {
        // Auto-detect if single tool
        if let Some(parent_caps) = parent_warrant.capabilities() {
            if parent_caps.len() == 1 {
                let tool = parent_caps.keys().next().unwrap();
                let mut cs = tenuo::constraints::ConstraintSet::new();
                for (k, v) in &child_constraints {
                    cs.insert(k.clone(), v.clone());
                }
                builder = builder.capability(tool.clone(), cs);
            } else if !child_constraints.is_empty() {
                return Err("Cannot apply constraints without specifying --tool (parent has multiple tools)".into());
            }
        } else if parent_warrant.issuable_tools().is_some() {
            // Issuer warrant attenuation (no capabilities)
            // But warnings already issued above.
        }
    }

    // Handle preview mode - show what would change without creating warrant
    if preview {
        print_attenuation_diff(
            &parent_warrant,
            tool.as_deref(),
            &child_constraints,
            child_ttl_duration,
            holder.as_deref(),
            json,
            true, // is_preview
        )?;
        return Ok(());
    }

    let child_warrant = builder.build(&current_kp).map_err(|e| {
        // Format error messages to match spec format
        let error_str = format!("{}", e);
        // Check for PatternExpanded error and format it per spec
        if error_str.contains("pattern expanded") {
            // Error format: "pattern expanded: child pattern 'X' is broader than parent 'Y'"
            // Spec format: "constraint \"path\" would widen scope (pattern:X is broader than pattern:Y)"
            // Try to extract patterns and reformat
            if let Some(child_start) = error_str.find("child pattern '") {
                if let Some(parent_start) = error_str.find("parent '") {
                    let child_end = error_str[child_start + 15..]
                        .find('\'')
                        .map(|i| child_start + 15 + i);
                    let parent_end = error_str[parent_start + 8..]
                        .find('\'')
                        .map(|i| parent_start + 8 + i);
                    if let (Some(ce), Some(pe)) = (child_end, parent_end) {
                        let child = &error_str[child_start + 15..ce];
                        let parent = &error_str[parent_start + 8..pe];
                        return format!(
                            "constraint would widen scope (pattern:{} is broader than pattern:{})",
                            child, parent
                        );
                    }
                }
            }
        }
        // For other errors, use as-is
        error_str
    })?;
    let warrant_b64 = wire::encode_base64(&child_warrant)?;

    // Handle diff mode - show what changed along with the warrant
    if diff {
        print_attenuation_diff(
            &parent_warrant,
            tool.as_deref(),
            &child_constraints,
            child_ttl_duration,
            holder.as_deref(),
            json,
            false, // is_preview
        )?;
        if !json {
            eprintln!();
            eprintln!("Child warrant:");
        }
    }

    if quiet {
        println!("{}", warrant_b64);
    } else if json {
        let mut info = serde_json::json!({
            "id": child_warrant.id().to_string(),
            "type": format!("{:?}", child_warrant.r#type()).to_lowercase(),
            "depth": child_warrant.depth(),
            "expires_at": child_warrant.expires_at().to_rfc3339(),
            "parent_hash": child_warrant.parent_hash().map(hex::encode),
            "base64": warrant_b64,
        });
        let tools = child_warrant.tools();
        if !tools.is_empty() {
            info["tools"] = serde_json::Value::Array(
                tools
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            );
        }
        if let Some(issuable_tools) = child_warrant.issuable_tools() {
            info["issuable_tools"] = serde_json::Value::Array(
                issuable_tools
                    .iter()
                    .map(|t| serde_json::Value::String(t.clone()))
                    .collect(),
            );
        }
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("{}", warrant_b64);
    }

    Ok(())
}

/// Format a constraint for human-readable display
fn format_constraint(c: &Constraint) -> String {
    match c {
        Constraint::Wildcard(_) => "Wildcard(*)".to_string(),
        Constraint::Exact(e) => format!("Exact(\"{}\")", e.value),
        Constraint::Pattern(p) => format!("Pattern(\"{}\")", p.pattern),
        Constraint::Regex(r) => format!("Regex(\"{}\")", r.pattern),
        Constraint::Range(r) => match (r.min, r.max) {
            (Some(min), Some(max)) => format!("Range({} .. {})", min, max),
            (Some(min), None) => format!("Range({} ..)", min),
            (None, Some(max)) => format!("Range(.. {})", max),
            (None, None) => "Range(..)".to_string(),
        },
        Constraint::OneOf(o) => {
            let vals: Vec<String> = o.values.iter().map(|v| format!("{}", v)).collect();
            format!("OneOf([{}])", vals.join(", "))
        }
        Constraint::NotOneOf(n) => {
            let vals: Vec<String> = n.excluded.iter().map(|v| format!("{}", v)).collect();
            format!("NotOneOf([{}])", vals.join(", "))
        }
        Constraint::Contains(c) => {
            let vals: Vec<String> = c.required.iter().map(|v| format!("{}", v)).collect();
            format!("Contains([{}])", vals.join(", "))
        }
        Constraint::Subset(s) => {
            let vals: Vec<String> = s.allowed.iter().map(|v| format!("{}", v)).collect();
            format!("Subset([{}])", vals.join(", "))
        }
        Constraint::Cidr(c) => format!("Cidr(\"{}\")", c.cidr_string),
        Constraint::UrlPattern(u) => format!("UrlPattern(\"{}\")", u.pattern),
        Constraint::All(a) => format!("All({} constraints)", a.constraints.len()),
        Constraint::Any(a) => format!("Any({} constraints)", a.constraints.len()),
        Constraint::Not(n) => format!("Not({})", format_constraint(&n.constraint)),
        Constraint::Cel(c) => format!("CEL(\"{}\")", c.expression),
        Constraint::Unknown { type_id, .. } => format!("UNKNOWN({})", type_id),
    }
}

/// Print diff showing what changed between parent and child warrant
fn print_attenuation_diff(
    parent: &Warrant,
    child_tool: Option<&str>,
    child_constraints: &HashMap<String, Constraint>,
    child_ttl: Option<Duration>,
    child_holder: Option<&str>,
    json_output: bool,
    is_preview: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent_ttl_remaining = (parent.expires_at() - Utc::now()).num_seconds().max(0) as u64;
    let child_ttl_secs = child_ttl
        .map(|d| d.as_secs())
        .unwrap_or(parent_ttl_remaining);

    // Build diff info
    let mut deltas: Vec<serde_json::Value> = Vec::new();

    // Tools diff
    // Tools diff
    let parent_tools = parent.tools();
    let effective_child_tools = child_tool
        .map(|t| {
            t.split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| parent_tools.clone());

    if parent_tools != effective_child_tools {
        deltas.push(serde_json::json!({
            "field": "tools",
            "change": "narrowed",
            "from": parent_tools,
            "to": effective_child_tools,
        }));
    }

    // Constraints diff
    let parent_constraints = parent.constraint_bounds();
    for (key, child_val) in child_constraints {
        let parent_val = parent_constraints.as_ref().and_then(|c| c.get(key));
        if let Some(pv) = parent_val {
            deltas.push(serde_json::json!({
                "field": format!("constraints.{}", key),
                "change": "narrowed",
                "from": format_constraint(pv),
                "to": format_constraint(child_val),
            }));
        } else {
            deltas.push(serde_json::json!({
                "field": format!("constraints.{}", key),
                "change": "added",
                "to": format_constraint(child_val),
            }));
        }
    }

    // TTL diff
    if child_ttl_secs < parent_ttl_remaining {
        deltas.push(serde_json::json!({
            "field": "ttl",
            "change": "reduced",
            "from": parent_ttl_remaining,
            "to": child_ttl_secs,
        }));
    }

    // Holder diff
    if child_holder.is_some() {
        deltas.push(serde_json::json!({
            "field": "holder",
            "change": "changed",
            "from": hex::encode(parent.authorized_holder().to_bytes()),
            "to": child_holder,
        }));
    }

    // Depth diff
    deltas.push(serde_json::json!({
        "field": "depth",
        "change": "incremented",
        "from": parent.depth(),
        "to": parent.depth() + 1,
    }));

    if json_output {
        let diff_json = serde_json::json!({
            "preview": is_preview,
            "parent_id": parent.id().to_string(),
            "deltas": deltas,
            "summary": {
                "constraints_narrowed": child_constraints.len(),
                "ttl_reduced": child_ttl_secs < parent_ttl_remaining,
                "holder_changed": child_holder.is_some(),
            }
        });
        println!("{}", serde_json::to_string_pretty(&diff_json)?);
    } else {
        let mode_label = if is_preview { "PREVIEW" } else { "DIFF" };
        eprintln!("╔══════════════════════════════════════════════════════════════════╗");
        eprintln!(
            "║  DELEGATION {}                                                  ║",
            mode_label
        );
        eprintln!(
            "║  Parent: {} → Child: {}           ║",
            &parent.id().to_string()[..20],
            if is_preview { "(pending)" } else { "(created)" }
        );
        eprintln!("╠══════════════════════════════════════════════════════════════════╣");

        // Tools
        let parent_tools = parent.tools();
        if !parent_tools.is_empty() {
            eprintln!("║                                                                  ║");
            eprintln!("║  TOOLS                                                           ║");
            if effective_child_tools != parent_tools {
                // Show added/kept tools
                for tool in &effective_child_tools {
                    eprintln!("║    ✓ {:<51} ║", tool);
                }
                // Show dropped tools
                for pt in &parent_tools {
                    if !effective_child_tools.contains(pt) {
                        eprintln!("║    ✗ {:<51} ║", format!("{} (DROPPED)", pt));
                    }
                }
            } else {
                eprintln!("║    ✓ {:<51} ║", format!("{:?} (unchanged)", parent_tools));
            }
        }

        // Constraints
        if !child_constraints.is_empty() || parent_constraints.is_some() {
            eprintln!("║                                                                  ║");
            eprintln!("║  CONSTRAINTS                                                     ║");
            for (key, child_val) in child_constraints {
                let parent_val = parent_constraints.as_ref().and_then(|c| c.get(key));
                if let Some(pv) = parent_val {
                    eprintln!(
                        "║    {}                                                      ║",
                        key
                    );
                    eprintln!(
                        "║      parent: {}                               ║",
                        format_constraint(pv)
                    );
                    eprintln!(
                        "║      child:  {}                               ║",
                        format_constraint(child_val)
                    );
                    eprintln!("║      change: NARROWED                                        ║");
                } else {
                    eprintln!(
                        "║    {} (new)                                               ║",
                        key
                    );
                    eprintln!(
                        "║      child:  {}                               ║",
                        format_constraint(child_val)
                    );
                    eprintln!("║      change: ADDED                                           ║");
                }
            }
        }

        // TTL
        eprintln!("║                                                                  ║");
        eprintln!("║  TTL                                                             ║");
        eprintln!(
            "║    parent: {}s remaining                                      ║",
            parent_ttl_remaining
        );
        eprintln!(
            "║    child:  {}s                                                ║",
            child_ttl_secs
        );
        if child_ttl_secs < parent_ttl_remaining {
            eprintln!("║    change: REDUCED                                             ║");
        } else {
            eprintln!("║    change: (inherited)                                         ║");
        }

        // Depth
        eprintln!("║                                                                  ║");
        eprintln!("║  DEPTH                                                           ║");
        eprintln!(
            "║    parent: {}                                                     ║",
            parent.depth()
        );
        eprintln!(
            "║    child:  {}                                                     ║",
            parent.depth() + 1
        );
        eprintln!("╚══════════════════════════════════════════════════════════════════╝");
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
    let holder = warrant_obj.authorized_holder();

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
            "warrant_id": warrant_obj.id().to_string(),
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
fn json_to_constraint_value(
    v: &serde_json::Value,
) -> Result<ConstraintValue, Box<dyn std::error::Error>> {
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
            let items: Result<Vec<ConstraintValue>, _> =
                arr.iter().map(json_to_constraint_value).collect();
            Ok(ConstraintValue::List(items?))
        }
        serde_json::Value::Object(_) => {
            // Objects are not directly supported, serialize to string
            Ok(ConstraintValue::String(v.to_string()))
        }
        serde_json::Value::Null => Ok(ConstraintValue::Null),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_verify(
    payload: String,
    warrant: Vec<String>,
    signature: String,
    tool: String,
    trusted_issuer: Vec<String>,
    at: Option<String>,
    json: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse all warrants
    let mut warrants = Vec::new();
    for w_str in &warrant {
        warrants.push(read_warrant(w_str)?);
    }

    if warrants.is_empty() {
        return Err("No warrants provided".into());
    }

    // The leaf warrant is the last one in the chain (or the only one)
    let leaf_warrant = warrants
        .last()
        .expect("Warrants vector should not be empty at this point");

    // Decode signature
    let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "Invalid signature length")?;
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

    // Configure DataPlane
    let mut data_plane = DataPlane::new();
    let mut trusted_any = false;

    for issuer_str in &trusted_issuer {
        match load_public_key(issuer_str) {
            Ok(pubkey) => {
                data_plane.trust_issuer("cli", pubkey);
                trusted_any = true;
            }
            Err(e) => {
                eprintln!(
                    "Warning: Could not load trusted issuer '{}': {}",
                    issuer_str, e
                );
            }
        }
    }

    // Verify chain or single warrant
    let chain_valid;
    let mut chain_error = None;

    if warrants.len() > 1 {
        match data_plane.verify_chain(&warrants) {
            Ok(_) => chain_valid = true,
            Err(e) => {
                chain_valid = false;
                chain_error = Some(e.to_string());
            }
        }
    } else {
        // Single warrant verification
        if trusted_any {
            // Production mode: verify signature AND trust
            match data_plane.verify(leaf_warrant) {
                Ok(_) => chain_valid = true,
                Err(e) => {
                    chain_valid = false;
                    chain_error = Some(e.to_string());
                }
            }
        } else {
            // Debugging mode: verify signature only (no trust check)
            match leaf_warrant.verify_signature() {
                Ok(_) => chain_valid = true,
                Err(e) => {
                    chain_valid = false;
                    chain_error = Some(e.to_string());
                }
            }
        }
    }

    // Check expiration of leaf warrant
    let expired = if let Some(at_str) = at {
        let verify_time = DateTime::parse_from_rfc3339(&at_str)
            .map_err(|_| "Invalid timestamp format (use ISO 8601)")?
            .with_timezone(&Utc);
        verify_time > leaf_warrant.expires_at()
    } else {
        leaf_warrant.is_expired()
    };

    if expired {
        if quiet {
            std::process::exit(2);
        }
        eprintln!("❌ INVALID: Warrant has expired");
        eprintln!("Expires at: {}", leaf_warrant.expires_at());
        std::process::exit(2);
    }

    if !chain_valid {
        if quiet {
            std::process::exit(2);
        }
        if let Some(e) = chain_error {
            eprintln!("❌ INVALID: {}", e);
        }
        std::process::exit(2);
    }

    // Verify authorization (includes PoP signature verification)
    let holder = leaf_warrant.authorized_holder();

    match leaf_warrant.authorize(&tool, &args, Some(&sig)) {
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
            "warrant_id": leaf_warrant.id().to_string(),
            "holder": hex::encode(holder.to_bytes()),
            "expires_at": leaf_warrant.expires_at().to_rfc3339(),
            "tools": leaf_warrant.tools(),
            "chain_verified": chain_valid,
            "chain_length": warrants.len(),
            "trusted_root": trusted_any,
        });

        // Add constraints
        let mut constraints_obj = serde_json::Map::new();
        if let Some(caps) = leaf_warrant.capabilities() {
            for (tool, constraints) in caps {
                let mut tool_constraints = serde_json::Map::new();
                for (key, constraint) in constraints.iter() {
                    tool_constraints
                        .insert(key.clone(), serde_json::json!(format!("{:?}", constraint)));
                }
                constraints_obj.insert(tool.clone(), serde_json::Value::Object(tool_constraints));
            }
        }
        result["capabilities"] = serde_json::Value::Object(constraints_obj);

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

        eprintln!("Warrant:     {}", leaf_warrant.id());
        eprintln!("Holder:      {} (verified)", hex::encode(holder.to_bytes()));

        let remaining = leaf_warrant.expires_at() - Utc::now();
        if remaining.num_minutes() > 0 {
            eprintln!("Expires:     in {}m", remaining.num_minutes());
        } else {
            eprintln!("Expires:     in {}s", remaining.num_seconds());
        }

        let tools = leaf_warrant.tools();
        if !tools.is_empty() {
            eprintln!("Tools:       {:?}", tools);
        }
        if let Some(issuable_tools) = leaf_warrant.issuable_tools() {
            eprintln!("Issuable Tools: [{}]", issuable_tools.join(", "));
        }
        eprintln!("Capabilities:");
        if let Some(caps) = leaf_warrant.capabilities() {
            for (tool, constraints) in caps {
                eprintln!("  Tool: {}", tool);
                for (key, constraint) in constraints.iter() {
                    eprintln!("    {}: {:?}", key, constraint);
                }
            }
        } else {
            eprintln!("  (none)");
        }
        eprintln!();

        eprintln!(
            "Chain:       {} warrants (depth {})",
            warrants.len(),
            leaf_warrant.depth()
        );

        eprintln!("PoP:         ✅ Signature valid, signer matches holder");
    }

    Ok(())
}

fn handle_inspect(
    warrants: Vec<Warrant>,
    json: bool,
    verify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if warrants.is_empty() {
        return Err("No warrants provided".into());
    }

    // The leaf warrant is the last one in the chain (or the only one)
    let warrant = warrants
        .last()
        .expect("Warrants vector should not be empty at this point");

    if verify {
        if warrant.is_expired() {
            eprintln!("❌ EXPIRED: Warrant expired at {}", warrant.expires_at());
            std::process::exit(2);
        }

        // If chain provided, verify it
        if warrants.len() > 1 {
            let data_plane = DataPlane::new();
            if let Err(e) = data_plane.verify_chain(&warrants) {
                eprintln!("❌ INVALID CHAIN: {}", e);
                std::process::exit(2);
            }
        }
    }

    if json {
        // If multiple warrants, output array. If single, output object.
        if warrants.len() > 1 {
            let mut chain_json = Vec::new();
            for w in &warrants {
                chain_json.push(warrant_to_json(w));
            }
            println!("{}", serde_json::to_string_pretty(&chain_json)?);
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&warrant_to_json(warrant))?
            );
        }
    } else {
        println!("──────────────────────────────────────────────────");
        println!("TENUO WARRANT INSPECTOR");
        println!("──────────────────────────────────────────────────");

        for (i, w) in warrants.iter().enumerate() {
            if i > 0 {
                println!("  │");
                println!("  ▼");
            }

            println!("Warrant[{}]:  {}", i, w.id());
            println!("Issuer:      {}", hex::encode(w.issuer().to_bytes()));
            println!(
                "Holder:      {}",
                hex::encode(w.authorized_holder().to_bytes())
            );
            let tools = w.tools();
            if !tools.is_empty() {
                println!("Tools:       {:?}", tools);
            } else if let Some(issuable_tools) = w.issuable_tools() {
                println!("Issuable Tools: [{}]", issuable_tools.join(", "));
            }

            let ttl_secs = (w.expires_at() - Utc::now()).num_seconds();
            if ttl_secs > 0 {
                println!("TTL:         {}s", ttl_secs);
            } else {
                println!("TTL:         expired");
            }

            if let Some(constraints_set) = w.constraint_bounds() {
                if !constraints_set.is_empty() {
                    println!("Constraints:");
                    for (key, constraint) in constraints_set.iter() {
                        println!("  {}: {:?}", key, constraint);
                    }
                }
            }
            println!("──────────────────────────────────────────────────");
        }
    }

    Ok(())
}

fn warrant_to_json(w: &Warrant) -> serde_json::Value {
    let mut constraints = serde_json::Map::new();
    if let Some(constraints_set) = w.constraint_bounds() {
        for (key, constraint) in constraints_set.iter() {
            constraints.insert(key.clone(), serde_json::json!(format!("{:?}", constraint)));
        }
    }

    let mut json = serde_json::json!({
        "id": w.id().to_string(),
        "issuer": hex::encode(w.issuer().to_bytes()),
        "expires_at": w.expires_at().to_rfc3339(),
        "tools": w.tools(),
        "depth": w.depth(),
        "constraints": constraints,
    });

    json["holder"] = serde_json::json!(hex::encode(w.authorized_holder().to_bytes()));

    if let Some(hash) = w.parent_hash() {
        json["parent_hash"] = serde_json::json!(hex::encode(hash));
    }

    json
}

#[allow(clippy::too_many_arguments)]
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
    let body: serde_json::Value = if let Some(file_path) = request.strip_prefix('@') {
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
                    println!("[INFO] Extraction Results:\n");
                    println!(
                        "   {:<20} {:<10} {:<25} {:<10} Result",
                        "Field", "Source", "Path", "Required"
                    );
                    println!("   {}", "─".repeat(85));

                    for trace in &r.traces {
                        let status = if trace.result.is_some() {
                            "[OK]"
                        } else if trace.required {
                            "[ERR]"
                        } else {
                            "[-]"
                        };

                        let result_str = match &trace.result {
                            Some(v) => format_value(v),
                            None => "-".to_string(),
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
                            println!(
                                "      └── 💡 {}",
                                trace
                                    .hint
                                    .as_ref()
                                    .expect("hint should be present when is_some() is true")
                            );
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
