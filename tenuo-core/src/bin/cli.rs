//! Tenuo CLI - Development and debugging tool.
//!
//! Usage:
//!   tenuo dev              - Start local dev server
//!   tenuo keygen           - Generate a new keypair
//!   tenuo issue            - Issue a warrant
//!   tenuo verify           - Verify a warrant
//!   tenuo audit `<id>`     - Audit a warrant chain
//!   tenuo extract          - Test extraction rules (dry run)

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use tenuo_core::{
    constraints::{ConstraintValue, Pattern},
    crypto::Keypair,
    extraction::RequestContext,
    gateway_config::GatewayConfig,
    planes::{ControlPlane, DataPlane},
    warrant::Warrant,
    wire,
};

#[derive(Parser)]
#[command(name = "tenuo")]
#[command(about = "Agent Capability Flow Control", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start local development server
    Dev {
        /// Port to listen on
        #[arg(short, long, default_value = "9999")]
        port: u16,
    },

    /// Generate a new keypair
    Keygen {
        /// Output file for the keypair (JSON format)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Issue a new warrant
    Issue {
        /// Tool name
        #[arg(short, long)]
        tool: String,

        /// Constraints in field=pattern format (can be repeated)
        #[arg(short, long)]
        constraint: Vec<String>,

        /// TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u64,

        /// Path to keypair file
        #[arg(short, long)]
        keypair: PathBuf,

        /// Output format: base64, json, or binary
        #[arg(short, long, default_value = "base64")]
        format: String,
    },

    /// Verify a warrant
    Verify {
        /// Warrant (base64 encoded, or - for stdin)
        warrant: String,

        /// Path to public key file (or use --key-bytes)
        #[arg(short, long)]
        public_key: Option<PathBuf>,

        /// Public key as hex bytes
        #[arg(long)]
        key_bytes: Option<String>,
    },

    /// Attenuate an existing warrant
    Attenuate {
        /// Parent warrant (base64 encoded)
        #[arg(short, long)]
        parent: String,

        /// New constraints (can override parent)
        #[arg(short, long)]
        constraint: Vec<String>,

        /// New TTL in seconds (must be <= parent)
        #[arg(long)]
        ttl: Option<u64>,

        /// Path to keypair file for signing
        #[arg(short, long)]
        keypair: PathBuf,
    },

    /// Show warrant details
    Inspect {
        /// Warrant (base64 encoded, or - for stdin)
        warrant: String,
    },

    /// Export public key from a keypair
    ExportPubkey {
        /// Path to keypair file
        #[arg(short, long)]
        keypair: PathBuf,

        /// Output format: hex, base64, or json
        #[arg(short, long, default_value = "hex")]
        format: String,
    },

    /// Test extraction rules against a sample request (dry run)
    ///
    /// This command validates your gateway configuration by simulating
    /// constraint extraction without making actual authorization decisions.
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
        Commands::Dev { port } => {
            eprintln!();
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  WARNING: TENUO RUNNING IN INSECURE DEV MODE                 ║");
            eprintln!("║           DO NOT USE IN PRODUCTION                           ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            eprintln!();

            // Generate dev keypair
            let control_plane = ControlPlane::generate();
            let pubkey_hex = hex::encode(control_plane.public_key_bytes());

            // Write dev credentials
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let tenuo_dir = PathBuf::from(&home).join(".tenuo");
            fs::create_dir_all(&tenuo_dir)?;

            let dev_config = serde_json::json!({
                "endpoint": format!("http://localhost:{}", port),
                "public_key": pubkey_hex,
                "mode": "dev"
            });

            fs::write(
                tenuo_dir.join("dev.json"),
                serde_json::to_string_pretty(&dev_config)?,
            )?;

            eprintln!("Dev server running on http://localhost:{}", port);
            eprintln!("Wrote credentials to ~/.tenuo/dev.json");
            eprintln!();
            eprintln!("Public Key: {}", pubkey_hex);
            eprintln!();
            eprintln!("Set TENUO_DEV=1 in your agent to use dev mode.");
            eprintln!();

            // In a real implementation, this would start an HTTP server
            // For now, just wait
            eprintln!("Press Ctrl+C to stop.");
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }

        Commands::Keygen { output } => {
            let keypair = Keypair::generate();
            let pubkey = keypair.public_key();

            let keypair_json = serde_json::json!({
                "secret_key": hex::encode(keypair.secret_key_bytes()),
                "public_key": hex::encode(pubkey.to_bytes()),
            });

            let json_str = serde_json::to_string_pretty(&keypair_json)?;

            if let Some(path) = output {
                fs::write(&path, &json_str)?;
                eprintln!("Wrote keypair to {}", path.display());
                eprintln!("Public key: {}", hex::encode(pubkey.to_bytes()));
            } else {
                println!("{}", json_str);
            }
        }

        Commands::Issue {
            tool,
            constraint,
            ttl,
            keypair,
            format,
        } => {
            // Load keypair
            let kp_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&keypair)?)?;
            let secret_bytes = hex::decode(kp_json["secret_key"].as_str().unwrap())?;
            let secret_arr: [u8; 32] = secret_bytes.try_into().map_err(|_| "invalid key length")?;
            let kp = Keypair::from_bytes(&secret_arr);

            // Build warrant
            let mut builder = Warrant::builder().tool(&tool).ttl(Duration::from_secs(ttl));

            for c in constraint {
                let parts: Vec<&str> = c.splitn(2, '=').collect();
                if parts.len() != 2 {
                    return Err(format!("Invalid constraint format: {}", c).into());
                }
                builder = builder.constraint(parts[0], Pattern::new(parts[1])?);
            }

            let warrant = builder.build(&kp)?;

            match format.as_str() {
                "base64" => {
                    println!("{}", wire::encode_base64(&warrant)?);
                }
                "json" => {
                    let info = serde_json::json!({
                        "id": warrant.id().as_str(),
                        "tool": warrant.tool(),
                        "depth": warrant.depth(),
                        "expires_at": warrant.expires_at().to_rfc3339(),
                        "base64": wire::encode_base64(&warrant)?,
                    });
                    println!("{}", serde_json::to_string_pretty(&info)?);
                }
                "binary" => {
                    let bytes = wire::encode(&warrant)?;
                    io::stdout().write_all(&bytes)?;
                }
                _ => return Err(format!("Unknown format: {}", format).into()),
            }
        }

        Commands::Verify {
            warrant,
            public_key,
            key_bytes,
        } => {
            // Read warrant
            let warrant_str = if warrant == "-" {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf.trim().to_string()
            } else {
                warrant
            };

            let w = wire::decode_base64(&warrant_str)?;

            // Get public key
            let pubkey = if let Some(path) = public_key {
                let kp_json: serde_json::Value =
                    serde_json::from_str(&fs::read_to_string(&path)?)?;
                let bytes = hex::decode(kp_json["public_key"].as_str().unwrap())?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
                tenuo_core::PublicKey::from_bytes(&arr)?
            } else if let Some(hex_str) = key_bytes {
                let bytes = hex::decode(&hex_str)?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
                tenuo_core::PublicKey::from_bytes(&arr)?
            } else {
                return Err("Must provide --public-key or --key-bytes".into());
            };

            // Verify
            let mut data_plane = DataPlane::new();
            data_plane.trust_issuer("provided", pubkey.clone());

            match data_plane.verify(&w) {
                Ok(()) => {
                    eprintln!("✓ Warrant is valid");
                    eprintln!("  ID: {}", w.id());
                    eprintln!("  Tool: {}", w.tool());
                    eprintln!("  Depth: {}", w.depth());
                    eprintln!("  Expires: {}", w.expires_at());
                    if w.is_expired() {
                        eprintln!("  ⚠ WARNING: Warrant has expired!");
                    }
                }
                Err(e) => {
                    eprintln!("✗ Verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Attenuate {
            parent,
            constraint,
            ttl,
            keypair,
        } => {
            // Load parent warrant
            let parent_warrant = wire::decode_base64(&parent)?;

            // Load keypair
            let kp_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&keypair)?)?;
            let secret_bytes = hex::decode(kp_json["secret_key"].as_str().unwrap())?;
            let secret_arr: [u8; 32] = secret_bytes.try_into().map_err(|_| "invalid key length")?;
            let kp = Keypair::from_bytes(&secret_arr);

            // Build attenuated warrant
            let mut builder = parent_warrant.attenuate();

            if let Some(ttl_secs) = ttl {
                builder = builder.ttl(Duration::from_secs(ttl_secs));
            }

            for c in constraint {
                let parts: Vec<&str> = c.splitn(2, '=').collect();
                if parts.len() != 2 {
                    return Err(format!("Invalid constraint format: {}", c).into());
                }
                builder = builder.constraint(parts[0], Pattern::new(parts[1])?);
            }

            let child = builder.build(&kp)?;
            println!("{}", wire::encode_base64(&child)?);
        }

        Commands::Inspect { warrant } => {
            let warrant_str = if warrant == "-" {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf)?;
                buf.trim().to_string()
            } else {
                warrant
            };

            let w = wire::decode_base64(&warrant_str)?;

            println!("Warrant Details");
            println!("===============");
            println!("ID:         {}", w.id());
            println!("Tool:       {}", w.tool());
            println!("Depth:      {}", w.depth());
            println!("Expires:    {}", w.expires_at());
            println!("Expired:    {}", w.is_expired());
            if let Some(parent) = w.parent_id() {
                println!("Parent ID:  {}", parent);
            }
            if let Some(session) = w.session_id() {
                println!("Session:    {}", session);
            }
            println!("Issuer:     {}", hex::encode(w.issuer().to_bytes()));
            println!();
            println!("Constraints:");
            for (field, constraint) in w.constraints().iter() {
                println!("  {}: {:?}", field, constraint);
            }
        }

        Commands::ExportPubkey { keypair, format } => {
            let kp_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(&keypair)?)?;
            let pubkey_hex = kp_json["public_key"].as_str().unwrap();

            match format.as_str() {
                "hex" => println!("{}", pubkey_hex),
                "base64" => {
                    let bytes = hex::decode(pubkey_hex)?;
                    println!("{}", base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &bytes
                    ));
                }
                "json" => {
                    println!("{}", serde_json::json!({ "public_key": pubkey_hex }));
                }
                _ => return Err(format!("Unknown format: {}", format).into()),
            }
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

