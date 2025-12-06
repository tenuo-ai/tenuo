//! Tenuo CLI - Development and debugging tool.
//!
//! Usage:
//!   tenuo dev              - Start local dev server
//!   tenuo keygen           - Generate a new keypair
//!   tenuo issue            - Issue a warrant
//!   tenuo verify           - Verify a warrant
//!   tenuo audit `<id>`     - Audit a warrant chain

use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use tenuo_core::{
    constraints::Pattern,
    crypto::Keypair,
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
    }

    Ok(())
}

