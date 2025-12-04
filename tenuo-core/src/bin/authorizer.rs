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
//! tenuo-authorizer serve --port 9090
//! ```
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
use tenuo_core::{
    constraints::ConstraintValue,
    planes::Authorizer,
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

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Build authorizer from trusted keys
    let authorizer = build_authorizer(&cli.trusted_keys)?;

    match cli.command {
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
                "exit-code" => {
                    if result.is_ok() {
                        std::process::exit(0);
                    } else {
                        eprintln!("Authorization failed: {}", result.unwrap_err());
                        std::process::exit(1);
                    }
                }
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
                    println!("  Tool: {}", w.tool());
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
        }
    }

    Ok(())
}

fn build_authorizer(trusted_keys: &Option<String>) -> Result<Authorizer, Box<dyn std::error::Error>> {
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

    let mut authorizer = Authorizer::new(first_key);

    // Add remaining keys
    if let Some(keys) = trusted_keys {
        for key_hex in keys.split(',').skip(1) {
            if !key_hex.is_empty() {
                let bytes = hex::decode(key_hex)?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| "invalid key length")?;
                authorizer.add_trusted_key(PublicKey::from_bytes(&arr)?);
            }
        }
    }

    Ok(authorizer)
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

