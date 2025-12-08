//! Key Generation Utility
//!
//! Generates an Ed25519 keypair and outputs both keys in hex format.
//! Used for Identity-as-Config pattern demo setup.
//!
//! Usage:
//!   cargo run --bin keygen
//!   cargo run --bin keygen -- --name worker
//!
//! Output (to stdout):
//!   WORKER_PRIVATE_KEY=<hex>
//!   WORKER_PUBLIC_KEY=<hex>

use tenuo_core::Keypair;
use std::env;

fn main() {
    // Get optional name prefix from args
    let args: Vec<String> = env::args().collect();
    let name = if args.len() > 2 && args[1] == "--name" {
        args[2].to_uppercase()
    } else {
        "KEY".to_string()
    };

    // Generate keypair
    let keypair = Keypair::generate();
    
    // Output in shell-sourceable format
    println!("export {}_PRIVATE_KEY={}", name, hex::encode(keypair.secret_key_bytes()));
    println!("export {}_PUBLIC_KEY={}", name, hex::encode(keypair.public_key().to_bytes()));
}
