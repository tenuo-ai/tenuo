//! Worker Agent Demo
//!
//! This demonstrates how a worker agent:
//! 1. Receives a delegation chain from an orchestrator
//! 2. Verifies the complete chain back to a trusted root
//! 3. Attempts various actions (some allowed, some blocked)

use tenuo_core::{Authorizer, Warrant, PublicKey, ConstraintValue};
use std::env;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                       WORKER AGENT DEMO                          ║");
    println!("║          Demonstrating Chain Verification & Authorization        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // =========================================================================
    // Step 1: Setup the Authorizer with trusted public keys
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 1: Setting Up Authorizer (Data Plane)                      │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let trusted_key_hex = env::var("TENUO_TRUSTED_KEYS")
        .expect("TENUO_TRUSTED_KEYS must be set (Control Plane public key)");
    let trusted_key_bytes: [u8; 32] = hex::decode(&trusted_key_hex)?
        .try_into()
        .map_err(|_| "Trusted key must be 32 bytes")?;
    
    let trusted_key = PublicKey::from_bytes(&trusted_key_bytes)?;
    let authorizer = Authorizer::new(trusted_key);

    println!("  ✓ Authorizer configured with trusted root:");
    println!("    Public Key: {}", trusted_key_hex);
    println!("\n  NOTE: The worker only trusts the Control Plane's public key.");
    println!("        It does NOT need the Orchestrator's key - chain verification");
    println!("        cryptographically proves the delegation path.");

    // =========================================================================
    // Step 2: Wait for and load the delegation chain
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Loading Delegation Chain                                │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let input_path = env::var("TENUO_CHAIN_INPUT")
        .unwrap_or_else(|_| "/data/chain.json".to_string());
    
    println!("  Waiting for chain at: {}", input_path);

    let mut attempts = 0;
    let chain_json = loop {
        if Path::new(&input_path).exists() {
            break fs::read_to_string(&input_path)?;
        }
        attempts += 1;
        if attempts > 30 {
            eprintln!("  ✗ Timeout waiting for chain file");
            std::process::exit(1);
        }
        print!(".");
        thread::sleep(Duration::from_secs(1));
    };
    println!();

    let chain: Vec<Warrant> = serde_json::from_str(&chain_json)?;
    
    println!("\n  ✓ Chain loaded with {} warrant(s):", chain.len());
    for (i, warrant) in chain.iter().enumerate() {
        let signer = if i == 0 { "Control Plane" } else { "Orchestrator" };
        println!("    [{}] {} (depth={}, signed by {})", 
            i, warrant.id(), warrant.depth(), signer);
    }

    // =========================================================================
    // Step 3: Verify the complete delegation chain
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Verifying Chain (Cryptographic Proof of Authority)      │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Checking:");
    println!("    • Root warrant signed by trusted issuer");
    println!("    • Each delegation properly linked (parent_id matches)");
    println!("    • Constraints only narrow (never expand)");
    println!("    • Expiration times only shorten");
    println!("    • All signatures valid");

    match authorizer.verify_chain(&chain) {
        Ok(result) => {
            println!("\n  ✓ Chain verification PASSED");
            println!("    • Chain length:  {}", result.chain_length);
            println!("    • Leaf depth:    {}", result.leaf_depth);
            println!("    • Root issuer:   {}", hex::encode(result.root_issuer.unwrap()));
        }
        Err(e) => {
            eprintln!("\n  ✗ Chain verification FAILED: {}", e);
            std::process::exit(1);
        }
    }

    // =========================================================================
    // Step 4: Attempt various actions
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Attempting Actions (Authorization Tests)                │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let leaf_warrant = chain.last().unwrap();
    println!("\n  Leaf warrant constraints:");
    println!("    • cluster: staging-web (exact)");
    println!("    • action:  upgrade|restart");
    println!("    • budget:  ≤$1,000\n");

    // Test cases
    let test_cases = vec![
        // (name, tool, args, expected_allowed, explanation)
        (
            "Upgrade staging-web with $500 budget",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("staging-web".to_string())),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("budget", ConstraintValue::Float(500.0)),
            ],
            true,
            "Within all constraints",
        ),
        (
            "Restart staging-web",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("staging-web".to_string())),
                ("action", ConstraintValue::String("restart".to_string())),
                ("budget", ConstraintValue::Float(0.0)),
            ],
            true,
            "Restart is an allowed action",
        ),
        (
            "Upgrade staging-db (wrong cluster)",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("staging-db".to_string())),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("budget", ConstraintValue::Float(500.0)),
            ],
            false,
            "Blocked: only staging-web is allowed",
        ),
        (
            "Upgrade prod-web (production access)",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("prod-web".to_string())),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("budget", ConstraintValue::Float(500.0)),
            ],
            false,
            "Blocked: no production access",
        ),
        (
            "Delete staging-web (forbidden action)",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("staging-web".to_string())),
                ("action", ConstraintValue::String("delete".to_string())),
                ("budget", ConstraintValue::Float(0.0)),
            ],
            false,
            "Blocked: delete is not in allowed actions",
        ),
        (
            "Expensive upgrade ($5,000)",
            "manage_infrastructure",
            vec![
                ("cluster", ConstraintValue::String("staging-web".to_string())),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("budget", ConstraintValue::Float(5000.0)),
            ],
            false,
            "Blocked: exceeds $1,000 budget limit",
        ),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, tool, args_vec, expected, explanation) in test_cases {
        let args: HashMap<String, ConstraintValue> = args_vec.into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        
        let result = leaf_warrant.authorize(tool, &args);
        let allowed = result.is_ok();
        let status = if allowed == expected { "✓" } else { "✗" };
        let action_status = if allowed { "ALLOWED" } else { "BLOCKED" };
        
        if allowed == expected {
            passed += 1;
        } else {
            failed += 1;
        }
        
        println!("  {} {} → {}", status, name, action_status);
        println!("      {}", explanation);
        if !allowed {
            if let Err(e) = result {
                println!("      Reason: {}", e);
            }
        }
        println!();
    }

    // =========================================================================
    // Summary
    // =========================================================================
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                        WORKER COMPLETE                           ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Test Results: {} passed, {} failed                                ║", passed, failed);
    println!("║                                                                  ║");
    println!("║  Key Observations:                                               ║");
    println!("║  • Chain verification proves authority without network calls     ║");
    println!("║  • Constraints are enforced exactly as specified                 ║");
    println!("║  • Capability attenuation prevents privilege escalation          ║");
    println!("║  • The worker never needed the orchestrator's private key        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    if failed > 0 {
        std::process::exit(1);
    }
    
    Ok(())
}
