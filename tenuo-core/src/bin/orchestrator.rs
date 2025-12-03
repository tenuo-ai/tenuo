//! Orchestrator Agent Demo
//!
//! This demonstrates how an orchestrator agent:
//! 1. Receives a broad warrant from the Control Plane
//! 2. Attenuates it to create a narrower warrant for a worker
//! 3. Delegates the attenuated warrant via a chain

use tenuo_core::{ControlPlane, Keypair, Pattern, Exact, Range, wire};
use std::time::Duration;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    ORCHESTRATOR AGENT DEMO                       ║");
    println!("║          Demonstrating Capability Delegation in Tenuo            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // =========================================================================
    // Step 1: Simulate receiving a root warrant from the Control Plane
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 1: Receiving Root Warrant from Control Plane               │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let cp_key = env::var("TENUO_SECRET_KEY")
        .expect("TENUO_SECRET_KEY must be set (hex-encoded 32-byte key)");
    let cp_key_bytes: [u8; 32] = hex::decode(&cp_key)?
        .try_into()
        .map_err(|_| "Secret key must be 32 bytes")?;
    
    let cp_keypair = Keypair::from_bytes(&cp_key_bytes);
    let control_plane = ControlPlane::new(cp_keypair);

    println!("  Control Plane Public Key: {}", hex::encode(control_plane.public_key_bytes()));

    // The Control Plane issues a broad warrant for infrastructure management
    let root_warrant = control_plane.issue_warrant(
        "manage_infrastructure",
        &[
            ("cluster", Pattern::new("staging-*")?.into()),
            ("action", Pattern::new("*")?.into()),
            ("budget", Range::max(10000.0).into()),
        ],
        Duration::from_secs(3600), // 1 hour TTL
    )?;

    println!("\n  ✓ Root Warrant Received:");
    println!("    • ID:          {}", root_warrant.id());
    println!("    • Tool:        {}", root_warrant.tool());
    println!("    • Depth:       {} (root)", root_warrant.depth());
    println!("    • Expires:     {}", root_warrant.expires_at());
    println!("    • Constraints:");
    println!("      - cluster:   staging-*");
    println!("      - action:    * (any)");
    println!("      - budget:    ≤ $10,000");

    // =========================================================================
    // Step 2: Orchestrator creates its own identity
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Orchestrator Establishes Identity                       │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let orchestrator_keypair = Keypair::generate();
    println!("  Generated Orchestrator Keypair");
    println!("    Public Key: {}", hex::encode(orchestrator_keypair.public_key().to_bytes()));

    // Generate worker keypair (for PoP)
    let worker_keypair = Keypair::generate();
    println!("  Generated Worker Keypair (for PoP)");
    println!("    Public Key: {}", hex::encode(worker_keypair.public_key().to_bytes()));

    // Save worker key for the worker agent
    let worker_key_path = env::var("TENUO_WORKER_KEY_OUTPUT")
        .unwrap_or_else(|_| "/data/worker.key".to_string());
    std::fs::write(&worker_key_path, hex::encode(worker_keypair.secret_key_bytes()))?;
    println!("    Saved to: {}", worker_key_path);

    // =========================================================================
    // Step 3: Attenuate warrant for the Worker
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Attenuating Warrant for Worker                          │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Narrowing capabilities:");
    println!("    • cluster: staging-* → staging-web (exact)");
    println!("    • action:  *         → upgrade,restart (limited)");
    println!("    • budget:  ≤$10,000  → ≤$1,000 (reduced)");
    println!("    • TTL:     1 hour    → 10 minutes (shortened)");

    let worker_warrant = root_warrant.attenuate()
        .constraint("cluster", Exact::new("staging-web"))
        .constraint("action", Pattern::new("upgrade|restart")?)
        .constraint("budget", Range::max(1000.0))
        .ttl(Duration::from_secs(600)) // 10 minutes
        .authorized_holder(worker_keypair.public_key()) // PoP
        .agent_id("worker-agent-01") // Traceability
        .build(&orchestrator_keypair)?;

    println!("\n  ✓ Worker Warrant Created:");
    println!("    • ID:          {}", worker_warrant.id());
    println!("    • Parent ID:   {}", worker_warrant.parent_id().unwrap());
    println!("    • Depth:       {} (delegated)", worker_warrant.depth());
    println!("    • Expires:     {}", worker_warrant.expires_at());
    println!("    • Signed by:   Orchestrator");

    // =========================================================================
    // Step 4: Create and output the delegation chain
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Creating Delegation Chain                               │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let chain = vec![root_warrant.clone(), worker_warrant.clone()];
    
    println!("  Chain Structure:");
    println!("    ┌─────────────────────────────────────────────────────────────┐");
    println!("    │  [0] Root Warrant (Control Plane)                           │");
    println!("    │      └── cluster: staging-*, action: *, budget: ≤$10k       │");
    println!("    │              │                                              │");
    println!("    │              ▼  (attenuation)                               │");
    println!("    │  [1] Worker Warrant (Orchestrator)                          │");
    println!("    │      └── cluster: staging-web, action: upgrade|restart,     │");
    println!("    │          budget: ≤$1k                                       │");
    println!("    └─────────────────────────────────────────────────────────────┘");

    // Serialize the chain for the worker
    let chain_json = serde_json::to_string_pretty(&chain)?;
    
    let output_path = env::var("TENUO_CHAIN_OUTPUT")
        .unwrap_or_else(|_| "/data/chain.json".to_string());
    std::fs::write(&output_path, &chain_json)?;
    println!("\n  ✓ Chain written to: {}", output_path);

    // Also output the warrant in wire format (base64)
    let wire_format = wire::encode_base64(&worker_warrant)?;
    println!("\n  Worker Warrant (wire format, {} bytes):", wire_format.len());
    println!("    {}", &wire_format[..80.min(wire_format.len())]);
    if wire_format.len() > 80 {
        println!("    ... ({} more bytes)", wire_format.len() - 80);
    }

    // =========================================================================
    // Summary
    // =========================================================================
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     ORCHESTRATOR COMPLETE                        ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  The orchestrator has:                                           ║");
    println!("║  1. Received a broad warrant from the Control Plane              ║");
    println!("║  2. Created a narrower warrant for the Worker                    ║");
    println!("║  3. Signed the delegation with its own key                       ║");
    println!("║  4. Written the chain for the Worker to consume                  ║");
    println!("║                                                                  ║");
    println!("║  The Worker can now verify the chain and perform actions         ║");
    println!("║  within its constrained scope (staging-web only).                ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}
