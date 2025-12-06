//! Orchestrator Agent Demo
//!
//! This demonstrates how an orchestrator agent:
//! 1. Receives a broad warrant from the Control Plane (with max_depth policy)
//! 2. Attenuates it to create a narrower warrant for a worker
//! 3. Delegates the attenuated warrant via a chain with session binding
//! 4. Shows how depth limits prevent unbounded delegation
//! 5. **Multi-sig approval**: Requires human approval for sensitive actions
//! 6. **Notary Registry**: Maps enterprise identities to cryptographic keys

use tenuo_core::{Keypair, Pattern, Exact, Range, Warrant, wire, OneOf, Wildcard};
use std::time::Duration;
use std::env;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    ORCHESTRATOR AGENT DEMO                       ║");
    println!("║          Demonstrating Capability Delegation in Tenuo            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Generate a session ID for this workflow (for traceability)
    let session_id = format!("sess_{}", Uuid::now_v7().simple());
    println!("  Session ID: {}\n", session_id);

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

    println!("  Control Plane Public Key: {}", hex::encode(cp_keypair.public_key().to_bytes()));

    // The Control Plane issues a broad warrant with POLICY LIMITS
    // action uses Wildcard - can be attenuated to any constraint type
    let root_warrant = Warrant::builder()
        .tool("manage_infrastructure")
        .constraint("cluster", Pattern::new("staging-*")?)
        .constraint("action", Wildcard::new())  // Wildcard: can narrow to anything
        .constraint("budget", Range::max(10000.0))
        .ttl(Duration::from_secs(3600))
        .max_depth(3)                          // POLICY: Only 3 levels of delegation allowed!
        .session_id(session_id.clone())        // Session binding for traceability
        .agent_id("orchestrator-main")         // Agent ID for audit
        .build(&cp_keypair)?;

    println!("\n  ✓ Root Warrant Received:");
    println!("    • ID:          {}", root_warrant.id());
    println!("    • Tool:        {}", root_warrant.tool());
    println!("    • Depth:       {} (root)", root_warrant.depth());
    println!("    • Max Depth:   {} (policy limit)", root_warrant.effective_max_depth());
    println!("    • Session:     {}", root_warrant.session_id().unwrap_or("-"));
    println!("    • Expires:     {}", root_warrant.expires_at());
    println!("    • Constraints:");
    println!("      - cluster:   staging-*");
    println!("      - action:    * (Wildcard)");
    println!("      - budget:    ≤ $10,000");

    // =========================================================================
    // Step 2: Establish Identities (Key Generation)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Establish Identities (Key Generation)                   │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Orchestrator generates its OWN keypair locally
    let orchestrator_keypair = Keypair::generate();
    println!("  Orchestrator generates its own keypair:");
    println!("    Public Key: {}", hex::encode(orchestrator_keypair.public_key().to_bytes()));

    // ─────────────────────────────────────────────────────────────────────────
    // DEMO SIMPLIFICATION: In production, the worker generates its own keypair
    // and sends ONLY the public key to the orchestrator.
    //
    // Production flow:
    //   1. Worker: keypair = Keypair::generate()
    //   2. Worker: send(orchestrator, keypair.public_key())
    //   3. Orchestrator: receives worker_public_key
    //   4. Orchestrator: attenuate().authorized_holder(worker_public_key)
    //
    // For this demo, we generate on behalf of worker for simplicity.
    // ─────────────────────────────────────────────────────────────────────────
    let worker_keypair = Keypair::generate();
    println!("\n  [DEMO] Simulating worker key registration:");
    println!("    In production: Worker generates key, sends ONLY public key");
    println!("    Worker Public Key: {}", hex::encode(worker_keypair.public_key().to_bytes()));

    // Save worker SECRET key for demo (PRODUCTION: worker keeps this locally!)
    let worker_key_path = env::var("TENUO_WORKER_KEY_OUTPUT")
        .unwrap_or_else(|_| "/data/worker.key".to_string());
    std::fs::write(&worker_key_path, hex::encode(worker_keypair.secret_key_bytes()))?;
    println!("    [DEMO] Saved secret key to: {} (production: NEVER shared!)", worker_key_path);

    // =========================================================================
    // Step 3: Attenuate warrant for the Worker
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Attenuating Warrant for Worker                          │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Narrowing capabilities:");
    println!("    • cluster: staging-*  → staging-web (exact)");
    println!("    • action:  * (any)    → [upgrade, restart] (OneOf)");
    println!("    • budget:  ≤$10,000   → ≤$1,000 (reduced)");
    println!("    • TTL:     1 hour     → 10 minutes (shortened)");

    let worker_warrant = root_warrant.attenuate()
        .constraint("cluster", Exact::new("staging-web"))
        .constraint("action", OneOf::new(vec!["upgrade", "restart"]))
        .constraint("budget", Range::max(1000.0))
        .ttl(Duration::from_secs(600)) // 10 minutes
        .authorized_holder(worker_keypair.public_key()) // PoP
        .agent_id("worker-agent-01") // Traceability
        // Session ID is inherited from parent automatically
        .build(&orchestrator_keypair)?;

    println!("\n  ✓ Worker Warrant Created:");
    println!("    • ID:          {}", worker_warrant.id());
    println!("    • Parent ID:   {}", worker_warrant.parent_id().unwrap());
    println!("    • Depth:       {} / {} (delegated)", worker_warrant.depth(), worker_warrant.effective_max_depth());
    println!("    • Session:     {} (inherited)", worker_warrant.session_id().unwrap_or("-"));
    println!("    • Expires:     {}", worker_warrant.expires_at());
    println!("    • Holder:      {} (PoP required)", hex::encode(&worker_keypair.public_key().to_bytes()[..8]));
    println!("    • Signed by:   Orchestrator");

    // =========================================================================
    // Step 4: Multi-Sig Warrant (Sensitive Actions with Human Approval)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Creating Multi-Sig Warrant (Human Approval Required)    │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  For sensitive actions (delete, scale-down), we require human approval.");
    println!("  This is enforced via multi-sig: the warrant lists required approvers.\n");

    // Create an "approver" keypair (simulates an admin mapped via Notary Registry)
    let admin_keypair = Keypair::generate();
    println!("  Generated Admin Keypair (simulating Notary-bound identity):");
    println!("    • Public Key: {}", hex::encode(&admin_keypair.public_key().to_bytes()[..16]));
    println!("    • External ID: arn:aws:iam::123456789:user/admin (simulated)\n");

    // Save admin key for the worker demo
    let admin_key_path = env::var("TENUO_ADMIN_KEY_OUTPUT")
        .unwrap_or_else(|_| "/data/admin.key".to_string());
    std::fs::write(&admin_key_path, hex::encode(admin_keypair.secret_key_bytes()))?;
    println!("    Saved admin key to: {}", admin_key_path);

    // Create a warrant for sensitive operations that REQUIRES multi-sig approval
    let sensitive_warrant = root_warrant.attenuate()
        .constraint("cluster", Exact::new("staging-web"))
        .constraint("action", OneOf::new(vec!["delete", "scale-down"]))  // Dangerous actions
        .constraint("budget", Range::max(500.0))
        .ttl(Duration::from_secs(300)) // 5 minutes (short for sensitive ops)
        .authorized_holder(worker_keypair.public_key())
        .agent_id("worker-agent-01-sensitive")
        // MULTI-SIG: Require 1-of-1 approval from the admin
        .add_approvers(vec![admin_keypair.public_key()])
        .raise_min_approvals(1)
        .build(&orchestrator_keypair)?;

    println!("\n  ✓ Multi-Sig Warrant Created:");
    println!("    • ID:          {}", sensitive_warrant.id());
    println!("    • Actions:     [delete, scale-down] (dangerous!)");
    println!("    • Budget:      ≤$500");
    println!("    • Approvers:   1 (admin required)");
    println!("    • Threshold:   1-of-1");
    println!("    • TTL:         5 minutes (short-lived for safety)");

    // =========================================================================
    // Step 5: Create and output the delegation chain
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 5: Creating Delegation Chain                               │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let chain = vec![root_warrant.clone(), worker_warrant.clone()];
    let sensitive_chain = vec![root_warrant.clone(), sensitive_warrant.clone()];
    
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

    // Serialize the chains for the worker
    let chain_json = serde_json::to_string_pretty(&chain)?;
    let sensitive_chain_json = serde_json::to_string_pretty(&sensitive_chain)?;
    
    let output_path = env::var("TENUO_CHAIN_OUTPUT")
        .unwrap_or_else(|_| "/data/chain.json".to_string());
    std::fs::write(&output_path, &chain_json)?;
    println!("\n  ✓ Standard chain written to: {}", output_path);

    let sensitive_output_path = output_path.replace(".json", "_sensitive.json");
    std::fs::write(&sensitive_output_path, &sensitive_chain_json)?;
    println!("  ✓ Sensitive chain written to: {}", sensitive_output_path);

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
    println!("║  Features Demonstrated:                                          ║");
    println!("║  1. max_depth(3)       - Policy limits delegation depth          ║");
    println!("║  2. session_id         - Warrants share same session             ║");
    println!("║  3. agent_id           - Agents are identifiable for audit       ║");
    println!("║  4. holder_key         - Worker must prove possession (PoP)      ║");
    println!("║  5. MULTI-SIG          - 1-of-1 admin approval for delete!       ║");
    println!("║                                                                  ║");
    println!("║  The Worker will demonstrate:                                    ║");
    println!("║  • Standard actions (upgrade/restart) → no approval needed       ║");
    println!("║  • Sensitive actions (delete) → BLOCKED without approval         ║");
    println!("║  • Sensitive actions (delete) → ALLOWED with admin approval      ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}
