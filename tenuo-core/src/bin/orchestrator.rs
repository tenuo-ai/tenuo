//! Orchestrator Agent Demo
//!
//! This demonstrates how an orchestrator agent:
//! 1. Receives a broad warrant from the Control Plane (with max_depth policy)
//! 2. Attenuates it to create a narrower warrant for a worker
//! 3. Delegates the attenuated warrant via a chain with session binding
//! 4. Shows how depth limits prevent unbounded delegation
//! 5. **Multi-sig approval**: Requires human approval for sensitive actions
//! 6. **Notary Registry**: Maps enterprise identities to cryptographic keys

use tenuo_core::{Keypair, PublicKey, Exact, Range, Warrant, wire, OneOf};
use std::time::Duration;
use std::env;
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    ORCHESTRATOR AGENT DEMO                       ║");
    println!("║          Demonstrating Capability Delegation in Tenuo            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Generate a session ID for this workflow (for traceability)
    let session_id = format!("sess_{}", Uuid::now_v7().simple());
    println!("  Session ID: {}\n", session_id);

    // =========================================================================
    // Step 1: Enrollment - Request Root Warrant from Control Plane
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 1: Enrollment - Requesting Root Warrant from Control Plane │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // 1. Generate our OWN keypair (Orchestrator Identity)
    let orchestrator_keypair = Keypair::generate();
    let pubkey_hex = hex::encode(orchestrator_keypair.public_key().to_bytes());
    println!("  Orchestrator Public Key: {}", pubkey_hex);

    // 2. Get Enrollment Token from Env
    let enrollment_token = env::var("TENUO_ENROLLMENT_TOKEN")
        .expect("TENUO_ENROLLMENT_TOKEN must be set (copy from control plane stdout)");
    
    let control_url = env::var("TENUO_CONTROL_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    // 3. Create Proof of Possession with timestamp (prevents replay attacks)
    // Format: "tenuo:enroll:v1:{public_key_hex}:{timestamp}"
    // IMPORTANT: We SHA-256 hash the message to get a fixed 32-byte input.
    // This is coordinated with the Python SDK and Rust verifier.
    // Ed25519 will then internally hash again (SHA-512), giving us:
    // Ed25519(SHA-512(SHA-256(message))) - this is perfectly secure.
    let timestamp = Utc::now().timestamp();
    let pop_message = format!("tenuo:enroll:v1:{}:{}", pubkey_hex, timestamp);
    let pop_message_hash = Sha256::digest(pop_message.as_bytes());
    let pop_signature = orchestrator_keypair.sign(&pop_message_hash);
    let pop_signature_hex = hex::encode(pop_signature.to_bytes());

    // 4. Send Enrollment Request
    println!("  Requesting enrollment from {}...", control_url);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(format!("{}/v1/enroll", control_url))
        .json(&serde_json::json!({
            "enrollment_token": enrollment_token,
            "public_key_hex": pubkey_hex,
            "timestamp": timestamp,
            "pop_signature_hex": pop_signature_hex
        }))
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text()?;
        eprintln!("❌ Enrollment Failed: {} - {}", status, text);
        std::process::exit(1);
    }

    let issue_resp: serde_json::Value = resp.json()?;
    let warrant_base64 = issue_resp["warrant_base64"].as_str().unwrap();
    let root_warrant: Warrant = wire::decode_base64(warrant_base64)?;

    println!("\n  ✓ Root Warrant Received via Enrollment Protocol:");
    println!("    • ID:          {}", root_warrant.id());
    println!("    • Tool:        {}", root_warrant.tool());
    println!("    • Depth:       {} (root)", root_warrant.depth());
    println!("    • Max Depth:   {} (policy limit)", root_warrant.effective_max_depth());
    println!("    • Expires:     {}", root_warrant.expires_at());
    println!("    • Constraints:");
    println!("      - cluster:   staging-*");
    println!("      - action:    * (Wildcard)");
    println!("      - budget:    ≤ $10,000");

    // =========================================================================
    // Step 2: Load Worker Identity (Identity-as-Config Pattern)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Load Worker Identity (Identity-as-Config)               │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Orchestrator already generated its keypair in Step 1 (for enrollment)
    // We reuse the same keypair for signing delegated warrants
    println!("  Orchestrator keypair (from enrollment):");
    println!("    Public Key: {}", hex::encode(orchestrator_keypair.public_key().to_bytes()));

    // ─────────────────────────────────────────────────────────────────────────
    // IDENTITY-AS-CONFIG PATTERN (Production Best Practice)
    // ─────────────────────────────────────────────────────────────────────────
    // In production (Kubernetes), worker identities are wired at deploy time:
    //   - Worker gets WORKER_PRIVATE_KEY from K8s Secret
    //   - Orchestrator gets WORKER_PUBLIC_KEY from same Secret
    //
    // This is "Identity-as-Config" - static wiring via Terraform/Helm.
    // The orchestrator knows the worker's public key at startup, not runtime.
    // ─────────────────────────────────────────────────────────────────────────
    let worker_pubkey_hex = env::var("WORKER_PUBLIC_KEY")
        .expect("WORKER_PUBLIC_KEY must be set (from K8s Secret or demo script)");
    let worker_pubkey_bytes: [u8; 32] = hex::decode(&worker_pubkey_hex)?
        .try_into()
        .map_err(|_| "WORKER_PUBLIC_KEY must be 32 bytes hex")?;
    let worker_public_key = PublicKey::from_bytes(&worker_pubkey_bytes)?;
    
    println!("\n  Worker identity loaded from environment:");
    println!("    Public Key: {}", worker_pubkey_hex);
    println!("    ✓ Identity-as-Config: Static wiring at deploy time");
    println!("    ✓ Private key stays with Worker (never shared)");

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
        .authorized_holder(worker_public_key.clone()) // PoP-bound to Worker's static identity
        .agent_id("worker-agent-01") // Traceability
        // Session ID is inherited from parent automatically
        .build(&orchestrator_keypair)?;

    println!("\n  ✓ Worker Warrant Created:");
    println!("    • ID:          {}", worker_warrant.id());
    println!("    • Parent ID:   {}", worker_warrant.parent_id().unwrap());
    println!("    • Depth:       {} / {} (delegated)", worker_warrant.depth(), worker_warrant.effective_max_depth());
    println!("    • Session:     {} (inherited)", worker_warrant.session_id().unwrap_or("-"));
    println!("    • Expires:     {}", worker_warrant.expires_at());
    println!("    • Holder:      {} (PoP required)", &worker_pubkey_hex[..16]);
    println!("    • Signed by:   Orchestrator");

    // =========================================================================
    // Step 4: Multi-Sig Warrant (Sensitive Actions with Human Approval)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Creating Multi-Sig Warrant (Human Approval Required)    │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  For sensitive actions (delete, scale-down), we require human approval.");
    println!("  This is enforced via multi-sig: the warrant lists required approvers.\n");

    // ─────────────────────────────────────────────────────────────────────────
    // ADMIN IDENTITY (Identity-as-Config Pattern)
    // ─────────────────────────────────────────────────────────────────────────
    // In production, admin public keys come from:
    //   - Enterprise identity provider (via Notary Registry)
    //   - K8s ConfigMap/Secret
    //   - Terraform/Helm configuration
    //
    // The admin's PRIVATE key is managed by the admin themselves (HSM, Yubikey).
    // Only the PUBLIC key is shared with systems that need to verify approvals.
    // ─────────────────────────────────────────────────────────────────────────
    let admin_pubkey_hex = env::var("ADMIN_PUBLIC_KEY")
        .expect("ADMIN_PUBLIC_KEY must be set (from K8s Secret or demo script)");
    let admin_pubkey_bytes: [u8; 32] = hex::decode(&admin_pubkey_hex)?
        .try_into()
        .map_err(|_| "ADMIN_PUBLIC_KEY must be 32 bytes hex")?;
    let admin_public_key = PublicKey::from_bytes(&admin_pubkey_bytes)?;
    
    println!("  Admin identity loaded from environment:");
    println!("    • Public Key: {}", &admin_pubkey_hex[..32]);
    println!("    • External ID: arn:aws:iam::123456789:user/admin (simulated)");
    println!("    ✓ Private key managed by Admin (HSM/Yubikey)");

    // Create a warrant for sensitive operations that REQUIRES multi-sig approval
    let sensitive_warrant = root_warrant.attenuate()
        .constraint("cluster", Exact::new("staging-web"))
        .constraint("action", OneOf::new(vec!["delete", "scale-down"]))  // Dangerous actions
        .constraint("budget", Range::max(500.0))
        .ttl(Duration::from_secs(300)) // 5 minutes (short for sensitive ops)
        .authorized_holder(worker_public_key) // PoP-bound to Worker
        .agent_id("worker-agent-01-sensitive")
        // MULTI-SIG: Require 1-of-1 approval from the admin
        .add_approvers(vec![admin_public_key])
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
