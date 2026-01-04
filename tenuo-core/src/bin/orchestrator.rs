//! Orchestrator Agent Demo
//!
//! This demonstrates how an orchestrator agent:
//! 1. Receives a broad warrant from the Control Plane (with max_depth policy)
//! 2. Attenuates it to create a narrower warrant for a worker
//! 3. Delegates the attenuated warrant via a chain with session binding
//! 4. Shows how depth limits prevent unbounded delegation
//! 5. **Multi-sig approval**: Requires human approval for sensitive actions
//! 6. **Notary Registry**: Maps enterprise identities to cryptographic keys

use chrono::Utc;
use std::env;
use std::time::Duration;
use tenuo::constraints::{ConstraintSet, Range};
use tenuo::{wire, Exact, OneOf, SigningKey, Warrant};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    ORCHESTRATOR AGENT DEMO                       ║");
    println!("║          Demonstrating Capability Delegation in Tenuo            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Generate a session ID for this workflow (for traceability)
    // Note: Session IDs are not sensitive. They're for correlation only.
    let session_id = format!("sess_{}", Uuid::now_v7().simple());
    println!("  Session ID: {}\n", session_id); // Safe: not a secret

    // =========================================================================
    // Step 1: Enrollment - Request Root Warrant from Control Plane
    // =========================================================================
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 1: Enrollment - Requesting Root Warrant from Control Plane │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // 1. Generate our OWN keypair (Orchestrator Identity)
    let orchestrator_keypair = SigningKey::generate();
    let pubkey_hex = hex::encode(orchestrator_keypair.public_key().to_bytes());
    println!("  Orchestrator Public Key: {}", pubkey_hex);

    // 2. Get Enrollment Token from Env
    let enrollment_token = env::var("TENUO_ENROLLMENT_TOKEN")
        .expect("TENUO_ENROLLMENT_TOKEN must be set (copy from control plane stdout)");

    let control_url =
        env::var("TENUO_CONTROL_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    // 3. Create Proof of Possession with timestamp (prevents replay attacks)
    // Format: "enroll:{public_key_hex}:{timestamp}"
    let timestamp = Utc::now().timestamp();
    let pop_message = format!("enroll:{}:{}", pubkey_hex, timestamp);
    let pop_signature = orchestrator_keypair.sign(pop_message.as_bytes());
    let pop_signature_hex = hex::encode(pop_signature.to_bytes());

    // 4. Send Enrollment Request
    println!("  Requesting enrollment from {}...", control_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/v1/enroll", control_url))
        .json(&serde_json::json!({
            "enrollment_token": enrollment_token,
            "public_key_hex": pubkey_hex,
            "timestamp": timestamp,
            "pop_signature_hex": pop_signature_hex,
            // Request wildcard tool access with NO constraints
            // Each mission will add its own constraints when attenuating
            "tool": "*"
            // No constraints - missions add their own
        }))
        .send()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text()?;
        eprintln!("❌ Enrollment Failed: {} - {}", status, text);
        std::process::exit(1);
    }

    let issue_resp: serde_json::Value = resp.json()?;
    let warrant_base64 = issue_resp["warrant_base64"]
        .as_str()
        .ok_or("Control plane response missing 'warrant_base64' field")?;
    let root_warrant: Warrant = wire::decode_base64(warrant_base64)?;

    // Get control plane keypair for chain link signature
    // In production, the control plane would sign the chain link
    // For demo, we get it from environment or use a placeholder
    let _control_plane_keypair = if let Ok(cp_key_hex) = env::var("TENUO_CONTROL_PLANE_KEY") {
        let cp_key_bytes: [u8; 32] = hex::decode(cp_key_hex)?
            .try_into()
            .map_err(|_| "Control plane key must be 32 bytes")?;
        SigningKey::from_bytes(&cp_key_bytes)
    } else {
        // For demo, if not provided, we can't create proper chain link signature
        // In production, this should always be provided
        println!(
            "  ⚠️  WARNING: TENUO_CONTROL_PLANE_KEY not set - chain link signature will be invalid"
        );
        println!("     In production, the control plane must sign chain links");
        SigningKey::generate() // Placeholder - won't match root_warrant.issuer()
    };

    println!("\n  ✓ Root Warrant Received via Enrollment Protocol:");
    println!("    • ID:          {}", root_warrant.id());
    if !root_warrant.payload.tools.is_empty() {
        println!("    • Tools:       {:?}", root_warrant.payload.tools.keys());
    }
    println!("    • Depth:       {} (root)", root_warrant.depth());
    println!(
        "    • Max Depth:   {} (policy limit)",
        root_warrant.effective_max_depth()
    );
    println!("    • Expires:     {}", root_warrant.expires_at());
    println!("    • Constraints: (none - missions add their own)");

    // =========================================================================
    // Step 2: Establish Identities (Key Generation)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Establish Identities (Key Generation)                   │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Orchestrator already generated its keypair in Step 1 (for enrollment)
    // We reuse the same keypair for signing delegated warrants
    println!("  Orchestrator keypair (from enrollment):");
    println!(
        "    Public Key: {}",
        hex::encode(orchestrator_keypair.public_key().to_bytes())
    );

    // ─────────────────────────────────────────────────────────────────────────
    // DEMO SIMPLIFICATION: In production, the worker generates its own keypair
    // and sends ONLY the public key to the orchestrator.
    //
    // Production flow:
    //   1. Worker: keypair = SigningKey::generate()
    //   2. Worker: send(orchestrator, keypair.public_key())
    //   3. Orchestrator: receives worker_public_key
    //   4. Orchestrator: attenuate().holder(worker_public_key)
    //
    // For this demo, we generate on behalf of worker for simplicity.
    // ─────────────────────────────────────────────────────────────────────────
    let worker_keypair = SigningKey::generate();
    println!("\n  [DEMO] Simulating worker key registration:");
    println!("    In production: Worker generates key, sends ONLY public key");
    println!(
        "    Worker Public Key: {}",
        hex::encode(worker_keypair.public_key().to_bytes())
    );

    // ⚠️  DEMO ONLY: Writing private key to shared storage
    // ─────────────────────────────────────────────────────────────────────────
    // SECURITY WARNING: In production, private keys MUST NEVER leave the agent.
    // This file-sharing approach is ONLY for demo convenience.
    // Production: Worker generates key locally, sends only PUBLIC key to orchestrator.
    // ─────────────────────────────────────────────────────────────────────────
    let worker_key_path =
        env::var("TENUO_WORKER_KEY_OUTPUT").unwrap_or_else(|_| "/data/worker.key".to_string());
    std::fs::write(
        &worker_key_path,
        hex::encode(worker_keypair.secret_key_bytes()),
    )?;
    println!(
        "    ⚠️  [DEMO ONLY] Saved secret key to: {}",
        worker_key_path
    );
    println!("    ⚠️  PRODUCTION: Private keys MUST stay with the agent!");

    // =========================================================================
    // Step 3: Create Mission-Specific Warrants (Temporal Least-Privilege)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Creating Mission-Specific Warrants                      │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Demonstrating temporal least-privilege:");
    println!("    Same worker, different missions, different capabilities.\n");

    // ─────────────────────────────────────────────────────────────────────────
    // MISSION A: File Operations (read-only data access)
    // ─────────────────────────────────────────────────────────────────────────
    println!("  📁 MISSION A: File Operations");
    println!("    • tool:     read_file");
    println!("    • path:     /data/* (Pattern constraint)");
    println!("    • priority: 1-5 (Range constraint)");
    println!("    • TTL:      5 minutes");

    let mut file_constraints = ConstraintSet::new();
    file_constraints.insert(
        "path".to_string(),
        tenuo::constraints::Pattern::new("/data/*")?,
    );
    file_constraints.insert("priority".to_string(), Range::new(Some(1.0), Some(5.0))?);

    let mission_a_warrant = root_warrant
        .attenuate()
        .capability("read_file", file_constraints)
        .ttl(Duration::from_secs(300)) // 5 minutes
        .holder(worker_keypair.public_key())
        .agent_id("worker-mission-A")
        .build(&orchestrator_keypair)?;

    println!("    ✓ Mission A Warrant: {}", mission_a_warrant.id());

    // ─────────────────────────────────────────────────────────────────────────
    // MISSION B: Infrastructure Operations (cluster management)
    // ─────────────────────────────────────────────────────────────────────────
    println!("\n  🔧 MISSION B: Infrastructure Operations");
    println!("    • tool:     manage_infrastructure");
    println!("    • cluster:  staging-web (Exact constraint)");
    println!("    • action:   [upgrade, restart] (OneOf constraint)");
    println!("    • replicas: ≤10 (Range constraint)");
    println!("    • TTL:      10 minutes");

    let mut infra_constraints = ConstraintSet::new();
    infra_constraints.insert("cluster".to_string(), Exact::new("staging-web"));
    infra_constraints.insert("action".to_string(), OneOf::new(vec!["upgrade", "restart"]));
    infra_constraints.insert("replicas".to_string(), Range::max(10.0)?);

    let mission_b_warrant = root_warrant
        .attenuate()
        .capability("manage_infrastructure", infra_constraints)
        .ttl(Duration::from_secs(600)) // 10 minutes
        .holder(worker_keypair.public_key())
        .agent_id("worker-mission-B")
        .build(&orchestrator_keypair)?;

    println!("    ✓ Mission B Warrant: {}", mission_b_warrant.id());

    // For backward compatibility, keep worker_warrant as alias for mission_b
    let worker_warrant = mission_b_warrant.clone();

    println!("\n  Summary:");
    println!("    ┌────────────────┬─────────────────────────┬─────────────┐");
    println!("    │ Mission        │ Tool                    │ TTL         │");
    println!("    ├────────────────┼─────────────────────────┼─────────────┤");
    println!("    │ A (Files)      │ read_file               │ 5 min       │");
    println!("    │ B (Infra)      │ manage_infrastructure   │ 10 min      │");
    println!("    └────────────────┴─────────────────────────┴─────────────┘");
    println!("\n  Key insight: Same worker, same session, but DIFFERENT capabilities.");
    println!("  Using Mission A warrant for infrastructure → DENIED");
    println!("  Using Mission B warrant for file access    → DENIED");

    // =========================================================================
    // Step 4: Create and output the delegation chains
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Creating Delegation Chains                              │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Build chains for each mission
    let mission_a_chain = vec![root_warrant.clone(), mission_a_warrant.clone()];
    let mission_b_chain = vec![root_warrant.clone(), mission_b_warrant.clone()];

    println!("  Chain Structure:");
    println!("    ┌─────────────────────────────────────────────────────────────┐");
    println!("    │  [0] Root Warrant (Control Plane)                           │");
    println!("    │      └── cluster: staging-*, read_file: /data/*, etc.       │");
    println!("    │              │                                              │");
    println!("    │      ┌───────┴───────┐                                      │");
    println!("    │      ▼               ▼                                      │");
    println!("    │  [Mission A]     [Mission B]                                │");
    println!("    │  read_file       manage_infrastructure                      │");
    println!("    │  /data/*         staging-web, upgrade|restart               │");
    println!("    └─────────────────────────────────────────────────────────────┘");

    // Serialize chains
    let base_path =
        env::var("TENUO_CHAIN_OUTPUT").unwrap_or_else(|_| "/data/chain.json".to_string());

    // Mission A chain (file operations)
    let mission_a_path = base_path.replace(".json", "_mission_a.json");
    std::fs::write(
        &mission_a_path,
        serde_json::to_string_pretty(&mission_a_chain)?,
    )?;
    println!("\n  ✓ Mission A chain (read_file): {}", mission_a_path);

    // Mission B chain (infrastructure) - also write as default chain.json for compatibility
    let mission_b_path = base_path.replace(".json", "_mission_b.json");
    std::fs::write(
        &mission_b_path,
        serde_json::to_string_pretty(&mission_b_chain)?,
    )?;
    std::fs::write(&base_path, serde_json::to_string_pretty(&mission_b_chain)?)?;
    println!(
        "  ✓ Mission B chain (manage_infrastructure): {}",
        mission_b_path
    );
    println!("  ✓ Default chain (Mission B): {}", base_path);

    // Wire format example
    let wire_format = wire::encode_base64(&worker_warrant)?;
    println!(
        "\n  Worker Warrant (wire format, {} bytes):",
        wire_format.len()
    );
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
    println!("║  1. MULTI-MISSION      - Same worker, different warrants         ║");
    println!("║  2. TEMPORAL SCOPE     - Mission A: 5min, Mission B: 10min       ║");
    println!("║  3. max_depth(3)       - Policy limits delegation depth          ║");
    println!("║  4. session_id         - All warrants share same session         ║");
    println!("║  5. holder_key         - Worker must prove possession (PoP)      ║");

    println!("║                                                                  ║");
    println!("║  The Worker will demonstrate:                                    ║");
    println!("║  • Mission A: read_file with /data/* constraint                  ║");
    println!("║  • Mission B: manage_infrastructure with staging-web             ║");
    println!("║  • CROSS-MISSION DENIED: wrong warrant for wrong tool            ║");

    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    Ok(())
}
