//! Worker Agent Demo
//!
//! This demonstrates how a worker agent:
//! 1. Receives a delegation chain from an orchestrator
//! 2. Verifies the complete chain back to a trusted root
//! 3. Attempts various actions (some allowed, some blocked)
//! 4. Delegates to a sub-agent (showing depth limits)
//! 5. Tries to exceed max_depth (shows error)
//! 6. **Multi-sig approval** for sensitive actions

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
use tenuo_core::approval::{compute_request_hash, Approval};
use tenuo_core::{Authorizer, ConstraintValue, Keypair, PublicKey, Range, Warrant};

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

    let input_path =
        env::var("TENUO_CHAIN_INPUT").unwrap_or_else(|_| "/data/chain.json".to_string());

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
        let signer = if i == 0 {
            "Control Plane"
        } else {
            "Orchestrator"
        };
        println!(
            "    [{}] {} (depth={}/{}, signed by {})",
            i,
            warrant.id(),
            warrant.depth(),
            warrant.effective_max_depth(),
            signer
        );
        if let Some(session) = warrant.session_id() {
            println!("        session: {}", session);
        }
    }

    // =========================================================================
    // Step 2b: Worker Keypair (for Proof-of-Possession)
    // =========================================================================
    // ─────────────────────────────────────────────────────────────────────────
    // PRODUCTION PATTERN:
    //   1. Worker generates its own keypair: keypair = Keypair::generate()
    //   2. Worker sends ONLY public key to orchestrator
    //   3. Worker keeps private key locally (NEVER shared)
    //
    // DEMO SIMPLIFICATION:
    //   For this demo, we load a pre-generated key from the orchestrator.
    //   This simulates the case where the worker already has its key.
    // ─────────────────────────────────────────────────────────────────────────
    let worker_key_path =
        env::var("TENUO_WORKER_KEY_INPUT").unwrap_or_else(|_| "/data/worker.key".to_string());

    println!(
        "\n  ⚠️  [DEMO ONLY] Loading pre-shared keypair from: {}",
        worker_key_path
    );
    println!("    PRODUCTION: Worker generates key locally with Keypair::generate()");
    println!("    PRODUCTION: Only PUBLIC key is sent to orchestrator");

    // Simple wait loop (similar to chain)
    let worker_key_hex = loop {
        if Path::new(&worker_key_path).exists() {
            break fs::read_to_string(&worker_key_path)?;
        }
        thread::sleep(Duration::from_secs(1));
    };
    let worker_key_bytes: [u8; 32] = hex::decode(worker_key_hex.trim())?
        .try_into()
        .map_err(|_| "Worker key must be 32 bytes")?;
    let worker_keypair = Keypair::from_bytes(&worker_key_bytes);
    println!("  ✓ Worker keypair ready (private key for PoP signing)");

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
    println!("    • Depth within max_depth limit");
    println!("    • All signatures valid");

    let start = Instant::now();
    match authorizer.verify_chain(&chain) {
        Ok(result) => {
            let elapsed = start.elapsed();
            println!("\n  ✓ Chain verification PASSED ({:.0?})", elapsed);
            println!("    • Chain length:  {}", result.chain_length);
            println!("    • Leaf depth:    {}", result.leaf_depth);
            println!(
                "    • Root issuer:   {}",
                hex::encode(result.root_issuer.unwrap())
            );
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
    println!("    • action:  [upgrade, restart] (OneOf)");
    println!("    • budget:  ≤$1,000\n");

    // Test cases
    let test_cases = vec![
        // (name, tool, args, expected_allowed, explanation)
        (
            "Upgrade staging-web with $500 budget",
            "manage_infrastructure",
            vec![
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
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
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
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
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
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
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("budget", ConstraintValue::Float(5000.0)),
            ],
            false,
            "Blocked: exceeds $1,000 budget limit",
        ),
    ];

    let mut passed = 0;
    let mut failed = 0;
    let mut allowed_time = Duration::ZERO;
    let mut allowed_count = 0u32;
    let mut blocked_time = Duration::ZERO;
    let mut blocked_count = 0u32;

    for (name, tool, args_vec, expected, explanation) in test_cases {
        let args: HashMap<String, ConstraintValue> = args_vec
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();

        // Sign the request (Proof-of-Possession)
        let signature = leaf_warrant.create_pop_signature(&worker_keypair, tool, &args)?;

        let start = Instant::now();
        let result = leaf_warrant.authorize(tool, &args, Some(&signature));
        let elapsed = start.elapsed();

        let allowed = result.is_ok();
        if allowed {
            allowed_time += elapsed;
            allowed_count += 1;
        } else {
            blocked_time += elapsed;
            blocked_count += 1;
        }

        let status = if allowed == expected { "✓" } else { "✗" };
        let action_status = if allowed { "ALLOWED" } else { "BLOCKED" };

        if allowed == expected {
            passed += 1;
        } else {
            failed += 1;
        }

        println!(
            "  {} {} → {} ({:.0?})",
            status, name, action_status, elapsed
        );
        println!("      {}", explanation);
        if !allowed {
            if let Err(e) = result {
                println!("      Reason: {}", e);
            }
        }
        println!();
    }

    println!("  ───────────────────────────────────────────────────────────────");
    println!("  Performance Metrics:");
    if allowed_count > 0 {
        let avg_allowed = allowed_time / allowed_count;
        println!(
            "    • Allowed: ~{:.0?} avg (full verification)",
            avg_allowed
        );
    }
    if blocked_count > 0 {
        let avg_blocked = blocked_time / blocked_count;
        println!("    • Blocked: ~{:.0?} avg (short-circuit)", avg_blocked);
    }
    println!("  ───────────────────────────────────────────────────────────────");

    // =========================================================================
    // Step 5: Demonstrate delegation depth limits (max_depth)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 5: Demonstrating Depth Limits (max_depth Policy)           │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let leaf_warrant = chain.last().unwrap();
    println!(
        "\n  Current depth: {} / {}",
        leaf_warrant.depth(),
        leaf_warrant.effective_max_depth()
    );

    // Worker can create sub-agent warrants up to max_depth
    let sub_agent_keypair = Keypair::generate();

    // Try to create depth 2 warrant (should work if max_depth >= 2)
    println!(
        "\n  Attempting to delegate to Sub-Agent (depth {})...",
        leaf_warrant.depth() + 1
    );

    // Get orchestrator keypair for chain link signature
    // In production, the orchestrator (parent issuer) would sign the chain link
    // For demo, we get it from environment or use a placeholder
    let orchestrator_keypair = if let Ok(orch_key_hex) = env::var("TENUO_ORCHESTRATOR_KEY") {
        let orch_key_bytes: [u8; 32] = hex::decode(orch_key_hex)?
            .try_into()
            .map_err(|_| "Orchestrator key must be 32 bytes")?;
        Keypair::from_bytes(&orch_key_bytes)
    } else {
        // For demo, if not provided, we can't create proper chain link signature
        // In production, this should always be provided
        println!(
            "  ⚠️  WARNING: TENUO_ORCHESTRATOR_KEY not set - chain link signature will be invalid"
        );
        println!("     In production, the orchestrator must sign chain links");
        Keypair::generate() // Placeholder - won't match leaf_warrant.issuer()
    };

    match leaf_warrant
        .attenuate()
        .constraint("budget", Range::max(500.0)) // Further restrict
        .ttl(Duration::from_secs(300)) // 5 minutes
        .authorized_holder(sub_agent_keypair.public_key())
        .agent_id("sub-agent-tool-handler")
        .build(&worker_keypair, &orchestrator_keypair)
    {
        Ok(sub_warrant) => {
            println!(
                "  ✓ Sub-Agent warrant created (depth {})",
                sub_warrant.depth()
            );
            println!("    • ID: {}", sub_warrant.id());
            println!("    • Budget: ≤$500 (narrowed from ≤$1,000)");

            // Now try to go even deeper
            println!(
                "\n  Attempting to delegate from Sub-Agent (depth {})...",
                sub_warrant.depth() + 1
            );

            match sub_warrant
                .attenuate()
                .constraint("budget", Range::max(100.0))
                .ttl(Duration::from_secs(60))
                .build(&sub_agent_keypair, &worker_keypair) // Worker signed the parent
            {
                Ok(deep_warrant) => {
                    println!("  ✓ Deep warrant created (depth {})", deep_warrant.depth());

                    // Try one more level (should fail at max_depth=3)
                    println!(
                        "\n  Attempting depth {} (should hit max_depth limit)...",
                        deep_warrant.depth() + 1
                    );

                    let another_keypair = Keypair::generate();
                    match deep_warrant
                        .attenuate()
                        .constraint("budget", Range::max(50.0))
                        .build(&another_keypair, &sub_agent_keypair) // Sub-agent signed the parent
                    {
                        Ok(w) => {
                            println!(
                                "  ✓ Created warrant at depth {} (max_depth allows it)",
                                w.depth()
                            );
                        }
                        Err(e) => {
                            println!("  ✗ BLOCKED: {}", e);
                            println!("    → max_depth policy enforced!");
                        }
                    }
                }
                Err(e) => {
                    println!("  ✗ BLOCKED: {}", e);
                    println!("    → max_depth policy enforced!");
                }
            }
        }
        Err(e) => {
            println!("  ✗ Cannot create Sub-Agent warrant: {}", e);
        }
    }

    // =========================================================================
    // Step 6: Multi-Sig Approval Demo (Sensitive Actions)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 6: Multi-Sig Approval (Sensitive Actions)                  │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Load the sensitive warrant chain
    let sensitive_chain_path = input_path.replace(".json", "_sensitive.json");
    if Path::new(&sensitive_chain_path).exists() {
        println!("\n  Loading sensitive chain (requires multi-sig approval)...");

        let sensitive_chain_json = fs::read_to_string(&sensitive_chain_path)?;
        let sensitive_chain: Vec<Warrant> = serde_json::from_str(&sensitive_chain_json)?;

        // Verify the sensitive chain
        authorizer.verify_chain(&sensitive_chain)?;
        println!("  ✓ Sensitive chain verified");

        let sensitive_warrant = sensitive_chain.last().unwrap();

        // Display multi-sig requirements
        let threshold = sensitive_warrant.approval_threshold();
        let approvers_count = sensitive_warrant
            .required_approvers()
            .map(|a| a.len())
            .unwrap_or(0);

        println!("\n  Sensitive Warrant Requirements:");
        println!("    • cluster:    staging-web");
        println!("    • action:     [delete, scale-down]");
        println!(
            "    • approvals:  {} required ({} registered)",
            threshold, approvers_count
        );
        println!("    • threshold:  {}-of-{}", threshold, approvers_count);

        // Load admin keypair for multi-sig
        let admin_key_path =
            env::var("TENUO_ADMIN_KEY_INPUT").unwrap_or_else(|_| "/data/admin.key".to_string());

        let admin_keypair = if Path::new(&admin_key_path).exists() {
            let admin_key_hex = fs::read_to_string(&admin_key_path)?;
            let admin_key_bytes: [u8; 32] = hex::decode(admin_key_hex.trim())?
                .try_into()
                .map_err(|_| "Admin key must be 32 bytes")?;
            Some(Keypair::from_bytes(&admin_key_bytes))
        } else {
            println!("  ⚠ Admin key not found at {}", admin_key_path);
            None
        };

        // Test 1: Try to delete WITHOUT approval
        println!("\n  TEST 1: Attempt 'delete' WITHOUT multi-sig approval...");

        let mut args_no_approval: HashMap<String, ConstraintValue> = HashMap::new();
        args_no_approval.insert(
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        );
        args_no_approval.insert(
            "action".to_string(),
            ConstraintValue::String("delete".to_string()),
        );
        args_no_approval.insert("budget".to_string(), ConstraintValue::Float(100.0));

        let holder_sig = sensitive_warrant.create_pop_signature(
            &worker_keypair,
            "manage_infrastructure",
            &args_no_approval,
        )?;

        // Try authorization with NO approvals
        let start = Instant::now();
        let result = authorizer.authorize(
            sensitive_warrant,
            "manage_infrastructure",
            &args_no_approval,
            Some(&holder_sig),
            &[], // No approvals!
        );
        let elapsed = start.elapsed();

        match result {
            Ok(()) => println!("  ✗ UNEXPECTED: Action was allowed without approval!"),
            Err(e) => {
                println!("  ✓ BLOCKED ({:.0?}): {}", elapsed, e);
                println!("    → Multi-sig approval is required for sensitive actions!");
            }
        }

        // Test 2: Try to delete WITH admin approval
        // ⚠️  DEMO ONLY: In production, the ADMIN signs the approval independently.
        // The worker would request approval via a separate channel (Slack, email, UI).
        // Here we simulate admin signing for demo purposes.
        if let Some(ref admin_kp) = admin_keypair {
            println!("\n  TEST 2: Attempt 'delete' WITH admin approval...");
            println!(
                "    ⚠️  [DEMO] Simulating admin signature (production: admin signs independently)"
            );

            // Compute the request hash that will be approved (includes holder for theft protection)
            let request_hash = compute_request_hash(
                sensitive_warrant.id().as_str(),
                "manage_infrastructure",
                &args_no_approval,
                Some(sensitive_warrant.authorized_holder()),
            );

            // Admin creates an approval signature
            let now = chrono::Utc::now();
            let expires = now + chrono::Duration::seconds(300);

            // Create signable bytes (same as Approval::signable_bytes)
            let mut signable = Vec::new();
            signable.extend_from_slice(&request_hash);
            signable.extend_from_slice("arn:aws:iam::123456789:user/admin".as_bytes());
            signable.extend_from_slice(&now.timestamp().to_le_bytes());
            signable.extend_from_slice(&expires.timestamp().to_le_bytes());

            let approval_sig = admin_kp.sign(&signable);

            let approval = Approval {
                request_hash,
                approver_key: admin_kp.public_key(),
                external_id: "arn:aws:iam::123456789:user/admin".to_string(),
                provider: "aws-iam".to_string(),
                approved_at: now,
                expires_at: expires,
                reason: Some("Approved for staging cleanup".to_string()),
                signature: approval_sig,
            };

            println!("    ✓ Approval created by: {}", &approval.external_id);
            println!("    ✓ Expires at: {}", approval.expires_at);

            // Now authorize with the approval
            let start = Instant::now();
            let result = authorizer.authorize(
                sensitive_warrant,
                "manage_infrastructure",
                &args_no_approval,
                Some(&holder_sig),
                &[approval],
            );
            let elapsed = start.elapsed();

            match result {
                Ok(()) => {
                    println!(
                        "\n  ✓ ALLOWED ({:.0?}): Delete action authorized with admin approval",
                        elapsed
                    );
                    println!("    → Multi-sig verification complete!");
                }
                Err(e) => println!("  ✗ UNEXPECTED ERROR: {}", e),
            }
        }

        println!("\n  ╭────────────────────────────────────────────────────────────╮");
        println!("  │  MULTI-SIG APPROVAL PATTERN                                │");
        println!("  ├────────────────────────────────────────────────────────────┤");
        println!("  │  1. Orchestrator creates warrant with required_approvers:  │");
        println!("  │     [admin_public_key] with min_approvals=1                │");
        println!("  │                                                            │");
        println!("  │  2. Worker cannot execute without valid Approval objects   │");
        println!("  │                                                            │");
        println!("  │  3. Admin signs an Approval over request_hash:             │");
        println!("  │     H(warrant_id || tool || sorted(args))                  │");
        println!("  │                                                            │");
        println!("  │  4. Worker submits request with Approval → ALLOWED         │");
        println!("  ╰────────────────────────────────────────────────────────────╯");
    } else {
        println!("\n  (Sensitive chain not found - skipping multi-sig demo)");
    }

    // =========================================================================
    // Summary
    // =========================================================================
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                        WORKER COMPLETE                           ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!(
        "║  Test Results: {} passed, {} failed                                ║",
        passed, failed
    );
    println!("║                                                                  ║");
    println!("║  Features Demonstrated:                                          ║");
    println!("║  • Chain verification proves authority (offline)                ║");
    println!("║  • Constraints enforced exactly as specified                    ║");
    println!("║  • Proof-of-Possession prevents stolen warrant usage            ║");
    println!("║  • max_depth limits how deep delegation can go                  ║");
    println!("║  • session_id links all warrants for traceability               ║");
    println!("║  • MULTI-SIG approval for sensitive actions                    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}
