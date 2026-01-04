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
use tenuo::{Authorizer, ConstraintSet, ConstraintValue, PublicKey, Range, SigningKey, Warrant};

// Remote check dependencies (only when http-client feature is enabled)
#[cfg(feature = "http-client")]
use base64::Engine;
#[cfg(feature = "http-client")]
use reqwest::blocking::Client;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                       WORKER AGENT DEMO                          ║");
    println!("║          Demonstrating Chain Verification & Authorization        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Configure client with timeout for remote calls (only when http-client feature enabled)
    #[cfg(feature = "http-client")]
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

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
    let authorizer = Authorizer::new().with_trusted_root(trusted_key);

    println!("  ✓ Authorizer configured with trusted root");
    // Note: In production, avoid logging key material
    // This is a demo binary - key fingerprint shown for educational purposes
    println!("    Key fingerprint: {}...", &trusted_key_hex[..16]);
    println!("\n  NOTE: The worker only trusts the Control Plane's public key.");
    println!("        It does NOT need the Orchestrator's key - chain verification");
    println!("        cryptographically proves the delegation path.");

    // =========================================================================
    // Step 2: Wait for and load the delegation chains (Multi-Mission)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Loading Mission-Specific Chains                         │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let base_path =
        env::var("TENUO_CHAIN_INPUT").unwrap_or_else(|_| "/data/chain.json".to_string());

    // Derive mission paths from base path
    let mission_a_path = base_path.replace(".json", "_mission_a.json");
    let mission_b_path = base_path.replace(".json", "_mission_b.json");

    println!("  Waiting for mission chains...");
    println!("    Mission A (read_file):            {}", mission_a_path);
    println!("    Mission B (manage_infrastructure): {}", mission_b_path);

    // Wait for chains to be written by orchestrator
    let mut attempts = 0;
    loop {
        if Path::new(&mission_a_path).exists() && Path::new(&mission_b_path).exists() {
            break;
        }
        attempts += 1;
        if attempts > 30 {
            eprintln!("  ✗ Timeout waiting for mission chain files");
            std::process::exit(1);
        }
        print!(".");
        thread::sleep(Duration::from_secs(1));
    }
    println!();

    // Load Mission A chain (read_file)
    let mission_a_json = fs::read_to_string(&mission_a_path)?;
    let mission_a_chain: Vec<Warrant> = serde_json::from_str(&mission_a_json)?;

    // Load Mission B chain (manage_infrastructure)
    let mission_b_json = fs::read_to_string(&mission_b_path)?;
    let mission_b_chain: Vec<Warrant> = serde_json::from_str(&mission_b_json)?;

    // For backward compatibility, 'chain' refers to Mission B
    let chain = mission_b_chain.clone();

    println!("\n  ✓ Mission A Chain (read_file):");
    for (i, warrant) in mission_a_chain.iter().enumerate() {
        let role = if i == 0 { "Root" } else { "Mission A" };
        println!(
            "    [{}] {} ({}, tools: {:?})",
            i,
            warrant.id(),
            role,
            warrant.tools()
        );
    }

    println!("\n  ✓ Mission B Chain (manage_infrastructure):");
    for (i, warrant) in mission_b_chain.iter().enumerate() {
        let role = if i == 0 { "Root" } else { "Mission B" };
        println!(
            "    [{}] {} ({}, tools: {:?})",
            i,
            warrant.id(),
            role,
            warrant.tools()
        );
    }

    // Both missions share the same session (from root warrant)
    if let Some(session) = mission_a_chain.first().and_then(|w| w.session_id()) {
        println!("\n  📋 Shared Session: {}", session);
        println!("     (Both missions traced to same workflow)");
    }

    // =========================================================================
    // Step 2b: Worker Keypair (for Proof-of-Possession)
    // =========================================================================
    // ─────────────────────────────────────────────────────────────────────────
    // PRODUCTION PATTERN:
    //   1. Worker generates its own keypair: keypair = SigningKey::generate()
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
    println!("    PRODUCTION: Worker generates key locally with SigningKey::generate()");
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
    let worker_keypair = SigningKey::from_bytes(&worker_key_bytes);
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
    // Step 4: Multi-Mission Demo (Temporal Least-Privilege)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Multi-Mission Demo (Wrong Warrant = DENIED)             │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Demonstrating mission isolation:");
    println!("    • Mission A warrant can ONLY do read_file");
    println!("    • Mission B warrant can ONLY do manage_infrastructure");
    println!("    • Using the wrong warrant for a tool → DENIED\n");

    let mission_a_leaf = mission_a_chain.last().unwrap();
    let mission_b_leaf = mission_b_chain.last().unwrap();

    // Test 1: Mission A warrant for read_file (should PASS)
    let file_args: HashMap<String, ConstraintValue> = [
        (
            "path".to_string(),
            ConstraintValue::String("/data/config.json".to_string()),
        ),
        ("priority".to_string(), ConstraintValue::Float(3.0)),
    ]
    .into_iter()
    .collect();

    let mission_a_sig = mission_a_leaf.sign(&worker_keypair, "read_file", &file_args)?;
    let result = mission_a_leaf.authorize("read_file", &file_args, Some(&mission_a_sig));
    println!("  📁 Mission A → read_file /data/config.json");
    match result {
        Ok(()) => println!("     ✓ ALLOWED (correct warrant for this mission)"),
        Err(e) => println!("     ✗ DENIED: {} (unexpected!)", e),
    }

    // Test 2: Mission A warrant for manage_infrastructure (should FAIL)
    let infra_args: HashMap<String, ConstraintValue> = [
        (
            "cluster".to_string(),
            ConstraintValue::String("staging-web".to_string()),
        ),
        (
            "action".to_string(),
            ConstraintValue::String("upgrade".to_string()),
        ),
        ("replicas".to_string(), ConstraintValue::Float(5.0)),
    ]
    .into_iter()
    .collect();

    let result = mission_a_leaf.authorize("manage_infrastructure", &infra_args, None);
    println!("\n  📁 Mission A → manage_infrastructure staging-web");
    match result {
        Ok(()) => println!("     ✗ ALLOWED (unexpected! should be denied)"),
        Err(_) => println!("     ✓ DENIED (correct: wrong warrant for this tool)"),
    }

    // Test 3: Mission B warrant for manage_infrastructure (should PASS)
    let mission_b_sig =
        mission_b_leaf.sign(&worker_keypair, "manage_infrastructure", &infra_args)?;
    let result =
        mission_b_leaf.authorize("manage_infrastructure", &infra_args, Some(&mission_b_sig));
    println!("\n  🔧 Mission B → manage_infrastructure staging-web");
    match result {
        Ok(()) => println!("     ✓ ALLOWED (correct warrant for this mission)"),
        Err(e) => println!("     ✗ DENIED: {} (unexpected!)", e),
    }

    // Test 4: Mission B warrant for read_file (should FAIL)
    let result = mission_b_leaf.authorize("read_file", &file_args, None);
    println!("\n  🔧 Mission B → read_file /data/config.json");
    match result {
        Ok(()) => println!("     ✗ ALLOWED (unexpected! should be denied)"),
        Err(_) => println!("     ✓ DENIED (correct: wrong warrant for this tool)"),
    }

    println!("\n  ────────────────────────────────────────────────────────────────");
    println!("  KEY INSIGHT: Same worker, same session, but warrants are scoped.");
    println!("  Even if an attacker compromises one warrant, they can't pivot");
    println!("  to other tools. This is temporal least-privilege in action.");
    println!("  ────────────────────────────────────────────────────────────────");

    // =========================================================================
    // Step 5: Verify Actions (Local or Remote) - Detailed Tests
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 5: Detailed Action Tests (Mission B: Infrastructure)      │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    // Check for remote authorizer mode (requires http-client feature)
    #[cfg(feature = "http-client")]
    let authorizer_url = env::var("TENUO_AUTHORIZER_URL").ok();
    #[cfg(not(feature = "http-client"))]
    let authorizer_url: Option<String> = {
        if env::var("TENUO_AUTHORIZER_URL").is_ok() {
            println!("  ⚠️  TENUO_AUTHORIZER_URL is set but http-client feature not enabled.");
            println!("     Rebuild with: cargo build --features http-client");
            println!("     Falling back to local verification.");
        }
        None
    };

    if let Some(ref url) = authorizer_url {
        println!("  🌐 [Worker] Mode: Gateway Client ({})", url);
        println!("     Delegating verification to remote authorizer service.");
    } else {
        println!("  🔒 [Worker] Mode: Local Library");
        println!("     Verifying warrants in-process using tenuo-core.");
    }

    let leaf_warrant = chain.last().unwrap();
    println!("\n  Using Mission B warrant for detailed constraint tests:");
    println!("    • cluster: staging-web (exact)");
    println!("    • action:  [upgrade, restart] (OneOf)");
    println!("    • replicas: ≤10\n");

    let test_cases = vec![
        // (name, tool, args, expected_allowed, explanation)
        (
            "Scale staging-web to 5 replicas",
            "manage_infrastructure",
            vec![
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("replicas", ConstraintValue::Integer(5)),
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
                ("replicas", ConstraintValue::Integer(0)),
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
                ("replicas", ConstraintValue::Integer(5)),
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
                ("replicas", ConstraintValue::Integer(5)),
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
                ("replicas", ConstraintValue::Integer(0)),
            ],
            false,
            "Blocked: delete is not in allowed actions",
        ),
        (
            "Scale to 20 replicas (exceeds limit)",
            "manage_infrastructure",
            vec![
                (
                    "cluster",
                    ConstraintValue::String("staging-web".to_string()),
                ),
                ("action", ConstraintValue::String("upgrade".to_string())),
                ("replicas", ConstraintValue::Integer(20)),
            ],
            false,
            "Blocked: exceeds 10 replica limit",
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
        // This generates a signature over the application-specific challenge:
        // (warrant_id, tool, sorted_args, timestamp_window)
        let signature = leaf_warrant.sign(&worker_keypair, tool, &args)?;

        let start = Instant::now();
        #[cfg(feature = "http-client")]
        let result = if let Some(ref url) = authorizer_url {
            // Remote mode: Send full chain to authorizer (zero-trust pattern)
            remote_check(&client, url, &chain, tool, &args, &signature)
        } else {
            // Local mode: Verify leaf warrant directly
            leaf_warrant
                .authorize(tool, &args, Some(&signature))
                .map_err(|e| e.into())
        };
        #[cfg(not(feature = "http-client"))]
        let result = leaf_warrant
            .authorize(tool, &args, Some(&signature))
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
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
    // Step 6: Demonstrate delegation depth limits (max_depth)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 6: Demonstrating Depth Limits (max_depth Policy)           │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    let leaf_warrant = chain.last().unwrap();
    println!(
        "\n  Current depth: {} / {}",
        leaf_warrant.depth(),
        leaf_warrant.effective_max_depth()
    );

    // Worker can create sub-agent warrants up to max_depth
    let sub_agent_keypair = SigningKey::generate();

    // Try to create depth 2 warrant (should work if max_depth >= 2)
    println!(
        "\n  Attempting to delegate to Sub-Agent (depth {})...",
        leaf_warrant.depth() + 1
    );

    // Get orchestrator keypair for chain link signature
    // Note: With the new API, the signing_key must be the parent warrant's holder
    // For demo, we get it from environment or use a placeholder
    let _orchestrator_keypair = if let Ok(orch_key_hex) = env::var("TENUO_ORCHESTRATOR_KEY") {
        let orch_key_bytes: [u8; 32] = hex::decode(orch_key_hex)?
            .try_into()
            .map_err(|_| "Orchestrator key must be 32 bytes")?;
        SigningKey::from_bytes(&orch_key_bytes)
    } else {
        // For demo, if not provided, we can't create proper chain link signature
        // In production, this should always be provided
        println!(
            "  ⚠️  WARNING: TENUO_ORCHESTRATOR_KEY not set - chain link signature will be invalid"
        );
        println!("     In production, the orchestrator must sign chain links");
        SigningKey::generate() // Placeholder - won't match leaf_warrant.issuer()
    };

    let mut sub_constraints = ConstraintSet::new();
    sub_constraints.insert("replicas".to_string(), Range::max(5.0)?);

    match leaf_warrant
        .attenuate()
        .capability("manage_infrastructure", sub_constraints) // Further restrict
        .ttl(Duration::from_secs(300)) // 5 minutes
        .holder(sub_agent_keypair.public_key())
        .agent_id("sub-agent-tool-handler")
        .build(&worker_keypair)  // Worker is leaf_warrant's holder
    {
        Ok(sub_warrant) => {
            println!(
                "  ✓ Sub-Agent warrant created (depth {})",
                sub_warrant.depth()
            );
            println!("    • ID: {}", sub_warrant.id());
            println!("    • Replicas: ≤5 (narrowed from ≤10)");

            // Now try to go even deeper
            println!(
                "\n  Attempting to delegate from Sub-Agent (depth {})...",
                sub_warrant.depth() + 1
            );

            let mut sub_constraints = ConstraintSet::new();
            sub_constraints.insert("replicas".to_string(), Range::max(3.0)?);

            match sub_warrant
                .attenuate()
                .capability("cluster_manager", sub_constraints)
                .ttl(Duration::from_secs(60))
                .build(&sub_agent_keypair)  // Sub-agent is sub_warrant's holder
            {
                Ok(deep_warrant) => {
                    println!("  ✓ Deep warrant created (depth {})", deep_warrant.depth());

                    // Try one more level (should fail at max_depth=3)
                    println!(
                        "\n  Attempting depth {} (should hit max_depth limit)...",
                        deep_warrant.depth() + 1
                    );

                    let another_keypair = SigningKey::generate();
                    let mut deep_constraints = ConstraintSet::new();
                    deep_constraints.insert("replicas".to_string(), Range::max(2.0)?);

                    match deep_warrant
                        .attenuate()
                        .capability("cluster_manager", deep_constraints)
                        .build(&another_keypair)  // Another is deep_warrant's holder
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
    println!("║  • Multi-sig approval (preview - see README)                    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    if failed > 0 {
        std::process::exit(1);
    }

    // =========================================================================
    // Step 7: Temporal Mismatch Demo (Real-Time Expiration)
    // =========================================================================
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 7: Temporal Mismatch Demo (Real-Time Expiration)           │");
    println!("└─────────────────────────────────────────────────────────────────┘");

    println!("  Demonstrating real-time expiration enforcement:");
    println!("    1. Issue self-warrant with 2-second TTL");
    println!("    2. Verify it works immediately");
    println!("    3. Wait 3 seconds");
    println!("    4. Verify it FAILS (Expired)");
    println!("    5. Verify parent warrant still works (Scoping)");

    // 1. Issue short-lived sub-warrant (2s TTL)
    println!("\n  [1/5] Creating short-lived warrant (2s TTL)...");

    // We'll just use "read_file" capability for this test, derived from Mission A
    // Note: Mission A has read_file access with constraints on "path".
    // We MUST propagate or narrow these constraints to satisfy monotonicity.
    let mission_a_leaf = mission_a_chain.last().unwrap();

    // Get the constraints from the parent warrant for "read_file"
    // In a real app we might narrow them further. For this demo, we just copy them
    // to ensure we don't violate monotonicity (by accidentally expanding to all paths).
    let parent_constraints = mission_a_leaf
        .capabilities()
        .and_then(|c| c.get("read_file"))
        .cloned()
        .unwrap_or_default();

    let short_warrant = mission_a_leaf
        .attenuate()
        .capability("read_file", parent_constraints) // Inherit constraints
        .ttl(Duration::from_secs(2))
        .build(&worker_keypair)?;

    println!("        ID: {}", short_warrant.id());
    println!("        Expires: {}", short_warrant.expires_at());

    // 2. Immediate verification
    println!("  [2/5] Testing immediately...");
    let short_args: HashMap<String, ConstraintValue> = [
        (
            "path".to_string(),
            ConstraintValue::String("/data/config.json".to_string()),
        ),
        ("priority".to_string(), ConstraintValue::Float(3.0)),
    ]
    .into_iter()
    .collect();

    let sig_immediate = short_warrant.sign(&worker_keypair, "read_file", &short_args)?;

    match short_warrant.authorize("read_file", &short_args, Some(&sig_immediate)) {
        Ok(_) => println!("        ✓ Success (Authorized)"),
        Err(e) => {
            println!("        ✗ Failed: {}", e);
            std::process::exit(1);
        }
    }

    // 3. Wait 3 seconds
    println!("  [3/5] Sleeping 3 seconds...");
    thread::sleep(Duration::from_secs(3));

    // 4. Verification after expiration
    println!("  [4/5] Testing after expiration...");
    // Update signature implies new timestamp, but warrant itself is expired
    // We can try to sign, or just rely on authorize check.
    // authorize() checks expiration first.

    let sig_delayed = short_warrant.sign(&worker_keypair, "read_file", &short_args)?;
    match short_warrant.authorize("read_file", &short_args, Some(&sig_delayed)) {
        Ok(_) => {
            println!("        ✗ Unexpected SUCCESS (Should be expired!)");
            std::process::exit(1);
        }
        Err(e) => {
            // We expect "Warrant expired" error or similar
            println!("        ✓ DENIED: {}", e);
            if !e.to_string().contains("expired") && !e.to_string().contains("Expired") {
                println!("          (Note: Check error message to ensure it's expiration)");
            }
        }
    }

    // 5. Verify parent works
    println!("  [5/5] Verifying parent (Mission A) is still valid...");
    match mission_a_leaf.sign(&worker_keypair, "read_file", &short_args) {
        Ok(fresh_sig) => {
            match mission_a_leaf.authorize("read_file", &short_args, Some(&fresh_sig)) {
                Ok(_) => println!("        ✓ Parent still valid"),
                Err(e) => {
                    println!("        ✗ Parent verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("        ✗ Failed to sign for parent: {}", e);
            std::process::exit(1);
        }
    }

    println!("\n  ✓ Temporal Mismatch Logic Verified: Child expired, Parent remained.");

    Ok(())
}

/// Perform remote authorization check against the Gateway/Authorizer service.
///
/// # Zero-Trust Pattern
/// We send the FULL warrant chain (WarrantStack), not just the leaf warrant.
/// This allows the authorizer to independently verify:
/// - Chain signatures back to trusted root
/// - Monotonic attenuation (capabilities only shrink)
/// - TTL cascade (child expires <= parent)
/// - Depth limits
///
/// The authorizer doesn't trust that we did local verification — it re-verifies.
///
/// # Headers
/// - `X-Tenuo-Chain`: Base64-encoded WarrantStack (CBOR array of warrants)
/// - `X-Tenuo-PoP`: Base64-encoded signature proving holder possession
///
/// # TODO (Production)
/// - Add retry with exponential backoff for transient failures
/// - Parse structured error responses from authorizer
#[cfg(feature = "http-client")]
fn remote_check(
    client: &Client,
    base_url: &str,
    chain: &[Warrant],
    tool: &str,
    args: &HashMap<String, ConstraintValue>,
    signature: &tenuo::Signature,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/verify/{}", base_url.trim_end_matches('/'), tool);

    // 1. Encode full chain as WarrantStack (best practice: authorizer verifies independently)
    let stack = tenuo::wire::WarrantStack::new(chain.to_vec());
    let stack_bytes = tenuo::wire::encode_stack(&stack)?;
    let chain_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&stack_bytes);

    // 2. Encode PoP signature as base64 (consistent with SDK conventions)
    let pop_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

    // 3. Send POST request with full chain
    let resp = match client
        .post(&url)
        .header("X-Tenuo-Warrant", chain_b64) // Use standard header (auto-detects single vs chain)
        .header("X-Tenuo-PoP", pop_b64)
        .header("Content-Type", "application/json")
        .json(args)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            // Connection error (Gateway down, network issue, timeout)
            // This is NOT an authorization denial - it's an infrastructure failure
            eprintln!("\n  ╔════════════════════════════════════════════════════════════╗");
            eprintln!("  ║  ⚠️  GATEWAY CONNECTION ERROR                              ║");
            eprintln!("  ╠════════════════════════════════════════════════════════════╣");
            eprintln!("  ║  Cannot reach the Authorizer service at:                   ║");
            eprintln!("  ║    {}                                    ", url);
            eprintln!("  ║                                                            ║");
            eprintln!(
                "  ║  Error: {:50}║",
                e.to_string().chars().take(50).collect::<String>()
            );
            eprintln!("  ║                                                            ║");
            eprintln!("  ║  Did you start the authorizer?                             ║");
            eprintln!("  ║    docker compose up authorizer                            ║");
            eprintln!("  ╚════════════════════════════════════════════════════════════╝\n");
            std::process::exit(1);
        }
    };

    if resp.status().is_success() {
        Ok(())
    } else {
        // Authorization denial (401, 403, etc.) - this IS a valid test result
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        Err(format!("Remote denial: {} - {}", status, text).into())
    }
}
