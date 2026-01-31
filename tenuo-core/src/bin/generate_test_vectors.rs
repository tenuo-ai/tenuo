//! Byte-exact test vector generator for Tenuo protocol specification
//!
//! Generates deterministic test vectors with fixed:
//! - Keys (from fixed seeds)
//! - Timestamps (fixed epoch values)
//! - Warrant IDs (fixed UUIDs)
//!
//! Run with: cargo run --bin generate_test_vectors

use base64::Engine;
use std::collections::BTreeMap;
use tenuo::{
    constraints::{Constraint, ConstraintSet, Exact, Pattern},
    payload::WarrantPayload,
    warrant::{Warrant, WarrantId, WarrantType, WARRANT_VERSION},
    SigningKey,
};

// Fixed warrant IDs for new tests
const ID_A15_ISSUER: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0,
];
const ID_A15_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD1,
];
const ID_A16_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0,
];
const ID_A17_PARENT: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0,
];
const ID_A17_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF1,
];
const ID_A18: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
];

// Fixed timestamps (2024-01-01T00:00:00Z and +1 hour)
const ISSUED_AT: u64 = 1704067200;
const EXPIRES_AT: u64 = 1704070800;

// Fixed warrant IDs (deterministic UUIDs)
const ID_A1: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const ID_A2: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const ID_A3_L0: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
const ID_A3_L1: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
];
const ID_A3_L2: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
];
const ID_A4: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
];
const ID_A5: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50,
];
const ID_A6: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60,
];

// Fixed timestamp window for PoP (floor(ISSUED_AT / 30) * 30)
const POP_TIMESTAMP_WINDOW: i64 = (ISSUED_AT as i64 / 30) * 30;
const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";

fn main() {
    // Fixed seeds for deterministic key generation
    let control_plane_seed: [u8; 32] = [0x01; 32];
    let orchestrator_seed: [u8; 32] = [0x02; 32];
    let worker_seed: [u8; 32] = [0x03; 32];
    let worker2_seed: [u8; 32] = [0x04; 32];
    let attacker_seed: [u8; 32] = [0xFF; 32]; // Attacker's key for forged signature tests

    let control_plane = SigningKey::from_bytes(&control_plane_seed);
    let orchestrator = SigningKey::from_bytes(&orchestrator_seed);
    let worker = SigningKey::from_bytes(&worker_seed);
    let worker2 = SigningKey::from_bytes(&worker2_seed);
    let attacker = SigningKey::from_bytes(&attacker_seed);

    println!("# Tenuo Protocol Test Vectors");
    println!();
    println!("**Version:** 1.0");
    println!("**Documentation Revision:** 2 (2026-01-21)");
    println!("**Generated:** 2024-01-01 (deterministic timestamps for reproducibility)");
    println!("**Specification:** [wire-format-v1.md](wire-format-v1.md)");
    println!();
    println!("---");
    println!();
    println!("## Revision History");
    println!();
    println!("- **Rev 2** (2026-01-21): Documentation cleanup");
    println!("  - Regenerated all test vectors to match current generator output");
    println!("  - Added cross-reference note to full constraint type list in wire-format-v1.md");
    println!("  - **No protocol changes** - test vectors remain v1.0 compatible");
    println!();
    println!("- **Rev 1** (2026-01-01): Initial release");
    println!();
    println!("---");
    println!();
    println!("## Overview");
    println!();
    println!("All test vectors are **byte-exact** and reproducible. Implementations MUST:");
    println!();
    println!("1. Reproduce the exact CBOR payload bytes");
    println!("2. Verify signatures match exactly");
    println!("3. Verify chain linkage via `parent_hash = SHA256(parent.payload)`");
    println!();
    println!("---");
    println!();

    // Print key material
    println!("## Key Material");
    println!();
    println!("Keys are derived deterministically from 32-byte seeds using Ed25519.");
    println!();
    println!("| Role | Seed | Public Key |");
    println!("|------|------|------------|");
    println!(
        "| Control Plane | `{:02x}{:02x}...{:02x}` (32×0x01) | `{}` |",
        control_plane_seed[0],
        control_plane_seed[1],
        control_plane_seed[31],
        hex::encode(control_plane.public_key().to_bytes())
    );
    println!(
        "| Orchestrator | `{:02x}{:02x}...{:02x}` (32×0x02) | `{}` |",
        orchestrator_seed[0],
        orchestrator_seed[1],
        orchestrator_seed[31],
        hex::encode(orchestrator.public_key().to_bytes())
    );
    println!(
        "| Worker | `{:02x}{:02x}...{:02x}` (32×0x03) | `{}` |",
        worker_seed[0],
        worker_seed[1],
        worker_seed[31],
        hex::encode(worker.public_key().to_bytes())
    );
    println!(
        "| Worker2 | `{:02x}{:02x}...{:02x}` (32×0x04) | `{}` |",
        worker2_seed[0],
        worker2_seed[1],
        worker2_seed[31],
        hex::encode(worker2.public_key().to_bytes())
    );
    println!(
        "| Attacker | `{:02x}{:02x}...{:02x}` (32×0xFF) | `{}` |",
        attacker_seed[0],
        attacker_seed[1],
        attacker_seed[31],
        hex::encode(attacker.public_key().to_bytes())
    );
    println!();

    println!("**Full Seeds:**");
    println!("```");
    println!("Control Plane: {}", hex::encode(control_plane_seed));
    println!("Orchestrator:  {}", hex::encode(orchestrator_seed));
    println!("Worker:        {}", hex::encode(worker_seed));
    println!("Worker2:       {}", hex::encode(worker2_seed));
    println!("Attacker:      {}", hex::encode(attacker_seed));
    println!("```");
    println!();

    println!("---");
    println!();
    println!("## Timestamps");
    println!();
    println!("| Name | Unix (seconds) | ISO 8601 |");
    println!("|------|----------------|----------|");
    println!("| `issued_at` | `{}` | `2024-01-01T00:00:00Z` |", ISSUED_AT);
    println!(
        "| `expires_at` | `{}` | `2024-01-01T01:00:00Z` |",
        EXPIRES_AT
    );
    println!();

    println!("---");
    println!();

    // A.1: Minimal Valid Execution Warrant
    println!("## A.1 Minimal Valid Execution Warrant");
    println!();
    println!("Root warrant with `read_file` tool and Wildcard constraint.");
    println!();

    let mut tools_a1 = BTreeMap::new();
    let mut cs_a1 = ConstraintSet::new();
    cs_a1.insert("path".to_string(), Constraint::Wildcard(tenuo::Wildcard));
    tools_a1.insert("read_file".to_string(), cs_a1);

    let payload_a1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A1),
        tools: tools_a1,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a1 = sign_payload(&payload_a1, &control_plane);
    print_vector("A.1", &warrant_a1);
    print_complete_envelope(&warrant_a1);

    // A.2: Minimal Issuer Warrant
    println!("---");
    println!();
    println!("## A.2 Minimal Issuer Warrant");
    println!();
    println!("Issuer warrant that can grant `read_file` and `write_file` capabilities.");
    println!();

    let payload_a2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Issuer,
        id: WarrantId::from_bytes(ID_A2),
        tools: BTreeMap::new(), // Issuer warrants have empty tools
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 5,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: Some(vec!["read_file".to_string(), "write_file".to_string()]),
        max_issue_depth: Some(3),
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a2 = sign_payload(&payload_a2, &control_plane);
    print_vector("A.2", &warrant_a2);

    // A.3: Valid 3-Level Chain
    println!("---");
    println!();
    println!("## A.3 Valid 3-Level Chain");
    println!();
    println!("Demonstrates progressive attenuation:");
    println!();
    println!("```");
    println!("Level 0: Pattern(\"/data/*\")");
    println!("    -> Level 1: Pattern(\"/data/reports/*\")");
    println!("          -> Level 2: Exact(\"/data/reports/q3.pdf\")");
    println!("```");
    println!();

    // Level 0
    println!("### Level 0 (Root)");
    println!();

    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L0),
        tools: tools_l0,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l0 = sign_payload(&payload_l0, &control_plane);
    print_vector("Level 0", &warrant_l0);

    // Level 1
    println!("### Level 1 (Attenuated)");
    println!();
    println!("**Invariants:**");
    println!("- `issuer` = Level 0's `holder` (Orchestrator)");
    println!("- `depth` = 1");
    println!("- `parent_hash` = SHA256(Level 0 payload)");
    println!();

    let parent_hash_l1 = sha256(warrant_l0.payload_bytes());

    let mut tools_l1 = BTreeMap::new();
    let mut cs_l1 = ConstraintSet::new();
    cs_l1.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_l1.insert("read_file".to_string(), cs_l1);

    let payload_l1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L1),
        tools: tools_l1,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_l1),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l1 = sign_payload(&payload_l1, &orchestrator);
    print_vector("Level 1", &warrant_l1);

    // Level 2
    println!("### Level 2 (Most Restricted)");
    println!();
    println!("**Invariants:**");
    println!("- `issuer` = Level 1's `holder` (Worker)");
    println!("- `depth` = 2");
    println!("- `parent_hash` = SHA256(Level 1 payload)");
    println!();

    let parent_hash_l2 = sha256(warrant_l1.payload_bytes());

    let mut tools_l2 = BTreeMap::new();
    let mut cs_l2 = ConstraintSet::new();
    cs_l2.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/reports/q3.pdf")),
    );
    tools_l2.insert("read_file".to_string(), cs_l2);

    let payload_l2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L2),
        tools: tools_l2,
        holder: worker2.public_key(),
        issuer: worker.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 2,
        parent_hash: Some(parent_hash_l2),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l2 = sign_payload(&payload_l2, &worker);
    print_vector("Level 2", &warrant_l2);

    // A.4: Invalid Chain with actual bytes
    println!("---");
    println!();
    println!("## A.4 Invalid Chain (I1 Violation)");
    println!();
    println!("**Scenario:** Attacker (Worker) signs attenuation of a warrant where they are NOT the holder.");
    println!();
    println!("Using Level 0 from A.3:");
    println!();
    println!("| Field | Level 0 | Invalid Child |");
    println!("|-------|---------|---------------|");
    println!("| holder | Orchestrator | Worker2 |");
    println!("| issuer | Control Plane | **Worker** (WRONG) |");
    println!();

    // Generate the actual invalid warrant bytes
    let parent_hash_invalid = sha256(warrant_l0.payload_bytes());

    let mut tools_a4 = BTreeMap::new();
    let mut cs_a4 = ConstraintSet::new();
    cs_a4.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a4.insert("read_file".to_string(), cs_a4);

    let payload_a4 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A4),
        tools: tools_a4,
        holder: worker2.public_key(),
        issuer: worker.public_key(), // WRONG: Should be orchestrator (parent's holder)
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_invalid),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a4 = sign_payload(&payload_a4, &worker);

    println!(
        "**Invalid Child Payload CBOR ({} bytes):**",
        warrant_a4.payload_bytes().len()
    );
    println!("```");
    print_hex_block(warrant_a4.payload_bytes());
    println!("```");
    println!();

    println!("**Invalid Child Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(warrant_a4.signature().to_bytes()));
    println!("```");
    println!();

    println!(
        "**Expected Error:** `child.issuer ({}) != parent.holder ({})`",
        &hex::encode(worker.public_key().to_bytes())[..16],
        &hex::encode(orchestrator.public_key().to_bytes())[..16]
    );
    println!();

    println!("Verifiers MUST reject this chain even though signatures are valid.");
    println!();

    // A.5: Expired Warrant
    println!("---");
    println!();
    println!("## A.5 Expired Warrant");
    println!();
    println!("Warrant with 1-second TTL.");
    println!();

    let mut tools_a5 = BTreeMap::new();
    let mut cs_a5 = ConstraintSet::new();
    cs_a5.insert("path".to_string(), Constraint::Wildcard(tenuo::Wildcard));
    tools_a5.insert("read_file".to_string(), cs_a5);

    let payload_a5 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A5),
        tools: tools_a5,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: ISSUED_AT + 1, // 1 second TTL
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a5 = sign_payload(&payload_a5, &control_plane);
    print_vector("A.5", &warrant_a5);
    println!(
        "**Expected:** Reject with `warrant_expired` when `now > {}`",
        ISSUED_AT + 1
    );
    println!();

    // A.6: PoP Verification
    println!("---");
    println!();
    println!("## A.6 Proof-of-Possession");
    println!();

    let mut tools_a6 = BTreeMap::new();
    let mut cs_a6 = ConstraintSet::new();
    cs_a6.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/report.pdf")),
    );
    tools_a6.insert("read_file".to_string(), cs_a6);

    let payload_a6 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A6),
        tools: tools_a6,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 1,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a6 = sign_payload(&payload_a6, &control_plane);
    print_vector("A.6", &warrant_a6);

    println!("**PoP Challenge:**");
    println!();
    println!("| Component | Value |");
    println!("|-----------|-------|");
    println!("| Domain Separator | `b\"tenuo-pop-v1\"` |");
    println!("| Warrant ID | `{}` |", warrant_a6.id());
    println!("| Tool | `read_file` |");
    println!("| Args | `{{\"path\": \"/data/report.pdf\"}}` |");
    println!("| Timestamp Window | `{}` |", POP_TIMESTAMP_WINDOW);
    println!();

    // Generate actual PoP signature
    let pop_challenge = (
        warrant_a6.id().to_string(),
        "read_file".to_string(),
        vec![("path".to_string(), "/data/report.pdf".to_string())],
        POP_TIMESTAMP_WINDOW,
    );
    let mut challenge_bytes = Vec::new();
    ciborium::ser::into_writer(&pop_challenge, &mut challenge_bytes)
        .expect("Failed to serialize challenge");

    let mut pop_preimage = Vec::new();
    pop_preimage.extend_from_slice(POP_CONTEXT);
    pop_preimage.extend_from_slice(&challenge_bytes);

    let pop_signature = worker.sign(&pop_preimage);

    println!("**PoP Challenge CBOR ({} bytes):**", challenge_bytes.len());
    println!("```");
    print_hex_block(&challenge_bytes);
    println!("```");
    println!();

    println!("**PoP Preimage (context || challenge):**");
    println!("```");
    println!("{}  # \"tenuo-pop-v1\"", hex::encode(POP_CONTEXT));
    print_hex_block(&challenge_bytes);
    println!("```");
    println!();

    println!("**PoP Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(pop_signature.to_bytes()));
    println!("```");
    println!();
    println!("**Signing Key:** Worker private key (seed `0303...03`)");
    println!();
    println!(
        "**Verification:** Signature MUST verify under Worker's public key: `{}`",
        hex::encode(worker.public_key().to_bytes())
    );
    println!();

    // A.7: Extensions with CBOR Values
    println!("---");
    println!();
    println!("## A.7 Extensions with CBOR Values");
    println!();
    println!("**Scenario:** Warrant with CBOR-encoded extension values.");
    println!();
    println!("Extensions demonstrate:");
    println!();
    println!("1. Simple string values (CBOR-encoded)");
    println!("2. Structured data (CBOR-encoded)");
    println!("3. Preservation through serialization/deserialization");
    println!();

    const ID_A7: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x70,
    ];

    let control_plane = control_plane;
    let orchestrator = orchestrator;

    // Create CBOR-encoded extensions
    let mut extensions = BTreeMap::new();

    // Extension 1: Simple string (CBOR-encoded)
    let trace_id = "request-12345";
    let mut trace_id_bytes = Vec::new();
    ciborium::ser::into_writer(&trace_id, &mut trace_id_bytes).expect("Failed to encode trace_id");
    extensions.insert("com.example.trace_id".to_string(), trace_id_bytes);

    // Extension 2: Structured data (CBOR-encoded)
    #[derive(serde::Serialize)]
    struct BillingTag {
        team: String,
        project: String,
        cost_center: u32,
    }
    let billing = BillingTag {
        team: "ml-research".to_string(),
        project: "warrant-system".to_string(),
        cost_center: 4201,
    };
    let mut billing_bytes = Vec::new();
    ciborium::ser::into_writer(&billing, &mut billing_bytes).expect("Failed to encode billing");
    extensions.insert("com.example.billing".to_string(), billing_bytes);

    let mut tools_a7 = BTreeMap::new();
    let mut cs_a7 = ConstraintSet::new();
    cs_a7.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/report.pdf")),
    );
    tools_a7.insert("read_file".to_string(), cs_a7);

    let payload_a7 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A7),
        tools: tools_a7,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions,
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a7 = sign_payload(&payload_a7, &control_plane);
    print_vector("A.7", &warrant_a7);

    println!("**Extension Values (CBOR-encoded):**");
    println!();
    println!("| Key | Type | CBOR Encoding |");
    println!("|-----|------|---------------|");
    println!(
        "| `com.example.trace_id` | String | `{}` |",
        hex::encode(&warrant_a7.payload.extensions["com.example.trace_id"])
    );
    println!(
        "| `com.example.billing` | Struct | `{}` |",
        hex::encode(&warrant_a7.payload.extensions["com.example.billing"])
    );
    println!();

    println!("**Decoded Extension Values:**");
    println!();
    println!("```rust");
    println!("// com.example.trace_id");
    println!("let trace_id: String = cbor::decode(extensions[\"com.example.trace_id\"])?;");
    println!("assert_eq!(trace_id, \"request-12345\");");
    println!();
    println!("// com.example.billing");
    println!("struct BillingTag {{");
    println!("    team: String,");
    println!("    project: String,");
    println!("    cost_center: u32,");
    println!("}}");
    println!("let billing: BillingTag = cbor::decode(extensions[\"com.example.billing\"])?;");
    println!("assert_eq!(billing.team, \"ml-research\");");
    println!("assert_eq!(billing.project, \"warrant-system\");");
    println!("assert_eq!(billing.cost_center, 4201);");
    println!("```");
    println!();

    println!("**Verification:**");
    println!();
    println!("1. Extensions are included in the warrant signature");
    println!("2. Extension values MUST be CBOR-encoded (not raw bytes)");
    println!("3. Extensions survive serialization/deserialization round-trip");
    println!("4. Unknown extension keys are preserved (not stripped)");
    println!();

    // A.8: WarrantStack Serialization (renumbered from A.7)
    println!("---");
    println!();
    println!("## A.8 WarrantStack Serialization");
    println!();
    println!("**Scenario:** Transporting a 3-level delegation chain as a single CBOR array.");
    println!();
    println!("A `WarrantStack` is a CBOR array of warrants ordered Root → Leaf:");
    println!();
    println!("```");
    println!("type WarrantStack = Vec<SignedWarrant>;");
    println!("```");
    println!();

    // Build the 3-level chain (reuse from A.3)
    let control_plane = control_plane;
    let orchestrator = orchestrator;
    let worker = worker;
    let worker2 = worker2;

    // Level 0
    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L0),
        tools: tools_l0,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l0 = sign_payload(&payload_l0, &control_plane);
    let parent_hash_l1 = sha256(warrant_l0.payload_bytes());

    // Level 1
    let mut tools_l1 = BTreeMap::new();
    let mut cs_l1 = ConstraintSet::new();
    cs_l1.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_l1.insert("read_file".to_string(), cs_l1);

    let payload_l1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L1),
        tools: tools_l1,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_l1),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l1 = sign_payload(&payload_l1, &orchestrator);
    let parent_hash_l2 = sha256(warrant_l1.payload_bytes());

    // Level 2
    let mut tools_l2 = BTreeMap::new();
    let mut cs_l2 = ConstraintSet::new();
    cs_l2.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/reports/q3.pdf")),
    );
    tools_l2.insert("read_file".to_string(), cs_l2);

    let payload_l2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A3_L2),
        tools: tools_l2,
        holder: worker2.public_key(),
        issuer: worker.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 2,
        parent_hash: Some(parent_hash_l2),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l2 = sign_payload(&payload_l2, &worker);

    // Create WarrantStack as CBOR array
    let warrant_stack = vec![&warrant_l0, &warrant_l1, &warrant_l2];
    let mut stack_bytes = Vec::new();
    ciborium::ser::into_writer(&warrant_stack, &mut stack_bytes)
        .expect("Failed to serialize warrant stack");

    let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let stack_base64 = base64_engine.encode(&stack_bytes);

    println!("**WarrantStack CBOR ({} bytes):**", stack_bytes.len());
    println!("```");
    print_hex_block(&stack_bytes);
    println!("```");
    println!();

    println!("**WarrantStack Structure:**");
    println!("```cbor");
    println!("83                  # array(3)");
    println!("   # warrant_l0 (envelope)");
    println!("   83               # array(3) - SignedWarrant");
    println!("      01            # envelope_version");
    println!("      58 AC         # payload (172 bytes)");
    println!("      82 01 58 40   # signature");
    println!("   # warrant_l1 (envelope)");
    println!("   83               # array(3) - SignedWarrant");
    println!("      01            # envelope_version");
    println!("      58 F6         # payload (246 bytes)");
    println!("      82 01 58 40   # signature");
    println!("   # warrant_l2 (envelope)");
    println!("   83               # array(3) - SignedWarrant");
    println!("      01            # envelope_version");
    println!("      58 F8         # payload (248 bytes)");
    println!("      82 01 58 40   # signature");
    println!("```");
    println!();

    println!("**Base64 (URL-safe, no padding):**");
    println!("```");
    for chunk in stack_base64.as_bytes().chunks(76) {
        println!("{}", std::str::from_utf8(chunk).unwrap());
    }
    println!("```");
    println!();

    println!("**Verification steps:**");
    println!();
    println!("1. Deserialize as `Vec<SignedWarrant>` (3 elements)");
    println!("2. Verify warrant_l0 signature (control plane key)");
    println!("3. Verify warrant_l1:");
    println!("   - Issuer = warrant_l0.holder");
    println!("   - parent_hash = SHA256(warrant_l0.payload)");
    println!("   - depth = 1, expires_at ≤ warrant_l0.expires_at");
    println!("   - Signature valid (orchestrator key)");
    println!("4. Verify warrant_l2:");
    println!("   - Issuer = warrant_l1.holder");
    println!("   - parent_hash = SHA256(warrant_l1.payload)");
    println!("   - depth = 2, expires_at ≤ warrant_l1.expires_at");
    println!("   - Signature valid (worker key)");
    println!();

    // A.9: Edge Cases (renumbered from A.8)
    println!("---");
    println!();
    println!("## A.9 Edge Cases");
    println!();
    println!("### A.9.1 Terminal Warrant (depth = max_depth)");
    println!();
    println!("**Scenario:** Warrant at maximum delegation depth cannot be further attenuated.");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!("| depth | 3 |");
    println!("| max_depth | 3 |");
    println!();
    println!(
        "**Expected:** Any attempt to attenuate this warrant MUST fail with `depth_exceeded`."
    );
    println!();
    println!("### A.9.2 Unknown Constraint Type");
    println!();
    println!("**Scenario:** Constraint with unrecognized type ID (experimental range).");
    println!();
    println!("**CBOR bytes:**");
    println!("```");
    println!("82          # array(2)");
    println!("   18 80    # unsigned(128) - type ID in experimental range");
    println!("   a1       # map(1)");
    println!("      66    # text(6)");
    println!("         637573746f6d  # \"custom\"");
    println!("      64    # text(4)");
    println!("         64617461      # \"data\"");
    println!("```");
    println!();
    println!("**Hex:** `821880a166637573746f6d6464617461`");
    println!();
    println!("**Expected:** Verifier deserializes as `Constraint::Unknown {{ type_id: 128, payload: ... }}`, authorization MUST fail (fail closed).");
    println!();
    println!("### A.9.3 Invalid CBOR: Duplicate Map Keys");
    println!();
    println!("**Scenario:** Malformed CBOR payload with duplicate keys.");
    println!();
    println!("```hex");
    println!("# Map with duplicate key 0");
    println!("a2 00 01 00 02");
    println!("# {{0: 1, 0: 2}}");
    println!("```");
    println!();
    println!("**Expected:** Senders MUST NOT produce. Verifier behavior is undefined per RFC 8949 §5.6. This is NOT a normative test case.");
    println!();
    println!("### A.9.4 SRL Revocation");
    println!();
    println!("**Scenario:** Warrant ID appears in Signed Revocation List.");
    println!();
    println!("| warrant.id | SRL.revoked_ids |");
    println!("|------------|-----------------|");
    println!("| `019471f8-0000-7000-8000-000000000001` | `[..., \"019471f8-0000-7000-8000-000000000001\", ...]` |");
    println!();
    println!("**Expected:** Authorization MUST fail with `warrant_revoked`.");
    println!();

    // A.10: Invalid Depth Monotonicity (I2 Violation)
    println!("---");
    println!();
    println!("## A.10 Invalid Depth Monotonicity (I2 Violation)");
    println!();
    println!("**Scenario:** Child warrant skips a depth level (child.depth != parent.depth + 1).");
    println!();

    const ID_A10_PARENT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90,
    ];
    const ID_A10_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x91,
    ];

    // Create parent warrant (depth=0)
    let mut tools_a10_parent = BTreeMap::new();
    let mut cs_a10_parent = ConstraintSet::new();
    cs_a10_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a10_parent.insert("read_file".to_string(), cs_a10_parent);

    let payload_a10_parent = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A10_PARENT),
        tools: tools_a10_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a10_parent = sign_payload(&payload_a10_parent, &control_plane);
    let parent_hash_a10 = sha256(warrant_a10_parent.payload_bytes());

    // Create child with WRONG depth (2 instead of 1)
    let mut tools_a10_child = BTreeMap::new();
    let mut cs_a10_child = ConstraintSet::new();
    cs_a10_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_a10_child.insert("read_file".to_string(), cs_a10_child);

    let payload_a10_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A10_CHILD),
        tools: tools_a10_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 2, // ← WRONG: should be 1
        parent_hash: Some(parent_hash_a10),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a10_child = sign_payload(&payload_a10_child, &orchestrator);

    print_vector("A.10 Parent", &warrant_a10_parent);
    print_vector("A.10 Child (Invalid)", &warrant_a10_child);

    println!("**Depth Comparison:**");
    println!();
    println!("| Warrant | Depth | Expected |");
    println!("|---------|-------|----------|");
    println!("| Parent  | 0     | -        |");
    println!("| Child   | 2     | 1        |");
    println!();
    println!("**Expected:** Verification MUST fail with `depth_monotonicity_violated`.");
    println!();
    println!("**Invariant I2:** `child.depth == parent.depth + 1`");
    println!();

    // A.11: Invalid Capability Monotonicity (I4 Violation)
    println!("---");
    println!();
    println!("## A.11 Invalid Capability Monotonicity (I4 Violation)");
    println!();
    println!("**Scenario:** Child warrant attempts to expand authority beyond parent's grants.");
    println!();

    const ID_A11_PARENT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x92,
    ];
    const ID_A11_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x93,
    ];

    // Create parent warrant with NARROW constraint
    let mut tools_a11_parent = BTreeMap::new();
    let mut cs_a11_parent = ConstraintSet::new();
    cs_a11_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()), // Narrow
    );
    tools_a11_parent.insert("read_file".to_string(), cs_a11_parent);

    let payload_a11_parent = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A11_PARENT),
        tools: tools_a11_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a11_parent = sign_payload(&payload_a11_parent, &control_plane);
    let parent_hash_a11 = sha256(warrant_a11_parent.payload_bytes());

    // Create child with BROADER constraint (invalid!)
    let mut tools_a11_child = BTreeMap::new();
    let mut cs_a11_child = ConstraintSet::new();
    cs_a11_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()), // ← TOO BROAD!
    );
    tools_a11_child.insert("read_file".to_string(), cs_a11_child);

    let payload_a11_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A11_CHILD),
        tools: tools_a11_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a11),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a11_child = sign_payload(&payload_a11_child, &orchestrator);

    print_vector("A.11 Parent", &warrant_a11_parent);
    print_vector("A.11 Child (Invalid)", &warrant_a11_child);

    println!("**Constraint Comparison:**");
    println!();
    println!("| Warrant | path Constraint | Matches |");
    println!("|---------|-----------------|---------|");
    println!("| Parent  | `/data/reports/*` | `/data/reports/foo`, `/data/reports/bar` |");
    println!("| Child   | `/data/*` | `/data/foo`, `/data/reports/foo`, `/data/secret/key` |");
    println!();
    println!("**Expected:** Verification MUST fail with `capability_monotonicity_violated`.");
    println!();
    println!("**Invariant I4:** Child constraints must be equal or more restrictive than parent.");

    // A.12: Invalid Parent Hash (I5 Violation)
    println!("---");
    println!();
    println!("## A.12 Invalid Parent Hash (I5 Violation)");
    println!();
    println!("**Scenario:** Child warrant claims to delegate from parent but parent_hash doesn't match SHA256(parent.payload).");
    println!();

    const ID_A12_PARENT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA0,
    ];
    const ID_A12_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA1,
    ];

    // Create parent warrant
    let mut tools_a12_parent = BTreeMap::new();
    let mut cs_a12_parent = ConstraintSet::new();
    cs_a12_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a12_parent.insert("read_file".to_string(), cs_a12_parent);

    let payload_a12_parent = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A12_PARENT),
        tools: tools_a12_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a12_parent = sign_payload(&payload_a12_parent, &control_plane);

    // Create WRONG parent hash (use all zeros instead of actual hash)
    let wrong_parent_hash = [0u8; 32];
    let correct_parent_hash = sha256(warrant_a12_parent.payload_bytes());

    // Create child with WRONG parent hash
    let mut tools_a12_child = BTreeMap::new();
    let mut cs_a12_child = ConstraintSet::new();
    cs_a12_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_a12_child.insert("read_file".to_string(), cs_a12_child);

    let payload_a12_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A12_CHILD),
        tools: tools_a12_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(wrong_parent_hash), // ← WRONG HASH
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a12_child = sign_payload(&payload_a12_child, &orchestrator);

    print_vector("A.12 Parent", &warrant_a12_parent);
    print_vector("A.12 Child (Invalid)", &warrant_a12_child);

    println!("**Parent Hash Comparison:**");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!(
        "| Correct parent_hash | `{}` |",
        hex::encode(correct_parent_hash)
    );
    println!(
        "| Child's parent_hash | `{}` |",
        hex::encode(wrong_parent_hash)
    );
    println!();
    println!("**Expected:** Verification MUST fail with `parent_hash_mismatch`.");
    println!();
    println!("**Invariant I5:** `child.parent_hash == SHA256(parent.payload_bytes)`");
    println!();

    // A.13: TTL Extension Attack (I3 Violation)
    println!("---");
    println!();
    println!("## A.13 TTL Extension Attack (I3 Violation)");
    println!();
    println!("**Scenario:** Child warrant attempts to extend lifetime beyond parent's expiration.");
    println!();

    const ID_A13_PARENT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB0,
    ];
    const ID_A13_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xB1,
    ];

    // Parent expires at EXPIRES_AT (1704070800)
    let mut tools_a13_parent = BTreeMap::new();
    let mut cs_a13_parent = ConstraintSet::new();
    cs_a13_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a13_parent.insert("read_file".to_string(), cs_a13_parent);

    let payload_a13_parent = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A13_PARENT),
        tools: tools_a13_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT, // 1704070800
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a13_parent = sign_payload(&payload_a13_parent, &control_plane);
    let parent_hash_a13 = sha256(warrant_a13_parent.payload_bytes());

    // Child attempts to extend TTL by 1 hour (invalid)
    let extended_expires_at = EXPIRES_AT + 3600;

    let mut tools_a13_child = BTreeMap::new();
    let mut cs_a13_child = ConstraintSet::new();
    cs_a13_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_a13_child.insert("read_file".to_string(), cs_a13_child);

    let payload_a13_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A13_CHILD),
        tools: tools_a13_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: extended_expires_at, // ← EXTENDED TTL (invalid)
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a13),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_a13_child = sign_payload(&payload_a13_child, &orchestrator);

    print_vector("A.13 Parent", &warrant_a13_parent);
    print_vector("A.13 Child (Invalid)", &warrant_a13_child);

    println!("**TTL Comparison:**");
    println!();
    println!("| Field | Parent | Child | Valid? |");
    println!("|-------|--------|-------|--------|");
    println!("| issued_at | {} | {} | YES |", ISSUED_AT, ISSUED_AT);
    println!(
        "| expires_at | {} | {} | NO (child > parent) |",
        EXPIRES_AT, extended_expires_at
    );
    println!();
    println!("**Expected:** Verification MUST fail with `ttl_monotonicity_violated`.");
    println!();
    println!("**Invariant I3:** `child.expires_at <= parent.expires_at`");
    println!();

    // A.14: Invalid Signature (Cryptographic Verification)
    println!("---");
    println!();
    println!("## A.14 Invalid Signature (Cryptographic Verification)");
    println!();
    println!("**Scenario:** Warrant payload is valid but signature was created by wrong key.");
    println!();
    println!("This tests that implementations correctly verify Ed25519 signatures. A common");
    println!(
        "implementation bug is to skip signature verification or verify against the wrong key."
    );
    println!();

    const ID_A14: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0,
    ];

    // Create a warrant payload that CLAIMS to be issued by control_plane
    let mut tools_a14 = BTreeMap::new();
    let mut cs_a14 = ConstraintSet::new();
    cs_a14.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a14.insert("read_file".to_string(), cs_a14);

    let payload_a14 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A14),
        tools: tools_a14,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(), // Claims to be from control_plane
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    // But sign with a DIFFERENT key (attacker's key)
    // This simulates an attacker trying to forge a warrant
    let warrant_a14_forged = sign_payload(&payload_a14, &attacker);

    // Also create a valid version for comparison
    let warrant_a14_valid = sign_payload(&payload_a14, &control_plane);

    print_vector("A.14 Forged (Invalid Signature)", &warrant_a14_forged);
    print_vector("A.14 Valid (Correct Signature)", &warrant_a14_valid);

    println!("**Key Comparison:**");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!(
        "| Claimed issuer | `{}` |",
        hex::encode(control_plane.public_key().to_bytes())
    );
    println!(
        "| Actual signer (forged) | `{}` |",
        hex::encode(attacker.public_key().to_bytes())
    );
    println!(
        "| Actual signer (valid) | `{}` |",
        hex::encode(control_plane.public_key().to_bytes())
    );
    println!();
    println!("**Note:** The payload bytes are IDENTICAL between forged and valid warrants.");
    println!("Only the signature differs.");
    println!();
    println!("**Expected:** Verification MUST fail with `signature_invalid` or `signature_verification_failed`.");
    println!();
    println!("**Security Note:** This is a critical security check. Implementations that skip");
    println!("signature verification would accept forged warrants, completely breaking the");
    println!("security model.");
    println!();

    // Implementation Notes
    println!("---");
    println!();
    println!("## Implementation Notes");
    println!();
    println!("### CBOR Wire Format");
    println!();
    println!("Payload fields use integer keys:");
    println!();
    println!("| Key | Field |");
    println!("|-----|-------|");
    println!("| 0 | version |");
    println!("| 1 | id |");
    println!("| 2 | warrant_type |");
    println!("| 3 | tools |");
    println!("| 4 | holder |");
    println!("| 5 | issuer |");
    println!("| 6 | issued_at |");
    println!("| 7 | expires_at |");
    println!("| 8 | max_depth |");
    println!("| 9 | parent_hash (optional) |");
    println!("| 10 | extensions (optional) |");
    println!("| 11 | issuable_tools (optional) |");
    println!("| 12 | (reserved) |");
    println!("| 13 | max_issue_depth (optional) |");
    println!("| 14 | constraint_bounds (optional) |");
    println!("| 15 | required_approvers (optional) |");
    println!("| 16 | min_approvals (optional) |");
    println!("| 17 | clearance (optional) |");
    println!("| 18 | depth |");
    println!();
    println!("### Signature Message");
    println!();
    println!("The signature is computed over a domain-separated message:");
    println!();
    println!("```");
    println!("message = b\"tenuo-warrant-v1\" || envelope_version || payload_cbor_bytes");
    println!("signature = Ed25519.sign(issuer_key, message)");
    println!("```");
    println!();
    println!("Where `envelope_version` is `0x01` for v1 warrants.");
    println!();
    println!("### Constraint Type IDs");
    println!();
    println!("| Type | ID |");
    println!("|------|-----|");
    println!("| Exact | 1 |");
    println!("| Pattern | 2 |");
    println!("| Wildcard | 16 |");
    println!();

    println!("---");
    println!();
    println!("## References");
    println!();
    println!("- **[RFC 8032]** Josefsson, S., Liusvaara, I., \"Edwards-Curve Digital Signature Algorithm (EdDSA)\", January 2017. https://datatracker.ietf.org/doc/html/rfc8032");
    println!("- **[RFC 8949]** Bormann, C., Hoffman, P., \"Concise Binary Object Representation (CBOR)\", December 2020. https://datatracker.ietf.org/doc/html/rfc8949");
    println!("- **[protocol-spec-v1.md]** Tenuo Protocol Specification");
    println!();

    // Recreate tools_l0 as it was moved earlier
    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    // A.15: Issuer Constraint Bounds Violation
    println!("---");
    println!();
    println!("## A.15 Issuer Constraint Violation");
    println!();
    println!("**Scenario:** Issuer warrant defines bounds, child exceeds them.");
    println!();

    let mut bounds_a15 = ConstraintSet::new();
    bounds_a15.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    // constraint_bounds is Option<ConstraintSet>, which maps field_name -> Constraint.
    // It assumes all issued tools share these argument bounds (e.g. any tool with 'path' arg must match).

    let payload_a15_issuer = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Issuer,
        id: WarrantId::from_bytes(ID_A15_ISSUER),
        tools: BTreeMap::new(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 5,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: Some(vec!["read_file".to_string()]),
        max_issue_depth: Some(3),
        constraint_bounds: Some(bounds_a15),
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a15_issuer = sign_payload(&payload_a15_issuer, &control_plane);
    print_vector("A.15 Issuer Warrant", &warrant_a15_issuer);

    println!("**Child Warrant (Invalid - Constraints Outside Bounds):**");
    println!();
    let mut tools_a15_child = BTreeMap::new();
    let mut cs_a15_child = ConstraintSet::new();
    cs_a15_child.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/etc/passwd")), // Not in /data/*
    );
    tools_a15_child.insert("read_file".to_string(), cs_a15_child);

    let parent_hash_a15 = sha256(warrant_a15_issuer.payload_bytes());

    let payload_a15_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A15_CHILD),
        tools: tools_a15_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a15),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a15_child = sign_payload(&payload_a15_child, &orchestrator);
    print_vector("A.15 Invalid Child", &warrant_a15_child);
    println!("**Expected:** Verification MUST fail with `constraint_violation` (Child constraints not subset of Parent bounds).");
    println!();

    // A.16: Self-Issuance Violation
    println!("---");
    println!();
    println!("## A.16 Self-Issuance Violation");
    println!();
    println!("**Scenario:** Holder delegates execution warrant to themselves (Privilege Escalation / Separation of Duties).");
    println!();

    let parent_hash_l0 = sha256(warrant_l0.payload_bytes());
    let mut tools_a16 = BTreeMap::new();
    let mut cs_a16 = ConstraintSet::new();
    cs_a16.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a16.insert("read_file".to_string(), cs_a16);

    let payload_a16 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A16_CHILD),
        tools: tools_a16,
        holder: orchestrator.public_key(), // Same as issuer (Orchestrator self-signing)
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_l0), // Parent is Orchestrator's L0
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a16 = sign_payload(&payload_a16, &orchestrator);
    print_vector("A.16 Invalid Self-Issuance", &warrant_a16);
    println!("**Expected:** Verification MUST fail with `self_issuance` error.");
    println!();

    // A.17: Clearance Monotonicity Violation
    println!("---");
    println!();
    println!("## A.17 Clearance Violation");
    println!();
    println!("**Scenario:** Child attempts to increase clearance level.");
    println!();

    let payload_a17_parent = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A17_PARENT),
        tools: tools_l0.clone(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: Some(tenuo::warrant::Clearance(5)), // Parent clearance = 5
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a17_parent = sign_payload(&payload_a17_parent, &control_plane);
    print_vector("A.17 Parent (Clearance=5)", &warrant_a17_parent);

    let parent_hash_a17 = sha256(warrant_a17_parent.payload_bytes());
    let payload_a17_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A17_CHILD),
        tools: tools_l0.clone(),
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a17),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: Some(tenuo::warrant::Clearance(6)), // Child clearance = 6 (Invalid increase)
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a17_child = sign_payload(&payload_a17_child, &orchestrator);
    print_vector("A.17 Invalid Child (Clearance=6)", &warrant_a17_child);
    println!("**Expected:** Verification MUST fail with `clearance_monotonicity_violated`.");
    println!();

    // A.18: Multi-sig Config
    println!("---");
    println!();
    println!("## A.18 Multi-sig Configuration");
    println!();
    println!("**Scenario:** Warrant with required approvers.");
    println!();

    let payload_a18 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A18),
        tools: tools_l0.clone(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: Some(vec![worker.public_key(), worker2.public_key()]),
        min_approvals: Some(1),
    };
    let warrant_a18 = sign_payload(&payload_a18, &control_plane);
    print_vector("A.18 Multi-sig", &warrant_a18);
    println!("Verifiers MUST enforce approvals from `worker` or `worker2` before execution.");

    // =========================================================================
    // A.19 Constraint Type Coverage
    // =========================================================================
    println!();
    println!("---");
    println!();
    println!("## A.19 Constraint Type Coverage");
    println!();
    println!("Byte-exact test vectors for constraint type validation.");
    println!();

    // A.19.1 Range Constraint
    println!("### A.19.1 Range Constraint");
    println!();

    const ID_A19_1: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
        0x01,
    ];

    let mut tools_a19_1 = BTreeMap::new();
    let mut cs_a19_1 = ConstraintSet::new();
    cs_a19_1.insert(
        "count".to_string(),
        Constraint::Range(tenuo::constraints::Range::new(Some(0.0), Some(100.0)).unwrap()),
    );
    tools_a19_1.insert("api_call".to_string(), cs_a19_1);

    let payload_a19_1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A19_1),
        tools: tools_a19_1,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a19_1 = sign_payload(&payload_a19_1, &control_plane);
    print_vector("A.19.1 Range", &warrant_a19_1);
    println!("| Valid Input | `count = 50.0` |");
    println!("| Invalid Input | `count = 150.0` |");
    println!();
    println!("**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.");
    println!();

    // A.19.2 OneOf Constraint
    println!("### A.19.2 OneOf Constraint");
    println!();

    const ID_A19_2: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
        0x02,
    ];

    let mut tools_a19_2 = BTreeMap::new();
    let mut cs_a19_2 = ConstraintSet::new();
    cs_a19_2.insert(
        "env".to_string(),
        Constraint::OneOf(tenuo::constraints::OneOf::new(vec![
            "staging".to_string(),
            "production".to_string(),
        ])),
    );
    tools_a19_2.insert("deploy".to_string(), cs_a19_2);

    let payload_a19_2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A19_2),
        tools: tools_a19_2,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a19_2 = sign_payload(&payload_a19_2, &control_plane);
    print_vector("A.19.2 OneOf", &warrant_a19_2);
    println!("| Valid Input | `env = \"staging\"` |");
    println!("| Invalid Input | `env = \"development\"` |");
    println!();
    println!("**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.");
    println!();

    // A.19.3 CIDR Constraint
    println!("### A.19.3 CIDR Constraint");
    println!();

    const ID_A19_3: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19,
        0x03,
    ];

    let mut tools_a19_3 = BTreeMap::new();
    let mut cs_a19_3 = ConstraintSet::new();
    cs_a19_3.insert(
        "ip".to_string(),
        Constraint::Cidr(tenuo::constraints::Cidr::new("10.0.0.0/8").unwrap()),
    );
    tools_a19_3.insert("connect".to_string(), cs_a19_3);

    let payload_a19_3 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A19_3),
        tools: tools_a19_3,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a19_3 = sign_payload(&payload_a19_3, &control_plane);
    print_vector("A.19.3 CIDR", &warrant_a19_3);
    println!("| Valid Input | `ip = \"10.1.2.3\"` |");
    println!("| Invalid Input | `ip = \"192.168.1.1\"` |");
    println!();
    println!("**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.");
    println!();

    // =========================================================================
    // A.20 PoP Failure Cases
    // =========================================================================
    println!("---");
    println!();
    println!("## A.20 Proof-of-Possession Failures");
    println!();

    // A.20.1 Wrong Holder Key
    println!("### A.20.1 PoP with Wrong Holder Key");
    println!();

    const ID_A20_1: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x01,
    ];

    let mut tools_a20_1 = BTreeMap::new();
    let mut cs_a20_1 = ConstraintSet::new();
    cs_a20_1.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a20_1.insert("read_file".to_string(), cs_a20_1);

    let payload_a20_1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A20_1),
        tools: tools_a20_1,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a20_1 = sign_payload(&payload_a20_1, &control_plane);
    print_vector("A.20.1", &warrant_a20_1);

    // Generate PoP signed by ATTACKER (wrong key)
    let pop_a20_1_challenge = (
        warrant_a20_1.id().to_string(),
        "read_file".to_string(),
        vec![("path".to_string(), "/data/test.txt".to_string())],
        POP_TIMESTAMP_WINDOW,
    );
    let mut pop_a20_1_bytes = Vec::new();
    ciborium::ser::into_writer(&pop_a20_1_challenge, &mut pop_a20_1_bytes)
        .expect("Failed to serialize PoP challenge");

    let mut pop_a20_1_preimage = Vec::new();
    pop_a20_1_preimage.extend_from_slice(POP_CONTEXT);
    pop_a20_1_preimage.extend_from_slice(&pop_a20_1_bytes);

    let pop_a20_1_sig_wrong = attacker.sign(&pop_a20_1_preimage); // WRONG: signed by attacker
    let pop_a20_1_sig_correct = worker.sign(&pop_a20_1_preimage); // Correct: signed by holder

    println!("| Holder | Worker |");
    println!("| PoP Signer (Invalid) | Attacker |");
    println!();
    println!("**Invalid PoP Signature (signed by Attacker):**");
    println!("```");
    println!("{}", hex::encode(pop_a20_1_sig_wrong.to_bytes()));
    println!("```");
    println!();
    println!("**Valid PoP Signature (signed by Holder/Worker):**");
    println!("```");
    println!("{}", hex::encode(pop_a20_1_sig_correct.to_bytes()));
    println!("```");
    println!();
    println!("**Expected:** Invalid PoP MUST fail with signature error.");
    println!();

    // =========================================================================
    // A.21 Multi-sig Approval
    // =========================================================================
    println!("---");
    println!();
    println!("## A.21 Signed Approval (Multi-sig)");
    println!();

    const ID_A21_1: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
        0x01,
    ];

    // Create approver keys (separate from main keys for clarity)
    let approver1_seed: [u8; 32] = [0x11; 32];
    let approver2_seed: [u8; 32] = [0x12; 32];
    let approver3_seed: [u8; 32] = [0x13; 32];
    let approver1 = SigningKey::from_bytes(&approver1_seed);
    let approver2 = SigningKey::from_bytes(&approver2_seed);
    let approver3 = SigningKey::from_bytes(&approver3_seed);

    println!("### A.21.1 Valid 2-of-3 Multi-sig");
    println!();
    println!("**Additional Key Material:**");
    println!();
    println!("| Role | Seed | Public Key |");
    println!("|------|------|------------|");
    println!(
        "| Approver1 | `1111...11` (32×0x11) | `{}` |",
        hex::encode(approver1.public_key().to_bytes())
    );
    println!(
        "| Approver2 | `1212...12` (32×0x12) | `{}` |",
        hex::encode(approver2.public_key().to_bytes())
    );
    println!(
        "| Approver3 | `1313...13` (32×0x13) | `{}` |",
        hex::encode(approver3.public_key().to_bytes())
    );
    println!();

    let mut tools_a21_1 = BTreeMap::new();
    let mut cs_a21_1 = ConstraintSet::new();
    cs_a21_1.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a21_1.insert("read_file".to_string(), cs_a21_1);

    // Sort approvers by public key bytes for determinism
    let mut approver_keys = vec![
        approver1.public_key(),
        approver2.public_key(),
        approver3.public_key(),
    ];
    approver_keys.sort_by_key(|k| k.to_bytes());

    let payload_a21_1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A21_1),
        tools: tools_a21_1,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: Some(approver_keys),
        min_approvals: Some(2),
    };
    let warrant_a21_1 = sign_payload(&payload_a21_1, &control_plane);
    print_vector("A.21.1", &warrant_a21_1);
    println!("| Required Approvers | 3 |");
    println!("| Min Approvals | 2 |");
    println!();
    println!(
        "**Expected:** Authorization MUST succeed with 2+ valid approvals from listed approvers."
    );
    println!();

    // A.21.2 Insufficient Approvals
    println!("### A.21.2 Insufficient Approvals");
    println!();

    const ID_A21_2: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
        0x02,
    ];

    let mut tools_a21_2 = BTreeMap::new();
    let mut cs_a21_2 = ConstraintSet::new();
    cs_a21_2.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a21_2.insert("read_file".to_string(), cs_a21_2);

    let mut approver_keys_2 = vec![approver1.public_key(), approver2.public_key()];
    approver_keys_2.sort_by_key(|k| k.to_bytes());

    let payload_a21_2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A21_2),
        tools: tools_a21_2,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: Some(approver_keys_2),
        min_approvals: Some(2),
    };
    let warrant_a21_2 = sign_payload(&payload_a21_2, &control_plane);
    print_vector("A.21.2", &warrant_a21_2);
    println!("| Required Approvers | 2 |");
    println!("| Min Approvals | 2 |");
    println!("| Provided Approvals | 1 (only Approver1) |");
    println!();
    println!("**Expected:** Authorization MUST fail with insufficient approvals.");
    println!();

    // =========================================================================
    // A.22 Cascading Revocation
    // =========================================================================
    println!("---");
    println!();
    println!("## A.22 Cascading Revocation");
    println!();

    const ID_A22_ROOT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22,
        0x00,
    ];
    const ID_A22_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22,
        0x01,
    ];

    let mut tools_a22 = BTreeMap::new();
    let mut cs_a22 = ConstraintSet::new();
    cs_a22.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_a22.insert("read_file".to_string(), cs_a22);

    // Root warrant
    let payload_a22_root = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A22_ROOT),
        tools: tools_a22.clone(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a22_root = sign_payload(&payload_a22_root, &control_plane);
    print_vector("A.22 Root", &warrant_a22_root);

    let parent_hash_a22 = sha256(warrant_a22_root.payload_bytes());

    // Child warrant
    let payload_a22_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A22_CHILD),
        tools: tools_a22.clone(),
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a22),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a22_child = sign_payload(&payload_a22_child, &orchestrator);
    print_vector("A.22 Child", &warrant_a22_child);

    println!("**Revocation Scenario:**");
    println!();
    println!("| Revoked Warrant | Child (`{}`) |", warrant_a22_child.id());
    println!();
    println!("**Expected:** Chain verification MUST fail when child warrant is revoked.");
    println!();

    // =========================================================================
    // A.23 Session Mismatch
    // =========================================================================
    println!("---");
    println!();
    println!("## A.23 Session Mismatch");
    println!();

    const ID_A23_ROOT: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23,
        0x00,
    ];
    const ID_A23_ROOT_NO_SESS: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23,
        0x01,
    ];
    const ID_A23_CHILD: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23,
        0x02,
    ];

    let mut tools_a23 = BTreeMap::new();
    let mut cs_a23 = ConstraintSet::new();
    cs_a23.insert("path".to_string(), Constraint::Wildcard(tenuo::Wildcard));
    tools_a23.insert("read_file".to_string(), cs_a23);

    // Root WITH session_id
    let payload_a23_root = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A23_ROOT),
        tools: tools_a23.clone(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: Some("sess-abc".to_string()),
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a23_root = sign_payload(&payload_a23_root, &control_plane);
    print_vector("A.23 Root (session_id=sess-abc)", &warrant_a23_root);

    // Root WITHOUT session_id
    let payload_a23_root_no_sess = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A23_ROOT_NO_SESS),
        tools: tools_a23.clone(),
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a23_root_no_sess = sign_payload(&payload_a23_root_no_sess, &control_plane);
    print_vector("A.23 Root (no session_id)", &warrant_a23_root_no_sess);

    // Child from root WITHOUT session (inherits None)
    let parent_hash_a23 = sha256(warrant_a23_root_no_sess.payload_bytes());
    let payload_a23_child = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A23_CHILD),
        tools: tools_a23.clone(),
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash_a23),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None, // Inherited from parent (None)
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a23_child = sign_payload(&payload_a23_child, &orchestrator);
    print_vector("A.23 Child (inherited no session)", &warrant_a23_child);

    println!("**Session Mismatch Scenario:**");
    println!();
    println!("Mix Root (with session) and Child (without session) in a chain:");
    println!();
    println!(
        "| Root | `{}` (session_id=sess-abc) |",
        warrant_a23_root.id()
    );
    println!("| Child | `{}` (session_id=None) |", warrant_a23_child.id());
    println!();
    println!("**Expected:**");
    println!("- `verify_chain()`: MAY succeed (session check optional)");
    println!("- `verify_chain_strict()`: MUST fail with session mismatch error");
    println!();
    println!("> [!NOTE]");
    println!("> `session_id` is inherited during attenuation and cannot be changed.");
    println!("> Mismatch occurs when mixing warrants from different session contexts.");

    // =========================================================================
    // A.24 SignedApproval Envelope
    // =========================================================================
    println!();
    println!("---");
    println!();
    println!("## A.24 SignedApproval Envelope");
    println!();
    println!("Complete wire format for human-in-the-loop approval.");
    println!();

    // Use pre-defined IDs and nonce for determinism
    const APPROVAL_NONCE: [u8; 16] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0xB8,
    ];

    // Construct request hash: H(warrant_id || tool || sorted_args || holder)
    let mut request_preimage = Vec::new();
    request_preimage.extend_from_slice(b"tnu_wrt_019471f8000070008000000000002101"); // warrant_id
    request_preimage.extend_from_slice(b"read_file"); // tool
    request_preimage.extend_from_slice(b"path=/data/sensitive.txt"); // sorted args
    request_preimage.extend_from_slice(&worker.public_key().to_bytes()); // holder
    let request_hash = sha256(&request_preimage);

    // Create ApprovalPayload
    #[derive(serde::Serialize)]
    struct ApprovalPayloadGen {
        version: u8,
        #[serde(with = "serde_bytes")]
        request_hash: [u8; 32],
        #[serde(with = "serde_bytes")]
        nonce: [u8; 16],
        external_id: String,
        approved_at: u64,
        expires_at: u64,
    }

    let approval_payload = ApprovalPayloadGen {
        version: 1,
        request_hash,
        nonce: APPROVAL_NONCE,
        external_id: "arn:aws:iam::123456789012:user/security-admin".to_string(),
        approved_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
    };

    let mut approval_payload_bytes = Vec::new();
    ciborium::ser::into_writer(&approval_payload, &mut approval_payload_bytes)
        .expect("Failed to serialize approval payload");

    // Build preimage and sign
    let mut approval_preimage = Vec::new();
    approval_preimage.extend_from_slice(b"tenuo-approval-v1");
    approval_preimage.push(1); // approval_version
    approval_preimage.extend_from_slice(&approval_payload_bytes);
    let approval_sig = approver1.sign(&approval_preimage);

    // Build full envelope
    #[derive(serde::Serialize)]
    struct SignedApprovalGen {
        approval_version: u8,
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
        #[serde(with = "serde_bytes")]
        approver_key: [u8; 32],
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    }

    let signed_approval = SignedApprovalGen {
        approval_version: 1,
        payload: approval_payload_bytes.clone(),
        approver_key: approver1.public_key().to_bytes(),
        signature: approval_sig.to_bytes(),
    };

    let mut signed_approval_bytes = Vec::new();
    ciborium::ser::into_writer(&signed_approval, &mut signed_approval_bytes)
        .expect("Failed to serialize signed approval");

    println!("### SignedApproval Structure");
    println!();
    println!("| Field | Type | Description |");
    println!("|-------|------|-------------|");
    println!("| `approval_version` | u8 | Envelope version (1) |");
    println!("| `payload` | bytes | CBOR-encoded ApprovalPayload |");
    println!("| `approver_key` | [u8; 32] | Ed25519 public key |");
    println!("| `signature` | [u8; 64] | Ed25519 signature |");
    println!();

    println!("### ApprovalPayload");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!("| `version` | 1 |");
    println!("| `request_hash` | `{}` |", hex::encode(&request_hash));
    println!("| `nonce` | `{}` |", hex::encode(APPROVAL_NONCE));
    println!("| `external_id` | `arn:aws:iam::123456789012:user/security-admin` |");
    println!("| `approved_at` | `{}` |", ISSUED_AT);
    println!("| `expires_at` | `{}` |", EXPIRES_AT);
    println!();

    println!(
        "**ApprovalPayload CBOR ({} bytes):**",
        approval_payload_bytes.len()
    );
    println!("```");
    print_hex_block(&approval_payload_bytes);
    println!("```");
    println!();

    println!("**Signing Preimage:**");
    println!("```");
    println!("b\"tenuo-approval-v1\" || 0x01 || payload_bytes");
    println!("```");
    println!();

    println!("**Approver Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(approval_sig.to_bytes()));
    println!("```");
    println!();

    println!(
        "**Complete SignedApproval Envelope ({} bytes):**",
        signed_approval_bytes.len()
    );
    println!("```");
    print_hex_block(&signed_approval_bytes);
    println!("```");
    println!();

    // =========================================================================
    // Update A.22 with SRL CBOR
    // =========================================================================
    println!("---");
    println!();
    println!("## A.22.b SignedRevocationList (SRL)");
    println!();
    println!("Complete wire format for revocation list.");
    println!();

    #[derive(serde::Serialize)]
    struct SrlPayloadGen {
        revoked_ids: Vec<String>,
        version: u64,
        issued_at: u64,
        issuer: [u8; 32],
    }

    let srl_payload = SrlPayloadGen {
        revoked_ids: vec![warrant_a22_child.id().to_string()],
        version: 1,
        issued_at: ISSUED_AT,
        issuer: control_plane.public_key().to_bytes(),
    };

    let mut srl_payload_bytes = Vec::new();
    ciborium::ser::into_writer(&srl_payload, &mut srl_payload_bytes)
        .expect("Failed to serialize SRL payload");

    // Sign SRL
    let mut srl_preimage = Vec::new();
    srl_preimage.extend_from_slice(b"tenuo-srl-v1");
    srl_preimage.extend_from_slice(&srl_payload_bytes);
    let srl_sig = control_plane.sign(&srl_preimage);

    #[derive(serde::Serialize)]
    struct SignedSrlGen {
        payload: SrlPayloadGen,
        #[serde(with = "serde_bytes")]
        signature: [u8; 64],
    }

    let signed_srl = SignedSrlGen {
        payload: srl_payload,
        signature: srl_sig.to_bytes(),
    };

    let mut signed_srl_bytes = Vec::new();
    ciborium::ser::into_writer(&signed_srl, &mut signed_srl_bytes)
        .expect("Failed to serialize signed SRL");

    println!("### SrlPayload");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!("| `revoked_ids` | `[\"{}\"]` |", warrant_a22_child.id());
    println!("| `version` | 1 |");
    println!("| `issued_at` | `{}` |", ISSUED_AT);
    println!(
        "| `issuer` | `{}` |",
        hex::encode(control_plane.public_key().to_bytes())
    );
    println!();

    println!("**SrlPayload CBOR ({} bytes):**", srl_payload_bytes.len());
    println!("```");
    print_hex_block(&srl_payload_bytes);
    println!("```");
    println!();

    println!("**Signing Preimage:**");
    println!("```");
    println!("b\"tenuo-srl-v1\" || payload_bytes");
    println!("```");
    println!();

    println!("**Control Plane Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(srl_sig.to_bytes()));
    println!("```");
    println!();

    println!(
        "**Complete SignedRevocationList ({} bytes):**",
        signed_srl_bytes.len()
    );
    println!("```");
    print_hex_block(&signed_srl_bytes);
    println!("```");
    println!();

    // =========================================================================
    // A.25 Additional Constraint Types
    // =========================================================================
    println!("---");
    println!();
    println!("## A.25 Additional Constraint Types");
    println!();
    println!("Byte-exact test vectors for remaining constraint types.");
    println!();

    // A.25.1 UrlSafe Constraint
    println!("### A.25.1 UrlSafe Constraint");
    println!();

    const ID_A25_1: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
        0x01,
    ];

    let mut tools_a25_1 = BTreeMap::new();
    let mut cs_a25_1 = ConstraintSet::new();
    cs_a25_1.insert(
        "url".to_string(),
        Constraint::UrlSafe(tenuo::constraints::UrlSafe::new()),
    );
    tools_a25_1.insert("http_request".to_string(), cs_a25_1);

    let payload_a25_1 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A25_1),
        tools: tools_a25_1,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a25_1 = sign_payload(&payload_a25_1, &control_plane);
    print_vector("A.25.1 UrlSafe", &warrant_a25_1);
    println!("| Valid Input | `url = \"https://api.example.com/data\"` |");
    println!("| Invalid Input | `url = \"http://169.254.169.254/\"` (AWS metadata) |");
    println!();
    println!("**Expected:** SSRF-safe URLs succeed, internal/metadata URLs fail.");
    println!();

    // A.25.2 Subpath Constraint
    println!("### A.25.2 Subpath Constraint");
    println!();

    const ID_A25_2: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
        0x02,
    ];

    let mut tools_a25_2 = BTreeMap::new();
    let mut cs_a25_2 = ConstraintSet::new();
    cs_a25_2.insert(
        "path".to_string(),
        Constraint::Subpath(tenuo::constraints::Subpath::new("/home/agent/workspace").unwrap()),
    );
    tools_a25_2.insert("write_file".to_string(), cs_a25_2);

    let payload_a25_2 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A25_2),
        tools: tools_a25_2,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a25_2 = sign_payload(&payload_a25_2, &control_plane);
    print_vector("A.25.2 Subpath", &warrant_a25_2);
    println!("| Valid Input | `path = \"/home/agent/workspace/file.txt\"` |");
    println!("| Invalid Input | `path = \"/home/agent/workspace/../../../etc/passwd\"` |");
    println!();
    println!("**Expected:** Contained paths succeed, traversal attacks fail.");
    println!();

    // A.25.3 Contains Constraint
    println!("### A.25.3 Contains Constraint");
    println!();

    const ID_A25_3: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
        0x03,
    ];

    let mut tools_a25_3 = BTreeMap::new();
    let mut cs_a25_3 = ConstraintSet::new();
    cs_a25_3.insert(
        "tags".to_string(),
        Constraint::Contains(tenuo::constraints::Contains::new(vec![
            "approved", "reviewed",
        ])),
    );
    tools_a25_3.insert("deploy".to_string(), cs_a25_3);

    let payload_a25_3 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A25_3),
        tools: tools_a25_3,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a25_3 = sign_payload(&payload_a25_3, &control_plane);
    print_vector("A.25.3 Contains", &warrant_a25_3);
    println!("| Valid Input | `tags = [\"approved\", \"reviewed\", \"urgent\"]` |");
    println!("| Invalid Input | `tags = [\"approved\", \"urgent\"]` (missing \"reviewed\") |");
    println!();
    println!("**Expected:** Lists containing required values succeed.");
    println!();

    // A.25.4 Subset Constraint
    println!("### A.25.4 Subset Constraint");
    println!();

    const ID_A25_4: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
        0x04,
    ];

    let mut tools_a25_4 = BTreeMap::new();
    let mut cs_a25_4 = ConstraintSet::new();
    cs_a25_4.insert(
        "permissions".to_string(),
        Constraint::Subset(tenuo::constraints::Subset::new(vec![
            "read", "write", "delete",
        ])),
    );
    tools_a25_4.insert("set_permissions".to_string(), cs_a25_4);

    let payload_a25_4 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A25_4),
        tools: tools_a25_4,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a25_4 = sign_payload(&payload_a25_4, &control_plane);
    print_vector("A.25.4 Subset", &warrant_a25_4);
    println!("| Valid Input | `permissions = [\"read\", \"write\"]` |");
    println!("| Invalid Input | `permissions = [\"read\", \"admin\"]` |");
    println!();
    println!("**Expected:** Subset of allowed values succeeds, extras fail.");
    println!();

    // A.25.5 UrlPattern Constraint
    println!("### A.25.5 UrlPattern Constraint");
    println!();

    const ID_A25_5: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,
        0x05,
    ];

    let mut tools_a25_5 = BTreeMap::new();
    let mut cs_a25_5 = ConstraintSet::new();
    cs_a25_5.insert(
        "endpoint".to_string(),
        Constraint::UrlPattern(
            tenuo::constraints::UrlPattern::new("https://api.example.com/v1/*").unwrap(),
        ),
    );
    tools_a25_5.insert("api_call".to_string(), cs_a25_5);

    let payload_a25_5 = WarrantPayload {
        version: WARRANT_VERSION as u8,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(ID_A25_5),
        tools: tools_a25_5,
        holder: worker.public_key(),
        issuer: control_plane.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 0,
        parent_hash: None,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let warrant_a25_5 = sign_payload(&payload_a25_5, &control_plane);
    print_vector("A.25.5 UrlPattern", &warrant_a25_5);
    println!("| Valid Input | `endpoint = \"https://api.example.com/v1/users\"` |");
    println!("| Invalid Input | `endpoint = \"https://evil.com/api\"` |");
    println!();
    println!("**Expected:** URLs matching pattern succeed.");
}

fn sign_payload(payload: &WarrantPayload, signing_key: &SigningKey) -> Warrant {
    // Serialize payload to CBOR
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes).expect("Failed to serialize payload");

    // Create preimage: envelope_version || payload_bytes
    let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
    preimage.push(1); // envelope_version
    preimage.extend_from_slice(&payload_bytes);

    // Sign with domain separation
    let signature = signing_key.sign(&preimage);

    Warrant {
        payload: payload.clone(),
        signature,
        payload_bytes,
        envelope_version: 1,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn print_vector(label: &str, warrant: &Warrant) {
    let payload_bytes = warrant.payload_bytes();
    let sig_bytes = warrant.signature().to_bytes();

    println!("**{}**", label);
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!("| ID | `{}` |", warrant.id());
    println!(
        "| Type | {} |",
        if warrant.r#type() == WarrantType::Issuer {
            "Issuer"
        } else {
            "Execution"
        }
    );
    println!("| Depth | {} |", warrant.depth());
    println!("| Max Depth | {} |", warrant.max_depth().unwrap_or(0));
    println!("| Issued At | `{}` |", warrant.issued_at().timestamp());
    println!("| Expires At | `{}` |", warrant.expires_at().timestamp());
    println!(
        "| Holder | `{}` |",
        hex::encode(warrant.authorized_holder().to_bytes())
    );
    println!(
        "| Issuer | `{}` |",
        hex::encode(warrant.issuer().to_bytes())
    );
    if let Some(hash) = warrant.parent_hash() {
        println!("| Parent Hash | `{}` |", hex::encode(hash));
    }
    println!();

    println!("**Payload CBOR ({} bytes):**", payload_bytes.len());
    println!("```");
    print_hex_block(payload_bytes);
    println!("```");
    println!();

    println!("**Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(sig_bytes));
    println!("```");
    println!();
}

fn print_hex_block(bytes: &[u8]) {
    let hex_str = hex::encode(bytes);
    for (i, chunk) in hex_str.as_bytes().chunks(64).enumerate() {
        if i > 0 {
            println!();
        }
        print!("{}", std::str::from_utf8(chunk).unwrap());
    }
    println!();
}

fn print_complete_envelope(warrant: &Warrant) {
    // Serialize the complete SignedWarrant envelope
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(warrant, &mut envelope_bytes).expect("Failed to serialize envelope");

    let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let base64_str = base64_engine.encode(&envelope_bytes);

    println!(
        "**Complete SignedWarrant Envelope ({} bytes):**",
        envelope_bytes.len()
    );
    println!("```cbor");
    println!("83                          # array(3)");
    println!("   01                       # envelope_version = 1");
    println!(
        "   58 {:02x}                    # payload ({} bytes)",
        warrant.payload_bytes().len(),
        warrant.payload_bytes().len()
    );
    println!("      {}...", &hex::encode(&warrant.payload_bytes()[..16]));
    println!("   82                       # signature array(2)");
    println!("      01                    # algorithm = Ed25519");
    println!("      58 40                 # signature bytes (64)");
    println!(
        "         {}...",
        &hex::encode(&warrant.signature().to_bytes()[..16])
    );
    println!("```");
    println!();

    println!("**Full Envelope CBOR (hex):**");
    println!("```");
    print_hex_block(&envelope_bytes);
    println!("```");
    println!();

    println!("**Base64 (URL-safe, no padding):**");
    println!("```");
    // Print base64 in chunks for readability
    for chunk in base64_str.as_bytes().chunks(76) {
        println!("{}", std::str::from_utf8(chunk).unwrap());
    }
    println!("```");
    println!();
}
