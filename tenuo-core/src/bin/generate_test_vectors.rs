//! Byte-exact test vector generator for Tenuo protocol specification
//!
//! Generates deterministic test vectors with fixed:
//! - Keys (from fixed seeds)
//! - Timestamps (fixed epoch values)
//! - Warrant IDs (fixed UUIDs)
//!
//! Run with: cargo run --example generate_test_vectors

use base64::Engine;
use std::collections::BTreeMap;
use tenuo::{
    constraints::{Constraint, ConstraintSet, Exact, Pattern},
    payload::WarrantPayload,
    warrant::{Warrant, WarrantId, WarrantType, WARRANT_VERSION},
    SigningKey,
};

// Fixed timestamps (2024-01-01T00:00:00Z and +1 hour)
const ISSUED_AT: u64 = 1704067200;
const EXPIRES_AT: u64 = 1704070800;

// Fixed warrant IDs (deterministic UUIDs)
const ID_A1: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
const ID_A2: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
const ID_A3_L0: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
const ID_A3_L1: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11];
const ID_A3_L2: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12];
const ID_A4: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
const ID_A5: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50];
const ID_A6: [u8; 16] = [0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60];

// Fixed timestamp window for PoP (floor(ISSUED_AT / 30) * 30)
const POP_TIMESTAMP_WINDOW: i64 = (ISSUED_AT as i64 / 30) * 30;
const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";

fn main() {
    // Fixed seeds for deterministic key generation
    let control_plane_seed: [u8; 32] = [0x01; 32];
    let orchestrator_seed: [u8; 32] = [0x02; 32];
    let worker_seed: [u8; 32] = [0x03; 32];
    let worker2_seed: [u8; 32] = [0x04; 32];

    let control_plane = SigningKey::from_bytes(&control_plane_seed);
    let orchestrator = SigningKey::from_bytes(&orchestrator_seed);
    let worker = SigningKey::from_bytes(&worker_seed);
    let worker2 = SigningKey::from_bytes(&worker2_seed);

    println!("# Tenuo Protocol Test Vectors");
    println!();
    println!("**Version:** 1.0  ");
    println!("**Generated:** 2024-01-01 (deterministic timestamps for reproducibility)  ");
    println!("**Specification:** [protocol-spec-v1.md](protocol-spec-v1.md)");
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
    println!("| Control Plane | `{:02x}{:02x}...{:02x}` (32×0x01) | `{}` |", 
        control_plane_seed[0], control_plane_seed[1], control_plane_seed[31],
        hex::encode(control_plane.public_key().to_bytes()));
    println!("| Orchestrator | `{:02x}{:02x}...{:02x}` (32×0x02) | `{}` |",
        orchestrator_seed[0], orchestrator_seed[1], orchestrator_seed[31],
        hex::encode(orchestrator.public_key().to_bytes()));
    println!("| Worker | `{:02x}{:02x}...{:02x}` (32×0x03) | `{}` |",
        worker_seed[0], worker_seed[1], worker_seed[31],
        hex::encode(worker.public_key().to_bytes()));
    println!("| Worker2 | `{:02x}{:02x}...{:02x}` (32×0x04) | `{}` |",
        worker2_seed[0], worker2_seed[1], worker2_seed[31],
        hex::encode(worker2.public_key().to_bytes()));
    println!();

    println!("**Full Seeds:**");
    println!("```");
    println!("Control Plane: {}", hex::encode(control_plane_seed));
    println!("Orchestrator:  {}", hex::encode(orchestrator_seed));
    println!("Worker:        {}", hex::encode(worker_seed));
    println!("Worker2:       {}", hex::encode(worker2_seed));
    println!("```");
    println!();

    println!("---");
    println!();
    println!("## Timestamps");
    println!();
    println!("| Name | Unix (seconds) | ISO 8601 |");
    println!("|------|----------------|----------|");
    println!("| `issued_at` | `{}` | `2024-01-01T00:00:00Z` |", ISSUED_AT);
    println!("| `expires_at` | `{}` | `2024-01-01T01:00:00Z` |", EXPIRES_AT);
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
    cs_l0.insert("path".to_string(), Constraint::Pattern(Pattern::new("/data/*").unwrap()));
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
    cs_l1.insert("path".to_string(), Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()));
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
    cs_l2.insert("path".to_string(), Constraint::Exact(Exact::new("/data/reports/q3.pdf")));
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
    cs_a4.insert("path".to_string(), Constraint::Pattern(Pattern::new("/data/*").unwrap()));
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
    
    println!("**Invalid Child Payload CBOR ({} bytes):**", warrant_a4.payload_bytes().len());
    println!("```");
    print_hex_block(warrant_a4.payload_bytes());
    println!("```");
    println!();
    
    println!("**Invalid Child Signature (64 bytes):**");
    println!("```");
    println!("{}", hex::encode(warrant_a4.signature().to_bytes()));
    println!("```");
    println!();
    
    println!("**Expected Error:** `child.issuer ({}) != parent.holder ({})`",
        &hex::encode(worker.public_key().to_bytes())[..16],
        &hex::encode(orchestrator.public_key().to_bytes())[..16]);
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
    println!("**Expected:** Reject with `warrant_expired` when `now > {}`", ISSUED_AT + 1);
    println!();

    // A.6: PoP Verification
    println!("---");
    println!();
    println!("## A.6 Proof-of-Possession");
    println!();

    let mut tools_a6 = BTreeMap::new();
    let mut cs_a6 = ConstraintSet::new();
    cs_a6.insert("path".to_string(), Constraint::Exact(Exact::new("/data/report.pdf")));
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
    println!("**Verification:** Signature MUST verify under Worker's public key: `{}`", 
        hex::encode(worker.public_key().to_bytes()));
    println!();

    // Implementation notes
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

    // A.7: Edge Cases
    println!("---");
    println!();
    println!("## A.7 Edge Cases");
    println!();
    println!("### A.7.1 Terminal Warrant (depth = max_depth)");
    println!();
    println!("**Scenario:** Warrant at maximum delegation depth cannot be further attenuated.");
    println!();
    println!("| Field | Value |");
    println!("|-------|-------|");
    println!("| depth | 3 |");
    println!("| max_depth | 3 |");
    println!();
    println!("**Expected:** Any attempt to attenuate this warrant MUST fail with `depth_exceeded`.");
    println!();
    println!("### A.7.2 Unknown Constraint Type");
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
    println!("### A.7.3 Invalid CBOR: Duplicate Map Keys");
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
    println!("### A.7.4 SRL Revocation");
    println!();
    println!("**Scenario:** Warrant ID appears in Signed Revocation List.");
    println!();
    println!("| warrant.id | SRL.revoked_ids |");
    println!("|------------|-----------------|");
    println!("| `019471f8-0000-7000-8000-000000000001` | `[..., \"019471f8-0000-7000-8000-000000000001\", ...]` |");
    println!();
    println!("**Expected:** Authorization MUST fail with `warrant_revoked`.");
    println!();

    println!("---");
    println!();
    println!("## References");
    println!();
    println!("- **[RFC 8032]** Josefsson, S., Liusvaara, I., \"Edwards-Curve Digital Signature Algorithm (EdDSA)\", January 2017. https://datatracker.ietf.org/doc/html/rfc8032");
    println!("- **[RFC 8949]** Bormann, C., Hoffman, P., \"Concise Binary Object Representation (CBOR)\", December 2020. https://datatracker.ietf.org/doc/html/rfc8949");
    println!("- **[protocol-spec-v1.md]** Tenuo Protocol Specification");
}

fn sign_payload(payload: &WarrantPayload, signing_key: &SigningKey) -> Warrant {
    // Serialize payload to CBOR
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes)
        .expect("Failed to serialize payload");

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
    println!("| Type | {} |", 
        if warrant.r#type() == WarrantType::Issuer { "Issuer" } else { "Execution" });
    println!("| Depth | {} |", warrant.depth());
    println!("| Max Depth | {} |", warrant.max_depth().unwrap_or(0));
    println!("| Issued At | `{}` |", warrant.issued_at().timestamp());
    println!("| Expires At | `{}` |", warrant.expires_at().timestamp());
    println!("| Holder | `{}` |", hex::encode(warrant.authorized_holder().to_bytes()));
    println!("| Issuer | `{}` |", hex::encode(warrant.issuer().to_bytes()));
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
    ciborium::ser::into_writer(warrant, &mut envelope_bytes)
        .expect("Failed to serialize envelope");
    
    let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let base64_str = base64_engine.encode(&envelope_bytes);
    
    println!("**Complete SignedWarrant Envelope ({} bytes):**", envelope_bytes.len());
    println!("```cbor");
    println!("83                          # array(3)");
    println!("   01                       # envelope_version = 1");
    println!("   58 {:02x}                    # payload ({} bytes)", warrant.payload_bytes().len(), warrant.payload_bytes().len());
    println!("      {}...", &hex::encode(&warrant.payload_bytes()[..16]));
    println!("   82                       # signature array(2)");
    println!("      01                    # algorithm = Ed25519");
    println!("      58 40                 # signature bytes (64)");
    println!("         {}...", &hex::encode(&warrant.signature().to_bytes()[..16]));
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
