//! Tests for chain verification invariants (I1-I5).
//!
//! These tests verify that the chain verifier correctly rejects chains
//! that violate the cryptographic invariants defined in wire-format-spec.md.
//!
//! The tests construct "forged" warrants by bypassing the builder's
//! enforcement, to ensure the verifier provides defense-in-depth.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use tenuo::{
    constraints::ConstraintSet,
    crypto::SigningKey,
    payload::WarrantPayload,
    planes::DataPlane,
    warrant::{Warrant, WarrantId, WarrantType},
};

/// Helper to create a forged warrant from a payload and signing key.
/// This bypasses the builder's invariant checks.
fn forge_warrant(payload: WarrantPayload, signing_key: &SigningKey) -> Warrant {
    // Serialize payload to bytes
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).unwrap();

    // Create signature preimage: envelope_version || payload_bytes
    let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
    preimage.push(1u8); // envelope_version
    preimage.extend_from_slice(&payload_bytes);

    // Sign
    let signature = signing_key.sign(&preimage);

    Warrant {
        payload,
        signature,
        payload_bytes,
        envelope_version: 1,
    }
}

/// Compute SHA256 hash of warrant's payload bytes
fn hash_payload(warrant: &Warrant) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&warrant.payload_bytes);
    hasher.finalize().into()
}

/// Helper to get expires_at as u64 from a warrant
fn expires_at_secs(warrant: &Warrant) -> u64 {
    warrant.payload.expires_at
}

// =============================================================================
// I1: Delegation Authority - child.issuer == parent.holder
// =============================================================================

/// Test: Verifier rejects chain where child.issuer != parent.holder (I1 violation)
///
/// This simulates an attacker who:
/// 1. Sees a legitimate warrant with holder = Victim
/// 2. Creates their own child warrant claiming to delegate from it
/// 3. Signs it with their own key (Attacker)
///
/// The verifier MUST reject this because child.issuer (Attacker) != parent.holder (Victim).
#[test]
fn test_verify_chain_rejects_i1_violation_wrong_issuer() {
    let root_keypair = SigningKey::generate();
    let victim_keypair = SigningKey::generate();
    let attacker_keypair = SigningKey::generate();

    // Create legitimate parent (root warrant)
    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Attenuate to victim (legitimate)
    let victim_warrant = parent
        .attenuate()
        .inherit_all()
        .authorized_holder(victim_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Attacker forges a child warrant:
    // - parent_hash matches victim_warrant (correct linkage)
    // - issuer = attacker (NOT victim, violates I1)
    // - signed by attacker
    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: victim_warrant.payload.tools.clone(),
        holder: attacker_keypair.public_key(), // Attacker claims to be holder
        issuer: attacker_keypair.public_key(), // VIOLATION: issuer != parent.holder
        issued_at: victim_warrant.payload.issued_at,
        expires_at: expires_at_secs(&victim_warrant), // Within parent's TTL
        max_depth: victim_warrant.payload.max_depth,
        depth: victim_warrant.depth() + 1,
        parent_hash: Some(hash_payload(&victim_warrant)), // Correct linkage!
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &attacker_keypair);

    // Verify the forgery is internally consistent
    assert_eq!(
        forged_child.parent_hash(),
        Some(&hash_payload(&victim_warrant)),
        "Forged child should have correct parent_hash"
    );
    assert_ne!(
        forged_child.issuer(),
        victim_warrant.authorized_holder(),
        "Forged child should have wrong issuer (the attack)"
    );

    // Set up verifier with trusted root
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), victim_warrant.clone(), forged_child]);
    assert!(result.is_err(), "Chain with I1 violation must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I1") || err.contains("issuer") || err.contains("holder"),
        "Error should mention I1, issuer, or holder: {}",
        err
    );

    println!("✅ I1 violation correctly rejected: {}", err);
}

// =============================================================================
// I3: TTL Monotonicity - child.expires_at <= parent.expires_at
// =============================================================================

/// Test: Verifier rejects chain where child.expires_at > parent.expires_at (I3 violation)
///
/// This simulates an attacker who:
/// 1. Receives a warrant with limited TTL
/// 2. Creates a child warrant with a longer expiration
///
/// The verifier MUST reject this because a child cannot outlive its parent.
#[test]
fn test_verify_chain_rejects_i3_violation_ttl_extended() {
    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Create parent with short TTL (1 hour)
    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Forge a child with LONGER TTL (violates I3)
    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: parent.payload.tools.clone(),
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(), // Correct issuer
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent) + 86400, // VIOLATION: 1 day longer than parent!
        max_depth: parent.payload.max_depth,
        depth: parent.depth() + 1,
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    // Sign with root key (pretending to be legitimate)
    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Verify the forgery setup
    assert!(
        expires_at_secs(&forged_child) > expires_at_secs(&parent),
        "Forged child should outlive parent (the attack)"
    );

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(result.is_err(), "Chain with I3 violation must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I3") || err.contains("expire") || err.contains("TTL"),
        "Error should mention I3, expiration, or TTL: {}",
        err
    );

    println!("✅ I3 violation correctly rejected: {}", err);
}

// =============================================================================
// I4: Capability Monotonicity - child.tools ⊆ parent.tools
// =============================================================================

/// Test: Verifier rejects chain where child has tools not in parent (I4 violation)
///
/// This simulates an attacker who:
/// 1. Receives a warrant for tool "read"
/// 2. Creates a child warrant that adds tool "write"
///
/// The verifier MUST reject this because capabilities can only narrow.
#[test]
fn test_verify_chain_rejects_i4_violation_tool_escalation() {
    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Create parent with only "read" capability
    let parent = Warrant::builder()
        .capability("read", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Forge a child that adds "write" (violates I4)
    let mut escalated_tools = BTreeMap::new();
    escalated_tools.insert("read".to_string(), ConstraintSet::new());
    escalated_tools.insert("write".to_string(), ConstraintSet::new()); // ESCALATION!

    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: escalated_tools,
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(), // Correct issuer
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: parent.payload.max_depth,
        depth: parent.depth() + 1,
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Verify the escalation
    assert!(
        forged_child.tools().contains(&"write".to_string()),
        "Forged child should have escalated tools"
    );
    assert!(
        !parent.tools().contains(&"write".to_string()),
        "Parent should not have write tool"
    );

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(result.is_err(), "Chain with I4 violation must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I4")
            || err.contains("capability")
            || err.contains("tool")
            || err.contains("monoton"),
        "Error should mention I4, capability, tool, or monotonicity: {}",
        err
    );

    println!("✅ I4 violation correctly rejected: {}", err);
}

/// Test: Verifier rejects chain where child has wider constraint (I4 violation)
///
/// This simulates constraint weakening: parent has Range::max(100),
/// child tries Range::max(1000).
#[test]
fn test_verify_chain_rejects_i4_violation_constraint_widening() {
    use tenuo::constraints::Range;

    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Create parent with constrained capability
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("amount", Range::max(100.0).unwrap());
    let parent = Warrant::builder()
        .capability("transfer", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Forge a child with WIDER constraint (violates I4)
    let mut widened_tools = BTreeMap::new();
    let mut widened_constraints = ConstraintSet::new();
    widened_constraints.insert("amount", Range::max(1000.0).unwrap()); // WIDER!
    widened_tools.insert("transfer".to_string(), widened_constraints);

    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: widened_tools,
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(),
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: parent.payload.max_depth,
        depth: parent.depth() + 1,
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(
        result.is_err(),
        "Chain with I4 constraint widening must be rejected"
    );
    let err = result.unwrap_err().to_string();

    println!("✅ I4 constraint widening correctly rejected: {}", err);
}

// =============================================================================
// I2: Depth Monotonicity - depth increments correctly
// =============================================================================

/// Test: Verifier rejects chain where depth doesn't increment (I2 violation)
#[test]
fn test_verify_chain_rejects_i2_violation_depth_not_incremented() {
    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    assert_eq!(parent.depth(), 0);

    // Forge a child with SAME depth (should be parent.depth + 1)
    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: parent.payload.tools.clone(),
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(),
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: parent.payload.max_depth,
        depth: 0, // VIOLATION: should be 1
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(
        result.is_err(),
        "Chain with I2 depth violation must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I2") || err.contains("depth"),
        "Error should mention I2 or depth: {}",
        err
    );

    println!(
        "✅ I2 violation (depth not incremented) correctly rejected: {}",
        err
    );
}

/// Test: Verifier rejects chain where depth exceeds max_depth (I2 violation)
#[test]
fn test_verify_chain_rejects_i2_violation_depth_exceeds_max() {
    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Create parent with max_depth = 1 (can only delegate once)
    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .max_depth(1) // Only 1 level of delegation allowed
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    assert_eq!(parent.depth(), 0);
    assert_eq!(parent.max_depth(), Some(1));

    // Forge a child at depth 2 (exceeds max_depth of 1)
    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: parent.payload.tools.clone(),
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(),
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: 1,
        depth: 2, // VIOLATION: exceeds max_depth
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(
        result.is_err(),
        "Chain with depth exceeding max_depth must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I2") || err.contains("depth") || err.contains("max"),
        "Error should mention I2, depth, or max: {}",
        err
    );

    println!(
        "✅ I2 violation (depth exceeds max) correctly rejected: {}",
        err
    );
}

// =============================================================================
// I5: Cryptographic Linkage - signature and parent_hash
// =============================================================================

/// Test: Verifier rejects chain with invalid signature (I5 violation)
#[test]
fn test_verify_chain_rejects_i5_violation_bad_signature() {
    let root_keypair = SigningKey::generate();
    let attacker_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Create a valid-looking payload but sign with WRONG key
    let payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: parent.payload.tools.clone(),
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(), // Claims to be signed by root_keypair
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: parent.payload.max_depth,
        depth: parent.depth() + 1,
        parent_hash: Some(hash_payload(&parent)),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    // Sign with ATTACKER key (but payload claims issuer = root_keypair)
    let forged_child = forge_warrant(payload, &attacker_keypair);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail (signature verification will fail)
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(
        result.is_err(),
        "Chain with invalid signature must be rejected"
    );
    let err = result.unwrap_err().to_string();

    println!(
        "✅ I5 violation (bad signature) correctly rejected: {}",
        err
    );
}

/// Test: Verifier rejects chain with wrong parent_hash (I5 violation)
#[test]
fn test_verify_chain_rejects_i5_violation_wrong_parent_hash() {
    let root_keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Create a child with WRONG parent_hash
    let wrong_hash: [u8; 32] = [0xDE; 32]; // Garbage hash

    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: parent.payload.tools.clone(),
        holder: child_keypair.public_key(),
        issuer: root_keypair.public_key(),
        issued_at: parent.payload.issued_at,
        expires_at: expires_at_secs(&parent),
        max_depth: parent.payload.max_depth,
        depth: parent.depth() + 1,
        parent_hash: Some(wrong_hash), // WRONG!
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_child = forge_warrant(forged_payload, &root_keypair);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // Chain verification MUST fail
    let result = data_plane.verify_chain(&[parent.clone(), forged_child]);
    assert!(
        result.is_err(),
        "Chain with wrong parent_hash must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("I5") || err.contains("parent_hash") || err.contains("chain broken"),
        "Error should mention I5, parent_hash, or chain broken: {}",
        err
    );

    println!(
        "✅ I5 violation (wrong parent_hash) correctly rejected: {}",
        err
    );
}

// =============================================================================
// Combined attack scenarios
// =============================================================================

/// Test: Sophisticated attack - all fields look correct except I1
///
/// This is the most dangerous attack: everything passes EXCEPT the
/// fundamental rule that only the holder can delegate.
#[test]
fn test_sophisticated_i1_attack() {
    let root_keypair = SigningKey::generate();
    let legitimate_holder = SigningKey::generate();
    let attacker = SigningKey::generate();
    let recipient = SigningKey::generate();

    // Create root warrant
    let root = Warrant::builder()
        .capability("sensitive_tool", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .authorized_holder(root_keypair.public_key())
        .build(&root_keypair)
        .unwrap();

    // Delegate to legitimate holder
    let legitimate_warrant = root
        .attenuate()
        .inherit_all()
        .authorized_holder(legitimate_holder.public_key())
        .build(&root_keypair)
        .unwrap();

    // Attacker forges a delegation FROM legitimate_warrant TO recipient
    // - Correct parent_hash (attacker knows the warrant)
    // - Correct depth increment
    // - Correct TTL narrowing
    // - Correct capability inheritance
    // BUT: signed by attacker (not legitimate_holder)
    let forged_payload = WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::new_random(),
        tools: legitimate_warrant.payload.tools.clone(),
        holder: recipient.public_key(),
        issuer: attacker.public_key(), // ATTACK: attacker claims to be issuer
        issued_at: legitimate_warrant.payload.issued_at,
        expires_at: expires_at_secs(&legitimate_warrant) - 60, // Even narrower TTL!
        max_depth: legitimate_warrant.payload.max_depth,
        depth: legitimate_warrant.depth() + 1, // Correct
        parent_hash: Some(hash_payload(&legitimate_warrant)), // Correct!
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        trust_level: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let forged_delegation = forge_warrant(forged_payload, &attacker);

    // Set up verifier
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", root_keypair.public_key());

    // This MUST fail - attacker cannot delegate legitimate_holder's authority
    let result =
        data_plane.verify_chain(&[root.clone(), legitimate_warrant.clone(), forged_delegation]);
    assert!(
        result.is_err(),
        "Sophisticated I1 attack must be rejected! Attacker cannot delegate others' authority."
    );

    println!("✅ Sophisticated I1 attack correctly rejected");
}
