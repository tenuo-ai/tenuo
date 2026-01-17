//! Test Vector Validation
//!
//! Validates that our implementation produces byte-exact output matching
//! the test vectors in docs/spec/test-vectors.md
//!
//! These tests ensure the specification and implementation stay in sync.

use std::collections::BTreeMap;
use tenuo::*;

// Fixed timestamps from spec (2024-01-01T00:00:00Z and +1 hour)
const ISSUED_AT: u64 = 1704067200;
const EXPIRES_AT: u64 = 1704070800;

// Future timestamps for tests that need to verify against live verifier
// (2030-01-01T00:00:00Z and +1 hour)
const FUTURE_ISSUED_AT: u64 = 1893456000;
const FUTURE_EXPIRES_AT: u64 = 1893459600;

// Fixed warrant IDs (deterministic UUIDs from spec)
const ID_A1: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
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
const ID_A5: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50,
];
const ID_A6: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60,
];
const ID_A7: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70,
];
const ID_A10_PARENT: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90,
];
const ID_A10_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91,
];
const ID_A11_PARENT: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92,
];
const ID_A11_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93,
];
const ID_A12_PARENT: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0,
];
const ID_A12_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA1,
];
const ID_A13_PARENT: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0,
];
const ID_A13_CHILD: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB1,
];
const ID_A14: [u8; 16] = [
    0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
];

// Fixed seeds for deterministic key generation (from spec)
fn control_plane_key() -> SigningKey {
    SigningKey::from_bytes(&[0x01; 32])
}

fn orchestrator_key() -> SigningKey {
    SigningKey::from_bytes(&[0x02; 32])
}

fn worker_key() -> SigningKey {
    SigningKey::from_bytes(&[0x03; 32])
}

fn worker2_key() -> SigningKey {
    SigningKey::from_bytes(&[0x04; 32])
}

fn attacker_key() -> SigningKey {
    SigningKey::from_bytes(&[0xFF; 32])
}

/// Test Vector A.1: Minimal Valid Execution Warrant
#[test]
fn test_vector_a1_minimal_execution_warrant() {
    // Expected bytes from docs/spec/test-vectors.md A.1
    let expected_payload_hex = "\
aa00010150019471f800007000800000000000000102696578656375\
74696f6e03a169726561645f66696c65a16b636f6e73747261696e7473a16470\
6174688210f604820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4\
ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72\
ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008031200";

    let expected_sig_hex = "\
eb112ef8cc34cace169bc0f52889e07096c0149980d1b2ed7e7b5c97a4143e8f\
599c47dbc21172320de707635c17d2d05447635d38a013698b8e02a5b7828200";

    // Regenerate the warrant
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();

    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert("path".to_string(), Constraint::Wildcard(Wildcard));
    tools.insert("read_file".to_string(), cs);

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A1),
        tools,
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

    let warrant = sign_payload(&payload, &control_plane);

    // Verify byte-exact match
    assert_eq!(
        hex::encode(warrant.payload_bytes()),
        expected_payload_hex,
        "A.1 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant.signature().to_bytes()),
        expected_sig_hex,
        "A.1 signature mismatch"
    );
}

/// Test Vector A.3 Level 0: 3-Level Chain Root
#[test]
fn test_vector_a3_level0_chain_root() {
    let expected_payload_hex = "\
aa00010150019471f80000700080000000000000100269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56\
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd\
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592\
0080071a65920e9008031200";

    let expected_sig_hex = "\
941d60f6611abb8e079360160e06135fcf8de72d0fec056fdfc586b342f8a35c\
2affb7c727011da5707462a16b970ad60fdc34225accd9cc0bc44f271914e50d";

    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();

    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools.insert("read_file".to_string(), cs);

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L0),
        tools,
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

    let warrant = sign_payload(&payload, &control_plane);

    assert_eq!(
        hex::encode(warrant.payload_bytes()),
        expected_payload_hex,
        "A.3 Level 0 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant.signature().to_bytes()),
        expected_sig_hex,
        "A.3 Level 0 signature mismatch"
    );
}

/// Test Vector A.3 Level 1: First Attenuation
#[test]
fn test_vector_a3_level1_first_attenuation() {
    let expected_payload_hex = "\
ab00010150019471f80000700080000000000000110269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed\
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105\
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b\
8fc9b394061a65920080071a65920e900803099820184118cc18d61821189b05\
189318c01825186318e5182518dc183418fb18d618e01836188218d7186018c9\
18a81879183818d618aa1884189418d518c518fa1201";

    let expected_sig_hex = "\
e54c8ae27e4d852656e0d596556d2011953630663a4c93a9c7ee2407b89a2e71\
d82bec137f09e1b7e4e4768bf8f19d0df235e22762650e7bd588c3ead8d1790c";

    // Need Level 0 parent for parent_hash
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();

    // Build Level 0
    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L0),
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

    // Build Level 1
    let mut tools_l1 = BTreeMap::new();
    let mut cs_l1 = ConstraintSet::new();
    cs_l1.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_l1.insert("read_file".to_string(), cs_l1);

    let payload_l1 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L1),
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

    assert_eq!(
        hex::encode(warrant_l1.payload_bytes()),
        expected_payload_hex,
        "A.3 Level 1 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant_l1.signature().to_bytes()),
        expected_sig_hex,
        "A.3 Level 1 signature mismatch"
    );
}

/// Test Vector A.3 Level 2: Most Restricted
#[test]
fn test_vector_a3_level2_most_restricted() {
    let expected_payload_hex = "\
ab00010150019471f80000700080000000000000120269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
01a16576616c7565742f646174612f7265706f7274732f71332e706466048201\
5820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbda\
be7c0582015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636\
c14614ac8737d1061a65920080071a65920e900803099820182b18b2189618e5\
187d18b0182c18e718571218df18d4181a187b189f18a5182d18331835187c08\
1862183518b518ad188f18751890184f186c181818f91202";

    let expected_sig_hex = "\
3df67259e4190b93095ad146a5b0b6d2c45e8d9115031628f75b76ce17dab1aa\
37a55509ebc16963ff7b508c492402e0e44f0a455900741efde312cb19ae850f";

    // Build full chain to get correct parent_hash
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();
    let worker2 = worker2_key();

    // Level 0
    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L0),
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

    let payload_l1 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L1),
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

    let payload_l2 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L2),
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

    assert_eq!(
        hex::encode(warrant_l2.payload_bytes()),
        expected_payload_hex,
        "A.3 Level 2 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant_l2.signature().to_bytes()),
        expected_sig_hex,
        "A.3 Level 2 signature mismatch"
    );
}

/// Test Vector A.5: Expired Warrant
#[test]
fn test_vector_a5_expired_warrant() {
    let expected_payload_hex = "\
aa00010150019471f80000700080000000000000500269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
10f604820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25d\
f60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf\
1d94121bf3748801b40f6f5c061a65920080071a6592008108031200";

    let expected_sig_hex = "\
c270f5d1468a09c84ca2de9040013c759eb10586b9373baf8486ad34be643be9\
8a5b97f08fddc66f8add76e20989b1b8620c113ebcb793e27d793f1ae152ff0a";

    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();

    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert("path".to_string(), Constraint::Wildcard(Wildcard));
    tools.insert("read_file".to_string(), cs);

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A5),
        tools,
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

    let warrant = sign_payload(&payload, &control_plane);

    assert_eq!(
        hex::encode(warrant.payload_bytes()),
        expected_payload_hex,
        "A.5 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant.signature().to_bytes()),
        expected_sig_hex,
        "A.5 signature mismatch"
    );

    // Verify it's actually expired
    assert!(
        warrant.is_expired(),
        "A.5 warrant should be expired (TTL was 1 second)"
    );
}

/// Test Vector A.6: Proof-of-Possession
#[test]
fn test_vector_a6_proof_of_possession() {
    let expected_payload_hex = "\
aa00010150019471f80000700080000000000000600269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
01a16576616c7565702f646174612f7265706f72742e7064660482015820ed49\
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10582\
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4\
0f6f5c061a65920080071a65920e9008011200";

    let expected_sig_hex = "\
af7ef8bd6527842e87d8db91c3614e93bc1ecabb58e99f87d11511bfcbce0605\
fa488b02388830720efe618f35470595e04176714cd4d15a294c9971789c2209";

    let expected_pop_sig_hex = "\
84f11618ec5b7234287e3fc1dbb6f8c18de9aab1ad60d8bc3e26ba293814a062\
0cae3be2c96baf7698ef959105231d2b4eee57fa247a56c11170d100e66d6f0a";

    let control_plane = control_plane_key();
    let worker = worker_key();

    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/report.pdf")),
    );
    tools.insert("read_file".to_string(), cs);

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A6),
        tools,
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

    let warrant = sign_payload(&payload, &control_plane);

    assert_eq!(
        hex::encode(warrant.payload_bytes()),
        expected_payload_hex,
        "A.6 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant.signature().to_bytes()),
        expected_sig_hex,
        "A.6 signature mismatch"
    );

    // Generate PoP signature
    const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";
    const POP_TIMESTAMP_WINDOW: i64 = (ISSUED_AT as i64 / 30) * 30;

    let pop_challenge = (
        warrant.id().to_string(),
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

    assert_eq!(
        hex::encode(pop_signature.to_bytes()),
        expected_pop_sig_hex,
        "A.6 PoP signature mismatch"
    );

    // Verify PoP signature
    assert!(
        worker
            .public_key()
            .verify(&pop_preimage, &pop_signature)
            .is_ok(),
        "A.6 PoP signature should verify"
    );
}

/// Test Vector A.2: Minimal Issuer Warrant
#[test]
fn test_vector_a2_minimal_issuer_warrant() {
    const ID_A2: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];

    let expected_payload_hex = "\
ac00010150019471f8000070008000000000000002026669737375657203a004\
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b\
8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d9412\
1bf3748801b40f6f5c061a65920080071a65920e9008050b8269726561645f66\
696c656a77726974655f66696c650d031200";

    let expected_sig_hex = "\
641e6ceab4abc76ff9bd5967d09808fe0a8efc65b7c918af11acfb118c941587\
47f8b02f0459dacb052ce5f1eda5d678e2dff2ced1b948d6123deeb48e25500f";

    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Issuer,
        id: warrant::WarrantId::from_bytes(ID_A2),
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

    let warrant = sign_payload(&payload, &control_plane);

    assert_eq!(
        hex::encode(warrant.payload_bytes()),
        expected_payload_hex,
        "A.2 payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(warrant.signature().to_bytes()),
        expected_sig_hex,
        "A.2 signature mismatch"
    );

    // Verify it's an issuer warrant
    assert_eq!(
        warrant.r#type(),
        warrant::WarrantType::Issuer,
        "A.2 should be an Issuer warrant"
    );
}

/// Test Vector A.4: Invalid Chain (I1 Violation)
/// Verifies that chains with wrong issuer are properly detected
#[test]
fn test_vector_a4_invalid_chain_i1_violation() {
    const ID_A4: [u8; 16] = [
        0x01, 0x94, 0x71, 0xf8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40,
    ];

    let expected_invalid_payload_hex = "\
ab00010150019471f80000700080000000000000400269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e672f646174612f2a0482015820ca93ac1705187071d6\
7b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0582015820ed4928c6\
28d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1061a6592\
0080071a65920e900803099820184118cc18d61821189b05189318c018251863\
18e5182518dc183418fb18d618e01836188218d7186018c918a81879183818d6\
18aa1884189418d518c518fa1201";

    let expected_invalid_sig_hex = "\
8cd9457fec06791ab587aea5cf3b19437630e60d7adbe8cfb56bfce692ea2874\
bb9f3162645407a6b58316e2eb2d29ceb651b4f2582e083e45010a11e5774909";

    // Build valid Level 0 (parent)
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();
    let worker2 = worker2_key();

    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L0),
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
        required_approvers: None,
        min_approvals: None,
    };

    let warrant_l0 = sign_payload(&payload_l0, &control_plane);
    let parent_hash = sha256(warrant_l0.payload_bytes());

    // Build INVALID child: signed by Worker (wrong), should be Orchestrator
    let payload_invalid = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A4),
        tools: tools_l0,
        holder: worker2.public_key(),
        issuer: worker.public_key(), // WRONG: Should be orchestrator (parent's holder)
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash),
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

    let invalid_warrant = sign_payload(&payload_invalid, &worker);

    // Verify byte-exact match with test vector
    assert_eq!(
        hex::encode(invalid_warrant.payload_bytes()),
        expected_invalid_payload_hex,
        "A.4 invalid payload bytes mismatch"
    );
    assert_eq!(
        hex::encode(invalid_warrant.signature().to_bytes()),
        expected_invalid_sig_hex,
        "A.4 invalid signature mismatch"
    );

    // Verify that the I1 invariant is violated:
    // child.issuer != parent.holder
    assert_ne!(
        invalid_warrant.issuer(),
        warrant_l0.authorized_holder(),
        "A.4 should demonstrate I1 violation: child.issuer != parent.holder"
    );
}

/// Test Vector A.8: WarrantStack Serialization
#[test]
fn test_vector_a8_warrant_stack_serialization() {
    // Expected WarrantStack CBOR (883 bytes) - first 64 hex chars for verification
    let expected_stack_prefix = "83830158acaa00010150019471f8000070008000000000000010";

    // Build the full 3-level chain
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();
    let worker2 = worker2_key();

    // Level 0
    let mut tools_l0 = BTreeMap::new();
    let mut cs_l0 = ConstraintSet::new();
    cs_l0.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_l0.insert("read_file".to_string(), cs_l0);

    let payload_l0 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L0),
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

    let payload_l1 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L1),
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

    let payload_l2 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A3_L2),
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

    // Verify size (883 bytes per spec)
    assert_eq!(
        stack_bytes.len(),
        883,
        "A.8 WarrantStack should be 883 bytes"
    );

    // Verify prefix matches expected
    let stack_hex = hex::encode(&stack_bytes);
    assert!(
        stack_hex.starts_with(expected_stack_prefix),
        "A.8 WarrantStack prefix mismatch.\nExpected prefix: {}\nGot: {}",
        expected_stack_prefix,
        &stack_hex[..expected_stack_prefix.len().min(stack_hex.len())]
    );

    // Verify structure: outer array has 3 elements
    assert_eq!(stack_bytes[0], 0x83, "A.8 should start with array(3)");

    // Verify round-trip deserialization
    let deserialized: Vec<Warrant> =
        ciborium::de::from_reader(&stack_bytes[..]).expect("Failed to deserialize WarrantStack");
    assert_eq!(
        deserialized.len(),
        3,
        "A.8 should deserialize to 3 warrants"
    );

    // Verify chain invariants
    assert_eq!(
        deserialized[1].issuer(),
        deserialized[0].authorized_holder(),
        "A.8 Level 1 issuer should be Level 0 holder"
    );
    assert_eq!(
        deserialized[2].issuer(),
        deserialized[1].authorized_holder(),
        "A.8 Level 2 issuer should be Level 1 holder"
    );
}

/// Test Vector A.7: Extensions with CBOR Values
#[test]
fn test_vector_a7_extensions_with_cbor() {
    let expected_payload_hex = "\
ab00010150019471f80000700080000000000000700269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
01a16576616c7565702f646174612f7265706f72742e70646604820158208139\
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582\
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4\
0f6f5c061a65920080071a65920e9008030aa273636f6d2e6578616d706c652e\
62696c6c696e67983818a31864187418651861186d186b186d186c182d187218\
65187318651861187218631868186718701872186f186a186518631874186e18\
771861187218721861186e1874182d18731879187318741865186d186b186318\
6f18731874185f18631865186e187418651872181910186974636f6d2e657861\
6d706c652e74726163655f69648e186d1872186518711875186518731874182d\
183118321833183418351200";

    let expected_sig_hex = "\
20ee2c6299dca2ade227cdee2272c09c696fd888547c7b9f03b2d5c0d4e15743\
086212bf85612ba5d84012276ea55ec3696598991bc93bd3a2ef496099a82506";

    // Create keys (same seeds as generator)
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();

    // Create extensions with CBOR-encoded values
    let mut extensions = BTreeMap::new();

    // Extension 1: Simple string (CBOR-encoded)
    let trace_id = "request-12345";
    let mut trace_id_bytes = Vec::new();
    ciborium::ser::into_writer(&trace_id, &mut trace_id_bytes).expect("Failed to encode trace_id");
    extensions.insert("com.example.trace_id".to_string(), trace_id_bytes);

    // Extension 2: Structured data (CBOR-encoded)
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
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

    // Create payload
    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert(
        "path".to_string(),
        Constraint::Exact(Exact::new("/data/report.pdf")),
    );
    tools.insert("read_file".to_string(), cs);

    let payload_a7 = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A7),
        tools,
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

    // Sign payload
    let warrant_a7 = sign_payload(&payload_a7, &control_plane);

    // Verify byte-exact match
    assert_eq!(
        hex::encode(warrant_a7.payload_bytes()),
        expected_payload_hex,
        "A.7 payload bytes should match test vector"
    );
    assert_eq!(
        hex::encode(warrant_a7.signature().to_bytes()),
        expected_sig_hex,
        "A.7 signature should match test vector"
    );

    // Verify extensions round-trip
    let extensions_map = &warrant_a7.payload.extensions;
    assert_eq!(extensions_map.len(), 2, "A.7 should have 2 extensions");
    assert!(
        extensions_map.contains_key("com.example.trace_id"),
        "A.7 should have trace_id extension"
    );
    assert!(
        extensions_map.contains_key("com.example.billing"),
        "A.7 should have billing extension"
    );

    // Verify extension values decode correctly
    let trace_id_decoded: String =
        ciborium::de::from_reader(&extensions_map["com.example.trace_id"][..])
            .expect("Failed to decode trace_id");
    assert_eq!(
        trace_id_decoded, "request-12345",
        "A.7 trace_id should match"
    );

    let billing_decoded: BillingTag =
        ciborium::de::from_reader(&extensions_map["com.example.billing"][..])
            .expect("Failed to decode billing");
    assert_eq!(
        billing_decoded.team, "ml-research",
        "A.7 billing.team should match"
    );
    assert_eq!(
        billing_decoded.project, "warrant-system",
        "A.7 billing.project should match"
    );
    assert_eq!(
        billing_decoded.cost_center, 4201,
        "A.7 billing.cost_center should match"
    );

    // Verify CBOR hex encoding matches documented values
    let expected_trace_id_cbor = "6d726571756573742d3132333435";
    let expected_billing_cbor = "a3647465616d6b6d6c2d72657365617263686770726f6a6563746e77617272616e742d73797374656d6b636f73745f63656e746572191069";

    assert_eq!(
        hex::encode(&extensions_map["com.example.trace_id"]),
        expected_trace_id_cbor,
        "A.7 trace_id CBOR encoding should match"
    );
    assert_eq!(
        hex::encode(&extensions_map["com.example.billing"]),
        expected_billing_cbor,
        "A.7 billing CBOR encoding should match"
    );
}

/// Test Vector A.10: Invalid Depth Monotonicity (I2 Violation)
/// Uses future timestamps so verifier doesn't reject on expiration
#[test]
fn test_vector_a10_invalid_depth_monotonicity() {
    // Create keys
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();

    // Create parent warrant (depth=0) with FUTURE timestamps
    let mut tools_parent = BTreeMap::new();
    let mut cs_parent = ConstraintSet::new();
    cs_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_parent.insert("read_file".to_string(), cs_parent);

    let payload_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A10_PARENT),
        tools: tools_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
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

    let warrant_parent = sign_payload(&payload_parent, &control_plane);
    let parent_hash = sha256(warrant_parent.payload_bytes());

    // Create child with WRONG depth (2 instead of 1)
    let mut tools_child = BTreeMap::new();
    let mut cs_child = ConstraintSet::new();
    cs_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_child.insert("read_file".to_string(), cs_child);

    let payload_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A10_CHILD),
        tools: tools_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        max_depth: 3,
        depth: 2, // WRONG: should be 1
        parent_hash: Some(parent_hash),
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

    let warrant_child = sign_payload(&payload_child, &orchestrator);

    // Verify the depth violation
    assert_eq!(warrant_parent.payload.depth, 0, "A.10 parent depth");
    assert_eq!(warrant_child.payload.depth, 2, "A.10 child depth (wrong)");
    assert_ne!(
        warrant_child.payload.depth,
        warrant_parent.payload.depth + 1,
        "A.10 child should have WRONG depth (I2 violation)"
    );

    // Verify that the verifier REJECTS this chain
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", control_plane.public_key());

    let result = data_plane.verify_chain(&[warrant_parent, warrant_child]);
    assert!(
        result.is_err(),
        "A.10 verify_chain should REJECT depth violation"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("depth") || err_msg.contains("Depth"),
        "A.10 error should mention depth: {}",
        err_msg
    );
}

/// Test Vector A.11: Invalid Capability Monotonicity (I4 Violation)
/// Uses future timestamps so verifier doesn't reject on expiration
#[test]
fn test_vector_a11_invalid_capability_monotonicity() {
    // Create keys
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();

    // Create parent warrant with NARROW constraint
    let mut tools_parent = BTreeMap::new();
    let mut cs_parent = ConstraintSet::new();
    cs_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()), // Narrow
    );
    tools_parent.insert("read_file".to_string(), cs_parent);

    let payload_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A11_PARENT),
        tools: tools_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
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

    let warrant_parent = sign_payload(&payload_parent, &control_plane);
    let parent_hash = sha256(warrant_parent.payload_bytes());

    // Create child with BROADER constraint (invalid!)
    let mut tools_child = BTreeMap::new();
    let mut cs_child = ConstraintSet::new();
    cs_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()), // TOO BROAD!
    );
    tools_child.insert("read_file".to_string(), cs_child);

    let payload_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A11_CHILD),
        tools: tools_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash),
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

    let warrant_child = sign_payload(&payload_child, &orchestrator);

    // Verify that the verifier REJECTS this chain
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", control_plane.public_key());

    let result = data_plane.verify_chain(&[warrant_parent, warrant_child]);
    assert!(
        result.is_err(),
        "A.11 verify_chain should REJECT capability expansion"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("attenuation")
            || err_msg.contains("Pattern")
            || err_msg.contains("expand"),
        "A.11 error should mention attenuation/pattern issue: {}",
        err_msg
    );
}

/// Test Vector A.12: Invalid Parent Hash (I5 Violation)
#[test]
fn test_vector_a12_invalid_parent_hash() {
    // Parent warrant
    let expected_parent_payload_hex = "\
aa00010150019471f80000700080000000000000a00269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56\
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd\
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592\
0080071a65920e9008031200";

    let expected_parent_sig_hex = "\
4e3bc36f5f718cda1f26f1e711d40b208c801dde6d8d5f33426241075f8dd1a2\
1c3e28f24f2787b364f6f983e54cb9e7c60e403cb89e485f2b0e336c53d05603";

    // Child warrant with WRONG parent hash
    let expected_child_payload_hex = "\
ab00010150019471f80000700080000000000000a10269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed\
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105\
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b\
8fc9b394061a65920080071a65920e9008030998200000000000000000000000\
0000000000000000000000000000000000000000001201";

    let expected_child_sig_hex = "\
9b87f984431fdb021aa5331b0960dd2a535df812c0d7c916168b495a9fdbb38e\
43a5a9a0ac2a1e65dc0076338deaa5da962f915588532ef1c8cd8916193ab806";

    // Create keys
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();

    // Create parent warrant
    let mut tools_parent = BTreeMap::new();
    let mut cs_parent = ConstraintSet::new();
    cs_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_parent.insert("read_file".to_string(), cs_parent);

    let payload_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A12_PARENT),
        tools: tools_parent,
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

    let warrant_parent = sign_payload(&payload_parent, &control_plane);

    // Verify parent matches
    assert_eq!(
        hex::encode(warrant_parent.payload_bytes()),
        expected_parent_payload_hex,
        "A.12 parent payload bytes should match"
    );
    assert_eq!(
        hex::encode(warrant_parent.signature().to_bytes()),
        expected_parent_sig_hex,
        "A.12 parent signature should match"
    );

    // Create child with WRONG parent hash (all zeros)
    let wrong_parent_hash = [0u8; 32];
    let correct_parent_hash = sha256(warrant_parent.payload_bytes());

    let mut tools_child = BTreeMap::new();
    let mut cs_child = ConstraintSet::new();
    cs_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_child.insert("read_file".to_string(), cs_child);

    let payload_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A12_CHILD),
        tools: tools_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(wrong_parent_hash),
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

    let warrant_child = sign_payload(&payload_child, &orchestrator);

    // Verify child matches
    assert_eq!(
        hex::encode(warrant_child.payload_bytes()),
        expected_child_payload_hex,
        "A.12 child payload bytes should match"
    );
    assert_eq!(
        hex::encode(warrant_child.signature().to_bytes()),
        expected_child_sig_hex,
        "A.12 child signature should match"
    );

    // Verify the hash comparison
    assert_eq!(
        hex::encode(correct_parent_hash),
        "e7d3e3e8cab3f920e623453f4c718ef5f440edde9ecd0140ecfff7502e073e45",
        "A.12 correct parent hash should match"
    );
    assert_eq!(
        hex::encode(wrong_parent_hash),
        "0000000000000000000000000000000000000000000000000000000000000000",
        "A.12 wrong parent hash should be all zeros"
    );
    assert_ne!(
        warrant_child.payload.parent_hash.unwrap(),
        correct_parent_hash,
        "A.12 child should have WRONG parent hash (I5 violation)"
    );

    // Create fresh warrants with FUTURE timestamps for verifier rejection test
    // (the byte-exact test above uses historical timestamps from the spec)
    let mut tools_verify_parent = BTreeMap::new();
    let mut cs_verify_parent = ConstraintSet::new();
    cs_verify_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_verify_parent.insert("read_file".to_string(), cs_verify_parent);

    let payload_verify_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A12_PARENT),
        tools: tools_verify_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
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

    let warrant_verify_parent = sign_payload(&payload_verify_parent, &control_plane);
    let wrong_hash = [0u8; 32]; // Wrong hash

    let mut tools_verify_child = BTreeMap::new();
    let mut cs_verify_child = ConstraintSet::new();
    cs_verify_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_verify_child.insert("read_file".to_string(), cs_verify_child);

    let payload_verify_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A12_CHILD),
        tools: tools_verify_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
        max_depth: 3,
        depth: 1,
        parent_hash: Some(wrong_hash),
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

    let warrant_verify_child = sign_payload(&payload_verify_child, &orchestrator);

    // Verify that the verifier REJECTS this chain
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", control_plane.public_key());

    let result = data_plane.verify_chain(&[warrant_verify_parent, warrant_verify_child]);
    assert!(
        result.is_err(),
        "A.12 verify_chain should REJECT parent hash mismatch"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("hash") || err_msg.contains("broken"),
        "A.12 error should mention hash mismatch: {}",
        err_msg
    );
}

/// Test Vector A.13: TTL Extension Attack (I3 Violation)
#[test]
fn test_vector_a13_ttl_extension_attack() {
    // Parent warrant
    let expected_parent_payload_hex = "\
aa00010150019471f80000700080000000000000b00269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56\
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd\
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592\
0080071a65920e9008031200";

    let expected_parent_sig_hex = "\
dc3d49adf4868a697512776fcb7bbe2b3ff35f7ae0d27b9546f4a98796d706e4\
f354b5e3bc1cee877d6404f20996e0e130d40358ea7468338144d5bdecb6950e";

    // Child warrant with EXTENDED TTL
    let expected_child_payload_hex = "\
ab00010150019471f80000700080000000000000b10269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed\
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105\
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b\
8fc9b394061a65920080071a65921ca00803099820184218d8185318f7187518\
3118dc18b1184118f0185c183f184318b218c21882188518f218511867185e18\
2118e0185318c818ab188218db18fc186018cb18f51201";

    let expected_child_sig_hex = "\
cdb83eb10d561edb54de001096bc80df3cb5ef9dd0f67134e1c4eeb52bc6d94e\
4f3b6284686fa319539f3218188c5b1634ae9757c02999d2baab5d2d5c54e604";

    // Create keys
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let worker = worker_key();

    // Create parent warrant
    let mut tools_parent = BTreeMap::new();
    let mut cs_parent = ConstraintSet::new();
    cs_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_parent.insert("read_file".to_string(), cs_parent);

    let payload_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A13_PARENT),
        tools: tools_parent,
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

    let warrant_parent = sign_payload(&payload_parent, &control_plane);

    // Verify parent matches
    assert_eq!(
        hex::encode(warrant_parent.payload_bytes()),
        expected_parent_payload_hex,
        "A.13 parent payload bytes should match"
    );
    assert_eq!(
        hex::encode(warrant_parent.signature().to_bytes()),
        expected_parent_sig_hex,
        "A.13 parent signature should match"
    );

    // Create child with EXTENDED TTL (parent + 1 hour)
    let parent_hash = sha256(warrant_parent.payload_bytes());
    let extended_expires_at = EXPIRES_AT + 3600; // 1704074400

    let mut tools_child = BTreeMap::new();
    let mut cs_child = ConstraintSet::new();
    cs_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_child.insert("read_file".to_string(), cs_child);

    let payload_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A13_CHILD),
        tools: tools_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: ISSUED_AT,
        expires_at: extended_expires_at, // EXTENDED (invalid)
        max_depth: 3,
        depth: 1,
        parent_hash: Some(parent_hash),
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

    let warrant_child = sign_payload(&payload_child, &orchestrator);

    // Verify child matches
    assert_eq!(
        hex::encode(warrant_child.payload_bytes()),
        expected_child_payload_hex,
        "A.13 child payload bytes should match"
    );
    assert_eq!(
        hex::encode(warrant_child.signature().to_bytes()),
        expected_child_sig_hex,
        "A.13 child signature should match"
    );

    // Verify TTL violation
    assert_eq!(
        warrant_parent.payload.expires_at, EXPIRES_AT,
        "A.13 parent expires_at"
    );
    assert_eq!(
        warrant_child.payload.expires_at, extended_expires_at,
        "A.13 child expires_at"
    );
    assert!(
        warrant_child.payload.expires_at > warrant_parent.payload.expires_at,
        "A.13 child should have EXTENDED TTL (I3 violation)"
    );

    // Create fresh warrants with FUTURE timestamps for verifier rejection test
    // (the byte-exact test above uses historical timestamps from the spec)
    let mut tools_verify_parent = BTreeMap::new();
    let mut cs_verify_parent = ConstraintSet::new();
    cs_verify_parent.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_verify_parent.insert("read_file".to_string(), cs_verify_parent);

    let payload_verify_parent = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A13_PARENT),
        tools: tools_verify_parent,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
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

    let warrant_verify_parent = sign_payload(&payload_verify_parent, &control_plane);
    let verify_parent_hash = sha256(warrant_verify_parent.payload_bytes());
    let verify_extended_expires_at = FUTURE_EXPIRES_AT + 3600; // Extended by 1 hour

    let mut tools_verify_child = BTreeMap::new();
    let mut cs_verify_child = ConstraintSet::new();
    cs_verify_child.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/reports/*").unwrap()),
    );
    tools_verify_child.insert("read_file".to_string(), cs_verify_child);

    let payload_verify_child = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A13_CHILD),
        tools: tools_verify_child,
        holder: worker.public_key(),
        issuer: orchestrator.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: verify_extended_expires_at, // EXTENDED (invalid)
        max_depth: 3,
        depth: 1,
        parent_hash: Some(verify_parent_hash),
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

    let warrant_verify_child = sign_payload(&payload_verify_child, &orchestrator);

    // Verify that the verifier REJECTS this chain
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", control_plane.public_key());

    let result = data_plane.verify_chain(&[warrant_verify_parent, warrant_verify_child]);
    assert!(
        result.is_err(),
        "A.13 verify_chain should REJECT TTL extension"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("expir") || err_msg.contains("TTL") || err_msg.contains("lifetime"),
        "A.13 error should mention expiration/TTL issue: {}",
        err_msg
    );
}

/// Test Vector A.14: Invalid Signature (Cryptographic Verification)
/// Tests that implementations correctly verify Ed25519 signatures
#[test]
fn test_vector_a14_invalid_signature() {
    // Expected hex values from generated test vectors
    let expected_forged_payload_hex = "\
aa00010150019471f80000700080000000000000c00269657865637574696f6e\
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882\
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56\
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd\
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592\
0080071a65920e9008031200";

    // Forged signature (signed by attacker key, not control_plane)
    let expected_forged_sig_hex = "\
fc2d4c07b9f0b6c1955e0f3782cd505300d684dd3bd0de70252ca7099b6ef801\
6f2c9a349a1a7d30c2bd63a15a9e3555d5b50c76d6721d3e86ac8dc32f7e7508";

    // Valid signature (signed by control_plane)
    let expected_valid_sig_hex = "\
5c0063e566238e19c27394e0093e09b40ab750c8878a2edb83b051f01ff6469a\
c3447b19f02d4e8f230a024c9d0dbb236b53a2bb5d439cdff7929627bc5b690d";

    // Create keys
    let control_plane = control_plane_key();
    let orchestrator = orchestrator_key();
    let attacker = attacker_key();

    // Create warrant payload that CLAIMS to be issued by control_plane
    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools.insert("read_file".to_string(), cs);

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A14),
        tools,
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

    // Sign with WRONG key (attacker) - this should be rejected
    let warrant_forged = sign_payload(&payload, &attacker);

    // Sign with CORRECT key (control_plane) - this should be accepted
    let warrant_valid = sign_payload(&payload, &control_plane);

    // Verify payload bytes are IDENTICAL
    assert_eq!(
        warrant_forged.payload_bytes(),
        warrant_valid.payload_bytes(),
        "A.14 forged and valid should have identical payload bytes"
    );

    // Verify byte-exact match for forged warrant
    assert_eq!(
        hex::encode(warrant_forged.payload_bytes()),
        expected_forged_payload_hex,
        "A.14 forged payload bytes should match"
    );
    assert_eq!(
        hex::encode(warrant_forged.signature().to_bytes()),
        expected_forged_sig_hex,
        "A.14 forged signature should match"
    );

    // Verify byte-exact match for valid warrant
    assert_eq!(
        hex::encode(warrant_valid.signature().to_bytes()),
        expected_valid_sig_hex,
        "A.14 valid signature should match"
    );

    // Verify the forged warrant has the claimed issuer but different signer
    assert_eq!(
        warrant_forged.payload.issuer,
        control_plane.public_key(),
        "A.14 forged warrant claims to be from control_plane"
    );
    assert_ne!(
        attacker.public_key(),
        control_plane.public_key(),
        "A.14 attacker key should differ from control_plane"
    );

    // Create fresh warrants with FUTURE timestamps for verifier rejection test
    let mut tools_verify = BTreeMap::new();
    let mut cs_verify = ConstraintSet::new();
    cs_verify.insert(
        "path".to_string(),
        Constraint::Pattern(Pattern::new("/data/*").unwrap()),
    );
    tools_verify.insert("read_file".to_string(), cs_verify);

    let payload_verify = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::from_bytes(ID_A14),
        tools: tools_verify,
        holder: orchestrator.public_key(),
        issuer: control_plane.public_key(),
        issued_at: FUTURE_ISSUED_AT,
        expires_at: FUTURE_EXPIRES_AT,
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

    let warrant_verify_forged = sign_payload(&payload_verify, &attacker);
    let warrant_verify_valid = sign_payload(&payload_verify, &control_plane);

    // Verify that the verifier REJECTS the forged warrant
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("root", control_plane.public_key());

    let result_forged = data_plane.verify_chain(&[warrant_verify_forged]);
    assert!(
        result_forged.is_err(),
        "A.14 verify_chain should REJECT forged signature"
    );
    let err_msg = result_forged.unwrap_err().to_string();
    assert!(
        err_msg.contains("ignature") || err_msg.contains("verification"),
        "A.14 error should mention signature issue: {}",
        err_msg
    );

    // Verify that the verifier ACCEPTS the valid warrant
    let result_valid = data_plane.verify_chain(&[warrant_verify_valid]);
    assert!(
        result_valid.is_ok(),
        "A.14 verify_chain should ACCEPT valid signature: {:?}",
        result_valid.err()
    );
}

// Helper function to sign a payload
fn sign_payload(payload: &payload::WarrantPayload, signing_key: &SigningKey) -> Warrant {
    // Serialize payload to CBOR
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes).expect("Failed to serialize payload");

    // Create preimage: envelope_version || payload_bytes
    // (signing_key.sign() will automatically add "tenuo-warrant-v1" context prefix)
    let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
    preimage.push(1); // envelope_version
    preimage.extend_from_slice(&payload_bytes);

    // Sign (context prefix added automatically by SigningKey::sign)
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
