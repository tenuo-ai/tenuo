//! Approvers and threshold follow approval gates down a chain:
//!
//! - an issuer warrant's approvers and threshold carry into the execution
//!   warrants it issues, wherever a gate survives scoping to the issued tools
//! - issuance may add approvers or raise the threshold, never remove or lower
//! - the Authorizer re-checks this on every gated link, so a chain signed
//!   outside the builder cannot swap the approvers
#![allow(deprecated)]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use tenuo::{
    approval_gate::{
        encode_approval_gate_map, ApprovalGateMap, ToolApprovalGate, APPROVAL_GATE_EXTENSION_KEY,
    },
    constraints::{Constraint, ConstraintSet, Wildcard},
    crypto::{PublicKey, SigningKey},
    payload::WarrantPayload,
    planes::Authorizer,
    warrant::{Warrant, WarrantId, WarrantType},
};

fn gate_bytes(tool: &str) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert(tool.to_string(), ToolApprovalGate::whole_tool());
    encode_approval_gate_map(&ApprovalGateMap(map)).unwrap()
}

fn sorted(mut keys: Vec<PublicKey>) -> Vec<PublicKey> {
    keys.sort_by_key(|k| k.to_bytes());
    keys
}

fn issuer_warrant(root: &SigningKey, approvers: &[&SigningKey], min: u32) -> Warrant {
    Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["transfer".to_string(), "read_file".to_string()])
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(approvers.iter().map(|k| k.public_key()).collect())
        .min_approvals(min)
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(root)
        .unwrap()
}

#[test]
fn issued_warrant_inherits_issuer_approvers_and_threshold() {
    let (root, worker, a, b) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = issuer_warrant(&root, &[&a, &b], 2);

    let exec = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap();

    assert!(exec.extension(APPROVAL_GATE_EXTENSION_KEY).is_some());
    assert_eq!(
        exec.required_approvers().cloned(),
        Some(sorted(vec![a.public_key(), b.public_key()]))
    );
    assert_eq!(exec.approval_threshold(), 2);

    let auth = Authorizer::new().with_trusted_root(root.public_key());
    auth.verify_chain(&[issuer, exec]).unwrap();
}

#[test]
fn issuance_cannot_remove_issuer_approver() {
    let (root, worker, a, b) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = issuer_warrant(&root, &[&a], 1);

    let err = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .required_approvers(vec![b.public_key()])
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot remove issuer approver"),
        "{err}"
    );
}

#[test]
fn issuance_cannot_lower_issuer_threshold() {
    let (root, worker, a, b) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = issuer_warrant(&root, &[&a, &b], 2);

    let err = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .min_approvals(1)
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot lower min_approvals"),
        "{err}"
    );
}

#[test]
fn ungated_issued_tool_carries_no_approvers() {
    let (root, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = issuer_warrant(&root, &[&a], 1);

    let exec = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("read_file", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap();

    assert!(exec.extension(APPROVAL_GATE_EXTENSION_KEY).is_none());
    assert!(exec.required_approvers().is_none());
}

// --- Verifier: chains signed outside the builder ---------------------------

fn forge(payload: WarrantPayload, key: &SigningKey) -> Warrant {
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).unwrap();
    let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
    preimage.push(1u8);
    preimage.extend_from_slice(&payload_bytes);
    let signature = key.sign(&preimage);
    Warrant {
        payload,
        signature,
        payload_bytes,
        envelope_version: 1,
    }
}

const NOW: i64 = 1_704_067_500;
const IAT: u64 = 1_704_067_200;
const EXP: u64 = 1_704_070_800;

#[allow(clippy::too_many_arguments)]
fn gated_payload(
    id_byte: u8,
    holder: &SigningKey,
    issuer: &SigningKey,
    issued_at: u64,
    depth: u32,
    parent_hash: Option<[u8; 32]>,
    approvers: &[&SigningKey],
    min: Option<u32>,
) -> WarrantPayload {
    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert("to", Constraint::Wildcard(Wildcard));
    tools.insert("transfer".to_string(), cs);
    let mut extensions = BTreeMap::new();
    extensions.insert(
        APPROVAL_GATE_EXTENSION_KEY.to_string(),
        gate_bytes("transfer"),
    );
    let mut id = [0u8; 16];
    id[15] = id_byte;
    WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(id),
        tools,
        holder: holder.public_key(),
        issuer: issuer.public_key(),
        issued_at,
        expires_at: EXP,
        max_depth: 3,
        depth,
        parent_hash,
        extensions,
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: Some(sorted(approvers.iter().map(|k| k.public_key()).collect())),
        min_approvals: min,
    }
}

struct Keys {
    cp: SigningKey,
    orch: SigningKey,
    worker: SigningKey,
    a: SigningKey,
    b: SigningKey,
}

fn keys() -> Keys {
    Keys {
        cp: SigningKey::generate(),
        orch: SigningKey::generate(),
        worker: SigningKey::generate(),
        a: SigningKey::generate(),
        b: SigningKey::generate(),
    }
}

/// Root gated with approvers `[a, b]` at threshold 2, then a forged child.
fn verify_child(
    k: &Keys,
    child_approvers: &[&SigningKey],
    child_min: Option<u32>,
) -> Result<(), String> {
    let root = forge(
        gated_payload(1, &k.orch, &k.cp, IAT, 0, None, &[&k.a, &k.b], Some(2)),
        &k.cp,
    );
    let parent_hash: [u8; 32] = Sha256::digest(&root.payload_bytes).into();
    let child = forge(
        gated_payload(
            2,
            &k.worker,
            &k.orch,
            IAT + 1,
            1,
            Some(parent_hash),
            child_approvers,
            child_min,
        ),
        &k.orch,
    );
    Authorizer::new()
        .with_trusted_root(k.cp.public_key())
        .verify_chain_as_of(&[root, child], NOW)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn verifier_accepts_child_keeping_approvers_and_threshold() {
    let k = keys();
    verify_child(&k, &[&k.a, &k.b], Some(2)).unwrap();
}

#[test]
fn verifier_rejects_child_that_swaps_an_approver() {
    let k = keys();
    let rogue = SigningKey::generate();
    let err = verify_child(&k, &[&k.a, &rogue], Some(2)).unwrap_err();
    assert!(err.contains("removes a parent approver"), "{err}");
}

#[test]
fn verifier_rejects_child_that_lowers_threshold() {
    let k = keys();
    let err = verify_child(&k, &[&k.a, &k.b], Some(1)).unwrap_err();
    assert!(err.contains("threshold lowered"), "{err}");
}

#[test]
fn unset_issuer_minimum_still_requires_every_approver() {
    let (root, worker, a, b) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["transfer".to_string()])
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key(), b.public_key()])
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();
    assert_eq!(issuer.approval_threshold(), 2);

    let err = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .min_approvals(1)
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string().contains("cannot lower approval threshold"),
        "{err}"
    );
}

#[test]
fn gate_survives_issuer_to_issuer_delegation() {
    let (root, mid, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let top = issuer_warrant(&root, &[&a], 1);

    let delegated = top
        .attenuate()
        .inherit_all()
        .holder(mid.public_key())
        .build(&root)
        .unwrap();
    assert!(delegated.extension(APPROVAL_GATE_EXTENSION_KEY).is_some());
    assert_eq!(
        delegated.required_approvers().cloned(),
        Some(vec![a.public_key()])
    );

    let exec = delegated
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&mid)
        .unwrap();
    assert!(exec.extension(APPROVAL_GATE_EXTENSION_KEY).is_some());
    assert_eq!(
        exec.required_approvers().cloned(),
        Some(vec![a.public_key()])
    );

    let auth = Authorizer::new().with_trusted_root(root.public_key());
    auth.verify_chain(&[top, delegated, exec]).unwrap();
}

#[test]
fn wildcard_child_keeps_named_gate() {
    let (root, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = Warrant::builder()
        .tool("*", ConstraintSet::new())
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key()])
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    let child = parent
        .attenuate()
        .inherit_all()
        .holder(worker.public_key())
        .build(&root)
        .unwrap();
    assert!(child.extension(APPROVAL_GATE_EXTENSION_KEY).is_some());
}

#[test]
fn verifier_rejects_issuer_child_that_drops_gates() {
    let k = keys();
    let as_issuer = |mut p: WarrantPayload| {
        p.warrant_type = WarrantType::Issuer;
        p.tools = BTreeMap::new();
        p.issuable_tools = Some(vec!["transfer".to_string()]);
        p.max_issue_depth = Some(3);
        p
    };
    let root = forge(
        as_issuer(gated_payload(
            1,
            &k.orch,
            &k.cp,
            IAT,
            0,
            None,
            &[&k.a],
            Some(1),
        )),
        &k.cp,
    );
    let parent_hash: [u8; 32] = Sha256::digest(&root.payload_bytes).into();
    let mut child = as_issuer(gated_payload(
        2,
        &k.worker,
        &k.orch,
        IAT + 1,
        1,
        Some(parent_hash),
        &[],
        None,
    ));
    child.extensions = BTreeMap::new();
    child.required_approvers = None;
    let child = forge(child, &k.orch);

    let err = Authorizer::new()
        .with_trusted_root(k.cp.public_key())
        .verify_chain_as_of(&[root, child], NOW)
        .unwrap_err()
        .to_string();
    assert!(err.contains("approval gate monotonicity"), "{err}");
}
