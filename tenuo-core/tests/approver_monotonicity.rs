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
    planes::{Authorizer, DataPlane},
    warrant::{OwnedAttenuationBuilder, Warrant, WarrantId, WarrantType},
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

    verify_both(&root, &[issuer, exec]).unwrap();
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

// Relative to the real clock: DataPlane verifies at the current time only.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(clippy::too_many_arguments)]
fn gated_payload(
    id_byte: u8,
    holder: &SigningKey,
    issuer: &SigningKey,
    now: u64,
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
        // One clock reading per chain keeps child expiry within its parent's.
        issued_at: now - 60 + depth as u64,
        expires_at: now + 3600,
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
    now: u64,
    cp: SigningKey,
    orch: SigningKey,
    worker: SigningKey,
    a: SigningKey,
    b: SigningKey,
}

fn keys() -> Keys {
    Keys {
        now: now(),
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
        gated_payload(1, &k.orch, &k.cp, k.now, 0, None, &[&k.a, &k.b], Some(2)),
        &k.cp,
    );
    let parent_hash: [u8; 32] = Sha256::digest(&root.payload_bytes).into();
    let child = forge(
        gated_payload(
            2,
            &k.worker,
            &k.orch,
            k.now,
            1,
            Some(parent_hash),
            child_approvers,
            child_min,
        ),
        &k.orch,
    );
    verify_both(&k.cp, &[root, child])
}

/// Verify through the Authorizer and the DataPlane; both must agree.
fn verify_both(cp: &SigningKey, chain: &[Warrant]) -> Result<(), String> {
    let authorizer = Authorizer::new()
        .with_trusted_root(cp.public_key())
        .verify_chain(chain)
        .map(|_| ())
        .map_err(|e| e.to_string());
    let mut dp = DataPlane::new();
    dp.trust_issuer("cp", cp.public_key());
    let data_plane = dp
        .verify_chain(chain)
        .map(|_| ())
        .map_err(|e| e.to_string());
    assert_eq!(
        authorizer.is_ok(),
        data_plane.is_ok(),
        "{authorizer:?} vs {data_plane:?}"
    );
    authorizer
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
    assert!(err.contains("cannot lower approval threshold"), "{err}");
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

    verify_both(&root, &[top, delegated, exec]).unwrap();
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
            k.now,
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
        k.now,
        1,
        Some(parent_hash),
        &[],
        None,
    ));
    child.extensions = BTreeMap::new();
    child.required_approvers = None;
    let child = forge(child, &k.orch);

    let err = verify_both(&k.cp, &[root, child]).unwrap_err();
    assert!(err.contains("approval gate monotonicity"), "{err}");
}

#[test]
fn issuance_cannot_dilute_quorum_by_adding_approver_at_same_threshold() {
    let (root, worker, a, rogue) = (
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
        .required_approvers(vec![a.public_key(), rogue.public_key()])
        .min_approvals(1)
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("requires an approval threshold of at least 2"),
        "{err}"
    );
}

#[test]
fn issuance_adding_approver_without_explicit_min_raises_threshold() {
    let (root, worker, a, b) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = issuer_warrant(&root, &[&a], 1);

    let exec = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .required_approvers(vec![a.public_key(), b.public_key()])
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap();
    assert_eq!(exec.approval_threshold(), 2);
    verify_both(&root, &[issuer, exec]).unwrap();
}

#[test]
fn verifier_rejects_child_that_dilutes_quorum_with_extra_approver() {
    let k = keys();
    let rogue = SigningKey::generate();
    // Root requires 2-of-2 [a, b]; child adds rogue at threshold 2 (2-of-3).
    let err = verify_child(&k, &[&k.a, &k.b, &rogue], Some(2)).unwrap_err();
    assert!(
        err.contains("requires an approval threshold of at least"),
        "{err}"
    );

    // Raising threshold to 3-of-3 preserves the [a, b] quorum.
    verify_child(&k, &[&k.a, &k.b, &rogue], Some(3)).unwrap();
}

#[test]
fn attenuating_issuer_to_ungated_tool_clears_approvers() {
    let (root, mid, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let top = issuer_warrant(&root, &[&a], 1);

    let delegated = top
        .attenuate()
        .issuable_tools(vec!["read_file".to_string()])
        .holder(mid.public_key())
        .build(&root)
        .unwrap();
    assert!(delegated.extension(APPROVAL_GATE_EXTENSION_KEY).is_none());
    assert!(delegated.required_approvers().is_none());
    assert!(delegated.min_approvals().is_none());
    verify_both(&root, &[top, delegated]).unwrap();
}

#[test]
fn wildcard_issuer_issues_named_gated_tool() {
    let (root, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let issuer = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["*".to_string()])
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key()])
        .min_approvals(1)
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

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
        Some(vec![a.public_key()])
    );
    verify_both(&root, &[issuer, exec]).unwrap();
}

#[test]
fn repeated_approver_cannot_satisfy_a_higher_minimum() {
    let k = keys();
    let mut root = gated_payload(1, &k.orch, &k.cp, k.now, 0, None, &[], Some(2));
    root.required_approvers = Some(vec![k.a.public_key(), k.a.public_key()]);
    let root = forge(root, &k.cp);

    let err = verify_both(&k.cp, &[root]).unwrap_err();
    assert!(err.contains("distinct required_approvers"), "{err}");
}

#[test]
fn issuable_tools_on_execution_child_keeps_gates() {
    let (root, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = Warrant::builder()
        .tool("transfer", ConstraintSet::new())
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key()])
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    let child = parent
        .attenuate()
        .inherit_all()
        .issuable_tools(vec![])
        .holder(worker.public_key())
        .build(&root)
        .unwrap();
    assert!(child.extension(APPROVAL_GATE_EXTENSION_KEY).is_some());
    assert_eq!(
        child.required_approvers().cloned(),
        Some(vec![a.public_key()])
    );
    verify_both(&root, &[parent, child]).unwrap();
}

#[test]
fn delegation_raises_minimum_for_added_approver() {
    let (root, worker, a, b, c) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = Warrant::builder()
        .tool("transfer", ConstraintSet::new())
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key(), b.public_key()])
        .min_approvals(1)
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    let child = parent
        .attenuate()
        .inherit_all()
        .add_approvers(vec![c.public_key()])
        .holder(worker.public_key())
        .build(&root)
        .unwrap();
    assert_eq!(child.min_approvals(), Some(2));
    assert_eq!(child.approval_threshold(), 2);
    verify_both(&root, &[parent, child]).unwrap();
}

#[test]
fn delegation_rejects_explicit_approvers_without_a_gate() {
    let (root, worker, a, c) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let mut read = ConstraintSet::new();
    read.insert("path", Constraint::Wildcard(Wildcard));
    let parent = Warrant::builder()
        .tool("transfer", ConstraintSet::new())
        .tool("read_file", read.clone())
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .required_approvers(vec![a.public_key()])
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    // Inherited approvers fall away with the gate.
    let ungated = parent
        .attenuate()
        .tool("read_file", read.clone())
        .holder(worker.public_key())
        .build(&root)
        .unwrap();
    assert!(ungated.required_approvers().is_none());

    // Approvers set on the builder are an error, not silently dropped.
    let err = parent
        .attenuate()
        .tool("read_file", read)
        .add_approvers(vec![c.public_key()])
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("required_approvers requires an approval gate map"),
        "{err}"
    );
}

#[test]
fn inherited_unsorted_or_repeated_approvers_clear_with_their_gate() {
    let k = keys();
    let mut read = ConstraintSet::new();
    read.insert("path", Constraint::Wildcard(Wildcard));
    let mut root = gated_payload(1, &k.orch, &k.cp, k.now, 0, None, &[], Some(1));
    root.tools.insert("read_file".to_string(), read.clone());
    // Written by hand: repeated and in reverse byte order.
    let mut approvers = sorted(vec![k.a.public_key(), k.b.public_key()]);
    approvers.reverse();
    approvers.push(approvers[0].clone());
    root.required_approvers = Some(approvers);
    let root = forge(root, &k.cp);

    let child = root
        .attenuate()
        .tool("read_file", read.clone())
        .holder(k.worker.public_key())
        .build(&k.orch)
        .unwrap();
    assert!(child.required_approvers().is_none());
    assert!(child.extension(APPROVAL_GATE_EXTENSION_KEY).is_none());

    // The owned builder (behind the Python bindings) takes the same path.
    let owned = OwnedAttenuationBuilder::new(root)
        .tool("read_file", read)
        .holder(k.worker.public_key())
        .build(&k.orch)
        .unwrap();
    assert!(owned.required_approvers().is_none());
}

fn gated_without_approvers(root: &SigningKey, holder: &SigningKey) -> Warrant {
    Warrant::builder()
        .tool("transfer", ConstraintSet::new())
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .ttl(Duration::from_secs(3600))
        .holder(holder.public_key())
        .build(root)
        .unwrap()
}

#[test]
fn delegation_cannot_add_approvers_under_an_approverless_gate() {
    let (root, mid, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = gated_without_approvers(&root, &mid);

    let err = parent
        .attenuate()
        .inherit_all()
        .add_approvers(vec![mid.public_key()])
        .holder(worker.public_key())
        .build(&mid)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("parent approval gate that has none"),
        "{err}"
    );
}

#[test]
fn issuance_cannot_name_approvers_under_an_approverless_gate() {
    let (root, worker) = (SigningKey::generate(), SigningKey::generate());
    let issuer = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["transfer".to_string()])
        .extension(APPROVAL_GATE_EXTENSION_KEY, gate_bytes("transfer"))
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    let err = issuer
        .issue_execution_warrant()
        .unwrap()
        .tool("transfer", ConstraintSet::new())
        .required_approvers(vec![root.public_key()])
        .ttl(Duration::from_secs(60))
        .holder(worker.public_key())
        .build(&root)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("parent approval gate that has none"),
        "{err}"
    );
}

#[test]
fn verifier_rejects_approvers_added_under_an_approverless_gate() {
    let k = keys();
    let mut root = gated_payload(1, &k.orch, &k.cp, k.now, 0, None, &[], None);
    root.required_approvers = None;
    let root = forge(root, &k.cp);
    let parent_hash: [u8; 32] = Sha256::digest(&root.payload_bytes).into();
    let child = forge(
        gated_payload(
            2,
            &k.worker,
            &k.orch,
            k.now,
            1,
            Some(parent_hash),
            &[&k.orch],
            Some(1),
        ),
        &k.orch,
    );

    let err = verify_both(&k.cp, &[root, child]).unwrap_err();
    assert!(err.contains("parent approval gate that has none"), "{err}");
}

#[test]
fn child_may_gate_a_tool_the_parent_left_ungated() {
    let (root, worker, a) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = Warrant::builder()
        .tool("transfer", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .holder(root.public_key())
        .build(&root)
        .unwrap();

    let mut builder = OwnedAttenuationBuilder::new(parent.clone());
    builder.inherit_all();
    builder.set_holder(worker.public_key());
    builder
        .set_approval_gates_extension(gate_bytes("transfer"))
        .unwrap();
    let child = builder
        .add_approvers(vec![a.public_key()])
        .build(&root)
        .unwrap();
    assert_eq!(
        child.required_approvers().cloned(),
        Some(vec![a.public_key()])
    );
    verify_both(&root, &[parent, child]).unwrap();
}
