//! Regression tests for verifier hardening found during conformance review:
//!
//! - root shape for multi-warrant chains: depth 0, no parent_hash;
//!   a lone warrant stays exempt (Tenuo leaf format)
//! - issuance ordering: child.issued_at >= parent.issued_at (I3)
//! - an optional lifetime ceiling on the public Authorizer
//! - empty `All` constraints fail closed rather than matching every value
#![allow(deprecated)]

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::{
    constraints::{All, Any, Constraint, ConstraintSet, ConstraintValue, Exact, Wildcard},
    crypto::SigningKey,
    payload::WarrantPayload,
    planes::{Authorizer, DataPlane},
    warrant::{Warrant, WarrantId, WarrantType},
};

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

fn hash(w: &Warrant) -> [u8; 32] {
    Sha256::digest(&w.payload_bytes).into()
}

fn payload(
    id_byte: u8,
    holder: &SigningKey,
    issuer: &SigningKey,
    issued_at: u64,
    expires_at: u64,
    depth: u32,
    parent_hash: Option<[u8; 32]>,
) -> WarrantPayload {
    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert("path", Constraint::Wildcard(Wildcard));
    tools.insert("read_file".to_string(), cs);
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
        expires_at,
        max_depth: 3,
        depth,
        parent_hash,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    }
}

const NOW: i64 = 1_704_067_500;
const IAT: u64 = 1_704_067_200;
const EXP: u64 = 1_704_070_800;

fn authorizer(root: &SigningKey) -> Authorizer {
    Authorizer::new().with_trusted_root(root.public_key())
}

fn verify(auth: &Authorizer, chain: &[Warrant]) -> Result<(), String> {
    auth.verify_chain_as_of(chain, NOW)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn chain_whose_first_warrant_is_not_a_root_is_rejected() {
    let (cp, orch, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    // A depth-1 warrant signed by the anchor, followed by a correctly linked
    // depth-2 child. Presented as a chain, the first element must be depth 0.
    let mid = forge(payload(1, &orch, &cp, IAT, EXP, 1, Some([0xAA; 32])), &cp);
    let leaf = forge(
        payload(2, &worker, &orch, IAT + 1, EXP - 60, 2, Some(hash(&mid))),
        &orch,
    );
    let err = verify(&authorizer(&cp), &[mid.clone(), leaf.clone()]).unwrap_err();
    assert!(err.contains("depth-0 root"), "{err}");

    let mut dp = DataPlane::new();
    dp.trust_issuer("cp", cp.public_key());
    assert!(dp.verify_chain(&[mid, leaf]).is_err());
}

#[test]
fn chain_whose_first_warrant_carries_parent_hash_is_rejected() {
    let (cp, orch, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let root = forge(payload(1, &orch, &cp, IAT, EXP, 0, Some([0xAA; 32])), &cp);
    let child = forge(
        payload(2, &worker, &orch, IAT + 1, EXP - 60, 1, Some(hash(&root))),
        &orch,
    );
    let err = verify(&authorizer(&cp), &[root.clone(), child.clone()]).unwrap_err();
    assert!(err.contains("parent_hash"), "{err}");

    let mut dp = DataPlane::new();
    dp.trust_issuer("cp", cp.public_key());
    assert!(dp.verify_chain(&[root, child]).is_err());
}

/// Tenuo's wire format permits an intermediate warrant to be presented alone
/// (wire-format-v1 §12, leaf format), trusted on the anchor's direct
/// signature. This must keep working; `authorize_one` relies on it.
#[test]
fn lone_intermediate_signed_by_anchor_is_still_accepted() {
    let (cp, orch) = (SigningKey::generate(), SigningKey::generate());
    let mid = forge(payload(1, &orch, &cp, IAT, EXP, 1, Some([0xAA; 32])), &cp);
    verify(&authorizer(&cp), &[mid]).unwrap();
}

#[test]
fn child_issued_before_parent_is_rejected() {
    let (cp, orch, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let root = forge(payload(1, &orch, &cp, IAT, EXP, 0, None), &cp);
    let child = forge(
        payload(2, &worker, &orch, IAT - 1, EXP - 60, 1, Some(hash(&root))),
        &orch,
    );
    let err = verify(&authorizer(&cp), &[root.clone(), child.clone()]).unwrap_err();
    assert!(err.contains("I3") && err.contains("issued"), "{err}");

    let mut dp = DataPlane::new();
    dp.trust_issuer("cp", cp.public_key());
    assert!(dp.verify_chain(&[root, child]).is_err());
}

#[test]
fn child_issued_at_or_after_parent_is_accepted() {
    let (cp, orch, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let root = forge(payload(1, &orch, &cp, IAT, EXP, 0, None), &cp);
    let same = forge(
        payload(2, &worker, &orch, IAT, EXP - 60, 1, Some(hash(&root))),
        &orch,
    );
    verify(&authorizer(&cp), &[root.clone(), same]).unwrap();
    let later = forge(
        payload(3, &worker, &orch, IAT + 60, EXP - 60, 1, Some(hash(&root))),
        &orch,
    );
    verify(&authorizer(&cp), &[root, later]).unwrap();
}

#[test]
fn max_token_lifetime_ceiling_is_enforced_when_configured() {
    let (cp, orch) = (SigningKey::generate(), SigningKey::generate());
    let root = forge(payload(1, &orch, &cp, IAT, IAT + 7200, 0, None), &cp);
    // No ceiling: fine.
    verify(&authorizer(&cp), std::slice::from_ref(&root)).unwrap();
    // Ceiling below the lifetime: rejected.
    let strict = authorizer(&cp).with_max_token_lifetime(Duration::from_secs(3600));
    let err = verify(&strict, std::slice::from_ref(&root)).unwrap_err();
    assert!(err.contains("lifetime"), "{err}");
    // Ceiling at the lifetime: accepted (inclusive bound).
    let exact = authorizer(&cp).with_max_token_lifetime(Duration::from_secs(7200));
    verify(&exact, &[root]).unwrap();
}

#[test]
fn empty_all_is_invalid_and_empty_any_remains_deny_all() {
    let pdf = Constraint::Exact(Exact {
        value: ConstraintValue::String("pdf".into()),
    });
    let v = ConstraintValue::String("pdf".into());

    // matches: an empty All must not be vacuously true (accept-all); an empty
    // Any stays a deny-all, which is safe and what existing callers expect.
    assert!(All::new(vec![]).matches(&v).is_err());
    assert!(!Any::new(vec![]).matches(&v).unwrap());
    assert!(All::new(vec![pdf.clone()]).matches(&v).unwrap());

    // Empty All is invalid on either side of attenuation.
    assert!(All::new(vec![pdf.clone()])
        .validate_attenuation(&All::new(vec![]))
        .is_err());
    assert!(All::new(vec![])
        .validate_attenuation(&All::new(vec![pdf.clone()]))
        .is_err());
    // and a well-formed narrowing still works
    All::new(vec![pdf.clone()])
        .validate_attenuation(&All::new(vec![pdf.clone(), pdf.clone()]))
        .unwrap();

    // Through a ConstraintSet at the leaf, an empty All must not authorize.
    let mut cs = ConstraintSet::new();
    cs.insert("format", Constraint::All(All::new(vec![])));
    let mut args = HashMap::new();
    args.insert("format".to_string(), v);
    assert!(cs.matches(&args).is_err());
}
