//! A child's `*` tool entry covers every tool the child does not name. Each of
//! those tools must stay within what the parent allows for it by name.
#![allow(deprecated)]

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::constraints::{ConstraintSet, ConstraintValue, Exact, OneOf};
use tenuo::crypto::SigningKey;
use tenuo::payload::WarrantPayload;
use tenuo::planes::{Authorizer, DataPlane};
use tenuo::warrant::{Warrant, WarrantId, WarrantType};

type Tools = BTreeMap<String, ConstraintSet>;

fn path(values: &[&str]) -> ConstraintSet {
    let mut set = ConstraintSet::new();
    if values.len() == 1 {
        set.insert("path", Exact::new(values[0]));
    } else {
        set.insert("path", OneOf::new(values.to_vec()));
    }
    set
}

fn tools(entries: &[(&str, ConstraintSet)]) -> Tools {
    entries
        .iter()
        .map(|(tool, set)| (tool.to_string(), set.clone()))
        .collect()
}

fn call(path: &str) -> HashMap<String, ConstraintValue> {
    HashMap::from([("path".to_string(), ConstraintValue::from(path))])
}

fn root(key: &SigningKey, tools: &Tools) -> Warrant {
    let mut builder = Warrant::builder();
    for (tool, set) in tools {
        builder = builder.capability(tool, set.clone());
    }
    builder
        .ttl(Duration::from_secs(600))
        .holder(key.public_key())
        .build(key)
        .unwrap()
}

fn delegate(parent: &Warrant, key: &SigningKey, tools: &Tools) -> tenuo::Result<Warrant> {
    let mut builder = parent.attenuate();
    for (tool, set) in tools {
        builder = builder.capability(tool, set.clone());
    }
    builder
        .ttl(Duration::from_secs(60))
        .holder(SigningKey::generate().public_key())
        .build(key)
}

// --- a hand-signed chain, for the verifier ---------------------------------

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

fn payload(
    id: u8,
    holder: &SigningKey,
    issuer: &SigningKey,
    depth: u32,
    parent: Option<&Warrant>,
    tools: &Tools,
) -> WarrantPayload {
    let mut id_bytes = [0u8; 16];
    id_bytes[15] = id;
    WarrantPayload {
        version: 1,
        warrant_type: WarrantType::Execution,
        id: WarrantId::from_bytes(id_bytes),
        tools: tools.clone(),
        holder: holder.public_key(),
        issuer: issuer.public_key(),
        issued_at: now() - 60 + u64::from(depth),
        expires_at: now() + 3600 - 60 * u64::from(depth),
        max_depth: 3,
        depth,
        parent_hash: parent.map(|w| Sha256::digest(&w.payload_bytes).into()),
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

/// Whether both verifiers accept a hand-signed parent and child.
fn verifier_accepts(parent_tools: &Tools, child_tools: &Tools) -> bool {
    let (cp, orch, worker) = (
        SigningKey::generate(),
        SigningKey::generate(),
        SigningKey::generate(),
    );
    let parent = forge(payload(1, &orch, &cp, 0, None, parent_tools), &cp);
    let child = forge(
        payload(2, &worker, &orch, 1, Some(&parent), child_tools),
        &orch,
    );
    let chain = [parent, child];
    let authorizer = Authorizer::new().with_trusted_root(cp.public_key());
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("cp", cp.public_key());
    let a = authorizer.verify_chain(&chain).is_ok();
    let b = data_plane.verify_chain(&chain).is_ok();
    assert_eq!(a, b, "Authorizer and DataPlane disagree");
    a
}

/// Whether the builder accepts the delegation.
fn builder_accepts(parent_tools: &Tools, child_tools: &Tools) -> bool {
    let key = SigningKey::generate();
    delegate(&root(&key, parent_tools), &key, child_tools).is_ok()
}

fn accepted(parent_tools: &Tools, child_tools: &Tools) -> bool {
    let b = builder_accepts(parent_tools, child_tools);
    let v = verifier_accepts(parent_tools, child_tools);
    assert_eq!(
        b, v,
        "builder and verifier disagree for child {child_tools:?}"
    );
    b
}

#[test]
fn a_wildcard_only_child_cannot_loosen_a_tool_the_parent_names() {
    let parent = tools(&[
        ("read", path(&["/srv/readme.md"])),
        ("*", ConstraintSet::new()),
    ]);
    let child = tools(&[("*", ConstraintSet::new())]);
    assert!(!accepted(&parent, &child));
}

#[test]
fn a_wildcard_child_must_be_within_every_parent_tool_it_does_not_name() {
    let parent = tools(&[
        ("read", path(&["/srv/a", "/srv/b"])),
        ("write", path(&["/srv/a"])),
        ("*", ConstraintSet::new()),
    ]);
    // Within `read`, wider than `write`.
    assert!(!accepted(
        &parent,
        &tools(&[("*", path(&["/srv/a", "/srv/b"]))])
    ));
    // Naming `write` separately keeps it within bounds.
    assert!(accepted(
        &parent,
        &tools(&[
            ("write", path(&["/srv/a"])),
            ("*", path(&["/srv/a", "/srv/b"]))
        ]),
    ));
    // Within both.
    assert!(accepted(&parent, &tools(&[("*", path(&["/srv/a"]))])));
}

#[test]
fn delegations_that_were_sound_are_still_accepted() {
    let open = tools(&[("*", ConstraintSet::new())]);
    assert!(accepted(&open, &open));
    assert!(accepted(&open, &tools(&[("read", path(&["/srv/a"]))])));
    assert!(accepted(&open, &tools(&[("*", path(&["/srv/a"]))])));
    let named = tools(&[("read", path(&["/srv/a", "/srv/b"]))]);
    assert!(accepted(&named, &tools(&[("read", path(&["/srv/a"]))])));
    // A parent without `*` still cannot hand out `*`.
    assert!(!accepted(&named, &tools(&[("*", path(&["/srv/a"]))])));
}

/// Every delegation the builder or verifier accepts must not admit a call the parent rejects.
#[test]
fn no_accepted_delegation_authorizes_a_call_the_parent_rejects() {
    let sets = [
        None,
        Some(ConstraintSet::new()),
        Some(path(&["/srv/a"])),
        Some(path(&["/srv/a", "/srv/b"])),
    ];
    let mut maps = Vec::new();
    for read in &sets {
        for write in &sets {
            for wild in &sets {
                let mut map = Tools::new();
                for (name, set) in [("read", read), ("write", write), ("*", wild)] {
                    if let Some(set) = set {
                        map.insert(name.to_string(), set.clone());
                    }
                }
                if !map.is_empty() {
                    maps.push(map);
                }
            }
        }
    }
    let key = SigningKey::generate();
    let mut accepted_pairs = 0;
    for parent_tools in &maps {
        let parent = root(&key, parent_tools);
        for child_tools in &maps {
            let Ok(child) = delegate(&parent, &key, child_tools) else {
                continue;
            };
            accepted_pairs += 1;
            for tool in ["read", "write", "other"] {
                for target in ["/srv/a", "/srv/b", "/etc/shadow"] {
                    if child.check_constraints(tool, &call(target)).is_ok() {
                        assert!(
                            parent.check_constraints(tool, &call(target)).is_ok(),
                            "child {child_tools:?} allows {tool}({target}) but parent {parent_tools:?} does not"
                        );
                    }
                }
            }
        }
    }
    assert!(
        accepted_pairs > maps.len(),
        "only {accepted_pairs} delegations accepted"
    );
}
