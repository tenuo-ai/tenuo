//! The verifier applies the same delegation rules to a hand-signed child as
//! the builder applies when it creates one.
#![allow(deprecated)]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use tenuo::constraints::{ConstraintSet, Exact};
use tenuo::crypto::SigningKey;
use tenuo::payload::WarrantPayload;
use tenuo::planes::{Authorizer, DataPlane};
use tenuo::warrant::{Clearance, Warrant, WarrantId, WarrantType};

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

fn path(value: &str) -> ConstraintSet {
    let mut set = ConstraintSet::new();
    set.insert("path", Exact::new(value));
    set
}

struct Link<'a> {
    id: u8,
    kind: WarrantType,
    holder: &'a SigningKey,
    issuer: &'a SigningKey,
    parent: Option<&'a Warrant>,
    bounds: Option<ConstraintSet>,
    clearance: Option<Clearance>,
    read_path: &'a str,
}

fn link(l: Link<'_>) -> Warrant {
    let depth = l.parent.map_or(0, |p| p.payload.depth + 1);
    let issuer_type = l.kind == WarrantType::Issuer;
    let mut id = [0u8; 16];
    id[15] = l.id;
    let payload = WarrantPayload {
        version: 1,
        warrant_type: l.kind,
        id: WarrantId::from_bytes(id),
        tools: if issuer_type {
            BTreeMap::new()
        } else {
            BTreeMap::from([("read".to_string(), path(l.read_path))])
        },
        holder: l.holder.public_key(),
        issuer: l.issuer.public_key(),
        issued_at: now() - 60 + u64::from(depth),
        expires_at: now() + 3600 - 60 * u64::from(depth),
        max_depth: 5,
        depth,
        parent_hash: l.parent.map(|w| Sha256::digest(&w.payload_bytes).into()),
        extensions: BTreeMap::new(),
        issuable_tools: issuer_type.then(|| vec!["read".to_string()]),
        max_issue_depth: issuer_type.then_some(5),
        constraint_bounds: l.bounds,
        clearance: l.clearance,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    forge(payload, l.issuer)
}

fn accepted(root_key: &SigningKey, chain: &[Warrant]) -> bool {
    let authorizer = Authorizer::new().with_trusted_root(root_key.public_key());
    let mut data_plane = DataPlane::new();
    data_plane.trust_issuer("cp", root_key.public_key());
    let a = authorizer.verify_chain(chain).is_ok();
    let b = data_plane.verify_chain(chain).is_ok();
    assert_eq!(a, b, "Authorizer and DataPlane disagree");
    a
}

fn keys() -> [SigningKey; 4] {
    std::array::from_fn(|_| SigningKey::generate())
}

#[test]
fn an_issuer_child_cannot_drop_its_parents_constraint_bounds() {
    let [cp, a, b, w] = keys();
    let issuer = |id, holder, issuer, parent, bounds| {
        link(Link {
            id,
            kind: WarrantType::Issuer,
            holder,
            issuer,
            parent,
            bounds,
            clearance: None,
            read_path: "",
        })
    };
    let exec = |parent, target| {
        link(Link {
            id: 9,
            kind: WarrantType::Execution,
            holder: &w,
            issuer: &b,
            parent: Some(parent),
            bounds: None,
            clearance: None,
            read_path: target,
        })
    };
    let root = issuer(1, &a, &cp, None, Some(path("/srv/a")));

    let kept = issuer(2, &b, &a, Some(&root), Some(path("/srv/a")));
    assert!(accepted(&cp, &[root.clone(), kept.clone()]));
    assert!(accepted(
        &cp,
        &[root.clone(), kept.clone(), exec(&kept, "/srv/a")]
    ));
    assert!(!accepted(
        &cp,
        &[root.clone(), kept.clone(), exec(&kept, "/etc/shadow")]
    ));

    let dropped = issuer(3, &b, &a, Some(&root), None);
    assert!(!accepted(&cp, &[root.clone(), dropped.clone()]));
    assert!(!accepted(
        &cp,
        &[root, dropped.clone(), exec(&dropped, "/etc/shadow")]
    ));
}

#[test]
fn an_issuer_without_bounds_may_delegate_with_or_without_them() {
    let [cp, a, b, _w] = keys();
    let issuer = |id, holder, issuer, parent, bounds| {
        link(Link {
            id,
            kind: WarrantType::Issuer,
            holder,
            issuer,
            parent,
            bounds,
            clearance: None,
            read_path: "",
        })
    };
    let root = issuer(1, &a, &cp, None, None);
    assert!(accepted(
        &cp,
        &[root.clone(), issuer(2, &b, &a, Some(&root), None)]
    ));
    assert!(accepted(
        &cp,
        &[
            root.clone(),
            issuer(3, &b, &a, Some(&root), Some(path("/srv/a")))
        ]
    ));
}

#[test]
fn a_child_cannot_raise_or_introduce_clearance() {
    let [cp, a, b, w] = keys();
    for (parent_kind, child_kind) in [
        (WarrantType::Execution, WarrantType::Execution),
        (WarrantType::Issuer, WarrantType::Issuer),
        (WarrantType::Issuer, WarrantType::Execution),
    ] {
        let holder = if child_kind == WarrantType::Execution && parent_kind == WarrantType::Issuer {
            &w
        } else {
            &b
        };
        let pair = |parent_clearance, child_clearance| {
            let root = link(Link {
                id: 1,
                kind: parent_kind,
                holder: &a,
                issuer: &cp,
                parent: None,
                bounds: None,
                clearance: parent_clearance,
                read_path: "/srv/a",
            });
            let child = link(Link {
                id: 2,
                kind: child_kind,
                holder,
                issuer: &a,
                parent: Some(&root),
                bounds: None,
                clearance: child_clearance,
                read_path: "/srv/a",
            });
            accepted(&cp, &[root, child])
        };
        let label = format!("{parent_kind:?} -> {child_kind:?}");
        assert!(pair(None, None), "{label}: none to none");
        assert!(
            pair(Some(Clearance::INTERNAL), Some(Clearance::INTERNAL)),
            "{label}: equal"
        );
        assert!(
            pair(Some(Clearance::INTERNAL), Some(Clearance::EXTERNAL)),
            "{label}: lower"
        );
        assert!(pair(Some(Clearance::INTERNAL), None), "{label}: dropped");
        assert!(
            !pair(Some(Clearance::EXTERNAL), Some(Clearance::SYSTEM)),
            "{label}: raised"
        );
        assert!(!pair(None, Some(Clearance::SYSTEM)), "{label}: introduced");
    }
}

#[test]
fn the_builder_refuses_an_issuer_child_with_higher_clearance() {
    let [cp, a, b, _w] = keys();
    let root = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["read".to_string()])
        .clearance(Clearance::EXTERNAL)
        .max_issue_depth(3)
        .ttl(Duration::from_secs(600))
        .holder(a.public_key())
        .build(&cp)
        .unwrap();
    let raised = root
        .attenuate()
        .clearance(Clearance::SYSTEM)
        .ttl(Duration::from_secs(60))
        .holder(b.public_key())
        .build(&a);
    assert!(raised.is_err());
}
