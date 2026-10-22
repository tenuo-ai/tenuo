//! `Optional(inner)` (type ID 22) through real warrants: issuance,
//! proof-of-possession authorization, delegation and the wire format.

use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::ConstraintSet, crypto::SigningKey, warrant::Warrant, wire, Constraint,
    ConstraintValue, Optional, Range, Wildcard,
};

fn opt(inner: impl Into<Constraint>) -> Constraint {
    Optional::new(inner).unwrap().into()
}

fn range(max: f64) -> Constraint {
    Range::new(Some(1.0), Some(max)).unwrap().into()
}

/// `stripe_api_write(operation, parameters, human_confirmation?)`.
fn stripe_set(confirmation: Constraint) -> ConstraintSet {
    let mut cs = ConstraintSet::new();
    cs.insert("operation", Wildcard::new());
    cs.insert("parameters", Wildcard::new());
    cs.insert("human_confirmation", confirmation);
    cs
}

fn args(pairs: &[(&str, ConstraintValue)]) -> HashMap<String, ConstraintValue> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn root(cs: ConstraintSet, key: &SigningKey) -> Warrant {
    Warrant::builder()
        .capability("stripe_api_write", cs)
        .ttl(Duration::from_secs(600))
        .holder(key.public_key())
        .build(key)
        .unwrap()
}

fn authorize(w: &Warrant, key: &SigningKey, a: &HashMap<String, ConstraintValue>) -> bool {
    let sig = w.sign(key, "stripe_api_write", a).unwrap();
    w.authorize("stripe_api_write", a, Some(&sig)).is_ok()
}

#[test]
fn optional_argument_through_pop_authorization() {
    let key = SigningKey::generate();
    let w = root(stripe_set(opt(tenuo::Exact::new(true))), &key);
    let base = [
        ("operation", ConstraintValue::from("create_refund")),
        ("parameters", ConstraintValue::from("{}")),
    ];

    // absent
    assert!(authorize(&w, &key, &args(&base)));
    // explicit null == absent
    let mut with_null = base.to_vec();
    with_null.push(("human_confirmation", ConstraintValue::Null));
    assert!(authorize(&w, &key, &args(&with_null)));
    // present and valid
    let mut ok = base.to_vec();
    ok.push(("human_confirmation", true.into()));
    assert!(authorize(&w, &key, &args(&ok)));
    // present and invalid
    let mut bad = base.to_vec();
    bad.push(("human_confirmation", false.into()));
    assert!(!authorize(&w, &key, &args(&bad)));
    // a required argument sent as null is missing
    assert!(!authorize(
        &w,
        &key,
        &args(&[
            ("operation", "create_refund".into()),
            ("parameters", ConstraintValue::Null),
        ])
    ));
    // other unlisted keys are still denied (closed world)
    let mut extra = base.to_vec();
    extra.push(("amount", 5i64.into()));
    assert!(!authorize(&w, &key, &args(&extra)));
}

#[test]
fn optional_survives_wire_round_trip() {
    let key = SigningKey::generate();
    let w = root(stripe_set(opt(tenuo::Exact::new(true))), &key);
    let decoded = wire::decode(&wire::encode(&w).unwrap()).unwrap();
    let caps = decoded.capabilities().unwrap();
    let c = caps["stripe_api_write"].get("human_confirmation").unwrap();
    assert_eq!(c.type_name(), "Optional");
    decoded
        .check_constraints(
            "stripe_api_write",
            &args(&[("operation", "x".into()), ("parameters", "{}".into())]),
        )
        .unwrap();
}

fn delegate(
    parent: &Warrant,
    parent_key: &SigningKey,
    cs: ConstraintSet,
) -> tenuo::Result<Warrant> {
    let child_key = SigningKey::generate();
    parent
        .attenuate()
        .capability("stripe_api_write", cs)
        .holder(child_key.public_key())
        .build(parent_key)
}

#[test]
fn delegation_optional_to_narrower_optional() {
    let key = SigningKey::generate();
    let parent = root(stripe_set(opt(range(100.0))), &key);
    assert!(delegate(&parent, &key, stripe_set(opt(range(10.0)))).is_ok());
    assert!(delegate(&parent, &key, stripe_set(opt(range(1000.0)))).is_err());
}

#[test]
fn delegation_optional_to_required() {
    let key = SigningKey::generate();
    let parent = root(stripe_set(opt(range(100.0))), &key);
    let child = delegate(&parent, &key, stripe_set(range(10.0))).unwrap();
    // the child now requires the argument
    assert!(child
        .check_constraints(
            "stripe_api_write",
            &args(&[("operation", "x".into()), ("parameters", "{}".into())]),
        )
        .is_err());
    assert!(delegate(&parent, &key, stripe_set(range(1000.0))).is_err());
}

#[test]
fn delegation_required_to_optional_is_rejected() {
    let key = SigningKey::generate();
    let parent = root(stripe_set(range(100.0)), &key);
    assert!(delegate(&parent, &key, stripe_set(opt(range(10.0)))).is_err());
    let wildcard_parent = root(stripe_set(Wildcard::new().into()), &key);
    assert!(delegate(&wildcard_parent, &key, stripe_set(opt(Wildcard::new()))).is_err());
}

#[test]
fn delegation_cannot_add_optional_key_to_closed_parent() {
    let key = SigningKey::generate();
    let parent = root(stripe_set(opt(range(100.0))), &key);
    let mut cs = stripe_set(opt(range(100.0)));
    cs.insert("idempotency_key", opt(Wildcard::new()));
    assert!(delegate(&parent, &key, cs).is_err());
}

#[test]
fn nested_optional_is_rejected_at_issuance() {
    let key = SigningKey::generate();
    let mut cs = ConstraintSet::new();
    cs.insert(
        "x",
        Constraint::All(tenuo::All::new([opt(Wildcard::new())])),
    );
    let result = Warrant::builder()
        .capability("t", cs)
        .ttl(Duration::from_secs(600))
        .holder(key.public_key())
        .build(&key);
    assert!(result.is_err());
}
