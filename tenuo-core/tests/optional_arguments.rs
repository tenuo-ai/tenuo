//! Presence is part of argument authority, independently of its value constraint.
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    All, Any, Authorizer, Constraint, ConstraintSet, ConstraintValue, Not, Range, SigningKey,
    Warrant,
};

fn range_set(optional: bool, max: f64) -> ConstraintSet {
    let mut set = ConstraintSet::new();
    let range = Range::max(max).unwrap();
    if optional {
        set.insert_optional("head", range);
    } else {
        set.insert("head", range);
    }
    set
}

fn args(value: Option<ConstraintValue>) -> HashMap<String, ConstraintValue> {
    value.into_iter().map(|v| ("head".into(), v)).collect()
}

fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

#[test]
fn optional_presence_is_distinct_from_null_and_unknown_arguments() {
    for allow_unknown in [false, true] {
        let mut set = range_set(true, 200.0);
        set.set_allow_unknown(allow_unknown);
        for (value, allowed) in [
            (None, true),
            (Some(200.into()), true),
            (Some(201.into()), false),
            (Some(ConstraintValue::Null), false),
            (Some("200".into()), false),
        ] {
            let args = args(value);
            assert_eq!(set.matches(&args).is_ok(), allowed);
            assert_eq!(set.diagnose(&args).unwrap().is_satisfied(), allowed);
        }
        let unknown = HashMap::from([("other".into(), 1.into())]);
        assert_eq!(set.matches(&unknown).is_ok(), allow_unknown);
    }
    assert!(range_set(false, 200.0).matches(&args(None)).is_err());
}

#[test]
fn inserting_required_resets_presence_and_collect_defaults_to_required() {
    let mut set = range_set(true, 200.0);
    set.insert("head", Range::max(100.0).unwrap());
    assert!(!set.is_optional("head"));
    assert!(set.matches(&args(None)).is_err());
    set.insert_optional("head", Range::max(50.0).unwrap());
    assert!(set.is_optional("head"));
    assert!(!set.is_optional("unknown"));
    let collected: ConstraintSet = set.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert!(!collected.is_optional("head"));
}

#[test]
fn delegation_checks_presence_and_value_independently() {
    for parent_optional in [false, true] {
        for child_optional in [false, true] {
            for child_max in [100.0, 200.0, 300.0] {
                let parent = range_set(parent_optional, 200.0);
                let child = range_set(child_optional, child_max);
                let valid = (parent_optional || !child_optional) && child_max <= 200.0;
                assert_eq!(parent.validate_attenuation(&child).is_ok(), valid);
            }
        }
    }
    // An optional key remains declared; neither dropping it nor adding other
    // keys may reopen the parent's closed-world authority.
    let parent = range_set(true, 200.0);
    assert!(parent.validate_attenuation(&ConstraintSet::new()).is_err());
    let mut child = parent.clone();
    child.insert_optional("extra", Range::max(1.0).unwrap());
    assert!(parent.validate_attenuation(&child).is_err());
    assert!(ConstraintSet::new().validate_attenuation(&parent).is_ok());
}

#[test]
fn optional_metadata_is_strict_and_legacy_encoding_stays_identical() {
    let required = range_set(false, 200.0);
    #[derive(serde::Serialize)]
    struct LegacySet<'a> {
        constraints: std::collections::BTreeMap<&'a str, &'a tenuo::Constraint>,
    }
    let legacy = LegacySet {
        constraints: [("head", required.get("head").unwrap())].into(),
    };
    assert_eq!(cbor(&required), cbor(&legacy));
    for optional in [false, true] {
        let set = range_set(optional, 200.0);
        let bytes = cbor(&set);
        let decoded: ConstraintSet = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(set, decoded);
        assert_eq!(bytes, cbor(&decoded));
    }
    let valid = serde_json::to_value(range_set(true, 200.0)).unwrap();
    for invalid in [
        serde_json::json!({"constraints": {}, "optional_fields": ["head"]}),
        serde_json::json!({"constraints": {}, "optional_fields": true}),
        serde_json::json!({"constraints": {}, "optional_field": []}),
    ] {
        assert!(ciborium::de::from_reader::<ConstraintSet, _>(cbor(&invalid).as_slice()).is_err());
    }
    // Optionality cannot mask a misspelled or extra member in the nested payload.
    for nested in [
        serde_json::json!([3, {"maximum": 200, "min_inclusive": true, "max_inclusive": true}]),
        serde_json::json!([3, {"max": 200, "min_inclusive": true, "max_inclusive": true, "extra": 1}]),
    ] {
        let mut invalid = valid.clone();
        invalid["constraints"]["head"] = nested;
        let err =
            ciborium::de::from_reader::<ConstraintSet, _>(cbor(&invalid).as_slice()).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}

#[test]
fn optional_metadata_is_deterministic_and_rejected_by_strict_legacy_readers() {
    let mut left = range_set(true, 200.0);
    left.insert_optional("limit", Range::max(100.0).unwrap());
    let mut right = ConstraintSet::new();
    right.insert_optional("limit", Range::max(100.0).unwrap());
    right.insert_optional("head", Range::max(200.0).unwrap());
    assert_eq!(cbor(&left), cbor(&right));

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct StrictLegacySet {
        constraints: std::collections::BTreeMap<String, tenuo::Constraint>,
        #[serde(default)]
        allow_unknown: bool,
    }
    let err = ciborium::de::from_reader::<StrictLegacySet, _>(cbor(&left).as_slice())
        .err()
        .expect("legacy reader must reject optional metadata");
    assert!(err.to_string().contains("unknown field `optional_fields`"));
}

#[test]
fn signed_warrant_preserves_optional_authority_and_delegation() {
    let key = SigningKey::generate();
    let parent = Warrant::builder()
        .capability("read", range_set(true, 200.0))
        .holder(key.public_key())
        .ttl(Duration::from_secs(3600))
        .build(&key)
        .unwrap();
    let bytes = cbor(&parent);
    let decoded: Warrant = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    decoded.verify(&key.public_key()).unwrap();
    assert_eq!(bytes, cbor(&decoded));
    assert!(decoded.check_constraints("read", &args(None)).is_ok());
    assert!(decoded
        .check_constraints("read", &args(Some(201.into())))
        .is_err());
    let child = decoded
        .attenuate()
        .capability("read", range_set(false, 100.0))
        .build(&key)
        .unwrap();
    assert!(child.check_constraints("read", &args(None)).is_err());
    assert!(child
        .attenuate()
        .capability("read", range_set(true, 50.0))
        .build(&key)
        .is_err());
}

proptest! {
    #[test]
    fn permitted_delegations_never_expand_invocations(
        parent_optional in any::<bool>(), child_optional in any::<bool>(),
        parent_max in 0u32..500, child_max in 0u32..500,
        value in proptest::option::of(0i64..600),
    ) {
        let parent = range_set(parent_optional, parent_max as f64);
        let child = range_set(child_optional, child_max as f64);
        let invocation = args(value.map(ConstraintValue::Integer));
        if parent.validate_attenuation(&child).is_ok() && child.matches(&invocation).is_ok() {
            prop_assert!(parent.matches(&invocation).is_ok());
        }
    }
}

fn assert_unsupported_optional_denied(constraint: Constraint) {
    let mut set = ConstraintSet::new();
    set.insert_optional("head", constraint);
    let key = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability("read", set)
        .holder(key.public_key())
        .ttl(Duration::from_secs(3600))
        .build(&key)
        .unwrap();
    // Exercise the public wire decoder and trusted, PoP-authenticated receiver.
    let warrant = tenuo::wire::decode(&tenuo::wire::encode(&warrant).unwrap()).unwrap();
    let mut verifier = Authorizer::new();
    verifier.add_trusted_root(key.public_key());
    for invocation in [args(None), args(Some(1.into()))] {
        let signature = warrant.sign(&key, "read", &invocation).unwrap();
        assert!(verifier
            .authorize_one(&warrant, "read", &invocation, Some(&signature), &[])
            .is_err());
        assert!(warrant.diagnose_constraints("read", &invocation).is_err());
    }
}

#[test]
fn optional_unknown_constraints_fail_closed_through_composites() {
    let unknown = Constraint::Unknown {
        type_id: 99,
        payload: vec![0xf6],
    };
    for constraint in [
        unknown.clone(),
        All::new([unknown.clone()]).into(),
        Any::new([tenuo::Wildcard.into(), unknown.clone()]).into(),
        Not::new(unknown.clone()).into(),
        Any::new([
            tenuo::Wildcard.into(),
            All::new([Not::new(unknown).into()]).into(),
        ])
        .into(),
    ] {
        assert_unsupported_optional_denied(constraint);
    }
}

#[cfg(not(feature = "cel"))]
#[test]
fn optional_cel_requires_cel_support_even_when_omitted() {
    assert_unsupported_optional_denied(tenuo::CelConstraint::new("true").into());
    assert_unsupported_optional_denied(
        Any::new([
            tenuo::Wildcard.into(),
            tenuo::CelConstraint::new("true").into(),
        ])
        .into(),
    );
}

fn hand_signed_required_child(
    parent: &Warrant,
    constraint: Constraint,
    key: &SigningKey,
) -> Warrant {
    // Model a holder signing directly, without the attenuation builder's checks.
    let mut payload = parent.payload.clone();
    payload.id = tenuo::WarrantId::new();
    payload.depth += 1;
    payload.issuer = key.public_key();
    payload.parent_hash = Some(Sha256::digest(parent.payload_bytes()).into());
    let mut required = ConstraintSet::new();
    required.insert("head", constraint);
    payload.tools = [("read".to_string(), required)].into();
    let payload = cbor(&payload);
    let signature = key.sign_raw(&[tenuo::SIGNATURE_CONTEXT, &[1], &payload].concat());
    let envelope = cbor(&(1u8, serde_bytes::Bytes::new(&payload), signature));
    tenuo::wire::decode(&envelope).unwrap()
}

fn optional_parent(constraint: Constraint, issuer: &SigningKey, holder: &SigningKey) -> Warrant {
    let mut set = ConstraintSet::new();
    set.insert_optional("head", constraint);
    Warrant::builder()
        .capability("read", set)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(3600))
        .build(issuer)
        .unwrap()
}

fn assert_unsupported_optional_parent_cannot_delegate(constraint: Constraint) {
    let key = SigningKey::generate();
    let issuer = SigningKey::generate();
    let parent = optional_parent(constraint.clone(), &issuer, &key);
    let invocation = args(Some(1.into()));
    let refusal = parent
        .check_constraints("read", &invocation)
        .unwrap_err()
        .to_string();
    let verifier = Authorizer::new().with_trusted_root(issuer.public_key());
    for child_constraint in [constraint.clone(), tenuo::Exact::new(1).into()] {
        let child = hand_signed_required_child(&parent, child_constraint.clone(), &key);
        child.verify(&key.public_key()).unwrap();
        // The required leaf alone accepts the value. Only chain validation can
        // preserve the unsupported optional parent's refusal.
        child.check_constraints("read", &invocation).unwrap();
        let signature = child.sign(&key, "read", &invocation).unwrap();
        let error = verifier
            .check_chain(
                &[parent.clone(), child.clone()],
                "read",
                &invocation,
                Some(&signature),
                &[],
            )
            .unwrap_err();
        assert!(error.to_string().contains(&refusal), "{error}");
        assert!(verifier.verify_chain(&[parent.clone(), child]).is_err());
        let mut required = ConstraintSet::new();
        required.insert("head", child_constraint);
        assert!(parent
            .attenuate()
            .capability("read", required)
            .build(&key)
            .is_err());
    }
}

#[test]
fn signed_required_children_cannot_revive_unknown_optional_parent() {
    assert_unsupported_optional_parent_cannot_delegate(
        Any::new([
            tenuo::Wildcard.into(),
            Constraint::Unknown {
                type_id: 99,
                payload: vec![0xf6],
            },
        ])
        .into(),
    );
}

#[cfg(not(feature = "cel"))]
#[test]
fn signed_required_children_cannot_revive_unavailable_cel_parent() {
    assert_unsupported_optional_parent_cannot_delegate(
        Any::new([
            tenuo::Wildcard.into(),
            tenuo::CelConstraint::new("true").into(),
        ])
        .into(),
    );
}

#[test]
fn hand_signed_supported_optional_to_required_chain_is_valid() {
    let key = SigningKey::generate();
    let constraint: Constraint = Range::max(200.0).unwrap().into();
    let issuer = SigningKey::generate();
    let parent = optional_parent(constraint.clone(), &issuer, &key);
    let child = hand_signed_required_child(&parent, constraint, &key);
    let invocation = args(Some(1.into()));
    let signature = child.sign(&key, "read", &invocation).unwrap();
    Authorizer::new()
        .with_trusted_root(issuer.public_key())
        .check_chain(&[parent, child], "read", &invocation, Some(&signature), &[])
        .unwrap();
}

/// Regenerate the signed cross-language fixtures with:
/// cargo test --test optional_arguments regenerate_python_optional_fixtures -- --ignored
#[test]
#[ignore]
fn regenerate_python_optional_fixtures() {
    // Public synthetic fixture key. Never a deployed trust root.
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut list = ConstraintSet::new();
    list.insert_optional(
        "head",
        tenuo::Exact::new(ConstraintValue::List(vec![1.into()])),
    );
    let mut null = ConstraintSet::new();
    null.insert_optional("head", tenuo::Exact::new(ConstraintValue::Null));
    let mut unknown = ConstraintSet::new();
    unknown.insert_optional(
        "head",
        Any::new([
            tenuo::Wildcard.into(),
            Constraint::Unknown {
                type_id: 99,
                payload: vec![0xf6],
            },
        ]),
    );
    let mut fixtures = serde_json::Map::new();
    for (name, tool, set) in [
        ("range", "read", range_set(true, 200.0)),
        ("list", "read", list),
        ("null", "read", null),
        ("unknown", "read", unknown),
        ("wildcard", "*", range_set(true, 200.0)),
        ("exact_precedence", "*", range_set(true, 200.0)),
    ] {
        let mut builder = Warrant::builder().capability(tool, set);
        if name == "exact_precedence" {
            builder = builder.capability("read", range_set(false, 100.0));
        }
        let warrant = builder
            .holder(key.public_key())
            .ttl(Duration::from_secs(3600))
            .build(&key)
            .unwrap();
        let mut payload: tenuo::payload::WarrantPayload =
            ciborium::de::from_reader(warrant.payload_bytes()).unwrap();
        // Clock-independent test fixtures, valid from 2023 through 2100.
        payload.issued_at = 1_700_000_000;
        payload.expires_at = 4_102_444_800;
        let payload = cbor(&payload);
        let signed = [tenuo::SIGNATURE_CONTEXT, &[1], &payload].concat();
        let signature = key.sign_raw(&signed);
        let envelope = cbor(&(1u8, serde_bytes::Bytes::new(&payload), signature));
        let decoded = tenuo::wire::decode(&envelope).unwrap();
        if name == "unknown" {
            let constraint = decoded.payload.tools["read"].get("head").unwrap().clone();
            let child = hand_signed_required_child(&decoded, constraint, &key);
            fixtures.insert(
                "unknown_required_child".into(),
                tenuo::wire::encode_base64(&child).unwrap().into(),
            );
        }
        fixtures.insert(
            name.into(),
            tenuo::wire::encode_base64(&decoded).unwrap().into(),
        );
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/optional_arguments.json");
    std::fs::write(
        path,
        serde_json::to_string_pretty(&fixtures).unwrap() + "\n",
    )
    .unwrap();
}
