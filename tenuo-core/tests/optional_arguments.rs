//! Presence is part of argument authority, independently of its value constraint.
use proptest::prelude::*;
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{ConstraintSet, ConstraintValue, Range, SigningKey, Warrant};

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
