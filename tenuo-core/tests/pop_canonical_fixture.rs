//! Rust half of the cross-language PoP canonicalization fixture test.
//!
//! Reads the shared fixture at `tests/fixtures/pop_canonical.json` and
//! asserts that [`tenuo::warrant::Warrant::sign_with_timestamp`] produces
//! byte-identical signatures to what the fixture committed, for every
//! case. A sibling Python test
//! (`tenuo-python/tests/unit/test_pop_canonical_fixture.py`) asserts the
//! same thing against the same fixture — any canonicalization drift
//! between the Rust core and the PyO3 bindings will break one side but
//! not the other.
//!
//! Regenerate the fixture with
//! `tenuo-python/tests/unit/_regen_pop_canonical.py`. Do not hand-edit
//! the JSON.

use std::collections::HashMap;

use serde_json::Value as JsonValue;
use tenuo::constraints::ConstraintValue;
use tenuo::crypto::SigningKey;
use tenuo::wire;

const FIXTURE_BYTES: &str = include_str!("fixtures/pop_canonical.json");

/// Convert a JSON value from the fixture into the `ConstraintValue`
/// shape the Rust signing path expects. Mirrors `py_to_constraint_value`
/// in `tenuo-core/src/python.rs` so the Rust test sees the same input
/// the Python side would produce after `strip_none_values`.
///
/// `None` is explicitly rejected: the fixture regenerator is responsible
/// for emitting `None`-free args. If one slips in, fail loudly rather
/// than silently choose a coercion that diverges from the Python side.
fn json_to_constraint_value(v: &JsonValue) -> ConstraintValue {
    match v {
        JsonValue::String(s) => ConstraintValue::String(s.clone()),
        JsonValue::Bool(b) => ConstraintValue::Boolean(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                ConstraintValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                ConstraintValue::Float(f)
            } else {
                panic!("fixture number is neither i64 nor f64: {:?}", n);
            }
        }
        JsonValue::Array(items) => {
            ConstraintValue::List(items.iter().map(json_to_constraint_value).collect())
        }
        JsonValue::Null => {
            panic!("fixture contains a null value — regenerator must emit None-free args")
        }
        JsonValue::Object(_) => panic!(
            "fixture contains a nested object — Rust ConstraintValue has no object variant \
             at the arg-dict top level, and the regenerator must not emit them"
        ),
    }
}

fn json_object_to_arg_map(
    obj: &serde_json::Map<String, JsonValue>,
) -> HashMap<String, ConstraintValue> {
    obj.iter()
        .map(|(k, v)| (k.clone(), json_to_constraint_value(v)))
        .collect()
}

#[test]
fn rust_pop_matches_cross_language_fixture() {
    let fixture: JsonValue = serde_json::from_str(FIXTURE_BYTES).expect("fixture JSON must parse");
    let cases = fixture
        .get("cases")
        .and_then(JsonValue::as_array)
        .expect("fixture must have a .cases array");

    let holder_hex = fixture
        .get("holder_priv_hex")
        .and_then(JsonValue::as_str)
        .expect("fixture must have .holder_priv_hex");
    let holder_bytes: [u8; 32] = hex::decode(holder_hex)
        .expect("holder_priv_hex must be valid hex")
        .try_into()
        .expect("holder key must be exactly 32 bytes");
    let holder = SigningKey::from_bytes(&holder_bytes);

    let mut failures: Vec<(String, String, String)> = Vec::new();

    for case in cases {
        let name = case
            .get("name")
            .and_then(JsonValue::as_str)
            .unwrap_or("<unnamed>")
            .to_string();
        let tool = case
            .get("tool")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("case {:?} missing .tool", name));
        let timestamp = case
            .get("timestamp")
            .and_then(JsonValue::as_i64)
            .unwrap_or_else(|| panic!("case {:?} missing .timestamp", name));
        let warrant_b64 = case
            .get("warrant_b64")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("case {:?} missing .warrant_b64", name));
        let expected_hex = case
            .get("expected_signature_hex")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("case {:?} missing .expected_signature_hex", name));
        let args_obj = case
            .get("args")
            .and_then(JsonValue::as_object)
            .unwrap_or_else(|| panic!("case {:?} .args must be an object", name));

        let warrant = wire::decode_base64(warrant_b64).expect("warrant_b64 must decode");
        let args = json_object_to_arg_map(args_obj);

        let sig = warrant
            .sign_with_timestamp(&holder, tool, &args, Some(timestamp))
            .expect("sign_with_timestamp must succeed");
        let got = sig.to_bytes();

        let expected = hex::decode(expected_hex).expect("expected_signature_hex must be hex");
        if got.as_slice() != expected.as_slice() {
            failures.push((name, expected_hex.to_string(), hex::encode(got)));
        }
    }

    assert!(
        failures.is_empty(),
        "PoP canonicalization drift — Rust sign_with_timestamp did not reproduce the \
         fixture for {} case(s):\n{}",
        failures.len(),
        failures
            .iter()
            .map(|(name, exp, got)| format!(
                "  {}:\n    expected {}\n    got      {}",
                name, exp, got
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
