//! Shared holder-lifecycle vectors (`tests/vectors/holder-lifecycle.json`).

#![cfg(feature = "server")]

use serde_json::Value;
use tenuo::connect_token::ConnectToken;
use tenuo::SigningKey;

const VECTORS: &str = include_str!("../../tests/vectors/holder-lifecycle.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("holder-lifecycle vectors")
}

#[test]
fn connect_token_vectors() {
    for case in vectors()["connect_tokens"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap();
        let name = case["name"].as_str().unwrap();
        if case["expect"].as_str() == Some("error") {
            let err = ConnectToken::parse(raw).expect_err(name);
            let needle = case["error_contains"].as_str().unwrap();
            assert!(
                err.to_string().contains(needle),
                "{name}: {err} does not contain {needle:?}"
            );
            continue;
        }
        let mut token = ConnectToken::parse(raw).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            token.version,
            case["version"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(token.endpoint, case["endpoint"].as_str().unwrap(), "{name}");
        assert_eq!(token.api_key, case["api_key"].as_str().unwrap(), "{name}");
        assert_eq!(
            token.agent_id.as_deref(),
            case["agent_id"].as_str(),
            "{name}"
        );
        assert_eq!(
            token.registration_token.as_deref(),
            case["registration_token"].as_str(),
            "{name}"
        );
        assert_eq!(
            token.needs_endpoint_base(),
            case["needs_endpoint_base"].as_bool().unwrap(),
            "{name}"
        );
        if let Some(base) = case["resolve_base"].as_str() {
            token.resolve_endpoint(base).unwrap();
            assert_eq!(
                token.endpoint,
                case["resolved_endpoint"].as_str().unwrap(),
                "{name}"
            );
            assert!(!token.needs_endpoint_base(), "{name}");
        }
    }
}

#[test]
fn identity_vector_derives_and_redacts() {
    let case = &vectors()["identity"];
    let secret = hex::decode(case["secret_hex"].as_str().unwrap()).unwrap();
    let key = SigningKey::from_bytes(secret.as_slice().try_into().unwrap());
    assert_eq!(
        hex::encode(key.public_key().to_bytes()),
        case["public_key_hex"].as_str().unwrap()
    );
    let rendered = format!("{key:?}");
    assert!(!rendered.contains(case["secret_hex"].as_str().unwrap()));
}

#[test]
fn receipt_contract_flags() {
    let receipts = &vectors()["receipts"];
    assert_eq!(receipts["drain_is_snapshot"], true);
    assert_eq!(receipts["remove_only_on_acknowledge"], true);
    assert_eq!(receipts["overflow_does_not_deny_authorized_call"], true);
    assert_eq!(receipts["overflow_is_observable"], true);
}
