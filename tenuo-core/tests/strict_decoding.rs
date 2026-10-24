//! Signed payloads and policy files reject members they do not define.
//!
//! Each test first decodes the unmodified input, so a failure can only come from
//! the added member.

use chrono::{Duration, Utc};
use ciborium::value::Value;
use tenuo::approval::{ApprovalPayload, SignedApproval};
use tenuo::crypto::SigningKey;
use tenuo::domain::APPROVAL_CONTEXT;
use tenuo::gateway_config::{CompiledGatewayConfig, GatewayConfig};
use tenuo::mcp::{CompiledMcpConfig, McpConfig};
use tenuo::receipt::{Receipt, ReceiptPayload};
use tenuo::revocation::{RevocationRequest, SignedRevocationList};

fn to_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn to_value(bytes: &[u8]) -> Value {
    ciborium::de::from_reader(bytes).unwrap()
}

/// `value` (a CBOR map) with one more member, which no version of the format defines.
fn with_unknown_member(mut value: Value) -> Value {
    match &mut value {
        Value::Map(entries) => {
            entries.push((Value::Text("future_member".into()), Value::Bool(true)))
        }
        other => panic!("expected a CBOR map, got {other:?}"),
    }
    value
}

fn assert_unknown_field(err: impl std::fmt::Display) {
    let err = err.to_string();
    assert!(err.contains("unknown field"), "unexpected error: {err}");
}

// ============================================================================
// Signed payloads
// ============================================================================

#[test]
fn signed_approval_rejects_unknown_members() {
    let key = SigningKey::generate();
    let now = Utc::now();
    let payload = ApprovalPayload::new(
        [7; 32],
        rand::random(),
        "user:alice".into(),
        now,
        now + Duration::minutes(5),
    );

    // Envelope
    let envelope = to_cbor(&SignedApproval::create(payload.clone(), &key));
    ciborium::de::from_reader::<SignedApproval, _>(envelope.as_slice()).unwrap();
    let extended = to_cbor(&with_unknown_member(to_value(&envelope)));
    assert_unknown_field(
        ciborium::de::from_reader::<SignedApproval, _>(extended.as_slice()).unwrap_err(),
    );

    // Payload, correctly signed, so only the added member can fail verification
    let sign = |payload: Vec<u8>| {
        let mut preimage = APPROVAL_CONTEXT.to_vec();
        preimage.push(1);
        preimage.extend_from_slice(&payload);
        SignedApproval {
            approval_version: 1,
            payload,
            approver_key: key.public_key(),
            signature: key.sign(&preimage),
        }
    };
    let payload_bytes = to_cbor(&payload);
    sign(payload_bytes.clone()).verify().unwrap();
    let extended = to_cbor(&with_unknown_member(to_value(&payload_bytes)));
    assert_unknown_field(sign(extended).verify().unwrap_err());
}

#[test]
fn signed_revocation_list_rejects_unknown_members() {
    let key = SigningKey::generate();
    let srl = SignedRevocationList::builder()
        .revoke("tnu_wrt_1")
        .version(3)
        .build(&key)
        .unwrap();
    let bytes = srl.to_bytes().unwrap();
    SignedRevocationList::from_bytes(&bytes).unwrap();

    // Envelope
    let extended = to_cbor(&with_unknown_member(to_value(&bytes)));
    assert_unknown_field(SignedRevocationList::from_bytes(&extended).unwrap_err());

    // Payload
    let Value::Map(mut entries) = to_value(&bytes) else {
        panic!("SRL is not a CBOR map");
    };
    let payload = entries
        .iter_mut()
        .find(|(k, _)| k == &Value::Text("payload".into()))
        .map(|(_, v)| v)
        .expect("SRL has a payload member");
    *payload = with_unknown_member(payload.clone());
    let extended = to_cbor(&Value::Map(entries));
    assert_unknown_field(SignedRevocationList::from_bytes(&extended).unwrap_err());
}

#[test]
fn revocation_request_rejects_unknown_members() {
    let key = SigningKey::generate();
    let bytes = RevocationRequest::new("tnu_wrt_1", "key rotated", &key)
        .unwrap()
        .to_bytes()
        .unwrap();
    RevocationRequest::from_bytes(&bytes).unwrap();

    let extended = to_cbor(&with_unknown_member(to_value(&bytes)));
    assert_unknown_field(RevocationRequest::from_bytes(&extended).unwrap_err());
}

#[test]
fn receipt_rejects_unknown_members() {
    let key = SigningKey::generate();
    let payload = ReceiptPayload::allow(vec![0xA1], "read_file", 1_700_000_000, "req-1", [9; 64]);
    let bytes = to_cbor(&Receipt::create(&payload, &key).unwrap());
    ciborium::de::from_reader::<Receipt, _>(bytes.as_slice()).unwrap();

    let extended = to_cbor(&with_unknown_member(to_value(&bytes)));
    assert_unknown_field(ciborium::de::from_reader::<Receipt, _>(extended.as_slice()).unwrap_err());
}

// ============================================================================
// Policy files
// ============================================================================

const GATEWAY: &str = r#"
version: "1"
settings:
  trusted_roots: []
tools:
  read_pods:
    description: "List pods"
    constraints:
      cluster:
        from: path
        path: "cluster"
        required: true
routes:
  - pattern: "/api/{cluster}/pods"
    method: ["GET"]
    tool: "read_pods"
"#;

const MCP: &str = r#"
version: "1"
settings:
  trusted_issuers: []
tools:
  read_file:
    description: "Read a file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
"#;

fn load_gateway(yaml: &str) -> Result<CompiledGatewayConfig, String> {
    let config = GatewayConfig::from_yaml(yaml).map_err(|e| e.to_string())?;
    CompiledGatewayConfig::compile(config).map_err(|e| e.to_string())
}

fn load_mcp(yaml: &str) -> Result<CompiledMcpConfig, String> {
    let config: McpConfig = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    CompiledMcpConfig::compile(config).map_err(|e| e.to_string())
}

/// `yaml` with `line` added after `anchor`.
fn with_line_after(yaml: &str, anchor: &str, line: &str) -> String {
    assert!(yaml.contains(anchor), "anchor not found: {anchor}");
    yaml.replacen(anchor, &format!("{anchor}\n{line}"), 1)
}

#[test]
fn gateway_config_rejects_unknown_keys() {
    load_gateway(GATEWAY).unwrap();

    for (level, yaml) in [
        ("config", format!("{GATEWAY}future_key: true\n")),
        (
            "settings",
            with_line_after(GATEWAY, "  trusted_roots: []", "  future_key: true"),
        ),
        (
            "tool",
            with_line_after(
                GATEWAY,
                "    description: \"List pods\"",
                "    future_key: true",
            ),
        ),
        (
            "extraction rule",
            with_line_after(
                GATEWAY,
                "        required: true",
                "        future_key: true",
            ),
        ),
        (
            "route",
            with_line_after(GATEWAY, "    tool: \"read_pods\"", "    future_key: true"),
        ),
        (
            "misspelled route key",
            GATEWAY.replace("method:", "methods:"),
        ),
    ] {
        match load_gateway(&yaml) {
            Ok(_) => panic!("{level}: unknown key was accepted"),
            Err(err) => assert!(err.contains("unknown field"), "{level}: {err}"),
        }
    }
}

#[test]
fn mcp_config_rejects_unknown_keys() {
    load_mcp(MCP).unwrap();

    for (level, yaml) in [
        ("config", format!("{MCP}future_key: true\n")),
        (
            "settings",
            with_line_after(MCP, "  trusted_issuers: []", "  future_key: true"),
        ),
        (
            "tool",
            with_line_after(
                MCP,
                "    description: \"Read a file\"",
                "    future_key: true",
            ),
        ),
        (
            "extraction rule",
            with_line_after(MCP, "        required: true", "        future_key: true"),
        ),
    ] {
        match load_mcp(&yaml) {
            Ok(_) => panic!("{level}: unknown key was accepted"),
            Err(err) => assert!(err.contains("unknown field"), "{level}: {err}"),
        }
    }
}

#[test]
fn shipped_configs_parse() {
    // The shipped configs live outside this crate, so the published package
    // does not carry them: read them from the repository, and skip elsewhere.
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    if !repo.join(".git").exists() {
        eprintln!("shipped_configs_parse: not a repository checkout, skipping");
        return;
    }
    let read = |path: &str| {
        std::fs::read_to_string(repo.join(path)).unwrap_or_else(|err| panic!("{path}: {err}"))
    };

    for path in [
        "demo/config/gateway.yaml",
        "docs/quickstart/envoy/gateway.yaml",
        "examples/gateway-config.yaml",
        "templates/gateway/database-query.yaml",
        "templates/gateway/file-operations.yaml",
        "templates/gateway/http-request.yaml",
        "templates/gateway/kubernetes-ops.yaml",
    ] {
        if let Err(err) = GatewayConfig::from_yaml(&read(path)) {
            panic!("{path}: {err}");
        }
    }

    for path in [
        "examples/mcp-config.yaml",
        "tenuo-python/examples/mcp-config.yaml",
    ] {
        if let Err(err) = serde_yaml::from_str::<McpConfig>(&read(path)) {
            panic!("{path}: {err}");
        }
    }
}
