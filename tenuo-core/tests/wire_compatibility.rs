use ciborium::value::Value;
use tenuo::warrant::Warrant;

#[test]
fn test_unknown_warrant_type_fails_deserialization() {
    // Manually construct CBOR that looks like a Warrant but with a string type "audit"

    // Construct a valid payload map
    let map = vec![
        (Value::Integer(0.into()), Value::Integer(1.into())), // Version = 1
        (Value::Integer(1.into()), Value::Bytes(vec![0u8; 16])), // ID
        (Value::Integer(2.into()), Value::Integer(99.into())), // Type = 99 (Unknown)
        (Value::Integer(3.into()), Value::Map(vec![])),       // Tools = {}
        (
            Value::Integer(4.into()),
            Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0u8; 32])]),
        ), // Holder
        (
            Value::Integer(5.into()),
            Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0u8; 32])]),
        ), // Issuer
        (Value::Integer(6.into()), Value::Integer(0.into())), // IssuedAt
        (Value::Integer(7.into()), Value::Integer(0.into())), // ExpiresAt
        (Value::Integer(8.into()), Value::Integer(0.into())), // MaxDepth
    ];

    let payload = Value::Map(map);

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).unwrap();

    // Wrap in Envelope
    // Envelope is [ver, payload_bytes, sig]
    let sig_bytes = vec![0u8; 64]; // Mock sig bytes

    let env_ver = Value::Integer(1.into());
    let payload_val = Value::Bytes(payload_bytes);
    let sig_val = Value::Array(vec![Value::Integer(1.into()), Value::Bytes(sig_bytes)]);

    let envelope = Value::Array(vec![env_ver, payload_val, sig_val]);

    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut envelope_bytes).unwrap();

    // Attempt deserialize
    let result: Result<Warrant, _> = ciborium::de::from_reader(&envelope_bytes[..]);

    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    // Error message depends on serde impl. Probably "unknown variant `audit`..."
    println!("Error: {}", err);
    assert!(err.contains("variant") || err.contains("unknown") || err.contains("invalid value") || err.contains("invalid warrant type"));
}

#[test]
fn test_unknown_payload_field_fails_deserialization() {
    // Similar setup but with valid type and unknown key 99

    let map = vec![
        (Value::Integer(0.into()), Value::Integer(1.into())), // Version = 1
        (Value::Integer(1.into()), Value::Bytes(vec![0u8; 16])), // ID
        (
            Value::Integer(2.into()),
            Value::Integer(0.into()),
        ), // Type = 0 (Execution)
        (Value::Integer(3.into()), Value::Map(vec![])),       // Tools = {}
        (
            Value::Integer(4.into()),
            Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0u8; 32])]),
        ), // Holder
        (
            Value::Integer(5.into()),
            Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0u8; 32])]),
        ), // Issuer
        (Value::Integer(6.into()), Value::Integer(0.into())), // IssuedAt
        (Value::Integer(7.into()), Value::Integer(0.into())), // ExpiresAt
        (Value::Integer(8.into()), Value::Integer(0.into())), // MaxDepth
        // UNKNOWN FIELD
        (
            Value::Integer(99.into()),
            Value::Text("FutureData".to_string()),
        ),
    ];

    let payload = Value::Map(map);

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).unwrap();

    // Envelope
    let sig_bytes = vec![0u8; 64];
    let envelope = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(payload_bytes),
        Value::Array(vec![Value::Integer(1.into()), Value::Bytes(sig_bytes)]),
    ]);

    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut envelope_bytes).unwrap();

    let result: Result<Warrant, _> = ciborium::de::from_reader(&envelope_bytes[..]);

    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    println!("Error: {}", err);
    assert!(err.contains("unknown payload field key 99"));
}
