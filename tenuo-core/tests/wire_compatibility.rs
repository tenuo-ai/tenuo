use ciborium::value::Value;
use tenuo::constraints::{Shlex, UrlSafe};
use tenuo::warrant::Warrant;
use tenuo::{
    All, Any, CelConstraint, Cidr, Constraint, ConstraintSet, Contains, Exact, Not, NotOneOf,
    OneOf, Pattern, Range, RegexConstraint, Subpath, Subset, UrlPattern, Wildcard,
};

/// RFC 8032 Test Vector 1 — a known valid, non-weak Ed25519 public key.
/// Using this instead of `vec![0u8; 32]` (the identity/small-order point) in tests that
/// must reach later validation stages without being blocked by the is_weak() check.
const VALID_ED25519_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

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
    assert!(
        err.contains("variant")
            || err.contains("unknown")
            || err.contains("invalid value")
            || err.contains("invalid warrant type")
    );
}

#[test]
fn test_unknown_payload_field_fails_deserialization() {
    // Similar setup but with valid type and unknown key 99

    let map = vec![
        (Value::Integer(0.into()), Value::Integer(1.into())), // Version = 1
        (Value::Integer(1.into()), Value::Bytes(vec![0u8; 16])), // ID
        (Value::Integer(2.into()), Value::Integer(0.into())), // Type = 0 (Execution)
        (Value::Integer(3.into()), Value::Map(vec![])),       // Tools = {}
        (
            Value::Integer(4.into()),
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(VALID_ED25519_PUBKEY.to_vec()),
            ]),
        ), // Holder
        (
            Value::Integer(5.into()),
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(VALID_ED25519_PUBKEY.to_vec()),
            ]),
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

// ---------------------------------------------------------------------------
// Constraint members: the decoder rejects members it does not know, and
// everything Tenuo itself writes still decodes.
// ---------------------------------------------------------------------------

fn to_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    ciborium::de::from_reader(to_cbor(value).as_slice()).unwrap()
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    ciborium::de::from_reader(to_cbor(value).as_slice()).map_err(|e| e.to_string())
}

/// The payload map of an encoded constraint (`[type_id, payload]`), if it is a map.
fn payload_map(encoded: &mut Value) -> Option<&mut Vec<(Value, Value)>> {
    match encoded {
        Value::Array(items) if items.len() == 2 => match &mut items[1] {
            Value::Map(map) => Some(map),
            _ => None,
        },
        _ => None,
    }
}

/// One of every constraint type, with optional members both set and left unset.
fn every_constraint() -> Vec<Constraint> {
    let mut cel_with_parent = CelConstraint::new("amount < 100");
    cel_with_parent.parent_expression = Some("amount < 1000".to_string());
    let mut url_safe_with_options = UrlSafe::with_domains(vec!["api.example.com"]);
    url_safe_with_options.deny_domains = Some(vec!["evil.example.com".to_string()]);
    url_safe_with_options.allow_ports = Some(vec![443]);
    url_safe_with_options.block_internal_tlds = true;
    vec![
        Constraint::Wildcard(Wildcard::new()),
        Constraint::Pattern(Pattern::new("staging-*").unwrap()),
        Constraint::Regex(RegexConstraint::new("^prod-[a-z]+$").unwrap()),
        Constraint::Exact(Exact::new("read")),
        Constraint::OneOf(OneOf::new(["a", "b"])),
        Constraint::NotOneOf(NotOneOf::new(["x"])),
        Constraint::Range(Range::new(Some(0.0), None).unwrap()),
        Constraint::Range(Range::new(None, Some(10.0)).unwrap().max_exclusive()),
        Constraint::Range(Range::new(Some(1.0), Some(5.0)).unwrap().min_exclusive()),
        Constraint::Cidr(Cidr::new("10.0.0.0/8").unwrap()),
        Constraint::UrlPattern(UrlPattern::new("https://api.example.com/*").unwrap()),
        Constraint::Contains(Contains::new(["admin"])),
        Constraint::Subset(Subset::new(["read", "write"])),
        Constraint::All(All::new([Constraint::Exact(Exact::new("a"))])),
        Constraint::Any(Any::new([Constraint::Pattern(Pattern::new("a*").unwrap())])),
        Constraint::Not(Not::new(Constraint::Exact(Exact::new("root")))),
        Constraint::Cel(CelConstraint::new("amount < 100")),
        Constraint::Cel(cel_with_parent),
        Constraint::Subpath(Subpath::new("/data").unwrap()),
        Constraint::Subpath(Subpath::with_options("/data", false, false).unwrap()),
        Constraint::UrlSafe(UrlSafe::new()),
        Constraint::UrlSafe(url_safe_with_options),
        Constraint::Shlex(Shlex::new(vec!["ls"])),
    ]
}

#[test]
fn test_every_constraint_type_round_trips_under_strict_decoding() {
    // Wire compatibility: nothing Tenuo writes may carry a member its decoder rejects.
    for constraint in every_constraint() {
        let bytes = to_cbor(&constraint);
        let decoded: Constraint = ciborium::de::from_reader(bytes.as_slice())
            .unwrap_or_else(|e| panic!("{constraint:?} no longer decodes: {e}"));
        assert_eq!(
            to_cbor(&decoded),
            bytes,
            "{constraint:?} did not round-trip"
        );
    }

    for allow_unknown in [false, true] {
        let mut set = ConstraintSet::new();
        for (i, constraint) in every_constraint().into_iter().enumerate() {
            set.insert(format!("arg{i}"), constraint);
        }
        set.set_allow_unknown(allow_unknown);
        let bytes = to_cbor(&set);
        let decoded: ConstraintSet = ciborium::de::from_reader(bytes.as_slice())
            .unwrap_or_else(|e| panic!("constraint set no longer decodes: {e}"));
        assert_eq!(to_cbor(&decoded), bytes);
    }
}

#[test]
fn test_unknown_constraint_member_fails_deserialization() {
    let mut checked = 0;
    for constraint in every_constraint() {
        let mut encoded = to_value(&constraint);
        let Some(map) = payload_map(&mut encoded) else {
            continue; // Wildcard, Cidr and UrlPattern payloads are not maps
        };
        map.push((Value::Text("future_member".into()), Value::Bool(true)));
        let err = decode::<Constraint>(&encoded)
            .expect_err(&format!("{constraint:?} accepted an unknown member"));
        assert!(err.contains("unknown field"), "{constraint:?}: {err}");
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} map payloads exercised");

    let mut set = ConstraintSet::new();
    set.insert("amount", Range::new(None, Some(10.0)).unwrap());
    let mut encoded = to_value(&set);
    let Value::Map(map) = &mut encoded else {
        panic!("a constraint set encodes as a map");
    };
    map.push((Value::Text("future_member".into()), Value::Bool(true)));
    let err =
        decode::<ConstraintSet>(&encoded).expect_err("constraint set accepted an unknown member");
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn test_misspelled_range_bound_fails_deserialization() {
    // A bound under the wrong name used to be dropped, leaving the range unbounded.
    let mut encoded = to_value(&Constraint::Range(Range::new(None, Some(10.0)).unwrap()));
    let map = payload_map(&mut encoded).unwrap();
    for (key, _) in map.iter_mut() {
        if *key == Value::Text("max".into()) {
            *key = Value::Text("maximum".into());
        }
    }
    let err = decode::<Constraint>(&encoded).expect_err("`maximum` decoded as an unbounded range");
    assert!(err.contains("unknown field `maximum`"), "{err}");
}

#[test]
fn test_non_finite_range_bound_fails_deserialization() {
    let mut encoded = to_value(&Constraint::Range(Range::new(None, Some(10.0)).unwrap()));
    let map = payload_map(&mut encoded).unwrap();
    let (_, max) = map
        .iter_mut()
        .find(|(key, _)| *key == Value::Text("max".into()))
        .expect("serialized range max");
    *max = Value::Float(f64::INFINITY);

    let err = decode::<Constraint>(&encoded).expect_err("infinite range bound was accepted");
    assert!(err.contains("range bound must be finite"), "{err}");
}

#[test]
fn test_unknown_constraint_member_fails_warrant_deserialization() {
    let mut set = ConstraintSet::new();
    set.insert("amount", Range::new(None, Some(10.0)).unwrap());
    let mut set_value = to_value(&set);
    let Value::Map(set_map) = &mut set_value else {
        panic!("a constraint set encodes as a map");
    };
    let range = set_map
        .iter_mut()
        .find_map(|(k, v)| (*k == Value::Text("constraints".into())).then_some(v))
        .and_then(|constraints| match constraints {
            Value::Map(args) => args.first_mut().map(|(_, c)| c),
            _ => None,
        })
        .and_then(payload_map)
        .expect("range payload map");
    range.push((Value::Text("max_exclusive".into()), Value::Bool(true)));

    let payload = Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(1.into())), // Version = 1
        (Value::Integer(1.into()), Value::Bytes(vec![0u8; 16])), // ID
        (Value::Integer(2.into()), Value::Integer(0.into())), // Type = 0 (Execution)
        (
            Value::Integer(3.into()),
            Value::Map(vec![(Value::Text("transfer".into()), set_value)]),
        ), // Tools
        (
            Value::Integer(4.into()),
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(VALID_ED25519_PUBKEY.to_vec()),
            ]),
        ), // Holder
        (
            Value::Integer(5.into()),
            Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(VALID_ED25519_PUBKEY.to_vec()),
            ]),
        ), // Issuer
        (Value::Integer(6.into()), Value::Integer(0.into())), // IssuedAt
        (Value::Integer(7.into()), Value::Integer(0.into())), // ExpiresAt
        (Value::Integer(8.into()), Value::Integer(0.into())), // MaxDepth
    ]);
    let envelope = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(to_cbor(&payload)),
        Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0u8; 64])]),
    ]);

    let result: Result<Warrant, _> = ciborium::de::from_reader(&to_cbor(&envelope)[..]);
    let err = result
        .expect_err("warrant accepted an unknown constraint member")
        .to_string();
    assert!(err.contains("unknown field `max_exclusive`"), "{err}");
}

#[test]
fn test_constraint_rejects_trailing_tuple_members() {
    let encoded = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Map(vec![(
            Value::Text("value".into()),
            Value::Text("allowed".into()),
        )]),
        Value::Map(vec![(
            Value::Text("future_restriction".into()),
            Value::Bool(true),
        )]),
    ]);

    let err =
        decode::<Constraint>(&encoded).expect_err("constraint accepted a trailing tuple member");
    assert!(err.contains("length 3"), "{err}");
}

#[test]
fn test_unknown_constraint_preserves_arbitrary_payload_shape() {
    let encoded = Value::Array(vec![
        Value::Integer(200.into()),
        Value::Map(vec![
            (
                Value::Text("region".into()),
                Value::Text("us-east-1".into()),
            ),
            (Value::Text("strict".into()), Value::Bool(true)),
        ]),
    ]);
    let expected_payload = match &encoded {
        Value::Array(items) => items[1].clone(),
        _ => unreachable!(),
    };

    let constraint: Constraint = decode(&encoded).expect("unknown map payload must decode");
    let Constraint::Unknown { type_id, payload } = &constraint else {
        panic!("expected an unknown constraint, got {constraint:?}");
    };
    assert_eq!(*type_id, 200);
    let preserved: Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    assert_eq!(preserved, expected_payload);
    assert!(constraint
        .matches(&tenuo::ConstraintValue::String("anything".into()))
        .is_err());
    assert_eq!(to_value(&constraint), encoded);
}

#[test]
fn test_warrant_preserves_unknown_constraint_payload_shape() {
    let signing_key = tenuo::SigningKey::generate();
    let public_key = to_value(&signing_key.public_key());
    let unknown_constraint = Value::Array(vec![
        Value::Integer(200.into()),
        Value::Map(vec![(
            Value::Text("region".into()),
            Value::Text("us-east-1".into()),
        )]),
    ]);
    let mut set = ConstraintSet::new();
    set.insert("region", Exact::new("placeholder"));
    let mut set_value = to_value(&set);
    let Value::Map(set_map) = &mut set_value else {
        panic!("a constraint set encodes as a map");
    };
    let constraint = set_map
        .iter_mut()
        .find_map(|(key, value)| (*key == Value::Text("constraints".into())).then_some(value))
        .and_then(|constraints| match constraints {
            Value::Map(args) => args.first_mut().map(|(_, constraint)| constraint),
            _ => None,
        })
        .expect("constraint payload");
    *constraint = unknown_constraint;

    let payload = Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(1.into())),
        (Value::Integer(1.into()), Value::Bytes(vec![0u8; 16])),
        (Value::Integer(2.into()), Value::Integer(0.into())),
        (
            Value::Integer(3.into()),
            Value::Map(vec![(Value::Text("deploy".into()), set_value)]),
        ),
        (Value::Integer(4.into()), public_key.clone()),
        (Value::Integer(5.into()), public_key),
        (Value::Integer(6.into()), Value::Integer(0.into())),
        (Value::Integer(7.into()), Value::Integer(0.into())),
        (Value::Integer(8.into()), Value::Integer(0.into())),
    ]);
    let payload_bytes = to_cbor(&payload);
    let mut signature_preimage = vec![1];
    signature_preimage.extend_from_slice(&payload_bytes);
    let signature = signing_key.sign(&signature_preimage);
    let envelope = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(payload_bytes),
        to_value(&signature),
    ]);
    let envelope_bytes = to_cbor(&envelope);

    let warrant: Warrant = decode(&envelope).expect("unknown constraint payload must be preserved");
    assert_eq!(tenuo::wire::encode(&warrant).unwrap(), envelope_bytes);

    let constraints = warrant
        .capabilities()
        .and_then(|capabilities| capabilities.get("deploy"))
        .expect("decoded deploy constraints");
    let constraint = constraints
        .get("region")
        .expect("unknown constraint in decoded warrant");
    assert!(matches!(
        constraint,
        Constraint::Unknown { type_id: 200, .. }
    ));

    let args = std::collections::HashMap::from([(
        "region".to_string(),
        tenuo::ConstraintValue::String("us-east-1".into()),
    )]);
    assert!(
        constraints.matches(&args).is_err(),
        "a constraint set containing an unknown constraint must fail closed"
    );
}
