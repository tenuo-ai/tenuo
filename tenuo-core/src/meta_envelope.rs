//! One encoding of `_meta.tenuo`.
//!
//! [`sign_meta`] writes the envelope. [`decode_meta`] reads it. Python and
//! TypeScript translate a host value into argument JSON text and call these
//! functions. They do not choose a base64 alphabet, frame a warrant stack, or
//! drop nulls.
//!
//! The signed argument map is this module's parse of that JSON text. A null
//! stays a null. The tool may still execute the host's own parse of the same
//! text.
//!
//! The canonical alphabet is standard base64, which a previous server already
//! decodes. [`decode_meta`] still accepts unpadded URL-safe text so an
//! envelope already issued in that alphabet can be checked. That fallback is
//! not a second representation, and the shared vector file does not use it.

use base64::Engine;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::approval::SignedApproval;
use crate::constraints::ConstraintValue;
use crate::crypto::{Signature, SigningKey};
use crate::error::Error;
use crate::strict_json::{parse_json_strict, StrictJsonError};
use crate::warrant::{Warrant, POP_TIMESTAMP_WINDOW_SECS};
use crate::wire::{self, MAX_STACK_SIZE};

const WARRANT_STRING_MAX: usize = 64 * 1024;
const SIGNATURE_STRING_MAX: usize = 4 * 1024;
const APPROVAL_STRING_MAX: usize = 8 * 1024;
const MAX_APPROVALS: usize = 64;
const MAX_JSON_DEPTH: usize = 8;
const MAX_JSON_STRING: usize = 8 * 1024;
const MAX_JSON_ITEMS: usize = 256;

/// `_meta.tenuo` as the three wire fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenuoMeta {
    /// Standard base64 of the CBOR warrant stack.
    pub warrant: String,
    /// Standard base64 of the 64-byte proof.
    pub signature: String,
    /// Standard base64 of each approval. Empty omits the field.
    pub approvals: Vec<String>,
}

impl TenuoMeta {
    /// JSON object placed at `_meta.tenuo`.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("warrant".into(), Value::String(self.warrant.clone()));
        object.insert("signature".into(), Value::String(self.signature.clone()));
        if !self.approvals.is_empty() {
            object.insert(
                "approvals".into(),
                Value::Array(self.approvals.iter().cloned().map(Value::String).collect()),
            );
        }
        Value::Object(object)
    }
}

/// Warrant chain, proof, and approvals from an envelope.
#[derive(Debug, Clone)]
pub struct DecodedMeta {
    /// Root first, leaf last.
    pub warrants: Vec<Warrant>,
    /// Holder proof over the core argument map.
    pub signature: Signature,
    /// Approvals attached to the call. Empty when the field is absent.
    pub approvals: Vec<SignedApproval>,
}

/// Why an envelope could not be signed or read.
#[derive(Debug)]
pub enum MetaError {
    /// The chain had no warrant to sign.
    EmptyChain,
    /// Argument JSON was not an object this module can sign.
    InvalidArguments(String),
    /// A field was not the expected base64 or CBOR.
    InvalidEncoding,
    /// The proof was not 64 bytes.
    InvalidSignature,
    /// More than [`MAX_APPROVALS`] approvals.
    TooManyApprovals,
    /// A field exceeded its size bound.
    PayloadTooLarge,
    /// Signing or proof verification failed.
    Proof(Error),
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "warrant chain is empty"),
            Self::InvalidArguments(msg) => write!(f, "argument JSON: {msg}"),
            Self::InvalidEncoding => write!(f, "_meta.tenuo encoding is invalid"),
            Self::InvalidSignature => write!(f, "_meta.tenuo signature is not 64 bytes"),
            Self::TooManyApprovals => write!(f, "too many approvals"),
            Self::PayloadTooLarge => write!(f, "_meta.tenuo field exceeds size limit"),
            Self::Proof(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for MetaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proof(err) => Some(err),
            _ => None,
        }
    }
}

impl From<MetaError> for Error {
    fn from(err: MetaError) -> Self {
        match err {
            MetaError::Proof(inner) => inner,
            other => Error::Validation(other.to_string()),
        }
    }
}

/// Sign `_meta.tenuo` for `args_json` at `timestamp`.
///
/// `args_json` is the argument text. The signature covers this module's parse
/// of that text, including JSON null. `timestamp` is unix seconds. The proof
/// window is [`POP_TIMESTAMP_WINDOW_SECS`].
pub fn sign_meta(
    warrants: &[Warrant],
    key: &SigningKey,
    tool: &str,
    args_json: &str,
    timestamp: i64,
    approvals: &[SignedApproval],
) -> std::result::Result<TenuoMeta, MetaError> {
    let leaf = warrants.last().ok_or(MetaError::EmptyChain)?;
    let args = args_from_json(args_json)?;
    let signature = leaf
        .sign_with_timestamp(key, tool, &args, Some(timestamp))
        .map_err(MetaError::Proof)?;
    encode_meta(warrants, &signature.to_bytes(), approvals)
}

/// Encode a chain, proof, and approvals as `_meta.tenuo`.
pub fn encode_meta(
    warrants: &[Warrant],
    signature: &[u8],
    approvals: &[SignedApproval],
) -> std::result::Result<TenuoMeta, MetaError> {
    if warrants.is_empty() {
        return Err(MetaError::EmptyChain);
    }
    if signature.len() != 64 {
        return Err(MetaError::InvalidSignature);
    }
    if approvals.len() > MAX_APPROVALS {
        return Err(MetaError::TooManyApprovals);
    }
    let warrant = encode_warrant_chain(warrants)?;
    let mut approval_tokens = Vec::with_capacity(approvals.len());
    for approval in approvals {
        approval_tokens.push(encode_approval(approval)?);
    }
    Ok(TenuoMeta {
        warrant,
        signature: encode_token(signature),
        approvals: approval_tokens,
    })
}

/// Read `_meta.tenuo`. Accepts standard base64 and unpadded URL-safe base64.
/// A PEM chain in `warrant` is accepted as well.
pub fn decode_meta(value: &Value) -> std::result::Result<DecodedMeta, MetaError> {
    let object = value.as_object().ok_or(MetaError::InvalidEncoding)?;
    let warrant = object
        .get("warrant")
        .and_then(Value::as_str)
        .ok_or(MetaError::InvalidEncoding)?;
    let signature = object
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(MetaError::InvalidEncoding)?;
    let approvals = match object.get("approvals") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or(MetaError::InvalidEncoding)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?,
        Some(_) => return Err(MetaError::InvalidEncoding),
    };
    decode_meta_parts(warrant, signature, &approvals)
}

/// Read the three wire fields. `approvals` may be empty.
pub fn decode_meta_parts(
    warrant: &str,
    signature: &str,
    approvals: &[String],
) -> std::result::Result<DecodedMeta, MetaError> {
    let warrants = decode_warrant_chain(warrant)?;
    let signature = decode_signature(signature)?;
    if approvals.len() > MAX_APPROVALS {
        return Err(MetaError::TooManyApprovals);
    }
    let mut decoded_approvals = Vec::with_capacity(approvals.len());
    for token in approvals {
        decoded_approvals.push(decode_approval(token)?);
    }
    Ok(DecodedMeta {
        warrants,
        signature,
        approvals: decoded_approvals,
    })
}

/// Check the proof in an envelope against `args_json` at `timestamp`.
///
/// Returns `Ok(false)` when the proof does not match. Malformed envelopes
/// are errors.
pub fn verify_meta(
    warrant: &str,
    signature: &str,
    tool: &str,
    args_json: &str,
    timestamp: i64,
) -> std::result::Result<bool, MetaError> {
    let decoded = decode_meta_parts(warrant, signature, &[])?;
    let leaf = decoded.warrants.last().ok_or(MetaError::EmptyChain)?;
    let args = args_from_json(args_json)?;
    match leaf.verify_pop_as_of(
        tool,
        &args,
        Some(&decoded.signature),
        POP_TIMESTAMP_WINDOW_SECS,
        1,
        timestamp,
    ) {
        Ok(()) => Ok(true),
        Err(Error::SignatureInvalid(_)) => Ok(false),
        Err(err) => Err(MetaError::Proof(err)),
    }
}

/// Argument map this module signs. JSON null is [`ConstraintValue::Null`].
pub fn args_from_json(
    text: &str,
) -> std::result::Result<HashMap<String, ConstraintValue>, MetaError> {
    let value = parse_json_strict(text).map_err(|err| match err {
        StrictJsonError::DuplicateKey => {
            MetaError::InvalidArguments("duplicate JSON key".to_string())
        }
        StrictJsonError::Malformed(message) => MetaError::InvalidArguments(message),
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| MetaError::InvalidArguments("arguments must be a JSON object".into()))?;
    if object.len() > MAX_JSON_ITEMS {
        return Err(MetaError::InvalidArguments("too many arguments".into()));
    }
    let mut args = HashMap::with_capacity(object.len());
    for (key, raw) in object {
        if key.len() > MAX_JSON_STRING {
            return Err(MetaError::InvalidArguments(
                "argument name is too long".into(),
            ));
        }
        args.insert(key.clone(), json_to_constraint(raw, 0)?);
    }
    Ok(args)
}

/// Standard base64 of a warrant stack.
pub fn encode_warrant_chain(warrants: &[Warrant]) -> std::result::Result<String, MetaError> {
    if warrants.is_empty() {
        return Err(MetaError::EmptyChain);
    }
    let stack = wire::WarrantStack(warrants.to_vec());
    let bytes = wire::encode_stack(&stack).map_err(|_| MetaError::InvalidEncoding)?;
    Ok(encode_token(&bytes))
}

/// Standard base64 of one approval.
pub fn encode_approval(approval: &SignedApproval) -> std::result::Result<String, MetaError> {
    let mut buf = Vec::new();
    ciborium::into_writer(approval, &mut buf).map_err(|_| MetaError::InvalidEncoding)?;
    if buf.len() > MAX_STACK_SIZE {
        return Err(MetaError::PayloadTooLarge);
    }
    Ok(encode_token(&buf))
}

/// Decode a warrant chain from the canonical alphabet, the older standard
/// alphabet, PEM, or a single warrant.
pub fn decode_warrant_chain(input: &str) -> std::result::Result<Vec<Warrant>, MetaError> {
    if input.len() > WARRANT_STRING_MAX {
        return Err(MetaError::PayloadTooLarge);
    }
    let trimmed = input.trim();
    if trimmed.contains("BEGIN TENUO") {
        let stack = wire::decode_pem_chain(trimmed).map_err(|_| MetaError::InvalidEncoding)?;
        if stack.0.is_empty() {
            return Err(MetaError::EmptyChain);
        }
        return Ok(stack.0);
    }
    let bytes = decode_token(trimmed)?;
    if bytes.len() > MAX_STACK_SIZE {
        return Err(MetaError::PayloadTooLarge);
    }
    if let Ok(stack) = wire::decode_stack(&bytes) {
        if stack.0.is_empty() {
            return Err(MetaError::EmptyChain);
        }
        return Ok(stack.0);
    }
    let warrant = wire::decode(&bytes).map_err(|_| MetaError::InvalidEncoding)?;
    Ok(vec![warrant])
}

pub fn decode_signature(input: &str) -> std::result::Result<Signature, MetaError> {
    if input.len() > SIGNATURE_STRING_MAX {
        return Err(MetaError::PayloadTooLarge);
    }
    let bytes = decode_token(input.trim())?;
    if bytes.len() != 64 {
        return Err(MetaError::InvalidSignature);
    }
    let mut raw = [0u8; 64];
    raw.copy_from_slice(&bytes);
    Signature::from_bytes(&raw).map_err(|_| MetaError::InvalidSignature)
}

pub fn decode_approval(input: &str) -> std::result::Result<SignedApproval, MetaError> {
    if input.len() > APPROVAL_STRING_MAX {
        return Err(MetaError::PayloadTooLarge);
    }
    let bytes = decode_token(input.trim())?;
    if bytes.len() > MAX_STACK_SIZE {
        return Err(MetaError::PayloadTooLarge);
    }
    ciborium::from_reader(bytes.as_slice()).map_err(|_| MetaError::InvalidEncoding)
}

fn number_value(n: &serde_json::Number) -> std::result::Result<ConstraintValue, MetaError> {
    if let Some(i) = n.as_i64() {
        return Ok(ConstraintValue::Integer(i));
    }
    if n.as_u64().is_some() {
        return Err(MetaError::InvalidArguments(
            "integer does not fit in i64".into(),
        ));
    }
    let Some(f) = n.as_f64() else {
        return Err(MetaError::InvalidArguments("unsupported number".into()));
    };
    // `1.0` and `1` are the same proof. Python's default dump and
    // `JSON.stringify` spell an integral value differently.
    // i64::MAX rounds up to 2^63 as f64. An inclusive upper bound would
    // saturate that distinct value to i64::MAX and give both the same proof.
    if f.is_finite() && f.fract() == 0.0 && f >= i64::MIN as f64 && f < -(i64::MIN as f64) {
        return Ok(ConstraintValue::Integer(f as i64));
    }
    if !f.is_finite() {
        return Err(MetaError::InvalidArguments("non-finite number".into()));
    }
    Ok(ConstraintValue::Float(f))
}

fn encode_token(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_token(input: &str) -> std::result::Result<Vec<u8>, MetaError> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact.as_bytes()) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(compact.as_bytes()) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| MetaError::InvalidEncoding)
}

fn json_to_constraint(
    value: &Value,
    depth: usize,
) -> std::result::Result<ConstraintValue, MetaError> {
    if depth > MAX_JSON_DEPTH {
        return Err(MetaError::InvalidArguments(
            "argument nesting is too deep".into(),
        ));
    }
    match value {
        Value::Null => Ok(ConstraintValue::Null),
        Value::Bool(b) => Ok(ConstraintValue::Boolean(*b)),
        Value::Number(n) => number_value(n),
        Value::String(s) => {
            if s.len() > MAX_JSON_STRING {
                return Err(MetaError::InvalidArguments("string is too long".into()));
            }
            Ok(ConstraintValue::String(s.clone()))
        }
        Value::Array(items) => {
            if items.len() > MAX_JSON_ITEMS {
                return Err(MetaError::InvalidArguments("list is too long".into()));
            }
            let converted = items
                .iter()
                .map(|item| json_to_constraint(item, depth + 1))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(ConstraintValue::List(converted))
        }
        Value::Object(map) => {
            if map.len() > MAX_JSON_ITEMS {
                return Err(MetaError::InvalidArguments(
                    "object has too many keys".into(),
                ));
            }
            let mut object = BTreeMap::new();
            for (key, raw) in map {
                if key.len() > MAX_JSON_STRING {
                    return Err(MetaError::InvalidArguments("object key is too long".into()));
                }
                object.insert(key.clone(), json_to_constraint(raw, depth + 1)?);
            }
            Ok(ConstraintValue::Object(object))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use serde_json::Value;
    use std::time::Duration;

    fn sample_warrant() -> (SigningKey, Warrant) {
        let issuer = SigningKey::from_bytes(&[0x11; 32]);
        let holder = SigningKey::from_bytes(&[0x22; 32]);
        let warrant = Warrant::builder()
            .capability("read_file", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(3600))
            .build(&issuer)
            .expect("warrant");
        (holder, warrant)
    }

    #[test]
    fn null_is_part_of_the_signed_map() {
        let args = args_from_json(r#"{"note":null,"path":"/data"}"#).unwrap();
        assert_eq!(args.get("note"), Some(&ConstraintValue::Null));
        assert!(args.contains_key("note"));
    }

    #[test]
    fn integral_float_matches_integer() {
        let one = args_from_json(r#"{"n":1}"#).unwrap();
        let one_point = args_from_json(r#"{"n":1.0}"#).unwrap();
        assert_eq!(one, one_point);
        assert_eq!(one.get("n"), Some(&ConstraintValue::Integer(1)));
        let fraction = args_from_json(r#"{"n":1.5}"#).unwrap();
        assert_eq!(fraction.get("n"), Some(&ConstraintValue::Float(1.5)));
    }

    #[test]
    fn decimal_floats_round_trip_without_collapsing_adjacent_values() {
        let values = [
            0.9384646938271072_f64,
            0.9384646938271073_f64,
            0.5862090086938249_f64,
        ];
        for value in values {
            let text = format!(r#"{{"n":{value}}}"#);
            assert_eq!(
                args_from_json(&text).unwrap()["n"],
                ConstraintValue::Float(value)
            );
        }
        let (holder, warrant) = sample_warrant();
        let signed = sign_meta(
            &[warrant],
            &holder,
            "read_file",
            r#"{"n":0.9384646938271072}"#,
            1_700_000_000,
            &[],
        )
        .unwrap();
        assert!(!verify_meta(
            &signed.warrant,
            &signed.signature,
            "read_file",
            r#"{"n":0.9384646938271073}"#,
            1_700_000_000
        )
        .unwrap());
    }

    #[test]
    fn integral_float_at_i64_upper_bound_does_not_saturate() {
        let max = args_from_json(r#"{"n":9223372036854775807}"#).unwrap();
        let above = args_from_json(r#"{"n":9223372036854775808.0}"#).unwrap();
        assert_eq!(max["n"], ConstraintValue::Integer(i64::MAX));
        assert_eq!(above["n"], ConstraintValue::Float(9223372036854775808.0));
        assert_ne!(max, above);
    }

    #[test]
    fn proof_rejects_null_insertions_at_every_list_depth() {
        let (holder, warrant) = sample_warrant();
        for (original, changed) in [
            (r#"{}"#, r#"{"target":null}"#),
            (r#"{"items":[1,2]}"#, r#"{"items":[null,1,2]}"#),
            (r#"{"items":[[1,2]]}"#, r#"{"items":[[1,null,2]]}"#),
            (r#"{"object":{}}"#, r#"{"object":{"target":null}}"#),
        ] {
            let signed = sign_meta(
                std::slice::from_ref(&warrant),
                &holder,
                "read_file",
                original,
                1_700_000_000,
                &[],
            )
            .unwrap();
            assert!(verify_meta(
                &signed.warrant,
                &signed.signature,
                "read_file",
                original,
                1_700_000_000
            )
            .unwrap());
            assert!(
                !verify_meta(
                    &signed.warrant,
                    &signed.signature,
                    "read_file",
                    changed,
                    1_700_000_000
                )
                .unwrap(),
                "{original} must not authorize {changed}"
            );
        }
    }

    #[test]
    fn older_url_safe_alphabet_still_decodes() {
        let (holder, warrant) = sample_warrant();
        let args_json = r#"{"path":"/data"}"#;
        let meta = sign_meta(
            &[warrant],
            &holder,
            "read_file",
            args_json,
            1_700_000_000,
            &[],
        )
        .unwrap();
        let signature = decode_signature(&meta.signature).unwrap();
        let url_safe =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());
        assert!(verify_meta(
            &meta.warrant,
            &url_safe,
            "read_file",
            args_json,
            1_700_000_000
        )
        .unwrap());
        assert!(!verify_meta(
            &meta.warrant,
            &meta.signature,
            "read_file",
            r#"{"path":"/etc/passwd"}"#,
            1_700_000_000
        )
        .unwrap());
    }

    #[test]
    fn proof_rejects_inserting_or_removing_null() {
        let (holder, warrant) = sample_warrant();
        let with_null = r#"{"note":null,"path":"/data"}"#;
        let stripped = r#"{"path":"/data"}"#;
        let old = sign_meta(
            std::slice::from_ref(&warrant),
            &holder,
            "read_file",
            stripped,
            1_700_000_000,
            &[],
        )
        .unwrap();
        assert!(!verify_meta(
            &old.warrant,
            &old.signature,
            "read_file",
            with_null,
            1_700_000_000
        )
        .unwrap());
        let current = sign_meta(
            &[warrant],
            &holder,
            "read_file",
            with_null,
            1_700_000_000,
            &[],
        )
        .unwrap();
        assert!(!verify_meta(
            &current.warrant,
            &current.signature,
            "read_file",
            stripped,
            1_700_000_000
        )
        .unwrap());
    }

    #[test]
    fn line_wrapped_standard_chain_still_decodes() {
        let (_holder, warrant) = sample_warrant();
        let token = encode_warrant_chain(&[warrant]).unwrap();
        let standard =
            base64::engine::general_purpose::STANDARD.encode(decode_token(&token).unwrap());
        let wrapped: String = standard
            .chars()
            .enumerate()
            .flat_map(|(index, ch)| {
                if index > 0 && index % 64 == 0 {
                    vec!['\n', ch]
                } else {
                    vec![ch]
                }
            })
            .collect();
        let decoded = decode_warrant_chain(&wrapped).unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn shared_vector_round_trips() {
        let vector: Value =
            serde_json::from_str(include_str!("../../tests/vectors/tenuo-meta.json")).unwrap();
        let seed = hex::decode(vector["holder_seed_hex"].as_str().unwrap()).unwrap();
        let mut holder_bytes = [0u8; 32];
        holder_bytes.copy_from_slice(&seed);
        let holder = SigningKey::from_bytes(&holder_bytes);
        let warrant = vector["warrant"].as_str().unwrap();
        let signature = vector["signature"].as_str().unwrap();
        let tool = vector["tool"].as_str().unwrap();
        let args_json = vector["args_json"].as_str().unwrap();
        let rejected = vector["rejected_args_json"].as_str().unwrap();
        let timestamp = vector["timestamp"].as_i64().unwrap();
        let chain = decode_warrant_chain(warrant).unwrap();
        let signed = sign_meta(&chain, &holder, tool, args_json, timestamp, &[]).unwrap();
        assert_eq!(signed.warrant, warrant);
        assert_eq!(signed.signature, signature);
        let float_args = vector["float_args_json"].as_str().unwrap();
        let float_signature = vector["float_signature"].as_str().unwrap();
        let float_signed = sign_meta(&chain, &holder, tool, float_args, timestamp, &[]).unwrap();
        assert_eq!(float_signed.signature, float_signature);
        assert!(verify_meta(warrant, float_signature, tool, float_args, timestamp).unwrap());
        let spelled = float_args.replace("1.5", "1.50");
        assert!(verify_meta(warrant, float_signature, tool, &spelled, timestamp).unwrap());
        assert!(verify_meta(warrant, signature, tool, args_json, timestamp).unwrap());
        assert!(!verify_meta(warrant, signature, tool, rejected, timestamp).unwrap());
        assert_eq!(
            args_from_json(args_json).unwrap().get("note"),
            Some(&ConstraintValue::Null)
        );
    }

    #[test]
    #[ignore]
    fn write_meta_vector() {
        let issuer = SigningKey::from_bytes(&[0x11; 32]);
        let holder = SigningKey::from_bytes(&[0x22; 32]);
        let warrant = Warrant::builder()
            .capability("read_file", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(3600))
            .build(&issuer)
            .unwrap();
        let args_json = r#"{"limit":1,"note":null,"path":"/data/ok"}"#;
        let float_args_json = r#"{"limit":1.5,"note":null,"path":"/data/ok"}"#;
        let meta = sign_meta(
            std::slice::from_ref(&warrant),
            &holder,
            "read_file",
            args_json,
            1_700_000_000,
            &[],
        )
        .unwrap();
        let float_meta = sign_meta(
            std::slice::from_ref(&warrant),
            &holder,
            "read_file",
            float_args_json,
            1_700_000_000,
            &[],
        )
        .unwrap();
        let vector = serde_json::json!({
            "holder_seed_hex": hex::encode([0x22u8; 32]),
            "tool": "read_file",
            "args_json": args_json,
            "float_args_json": float_args_json,
            "rejected_args_json": r#"{"limit":1,"note":null,"path":"/etc/passwd"}"#,
            "timestamp": 1_700_000_000,
            "warrant": meta.warrant,
            "signature": meta.signature,
            "float_signature": float_meta.signature,
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/tenuo-meta.json"
        );
        std::fs::write(path, format!("{vector}\n")).unwrap();
    }
}
