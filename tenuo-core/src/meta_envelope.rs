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
//! The canonical alphabet is unpadded URL-safe base64. [`decode_meta`] still
//! accepts the older standard-base64 envelopes so a message already issued
//! can be checked. That fallback is not a second representation, and the
//! shared vector file does not use it.

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
    /// Unpadded URL-safe base64 of the CBOR warrant stack.
    pub warrant: String,
    /// Unpadded URL-safe base64 of the 64-byte proof.
    pub signature: String,
    /// Unpadded URL-safe base64 of each approval. Empty omits the field.
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

/// Read `_meta.tenuo`. Accepts the canonical alphabet and the older standard
/// alphabet. A PEM chain in `warrant` is accepted as well.
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

/// Unpadded URL-safe base64 of a warrant stack.
pub fn encode_warrant_chain(warrants: &[Warrant]) -> std::result::Result<String, MetaError> {
    if warrants.is_empty() {
        return Err(MetaError::EmptyChain);
    }
    let stack = wire::WarrantStack(warrants.to_vec());
    let bytes = wire::encode_stack(&stack).map_err(|_| MetaError::InvalidEncoding)?;
    Ok(encode_token(&bytes))
}

/// Unpadded URL-safe base64 of one approval.
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

fn encode_token(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_token(input: &str) -> std::result::Result<Vec<u8>, MetaError> {
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(input) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(input)
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
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(ConstraintValue::Integer(i))
            } else if n.as_u64().is_some() {
                Err(MetaError::InvalidArguments(
                    "integer does not fit in i64".into(),
                ))
            } else if let Some(f) = n.as_f64() {
                Ok(ConstraintValue::Float(f))
            } else {
                Err(MetaError::InvalidArguments("unsupported number".into()))
            }
        }
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
    fn older_standard_alphabet_still_decodes() {
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
        let standard = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        assert!(verify_meta(
            &meta.warrant,
            &standard,
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
        let meta = sign_meta(
            std::slice::from_ref(&warrant),
            &holder,
            "read_file",
            args_json,
            1_700_000_000,
            &[],
        )
        .unwrap();
        let vector = serde_json::json!({
            "holder_seed_hex": hex::encode([0x22u8; 32]),
            "tool": "read_file",
            "args_json": args_json,
            "rejected_args_json": r#"{"limit":1,"note":null,"path":"/etc/passwd"}"#,
            "timestamp": 1_700_000_000,
            "warrant": meta.warrant,
            "signature": meta.signature,
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/tenuo-meta.json"
        );
        std::fs::write(path, format!("{vector}\n")).unwrap();
    }
}
