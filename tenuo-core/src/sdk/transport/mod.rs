//! Transport bindings. Encode consumes an `AuthorizedCall` and does not sign.

use crate::approval::SignedApproval;
use crate::crypto::Signature;
use crate::sdk::authority::{AuthorityError, OwnedReceivedAuthorization};
use crate::sdk::AuthorizedCall;
use crate::warrant::Warrant;
use crate::wire::{decode, decode_stack, encode_stack, WarrantStack, MAX_STACK_SIZE};
use base64::Engine;
use std::fmt;

#[cfg(feature = "http-transport")]
/// Header binding for HTTP-like transports.
pub mod http;
#[cfg(feature = "mcp-transport")]
/// `params._meta.tenuo` binding for MCP.
pub mod mcp_meta;

/// Maximum approvals accepted on one message.
pub const MAX_APPROVALS: usize = 64;
/// Maximum decoded size of the approvals block.
pub const MAX_APPROVALS_DECODED_BYTES: usize = 65_536;
/// Maximum encoded warrant-chain string on an MCP message.
pub const MCP_WARRANT_STRING_MAX: usize = 64 * 1024;
/// Maximum encoded proof-of-possession string on an MCP message.
pub const MCP_SIGNATURE_STRING_MAX: usize = 4 * 1024;
/// Maximum encoded string for one approval on an MCP message.
pub const MCP_APPROVAL_STRING_MAX: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Why a message could not be encoded or decoded. Checked before any decoding work.
pub enum TransportError {
    /// A required field was absent.
    MissingField(&'static str),
    /// A field exceeded its size bound.
    PayloadTooLarge,
    /// A field was not valid base64, CBOR, or the expected JSON shape.
    InvalidEncoding,
    /// The proof of possession was not a well-formed signature.
    InvalidSignature,
    /// More approvals than [`MAX_APPROVALS`].
    TooManyApprovals,
    /// The decoded artifacts did not form a usable authorization.
    Authority(AuthorityError),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(name) => write!(f, "missing transport field: {name}"),
            Self::PayloadTooLarge => write!(f, "transport payload exceeds size limit"),
            Self::InvalidEncoding => write!(f, "transport payload is not valid encoding"),
            Self::InvalidSignature => write!(f, "transport signature is not 64 bytes"),
            Self::TooManyApprovals => write!(f, "too many approvals"),
            Self::Authority(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<AuthorityError> for TransportError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

pub(crate) fn encode_authorized(
    call: &AuthorizedCall<'_>,
) -> Result<(String, String, Option<String>), TransportError> {
    encode_parts(call.chain(), call.pop_signature(), call.approvals())
}

pub(crate) fn encode_parts(
    chain: &[Warrant],
    signature: &Signature,
    approvals: &[SignedApproval],
) -> Result<(String, String, Option<String>), TransportError> {
    let stack = WarrantStack::new(chain.to_vec());
    let stack_bytes = encode_stack(&stack).map_err(|_| TransportError::InvalidEncoding)?;
    let warrant = url_no_pad().encode(stack_bytes);
    let pop = url_no_pad().encode(signature.to_bytes());
    if approvals.is_empty() {
        return Ok((warrant, pop, None));
    }
    if approvals.len() > MAX_APPROVALS {
        return Err(TransportError::TooManyApprovals);
    }
    let approval_bytes =
        crate::wire::to_vec(&approvals).map_err(|_| TransportError::InvalidEncoding)?;
    Ok((warrant, pop, Some(url_no_pad().encode(approval_bytes))))
}

pub(crate) fn encode_approval_standard(
    approval: &SignedApproval,
) -> Result<String, TransportError> {
    approval
        .to_cbor_b64()
        .map_err(|_| TransportError::InvalidEncoding)
}

pub(crate) fn decode_owned(
    warrant: &str,
    signature: &str,
    approvals: Option<&str>,
    limits: DecodeLimits,
) -> Result<OwnedReceivedAuthorization, TransportError> {
    if warrant.len() > limits.warrant_string_max {
        return Err(TransportError::PayloadTooLarge);
    }
    if signature.len() > limits.signature_string_max {
        return Err(TransportError::PayloadTooLarge);
    }
    if let Some(raw) = approvals {
        if raw.len() > limits.approvals_string_max {
            return Err(TransportError::PayloadTooLarge);
        }
    }

    let stack_bytes = decode_b64_flexible(warrant)?;
    if stack_bytes.len() > limits.stack_decoded_max {
        return Err(TransportError::PayloadTooLarge);
    }
    let chain = decode_chain(&stack_bytes)?;

    let pop_bytes = decode_b64_flexible(signature)?;
    if pop_bytes.len() != 64 {
        return Err(TransportError::InvalidSignature);
    }
    let mut pop = [0u8; 64];
    pop.copy_from_slice(&pop_bytes);
    let signature = Signature::from_bytes(&pop).map_err(|_| TransportError::InvalidSignature)?;

    let approvals = match approvals {
        None => Vec::new(),
        Some(raw) => decode_approvals(raw, limits.approval_string_max)?,
    };

    OwnedReceivedAuthorization::new(chain, signature, approvals).map_err(Into::into)
}

#[derive(Clone, Copy)]
pub(crate) struct DecodeLimits {
    warrant_string_max: usize,
    signature_string_max: usize,
    approvals_string_max: usize,
    approval_string_max: usize,
    stack_decoded_max: usize,
}

impl DecodeLimits {
    pub(crate) fn http() -> Self {
        Self {
            warrant_string_max: (MAX_STACK_SIZE * 4) / 3 + 8,
            signature_string_max: 128,
            approvals_string_max: (MAX_APPROVALS_DECODED_BYTES * 4) / 3 + 8,
            approval_string_max: usize::MAX,
            stack_decoded_max: MAX_STACK_SIZE,
        }
    }

    pub(crate) fn mcp() -> Self {
        Self {
            warrant_string_max: MCP_WARRANT_STRING_MAX,
            signature_string_max: MCP_SIGNATURE_STRING_MAX,
            approvals_string_max: MCP_APPROVAL_STRING_MAX * MAX_APPROVALS,
            approval_string_max: MCP_APPROVAL_STRING_MAX,
            stack_decoded_max: MAX_STACK_SIZE,
        }
    }
}

fn decode_chain(bytes: &[u8]) -> Result<Vec<Warrant>, TransportError> {
    if let Ok(stack) = decode_stack(bytes) {
        return Ok(stack.0);
    }
    let warrant = decode(bytes).map_err(|_| TransportError::InvalidEncoding)?;
    Ok(vec![warrant])
}

fn decode_approvals(raw: &str, per_item_max: usize) -> Result<Vec<SignedApproval>, TransportError> {
    if raw.starts_with('[') {
        return decode_mcp_approval_list(raw, per_item_max);
    }
    let bytes = decode_b64_flexible(raw)?;
    if bytes.len() > MAX_APPROVALS_DECODED_BYTES {
        return Err(TransportError::PayloadTooLarge);
    }
    if let Ok(list) = ciborium::from_reader::<Vec<SignedApproval>, _>(bytes.as_slice()) {
        if list.len() > MAX_APPROVALS {
            return Err(TransportError::TooManyApprovals);
        }
        return Ok(list);
    }
    let one: SignedApproval =
        ciborium::from_reader(bytes.as_slice()).map_err(|_| TransportError::InvalidEncoding)?;
    Ok(vec![one])
}

fn decode_mcp_approval_list(
    raw: &str,
    per_item_max: usize,
) -> Result<Vec<SignedApproval>, TransportError> {
    let values: Vec<String> =
        serde_json::from_str(raw).map_err(|_| TransportError::InvalidEncoding)?;
    if values.len() > MAX_APPROVALS {
        return Err(TransportError::TooManyApprovals);
    }
    let mut out = Vec::with_capacity(values.len());
    for item in values {
        if item.len() > per_item_max {
            return Err(TransportError::PayloadTooLarge);
        }
        let bytes = decode_b64_flexible(&item)?;
        let approval: SignedApproval =
            ciborium::from_reader(bytes.as_slice()).map_err(|_| TransportError::InvalidEncoding)?;
        out.push(approval);
    }
    Ok(out)
}

pub(crate) fn decode_b64_flexible(input: &str) -> Result<Vec<u8>, TransportError> {
    let clean = input.trim();
    if let Ok(bytes) = url_no_pad().decode(clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(clean) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(clean)
        .map_err(|_| TransportError::InvalidEncoding)
}

fn url_no_pad() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::URL_SAFE_NO_PAD
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::ConstraintSet;
    use crate::crypto::SigningKey;
    use crate::planes::Authorizer;
    use crate::sdk::signer::LocalSigner;
    use crate::sdk::{Call, Guard, PresentedAuthority, RevocationMode, VerifiedProjection};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn setup() -> (
        Guard,
        PresentedAuthority,
        HashMap<String, crate::constraints::ConstraintValue>,
    ) {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let mut authorizer = Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let authority =
            PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
        (guard, authority, HashMap::new())
    }

    #[cfg(feature = "http-transport")]
    #[test]
    fn http_roundtrip_reuses_decision_pop() {
        let (guard, authority, args) = setup();
        let call = Call::borrowed("read", &args);
        let _ = guard
            .guard(&authority, &call, |authorized| {
                let headers = http::headers_from_authorized(authorized).unwrap();
                assert!(!headers.warrant.contains('='));
                assert!(!headers.pop.contains('='));
                let owned = http::extract_headers(&headers).unwrap();
                let received = owned.as_received().unwrap();
                assert_eq!(received.signature(), authorized.pop_signature());
                let projection = VerifiedProjection::identical(HashMap::new());
                let inbound = Call::from_transport("read", &projection);
                let _ = guard
                    .guard_received(&received, &inbound, |_| Ok::<_, &str>(()))
                    .map_err(|_| "received")?;
                Ok::<_, &str>(())
            })
            .unwrap();
    }

    #[cfg(feature = "mcp-transport")]
    #[test]
    fn mcp_encode_uses_locked_alphabets() {
        let (guard, authority, args) = setup();
        let call = Call::borrowed("read", &args);
        let _ = guard
            .guard(&authority, &call, |authorized| {
                let meta = mcp_meta::encode_meta_from_authorized(authorized).unwrap();
                let warrant = meta.get("warrant").and_then(|v| v.as_str()).unwrap();
                let signature = meta.get("signature").and_then(|v| v.as_str()).unwrap();
                assert!(!warrant.contains('='));
                assert!(!signature.contains('+') && !signature.contains('/'));
                let decoded = mcp_meta::decode_meta(&meta).unwrap();
                let received = decoded.as_received().unwrap();
                assert_eq!(received.signature(), authorized.pop_signature());
                Ok::<_, &str>(())
            })
            .unwrap();
    }

    #[cfg(feature = "mcp-transport")]
    #[test]
    fn mcp_decode_accepts_standard_padded_warrant() {
        let (guard, authority, args) = setup();
        let call = Call::borrowed("read", &args);
        let _ = guard
            .guard(&authority, &call, |authorized| {
                let locked = mcp_meta::encode_meta_from_authorized(authorized).unwrap();
                let warrant = locked.get("warrant").and_then(|v| v.as_str()).unwrap();
                let bytes = decode_b64_flexible(warrant).unwrap();
                let padded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                let mut transitional = locked.clone();
                transitional
                    .as_object_mut()
                    .unwrap()
                    .insert("warrant".into(), serde_json::Value::String(padded));
                mcp_meta::decode_meta(&transitional).unwrap();
                Ok::<_, &str>(())
            })
            .unwrap();
    }

    #[cfg(feature = "mcp-transport")]
    #[test]
    fn mcp_rejects_oversized_warrant_string_before_decode() {
        let huge = "A".repeat(MCP_WARRANT_STRING_MAX + 1);
        let meta = serde_json::json!({
            "warrant": huge,
            "signature": "AA",
        });
        assert_eq!(
            mcp_meta::decode_meta(&meta).err(),
            Some(TransportError::PayloadTooLarge)
        );
    }

    #[cfg(feature = "mcp-transport")]
    #[test]
    fn strip_tenuo_removes_extension() {
        let mut meta = serde_json::json!({"tenuo": {"warrant": "x"}, "other": 1});
        mcp_meta::strip_tenuo(&mut meta);
        assert!(meta.get("tenuo").is_none());
        assert_eq!(meta.get("other"), Some(&serde_json::Value::from(1)));
    }
}
