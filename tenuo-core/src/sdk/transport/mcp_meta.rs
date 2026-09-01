use super::{decode_owned, encode_approval_standard, encode_parts, DecodeLimits, TransportError};
use crate::approval::SignedApproval;
use crate::crypto::Signature;
use crate::sdk::authority::OwnedReceivedAuthorization;
use crate::sdk::AuthorizedCall;
use crate::warrant::Warrant;
use serde_json::{Map, Value};

/// Decoded `params._meta.tenuo` payload. Owns the artifacts.
pub type TenuoMeta = OwnedReceivedAuthorization;

pub fn encode_meta(
    chain: &[Warrant],
    signature: &Signature,
    approvals: &[SignedApproval],
) -> Result<Value, TransportError> {
    let (warrant, pop, _) = encode_parts(chain, signature, approvals)?;
    let mut object = Map::new();
    object.insert("warrant".into(), Value::String(warrant));
    object.insert("signature".into(), Value::String(pop));
    if !approvals.is_empty() {
        let encoded = approvals
            .iter()
            .map(encode_approval_standard)
            .collect::<Result<Vec<_>, _>>()?;
        object.insert(
            "approvals".into(),
            Value::Array(encoded.into_iter().map(Value::String).collect()),
        );
    }
    Ok(Value::Object(object))
}

pub fn encode_meta_from_authorized(call: &AuthorizedCall<'_>) -> Result<Value, TransportError> {
    encode_meta(call.chain(), call.pop_signature(), call.approvals())
}

pub fn decode_meta(meta: &Value) -> Result<TenuoMeta, TransportError> {
    let object = meta.as_object().ok_or(TransportError::InvalidEncoding)?;
    let warrant = object
        .get("warrant")
        .and_then(Value::as_str)
        .ok_or(TransportError::MissingField("warrant"))?;
    let signature = object
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(TransportError::MissingField("signature"))?;
    let approvals = match object.get("approvals") {
        None => None,
        Some(Value::Array(items)) => {
            if items.len() > super::MAX_APPROVALS {
                return Err(TransportError::TooManyApprovals);
            }
            for item in items {
                let s = item.as_str().ok_or(TransportError::InvalidEncoding)?;
                if s.len() > super::MCP_APPROVAL_STRING_MAX {
                    return Err(TransportError::PayloadTooLarge);
                }
            }
            Some(serde_json::to_string(items).map_err(|_| TransportError::InvalidEncoding)?)
        }
        Some(_) => return Err(TransportError::InvalidEncoding),
    };
    decode_owned(
        warrant,
        signature,
        approvals.as_deref(),
        DecodeLimits::mcp(),
    )
}

pub fn strip_tenuo(meta: &mut Value) {
    if let Some(object) = meta.as_object_mut() {
        object.remove("tenuo");
    }
}
