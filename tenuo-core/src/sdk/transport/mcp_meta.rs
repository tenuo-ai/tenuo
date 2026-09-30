use super::{decode_owned, encode_approval_standard, encode_parts, DecodeLimits, TransportError};
use crate::approval::SignedApproval;
use crate::crypto::Signature;
use crate::sdk::authority::OwnedReceivedAuthorization;
use crate::sdk::AuthorizedCall;
use crate::warrant::Warrant;
use serde_json::{Map, Value};

/// Decoded `params._meta.tenuo` payload. Owns the artifacts.
pub type TenuoMeta = OwnedReceivedAuthorization;

/// Build the `_meta.tenuo` object for a chain, proof, and approvals.
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

/// Build `_meta.tenuo` for a call: the holder signs a proof of possession
/// now, with the default proof window, and attaches `approvals`.
///
/// Use this on the calling side when no local policy check is wanted, for
/// example in a proxy whose verifier is elsewhere. It does not check the call
/// against the warrant; [`crate::sdk::Guard`] and [`encode_meta_from_authorized`]
/// do both.
pub fn sign_meta(
    authority: &crate::sdk::PresentedAuthority,
    call: &crate::sdk::Call<'_>,
    approvals: &[SignedApproval],
) -> Result<Value, TransportError> {
    let signature = authority
        .prove(
            call,
            chrono::Utc::now().timestamp(),
            crate::planes::DEFAULT_POP_WINDOW_SECS,
        )
        .map_err(|_| TransportError::ProofFailed)?;
    encode_meta(authority.chain(), &signature, approvals)
}

/// Build the `_meta.tenuo` object from an authorized call, reusing its existing proof
/// of possession. Never signs again.
pub fn encode_meta_from_authorized(call: &AuthorizedCall<'_>) -> Result<Value, TransportError> {
    encode_meta(call.chain(), call.pop_signature(), call.approvals())
}

/// Decode a `_meta.tenuo` object.
///
/// Size bounds are enforced before any decoding work.
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

/// Remove `tenuo` from a `_meta` object.
///
/// A server MUST call this before forwarding the message to the handler, so tool code
/// never sees authorization material.
pub fn strip_tenuo(meta: &mut Value) {
    if let Some(object) = meta.as_object_mut() {
        object.remove("tenuo");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_meta_verifies_at_a_guard() {
        use crate::sdk::{Call, Guard, LocalSigner, PresentedAuthority, RevocationMode};
        use crate::{ConstraintSet, SigningKey};
        use std::sync::Arc;
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read", ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(std::time::Duration::from_secs(60))
            .build(&issuer)
            .unwrap();
        let authority =
            PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
        let arguments = serde_json::json!({"path": "/a"});
        let call = Call::try_from_json("read", &arguments).unwrap();
        let meta = sign_meta(&authority, &call, &[]).unwrap();

        let mut authorizer = crate::Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: std::time::Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let received = decode_meta(&meta).unwrap();
        assert!(guard
            .check_received(&received.as_received().unwrap(), &call)
            .is_ok());

        let other = serde_json::json!({"path": "/b"});
        let other = Call::try_from_json("read", &other).unwrap();
        assert!(guard
            .check_received(&received.as_received().unwrap(), &other)
            .is_err());
    }
}
