use super::TransportError;
use crate::approval::SignedApproval;
use crate::crypto::Signature;
use crate::sdk::authority::OwnedReceivedAuthorization;
use crate::sdk::AuthorizedCall;
use crate::warrant::Warrant;
use serde_json::Value;

/// Decoded `params._meta.tenuo` payload. Owns the artifacts.
pub type TenuoMeta = OwnedReceivedAuthorization;

/// Build the `_meta.tenuo` object for a chain, proof, and approvals.
pub fn encode_meta(
    chain: &[Warrant],
    signature: &Signature,
    approvals: &[SignedApproval],
) -> Result<Value, TransportError> {
    crate::meta_envelope::encode_meta(chain, &signature.to_bytes(), approvals)
        .map(|meta| meta.to_json())
        .map_err(meta_error)
}

fn meta_error(err: crate::meta_envelope::MetaError) -> TransportError {
    match err {
        crate::meta_envelope::MetaError::MissingField(name) => TransportError::MissingField(name),
        crate::meta_envelope::MetaError::TooManyApprovals => TransportError::TooManyApprovals,
        crate::meta_envelope::MetaError::InvalidSignature => TransportError::InvalidSignature,
        crate::meta_envelope::MetaError::PayloadTooLarge => TransportError::PayloadTooLarge,
        _ => TransportError::InvalidEncoding,
    }
}

/// Build `_meta.tenuo` for a call: the holder signs a proof of possession
/// at `timestamp` with `window_secs`, and attaches `approvals`.
///
/// `window_secs` must be the enforcement point's proof window. A proof
/// signed with a different window does not verify there. Use this on the
/// calling side when no local policy check is wanted, for example in a
/// proxy whose verifier is elsewhere. It does not check the call against
/// the warrant; [`crate::sdk::Guard`] and [`encode_meta_from_authorized`]
/// do both.
pub fn sign_meta(
    authority: &crate::sdk::PresentedAuthority,
    call: &crate::sdk::Call<'_>,
    approvals: &[SignedApproval],
    timestamp: i64,
    window_secs: i64,
) -> Result<Value, TransportError> {
    let signature = authority
        .prove(call, timestamp, window_secs)
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
    let decoded = crate::meta_envelope::decode_meta(meta).map_err(meta_error)?;
    OwnedReceivedAuthorization::new(decoded.warrants, decoded.signature, decoded.approvals)
        .map_err(Into::into)
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
    fn decoder_matches_core_conformance() {
        let suite: Value = serde_json::from_str(include_str!(
            "../../../../tests/vectors/tenuo-meta-conformance.json"
        ))
        .unwrap();
        let mut valid = suite["delegated"].clone();
        for approvals in [
            Value::Null,
            serde_json::json!([]),
            valid["approvals"].clone(),
        ] {
            valid["approvals"] = approvals;
            assert!(decode_meta(&valid).is_ok());
            assert!(crate::meta_envelope::decode_meta(&valid).is_ok());
        }
        for case in suite["invalid_envelopes"].as_array().unwrap() {
            let mut invalid = suite["delegated"].clone();
            for (key, value) in case.as_object().unwrap() {
                if key != "error" {
                    invalid[key] = value.clone();
                }
            }
            assert!(decode_meta(&invalid).is_err());
            assert!(crate::meta_envelope::decode_meta(&invalid).is_err());
        }
        valid.as_object_mut().unwrap().remove("signature");
        assert_eq!(
            decode_meta(&valid).err(),
            Some(TransportError::MissingField("signature"))
        );
    }

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
        let meta = sign_meta(
            &authority,
            &call,
            &[],
            chrono::Utc::now().timestamp(),
            crate::planes::DEFAULT_POP_WINDOW_SECS,
        )
        .unwrap();

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
