//! JWS Compact Serialization for `alg: Ed25519`, and Ed25519 JWKs.

use super::json::{self, Json, Obj};
use super::{deny, Denied};
use crate::crypto::{PublicKey, Signature};
use base64::Engine;
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(crate) const AAT_TYP: &str = "aat+jwt";
pub(crate) const POP_TYP: &str = "aat-pop+jwt";

/// base64url without padding (RFC 7515 Section 2). Padding, characters outside
/// the alphabet and non-zero trailing bits are refused.
pub(crate) fn b64u_decode(text: &str) -> Option<Vec<u8>> {
    B64.decode(text).ok()
}

/// A base64url segment holding UTF-8 text.
pub(crate) fn b64u_text(segment: &str) -> Option<String> {
    String::from_utf8(b64u_decode(segment)?).ok()
}

/// `base64url(SHA-256(text))`: `par_hash`, `aat_hash` and JWK thumbprints.
pub(crate) fn sha256_b64u(text: &str) -> String {
    B64.encode(Sha256::digest(text.as_bytes()))
}

/// The three segments of a compact JWS.
pub(crate) struct Compact<'a> {
    pub(crate) header: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

impl<'a> Compact<'a> {
    pub(crate) fn split(compact: &'a str) -> Option<Self> {
        let mut parts = compact.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        parts.next().is_none().then_some(Self {
            header,
            payload,
            signature,
        })
    }
}

/// The JWS Signing Input of a compact JWS: everything before the last dot.
/// `par_hash` and `aat_hash` are digests of it (Section 4.6).
pub(crate) fn signing_input(compact: &str) -> &str {
    compact.rsplit_once('.').map_or(compact, |(input, _)| input)
}

/// A structurally valid public Ed25519 JWK: `kty` OKP, `crv` Ed25519 and an
/// `x` that is the canonical base64url of 32 bytes. Other members are allowed
/// here; steps 3l and 4b2 refuse the private member `d` separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Jwk {
    x: String,
    raw: [u8; 32],
}

impl Jwk {
    pub(crate) fn from_json(jwk: Option<&Json>) -> Option<Self> {
        let jwk = jwk?.as_obj()?;
        if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
            return None;
        }
        let x = jwk.get("x")?.as_str()?;
        let raw: [u8; 32] = b64u_decode(x)?.try_into().ok()?;
        Some(Self {
            x: x.to_owned(),
            raw,
        })
    }

    pub(crate) fn from_key(key: &PublicKey) -> Self {
        let raw = key.to_bytes();
        Self {
            x: B64.encode(raw),
            raw,
        }
    }

    /// The key, or `None` for bytes that are not a usable Ed25519 point. A
    /// token bound to such a key is refused where its signature is checked.
    pub(crate) fn key(&self) -> Option<PublicKey> {
        PublicKey::from_bytes(&self.raw).ok()
    }

    /// RFC 7638 thumbprint as an RFC 9278 URI: the `iss` of a derived token.
    pub(crate) fn thumbprint_uri(&self) -> String {
        // The required members in lexicographic order with no whitespace. `x`
        // is base64url, so it needs no escaping.
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, self.x);
        format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
            sha256_b64u(&canonical)
        )
    }
}

/// `cnf.jwk` of a set of claims.
pub(crate) fn cnf_jwk(claims: &Obj) -> Option<&Json> {
    claims.get("cnf")?.as_obj()?.get("jwk")
}

/// Header checks (steps 3a, 4a, 7a), then the signature and claim parsing
/// (3b, 4b, 7b). `key` is a trust anchor's key or the `cnf.jwk` of the token
/// that authorizes the signer; a key named by the header is never used.
pub(crate) fn verify(
    compact: &str,
    key: Option<&Jwk>,
    typ: &str,
    header_step: &'static str,
    signature_step: &'static str,
) -> Result<Obj, Denied> {
    let parts = Compact::split(compact)
        .ok_or_else(|| deny(header_step, "not a JWS Compact Serialization"))?;
    let header = b64u_text(parts.header)
        .and_then(|text| json::parse_unique(&text))
        .ok_or_else(|| deny(header_step, "protected header is not JSON"))?;
    let header = header
        .as_obj()
        .ok_or_else(|| deny(header_step, "protected header is not a JSON object"))?;

    // Every key this verifier accepts is an OKP Ed25519 key, so `Ed25519` is
    // the one algorithm consistent with it.
    let alg = header.get("alg").and_then(Json::as_str);
    if alg != Some("Ed25519") || key.is_none() {
        return Err(deny(
            header_step,
            "alg is not permitted or is inconsistent with the verification key",
        ));
    }
    if header.get("typ").and_then(Json::as_str) != Some(typ) {
        return Err(deny(header_step, format!("typ is not {typ:?}")));
    }
    // No extension header parameter is understood, so a valid `crit` names an
    // unsupported one, and an empty or malformed `crit` is itself invalid
    // (RFC 7515 Section 4.1.11).
    if header.contains("crit") {
        return Err(deny(
            header_step,
            "crit is invalid or lists a parameter this verifier does not understand",
        ));
    }

    let signed = signing_input(compact);
    let verified = key
        .and_then(Jwk::key)
        .zip(decode_signature(parts.signature))
        .is_some_and(|(key, signature)| key.verify_raw(signed.as_bytes(), &signature).is_ok());
    if !verified {
        return Err(deny(signature_step, "signature does not verify"));
    }

    let parsed = b64u_text(parts.payload)
        .and_then(|text| json::parse(&text))
        .ok_or_else(|| deny(signature_step, "payload is not JSON"))?;
    if parsed.duplicate {
        return Err(deny(signature_step, "duplicate JSON member name"));
    }
    match parsed.value {
        Json::Obj(claims) => Ok(claims),
        _ => Err(deny(signature_step, "payload is not a JSON object")),
    }
}

fn decode_signature(segment: &str) -> Option<Signature> {
    let bytes: [u8; 64] = b64u_decode(segment)?.try_into().ok()?;
    Signature::from_bytes(&bytes).ok()
}

/// Step 2c: the `jti` of a payload whose signature has not been checked. The
/// claims are scanned for that one member and not parsed.
pub(crate) fn unverified_jti(compact: &str) -> Option<String> {
    let payload = compact.split('.').nth(1)?;
    json::top_level_string(&b64u_text(payload)?, "jti")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    #[test]
    fn thumbprint_matches_the_vector_suite_key_table() {
        // Control Plane key of tests/vectors/aat-jws-vectors.json.
        let key = SigningKey::from_bytes(&[0x01; 32]).public_key();
        assert_eq!(
            Jwk::from_key(&key).thumbprint_uri(),
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4"
        );
    }

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64u_decode("AQ"), Some(vec![1]));
        for text in ["AQ==", "AR", "A+", "A Q", "A"] {
            assert_eq!(b64u_decode(text), None, "{text:?}");
        }
    }

    #[test]
    fn jwk_needs_the_canonical_form_of_32_bytes() {
        let jwk = |x: &str| {
            let text = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#);
            Jwk::from_json(json::parse_unique(&text).as_ref())
        };
        assert!(jwk("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w").is_some());
        // 31 bytes, 33 bytes, non-zero trailing bits.
        assert!(jwk("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPbw").is_none());
        assert!(jwk("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1wA").is_none());
        assert!(jwk("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1x").is_none());
    }

    #[test]
    fn signing_input_is_everything_before_the_last_dot() {
        assert_eq!(signing_input("h.p.s"), "h.p");
    }
}
