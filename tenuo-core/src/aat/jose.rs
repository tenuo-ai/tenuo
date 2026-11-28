//! JWS Compact Serialization for `alg: Ed25519` and, with the `aat-es256`
//! feature, `alg: ES256`, and the JWKs of the keys that verify them.

use super::json::{self, Json, Obj};
#[cfg(feature = "aat-es256")]
use super::P256PublicKey;
use super::{deny, Algorithm, Denied, VerifyingKey};
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

/// A structurally valid public JWK of a key type this verifier accepts.
///
/// An Ed25519 key has `kty` OKP, `crv` Ed25519 and an `x` that is the
/// canonical base64url of 32 bytes. With the `aat-es256` feature, a P-256 key
/// has `kty` EC, `crv` P-256 and an `x` and `y` that are each the canonical
/// base64url of 32 bytes and together name a point on the curve. Other
/// members are allowed here; steps 3l and 4b2 refuse the private member `d`
/// separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Jwk {
    Ed25519 {
        x: String,
        raw: [u8; 32],
    },
    #[cfg(feature = "aat-es256")]
    P256 {
        x: String,
        y: String,
        key: P256PublicKey,
    },
}

impl Jwk {
    pub(crate) fn from_json(jwk: Option<&Json>) -> Option<Self> {
        let jwk = jwk?.as_obj()?;
        let coordinate = |name: &str| -> Option<(String, [u8; 32])> {
            let text = jwk.get(name)?.as_str()?;
            let raw: [u8; 32] = b64u_decode(text)?.try_into().ok()?;
            Some((text.to_owned(), raw))
        };
        match (jwk.get("kty")?.as_str()?, jwk.get("crv")?.as_str()?) {
            ("OKP", "Ed25519") => {
                let (x, raw) = coordinate("x")?;
                Some(Self::Ed25519 { x, raw })
            }
            #[cfg(feature = "aat-es256")]
            ("EC", "P-256") => {
                let (x, x_raw) = coordinate("x")?;
                let (y, y_raw) = coordinate("y")?;
                let key = P256PublicKey::from_coordinates(&x_raw, &y_raw)?;
                Some(Self::P256 { x, y, key })
            }
            _ => None,
        }
    }

    pub(crate) fn from_key(key: &VerifyingKey) -> Self {
        match key {
            VerifyingKey::Ed25519(key) => {
                let raw = key.to_bytes();
                Self::Ed25519 {
                    x: B64.encode(raw),
                    raw,
                }
            }
            #[cfg(feature = "aat-es256")]
            VerifyingKey::P256(key) => {
                let (x, y) = key.coordinates();
                Self::P256 {
                    x: B64.encode(x),
                    y: B64.encode(y),
                    key: key.clone(),
                }
            }
        }
    }

    /// The key, or `None` for bytes that are not a usable Ed25519 point. A
    /// token bound to such a key is refused where its signature is checked.
    pub(crate) fn key(&self) -> Option<VerifyingKey> {
        match self {
            Self::Ed25519 { raw, .. } => PublicKey::from_bytes(raw).ok().map(VerifyingKey::Ed25519),
            #[cfg(feature = "aat-es256")]
            Self::P256 { key, .. } => Some(VerifyingKey::P256(key.clone())),
        }
    }

    /// The one algorithm consistent with this key's `kty` and `crv`
    /// (Section 9.11).
    pub(crate) fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519 { .. } => Algorithm::Ed25519,
            #[cfg(feature = "aat-es256")]
            Self::P256 { .. } => Algorithm::Es256,
        }
    }

    /// Whether `signature`, a base64url JWS Signature segment, verifies over
    /// `signed` under this key. Both algorithms carry 64 bytes.
    fn verifies(&self, signed: &[u8], signature: &str) -> bool {
        let Some(bytes) = b64u_decode(signature).and_then(|b| <[u8; 64]>::try_from(b).ok()) else {
            return false;
        };
        match self {
            Self::Ed25519 { raw, .. } => PublicKey::from_bytes(raw)
                .ok()
                .zip(Signature::from_bytes(&bytes).ok())
                .is_some_and(|(key, signature)| key.verify_raw(signed, &signature).is_ok()),
            #[cfg(feature = "aat-es256")]
            Self::P256 { key, .. } => key.verify(signed, &bytes),
        }
    }

    /// RFC 7638 thumbprint as an RFC 9278 URI: the `iss` of a derived token.
    pub(crate) fn thumbprint_uri(&self) -> String {
        // The required members in lexicographic order with no whitespace.
        // The coordinates are base64url, so they need no escaping.
        let canonical = match self {
            Self::Ed25519 { x, .. } => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#),
            #[cfg(feature = "aat-es256")]
            Self::P256 { x, y, .. } => {
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
        };
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
/// `permitted` is the enforcement point's algorithm allowlist.
pub(crate) fn verify(
    compact: &str,
    key: Option<&Jwk>,
    typ: &str,
    permitted: &[Algorithm],
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

    // The key's type fixes the one algorithm consistent with it, so the
    // header cannot choose how the key is used. That algorithm must also be
    // on the allowlist, for this token on its own.
    let alg = header.get("alg").and_then(Json::as_str);
    let Some(key) = key.filter(|key| alg == Some(key.algorithm().name())) else {
        return Err(deny(
            header_step,
            "alg is absent or is inconsistent with the verification key",
        ));
    };
    if !permitted.contains(&key.algorithm()) {
        return Err(deny(
            header_step,
            format!(
                "alg {} is not on the permitted algorithm list",
                key.algorithm()
            ),
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
    if !key.verifies(signed.as_bytes(), parts.signature) {
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
            Jwk::from_key(&key.into()).thumbprint_uri(),
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

    const ED25519: &[Algorithm] = &[Algorithm::Ed25519];

    /// A compact JWS with the given `alg` and a signature of 64 zero bytes.
    /// The algorithm is checked before the signature.
    fn token(alg: &str) -> String {
        let header = B64.encode(format!(r#"{{"alg":"{alg}","typ":"aat+jwt"}}"#));
        format!("{header}.{}.{}", B64.encode("{}"), B64.encode([0u8; 64]))
    }

    fn ed25519_key() -> Jwk {
        Jwk::from_key(&SigningKey::from_bytes(&[0x01; 32]).public_key().into())
    }

    #[test]
    fn alg_must_be_the_one_the_key_fixes() {
        let key = ed25519_key();
        for alg in ["ES256", "EdDSA", "none", "HS256", "ed25519", ""] {
            let denied = verify(&token(alg), Some(&key), AAT_TYP, ED25519, "3a", "3b").unwrap_err();
            assert_eq!(denied.step, "3a", "{alg:?}");
        }
        // The right algorithm reaches the signature check, which fails.
        let denied =
            verify(&token("Ed25519"), Some(&key), AAT_TYP, ED25519, "3a", "3b").unwrap_err();
        assert_eq!(denied.step, "3b");
    }

    #[test]
    fn alg_must_be_on_the_allowlist() {
        // The key fits the algorithm, and an empty list permits nothing.
        let denied = verify(
            &token("Ed25519"),
            Some(&ed25519_key()),
            AAT_TYP,
            &[],
            "3a",
            "3b",
        )
        .unwrap_err();
        assert_eq!(denied.step, "3a");
    }

    #[cfg(not(feature = "aat-es256"))]
    #[test]
    fn a_p256_jwk_is_not_a_key_without_the_feature() {
        let text = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        assert!(Jwk::from_json(json::parse_unique(text).as_ref()).is_none());
    }

    /// The example of RFC 7515, Appendix A.3.
    #[cfg(feature = "aat-es256")]
    mod es256 {
        use super::*;

        const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        const SIGNED: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        const SIGNATURE: &str = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        const BOTH: &[Algorithm] = &[Algorithm::Ed25519, Algorithm::Es256];

        fn jwk(x: &str, y: &str) -> Option<Jwk> {
            let text = format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#);
            Jwk::from_json(json::parse_unique(&text).as_ref())
        }

        #[test]
        fn the_rfc_7515_example_verifies() {
            let key = jwk(X, Y).expect("the RFC key");
            assert_eq!(key.algorithm(), Algorithm::Es256);
            // S in this example is above half the group order. A JWS does
            // not require the low form, and nothing here depends on a
            // signature being unique: par_hash and aat_hash cover the JWS
            // Signing Input, and replay is tracked by the PoP jti.
            assert!(key.verifies(SIGNED.as_bytes(), SIGNATURE));
            // One changed character of the signing input, of R and of S.
            assert!(!key.verifies(SIGNED.replace("eyJpc3", "eyJpc4").as_bytes(), SIGNATURE));
            assert!(!key.verifies(SIGNED.as_bytes(), &SIGNATURE.replace("DtEh", "DtEi")));
            assert!(!key.verifies(SIGNED.as_bytes(), &SIGNATURE.replace("NU1Q", "NU1A")));
            // Not 64 bytes, not base64url, and R and S of zero.
            assert!(!key.verifies(SIGNED.as_bytes(), &SIGNATURE[..80]));
            assert!(!key.verifies(SIGNED.as_bytes(), &format!("{SIGNATURE}==")));
            assert!(!key.verifies(SIGNED.as_bytes(), &B64.encode([0u8; 64])));
        }

        #[test]
        fn thumbprint_is_over_crv_kty_x_y() {
            // Computed independently: SHA-256 of
            // {"crv":"P-256","kty":"EC","x":"...","y":"..."}.
            assert_eq!(
                jwk(X, Y).unwrap().thumbprint_uri(),
                "urn:ietf:params:oauth:jwk-thumbprint:sha-256:oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
            );
        }

        #[test]
        fn a_jwk_must_name_a_point_on_the_curve() {
            // The last bit of y flipped: not on the curve.
            assert!(jwk(X, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5aw").is_none());
            // 31 bytes, a padded value, and coordinates of zero.
            assert!(jwk(&X[..42], Y).is_none());
            assert!(jwk(&format!("{X}="), Y).is_none());
            let zero = B64.encode([0u8; 32]);
            assert!(jwk(&zero, &zero).is_none());
            // The key round-trips through the public key type.
            let key = jwk(X, Y).unwrap();
            assert_eq!(Jwk::from_key(&key.key().unwrap()), key);
        }

        #[test]
        fn alg_must_be_es256_for_a_p256_key() {
            let key = jwk(X, Y).unwrap();
            for alg in ["Ed25519", "ES384", "ES256K", "none", "HS256"] {
                let denied =
                    verify(&token(alg), Some(&key), AAT_TYP, BOTH, "4a", "4b").unwrap_err();
                assert_eq!(denied.step, "4a", "{alg:?}");
            }
            let denied =
                verify(&token("ES256"), Some(&key), AAT_TYP, BOTH, "4a", "4b").unwrap_err();
            assert_eq!(denied.step, "4b");
        }

        #[test]
        fn es256_must_be_on_the_allowlist() {
            // The key fits the algorithm, and the list does not name it.
            let key = jwk(X, Y).unwrap();
            for permitted in [&[][..], ED25519] {
                let denied = verify(&token("ES256"), Some(&key), AAT_TYP, permitted, "4a", "4b")
                    .unwrap_err();
                assert_eq!(denied.step, "4a", "{permitted:?}");
            }
            // Each algorithm is permitted on its own: a list that names
            // ES256 says nothing about Ed25519.
            let only_es256 = &[Algorithm::Es256];
            let denied = verify(
                &token("Ed25519"),
                Some(&ed25519_key()),
                AAT_TYP,
                only_es256,
                "4a",
                "4b",
            )
            .unwrap_err();
            assert_eq!(denied.step, "4a");
        }
    }
}
