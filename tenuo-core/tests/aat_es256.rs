//! ES256 in `tenuo::aat::verify_chain`: chains that use P-256 keys, alone
//! and beside Ed25519 keys, the algorithm allowlist, and the step each
//! failure is reported at.
//!
//! The draft's vector suite uses Ed25519 only, so these chains are minted
//! here. The suite itself runs unchanged in `aat_jws_vectors.rs`.

use base64::Engine;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tenuo::aat::{
    verify_chain, Algorithm, Denied, P256PublicKey, TrustAnchor, Verified, VerifyOptions,
    VerifyingKey,
};
use tenuo::SigningKey;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const ISSUER: &str = "https://auth.example.com";
const AUDIENCE: &str = "https://tools.example.com";
const TOOL: &str = "read_file";
const NOW: i64 = 1_704_067_500;
const AAT: &str = "aat+jwt";
const POP: &str = "aat-pop+jwt";
const ED25519: &[Algorithm] = &[Algorithm::Ed25519];
const ES256: &[Algorithm] = &[Algorithm::Es256];
const BOTH: &[Algorithm] = &[Algorithm::Ed25519, Algorithm::Es256];

/// The order of the P-256 group and the prime of its field, big-endian
/// (SP 800-186, Section 3.2.1.3).
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// The sum of two 32-byte big-endian numbers, which must fit in 32 bytes.
fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "the sum fits in 32 bytes");
    out
}

/// A point on the curve whose x coordinate is a small number.
fn point_with_small_x() -> ([u8; 32], [u8; 32]) {
    (1u8..=255)
        .find_map(|x| {
            // SEC 1 compressed form: 0x02 || X names the point with an even y.
            let mut compressed = [0u8; 33];
            compressed[0] = 0x02;
            compressed[32] = x;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed).ok()?;
            Some(coordinates_of(&key))
        })
        .expect("some small x is on the curve")
}

fn coordinates_of(key: &p256::ecdsa::VerifyingKey) -> ([u8; 32], [u8; 32]) {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    assert_eq!((bytes.len(), bytes[0]), (65, 0x04));
    (
        bytes[1..33].try_into().unwrap(),
        bytes[33..].try_into().unwrap(),
    )
}

/// The public keys an ECDSA signature over `input` verifies under. There
/// are two: the signer's, and one that follows from the signature.
fn keys_that_verify(input: &str, signature: &[u8]) -> Vec<P256PublicKey> {
    let signature = p256::ecdsa::Signature::from_slice(signature).expect("R and S in range");
    (0u8..2)
        .filter_map(|id| {
            let id = p256::ecdsa::RecoveryId::from_byte(id)?;
            p256::ecdsa::VerifyingKey::recover_from_msg(input.as_bytes(), &signature, id).ok()
        })
        .map(|key| {
            let (x, y) = coordinates_of(&key);
            P256PublicKey::from_coordinates(&x, &y).expect("a point on the curve")
        })
        .collect()
}

fn b64u(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes)
}

fn sha256_b64u(text: &str) -> String {
    b64u(Sha256::digest(text.as_bytes()))
}

/// `par_hash` and `aat_hash`: the digest of a token's JWS Signing Input.
fn token_hash(compact: &str) -> String {
    sha256_b64u(compact.rsplit_once('.').expect("compact JWS").0)
}

fn claims_of(compact: &str) -> Value {
    let payload = compact.split('.').nth(1).expect("payload");
    serde_json::from_slice(&B64.decode(payload).expect("base64url")).expect("JSON")
}

/// A signing key of either type, from a fixed seed.
enum Key {
    Ed25519(SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl Key {
    fn ed25519(seed: u8) -> Self {
        Self::Ed25519(SigningKey::from_bytes(&[seed; 32]))
    }

    fn p256(seed: u8) -> Self {
        Self::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("a scalar in range"))
    }

    /// The `alg` value this key's type fixes.
    fn alg(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => "Ed25519",
            Self::P256(_) => "ES256",
        }
    }

    fn coordinates(key: &p256::ecdsa::SigningKey) -> ([u8; 32], [u8; 32]) {
        coordinates_of(key.verifying_key())
    }

    fn public(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(key) => key.public_key().into(),
            Self::P256(key) => {
                let (x, y) = Self::coordinates(key);
                P256PublicKey::from_coordinates(&x, &y)
                    .expect("a point on the curve")
                    .into()
            }
        }
    }

    fn jwk(&self) -> Value {
        match self {
            Self::Ed25519(key) => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": b64u(key.public_key().to_bytes())})
            }
            Self::P256(key) => {
                let (x, y) = Self::coordinates(key);
                json!({"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)})
            }
        }
    }

    /// The RFC 7638 thumbprint as an RFC 9278 URI, computed here from the
    /// required members in lexicographic order.
    fn thumbprint(&self) -> String {
        let jwk = self.jwk();
        let member = |name: &str| jwk[name].as_str().unwrap().to_owned();
        let canonical = match self {
            Self::Ed25519(_) => {
                format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, member("x"))
            }
            Self::P256(_) => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                member("x"),
                member("y")
            ),
        };
        format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
            sha256_b64u(&canonical)
        )
    }

    fn signature(&self, input: &str) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign_raw(input.as_bytes()).to_bytes().to_vec(),
            Self::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.to_bytes().to_vec()
            }
        }
    }

    /// Sign `claims` under a header that names `alg`, whatever this key is.
    fn sign_as(&self, alg: &str, typ: &str, claims: &Value) -> String {
        let header = json!({"alg": alg, "typ": typ});
        let input = format!("{}.{}", b64u(header.to_string()), b64u(claims.to_string()));
        let signature = self.signature(&input);
        format!("{input}.{}", b64u(signature))
    }

    fn sign(&self, typ: &str, claims: &Value) -> String {
        self.sign_as(self.alg(), typ, claims)
    }

    fn anchor(&self) -> TrustAnchor {
        TrustAnchor {
            issuer: ISSUER.to_owned(),
            key: self.public(),
        }
    }
}

fn tools() -> Value {
    json!([{
        "type": "attenuating_agent_token",
        "tools": {TOOL: {"path": {"constraint_type": "exact", "value": "/data/q3.pdf"}}}
    }])
}

fn args() -> Value {
    json!({"path": "/data/q3.pdf"})
}

/// The claims of a root token bound to `holder`.
fn root_claims(holder: &Key) -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": NOW - 100,
        "exp": NOW + 900,
        "jti": "root",
        "cnf": {"jwk": holder.jwk()},
        "del_depth": 0,
        "del_max_depth": 3,
        "authorization_details": tools(),
    })
}

/// The claims of a token that `signer`, the holder of `parent`, derives for
/// `holder`.
fn child_claims(parent: &str, signer: &Key, holder: &Key) -> Value {
    let depth = claims_of(parent)["del_depth"].as_i64().unwrap() + 1;
    json!({
        "iss": signer.thumbprint(),
        "aud": AUDIENCE,
        "iat": NOW - 50,
        "exp": NOW + 600,
        "jti": format!("derived-{depth}"),
        "cnf": {"jwk": holder.jwk()},
        "par_hash": token_hash(parent),
        "del_depth": depth,
        "del_max_depth": 3,
        "authorization_details": tools(),
    })
}

fn pop_claims(leaf: &str) -> Value {
    json!({
        "jti": "pop",
        "iat": NOW,
        "aat_id": claims_of(leaf)["jti"],
        "aat_hash": token_hash(leaf),
        "aat_tool": TOOL,
        "aat_aud": AUDIENCE,
        "hta": args(),
    })
}

fn root(issuer: &Key, holder: &Key) -> String {
    issuer.sign(AAT, &root_claims(holder))
}

fn child(parent: &str, signer: &Key, holder: &Key) -> String {
    signer.sign(AAT, &child_claims(parent, signer, holder))
}

fn pop(leaf: &str, holder: &Key) -> String {
    holder.sign(POP, &pop_claims(leaf))
}

fn present(
    chain: &[&str],
    pop: &str,
    anchors: &[TrustAnchor],
    algorithms: &[Algorithm],
) -> Result<Verified, Denied> {
    let mut opts = VerifyOptions::new(AUDIENCE, NOW);
    opts.algorithms = algorithms;
    opts.require_pop_aud = true;
    verify_chain(chain, pop, anchors, TOOL, &args().to_string(), &mut opts)
}

/// The step a presentation is denied at.
fn step(result: Result<Verified, Denied>) -> &'static str {
    match result {
        Err(denied) => denied.step,
        Ok(verified) => panic!("expected a denial, got {verified:?}"),
    }
}

/// Replace the signature of a compact JWS.
fn with_signature(compact: &str, signature: &[u8]) -> String {
    format!(
        "{}.{}",
        compact.rsplit_once('.').unwrap().0,
        b64u(signature)
    )
}

fn signature_of(compact: &str) -> Vec<u8> {
    B64.decode(compact.rsplit_once('.').unwrap().1).unwrap()
}

/// `R || S` as the ASN.1 DER `SEQUENCE { INTEGER, INTEGER }` that X.509 and
/// TLS carry, and a JWS does not (RFC 7518, Section 3.4).
fn der(signature: &[u8]) -> Vec<u8> {
    let integer = |bytes: &[u8]| {
        let start = bytes.iter().take_while(|b| **b == 0).count();
        let mut body = bytes[start.min(bytes.len() - 1)..].to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut out = vec![0x02, body.len() as u8];
        out.extend(body);
        out
    };
    let (r, s) = signature.split_at(32);
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

#[test]
fn the_default_options_permit_ed25519_only() {
    assert_eq!(VerifyOptions::new(AUDIENCE, NOW).algorithms, ED25519);
    assert_eq!(Algorithm::Ed25519.name(), "Ed25519");
    assert_eq!(Algorithm::Es256.name(), "ES256");
}

#[test]
fn an_es256_root_verifies_under_a_p256_anchor() {
    let issuer = Key::p256(1);
    let holder = Key::ed25519(2);
    let root = root(&issuer, &holder);
    let pop = pop(&root, &holder);
    let anchors = [issuer.anchor()];

    let verified = present(&[&root], &pop, &anchors, BOTH).expect("ES256 is permitted");
    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.token_ids, ["root"]);
    assert_eq!(verified.holder, holder.public());

    // A P-256 trust anchor does not add ES256 to the allowlist.
    assert_eq!(step(present(&[&root], &pop, &anchors, ED25519)), "3a");
    assert_eq!(step(present(&[&root], &pop, &anchors, &[])), "3a");
    // The root's signature is permitted, and its holder's key type is not.
    assert_eq!(step(present(&[&root], &pop, &anchors, ES256)), "3l");
}

#[test]
fn p256_holders_derive_and_present_with_es256() {
    let issuer = Key::ed25519(1);
    let first = Key::p256(2);
    let second = Key::p256(3);
    let root = root(&issuer, &first);
    let leaf = child(&root, &first, &second);
    let pop = pop(&leaf, &second);
    let anchors = [issuer.anchor()];

    let verified = present(&[&root, &leaf], &pop, &anchors, BOTH).expect("both are permitted");
    assert_eq!(verified.token_ids, ["root", "derived-1"]);
    assert_eq!(verified.holder, second.public());
    assert_eq!(verified.holder.algorithm(), Algorithm::Es256);
    // A holder key of either type has the thumbprint a token it signs
    // carries as iss, and hashes as it compares.
    assert_eq!(verified.holder.thumbprint_uri(), second.thumbprint());
    assert_eq!(verified.holder.as_ed25519(), None);
    assert_eq!(issuer.public().thumbprint_uri(), issuer.thumbprint());
    assert!(issuer.public().as_ed25519().is_some());
    let seen: std::collections::HashSet<VerifyingKey> = [
        first.public(),
        second.public(),
        second.public(),
        issuer.public(),
    ]
    .into();
    assert_eq!(seen.len(), 3);

    // The root alone, presented by its P-256 holder.
    let root_pop = self::pop(&root, &first);
    assert!(present(&[&root], &root_pop, &anchors, BOTH).is_ok());

    // With Ed25519 alone, the root is refused for the key it binds: that
    // key could only sign what steps 4a and 7a deny.
    assert_eq!(
        step(present(&[&root, &leaf], &pop, &anchors, ED25519)),
        "3l"
    );
    assert_eq!(step(present(&[&root], &root_pop, &anchors, ED25519)), "3l");
}

#[test]
fn one_chain_may_mix_the_two_algorithms() {
    let issuer = Key::p256(1);
    let a = Key::ed25519(2);
    let b = Key::p256(3);
    let c = Key::ed25519(4);
    let root = root(&issuer, &a);
    let middle = child(&root, &a, &b);
    let leaf = child(&middle, &b, &c);
    let pop = pop(&leaf, &c);
    let chain = [root.as_str(), middle.as_str(), leaf.as_str()];
    let anchors = [issuer.anchor()];

    let verified = present(&chain, &pop, &anchors, BOTH).expect("both are permitted");
    assert_eq!(verified.token_ids, ["root", "derived-1", "derived-2"]);
    assert_eq!(verified.holder, c.public());

    // The allowlist is applied to each token on its own.
    assert_eq!(step(present(&chain, &pop, &anchors, ED25519)), "3a");
    assert_eq!(step(present(&chain, &pop, &anchors, ES256)), "3l");

    // The same holders under an Ed25519 issuer: the first token to bind a
    // P-256 key is the one refused.
    let issuer = Key::ed25519(5);
    let root = self::root(&issuer, &a);
    let middle = child(&root, &a, &b);
    let leaf = child(&middle, &b, &c);
    let pop = self::pop(&leaf, &c);
    let chain = [root.as_str(), middle.as_str(), leaf.as_str()];
    let anchors = [issuer.anchor()];
    assert!(present(&chain, &pop, &anchors, BOTH).is_ok());
    assert_eq!(step(present(&chain, &pop, &anchors, ED25519)), "4b2");
}

#[test]
fn a_chain_of_p256_keys_needs_es256_alone() {
    let issuer = Key::p256(1);
    let a = Key::p256(2);
    let b = Key::p256(3);
    let root = root(&issuer, &a);
    let leaf = child(&root, &a, &b);
    let pop = pop(&leaf, &b);
    assert!(present(&[&root, &leaf], &pop, &[issuer.anchor()], ES256).is_ok());
}

#[test]
fn each_signature_is_checked_under_the_key_that_authorizes_it() {
    let issuer = Key::p256(1);
    let a = Key::p256(2);
    let b = Key::p256(3);
    let stranger = Key::p256(9);
    let anchors = [issuer.anchor()];
    let root = root(&issuer, &a);
    let leaf = child(&root, &a, &b);
    let pop = pop(&leaf, &b);
    assert!(present(&[&root, &leaf], &pop, &anchors, BOTH).is_ok());

    // A root another P-256 key signed.
    let forged = self::root(&stranger, &a);
    let forged_pop = self::pop(&forged, &a);
    assert_eq!(step(present(&[&forged], &forged_pop, &anchors, BOTH)), "3b");

    // A token the stranger signed in the holder's name, with the holder's
    // thumbprint as iss.
    let forged = stranger.sign(AAT, &child_claims(&root, &a, &b));
    let forged_pop = self::pop(&forged, &b);
    assert_eq!(
        step(present(&[&root, &forged], &forged_pop, &anchors, BOTH)),
        "4b"
    );

    // A proof of possession the stranger signed.
    let forged_pop = stranger.sign(POP, &pop_claims(&leaf));
    assert_eq!(
        step(present(&[&root, &leaf], &forged_pop, &anchors, BOTH)),
        "7b"
    );
}

#[test]
fn an_es256_signature_is_r_and_s_in_64_bytes() {
    let issuer = Key::p256(1);
    let holder = Key::ed25519(2);
    let anchors = [issuer.anchor()];
    let root = root(&issuer, &holder);
    let signature = signature_of(&root);
    assert_eq!(signature.len(), 64);
    let denied_at_3b = |signature: &[u8]| {
        let token = with_signature(&root, signature);
        let pop = pop(&token, &holder);
        assert_eq!(step(present(&[&token], &pop, &anchors, BOTH)), "3b");
    };

    // One changed bit, in R and in S.
    let mut flipped = signature.clone();
    flipped[0] ^= 1;
    denied_at_3b(&flipped);
    let mut flipped = signature.clone();
    flipped[63] ^= 1;
    denied_at_3b(&flipped);
    // A byte short, a byte long, and empty.
    denied_at_3b(&signature[..63]);
    denied_at_3b(&[signature.as_slice(), &[0]].concat());
    denied_at_3b(&[]);
    // R and S of zero.
    denied_at_3b(&[0; 64]);
    // The DER form of the same signature.
    let encoded = der(&signature);
    assert!(encoded.len() > 64 && encoded[0] == 0x30);
    denied_at_3b(&encoded);
}

#[test]
fn alg_must_be_the_one_the_verifying_key_fixes() {
    let p256_issuer = Key::p256(1);
    let ed25519_issuer = Key::ed25519(5);
    let a = Key::p256(2);
    let b = Key::ed25519(3);

    // A root, by the type of the trust anchor's key.
    for (issuer, wrong) in [
        (
            &p256_issuer,
            ["Ed25519", "ES384", "ES256K", "EdDSA", "none", "HS256"],
        ),
        (
            &ed25519_issuer,
            ["ES256", "ES384", "ES256K", "EdDSA", "none", "HS256"],
        ),
    ] {
        for alg in wrong {
            let root = issuer.sign_as(alg, AAT, &root_claims(&b));
            let pop = pop(&root, &b);
            assert_eq!(
                step(present(&[&root], &pop, &[issuer.anchor()], BOTH)),
                "3a",
                "{alg}"
            );
        }
    }

    // A derived token, by the type of its parent's cnf.jwk.
    let root_a = root(&p256_issuer, &a);
    let root_b = root(&p256_issuer, &b);
    for (parent, signer, alg) in [(&root_a, &a, "Ed25519"), (&root_b, &b, "ES256")] {
        let leaf = signer.sign_as(alg, AAT, &child_claims(parent, signer, &b));
        let pop = pop(&leaf, &b);
        assert_eq!(
            step(present(
                &[parent, &leaf],
                &pop,
                &[p256_issuer.anchor()],
                BOTH
            )),
            "4a",
            "{alg}"
        );
    }

    // A proof of possession, by the type of the leaf's cnf.jwk.
    for (leaf, holder, alg) in [(&root_a, &a, "Ed25519"), (&root_b, &b, "ES256")] {
        let pop = holder.sign_as(alg, POP, &pop_claims(leaf));
        assert_eq!(
            step(present(&[leaf], &pop, &[p256_issuer.anchor()], BOTH)),
            "7a",
            "{alg}"
        );
    }
}

#[test]
fn iss_is_the_thumbprint_of_the_p256_key_that_signed() {
    let issuer = Key::ed25519(1);
    let a = Key::p256(2);
    let b = Key::ed25519(3);
    let other = Key::p256(9);
    let anchors = [issuer.anchor()];
    let root = root(&issuer, &a);

    let with_iss = |iss: String| {
        let mut claims = child_claims(&root, &a, &b);
        claims["iss"] = json!(iss);
        let leaf = a.sign(AAT, &claims);
        let pop = pop(&leaf, &b);
        present(&[&root, &leaf], &pop, &anchors, BOTH)
    };
    assert!(with_iss(a.thumbprint()).is_ok());
    // Another key's thumbprint.
    assert_eq!(step(with_iss(other.thumbprint())), "4c");
    // A digest of the same key that leaves out y.
    let x = a.jwk()["x"].as_str().unwrap().to_owned();
    let without_y = sha256_b64u(&format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}"}}"#));
    assert_eq!(
        step(with_iss(format!(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{without_y}"
        ))),
        "4c"
    );
}

#[test]
fn a_p256_cnf_jwk_is_a_public_point_on_the_curve() {
    let issuer = Key::ed25519(1);
    let holder = Key::p256(2);
    let anchors = [issuer.anchor()];
    let with_jwk = |edit: &dyn Fn(&mut Value)| {
        let mut claims = root_claims(&holder);
        edit(&mut claims["cnf"]["jwk"]);
        let root = issuer.sign(AAT, &claims);
        let pop = pop(&root, &holder);
        present(&[&root], &pop, &anchors, BOTH)
    };

    // Members the verifier does not read are allowed.
    assert!(with_jwk(&|jwk| {
        jwk["kid"] = json!("holder-1");
        jwk["use"] = json!("sig");
    })
    .is_ok());

    type Edit<'a> = &'a dyn Fn(&mut Value);
    let refused: [(&str, Edit); 8] = [
        ("the private member d", &|jwk| {
            jwk["d"] = json!(b64u([7u8; 32]))
        }),
        ("a y that is off the curve", &|jwk| {
            let mut y = B64.decode(jwk["y"].as_str().unwrap()).unwrap();
            y[31] ^= 1;
            jwk["y"] = json!(b64u(y));
        }),
        ("no y", &|jwk| {
            jwk.as_object_mut().unwrap().remove("y");
        }),
        ("an x of 31 bytes", &|jwk| {
            let x = B64.decode(jwk["x"].as_str().unwrap()).unwrap();
            jwk["x"] = json!(b64u(&x[1..]));
        }),
        ("a padded x", &|jwk| {
            jwk["x"] = json!(format!("{}=", jwk["x"].as_str().unwrap()));
        }),
        ("another curve", &|jwk| jwk["crv"] = json!("P-384")),
        ("another key type", &|jwk| jwk["kty"] = json!("OKP")),
        ("coordinates of zero", &|jwk| {
            jwk["x"] = json!(b64u([0u8; 32]));
            jwk["y"] = json!(b64u([0u8; 32]));
        }),
    ];
    for (what, edit) in refused {
        assert_eq!(step(with_jwk(edit)), "3l", "{what}");
    }
}

#[test]
fn anchors_of_both_key_types_may_name_one_issuer() {
    let ed25519 = Key::ed25519(1);
    let p256 = Key::p256(2);
    let holder = Key::ed25519(3);
    let orders = [
        [ed25519.anchor(), p256.anchor()],
        [p256.anchor(), ed25519.anchor()],
    ];
    for anchors in &orders {
        // A root verifies under the anchor whose key type fits its alg.
        for issuer in [&ed25519, &p256] {
            let root = root(issuer, &holder);
            let pop = pop(&root, &holder);
            assert!(present(&[&root], &pop, anchors, BOTH).is_ok());
        }
        // A root no anchor signed fails at the signature, in either order.
        for stranger in [Key::ed25519(8), Key::p256(9)] {
            let root = root(&stranger, &holder);
            let pop = pop(&root, &holder);
            assert_eq!(step(present(&[&root], &pop, anchors, BOTH)), "3b");
        }
        // An alg that fits no anchor's key fails at the header.
        let root = p256.sign_as("ES384", AAT, &root_claims(&holder));
        let pop = pop(&root, &holder);
        assert_eq!(step(present(&[&root], &pop, anchors, BOTH)), "3a");
        // An ES256 root where the allowlist names Ed25519 alone.
        let root = self::root(&p256, &holder);
        let pop = self::pop(&root, &holder);
        assert_eq!(step(present(&[&root], &pop, anchors, ED25519)), "3a");
    }
}

#[test]
fn a_root_is_its_issuers_in_any_order_of_trust_anchors() {
    let issuer = Key::p256(1);
    let holder = Key::ed25519(2);
    let root = root(&issuer, &holder);
    let pop = pop(&root, &holder);

    // The root's signature verifies under a second public key. Here that
    // key is the trust anchor of another issuer.
    let (input, _) = root.rsplit_once('.').unwrap();
    let twin = keys_that_verify(input, &signature_of(&root))
        .into_iter()
        .map(VerifyingKey::from)
        .find(|key| *key != issuer.public())
        .expect("a second key");
    let elsewhere = TrustAnchor {
        issuer: "https://other.example.com".to_owned(),
        key: twin,
    };

    for anchors in [
        [elsewhere.clone(), issuer.anchor()],
        [issuer.anchor(), elsewhere.clone()],
    ] {
        let verified = present(&[&root], &pop, &anchors, BOTH).expect("permitted in either order");
        assert_eq!(verified.issuer, ISSUER);
    }
    // Under the other issuer's anchor alone, the signature verifies and the
    // root does not name that issuer.
    assert_eq!(step(present(&[&root], &pop, &[elsewhere], BOTH)), "3k");
}

#[test]
fn a_root_must_name_the_issuer_whose_key_signed_it() {
    const OTHER: &str = "https://other.example.com";
    let ed25519 = Key::ed25519(1);
    let p256 = Key::p256(2);
    let holder = Key::ed25519(3);
    let anchors = [
        ed25519.anchor(),
        TrustAnchor {
            issuer: OTHER.to_owned(),
            key: p256.public(),
        },
    ];
    // Each issuer's own roots verify.
    let mut claims = root_claims(&holder);
    let own = ed25519.sign(AAT, &claims);
    assert!(present(&[&own], &pop(&own, &holder), &anchors, BOTH).is_ok());
    claims["iss"] = json!(OTHER);
    let own = p256.sign(AAT, &claims);
    assert!(present(&[&own], &pop(&own, &holder), &anchors, BOTH).is_ok());

    // A root one issuer signed that names the other.
    let crossed = ed25519.sign(AAT, &claims);
    assert_eq!(
        step(present(
            &[&crossed],
            &pop(&crossed, &holder),
            &anchors,
            BOTH
        )),
        "3k"
    );
    claims["iss"] = json!(ISSUER);
    let crossed = p256.sign(AAT, &claims);
    assert_eq!(
        step(present(
            &[&crossed],
            &pop(&crossed, &holder),
            &anchors,
            BOTH
        )),
        "3k"
    );
}

#[test]
fn a_coordinate_must_be_below_the_field_prime() {
    let issuer = Key::ed25519(1);
    let other = Key::ed25519(2);
    let anchors = [issuer.anchor()];
    let (x, y) = point_with_small_x();
    let with_x = |x: &[u8; 32]| {
        let mut claims = root_claims(&other);
        claims["cnf"]["jwk"] = json!({"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)});
        let root = issuer.sign(AAT, &claims);
        // No one holds this point's private key, so the proof is another
        // key's: a root that passes step 3l fails at the proof's header.
        let pop = pop(&root, &other);
        step(present(&[&root], &pop, &anchors, BOTH))
    };
    assert_eq!(with_x(&x), "7a");
    // x + p names the same field element, and is not the coordinate.
    assert_eq!(with_x(&add(&x, &P)), "3l");
}

#[test]
fn r_and_s_must_be_below_the_group_order() {
    // N is the group order: the largest private key is N - 1.
    let mut below = N;
    below[31] -= 1;
    assert!(p256::ecdsa::SigningKey::from_slice(&below).is_ok());
    assert!(p256::ecdsa::SigningKey::from_slice(&N).is_err());

    // A signature whose R and S are small numbers, and a key it is valid
    // under, as the trust anchor.
    let holder = Key::ed25519(2);
    let header = json!({"alg": "ES256", "typ": AAT});
    let input = format!(
        "{}.{}",
        b64u(header.to_string()),
        b64u(root_claims(&holder).to_string())
    );
    let (r, _) = point_with_small_x();
    let mut s = [0u8; 32];
    s[31] = 7;
    let token =
        |r: &[u8; 32], s: &[u8; 32]| format!("{input}.{}", b64u([r.as_slice(), s].concat()));
    let key = keys_that_verify(&input, &[r.as_slice(), &s].concat())
        .into_iter()
        .next()
        .expect("a key the signature is valid under");
    let anchors = [TrustAnchor {
        issuer: ISSUER.to_owned(),
        key: key.into(),
    }];
    let root = token(&r, &s);
    assert!(present(&[&root], &pop(&root, &holder), &anchors, BOTH).is_ok());

    // R + n and S + n name the same residues, and are not the signature.
    for (r, s) in [(add(&r, &N), s), (r, add(&s, &N))] {
        let root = token(&r, &s);
        assert_eq!(
            step(present(&[&root], &pop(&root, &holder), &anchors, BOTH)),
            "3b"
        );
    }
}
