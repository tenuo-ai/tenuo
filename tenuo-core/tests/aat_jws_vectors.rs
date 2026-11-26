//! The AAT JWS vector suite (`tests/vectors/aat-jws-vectors.json`) against
//! `tenuo::aat::verify_chain`.
//!
//! Every vector is presented exactly as the suite gives it: the compact
//! tokens, the PoP, and the argument text. The verdict must match, and so must
//! the first failing Section 8 step.

use base64::Engine;
use serde_json::Value;
use std::collections::BTreeSet;
use tenuo::aat::{verify_chain, Algorithm, Limits, ReplayStore, TrustAnchor, VerifyOptions};
use tenuo::{PublicKey, SigningKey};

const VECTORS: &str = include_str!("../../tests/vectors/aat-jws-vectors.json");
const SPEC: &str = "draft-niyikiza-oauth-attenuating-agent-tokens-02";
const VECTOR_COUNT: usize = 229;

#[derive(Default)]
struct Accepted(BTreeSet<String>);

impl ReplayStore for Accepted {
    fn record(&mut self, pop_jti: &str) -> bool {
        self.0.insert(pop_jti.to_owned())
    }
}

struct Suite {
    doc: Value,
    anchors: Vec<TrustAnchor>,
    /// The algorithms the enforcement point permits. The suite's own policy
    /// is the default, `Ed25519` only.
    algorithms: &'static [Algorithm],
}

impl Suite {
    fn load() -> Self {
        let doc: Value = serde_json::from_str(VECTORS).expect("vector file is JSON");
        assert_eq!(doc["spec"], SPEC);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let anchors = doc["trust_anchors"]
            .as_array()
            .expect("trust_anchors")
            .iter()
            .map(|anchor| {
                let x = b64
                    .decode(anchor["jwk"]["x"].as_str().expect("jwk.x"))
                    .expect("base64url");
                TrustAnchor {
                    issuer: anchor["iss"].as_str().expect("iss").to_owned(),
                    key: PublicKey::from_bytes(&x.try_into().expect("32 bytes"))
                        .expect("key")
                        .into(),
                }
            })
            .collect();
        Self {
            doc,
            anchors,
            algorithms: &[Algorithm::Ed25519],
        }
    }

    fn vectors(&self) -> &[Value] {
        self.doc["vectors"].as_array().expect("vectors")
    }

    fn limits(&self, vector: &Value) -> Limits {
        let param = |name: &str| {
            vector["params"]
                .get(name)
                .or_else(|| self.doc["params"].get(name))
                .and_then(Value::as_u64)
                .unwrap_or_else(|| panic!("param {name}"))
        };
        Limits {
            max_iat_skew: param("max_iat_skew") as u32,
            max_token_lifetime: param("max_token_lifetime"),
            max_delegation_depth: param("max_delegation_depth") as u8,
            max_constraint_depth: param("max_constraint_depth") as usize,
            max_token_size: param("max_token_size") as usize,
            max_chain_size: param("max_chain_size") as usize,
            pop_window: param("pop_window") as u32,
        }
    }

    /// Run one vector, with `edit` applied to the presentation first.
    /// Returns the verdict as the suite writes it and the replay state after.
    fn run(
        &self,
        vector: &Value,
        edit: impl FnOnce(&mut Vec<String>, &mut String, &mut String),
    ) -> ((String, Option<String>), Option<BTreeSet<String>>) {
        let mut chain: Vec<String> = strings(&vector["presentation"]["aat_chain"]);
        let mut pop = text(&vector["presentation"]["aat_pop"]);
        let mut args = text(&vector["args_json"]);
        edit(&mut chain, &mut pop, &mut args);

        let policy = &vector["policy"];
        let mut accepted = policy["track_pop_jti"].as_bool().unwrap_or(false).then(|| {
            Accepted(
                strings(&vector["replay_state"]["before"])
                    .into_iter()
                    .collect(),
            )
        });
        let audience = text(&self.doc["params"]["audience"]);
        let mut opts = VerifyOptions::new(&audience, vector["now"].as_i64().expect("now"));
        opts.limits = self.limits(vector);
        opts.algorithms = self.algorithms;
        opts.require_pop_aud = policy["require_pop_aud"].as_bool().unwrap_or(false);
        opts.require_chain_aud = policy["require_chain_aud"].as_bool().unwrap_or(false);
        opts.nonce = policy["nonce"].as_str();
        opts.replay = accepted.as_mut().map(|a| a as &mut dyn ReplayStore);

        let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
        let tool = text(&vector["tool"]);
        let verdict = match verify_chain(&chain, &pop, &self.anchors, &tool, &args, &mut opts) {
            Ok(_) => ("PERMIT".to_owned(), None),
            Err(denied) => ("DENY".to_owned(), Some(denied.step.to_owned())),
        };
        (verdict, accepted.map(|a| a.0))
    }
}

fn text(value: &Value) -> String {
    value.as_str().expect("string").to_owned()
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().expect("array").iter().map(text).collect()
}

fn permits(suite: &Suite) -> impl Iterator<Item = &Value> {
    suite
        .vectors()
        .iter()
        .filter(|v| v["expected"]["verdict"] == "PERMIT")
}

/// Change one character of the signature segment to another base64url one.
fn corrupt_signature(compact: &mut String) {
    let at = compact.rfind('.').expect("compact JWS") + 1;
    let replacement = if compact.as_bytes()[at] == b'A' {
        "B"
    } else {
        "A"
    };
    compact.replace_range(at..=at, replacement);
}

/// Every chain in the suite uses Ed25519 keys, so permitting ES256 as well
/// changes no verdict and no failing step.
#[cfg(feature = "aat-es256")]
#[test]
fn every_vector_is_unchanged_when_es256_is_also_permitted() {
    let mut suite = Suite::load();
    suite.algorithms = &[Algorithm::Ed25519, Algorithm::Es256];
    let differing: Vec<String> = suite
        .vectors()
        .iter()
        .filter_map(|vector| {
            let expected = (
                text(&vector["expected"]["verdict"]),
                vector["expected"]["step"].as_str().map(str::to_owned),
            );
            let (got, _) = suite.run(vector, |_, _, _| {});
            (got != expected)
                .then(|| format!("{}: expected {expected:?}, got {got:?}", vector["id"]))
        })
        .collect();
    assert!(differing.is_empty(), "{}", differing.join("\n"));
}

#[test]
fn every_vector_matches_verdict_and_step() {
    let suite = Suite::load();
    assert_eq!(suite.vectors().len(), VECTOR_COUNT);

    let mut mismatches = Vec::new();
    for vector in suite.vectors() {
        let id = vector["id"].as_str().expect("id");
        let expected = (
            text(&vector["expected"]["verdict"]),
            vector["expected"]["step"].as_str().map(str::to_owned),
        );
        let (got, replay_after) = suite.run(vector, |_, _, _| {});
        if got != expected {
            mismatches.push(format!("{id}: expected {expected:?}, got {got:?}"));
        }
        if let Some(after) = replay_after {
            let want: BTreeSet<String> = strings(&vector["replay_state"]["after"])
                .into_iter()
                .collect();
            if after != want {
                mismatches.push(format!("{id}: replay state {after:?}, expected {want:?}"));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {VECTOR_COUNT} vectors differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn a_permitted_presentation_fails_once_any_signature_changes() {
    let suite = Suite::load();
    let mut checked = 0;
    for vector in permits(&suite) {
        let id = &vector["id"];
        let tokens = strings(&vector["presentation"]["aat_chain"]).len();
        for i in 0..tokens {
            let (got, _) = suite.run(vector, |chain, _, _| corrupt_signature(&mut chain[i]));
            assert_eq!(got.0, "DENY", "{id}: token {i} with a changed signature");
            checked += 1;
        }
        let (got, _) = suite.run(vector, |_, pop, _| corrupt_signature(pop));
        assert_eq!(got, ("DENY".to_owned(), Some("7b".to_owned())), "{id}: PoP");
        checked += 1;
    }
    assert!(checked > 100, "only {checked} cases ran");
}

#[test]
fn a_permitted_presentation_fails_for_other_arguments_or_another_tool() {
    let suite = Suite::load();
    for vector in permits(&suite) {
        let id = &vector["id"];
        // An extra argument the PoP did not sign.
        let (got, _) = suite.run(vector, |_, _, args| {
            let extra = if args.trim() == "{}" {
                r#"{"__extra":1}"#.to_owned()
            } else {
                format!(r#"{{"__extra":1,{}"#, &args.trim_start()[1..])
            };
            *args = extra;
        });
        assert_eq!(got.0, "DENY", "{id}: extra argument");

        // The same member twice, which a lenient parser would collapse.
        let (got, _) = suite.run(vector, |_, _, args| {
            if let Some(body) = args.trim().strip_prefix('{').filter(|b| b.trim() != "}") {
                let member_end = top_level_member_end(body);
                *args = format!("{{{},{}", &body[..member_end], body);
            } else {
                *args = "[]".to_owned();
            }
        });
        assert_eq!(
            got,
            ("DENY".to_owned(), Some("6b".to_owned())),
            "{id}: repeated member"
        );
    }
}

/// Byte length of the first member of an object body (text after `{`).
fn top_level_member_end(body: &str) -> usize {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for (i, c) in body.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' if depth > 0 => depth -= 1,
            ',' | '}' if depth == 0 => return i,
            _ => {}
        }
    }
    body.len()
}

#[test]
fn an_unknown_trust_anchor_or_an_empty_anchor_set_denies() {
    let suite = Suite::load();
    let vector = permits(&suite).next().expect("a PERMIT vector");
    let chain = strings(&vector["presentation"]["aat_chain"]);
    let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
    let pop = text(&vector["presentation"]["aat_pop"]);
    let (tool, args) = (text(&vector["tool"]), text(&vector["args_json"]));
    let audience = text(&suite.doc["params"]["audience"]);
    let now = vector["now"].as_i64().expect("now");

    let mut opts = VerifyOptions::new(&audience, now);
    let denied = verify_chain(&chain, &pop, &[], &tool, &args, &mut opts).unwrap_err();
    assert_eq!(denied.step, "3b");

    // The right key under another issuer name.
    let renamed = [TrustAnchor {
        issuer: "https://other.example.com".to_owned(),
        key: suite.anchors[0].key.clone(),
    }];
    let mut opts = VerifyOptions::new(&audience, now);
    let denied = verify_chain(&chain, &pop, &renamed, &tool, &args, &mut opts).unwrap_err();
    assert_eq!(denied.step, "3k");
}

/// A compact JWS over `claims`, signed by the suite key whose public `x` is
/// given.
fn sign(suite: &Suite, x: &Value, header_b64: &Value, claims: &Value) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let seed = suite.doc["keys"]
        .as_object()
        .expect("keys")
        .values()
        .find(|key| &key["jwk"]["x"] == x)
        .and_then(|key| key["seed_hex"].as_str())
        .expect("the suite holds this key's seed");
    let seed: [u8; 32] = hex::decode(seed)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let input = format!("{}.{}", text(header_b64), b64.encode(claims.to_string()));
    let signature = SigningKey::from_bytes(&seed).sign_raw(input.as_bytes());
    format!("{input}.{}", b64.encode(signature.to_bytes()))
}

/// A PoP JWT for `vector`'s leaf with `edit` applied to the suite's claims,
/// signed by the suite key that holds the leaf.
fn signed_pop(suite: &Suite, vector: &Value, edit: impl FnOnce(&mut Value)) -> String {
    let leaf = vector["chain"]
        .as_array()
        .and_then(|chain| chain.last())
        .expect("leaf");
    let mut claims = vector["pop"]["payload"].clone();
    edit(&mut claims);
    sign(
        suite,
        &leaf["payload"]["cnf"]["jwk"]["x"],
        &vector["pop"]["header_b64"],
        &claims,
    )
}

/// The first PERMIT vector with no policy and a one-token chain.
fn plain_permit(suite: &Suite) -> &Value {
    permits(suite)
        .find(|v| {
            v["chain"].as_array().map(Vec::len) == Some(1)
                && v["policy"].as_object().is_some_and(|p| p.is_empty())
                && v["params"].as_object().is_some_and(|p| p.is_empty())
        })
        .expect("a plain PERMIT vector")
}

#[test]
fn a_null_pop_audience_is_present_and_names_nothing() {
    let suite = Suite::load();
    let vector = plain_permit(&suite);
    let verdict = |edit: fn(&mut Value)| {
        let pop = signed_pop(&suite, vector, edit);
        suite.run(vector, |_, presented, _| *presented = pop).0
    };
    let permit = ("PERMIT".to_owned(), None);

    // The helper signs what the verifier accepts.
    assert_eq!(verdict(|_| {}), permit);
    // The claim is optional: without it, and with no audience policy, PERMIT.
    assert_eq!(
        verdict(|claims| {
            claims.as_object_mut().expect("claims").remove("aat_aud");
        }),
        permit
    );
    assert_eq!(
        verdict(|claims| claims["aat_aud"] = Value::Null),
        ("DENY".to_owned(), Some("7d".to_owned()))
    );
}

#[test]
fn a_pop_larger_than_a_token_may_be_is_denied() {
    let suite = Suite::load();
    let vector = plain_permit(&suite);
    let limit = suite.limits(vector).max_token_size;
    let verdict = |padding: usize| {
        let pop = signed_pop(&suite, vector, |claims| {
            claims["padding"] = Value::String("x".repeat(padding));
        });
        (
            pop.len(),
            suite.run(vector, |_, presented, _| *presented = pop).0,
        )
    };

    // An unknown claim is ignored, so a padded PoP within the limit passes.
    let (size, small) = verdict(1_000);
    assert!(size <= limit);
    assert_eq!(small, ("PERMIT".to_owned(), None));
    let (size, large) = verdict(limit);
    assert!(size > limit);
    assert_eq!(large, ("DENY".to_owned(), Some("7a".to_owned())));
}

#[test]
fn anchors_that_share_a_key_each_vouch_for_their_own_issuer() {
    let suite = Suite::load();
    let vector = plain_permit(&suite);
    let chain = strings(&vector["presentation"]["aat_chain"]);
    let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
    let pop = text(&vector["presentation"]["aat_pop"]);
    let (tool, args) = (text(&vector["tool"]), text(&vector["args_json"]));
    let audience = text(&suite.doc["params"]["audience"]);
    let now = vector["now"].as_i64().expect("now");
    let issuer = text(&vector["chain"][0]["payload"]["iss"]);
    let key = suite
        .anchors
        .iter()
        .find(|anchor| anchor.issuer == issuer)
        .expect("the root's anchor")
        .key
        .clone();
    let anchor = |issuer: &str| TrustAnchor {
        issuer: issuer.to_owned(),
        key: key.clone(),
    };
    let other = "https://other.example.com";

    // The root's issuer is found whichever anchor with its key comes first.
    for anchors in [
        [anchor(other), anchor(&issuer)],
        [anchor(&issuer), anchor(other)],
    ] {
        let mut opts = VerifyOptions::new(&audience, now);
        let verified = verify_chain(&chain, &pop, &anchors, &tool, &args, &mut opts)
            .expect("the root's issuer and key are an anchor");
        assert_eq!(verified.issuer, issuer);
    }
    // The key alone is not enough.
    let mut opts = VerifyOptions::new(&audience, now);
    let denied = verify_chain(
        &chain,
        &pop,
        &[anchor(other), anchor("https://third.example.com")],
        &tool,
        &args,
        &mut opts,
    )
    .unwrap_err();
    assert_eq!(denied.step, "3k");
}

/// Step 3k asks for a URI. A root whose `iss` is not one is denied even when
/// a trust anchor is configured under that same string.
#[test]
fn a_root_issuer_that_is_not_a_uri_is_denied_even_when_an_anchor_matches() {
    let suite = Suite::load();
    let vector = plain_permit(&suite);
    let root = &vector["chain"][0];
    let anchor = suite.doc["trust_anchors"]
        .as_array()
        .expect("trust_anchors")
        .iter()
        .zip(&suite.anchors)
        .find(|(doc, _)| doc["iss"] == root["payload"]["iss"])
        .expect("the root's anchor");
    let step = |issuer: &str| {
        let mut claims = root["payload"].clone();
        claims["iss"] = Value::String(issuer.to_owned());
        let token = sign(&suite, &anchor.0["jwk"]["x"], &root["header_b64"], &claims);
        let anchors = [TrustAnchor {
            issuer: issuer.to_owned(),
            key: anchor.1.key.clone(),
        }];
        let pop = text(&vector["presentation"]["aat_pop"]);
        let (tool, args) = (text(&vector["tool"]), text(&vector["args_json"]));
        let audience = text(&suite.doc["params"]["audience"]);
        let mut opts = VerifyOptions::new(&audience, vector["now"].as_i64().expect("now"));
        verify_chain(&[token.as_str()], &pop, &anchors, &tool, &args, &mut opts)
            .unwrap_err()
            .step
    };

    // A well-formed issuer passes 3k; the suite's PoP names another token.
    assert_eq!(step("https://auth.example.com/tenant%20a"), "7c");
    for issuer in [
        "https://auth.example.com/%GG",
        "https://auth.example.com/a b",
        "auth.example.com",
    ] {
        assert_eq!(step(issuer), "3k", "{issuer}");
    }
}
