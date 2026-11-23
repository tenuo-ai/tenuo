//! The AAT JWS vector suite (`tests/vectors/aat-jws-vectors.json`) against
//! `tenuo::aat::verify_chain`.
//!
//! Every vector is presented exactly as the suite gives it: the compact
//! tokens, the PoP, and the argument text. The verdict must match, and so must
//! the first failing Section 8 step.

use base64::Engine;
use serde_json::Value;
use std::collections::BTreeSet;
use tenuo::aat::{verify_chain, Limits, ReplayStore, TrustAnchor, VerifyOptions};
use tenuo::PublicKey;

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
                    key: PublicKey::from_bytes(&x.try_into().expect("32 bytes")).expect("key"),
                }
            })
            .collect();
        Self { doc, anchors }
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
