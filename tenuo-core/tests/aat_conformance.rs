//! AAT conformance: the JWS vector suite, run against tenuo-core.
//!
//! The AAT draft's semantics are format-agnostic (Appendix D). This test reads
//! `ietf/vectors/aat-jws-vectors.json`, rebuilds every chain as CBOR warrants
//! signed with the same seeds, ids, timestamps, depths and constraints,
//! rebuilds the PoP with Tenuo's PoP scheme, runs the Authorizer at the
//! vector's clock, and asserts the verdict. Bytes cannot agree across formats;
//! decisions must.
//!
//! Claim mapping:
//!   jti -> id | iss (thumbprint) -> issuer key | cnf.jwk.x -> holder
//!   del_depth / del_max_depth -> depth / max_depth | iat / exp -> issued_at / expires_at
//!   par_hash -> parent_hash (recomputed over the transcoded parent; a wrong
//!   par_hash becomes a wrong parent_hash) | authorization_details.tools -> tools
//!   PoP (aat_id, aat_tool, hta, iat) -> warrant.sign_with_timestamp(...)
//!
//! Vectors with no CBOR-profile analogue are listed in [`NOT_APPLICABLE`] with
//! their reason. Everything else must match. Adding to that list is a change
//! to Tenuo's conformance claim and should be reviewed as one.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use tenuo::constraints::*;
use tenuo::*;

/// Local alias: `tenuo::*` exports its own `Result<T>`.
type R<T> = std::result::Result<T, String>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Vectors that exercise JWS-profile mechanics with no CBOR-profile analogue,
/// or where Tenuo's wire format deliberately differs. The Authorizer's verdict
/// on these is reported but not asserted.
const NOT_APPLICABLE: &[(&str, &str)] = &[
    ("J.6.1", "PoP audience: Tenuo PoP v1 carries no audience (pop-v2 adds it)"),
    ("J.6.2", "PoP audience: Tenuo PoP v1 carries no audience (pop-v2 adds it)"),
    ("J.7.1", "JWS typ header has no CBOR analogue"),
    ("J.7.2", "JWS typ header has no CBOR analogue"),
    ("J.7.3", "JWS typ header has no CBOR analogue"),
    ("J.7.4", "JWS typ header has no CBOR analogue"),
    ("J.21.3", "cnf.jwk private member: Tenuo holders are raw keys"),
    (
        "J.21.1",
        "lone warrant: Tenuo's leaf format presents a single warrant by itself, trusted on the anchor's signature; root-shape checks apply to chains only",
    ),
    (
        "J.21.2",
        "lone warrant: Tenuo's leaf format presents a single warrant by itself, trusted on the anchor's signature; root-shape checks apply to chains only",
    ),
];

fn seed_key(name: &str) -> Option<SigningKey> {
    let seed = match name {
        "control_plane" => 0x01,
        "orchestrator" => 0x02,
        "worker" => 0x03,
        "worker2" => 0x04,
        "attacker" => 0xFF,
        _ => return None,
    };
    Some(SigningKey::from_bytes(&[seed; 32]))
}

fn thumbprint_uri(key: &SigningKey) -> String {
    use base64::Engine;
    let x = B64.encode(key.public_key().to_bytes());
    let jcs = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        B64.encode(Sha256::digest(jcs.as_bytes()))
    )
}

fn to_value(v: &serde_json::Value) -> R<ConstraintValue> {
    use serde_json::Value as J;
    Ok(match v {
        J::String(s) => ConstraintValue::String(s.clone()),
        // Float unconditionally, as in Warden's interop shim: this is a test of
        // semantics, not of JSON-to-CBOR value-model translation.
        J::Number(n) => ConstraintValue::Float(n.as_f64().ok_or("number not f64")?),
        J::Bool(b) => ConstraintValue::Boolean(*b),
        J::Array(a) => ConstraintValue::List(a.iter().map(to_value).collect::<R<_>>()?),
        J::Object(o) => {
            let mut m = BTreeMap::new();
            for (k, x) in o {
                m.insert(k.clone(), to_value(x)?);
            }
            ConstraintValue::Object(m)
        }
        J::Null => return Err("null".into()),
    })
}

fn to_constraint(v: &serde_json::Value) -> R<Constraint> {
    let o = v.as_object().ok_or("constraint is not an object")?;
    let typ = o
        .get("constraint_type")
        .and_then(|t| t.as_str())
        .ok_or("missing constraint_type")?;
    let values = |k: &str| -> R<Vec<ConstraintValue>> {
        o.get(k)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{typ}: {k} missing"))?
            .iter()
            .map(to_value)
            .collect()
    };
    let clauses = || -> R<Vec<Constraint>> {
        o.get("constraints")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{typ}: constraints missing"))?
            .iter()
            .map(to_constraint)
            .collect()
    };
    Ok(match typ {
        "wildcard" => Constraint::Wildcard(Wildcard),
        "exact" => Constraint::Exact(Exact {
            value: to_value(o.get("value").ok_or("exact: missing value")?)?,
        }),
        "one_of" => Constraint::OneOf(OneOf {
            values: values("values")?,
        }),
        "not_one_of" => Constraint::NotOneOf(NotOneOf {
            excluded: values("excluded")?,
        }),
        "contains" => Constraint::Contains(Contains {
            required: values("required")?,
        }),
        "subset" => Constraint::Subset(Subset {
            allowed: values("allowed")?,
        }),
        "all" => Constraint::All(All {
            constraints: clauses()?,
        }),
        "any" => Constraint::Any(Any {
            constraints: clauses()?,
        }),
        "range" => {
            let num = |k: &str| -> R<Option<f64>> {
                match o.get(k) {
                    None => Ok(None),
                    Some(x) => x
                        .as_f64()
                        .map(Some)
                        .ok_or_else(|| format!("range: {k} not a number")),
                }
            };
            let flag = |k: &str| -> R<bool> {
                match o.get(k) {
                    None => Ok(true),
                    Some(x) => x.as_bool().ok_or_else(|| format!("range: {k} not a bool")),
                }
            };
            Constraint::Range(Range {
                min: num("min")?,
                max: num("max")?,
                min_inclusive: flag("min_inclusive")?,
                max_inclusive: flag("max_inclusive")?,
            })
        }
        other => {
            return Err(format!(
                "constraint_type {other:?} has no Tenuo equivalent (fail-closed)"
            ))
        }
    })
}

fn aat_tools(claims: &serde_json::Value) -> R<BTreeMap<String, ConstraintSet>> {
    let ents: Vec<&serde_json::Value> = claims["authorization_details"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e["type"].as_str() == Some("attenuating_agent_token"))
                .collect()
        })
        .unwrap_or_default();
    let mut tools = BTreeMap::new();
    if let Some(e) = ents.first() {
        for (tool, cmap) in e["tools"].as_object().ok_or("tools not object")? {
            let mut cs = ConstraintSet::new();
            for (arg, c) in cmap.as_object().ok_or("constraint map not object")? {
                cs.insert(arg.clone(), to_constraint(c)?);
            }
            tools.insert(tool.clone(), cs);
        }
    }
    Ok(tools)
}

fn args_map(v: &serde_json::Value) -> HashMap<String, ConstraintValue> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, x)| (k.clone(), to_value(x).expect("arg value")))
                .collect()
        })
        .unwrap_or_default()
}

fn jti_to_id(jti: &str) -> warrant::WarrantId {
    let hex_s: String = jti.chars().filter(|c| *c != '-').collect();
    let bytes = hex::decode(hex_s).expect("jti hex");
    warrant::WarrantId::from_bytes(bytes.try_into().expect("16 bytes"))
}

fn sign_payload(payload: &payload::WarrantPayload, signing_key: &SigningKey) -> Warrant {
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut payload_bytes).expect("serialize payload");
    let mut preimage = Vec::with_capacity(1 + payload_bytes.len());
    preimage.push(1);
    preimage.extend_from_slice(&payload_bytes);
    let signature = signing_key.sign(&preimage);
    Warrant {
        payload: payload.clone(),
        signature,
        payload_bytes,
        envelope_version: 1,
    }
}

/// Transcode one JWS token into a Tenuo warrant. `parent` is the transcoded
/// parent plus the base64url SHA-256 of the parent's JWS signing input.
fn transcode_token(
    tok: &serde_json::Value,
    parent: Option<(&Warrant, &str)>,
    keys_by_iss: &HashMap<String, SigningKey>,
) -> R<Warrant> {
    use base64::Engine;
    let claims = &tok["payload"];
    let signer_label = tok["signer"].as_str().unwrap_or("");
    let signer_name = signer_label.split(' ').next().unwrap_or("");
    let signer = seed_key(signer_name);

    let depth = claims["del_depth"].as_u64().ok_or("del_depth")? as u32;
    let holder_x = B64
        .decode(claims["cnf"]["jwk"]["x"].as_str().ok_or("cnf.jwk.x")?)
        .map_err(|e| e.to_string())?;
    let holder = PublicKey::from_bytes(&holder_x.try_into().map_err(|_| "holder len")?)
        .map_err(|e| e.to_string())?;

    // Tenuo has one field for "who signed", so a forged iss with an honest
    // signature (J.4.c) collapses into a signature failure. Same verdict.
    let issuer: PublicKey = if depth == 0 {
        signer
            .as_ref()
            .map(|k| k.public_key())
            .unwrap_or_else(|| seed_key("control_plane").unwrap().public_key())
    } else {
        let iss = claims["iss"].as_str().unwrap_or("");
        keys_by_iss
            .get(iss)
            .map(|k| k.public_key())
            .or_else(|| signer.as_ref().map(|k| k.public_key()))
            .ok_or("no issuer key")?
    };

    let parent_hash = match (claims.get("par_hash").and_then(|p| p.as_str()), parent) {
        (None, _) => None,
        (Some(ph), Some((pw, expected))) if ph == expected => {
            Some(Sha256::digest(pw.payload_bytes()).into())
        }
        // Faithfully wrong: a splice stays a splice after transcoding.
        (Some(ph), _) => Some(Sha256::digest(format!("wrong:{ph}").as_bytes()).into()),
    };

    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: jti_to_id(claims["jti"].as_str().ok_or("jti")?),
        tools: aat_tools(claims)?,
        holder,
        issuer,
        issued_at: claims["iat"].as_u64().ok_or("iat")?,
        expires_at: claims["exp"].as_u64().ok_or("exp")?,
        max_depth: claims["del_max_depth"].as_u64().ok_or("del_max_depth")? as u8,
        depth,
        parent_hash,
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };

    let mut w = match signer {
        Some(k) => sign_payload(&payload, &k),
        None => {
            // "(unsigned)" is alg:none. An all-zero signature is the closest
            // faithful transcoding of "no signature".
            let mut w = sign_payload(&payload, &seed_key("control_plane").unwrap());
            w.signature = Signature::from_bytes(&[0u8; 64]).map_err(|e| e.to_string())?;
            w
        }
    };
    if signer_label.contains("XOR 0x01") {
        let mut sig = w.signature.to_bytes();
        sig[0] ^= 0x01;
        w.signature = Signature::from_bytes(&sig).map_err(|e| e.to_string())?;
    }
    Ok(w)
}

/// The suite is compiled in, like the other cross-language vectors in
/// tests/vectors/, so a moved or missing file fails the build, not the run.
const SUITE: &str = include_str!("../../tests/vectors/aat-jws-vectors.json");

fn load_suite() -> serde_json::Value {
    serde_json::from_str(SUITE).expect("vector JSON")
}

#[test]
fn aat_jws_vector_suite_verdicts_match() {
    let suite = load_suite();
    let params = &suite["params"];
    let max_iat_skew = params["max_iat_skew"].as_i64().unwrap();
    let max_lifetime = params["max_token_lifetime"].as_u64().unwrap();
    let pop_window = params["pop_window"].as_i64().unwrap();
    let na: HashMap<&str, &str> = NOT_APPLICABLE.iter().copied().collect();

    let mut keys_by_iss = HashMap::new();
    for n in [
        "control_plane",
        "orchestrator",
        "worker",
        "worker2",
        "attacker",
    ] {
        let k = seed_key(n).unwrap();
        keys_by_iss.insert(thumbprint_uri(&k), k);
    }
    let cp = seed_key("control_plane").unwrap();

    let authorizer = Authorizer::new()
        .with_trusted_root(cp.public_key())
        .with_clock_tolerance(chrono::Duration::seconds(max_iat_skew))
        .with_max_token_lifetime(std::time::Duration::from_secs(max_lifetime))
        // ±window: current bucket, one back, one forward.
        .with_pop_window(pop_window, 3);

    let mut failures = Vec::new();
    let mut asserted = 0;
    let mut skipped = Vec::new();

    for v in suite["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let expected = v["expected"]["verdict"].as_str().unwrap();
        let now = v["now"].as_i64().unwrap();
        let tool = v["tool"].as_str().unwrap();
        let args = args_map(&v["args"]);

        // Transcode the chain; an unmappable token (unknown constraint type)
        // is a fail-closed DENY.
        let toks = v["chain"].as_array().unwrap();
        let mut chain: Vec<Warrant> = Vec::new();
        let mut verdict: Option<(String, String)> = None;
        for (i, tok) in toks.iter().enumerate() {
            let parent = if i > 0 {
                Some((
                    &chain[i - 1],
                    toks[i - 1]["signing_input_sha256_b64u"].as_str().unwrap(),
                ))
            } else {
                None
            };
            match transcode_token(tok, parent, &keys_by_iss) {
                Ok(w) => chain.push(w),
                Err(e) => {
                    verdict = Some(("DENY".into(), format!("transcode: {e}")));
                    break;
                }
            }
        }

        let (got, detail) = match verdict {
            Some(v) => v,
            None => {
                let pop_claims = &v["pop"]["payload"];
                let pop_signer = seed_key(
                    v["pop"]["signer"]
                        .as_str()
                        .unwrap_or("")
                        .split(' ')
                        .next()
                        .unwrap_or(""),
                )
                .unwrap();
                let aat_id = pop_claims["aat_id"].as_str().unwrap_or("");
                let pop_target = chain
                    .iter()
                    .find(|w| w.id() == &jti_to_id(aat_id))
                    .unwrap_or_else(|| chain.last().unwrap());
                let hta = args_map(&pop_claims["hta"]);
                let pop = pop_target
                    .sign_with_timestamp(
                        &pop_signer,
                        pop_claims["aat_tool"].as_str().unwrap(),
                        &hta,
                        pop_claims["iat"].as_i64(),
                    )
                    .expect("pop sign");
                match authorizer.check_chain_with_pop_args_as_of(
                    &chain,
                    tool,
                    &args,
                    &args,
                    Some(&pop),
                    &[],
                    now,
                ) {
                    Ok(_) => ("PERMIT".to_string(), String::new()),
                    Err(e) => ("DENY".to_string(), e.to_string()),
                }
            }
        };

        if let Some(reason) = na.get(id) {
            skipped.push(format!("{id}: tenuo {got} (expected {expected}); {reason}"));
            continue;
        }
        asserted += 1;
        if got != expected {
            failures.push(format!("{id}: expected {expected}, tenuo {got} [{detail}]"));
        }
    }

    println!("asserted {asserted} vectors; not applicable:");
    for s in &skipped {
        println!("  {s}");
    }
    assert_eq!(
        asserted + skipped.len(),
        suite["vectors"].as_array().unwrap().len(),
        "every vector is either asserted or listed as not applicable"
    );
    assert!(
        failures.is_empty(),
        "{} vector(s) disagree with tenuo-core:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every id in NOT_APPLICABLE must exist in the suite, so the allowlist
/// cannot silently outlive the vectors it excuses.
#[test]
fn not_applicable_ids_exist_in_suite() {
    let suite = load_suite();
    let ids: Vec<&str> = suite["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    for (id, _) in NOT_APPLICABLE {
        assert!(ids.contains(id), "NOT_APPLICABLE lists unknown vector {id}");
    }
}

/// The lone-warrant exemption is a deliberate profile difference (J.21.1 and
/// J.21.2 are not-applicable above). Pin it so a future tightening of the
/// root-shape check cannot break `authorize_one` silently.
#[test]
fn lone_intermediate_signed_by_anchor_is_accepted() {
    let (cp, orch) = (SigningKey::generate(), SigningKey::generate());
    let mut tools = BTreeMap::new();
    let mut cs = ConstraintSet::new();
    cs.insert("path", Constraint::Wildcard(Wildcard));
    tools.insert("read_file".to_string(), cs);
    let payload = payload::WarrantPayload {
        version: 1,
        warrant_type: warrant::WarrantType::Execution,
        id: warrant::WarrantId::new_random(),
        tools,
        holder: orch.public_key(),
        issuer: cp.public_key(),
        issued_at: 1_704_067_200,
        expires_at: 1_704_070_800,
        max_depth: 3,
        depth: 1,
        parent_hash: Some([0xAA; 32]),
        extensions: BTreeMap::new(),
        issuable_tools: None,
        max_issue_depth: None,
        constraint_bounds: None,
        clearance: None,
        session_id: None,
        agent_id: None,
        required_approvers: None,
        min_approvals: None,
    };
    let mid = sign_payload(&payload, &cp);
    Authorizer::new()
        .with_trusted_root(cp.public_key())
        .verify_chain_as_of(std::slice::from_ref(&mid), 1_704_067_500)
        .expect("a lone anchor-signed intermediate verifies (leaf format)");
}
