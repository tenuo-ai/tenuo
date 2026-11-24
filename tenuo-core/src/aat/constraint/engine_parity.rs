//! Keeps three sets of constraint rules from drifting apart: the draft's
//! (`draft_rules`), the codec's (`super`), and the engine's
//! (`crate::constraints`).
//!
//! - The codec must agree with the draft on every case.
//! - The engine may differ from the draft only in the ways [`NAMED`] lists.
//!   A new difference fails here, and so does a listed one that has gone
//!   away, which is the cue to delete the codec's handling of it.

use super::{decode, draft_rules, to_value};
use crate::aat::json::{parse_unique, Json};
use crate::constraints as engine;
use std::collections::BTreeSet;

/// Every way the engine's rules differ from the draft's.
const NAMED: &[&str] = &[
    // The engine refuses a value whose kind the excluded list does not
    // mention (`not_one_of ["a"]` refuses 5). The draft admits any value not
    // in the list. The codec keeps the draft's rule.
    "check not_one_of: draft admits, engine refuses",
    // For the same reason the engine refuses a derived list that excludes a
    // kind of value the parent's does not.
    "derive not_one_of under not_one_of: draft allows, engine refuses",
    // The engine accepts an exact value under an `all` it satisfies. The
    // draft's table has no such row. The codec applies the table.
    "derive exact under all: engine allows, draft refuses",
];

/// The engine's constraint for the JSON form, with none of the codec's rules
/// in between: `not_one_of`, `all` and `any` are the engine's own.
pub(super) fn raw_engine(constraint: &Json) -> engine::Constraint {
    use engine::Constraint as E;
    let object = constraint.as_obj().expect("constraint object");
    let values = |name: &str| -> Vec<engine::ConstraintValue> {
        object
            .get(name)
            .and_then(Json::as_arr)
            .expect(name)
            .iter()
            .map(to_value)
            .collect()
    };
    let bound = |name: &str| object.get(name).and_then(Json::as_num).map(|n| n.value());
    let inclusive = |name: &str| object.get(name).and_then(Json::as_bool) != Some(false);
    let clauses = || -> Vec<engine::Constraint> {
        object
            .get("constraints")
            .and_then(Json::as_arr)
            .expect("constraints")
            .iter()
            .map(raw_engine)
            .collect()
    };
    match draft_rules::kind(constraint) {
        "wildcard" => E::Wildcard(engine::Wildcard),
        "exact" => E::Exact(engine::Exact {
            value: to_value(object.get("value").expect("value")),
        }),
        "one_of" => E::OneOf(engine::OneOf {
            values: values("values"),
        }),
        "not_one_of" => E::NotOneOf(engine::NotOneOf {
            excluded: values("excluded"),
        }),
        "contains" => E::Contains(engine::Contains {
            required: values("required"),
        }),
        "subset" => E::Subset(engine::Subset {
            allowed: values("allowed"),
        }),
        "range" => E::Range(engine::Range {
            min: bound("min"),
            max: bound("max"),
            min_inclusive: inclusive("min_inclusive"),
            max_inclusive: inclusive("max_inclusive"),
        }),
        "all" => E::All(engine::All {
            constraints: clauses(),
        }),
        "any" => E::Any(engine::Any {
            constraints: clauses(),
        }),
        other => panic!("constraint_type {other:?}"),
    }
}

/// All lists of at most two of `items`, as JSON array text.
fn lists(items: &[&str]) -> Vec<String> {
    let mut out = vec!["[]".to_owned()];
    for (i, a) in items.iter().enumerate() {
        out.push(format!("[{a}]"));
        for b in &items[i + 1..] {
            out.push(format!("[{a},{b}]"));
        }
    }
    out
}

/// Constraints of every type over strings, numbers, booleans, null and
/// arrays, with `all` and `any` one level deep over engine-backed types.
fn pool() -> Vec<String> {
    let mut pool = vec![r#"{"constraint_type":"wildcard"}"#.to_owned()];
    for value in [r#""a""#, r#""b""#, "5", "5.5", "0", "true", "null"] {
        pool.push(format!(r#"{{"constraint_type":"exact","value":{value}}}"#));
    }
    let sets = lists(&[r#""a""#, r#""b""#, "5", "null", "true", r#"["a"]"#]);
    for set in &sets {
        if set != "[]" {
            pool.push(format!(r#"{{"constraint_type":"one_of","values":{set}}}"#));
        }
        pool.push(format!(
            r#"{{"constraint_type":"not_one_of","excluded":{set}}}"#
        ));
        pool.push(format!(
            r#"{{"constraint_type":"contains","required":{set}}}"#
        ));
        pool.push(format!(r#"{{"constraint_type":"subset","allowed":{set}}}"#));
    }
    let mut ranges = Vec::new();
    for min in [None, Some(0), Some(5)] {
        for max in [None, Some(5), Some(10)] {
            let flags = |bound: Option<i32>| {
                if bound.is_some() {
                    vec![true, false]
                } else {
                    vec![true]
                }
            };
            for min_inclusive in flags(min) {
                for max_inclusive in flags(max) {
                    let mut text = r#"{"constraint_type":"range""#.to_owned();
                    if let Some(min) = min {
                        text += &format!(r#","min":{min}"#);
                    }
                    if let Some(max) = max {
                        text += &format!(r#","max":{max}"#);
                    }
                    if !min_inclusive {
                        text += r#","min_inclusive":false"#;
                    }
                    if !max_inclusive {
                        text += r#","max_inclusive":false"#;
                    }
                    ranges.push(text + "}");
                }
            }
        }
    }
    pool.extend(ranges);

    let clauses = [
        r#"{"constraint_type":"range","min":0}"#,
        r#"{"constraint_type":"range","max":10}"#,
        r#"{"constraint_type":"range","min":0,"max":10}"#,
        r#"{"constraint_type":"exact","value":5}"#,
        r#"{"constraint_type":"exact","value":"a"}"#,
        r#"{"constraint_type":"one_of","values":["a","b"]}"#,
        r#"{"constraint_type":"subset","allowed":["a","b"]}"#,
        r#"{"constraint_type":"contains","required":["a"]}"#,
        r#"{"constraint_type":"wildcard"}"#,
    ];
    for kind in ["all", "any"] {
        for (i, a) in clauses.iter().enumerate() {
            pool.push(format!(
                r#"{{"constraint_type":"{kind}","constraints":[{a}]}}"#
            ));
            for b in &clauses[i + 1..] {
                pool.push(format!(
                    r#"{{"constraint_type":"{kind}","constraints":[{a},{b}]}}"#
                ));
            }
        }
    }
    pool
}

/// Where the codec's own recursion matters: `not_one_of` and composites
/// inside composites. Only the codec is held to these; for the engine they
/// would repeat the named differences under other type names.
const NESTED: &[&str] = &[
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"not_one_of","excluded":["a"]},{"constraint_type":"range","min":0}]}"#,
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"not_one_of","excluded":["a","b"]}]}"#,
    r#"{"constraint_type":"any","constraints":[{"constraint_type":"not_one_of","excluded":["a",5]},{"constraint_type":"exact","value":"a"}]}"#,
    r#"{"constraint_type":"any","constraints":[{"constraint_type":"not_one_of","excluded":["a"]}]}"#,
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0}]}]}"#,
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":5}]}"#,
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"all","constraints":[{"constraint_type":"exact","value":5}]}]}"#,
    r#"{"constraint_type":"any","constraints":[{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0},{"constraint_type":"range","max":10}]},{"constraint_type":"exact","value":"a"}]}"#,
    r#"{"constraint_type":"any","constraints":[{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"a"}]},{"constraint_type":"one_of","values":["a","b"]}]}"#,
    r#"{"constraint_type":"all","constraints":[{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":5},{"constraint_type":"not_one_of","excluded":[5]}]},{"constraint_type":"range","max":10}]}"#,
];

const VALUES: &[&str] = &[
    r#""a""#,
    r#""b""#,
    r#""c""#,
    r#""""#,
    "5",
    "5.0",
    "5.5",
    "0",
    "10",
    "-1",
    "1e1",
    "true",
    "false",
    "null",
    "[]",
    r#"["a"]"#,
    r#"["a","b"]"#,
    r#"["b","a"]"#,
    r#"["a","c"]"#,
    r#"["a","a"]"#,
    "[5]",
    "[null]",
    r#"[["a"]]"#,
    r#"{"k":1}"#,
    "{}",
];

fn parse_all<S: AsRef<str>>(texts: &[S]) -> Vec<Json> {
    texts
        .iter()
        .map(|text| parse_unique(text.as_ref()).expect("JSON"))
        .collect()
}

/// A disagreement between the engine and the draft, by rule and direction.
fn difference(what: &str, draft: bool) -> String {
    let direction = match (what.starts_with("check"), draft) {
        (true, true) => "draft admits, engine refuses",
        (true, false) => "engine admits, draft refuses",
        (false, true) => "draft allows, engine refuses",
        (false, false) => "engine allows, draft refuses",
    };
    format!("{what}: {direction}")
}

/// Every difference between the engine and the draft over these cases.
fn engine_differences(constraints: &[Json], values: &[Json]) -> BTreeSet<String> {
    let engines: Vec<engine::Constraint> = constraints.iter().map(raw_engine).collect();
    let mut found = BTreeSet::new();
    for (constraint, engine) in constraints.iter().zip(&engines) {
        for value in values {
            let draft = draft_rules::check(constraint, value);
            if draft != engine.matches(&to_value(value)).unwrap_or(false) {
                let what = format!("check {}", draft_rules::kind(constraint));
                found.insert(difference(&what, draft));
            }
        }
    }
    for (child, child_engine) in constraints.iter().zip(&engines) {
        for (parent, parent_engine) in constraints.iter().zip(&engines) {
            let draft = draft_rules::subsumes(child, parent);
            if draft != parent_engine.validate_attenuation(child_engine).is_ok() {
                let what = format!(
                    "derive {} under {}",
                    draft_rules::kind(child),
                    draft_rules::kind(parent)
                );
                found.insert(difference(&what, draft));
            }
        }
    }
    found
}

/// Cases where the codec does not give the draft's answer.
fn codec_mismatches(constraints: &[Json], values: &[Json]) -> Vec<String> {
    let codecs: Vec<super::Constraint> = constraints
        .iter()
        .map(|c| decode(c, 1, 32).expect("well-formed"))
        .collect();
    let mut wrong = Vec::new();
    for (constraint, codec) in constraints.iter().zip(&codecs) {
        for value in values {
            let draft = draft_rules::check(constraint, value);
            if codec.check(&to_value(value)) != draft {
                wrong.push(format!(
                    "check {constraint:?} on {value:?}: draft says {draft}"
                ));
            }
        }
    }
    for (child, child_codec) in constraints.iter().zip(&codecs) {
        for (parent, parent_codec) in constraints.iter().zip(&codecs) {
            let draft = draft_rules::subsumes(child, parent);
            if child_codec.subsumed_by(parent_codec) != draft {
                wrong.push(format!(
                    "derive {child:?} under {parent:?}: draft says {draft}"
                ));
            }
        }
    }
    wrong
}

#[test]
fn the_codec_agrees_with_the_draft() {
    let mut texts = pool();
    texts.extend(NESTED.iter().map(|s| (*s).to_owned()));
    let constraints = parse_all(&texts);
    assert!(constraints.len() > 150, "pool of {}", constraints.len());
    let wrong = codec_mismatches(&constraints, &parse_all(VALUES));
    assert!(
        wrong.is_empty(),
        "{} cases, first: {}",
        wrong.len(),
        wrong[0]
    );
}

#[test]
fn the_engine_differs_from_the_draft_only_where_named() {
    let found = engine_differences(&parse_all(&pool()), &parse_all(VALUES));
    let named: BTreeSet<String> = NAMED.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        found, named,
        "left: differences found; right: differences NAMED lists"
    );
}

/// The constraints the vector suite itself carries: every derivation between
/// adjacent tokens and every argument check at a leaf.
#[test]
fn the_suite_constraints_agree_too() {
    let suite: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/aat-jws-vectors.json"
    ))
    .expect("vector file");
    let named: BTreeSet<&str> = NAMED.iter().copied().collect();
    let (mut checks, mut derivations) = (0, 0);

    for vector in suite["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().expect("id");
        let tools: Vec<Option<Json>> = vector["chain"]
            .as_array()
            .expect("chain")
            .iter()
            .map(|token| tools_of(token["payload_json"].as_str()?))
            .collect();
        // A constraint that is well-formed, or nothing.
        let constraint = |tools: &Json, tool: &str, key: &str| -> Option<Json> {
            let constraint = tools.as_obj()?.get(tool)?.as_obj()?.get(key)?;
            decode(constraint, 1, 32).ok().map(|_| constraint.clone())
        };

        for pair in tools.windows(2) {
            let (Some(parent), Some(child)) = (&pair[0], &pair[1]) else {
                continue;
            };
            for (tool, map) in child.as_obj().into_iter().flat_map(|tools| tools.iter()) {
                for (key, _) in map.as_obj().into_iter().flat_map(|map| map.iter()) {
                    let (Some(c), Some(p)) =
                        (constraint(child, tool, key), constraint(parent, tool, key))
                    else {
                        continue;
                    };
                    derivations += 1;
                    let both = [p, c];
                    assert!(codec_mismatches(&both, &[]).is_empty(), "{id} {tool}.{key}");
                    let found = engine_differences(&both, &[]);
                    assert!(
                        found.iter().all(|d| named.contains(d.as_str())),
                        "{id} {tool}.{key}: {found:?}"
                    );
                }
            }
        }

        let (Some(Some(leaf)), Some(args)) = (
            tools.last(),
            vector["args_json"].as_str().and_then(parse_unique),
        ) else {
            continue;
        };
        let tool = vector["tool"].as_str().expect("tool");
        for (name, value) in args.as_obj().into_iter().flat_map(|args| args.iter()) {
            let Some(c) = constraint(leaf, tool, name) else {
                continue;
            };
            // Step 6b refuses such an argument before any constraint sees it.
            if value.has_inadmissible_number() {
                continue;
            }
            checks += 1;
            let (one, value) = ([c], [value.clone()]);
            assert!(codec_mismatches(&one, &value).is_empty(), "{id} {name}");
            let found = engine_differences(&one, &value);
            assert!(
                found.iter().all(|d| named.contains(d.as_str())),
                "{id} {name}: {found:?}"
            );
        }
    }
    assert!(
        checks > 300 && derivations > 400,
        "{checks} checks, {derivations} derivations"
    );
}

/// The `tools` object of a token's `attenuating_agent_token` entry.
pub(super) fn tools_of(payload_json: &str) -> Option<Json> {
    let claims = parse_unique(payload_json)?;
    let entry = claims
        .as_obj()?
        .get("authorization_details")?
        .as_arr()?
        .iter()
        .find(|entry| draft_type(entry) == Some("attenuating_agent_token"))?;
    entry.as_obj()?.get("tools").cloned()
}

fn draft_type(entry: &Json) -> Option<&str> {
    entry.as_obj()?.get("type")?.as_str()
}
