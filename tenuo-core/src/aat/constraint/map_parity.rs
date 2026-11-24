//! The rules for a tool's whole argument map, held together the way
//! `engine_parity` holds the rules for one constraint: the draft's
//! (`draft_rules`), the codec's (`super`), and the engine's
//! (`crate::constraints::ConstraintSet`).
//!
//! - The codec must agree with the draft on every case.
//! - The engine may differ from the draft only in the ways [`NAMED`] lists.

use super::engine_parity::{raw_engine, tools_of};
use super::{check_arguments, check_attenuation, decode_map, draft_rules, to_value, Tools};
use crate::aat::json::{parse_unique, Json};
use crate::constraints as engine;
use std::collections::{BTreeSet, HashMap};

/// Every way the engine's argument-map rules differ from the draft's.
const NAMED: &[&str] = &[];

/// One entry of a map: left out, or a constraint that is required or optional.
const ENTRIES: &[&str] = &[
    "",
    r#"{"constraint_type":"one_of","values":["x","y"]}"#,
    r#"{"constraint_type":"one_of","values":["x","y"],"optional":true}"#,
    r#"{"constraint_type":"exact","value":"x"}"#,
    r#"{"constraint_type":"exact","value":"x","optional":true}"#,
    r#"{"constraint_type":"wildcard"}"#,
    r#"{"constraint_type":"wildcard","optional":true}"#,
];

/// Every map over arguments `a` and `b` from [`ENTRIES`], with and without `"*"`.
fn maps() -> Vec<Json> {
    let mut out = Vec::new();
    for a in ENTRIES {
        for b in ENTRIES {
            for star in [false, true] {
                let mut members = Vec::new();
                if !a.is_empty() {
                    members.push(format!(r#""a":{a}"#));
                }
                if !b.is_empty() {
                    members.push(format!(r#""b":{b}"#));
                }
                if star {
                    members.push(r#""*":{"constraint_type":"wildcard"}"#.to_owned());
                }
                out.push(parse_unique(&format!("{{{}}}", members.join(","))).expect("JSON"));
            }
        }
    }
    out
}

/// Invocations over `a`, `b` and an argument `c` that no map names.
fn invocations() -> Vec<Json> {
    let mut out = Vec::new();
    for a in ["", r#""a":"x""#, r#""a":"y""#, r#""a":"z""#] {
        for b in ["", r#""b":"x""#, r#""b":"z""#] {
            for c in ["", r#""c":"q""#] {
                let members: Vec<&str> = [a, b, c].into_iter().filter(|m| !m.is_empty()).collect();
                out.push(parse_unique(&format!("{{{}}}", members.join(","))).expect("JSON"));
            }
        }
    }
    out
}

/// The engine's set for a map, with none of the codec's rules in between.
/// `"*"` is `allow_unknown`; an empty map is an empty set.
fn engine_set(map: &Json) -> engine::ConstraintSet {
    let mut set = engine::ConstraintSet::new();
    for (key, constraint) in map.as_obj().expect("map").iter() {
        if key == "*" {
            set.set_allow_unknown(true);
        } else if constraint
            .as_obj()
            .and_then(|c| c.get("optional"))
            .and_then(Json::as_bool)
            == Some(true)
        {
            set.insert_optional(key, raw_engine(constraint));
        } else {
            set.insert(key, raw_engine(constraint));
        }
    }
    set
}

fn engine_args(args: &Json) -> HashMap<String, engine::ConstraintValue> {
    args.as_obj()
        .expect("args")
        .iter()
        .map(|(name, value)| (name.to_owned(), to_value(value)))
        .collect()
}

fn codec_tools(map: &Json) -> Tools {
    let mut tools = Tools::new();
    tools.insert(
        "tool".to_owned(),
        decode_map(map.as_obj().expect("map"), 32).expect("well-formed"),
    );
    tools
}

/// Cases where the codec does not give the draft's answer.
fn codec_mismatches(maps: &[Json], invocations: &[Json]) -> Vec<String> {
    let mut wrong = Vec::new();
    for map in maps {
        let codec = codec_tools(map);
        for args in invocations {
            let draft = draft_rules::map_admits(map, args);
            if check_arguments(&codec["tool"], args.as_obj().expect("args")).is_ok() != draft {
                wrong.push(format!("check {map:?} on {args:?}: draft says {draft}"));
            }
        }
        for parent in maps {
            let draft = draft_rules::map_subsumes(map, parent);
            if check_attenuation(&codec_tools(parent), &codec).is_ok() != draft {
                wrong.push(format!(
                    "derive {map:?} under {parent:?}: draft says {draft}"
                ));
            }
        }
    }
    wrong
}

/// Every difference between the engine and the draft over these cases, by
/// what the derived map does and which side allows it.
fn engine_differences(maps: &[Json], invocations: &[Json]) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for map in maps {
        let set = engine_set(map);
        for args in invocations {
            let draft = draft_rules::map_admits(map, args);
            if set.matches(&engine_args(args)).is_ok() != draft {
                found.insert(format!(
                    "check a map: {}",
                    if draft {
                        "draft admits, engine refuses"
                    } else {
                        "engine admits, draft refuses"
                    }
                ));
            }
        }
        for parent in maps {
            let draft = draft_rules::map_subsumes(map, parent);
            if engine_set(parent).validate_attenuation(&set).is_ok() != draft {
                let names = |m: &Json| -> BTreeSet<String> {
                    m.as_obj()
                        .expect("map")
                        .iter()
                        .filter(|(k, _)| *k != "*")
                        .map(|(k, _)| k.to_owned())
                        .collect()
                };
                let (child, parent) = (names(map), names(parent));
                let what = match (child.is_subset(&parent), parent.is_subset(&child)) {
                    (true, true) => "derive a map with the same arguments",
                    (false, true) => "derive a map that names a new argument",
                    (true, false) => "derive a map that leaves an argument out",
                    (false, false) => "derive a map that names one argument and leaves out another",
                };
                found.insert(format!(
                    "{what}: {}",
                    if draft {
                        "draft allows, engine refuses"
                    } else {
                        "engine allows, draft refuses"
                    }
                ));
            }
        }
    }
    found
}

#[test]
fn the_codec_agrees_with_the_draft_on_argument_maps() {
    let wrong = codec_mismatches(&maps(), &invocations());
    assert!(
        wrong.is_empty(),
        "{} mismatches, first: {}",
        wrong.len(),
        wrong[0]
    );
}

#[test]
fn the_engine_differs_from_the_draft_on_argument_maps_only_where_named() {
    let (maps, invocations) = (maps(), invocations());
    // Enough cases that an empty list means agreement, not an empty pool.
    assert!(maps.len() * maps.len() > 9_000 && maps.len() * invocations.len() > 2_000);
    let found = engine_differences(&maps, &invocations);
    let named: BTreeSet<String> = NAMED.iter().map(|d| d.to_string()).collect();
    assert_eq!(found, named);
}

/// The maps the vector suite itself carries: every derivation between
/// adjacent tokens and the argument check at each leaf.
#[test]
fn the_codec_agrees_with_the_draft_on_the_suite_maps() {
    let suite: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/aat-jws-vectors.json"
    ))
    .expect("vector file");
    let well_formed = |map: &Json| map.as_obj().is_some_and(|m| decode_map(m, 32).is_ok());
    let (mut checks, mut derivations) = (0, 0);

    for vector in suite["vectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().expect("id");
        let tools: Vec<Option<Json>> = vector["chain"]
            .as_array()
            .expect("chain")
            .iter()
            .map(|token| tools_of(token["payload_json"].as_str()?))
            .collect();

        for pair in tools.windows(2) {
            let (Some(parent), Some(child)) = (&pair[0], &pair[1]) else {
                continue;
            };
            for (tool, map) in child.as_obj().into_iter().flat_map(|tools| tools.iter()) {
                let Some(parent_map) = parent.as_obj().and_then(|tools| tools.get(tool)) else {
                    continue;
                };
                if !well_formed(map) || !well_formed(parent_map) {
                    continue;
                }
                derivations += 1;
                assert_eq!(
                    check_attenuation(&codec_tools(parent_map), &codec_tools(map)).is_ok(),
                    draft_rules::map_subsumes(map, parent_map),
                    "{id} {tool}"
                );
            }
        }

        let (Some(Some(leaf)), Some(args)) = (
            tools.last(),
            vector["args_json"].as_str().and_then(parse_unique),
        ) else {
            continue;
        };
        let tool = vector["tool"].as_str().expect("tool");
        let Some(map) = leaf.as_obj().and_then(|tools| tools.get(tool)) else {
            continue;
        };
        // Step 6b refuses such arguments before any map sees them.
        if !well_formed(map) || args.as_obj().is_none() || args.has_inadmissible_number() {
            continue;
        }
        checks += 1;
        assert_eq!(
            check_arguments(&codec_tools(map)["tool"], args.as_obj().expect("args")).is_ok(),
            draft_rules::map_admits(map, &args),
            "{id}"
        );
    }
    assert!(
        checks > 150 && derivations > 250,
        "{checks} checks, {derivations} derivations"
    );
}
