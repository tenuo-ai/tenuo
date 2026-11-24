//! AAT constraints: well-formedness (Section 3.4), the check predicate
//! (Section 3.4) and subsumption (Section 4.5).
//!
//! The rules for a single constraint type are the engine's, the ones a CBOR
//! warrant is held to ([`crate::constraints`]): `exact`, `one_of`, `contains`,
//! `subset` and `range` are decoded into engine constraints and matched and
//! attenuated by them. This module adds what the draft fixes beyond that:
//!
//! - well-formedness of the JSON form;
//! - the Section 4.5 table of which type may derive from which, applied at
//!   every level of `all` and `any`, so no pairing the engine accepts beyond
//!   the table is admitted;
//! - `not_one_of`, where the engine is stricter than the draft (it refuses a
//!   value whose kind the list does not mention).
//!
//! `engine_parity` holds the draft's rules written out on their own, and
//! fails if this module stops agreeing with them or if the engine and the
//! draft come to differ anywhere other than the two places named there.

use super::json::{Json, Obj};
use super::{deny, Denied};
use crate::constraints as engine;
use engine::ConstraintValue as Value;
use std::collections::BTreeMap;

/// The reserved constraint-map key for arguments the issuer did not name.
const STAR: &str = "*";

#[derive(Debug, Clone)]
pub(crate) enum Constraint {
    Wildcard,
    All(Vec<Constraint>),
    Any(Vec<Constraint>),
    /// The draft's rule, kept here: any value not in the list is admitted.
    NotOneOf(Vec<Value>),
    /// `exact`, `one_of`, `contains`, `subset` or `range`, under the engine's
    /// rules for that type.
    Engine(engine::Constraint),
}

/// A JSON value as the engine's value type. Every number becomes a float:
/// the draft compares numbers as the doubles JCS writes, and all numbers
/// that reach a comparison are admissible, so nothing is lost.
pub(crate) fn to_value(json: &Json) -> Value {
    match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Boolean(*b),
        Json::Num(n) => Value::Float(n.value()),
        Json::Str(s) => Value::String(s.clone()),
        Json::Arr(items) => Value::List(items.iter().map(to_value).collect()),
        Json::Obj(members) => Value::Object(
            members
                .iter()
                .map(|(name, value)| (name.to_owned(), to_value(value)))
                .collect(),
        ),
    }
}

/// One named argument of a constraint map.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    constraint: Constraint,
    /// The argument may be absent (Section 3.3). Present values are checked.
    optional: bool,
}

/// The constraint map of one tool, normalized (Section 3.3): an empty map
/// admits every argument, the same as a map holding only `"*"`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ConstraintMap {
    named: BTreeMap<String, Entry>,
    /// Arguments the map does not name are admitted.
    star: bool,
}

pub(crate) type Tools = BTreeMap<String, ConstraintMap>;

/// Decode the `tools` object of an `attenuating_agent_token` entry, checking
/// every constraint for well-formedness (steps 3n and 4o).
pub(crate) fn decode_tools(
    tools: &Obj,
    max_depth: usize,
    step: &'static str,
) -> Result<Tools, Denied> {
    let mut out = Tools::new();
    for (tool, map) in tools.iter() {
        // Steps 3m and 4n have already required every value to be an object.
        let map = map
            .as_obj()
            .ok_or_else(|| deny(step, "a tools value is not a constraint-map object"))?;
        let decoded = decode_map(map, max_depth)
            .map_err(|why| deny(step, format!("tool {tool:?}: {why}")))?;
        out.insert(tool.to_owned(), decoded);
    }
    Ok(out)
}

fn decode_map(map: &Obj, max_depth: usize) -> Result<ConstraintMap, String> {
    let mut out = ConstraintMap {
        named: BTreeMap::new(),
        star: map.is_empty(),
    };
    for (key, value) in map.iter() {
        let constraint = decode(value, 1, max_depth).map_err(|why| format!("{key:?}: {why}"))?;
        let object = value.as_obj().ok_or("a constraint is not a JSON object")?;
        let optional = match object.get("optional") {
            None => false,
            Some(flag) => flag.as_bool().ok_or("optional is not a boolean")?,
        };
        if key == STAR {
            if !matches!(constraint, Constraint::Wildcard) {
                return Err("the * entry is not a wildcard constraint".into());
            }
            if object.contains("optional") {
                return Err("the * entry carries optional".into());
            }
            out.star = true;
        } else {
            out.named.insert(
                key.to_owned(),
                Entry {
                    constraint,
                    optional,
                },
            );
        }
    }
    Ok(out)
}

fn decode(value: &Json, depth: usize, max_depth: usize) -> Result<Constraint, String> {
    let object = value.as_obj().ok_or("a constraint is not a JSON object")?;
    if depth > max_depth {
        return Err("constraint tree deeper than MAX_CONSTRAINT_DEPTH".into());
    }
    if depth > 1 && object.contains("optional") {
        return Err("optional appears inside all or any".into());
    }
    let kind = object
        .get("constraint_type")
        .and_then(Json::as_str)
        .ok_or("constraint_type is missing or not a string")?;
    let members: &[&str] = match kind {
        "wildcard" => &[],
        "exact" => &["value"],
        "one_of" => &["values"],
        "not_one_of" => &["excluded"],
        "contains" => &["required"],
        "subset" => &["allowed"],
        "range" => &["min", "max", "min_inclusive", "max_inclusive"],
        "all" | "any" => &["constraints"],
        other => return Err(format!("unrecognized constraint_type {other:?}")),
    };
    if let Some((extra, _)) = object.iter().find(|(name, _)| {
        !matches!(*name, "constraint_type" | "optional") && !members.contains(name)
    }) {
        return Err(format!("{kind} does not define the member {extra:?}"));
    }
    // Checked on the whole constraint, nested clauses included, before any
    // number is compared.
    if value.has_inadmissible_number() {
        return Err("constraint contains a number that is not admissible".into());
    }
    let array = |name: &str| {
        object
            .get(name)
            .and_then(Json::as_arr)
            .map(|items| items.iter().map(to_value).collect::<Vec<_>>())
            .ok_or_else(|| format!("{kind}.{name} is not an array"))
    };
    use engine::Constraint as E;
    Ok(match kind {
        "wildcard" => Constraint::Wildcard,
        "exact" => match object.get("value") {
            Some(v @ (Json::Null | Json::Bool(_) | Json::Num(_) | Json::Str(_))) => {
                Constraint::Engine(E::Exact(engine::Exact { value: to_value(v) }))
            }
            _ => return Err("exact.value is not a string, number, boolean, or null".into()),
        },
        "one_of" => {
            let values = array("values")?;
            if values.is_empty() {
                return Err("one_of.values is empty".into());
            }
            Constraint::Engine(E::OneOf(engine::OneOf { values }))
        }
        "not_one_of" => Constraint::NotOneOf(array("excluded")?),
        "contains" => Constraint::Engine(E::Contains(engine::Contains {
            required: array("required")?,
        })),
        "subset" => Constraint::Engine(E::Subset(engine::Subset {
            allowed: array("allowed")?,
        })),
        "range" => Constraint::Engine(E::Range(decode_range(object)?)),
        _ => {
            let clauses = object
                .get("constraints")
                .and_then(Json::as_arr)
                .ok_or_else(|| format!("{kind}.constraints is not an array"))?;
            if clauses.is_empty() {
                return Err(format!("{kind} with an empty constraints array"));
            }
            let clauses = clauses
                .iter()
                .map(|clause| decode(clause, depth + 1, max_depth))
                .collect::<Result<Vec<_>, _>>()?;
            if kind == "all" {
                Constraint::All(clauses)
            } else {
                Constraint::Any(clauses)
            }
        }
    })
}

fn decode_range(object: &Obj) -> Result<engine::Range, String> {
    let bound = |name: &str| match object.get(name) {
        None => Ok(None),
        Some(Json::Num(n)) => Ok(Some(n.value())),
        Some(_) => Err(format!("range.{name} is not a number")),
    };
    let inclusive = |flag: &str, has_bound: bool| match object.get(flag) {
        None => Ok(true),
        Some(Json::Bool(b)) if has_bound => Ok(*b),
        Some(_) => Err(format!("range.{flag} is not a boolean or has no bound")),
    };
    let (min, max) = (bound("min")?, bound("max")?);
    let range = engine::Range {
        min,
        max,
        min_inclusive: inclusive("min_inclusive", min.is_some())?,
        max_inclusive: inclusive("max_inclusive", max.is_some())?,
    };
    // Admissible numbers order the same way as their doubles.
    if matches!((min, max), (Some(lo), Some(hi)) if lo > hi) {
        return Err("range min is greater than max".into());
    }
    Ok(range)
}

impl Constraint {
    /// The check predicate of Section 3.4.
    pub(crate) fn check(&self, value: &Value) -> bool {
        match self {
            Constraint::Wildcard => true,
            Constraint::All(clauses) => clauses.iter().all(|c| c.check(value)),
            Constraint::Any(clauses) => clauses.iter().any(|c| c.check(value)),
            Constraint::NotOneOf(excluded) => !excluded.contains(value),
            // An engine error is a constraint the engine cannot evaluate.
            Constraint::Engine(constraint) => constraint.matches(value).unwrap_or(false),
        }
    }

    /// True iff `self`, a derived constraint, is subsumed by `parent` under
    /// the Section 4.5 table. A pair the table does not list is invalid.
    pub(crate) fn subsumed_by(&self, parent: &Constraint) -> bool {
        use Constraint::*;
        match (self, parent) {
            (_, Wildcard) => true,
            (Wildcard, _) => false,
            // Every parent clause subsumes at least one derived clause; one
            // derived clause may cover several parent clauses.
            (All(child), All(parent)) => parent
                .iter()
                .all(|p| child.iter().any(|c| c.subsumed_by(p))),
            (Any(child), Any(parent)) => child
                .iter()
                .all(|c| parent.iter().any(|p| c.subsumed_by(p))),
            // The derived list excludes everything the parent's does.
            (NotOneOf(child), NotOneOf(parent)) => parent.iter().all(|x| child.contains(x)),
            (Engine(child), Engine(parent)) => {
                table_lists(child, parent) && parent.validate_attenuation(child).is_ok()
            }
            _ => false,
        }
    }
}

/// The rows of the Section 4.5 table between engine-backed types.
fn table_lists(child: &engine::Constraint, parent: &engine::Constraint) -> bool {
    use engine::Constraint::*;
    matches!(
        (child, parent),
        (Exact(_), Exact(_))
            | (Exact(_), OneOf(_))
            | (Exact(_), Range(_))
            | (OneOf(_), OneOf(_))
            | (Range(_), Range(_))
            | (Contains(_), Contains(_))
            | (Subset(_), Subset(_))
    )
}

/// Step 4p: capability monotonicity (Section 4.5). Each of 4p1 to 4p4 runs
/// over every tool before the next begins, so the step reported is the
/// earliest that fails anywhere in the token.
pub(crate) fn check_attenuation(parent: &Tools, child: &Tools) -> Result<(), Denied> {
    // 4p1: every tool the child names is in the parent.
    let mut pairs = Vec::with_capacity(child.len());
    for (tool, child_map) in child {
        let parent_map = parent
            .get(tool)
            .ok_or_else(|| deny("4p1", format!("tool {tool:?} is not in the parent")))?;
        pairs.push((tool, parent_map, child_map));
    }

    // 4p2: the key rules. "*" names no argument.
    for (tool, parent_map, child_map) in &pairs {
        for key in child_map.named.keys() {
            if !parent_map.named.contains_key(key) && !parent_map.star {
                return Err(deny(
                    "4p2",
                    format!("{tool}: child names {key:?}, which the parent neither names nor admits through *"),
                ));
            }
        }
        for (key, entry) in &parent_map.named {
            if !child_map.named.contains_key(key) {
                if !entry.optional {
                    return Err(deny(
                        "4p2",
                        format!("{tool}: child omits {key:?}, which the parent requires"),
                    ));
                }
                if child_map.star {
                    return Err(deny(
                        "4p2",
                        format!("{tool}: child omits {key:?} but keeps *, which would readmit it"),
                    ));
                }
            }
        }
        if child_map.star && !parent_map.star {
            return Err(deny(
                "4p2",
                format!("{tool}: child contains * but the parent does not"),
            ));
        }
    }

    // 4p3: a required argument stays required.
    for (tool, parent_map, child_map) in &pairs {
        for (key, entry) in &child_map.named {
            if let Some(parent_entry) = parent_map.named.get(key) {
                if !parent_entry.optional && entry.optional {
                    return Err(deny(
                        "4p3",
                        format!("{tool}.{key}: child makes a required argument optional"),
                    ));
                }
            }
        }
    }

    // 4p4: each child constraint attenuates the parent's. A key the parent
    // admits only through "*" is held to the "*" constraint, a wildcard,
    // which subsumes everything; so is the child's own "*".
    for (tool, parent_map, child_map) in &pairs {
        for (key, entry) in &child_map.named {
            if let Some(parent_entry) = parent_map.named.get(key) {
                if !entry.constraint.subsumed_by(&parent_entry.constraint) {
                    return Err(deny(
                        "4p4",
                        format!("{tool}.{key} does not attenuate the parent constraint"),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Step 6b, after the tool lookup: every argument satisfies the leaf's
/// constraint map, and every required argument is present.
pub(crate) fn check_arguments(map: &ConstraintMap, args: &Obj) -> Result<(), Denied> {
    for (name, value) in args.iter() {
        // An argument literally named "*" is an unnamed argument: `named`
        // never holds that key.
        match map.named.get(name) {
            Some(entry) => {
                if !entry.constraint.check(&to_value(value)) {
                    return Err(deny(
                        "6b",
                        format!("argument {name:?} violates its constraint"),
                    ));
                }
            }
            None if map.star => {}
            None => {
                return Err(deny(
                    "6b",
                    format!("argument {name:?} is not in the closed-world map"),
                ))
            }
        }
    }
    let present: std::collections::HashSet<&str> = args.iter().map(|(name, _)| name).collect();
    for (name, entry) in &map.named {
        if !entry.optional && !present.contains(name.as_str()) {
            return Err(deny("6b", format!("required argument {name:?} is absent")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod draft_rules;
#[cfg(test)]
mod engine_parity;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aat::json::parse_unique;

    fn c(text: &str) -> Constraint {
        decode(&parse_unique(text).unwrap(), 1, 32).unwrap()
    }

    fn v(text: &str) -> Value {
        to_value(&parse_unique(text).unwrap())
    }

    fn map(text: &str) -> Result<ConstraintMap, String> {
        decode_map(parse_unique(text).unwrap().as_obj().unwrap(), 32)
    }

    fn ill_formed(text: &str) -> bool {
        decode(&parse_unique(text).unwrap(), 1, 32).is_err()
    }

    #[test]
    fn not_one_of_admits_values_of_any_type() {
        let constraint = c(r#"{"constraint_type":"not_one_of","excluded":["a"]}"#);
        assert!(constraint.check(&v("5")));
        assert!(constraint.check(&v("null")));
        assert!(constraint.check(&v(r#"["a"]"#)));
        assert!(!constraint.check(&v(r#""a""#)));
        // Inside all and any as well, where the engine's own rule would apply
        // if the recursion were left to it.
        let nested = c(
            r#"{"constraint_type":"all","constraints":[{"constraint_type":"not_one_of","excluded":["a"]}]}"#,
        );
        assert!(nested.check(&v("5")));
    }

    #[test]
    fn exact_compares_numbers_by_value() {
        let one = c(r#"{"constraint_type":"exact","value":1}"#);
        assert!(one.check(&v("1.0")));
        assert!(one.check(&v("1e0")));
        assert!(!one.check(&v(r#""1""#)));
        assert!(!one.check(&v("true")));
    }

    #[test]
    fn range_bounds_and_inclusivity() {
        let half_open = c(r#"{"constraint_type":"range","min":0,"max":10,"max_inclusive":false}"#);
        assert!(half_open.check(&v("0")));
        assert!(half_open.check(&v("9.5")));
        assert!(!half_open.check(&v("10")));
        assert!(!half_open.check(&v(r#""5""#)));

        let closed = c(r#"{"constraint_type":"range","min":0,"max":10}"#);
        assert!(half_open.subsumed_by(&closed));
        assert!(!closed.subsumed_by(&half_open));
        let unbounded = c(r#"{"constraint_type":"range","min":0}"#);
        assert!(!unbounded.subsumed_by(&closed));
        assert!(closed.subsumed_by(&unbounded));
    }

    #[test]
    fn pairs_outside_the_table_do_not_attenuate() {
        let one_of = c(r#"{"constraint_type":"one_of","values":["a"]}"#);
        let exact = c(r#"{"constraint_type":"exact","value":"a"}"#);
        let any = c(
            r#"{"constraint_type":"any","constraints":[{"constraint_type":"exact","value":"a"}]}"#,
        );
        assert!(exact.subsumed_by(&one_of));
        assert!(!one_of.subsumed_by(&exact));
        assert!(!exact.subsumed_by(&any));
        assert!(!Constraint::Wildcard.subsumed_by(&exact));
        assert!(exact.subsumed_by(&Constraint::Wildcard));

        // The engine accepts an exact value under an `all` it satisfies. The
        // table has no such row, at the top or inside another `all`.
        let five = c(r#"{"constraint_type":"exact","value":5}"#);
        let all =
            c(r#"{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0}]}"#);
        assert!(!five.subsumed_by(&all));
        let wrap = |inner: &str| {
            c(&format!(
                r#"{{"constraint_type":"all","constraints":[{inner}]}}"#
            ))
        };
        let nested_child = wrap(r#"{"constraint_type":"exact","value":5}"#);
        let nested_parent = wrap(
            r#"{"constraint_type":"all","constraints":[{"constraint_type":"range","min":0}]}"#,
        );
        assert!(!nested_child.subsumed_by(&nested_parent));
    }

    #[test]
    fn ill_formed_constraints() {
        for text in [
            r#"{"constraint_type":"regex","pattern":"a"}"#,
            r#"{"constraint_type":"exact"}"#,
            r#"{"constraint_type":"exact","value":[1]}"#,
            r#"{"constraint_type":"exact","value":1,"values":[1]}"#,
            r#"{"constraint_type":"one_of","values":[]}"#,
            r#"{"constraint_type":"all","constraints":[]}"#,
            r#"{"constraint_type":"range","min":2,"max":1}"#,
            r#"{"constraint_type":"range","min_inclusive":true}"#,
            r#"{"constraint_type":"range","min":"1"}"#,
            r#"{"constraint_type":"range","max":9007199254740993}"#,
            r#"{"constraint_type":"any","constraints":[{"constraint_type":"wildcard","optional":true}]}"#,
            r#"{"constraint_type":"wildcard","extra":1}"#,
            r#"[]"#,
        ] {
            assert!(ill_formed(text), "{text}");
        }
    }

    #[test]
    fn depth_limit_counts_nested_constraints() {
        let nest = |levels: usize| {
            let mut text = r#"{"constraint_type":"wildcard"}"#.to_owned();
            for _ in 1..levels {
                text = format!(r#"{{"constraint_type":"all","constraints":[{text}]}}"#);
            }
            text
        };
        assert!(!ill_formed(&nest(32)));
        assert!(ill_formed(&nest(33)));
    }

    /// With faults in several tools, the step reported is the earliest in
    /// the algorithm's order, whichever tool sorts first.
    #[test]
    fn the_earliest_failing_step_is_reported_across_tools() {
        let tools = |text: &str| -> Tools {
            decode_tools(parse_unique(text).unwrap().as_obj().unwrap(), 32, "4o").unwrap()
        };
        let step = |parent: &str, child: &str| {
            check_attenuation(&tools(parent), &tools(child))
                .unwrap_err()
                .step
        };
        let one = r#"{"x":{"constraint_type":"exact","value":1}}"#;
        let two = r#"{"x":{"constraint_type":"exact","value":2}}"#;
        let optional = r#"{"x":{"constraint_type":"exact","value":1,"optional":true}}"#;
        let extra =
            r#"{"x":{"constraint_type":"exact","value":1},"y":{"constraint_type":"wildcard"}}"#;

        // Tool a widens a constraint (4p4); tool z is not in the parent (4p1).
        assert_eq!(
            step(
                &format!(r#"{{"a":{one}}}"#),
                &format!(r#"{{"a":{two},"z":{{}}}}"#)
            ),
            "4p1"
        );
        let parent = format!(r#"{{"a":{one},"z":{one}}}"#);
        // Tool a fails 4p4; tool z names a key the parent does not (4p2).
        assert_eq!(
            step(&parent, &format!(r#"{{"a":{two},"z":{extra}}}"#)),
            "4p2"
        );
        // Tool a fails 4p4; tool z makes a required argument optional (4p3).
        assert_eq!(
            step(&parent, &format!(r#"{{"a":{two},"z":{optional}}}"#)),
            "4p3"
        );
        assert_eq!(step(&parent, &format!(r#"{{"a":{two},"z":{one}}}"#)), "4p4");
        assert!(check_attenuation(&tools(&parent), &tools(&format!(r#"{{"a":{one}}}"#))).is_ok());
    }

    #[test]
    fn empty_map_is_the_star_map() {
        let empty = map("{}").unwrap();
        assert!(empty.star && empty.named.is_empty());
        let star = map(r#"{"*":{"constraint_type":"wildcard"}}"#).unwrap();
        assert!(star.star && star.named.is_empty());
        for text in [
            r#"{"*":{"constraint_type":"exact","value":1}}"#,
            r#"{"*":{"constraint_type":"wildcard","optional":false}}"#,
            r#"{"a":{"constraint_type":"wildcard","optional":1}}"#,
        ] {
            assert!(map(text).is_err(), "{text}");
        }
    }
}
