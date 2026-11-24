//! Sections 3.4 and 4.5 of the draft, written out directly over the JSON form
//! of a constraint. Nothing here calls the engine or the codec.
//!
//! Test-only. This is the standard `engine_parity` holds the codec and the
//! engine to; it follows the reference verifier that generates the vector
//! suite (`ietf/vectors/gen_vectors.py`, `check` and `subsumes`). Constraints
//! are assumed well-formed.

use crate::aat::json::Json;

pub(super) fn kind(constraint: &Json) -> &str {
    field(constraint, "constraint_type")
        .and_then(Json::as_str)
        .unwrap_or("")
}

fn field<'a>(constraint: &'a Json, name: &str) -> Option<&'a Json> {
    constraint.as_obj()?.get(name)
}

fn list<'a>(constraint: &'a Json, name: &str) -> &'a [Json] {
    field(constraint, name)
        .and_then(Json::as_arr)
        .unwrap_or(&[])
}

fn bound(constraint: &Json, name: &str) -> Option<f64> {
    field(constraint, name)?.as_num().map(|n| n.value())
}

/// An inclusivity flag is true unless written as false.
fn inclusive(constraint: &Json, name: &str) -> bool {
    field(constraint, name).and_then(Json::as_bool) != Some(false)
}

/// Value equality is identical JCS serializations.
fn among(value: &Json, set: &[Json]) -> bool {
    set.iter().any(|x| value.jcs_eq(x))
}

fn in_range(range: &Json, v: f64) -> bool {
    let above = bound(range, "min")
        .is_none_or(|min| v > min || (v == min && inclusive(range, "min_inclusive")));
    let below = bound(range, "max")
        .is_none_or(|max| v < max || (v == max && inclusive(range, "max_inclusive")));
    above && below
}

/// The check predicate of Section 3.4.
pub(super) fn check(constraint: &Json, value: &Json) -> bool {
    match kind(constraint) {
        "wildcard" => true,
        "exact" => field(constraint, "value").is_some_and(|x| value.jcs_eq(x)),
        "one_of" => among(value, list(constraint, "values")),
        "not_one_of" => !among(value, list(constraint, "excluded")),
        "contains" => value
            .as_arr()
            .is_some_and(|items| list(constraint, "required").iter().all(|r| among(r, items))),
        "subset" => value
            .as_arr()
            .is_some_and(|items| items.iter().all(|x| among(x, list(constraint, "allowed")))),
        "range" => value
            .as_num()
            .is_some_and(|n| in_range(constraint, n.value())),
        "all" => list(constraint, "constraints")
            .iter()
            .all(|clause| check(clause, value)),
        "any" => list(constraint, "constraints")
            .iter()
            .any(|clause| check(clause, value)),
        _ => false,
    }
}

/// Each bound of the parent is matched by a derived bound at least as tight.
fn range_within(child: &Json, parent: &Json) -> bool {
    let side = |name: &str, flag: &str, looser: fn(f64, f64) -> bool| match (
        bound(parent, name),
        bound(child, name),
    ) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(p), Some(c)) => {
            // An exclusive parent bound cannot become inclusive at the same value.
            let reopened = c == p && !inclusive(parent, flag) && inclusive(child, flag);
            !looser(c, p) && !reopened
        }
    };
    side("min", "min_inclusive", |c, p| c < p) && side("max", "max_inclusive", |c, p| c > p)
}

/// True iff `child` is subsumed by `parent` under the Section 4.5 table.
/// Every pair the table does not list is invalid.
pub(super) fn subsumes(child: &Json, parent: &Json) -> bool {
    let all_in = |name: &str, inner: &Json, outer: &Json| {
        list(inner, name)
            .iter()
            .all(|x| among(x, list(outer, name)))
    };
    match (kind(child), kind(parent)) {
        (_, "wildcard") => true,
        ("wildcard", _) => false,
        ("all", "all") => list(parent, "constraints")
            .iter()
            .all(|p| list(child, "constraints").iter().any(|c| subsumes(c, p))),
        ("any", "any") => list(child, "constraints")
            .iter()
            .all(|c| list(parent, "constraints").iter().any(|p| subsumes(c, p))),
        ("exact", "exact") => field(child, "value")
            .is_some_and(|c| field(parent, "value").is_some_and(|p| c.jcs_eq(p))),
        ("exact", "one_of") => {
            field(child, "value").is_some_and(|c| among(c, list(parent, "values")))
        }
        ("exact", "range") => field(child, "value")
            .and_then(Json::as_num)
            .is_some_and(|n| in_range(parent, n.value())),
        ("one_of", "one_of") => all_in("values", child, parent),
        ("range", "range") => range_within(child, parent),
        ("not_one_of", "not_one_of") => all_in("excluded", parent, child),
        ("contains", "contains") => all_in("required", parent, child),
        ("subset", "subset") => all_in("allowed", child, parent),
        _ => false,
    }
}
