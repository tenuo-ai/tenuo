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

/// True if `map` admits arguments it does not name (Section 3.3): it holds
/// `"*"`, or it is empty, which normalizes to the map holding only `"*"`.
fn has_star(map: &Json) -> bool {
    map.as_obj()
        .is_some_and(|m| m.is_empty() || m.contains("*"))
}

/// The entries of `map` other than `"*"`.
fn named(map: &Json) -> impl Iterator<Item = (&str, &Json)> {
    map.as_obj()
        .into_iter()
        .flat_map(|m| m.iter())
        .filter(|(key, _)| *key != "*")
}

fn entry<'a>(map: &'a Json, key: &str) -> Option<&'a Json> {
    named(map).find(|(k, _)| *k == key).map(|(_, c)| c)
}

/// An argument is required unless its entry carries `"optional": true`.
fn required(constraint: &Json) -> bool {
    field(constraint, "optional").and_then(Json::as_bool) != Some(true)
}

/// Step 6b for one tool: `args` satisfy the constraint map.
pub(super) fn map_admits(map: &Json, args: &Json) -> bool {
    let Some(args) = args.as_obj() else {
        return false;
    };
    args.iter().all(|(name, value)| match entry(map, name) {
        Some(constraint) => check(constraint, value),
        None => has_star(map),
    }) && named(map).all(|(key, constraint)| !required(constraint) || args.contains(key))
}

/// Steps 4p2 to 4p4 for one tool: the key rules of Section 4.5, then
/// subsumption of each argument named in both maps.
pub(super) fn map_subsumes(child: &Json, parent: &Json) -> bool {
    // 4p2: a key the child names is named by the parent, or the parent has "*".
    let names_only_known =
        named(child).all(|(key, _)| entry(parent, key).is_some() || has_star(parent));
    // 4p2: a key the parent names and the child omits is optional in the
    // parent, and the child then has no "*".
    let omits_only_optional = named(parent).all(|(key, constraint)| {
        entry(child, key).is_some() || (!required(constraint) && !has_star(child))
    });
    // 4p2: the child has "*" only if the parent does.
    let star_kept_narrow = !has_star(child) || has_star(parent);
    // 4p3 and 4p4, for each key named in both.
    let each_narrows = named(child).all(|(key, c)| match entry(parent, key) {
        Some(p) => (required(c) || !required(p)) && subsumes(c, p),
        None => true,
    });
    names_only_known && omits_only_optional && star_kept_narrow && each_narrows
}
