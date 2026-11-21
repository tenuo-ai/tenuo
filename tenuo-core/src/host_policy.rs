//! Host policy ceilings for Python enforcement points.
//!
//! A host policy is a per-tool set of argument constraints that an enforcement
//! point applies on top of any warrant it accepts. A call must satisfy both the
//! warrant chain and the host policy. This mirrors the `allow` ceiling of the
//! TypeScript SDK (`verify(..., { allow })`).
//!
//! The policy is committed to in receipt key 11 (`policy_definition_hash`) as
//! `policy_commitment_digest(canonical_policy_bytes(expr))`, where `expr` is the
//! per-field constraint-expression object the TypeScript SDK accepts
//! (`{ field: { kind: ..., ... } }`). Using the same expression shape means the
//! same ceiling produces the same digest from either SDK.
//!
//! Several expression spellings compile to the same constraint (`max(10)` and
//! `range({ max: 10 })`, `email` and `pattern`). Conversion here always emits
//! one spelling per constraint, listed on [`constraint_policy_expr`]. A digest
//! commits to that encoding, not to the semantics behind it.
//!
//! Conversion fails for constraints whose configuration the expression form
//! cannot carry, so two different ceilings never share a commitment.

use crate::constraints::{Constraint, ConstraintSet, ConstraintValue, Subpath, UrlSafe};
use serde_json::{json, Map, Number, Value};
use std::collections::BTreeMap;

/// Largest integer a JavaScript number represents exactly (2^53 - 1).
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// A tool's host ceiling: the constraints to enforce and the receipt commitment.
#[derive(Debug, Clone)]
pub struct HostPolicy {
    constraints: ConstraintSet,
    digest: [u8; 32],
}

impl HostPolicy {
    /// Build a ceiling from per-argument constraints.
    ///
    /// An empty map is an open ceiling that is still committed to: the host
    /// deliberately imposed nothing, which differs from configuring no ceiling.
    /// A non-empty ceiling is closed-world, like a warrant's constraint set:
    /// every argument must be named and every named argument must be present.
    pub fn new(fields: BTreeMap<String, Constraint>) -> Result<Self, String> {
        let mut expr = Map::new();
        for (field, constraint) in &fields {
            let value = constraint_policy_expr(constraint)
                .map_err(|e| format!("host policy field '{field}': {e}"))?;
            expr.insert(field.clone(), value);
        }
        let bytes = crate::receipt::canonical_policy_bytes(&Value::Object(expr))
            .ok_or_else(|| "host policy could not be encoded".to_string())?;
        let digest = crate::receipt::policy_commitment_digest(&bytes);

        let mut constraints = ConstraintSet::new();
        for (field, constraint) in fields {
            constraints.insert(field, constraint);
        }
        Ok(Self {
            constraints,
            digest,
        })
    }

    /// Receipt key 11 for decisions made under this ceiling.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Check arguments against the ceiling.
    pub fn check(
        &self,
        args: &std::collections::HashMap<String, ConstraintValue>,
    ) -> crate::error::Result<()> {
        self.constraints.matches(args)
    }
}

/// Constraint-expression JSON for one constraint.
///
/// Emitted spellings:
/// `wildcard`, `pattern`, `regex`, `exact`, `oneOf`, `notOneOf`,
/// `range` (never `min`/`max`), `cidr`, `urlPattern`, `under` (for Subpath),
/// `urlSafe`, `shlex`, `contains`, `subset`, `anyOf`, `all`, `not`, `cel`.
/// Options equal to their defaults are omitted, as the TypeScript helpers omit
/// options that were not passed.
pub fn constraint_policy_expr(constraint: &Constraint) -> Result<Value, String> {
    Ok(match constraint {
        Constraint::Wildcard(_) => json!({ "kind": "wildcard" }),
        Constraint::Pattern(p) => json!({ "kind": "pattern", "pattern": p.pattern }),
        Constraint::Regex(r) => json!({ "kind": "regex", "source": r.pattern }),
        Constraint::Exact(e) => json!({ "kind": "exact", "value": value_json(&e.value)? }),
        Constraint::OneOf(o) => {
            json!({ "kind": "oneOf", "values": string_list(&o.values, "OneOf")? })
        }
        Constraint::NotOneOf(n) => {
            json!({ "kind": "notOneOf", "values": string_list(&n.excluded, "NotOneOf")? })
        }
        Constraint::Range(r) => {
            let mut out = Map::new();
            out.insert("kind".into(), json!("range"));
            if let Some(min) = r.min {
                out.insert("min".into(), number_json(min)?);
            }
            if let Some(max) = r.max {
                out.insert("max".into(), number_json(max)?);
            }
            if r.min.is_some() && !r.min_inclusive {
                out.insert("minExclusive".into(), json!(true));
            }
            if r.max.is_some() && !r.max_inclusive {
                out.insert("maxExclusive".into(), json!(true));
            }
            if r.min.is_none() && r.max.is_none() {
                return Err("Range has no bounds".into());
            }
            Value::Object(out)
        }
        Constraint::Cidr(c) => json!({ "kind": "cidr", "network": c.cidr_string }),
        Constraint::UrlPattern(u) => json!({ "kind": "urlPattern", "pattern": u.pattern }),
        Constraint::Subpath(s) => subpath_json(s),
        Constraint::UrlSafe(u) => url_safe_json(u)?,
        Constraint::Shlex(s) => json!({ "kind": "shlex", "allow": s.allow }),
        Constraint::Contains(c) => {
            json!({ "kind": "contains", "values": value_list(&c.required)? })
        }
        Constraint::Subset(s) => json!({ "kind": "subset", "values": value_list(&s.allowed)? }),
        Constraint::Any(a) => json!({ "kind": "anyOf", "constraints": expr_list(&a.constraints)? }),
        Constraint::All(a) => json!({ "kind": "all", "constraints": expr_list(&a.constraints)? }),
        Constraint::Not(n) => {
            json!({ "kind": "not", "constraint": constraint_policy_expr(&n.constraint)? })
        }
        Constraint::Cel(c) => {
            if c.parent_expression.is_some() {
                return Err("CEL constraints derived from a parent expression are not supported in a host policy".into());
            }
            json!({ "kind": "cel", "expression": c.expression })
        }
        other => {
            return Err(format!(
                "constraint {other:?} has no host policy expression"
            ))
        }
    })
}

fn subpath_json(s: &Subpath) -> Value {
    let mut out = Map::new();
    out.insert("kind".into(), json!("under"));
    out.insert("root".into(), json!(s.root));
    if !s.case_sensitive {
        out.insert("caseSensitive".into(), json!(false));
    }
    if !s.allow_equal {
        out.insert("allowEqual".into(), json!(false));
    }
    Value::Object(out)
}

fn url_safe_json(u: &UrlSafe) -> Result<Value, String> {
    let defaults = UrlSafe::new();
    if u.allow_ports.is_some()
        || u.block_private != defaults.block_private
        || u.block_loopback != defaults.block_loopback
        || u.block_metadata != defaults.block_metadata
        || u.block_reserved != defaults.block_reserved
        || u.block_internal_tlds != defaults.block_internal_tlds
    {
        return Err(
            "UrlSafe in a host policy supports only schemes, allow_domains and deny_domains".into(),
        );
    }
    let mut out = Map::new();
    out.insert("kind".into(), json!("urlSafe"));
    if u.schemes != defaults.schemes {
        out.insert("schemes".into(), json!(u.schemes));
    }
    if let Some(domains) = &u.allow_domains {
        out.insert("allowDomains".into(), json!(domains));
    }
    if let Some(domains) = &u.deny_domains {
        out.insert("denyDomains".into(), json!(domains));
    }
    Ok(Value::Object(out))
}

fn expr_list(items: &[Constraint]) -> Result<Vec<Value>, String> {
    items.iter().map(constraint_policy_expr).collect()
}

fn string_list(values: &[ConstraintValue], kind: &str) -> Result<Vec<String>, String> {
    values
        .iter()
        .map(|v| match v {
            ConstraintValue::String(s) => Ok(s.clone()),
            _ => Err(format!(
                "{kind} in a host policy accepts only string values"
            )),
        })
        .collect()
}

fn value_list(values: &[ConstraintValue]) -> Result<Vec<Value>, String> {
    values.iter().map(value_json).collect()
}

/// Numbers are written the way a JavaScript caller's would arrive: integral
/// values in the safe-integer range as integers, everything else as floats.
fn number_json(n: f64) -> Result<Value, String> {
    if !n.is_finite() {
        return Err("non-finite numbers have no host policy expression".into());
    }
    if n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER {
        return Ok(Value::Number(Number::from(n as i64)));
    }
    Number::from_f64(n)
        .map(Value::Number)
        .ok_or_else(|| "number has no JSON form".to_string())
}

fn value_json(value: &ConstraintValue) -> Result<Value, String> {
    Ok(match value {
        ConstraintValue::String(s) => Value::String(s.clone()),
        ConstraintValue::Integer(i) => Value::Number(Number::from(*i)),
        ConstraintValue::Float(f) => number_json(*f)?,
        ConstraintValue::Boolean(b) => Value::Bool(*b),
        ConstraintValue::Null => Value::Null,
        ConstraintValue::List(items) => Value::Array(value_list(items)?),
        ConstraintValue::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), value_json(v)?);
            }
            Value::Object(out)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Exact, OneOf, Pattern, Range};
    use std::collections::HashMap;

    fn policy(fields: Vec<(&str, Constraint)>) -> HostPolicy {
        HostPolicy::new(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn range_uses_one_spelling_and_integral_bounds_are_integers() {
        let expr =
            constraint_policy_expr(&Range::new(Some(0.0), Some(10.0)).unwrap().into()).unwrap();
        assert_eq!(expr, json!({ "kind": "range", "min": 0, "max": 10 }));
        let expr =
            constraint_policy_expr(&Range::new(None, Some(2.5)).unwrap().max_exclusive().into())
                .unwrap();
        assert_eq!(
            expr,
            json!({ "kind": "range", "max": 2.5, "maxExclusive": true })
        );
    }

    #[test]
    fn closed_world_like_a_warrant() {
        let p = policy(vec![("queue", OneOf::new(vec!["a", "b"]).into())]);
        let ok: HashMap<_, _> = [("queue".to_string(), ConstraintValue::String("a".into()))].into();
        assert!(p.check(&ok).is_ok());
        let wrong: HashMap<_, _> =
            [("queue".to_string(), ConstraintValue::String("c".into()))].into();
        assert!(p.check(&wrong).is_err());
        let mut extra = ok.clone();
        extra.insert("other".into(), ConstraintValue::Boolean(true));
        assert!(p.check(&extra).is_err());
        assert!(p.check(&HashMap::new()).is_err());
    }

    #[test]
    fn empty_policy_is_open_but_committed() {
        let p = policy(vec![]);
        let any: HashMap<_, _> = [("x".to_string(), ConstraintValue::Integer(1))].into();
        assert!(p.check(&any).is_ok());
        let bytes = crate::receipt::canonical_policy_bytes(&json!({})).unwrap();
        assert_eq!(p.digest(), crate::receipt::policy_commitment_digest(&bytes));
    }

    #[test]
    fn digest_is_independent_of_insertion_order() {
        let a = policy(vec![
            ("path", Pattern::new("/data/*").unwrap().into()),
            ("mode", Exact::new("read").into()),
        ]);
        let b = policy(vec![
            ("mode", Exact::new("read").into()),
            ("path", Pattern::new("/data/*").unwrap().into()),
        ]);
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn unrepresentable_configuration_is_rejected() {
        let mut safe = UrlSafe::new();
        safe.allow_ports = Some(vec![443]);
        assert!(constraint_policy_expr(&safe.into()).is_err());
        let numeric = OneOf {
            values: vec![ConstraintValue::Integer(1), ConstraintValue::Integer(2)],
        };
        assert!(constraint_policy_expr(&numeric.into()).is_err());
    }
}
