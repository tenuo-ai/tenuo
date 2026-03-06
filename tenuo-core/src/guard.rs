//! Guard types for conditional approval requirements.
//!
//! Guards mark specific tools or argument ranges within a warrant's capability
//! set as requiring a signed approval before execution. Unguarded tools
//! execute with Proof-of-Possession only.
//!
//! ## Extension Key
//!
//! Guards are stored in `extensions["tenuo.guards"]` as CBOR-encoded bytes.
//! They are covered by the warrant's Ed25519 signature — tampering invalidates
//! the warrant.
//!
//! ## Evaluation
//!
//! Guard evaluation is a second pass after constraint checking succeeds:
//!
//! ```text
//! 1. tool in warrant.tools?           → no: DENIED
//! 2. constraints satisfied?            → no: DENIED
//! 3. guard triggered?                  → yes: APPROVAL REQUIRED
//! 4. otherwise                         → ALLOWED (PoP only)
//! ```

use crate::constraints::{Constraint, ConstraintValue};
use crate::error::{Error, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Extension key for guard data in the warrant payload.
pub const GUARD_EXTENSION_KEY: &str = "tenuo.guards";

/// Top-level guard map: tool name → guard specification.
///
/// Only tools present in the map are subject to guard evaluation.
/// Tools absent from the map are "free" (PoP only), assuming the
/// warrant also has a guard map. If no guard map exists and
/// `required_approvers` is set, all tools require approval.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardMap(pub BTreeMap<String, ToolGuard>);

impl GuardMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, tool: String, guard: ToolGuard) {
        self.0.insert(tool, guard);
    }

    pub fn get(&self, tool: &str) -> Option<&ToolGuard> {
        self.0.get(tool)
    }

    pub fn contains_tool(&self, tool: &str) -> bool {
        self.0.contains_key(tool)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &ToolGuard)> {
        self.0.iter()
    }

    pub fn tools(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }
}

impl Default for GuardMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard specification for a single tool.
///
/// - `args: None` — entire tool is guarded (all invocations require approval)
/// - `args: Some(map)` — only invocations where a guarded argument matches
#[derive(Debug, Clone, PartialEq)]
pub struct ToolGuard {
    pub args: Option<BTreeMap<String, ArgGuard>>,
}

impl ToolGuard {
    /// Create a whole-tool guard (all invocations require approval).
    pub fn whole_tool() -> Self {
        Self { args: None }
    }

    /// Create a per-argument guard.
    pub fn with_args(args: BTreeMap<String, ArgGuard>) -> Self {
        Self { args: Some(args) }
    }

    /// Returns true if this is a whole-tool guard.
    pub fn is_whole_tool(&self) -> bool {
        self.args.is_none()
    }
}

/// Guard specification for a single argument.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgGuard {
    /// All values of this argument trigger the guard.
    All,

    /// Only values satisfying this constraint trigger the guard.
    Constraint(Constraint),
}

// ---------------------------------------------------------------------------
// CBOR Serialization
// ---------------------------------------------------------------------------

impl Serialize for GuardMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GuardMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = BTreeMap::<String, ToolGuard>::deserialize(deserializer)?;
        Ok(GuardMap(map))
    }
}

impl Serialize for ToolGuard {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match &self.args {
            None => map.serialize_entry("args", &Option::<()>::None)?,
            Some(args) => map.serialize_entry("args", args)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ToolGuard {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ToolGuardVisitor;

        impl<'de> Visitor<'de> for ToolGuardVisitor {
            type Value = ToolGuard;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with an 'args' key")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<ToolGuard, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut args: Option<Option<BTreeMap<String, ArgGuard>>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "args" {
                        if args.is_some() {
                            return Err(de::Error::duplicate_field("args"));
                        }
                        // Deserialize Option<Map> — null means whole-tool guard
                        args = Some(map.next_value()?);
                    } else {
                        let _: de::IgnoredAny = map.next_value()?;
                    }
                }

                let args = args.ok_or_else(|| de::Error::missing_field("args"))?;
                Ok(ToolGuard { args })
            }
        }

        deserializer.deserialize_map(ToolGuardVisitor)
    }
}

impl Serialize for ArgGuard {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ArgGuard::All => serializer.serialize_str("all"),
            ArgGuard::Constraint(c) => c.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArgGuard {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArgGuardVisitor;

        impl<'de> Visitor<'de> for ArgGuardVisitor {
            type Value = ArgGuard;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("\"all\" or a [type_id, value] constraint")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<ArgGuard, E>
            where
                E: de::Error,
            {
                if v == "all" {
                    Ok(ArgGuard::All)
                } else {
                    Err(de::Error::unknown_variant(v, &["all"]))
                }
            }

            fn visit_seq<A>(self, seq: A) -> std::result::Result<ArgGuard, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let constraint =
                    Constraint::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(ArgGuard::Constraint(constraint))
            }
        }

        deserializer.deserialize_any(ArgGuardVisitor)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a guard map from raw extension bytes.
///
/// Returns `None` if the bytes are absent or empty.
/// Returns `Err` if the bytes are present but malformed.
pub fn parse_guard_map(raw: Option<&Vec<u8>>) -> Result<Option<GuardMap>> {
    let raw = match raw {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => return Ok(None),
    };

    let guard_map: GuardMap = ciborium::from_reader(raw.as_slice())
        .map_err(|e| Error::DeserializationError(format!("failed to decode guard map: {}", e)))?;

    Ok(Some(guard_map))
}

/// Encode a guard map to CBOR bytes for storage in extensions.
pub fn encode_guard_map(guard_map: &GuardMap) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(guard_map, &mut buf)
        .map_err(|e| Error::SerializationError(format!("failed to encode guard map: {}", e)))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether a tool invocation requires approval based on guards.
///
/// **Precondition**: `tool` is in `warrant.tools` and constraints are satisfied.
///
/// Returns `Ok(true)` if approval is required, `Ok(false)` if the
/// invocation is free (PoP only). Returns `Ok(false)` when no guard map
/// is present — all approval requirements must be expressed in the guard map.
pub fn evaluate_guards(
    guard_map: Option<&GuardMap>,
    tool: &str,
    args: &HashMap<String, ConstraintValue>,
) -> Result<bool> {
    let guard_map = match guard_map {
        Some(gm) => gm,
        None => return Ok(false),
    };

    // Tool not in guard map → no approval needed
    let tool_guard = match guard_map.get(tool) {
        Some(tg) => tg,
        None => return Ok(false),
    };

    // Entire tool guarded
    if tool_guard.is_whole_tool() {
        return Ok(true);
    }

    // Per-argument guards
    if let Some(arg_guards) = &tool_guard.args {
        for (arg_name, arg_guard) in arg_guards {
            let arg_value = match args.get(arg_name) {
                Some(v) => v,
                // SECURITY: absent guarded argument fires the guard (fail-safe).
                // A per-arg guard expresses "calls touching this argument need approval."
                // If the argument is absent the tool's behaviour for that parameter is
                // unknown, so we require approval rather than silently bypassing the gate.
                None => return Ok(true),
            };

            match arg_guard {
                ArgGuard::All => return Ok(true),
                ArgGuard::Constraint(constraint) => {
                    if constraint.matches(arg_value)? {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}

// ---------------------------------------------------------------------------
// Guard Propagation (for delegation / attenuation)
// ---------------------------------------------------------------------------

/// Propagate guards from parent to child, scoped to the child's tool set.
///
/// Guards for tools the child doesn't have are dropped (the tool is gone,
/// the guard is irrelevant). Guards for tools the child does have are
/// preserved exactly.
pub fn propagate_guards(
    parent_guards: &GuardMap,
    child_tools: &BTreeMap<String, crate::constraints::ConstraintSet>,
) -> Option<GuardMap> {
    let mut child_guards = GuardMap::new();

    for (tool, guard) in parent_guards.iter() {
        if child_tools.contains_key(tool) {
            child_guards.insert(tool.clone(), guard.clone());
        }
    }

    if child_guards.is_empty() {
        None
    } else {
        Some(child_guards)
    }
}

// ---------------------------------------------------------------------------
// Guard Merging (for attenuation / issuance)
// ---------------------------------------------------------------------------

/// Merge two guard maps, taking the union (more-restrictive wins for conflicts).
///
/// Used when a child explicitly adds guards during attenuation or issuance.
/// Parent guards are always preserved; additional guards are unioned in.
pub fn merge_guard_maps(base: &GuardMap, additional: &GuardMap) -> GuardMap {
    let mut merged = base.0.clone();
    for (tool, additional_guard) in additional.0.iter() {
        merged
            .entry(tool.clone())
            .and_modify(|existing| {
                *existing = take_stricter_guard(existing, additional_guard);
            })
            .or_insert_with(|| additional_guard.clone());
    }
    GuardMap(merged)
}

/// `a` is the existing/base guard (typically the parent's), `b` is the additional guard.
///
/// For same-argument conflicts in per-arg maps, `a` wins. This is intentional:
/// the base guard is the parent's established gate; the additional guard cannot
/// loosen it. Swapping the argument order would silently flip this security property.
fn take_stricter_guard(a: &ToolGuard, b: &ToolGuard) -> ToolGuard {
    match (&a.args, &b.args) {
        // Either is whole-tool → whole-tool wins (strictest possible)
        (None, _) | (_, None) => ToolGuard::whole_tool(),
        // Both per-arg → union of argument keys (more args guarded = stricter).
        // Same-argument conflicts: `a`'s guard wins (base takes precedence).
        (Some(args_a), Some(args_b)) => {
            let mut merged_args = args_a.clone();
            for (arg, guard) in args_b {
                merged_args.entry(arg.clone()).or_insert_with(|| guard.clone());
            }
            ToolGuard::with_args(merged_args)
        }
    }
}

// ---------------------------------------------------------------------------
// Guard Monotonicity Verification (Defense in Depth)
// ---------------------------------------------------------------------------

/// Errors specific to guard monotonicity violations.
#[derive(Debug, Clone, PartialEq)]
pub enum GuardError {
    /// Parent had guards but child stripped them entirely.
    GuardsStripped,
    /// A specific tool's guard was removed in the child.
    ToolGuardRemoved(String),
    /// A whole-tool guard was weakened to per-argument guards.
    ToolGuardWeakened(String),
    /// A per-argument guard was removed in the child.
    ArgGuardRemoved(String, String),
    /// A per-argument guard constraint was weakened.
    ArgGuardWeakened,
    /// A per-argument guard constraint changed (Phase 1: exact equality required).
    ArgGuardConstraintChanged,
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuardsStripped => write!(f, "child stripped all guards from parent"),
            Self::ToolGuardRemoved(tool) => write!(f, "guard removed for tool '{}'", tool),
            Self::ToolGuardWeakened(tool) => {
                write!(f, "whole-tool guard weakened to per-arg for '{}'", tool)
            }
            Self::ArgGuardRemoved(tool, arg) => {
                write!(f, "arg guard '{}' removed for tool '{}'", arg, tool)
            }
            Self::ArgGuardWeakened => write!(f, "arg guard weakened from All to Constraint"),
            Self::ArgGuardConstraintChanged => {
                write!(
                    f,
                    "arg guard constraint changed (Phase 1: exact equality required)"
                )
            }
        }
    }
}

impl std::error::Error for GuardError {}

/// Verify that child guards are monotonically narrower than parent guards.
///
/// This is **optional defense-in-depth** for Phase 1. The structured
/// delegation API is the primary enforcement mechanism.
///
/// Returns `Ok(())` if the child guards are valid, `Err(GuardError)` if
/// they violate monotonicity.
pub(crate) fn verify_guard_monotonicity(
    parent_guards: Option<&GuardMap>,
    child_guards: Option<&GuardMap>,
    child_tools: &BTreeMap<String, crate::constraints::ConstraintSet>,
) -> std::result::Result<(), GuardError> {
    let parent_guards = match parent_guards {
        None => return Ok(()), // Parent has no guards — child is unconstrained
        Some(g) => g,
    };

    let child_guards = match child_guards {
        None => return Err(GuardError::GuardsStripped),
        Some(g) => g,
    };

    for (tool, parent_guard) in parent_guards.iter() {
        // Only check tools the child has
        if !child_tools.contains_key(tool) {
            continue;
        }

        let child_guard = child_guards
            .get(tool)
            .ok_or_else(|| GuardError::ToolGuardRemoved(tool.clone()))?;

        match (&parent_guard.args, &child_guard.args) {
            // Both whole-tool → equal, valid
            (None, None) => {}

            // Parent whole-tool, child per-arg → weakening (cannot prove equivalence
            // without tool argument schema)
            (None, Some(_)) => {
                return Err(GuardError::ToolGuardWeakened(tool.clone()));
            }

            // Parent per-arg, child whole-tool → strictly stricter, valid
            (Some(_), None) => {}

            // Both per-arg → each parent arg guard must exist and be ≤ in child
            (Some(parent_args), Some(child_args)) => {
                for (arg, parent_arg_guard) in parent_args {
                    let child_arg_guard = child_args
                        .get(arg)
                        .ok_or_else(|| GuardError::ArgGuardRemoved(tool.clone(), arg.clone()))?;

                    validate_arg_guard_monotonic(child_arg_guard, parent_arg_guard)?;
                }
            }
        }
    }

    Ok(())
}

/// Validate that a child arg guard is monotonically at least as strict as the parent.
///
/// "At least as strict" means the child guards a superset of values: child ≥ parent.
/// Phase 1: constraint-based guards require exact equality.
fn validate_arg_guard_monotonic(
    child: &ArgGuard,
    parent: &ArgGuard,
) -> std::result::Result<(), GuardError> {
    match (child, parent) {
        (ArgGuard::All, ArgGuard::All) => Ok(()),

        // Child All, parent Constraint → child guards more values (stricter)
        (ArgGuard::All, ArgGuard::Constraint(_)) => Ok(()),

        // Child Constraint, parent All → child guards fewer values (weaker)
        (ArgGuard::Constraint(_), ArgGuard::All) => Err(GuardError::ArgGuardWeakened),

        // Phase 1: exact equality only
        (ArgGuard::Constraint(c_child), ArgGuard::Constraint(c_parent)) => {
            if c_child == c_parent {
                Ok(())
            } else {
                Err(GuardError::ArgGuardConstraintChanged)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Pattern, Subpath};

    fn make_args(pairs: &[(&str, &str)]) -> HashMap<String, ConstraintValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), ConstraintValue::String(v.to_string())))
            .collect()
    }

    // -- Serialization round-trip --

    #[test]
    fn test_guard_map_roundtrip_whole_tool() {
        let mut gm = GuardMap::new();
        gm.insert("email.delete".into(), ToolGuard::whole_tool());
        gm.insert("exec".into(), ToolGuard::whole_tool());

        let encoded = encode_guard_map(&gm).unwrap();
        let decoded = parse_guard_map(Some(&encoded)).unwrap().unwrap();
        assert_eq!(gm, decoded);
    }

    #[test]
    fn test_guard_map_roundtrip_per_arg() {
        let mut args = BTreeMap::new();
        args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        args.insert("mode".into(), ArgGuard::All);

        let mut gm = GuardMap::new();
        gm.insert("file.write".into(), ToolGuard::with_args(args));

        let encoded = encode_guard_map(&gm).unwrap();
        let decoded = parse_guard_map(Some(&encoded)).unwrap().unwrap();
        assert_eq!(gm, decoded);
    }

    #[test]
    fn test_parse_guard_map_absent() {
        assert!(parse_guard_map(None).unwrap().is_none());
    }

    #[test]
    fn test_parse_guard_map_empty_bytes() {
        assert!(parse_guard_map(Some(&vec![])).unwrap().is_none());
    }

    // -- evaluate_guards: no guard map --

    #[test]
    fn test_no_guard_map_allows() {
        assert!(!evaluate_guards(None, "any_tool", &HashMap::new()).unwrap());
    }

    // -- evaluate_guards: with guard map --

    #[test]
    fn test_tool_not_in_guard_map_allows() {
        let gm = GuardMap::new();
        assert!(!evaluate_guards(Some(&gm), "email.read", &HashMap::new()).unwrap());
    }

    #[test]
    fn test_whole_tool_guard_triggers() {
        let mut gm = GuardMap::new();
        gm.insert("email.delete".into(), ToolGuard::whole_tool());

        assert!(evaluate_guards(Some(&gm), "email.delete", &HashMap::new()).unwrap());
    }

    #[test]
    fn test_per_arg_all_triggers() {
        let mut args_guards = BTreeMap::new();
        args_guards.insert("command".into(), ArgGuard::All);
        let mut gm = GuardMap::new();
        gm.insert("exec".into(), ToolGuard::with_args(args_guards));

        let args = make_args(&[("command", "rm -rf /")]);
        assert!(evaluate_guards(Some(&gm), "exec", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_matches_triggers() {
        let mut args_guards = BTreeMap::new();
        args_guards.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = GuardMap::new();
        gm.insert("file.write".into(), ToolGuard::with_args(args_guards));

        let args = make_args(&[("path", "/etc/hosts")]);
        assert!(evaluate_guards(Some(&gm), "file.write", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_no_match_allows() {
        let mut args_guards = BTreeMap::new();
        args_guards.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = GuardMap::new();
        gm.insert("file.write".into(), ToolGuard::with_args(args_guards));

        let args = make_args(&[("path", "/workspace/foo.txt")]);
        assert!(!evaluate_guards(Some(&gm), "file.write", &args).unwrap());
    }

    #[test]
    fn test_per_arg_absent_argument_fires_guard() {
        // SECURITY: absent guarded argument → guard fires (fail-safe).
        // A call that omits the guarded argument has unknown behaviour for
        // that parameter, so we require approval rather than bypassing the gate.
        let mut args_guards = BTreeMap::new();
        args_guards.insert("path".into(), ArgGuard::All);
        let mut gm = GuardMap::new();
        gm.insert("file.write".into(), ToolGuard::with_args(args_guards));

        // Call with no "path" argument — guard must fire
        let args = make_args(&[("other", "value")]);
        assert!(evaluate_guards(Some(&gm), "file.write", &args).unwrap());

        // Confirm the guard does NOT fire for a completely different tool
        assert!(!evaluate_guards(Some(&gm), "file.read", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_absent_argument_fires_guard() {
        // Same fail-safe semantics apply when the guard is a constraint, not ArgGuard::All.
        let mut args_guards = BTreeMap::new();
        args_guards.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = GuardMap::new();
        gm.insert("file.write".into(), ToolGuard::with_args(args_guards));

        // No "path" supplied → guard fires even though the constraint can't match
        let args = make_args(&[("content", "hello")]);
        assert!(evaluate_guards(Some(&gm), "file.write", &args).unwrap());
    }

    // -- Guard propagation --

    #[test]
    fn test_propagate_guards_scopes_to_child_tools() {
        let mut parent_guards = GuardMap::new();
        parent_guards.insert("email.delete".into(), ToolGuard::whole_tool());
        parent_guards.insert("exec".into(), ToolGuard::whole_tool());
        parent_guards.insert("file.write".into(), ToolGuard::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "email.delete".into(),
            crate::constraints::ConstraintSet::new(),
        );
        // child doesn't have "exec" or "file.write"

        let result = propagate_guards(&parent_guards, &child_tools).unwrap();
        assert!(result.contains_tool("email.delete"));
        assert!(!result.contains_tool("exec"));
        assert!(!result.contains_tool("file.write"));
    }

    #[test]
    fn test_propagate_guards_returns_none_when_no_overlap() {
        let mut parent_guards = GuardMap::new();
        parent_guards.insert("exec".into(), ToolGuard::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "email.read".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert!(propagate_guards(&parent_guards, &child_tools).is_none());
    }

    // -- Guard monotonicity --

    #[test]
    fn test_monotonicity_no_parent_guards_always_ok() {
        let child_tools = BTreeMap::new();
        assert!(verify_guard_monotonicity(None, None, &child_tools).is_ok());
        let gm = GuardMap::new();
        assert!(verify_guard_monotonicity(None, Some(&gm), &child_tools).is_ok());
    }

    #[test]
    fn test_monotonicity_parent_guards_child_stripped_fails() {
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_guard_monotonicity(Some(&parent), None, &child_tools),
            Err(GuardError::GuardsStripped)
        );
    }

    #[test]
    fn test_monotonicity_tool_guard_removed_fails() {
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::whole_tool());
        parent.insert("email.delete".into(), ToolGuard::whole_tool());

        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::whole_tool());
        // "email.delete" guard missing

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());
        child_tools.insert(
            "email.delete".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert_eq!(
            verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(GuardError::ToolGuardRemoved("email.delete".into()))
        );
    }

    #[test]
    fn test_monotonicity_whole_to_per_arg_weakening_fails() {
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::whole_tool());

        let mut args = BTreeMap::new();
        args.insert("command".into(), ArgGuard::All);
        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::with_args(args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(GuardError::ToolGuardWeakened("exec".into()))
        );
    }

    #[test]
    fn test_monotonicity_per_arg_to_whole_strengthening_ok() {
        let mut args = BTreeMap::new();
        args.insert("command".into(), ArgGuard::All);
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::with_args(args));

        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert!(verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok());
    }

    #[test]
    fn test_monotonicity_arg_guard_all_to_constraint_weakening_fails() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert("command".into(), ArgGuard::All);
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "command".into(),
            ArgGuard::Constraint(Pattern::new("rm*").unwrap().into()),
        );
        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(GuardError::ArgGuardWeakened)
        );
    }

    #[test]
    fn test_monotonicity_constraint_to_all_strengthening_ok() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "command".into(),
            ArgGuard::Constraint(Pattern::new("rm*").unwrap().into()),
        );
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert("command".into(), ArgGuard::All);
        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert!(verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok());
    }

    #[test]
    fn test_monotonicity_constraint_changed_fails() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut parent = GuardMap::new();
        parent.insert("file.write".into(), ToolGuard::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/var").unwrap().into()),
        );
        let mut child = GuardMap::new();
        child.insert("file.write".into(), ToolGuard::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "file.write".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert_eq!(
            verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(GuardError::ArgGuardConstraintChanged)
        );
    }

    #[test]
    fn test_monotonicity_constraint_equal_ok() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut parent = GuardMap::new();
        parent.insert("file.write".into(), ToolGuard::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut child = GuardMap::new();
        child.insert("file.write".into(), ToolGuard::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "file.write".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert!(verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok());
    }

    #[test]
    fn test_monotonicity_skips_tools_child_doesnt_have() {
        let mut parent = GuardMap::new();
        parent.insert("exec".into(), ToolGuard::whole_tool());
        parent.insert("email.delete".into(), ToolGuard::whole_tool());

        let mut child = GuardMap::new();
        child.insert("exec".into(), ToolGuard::whole_tool());
        // No "email.delete" guard, but child doesn't have "email.delete" tool either

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());
        // No "email.delete" in child tools

        assert!(verify_guard_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok());
    }

    #[test]
    fn test_mixed_guard_map() {
        let mut gm = GuardMap::new();
        gm.insert("email.delete".into(), ToolGuard::whole_tool());
        gm.insert("email.send".into(), ToolGuard::whole_tool());

        let mut file_args = BTreeMap::new();
        file_args.insert(
            "path".into(),
            ArgGuard::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        gm.insert("file.write".into(), ToolGuard::with_args(file_args));

        // email.read is NOT guarded → should be free
        let args = make_args(&[("folder", "inbox")]);
        assert!(!evaluate_guards(Some(&gm), "email.read", &args).unwrap());

        // email.delete is whole-tool guarded
        assert!(evaluate_guards(Some(&gm), "email.delete", &HashMap::new()).unwrap());

        // file.write to /workspace → free
        let args = make_args(&[("path", "/workspace/foo.txt")]);
        assert!(!evaluate_guards(Some(&gm), "file.write", &args).unwrap());

        // file.write to /etc → requires approval
        let args = make_args(&[("path", "/etc/nginx/nginx.conf")]);
        assert!(evaluate_guards(Some(&gm), "file.write", &args).unwrap());
    }
}
