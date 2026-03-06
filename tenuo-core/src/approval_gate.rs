//! Approval gate types for conditional approval requirements.
//!
//! Approval gates mark specific tools or argument ranges within a warrant's
//! capability set as requiring a signed approval before execution. Ungated
//! tools execute with Proof-of-Possession only.
//!
//! ## Extension Key
//!
//! Approval gates are stored in `extensions["tenuo.approval_gates"]` as
//! CBOR-encoded bytes. They are covered by the warrant's Ed25519 signature —
//! tampering invalidates the warrant.
//!
//! ## Evaluation
//!
//! Approval gate evaluation is a second pass after constraint checking succeeds:
//!
//! ```text
//! 1. tool in warrant.tools?           → no: DENIED
//! 2. constraints satisfied?            → no: DENIED
//! 3. approval gate triggered?          → yes: APPROVAL REQUIRED
//! 4. otherwise                         → ALLOWED (PoP only)
//! ```

use crate::constraints::{Constraint, ConstraintValue};
use crate::error::{Error, Result};
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Extension key for approval gate data in the warrant payload.
pub const APPROVAL_GATE_EXTENSION_KEY: &str = "tenuo.approval_gates";

/// Top-level approval gate map: tool name → gate specification.
///
/// Only tools present in the map are subject to approval gate evaluation.
/// Tools absent from the map are "free" (PoP only), assuming the
/// warrant also has an approval gate map. If no gate map exists and
/// `required_approvers` is set, all tools require approval.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalGateMap(pub BTreeMap<String, ToolApprovalGate>);

impl ApprovalGateMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, tool: String, gate: ToolApprovalGate) {
        self.0.insert(tool, gate);
    }

    pub fn get(&self, tool: &str) -> Option<&ToolApprovalGate> {
        self.0.get(tool)
    }

    pub fn contains_tool(&self, tool: &str) -> bool {
        self.0.contains_key(tool)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &ToolApprovalGate)> {
        self.0.iter()
    }

    pub fn tools(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }
}

impl Default for ApprovalGateMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Approval gate specification for a single tool.
///
/// - `args: None` — entire tool is gated (all invocations require approval)
/// - `args: Some(map)` — only invocations where a gated argument matches
#[derive(Debug, Clone, PartialEq)]
pub struct ToolApprovalGate {
    pub args: Option<BTreeMap<String, ArgApprovalGate>>,
}

impl ToolApprovalGate {
    /// Create a whole-tool gate (all invocations require approval).
    pub fn whole_tool() -> Self {
        Self { args: None }
    }

    /// Create a per-argument gate.
    pub fn with_args(args: BTreeMap<String, ArgApprovalGate>) -> Self {
        Self { args: Some(args) }
    }

    /// Returns true if this is a whole-tool gate.
    pub fn is_whole_tool(&self) -> bool {
        self.args.is_none()
    }
}

/// Approval gate specification for a single argument.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgApprovalGate {
    /// All values of this argument trigger the gate.
    All,

    /// Only values satisfying this constraint trigger the gate.
    Constraint(Constraint),
}

// ---------------------------------------------------------------------------
// CBOR Serialization
// ---------------------------------------------------------------------------

impl Serialize for ApprovalGateMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApprovalGateMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = BTreeMap::<String, ToolApprovalGate>::deserialize(deserializer)?;
        Ok(ApprovalGateMap(map))
    }
}

impl Serialize for ToolApprovalGate {
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

impl<'de> Deserialize<'de> for ToolApprovalGate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ToolApprovalGateVisitor;

        impl<'de> Visitor<'de> for ToolApprovalGateVisitor {
            type Value = ToolApprovalGate;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with an 'args' key")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<ToolApprovalGate, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut args: Option<Option<BTreeMap<String, ArgApprovalGate>>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "args" {
                        if args.is_some() {
                            return Err(de::Error::duplicate_field("args"));
                        }
                        // Deserialize Option<Map> — null means whole-tool gate
                        args = Some(map.next_value()?);
                    } else {
                        let _: de::IgnoredAny = map.next_value()?;
                    }
                }

                let args = args.ok_or_else(|| de::Error::missing_field("args"))?;
                Ok(ToolApprovalGate { args })
            }
        }

        deserializer.deserialize_map(ToolApprovalGateVisitor)
    }
}

impl Serialize for ArgApprovalGate {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ArgApprovalGate::All => serializer.serialize_str("all"),
            ArgApprovalGate::Constraint(c) => c.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArgApprovalGate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArgApprovalGateVisitor;

        impl<'de> Visitor<'de> for ArgApprovalGateVisitor {
            type Value = ArgApprovalGate;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("\"all\" or a [type_id, value] constraint")
            }

            fn visit_str<E>(self, v: &str) -> std::result::Result<ArgApprovalGate, E>
            where
                E: de::Error,
            {
                if v == "all" {
                    Ok(ArgApprovalGate::All)
                } else {
                    Err(de::Error::unknown_variant(v, &["all"]))
                }
            }

            fn visit_seq<A>(self, seq: A) -> std::result::Result<ArgApprovalGate, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let constraint =
                    Constraint::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(ArgApprovalGate::Constraint(constraint))
            }
        }

        deserializer.deserialize_any(ArgApprovalGateVisitor)
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an approval gate map from raw extension bytes.
///
/// Returns `None` if the bytes are absent or empty.
/// Returns `Err` if the bytes are present but malformed.
pub fn parse_approval_gate_map(raw: Option<&Vec<u8>>) -> Result<Option<ApprovalGateMap>> {
    let raw = match raw {
        Some(bytes) if !bytes.is_empty() => bytes,
        _ => return Ok(None),
    };

    let approval_gate_map: ApprovalGateMap =
        ciborium::from_reader(raw.as_slice()).map_err(|e| {
            Error::DeserializationError(format!("failed to decode approval gate map: {}", e))
        })?;

    Ok(Some(approval_gate_map))
}

/// Encode an approval gate map to CBOR bytes for storage in extensions.
pub fn encode_approval_gate_map(approval_gate_map: &ApprovalGateMap) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(approval_gate_map, &mut buf).map_err(|e| {
        Error::SerializationError(format!("failed to encode approval gate map: {}", e))
    })?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether a tool invocation requires approval based on approval gates.
///
/// **Precondition**: `tool` is in `warrant.tools` and constraints are satisfied.
///
/// Returns `Ok(true)` if approval is required, `Ok(false)` if the
/// invocation is free (PoP only). Returns `Ok(false)` when no gate map
/// is present — all approval requirements must be expressed in the gate map.
pub fn evaluate_approval_gates(
    approval_gate_map: Option<&ApprovalGateMap>,
    tool: &str,
    args: &HashMap<String, ConstraintValue>,
) -> Result<bool> {
    let approval_gate_map = match approval_gate_map {
        Some(gm) => gm,
        None => return Ok(false),
    };

    // Tool not in gate map → no approval needed
    let tool_gate = match approval_gate_map.get(tool) {
        Some(tg) => tg,
        None => return Ok(false),
    };

    // Entire tool gated
    if tool_gate.is_whole_tool() {
        return Ok(true);
    }

    // Per-argument gates
    if let Some(arg_gates) = &tool_gate.args {
        for (arg_name, arg_gate) in arg_gates {
            let arg_value = match args.get(arg_name) {
                Some(v) => v,
                // SECURITY: absent gated argument fires the gate (fail-safe).
                // A per-arg gate expresses "calls touching this argument need approval."
                // If the argument is absent the tool's behaviour for that parameter is
                // unknown, so we require approval rather than silently bypassing the gate.
                None => return Ok(true),
            };

            match arg_gate {
                ArgApprovalGate::All => return Ok(true),
                ArgApprovalGate::Constraint(constraint) => {
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
// Approval Gate Propagation (for delegation / attenuation)
// ---------------------------------------------------------------------------

/// Propagate approval gates from parent to child, scoped to the child's tool set.
///
/// Gates for tools the child doesn't have are dropped (the tool is gone,
/// the gate is irrelevant). Gates for tools the child does have are
/// preserved exactly.
pub fn propagate_approval_gates(
    parent_gates: &ApprovalGateMap,
    child_tools: &BTreeMap<String, crate::constraints::ConstraintSet>,
) -> Option<ApprovalGateMap> {
    let mut child_gates = ApprovalGateMap::new();

    for (tool, gate) in parent_gates.iter() {
        if child_tools.contains_key(tool) {
            child_gates.insert(tool.clone(), gate.clone());
        }
    }

    if child_gates.is_empty() {
        None
    } else {
        Some(child_gates)
    }
}

// ---------------------------------------------------------------------------
// Approval Gate Merging (for attenuation / issuance)
// ---------------------------------------------------------------------------

/// Merge two approval gate maps, taking the union (more-restrictive wins for conflicts).
///
/// Used when a child explicitly adds gates during attenuation or issuance.
/// Parent gates are always preserved; additional gates are unioned in.
pub fn merge_approval_gate_maps(
    base: &ApprovalGateMap,
    additional: &ApprovalGateMap,
) -> ApprovalGateMap {
    let mut merged = base.0.clone();
    for (tool, additional_gate) in additional.0.iter() {
        merged
            .entry(tool.clone())
            .and_modify(|existing| {
                *existing = take_stricter_approval_gate(existing, additional_gate);
            })
            .or_insert_with(|| additional_gate.clone());
    }
    ApprovalGateMap(merged)
}

/// `a` is the existing/base gate (typically the parent's), `b` is the additional gate.
///
/// For same-argument conflicts in per-arg maps, `a` wins. This is intentional:
/// the base gate is the parent's established gate; the additional gate cannot
/// loosen it. Swapping the argument order would silently flip this security property.
fn take_stricter_approval_gate(a: &ToolApprovalGate, b: &ToolApprovalGate) -> ToolApprovalGate {
    match (&a.args, &b.args) {
        // Either is whole-tool → whole-tool wins (strictest possible)
        (None, _) | (_, None) => ToolApprovalGate::whole_tool(),
        // Both per-arg → union of argument keys (more args gated = stricter).
        // Same-argument conflicts: `a`'s gate wins (base takes precedence).
        (Some(args_a), Some(args_b)) => {
            let mut merged_args = args_a.clone();
            for (arg, gate) in args_b {
                merged_args
                    .entry(arg.clone())
                    .or_insert_with(|| gate.clone());
            }
            ToolApprovalGate::with_args(merged_args)
        }
    }
}

// ---------------------------------------------------------------------------
// Approval Gate Monotonicity Verification (Defense in Depth)
// ---------------------------------------------------------------------------

/// Errors specific to approval gate monotonicity violations.
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalGateError {
    /// Parent had approval gates but child stripped them entirely.
    GatesStripped,
    /// A specific tool's gate was removed in the child.
    ToolApprovalGateRemoved(String),
    /// A whole-tool gate was weakened to per-argument gates.
    ToolApprovalGateWeakened(String),
    /// A per-argument gate was removed in the child.
    ArgApprovalGateRemoved(String, String),
    /// A per-argument gate constraint was weakened.
    ArgApprovalGateWeakened,
    /// A per-argument gate constraint changed (Phase 1: exact equality required).
    ArgApprovalGateConstraintChanged,
}

impl fmt::Display for ApprovalGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GatesStripped => write!(f, "child stripped all approval gates from parent"),
            Self::ToolApprovalGateRemoved(tool) => {
                write!(f, "approval gate removed for tool '{}'", tool)
            }
            Self::ToolApprovalGateWeakened(tool) => {
                write!(f, "whole-tool gate weakened to per-arg for '{}'", tool)
            }
            Self::ArgApprovalGateRemoved(tool, arg) => {
                write!(f, "arg gate '{}' removed for tool '{}'", arg, tool)
            }
            Self::ArgApprovalGateWeakened => write!(f, "arg gate weakened from All to Constraint"),
            Self::ArgApprovalGateConstraintChanged => {
                write!(
                    f,
                    "arg gate constraint changed (Phase 1: exact equality required)"
                )
            }
        }
    }
}

impl std::error::Error for ApprovalGateError {}

/// Verify that child approval gates are monotonically narrower than parent gates.
///
/// This is **optional defense-in-depth** for Phase 1. The structured
/// delegation API is the primary enforcement mechanism.
///
/// Returns `Ok(())` if the child gates are valid, `Err(ApprovalGateError)` if
/// they violate monotonicity.
pub(crate) fn verify_approval_gate_monotonicity(
    parent_gates: Option<&ApprovalGateMap>,
    child_gates: Option<&ApprovalGateMap>,
    child_tools: &BTreeMap<String, crate::constraints::ConstraintSet>,
) -> std::result::Result<(), ApprovalGateError> {
    let parent_gates = match parent_gates {
        None => return Ok(()), // Parent has no gates — child is unconstrained
        Some(g) => g,
    };

    let child_gates = match child_gates {
        None => return Err(ApprovalGateError::GatesStripped),
        Some(g) => g,
    };

    for (tool, parent_gate) in parent_gates.iter() {
        // Only check tools the child has
        if !child_tools.contains_key(tool) {
            continue;
        }

        let child_gate = child_gates
            .get(tool)
            .ok_or_else(|| ApprovalGateError::ToolApprovalGateRemoved(tool.clone()))?;

        match (&parent_gate.args, &child_gate.args) {
            // Both whole-tool → equal, valid
            (None, None) => {}

            // Parent whole-tool, child per-arg → weakening (cannot prove equivalence
            // without tool argument schema)
            (None, Some(_)) => {
                return Err(ApprovalGateError::ToolApprovalGateWeakened(tool.clone()));
            }

            // Parent per-arg, child whole-tool → strictly stricter, valid
            (Some(_), None) => {}

            // Both per-arg → each parent arg gate must exist and be ≤ in child
            (Some(parent_args), Some(child_args)) => {
                for (arg, parent_arg_gate) in parent_args {
                    let child_arg_gate = child_args.get(arg).ok_or_else(|| {
                        ApprovalGateError::ArgApprovalGateRemoved(tool.clone(), arg.clone())
                    })?;

                    validate_arg_approval_gate_monotonic(child_arg_gate, parent_arg_gate)?;
                }
            }
        }
    }

    Ok(())
}

/// Validate that a child arg gate is monotonically at least as strict as the parent.
///
/// "At least as strict" means the child gates a superset of values: child ≥ parent.
/// Phase 1: constraint-based gates require exact equality.
fn validate_arg_approval_gate_monotonic(
    child: &ArgApprovalGate,
    parent: &ArgApprovalGate,
) -> std::result::Result<(), ApprovalGateError> {
    match (child, parent) {
        (ArgApprovalGate::All, ArgApprovalGate::All) => Ok(()),

        // Child All, parent Constraint → child gates more values (stricter)
        (ArgApprovalGate::All, ArgApprovalGate::Constraint(_)) => Ok(()),

        // Child Constraint, parent All → child gates fewer values (weaker)
        (ArgApprovalGate::Constraint(_), ArgApprovalGate::All) => {
            Err(ApprovalGateError::ArgApprovalGateWeakened)
        }

        // Phase 1: exact equality only
        (ArgApprovalGate::Constraint(c_child), ArgApprovalGate::Constraint(c_parent)) => {
            if c_child == c_parent {
                Ok(())
            } else {
                Err(ApprovalGateError::ArgApprovalGateConstraintChanged)
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
    fn test_approval_gate_map_roundtrip_whole_tool() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("email.delete".into(), ToolApprovalGate::whole_tool());
        gm.insert("exec".into(), ToolApprovalGate::whole_tool());

        let encoded = encode_approval_gate_map(&gm).unwrap();
        let decoded = parse_approval_gate_map(Some(&encoded)).unwrap().unwrap();
        assert_eq!(gm, decoded);
    }

    #[test]
    fn test_approval_gate_map_roundtrip_per_arg() {
        let mut args = BTreeMap::new();
        args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        args.insert("mode".into(), ArgApprovalGate::All);

        let mut gm = ApprovalGateMap::new();
        gm.insert("file.write".into(), ToolApprovalGate::with_args(args));

        let encoded = encode_approval_gate_map(&gm).unwrap();
        let decoded = parse_approval_gate_map(Some(&encoded)).unwrap().unwrap();
        assert_eq!(gm, decoded);
    }

    #[test]
    fn test_parse_approval_gate_map_absent() {
        assert!(parse_approval_gate_map(None).unwrap().is_none());
    }

    #[test]
    fn test_parse_approval_gate_map_empty_bytes() {
        assert!(parse_approval_gate_map(Some(&vec![])).unwrap().is_none());
    }

    // -- evaluate_approval_gates: no gate map --

    #[test]
    fn test_no_approval_gate_map_allows() {
        assert!(!evaluate_approval_gates(None, "any_tool", &HashMap::new()).unwrap());
    }

    // -- evaluate_approval_gates: with gate map --

    #[test]
    fn test_tool_not_in_approval_gate_map_allows() {
        let gm = ApprovalGateMap::new();
        assert!(!evaluate_approval_gates(Some(&gm), "email.read", &HashMap::new()).unwrap());
    }

    #[test]
    fn test_whole_tool_gate_triggers() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("email.delete".into(), ToolApprovalGate::whole_tool());

        assert!(evaluate_approval_gates(Some(&gm), "email.delete", &HashMap::new()).unwrap());
    }

    #[test]
    fn test_per_arg_all_triggers() {
        let mut arg_gates = BTreeMap::new();
        arg_gates.insert("command".into(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("exec".into(), ToolApprovalGate::with_args(arg_gates));

        let args = make_args(&[("command", "rm -rf /")]);
        assert!(evaluate_approval_gates(Some(&gm), "exec", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_matches_triggers() {
        let mut arg_gates = BTreeMap::new();
        arg_gates.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = ApprovalGateMap::new();
        gm.insert("file.write".into(), ToolApprovalGate::with_args(arg_gates));

        let args = make_args(&[("path", "/etc/hosts")]);
        assert!(evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_no_match_allows() {
        let mut arg_gates = BTreeMap::new();
        arg_gates.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = ApprovalGateMap::new();
        gm.insert("file.write".into(), ToolApprovalGate::with_args(arg_gates));

        let args = make_args(&[("path", "/workspace/foo.txt")]);
        assert!(!evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());
    }

    #[test]
    fn test_per_arg_absent_argument_fires_gate() {
        // SECURITY: absent gated argument → gate fires (fail-safe).
        // A call that omits the gated argument has unknown behaviour for
        // that parameter, so we require approval rather than bypassing the gate.
        let mut arg_gates = BTreeMap::new();
        arg_gates.insert("path".into(), ArgApprovalGate::All);
        let mut gm = ApprovalGateMap::new();
        gm.insert("file.write".into(), ToolApprovalGate::with_args(arg_gates));

        // Call with no "path" argument — gate must fire
        let args = make_args(&[("other", "value")]);
        assert!(evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());

        // Confirm the gate does NOT fire for a completely different tool
        assert!(!evaluate_approval_gates(Some(&gm), "file.read", &args).unwrap());
    }

    #[test]
    fn test_per_arg_constraint_absent_argument_fires_gate() {
        // Same fail-safe semantics apply when the gate is a constraint, not ArgApprovalGate::All.
        let mut arg_gates = BTreeMap::new();
        arg_gates.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut gm = ApprovalGateMap::new();
        gm.insert("file.write".into(), ToolApprovalGate::with_args(arg_gates));

        // No "path" supplied → gate fires even though the constraint can't match
        let args = make_args(&[("content", "hello")]);
        assert!(evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());
    }

    // -- Approval gate propagation --

    #[test]
    fn test_propagate_approval_gates_scopes_to_child_tools() {
        let mut parent_gates = ApprovalGateMap::new();
        parent_gates.insert("email.delete".into(), ToolApprovalGate::whole_tool());
        parent_gates.insert("exec".into(), ToolApprovalGate::whole_tool());
        parent_gates.insert("file.write".into(), ToolApprovalGate::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "email.delete".into(),
            crate::constraints::ConstraintSet::new(),
        );
        // child doesn't have "exec" or "file.write"

        let result = propagate_approval_gates(&parent_gates, &child_tools).unwrap();
        assert!(result.contains_tool("email.delete"));
        assert!(!result.contains_tool("exec"));
        assert!(!result.contains_tool("file.write"));
    }

    #[test]
    fn test_propagate_approval_gates_returns_none_when_no_overlap() {
        let mut parent_gates = ApprovalGateMap::new();
        parent_gates.insert("exec".into(), ToolApprovalGate::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "email.read".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert!(propagate_approval_gates(&parent_gates, &child_tools).is_none());
    }

    // -- Approval gate monotonicity --

    #[test]
    fn test_monotonicity_no_parent_gates_always_ok() {
        let child_tools = BTreeMap::new();
        assert!(verify_approval_gate_monotonicity(None, None, &child_tools).is_ok());
        let gm = ApprovalGateMap::new();
        assert!(verify_approval_gate_monotonicity(None, Some(&gm), &child_tools).is_ok());
    }

    #[test]
    fn test_monotonicity_parent_gates_child_stripped_fails() {
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_approval_gate_monotonicity(Some(&parent), None, &child_tools),
            Err(ApprovalGateError::GatesStripped)
        );
    }

    #[test]
    fn test_monotonicity_tool_gate_removed_fails() {
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::whole_tool());
        parent.insert("email.delete".into(), ToolApprovalGate::whole_tool());

        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::whole_tool());
        // "email.delete" gate missing

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());
        child_tools.insert(
            "email.delete".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert_eq!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(ApprovalGateError::ToolApprovalGateRemoved(
                "email.delete".into()
            ))
        );
    }

    #[test]
    fn test_monotonicity_whole_to_per_arg_weakening_fails() {
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::whole_tool());

        let mut args = BTreeMap::new();
        args.insert("command".into(), ArgApprovalGate::All);
        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::with_args(args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(ApprovalGateError::ToolApprovalGateWeakened("exec".into()))
        );
    }

    #[test]
    fn test_monotonicity_per_arg_to_whole_strengthening_ok() {
        let mut args = BTreeMap::new();
        args.insert("command".into(), ArgApprovalGate::All);
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::with_args(args));

        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::whole_tool());

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok()
        );
    }

    #[test]
    fn test_monotonicity_arg_gate_all_to_constraint_weakening_fails() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert("command".into(), ArgApprovalGate::All);
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "command".into(),
            ArgApprovalGate::Constraint(Pattern::new("rm*").unwrap().into()),
        );
        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert_eq!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(ApprovalGateError::ArgApprovalGateWeakened)
        );
    }

    #[test]
    fn test_monotonicity_constraint_to_all_strengthening_ok() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "command".into(),
            ArgApprovalGate::Constraint(Pattern::new("rm*").unwrap().into()),
        );
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::with_args(parent_args));

        let mut child_args = BTreeMap::new();
        child_args.insert("command".into(), ArgApprovalGate::All);
        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());

        assert!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok()
        );
    }

    #[test]
    fn test_monotonicity_constraint_changed_fails() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut parent = ApprovalGateMap::new();
        parent.insert(
            "file.write".into(),
            ToolApprovalGate::with_args(parent_args),
        );

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/var").unwrap().into()),
        );
        let mut child = ApprovalGateMap::new();
        child.insert("file.write".into(), ToolApprovalGate::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "file.write".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert_eq!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools),
            Err(ApprovalGateError::ArgApprovalGateConstraintChanged)
        );
    }

    #[test]
    fn test_monotonicity_constraint_equal_ok() {
        let mut parent_args = BTreeMap::new();
        parent_args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut parent = ApprovalGateMap::new();
        parent.insert(
            "file.write".into(),
            ToolApprovalGate::with_args(parent_args),
        );

        let mut child_args = BTreeMap::new();
        child_args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        let mut child = ApprovalGateMap::new();
        child.insert("file.write".into(), ToolApprovalGate::with_args(child_args));

        let mut child_tools = BTreeMap::new();
        child_tools.insert(
            "file.write".into(),
            crate::constraints::ConstraintSet::new(),
        );

        assert!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok()
        );
    }

    #[test]
    fn test_monotonicity_skips_tools_child_doesnt_have() {
        let mut parent = ApprovalGateMap::new();
        parent.insert("exec".into(), ToolApprovalGate::whole_tool());
        parent.insert("email.delete".into(), ToolApprovalGate::whole_tool());

        let mut child = ApprovalGateMap::new();
        child.insert("exec".into(), ToolApprovalGate::whole_tool());
        // No "email.delete" gate, but child doesn't have "email.delete" tool either

        let mut child_tools = BTreeMap::new();
        child_tools.insert("exec".into(), crate::constraints::ConstraintSet::new());
        // No "email.delete" in child tools

        assert!(
            verify_approval_gate_monotonicity(Some(&parent), Some(&child), &child_tools).is_ok()
        );
    }

    #[test]
    fn test_mixed_approval_gate_map() {
        let mut gm = ApprovalGateMap::new();
        gm.insert("email.delete".into(), ToolApprovalGate::whole_tool());
        gm.insert("email.send".into(), ToolApprovalGate::whole_tool());

        let mut file_args = BTreeMap::new();
        file_args.insert(
            "path".into(),
            ArgApprovalGate::Constraint(Subpath::new("/etc").unwrap().into()),
        );
        gm.insert("file.write".into(), ToolApprovalGate::with_args(file_args));

        // email.read is NOT gated → should be free
        let args = make_args(&[("folder", "inbox")]);
        assert!(!evaluate_approval_gates(Some(&gm), "email.read", &args).unwrap());

        // email.delete is whole-tool gated
        assert!(evaluate_approval_gates(Some(&gm), "email.delete", &HashMap::new()).unwrap());

        // file.write to /workspace → free
        let args = make_args(&[("path", "/workspace/foo.txt")]);
        assert!(!evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());

        // file.write to /etc → requires approval
        let args = make_args(&[("path", "/etc/nginx/nginx.conf")]);
        assert!(evaluate_approval_gates(Some(&gm), "file.write", &args).unwrap());
    }
}
