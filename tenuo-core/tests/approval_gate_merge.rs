//! Integration tests for approval gate merge semantics.
//!
//! Approval gates are strictly monotonic: children can only add gates, never remove them.
//! When a child sets approval gates during attenuation or issuance, the result is the union
//! of inherited parent gates and the explicitly added gates, scoped to the child's
//! tool set.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::{
    approval_gate::{
        encode_approval_gate_map, evaluate_approval_gates, merge_approval_gate_maps,
        ApprovalGateMap, ArgApprovalGate, ToolApprovalGate,
    },
    constraints::ConstraintSet,
    crypto::SigningKey,
    warrant::{OwnedAttenuationBuilder, OwnedIssuanceBuilder, Warrant, WarrantType},
};

// ---------------------------------------------------------------------------
// Unit tests: merge_approval_gate_maps()
// ---------------------------------------------------------------------------

#[test]
fn test_unit_merge_approval_gate_maps_both_empty() {
    let base = ApprovalGateMap::new();
    let additional = ApprovalGateMap::new();
    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.is_empty());
}

#[test]
fn test_unit_merge_approval_gate_maps_base_only() {
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::whole_tool());
    let additional = ApprovalGateMap::new();
    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.contains_tool("exec"));
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_approval_gate_maps_additional_only() {
    let base = ApprovalGateMap::new();
    let mut additional = ApprovalGateMap::new();
    additional.insert("read".into(), ToolApprovalGate::whole_tool());
    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.contains_tool("read"));
}

#[test]
fn test_unit_merge_approval_gate_maps_no_conflict() {
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::whole_tool());
    let mut additional = ApprovalGateMap::new();
    additional.insert("delete".into(), ToolApprovalGate::whole_tool());
    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.contains_tool("exec"));
    assert!(merged.contains_tool("delete"));
}

#[test]
fn test_unit_merge_whole_tool_wins_over_per_arg_base_wins() {
    // base: whole-tool, additional: per-arg → whole-tool wins
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::whole_tool());

    let mut args = BTreeMap::new();
    args.insert("command".into(), ArgApprovalGate::All);
    let mut additional = ApprovalGateMap::new();
    additional.insert("exec".into(), ToolApprovalGate::with_args(args));

    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_whole_tool_wins_over_per_arg_additional_wins() {
    // base: per-arg, additional: whole-tool → whole-tool wins
    let mut args = BTreeMap::new();
    args.insert("command".into(), ArgApprovalGate::All);
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::with_args(args));

    let mut additional = ApprovalGateMap::new();
    additional.insert("exec".into(), ToolApprovalGate::whole_tool());

    let merged = merge_approval_gate_maps(&base, &additional);
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_per_arg_union() {
    // base: exec={a}, additional: exec={b} → exec={a,b}
    let mut args_a = BTreeMap::new();
    args_a.insert("a".into(), ArgApprovalGate::All);
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::with_args(args_a));

    let mut args_b = BTreeMap::new();
    args_b.insert("b".into(), ArgApprovalGate::All);
    let mut additional = ApprovalGateMap::new();
    additional.insert("exec".into(), ToolApprovalGate::with_args(args_b));

    let merged = merge_approval_gate_maps(&base, &additional);
    let gate = merged.get("exec").unwrap();
    let args = gate.args.as_ref().unwrap();
    assert!(args.contains_key("a"), "arg 'a' should be in merged gate");
    assert!(args.contains_key("b"), "arg 'b' should be in merged gate");
}

#[test]
fn test_unit_merge_per_arg_base_survives_conflict() {
    // base: exec={a=All}, additional: exec={a=All} → exec={a=All} (base wins on duplicate)
    let mut args_a = BTreeMap::new();
    args_a.insert("a".into(), ArgApprovalGate::All);
    let mut base = ApprovalGateMap::new();
    base.insert("exec".into(), ToolApprovalGate::with_args(args_a));

    let mut args_b = BTreeMap::new();
    args_b.insert("a".into(), ArgApprovalGate::All);
    let mut additional = ApprovalGateMap::new();
    additional.insert("exec".into(), ToolApprovalGate::with_args(args_b));

    let merged = merge_approval_gate_maps(&base, &additional);
    let gate = merged.get("exec").unwrap();
    let args = gate.args.as_ref().unwrap();
    assert_eq!(args.len(), 1);
    assert!(args.contains_key("a"));
}

// ---------------------------------------------------------------------------
// Integration tests via OwnedAttenuationBuilder
// ---------------------------------------------------------------------------

fn make_warrant_with_tools(
    key: &SigningKey,
    tools: &[&str],
    holder: Option<&SigningKey>,
) -> Warrant {
    let mut builder = Warrant::builder();
    for t in tools {
        builder = builder.capability(*t, ConstraintSet::new());
    }
    builder = builder.ttl(Duration::from_secs(3600));
    if let Some(h) = holder {
        builder = builder.holder(h.public_key());
    } else {
        builder = builder.holder(key.public_key());
    }
    builder.build(key).unwrap()
}

#[test]
fn test_add_gate_on_parent_without_gates() {
    // parent: no gates, child adds exec=whole → child has exec gate
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();
    let parent = make_warrant_with_tools(&root_kp, &["exec", "read"], None);

    let mut builder = OwnedAttenuationBuilder::new(parent);
    builder.inherit_all(); // start with all parent tools
    builder.retain_capability("exec"); // narrow to just exec
    builder.set_holder(child_kp.public_key());
    builder.set_ttl(Duration::from_secs(1800));

    let mut approval_gate_map = ApprovalGateMap::new();
    approval_gate_map.insert("exec".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&approval_gate_map).unwrap();
    builder.set_approval_gates_extension(gate_bytes).unwrap();

    let child = builder.build(&root_kp).unwrap();

    // Verify gate is present in child
    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();
    assert!(child_gates.contains_tool("exec"));
    assert!(child_gates.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_merge_adds_to_existing_gates() {
    // parent: exec gate, child adds delete gate → child has exec+delete
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_gates = ApprovalGateMap::new();
    parent_gates.insert("exec".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&parent_gates).unwrap();

    // Create parent with gates via builder
    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("delete", ConstraintSet::new());
    builder = builder.capability("read", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY, gate_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.retain_tools(&["exec".to_string(), "delete".to_string()]);
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_gates = ApprovalGateMap::new();
    extra_gates.insert("delete".into(), ToolApprovalGate::whole_tool());
    let extra_gate_bytes = encode_approval_gate_map(&extra_gates).unwrap();
    attn.set_approval_gates_extension(extra_gate_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(
        child_gates.contains_tool("exec"),
        "exec gate should be inherited"
    );
    assert!(
        child_gates.contains_tool("delete"),
        "delete gate should be added"
    );
    // read was not in child tools, so its absence is fine (wasn't gated anyway)
}

#[test]
fn test_merge_whole_tool_wins_over_per_arg() {
    // parent: exec=per_arg, child adds exec=whole → whole wins
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_args = BTreeMap::new();
    parent_args.insert("command".into(), ArgApprovalGate::All);
    let mut parent_gates = ApprovalGateMap::new();
    parent_gates.insert("exec".into(), ToolApprovalGate::with_args(parent_args));
    let gate_bytes = encode_approval_gate_map(&parent_gates).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY, gate_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_gates = ApprovalGateMap::new();
    extra_gates.insert("exec".into(), ToolApprovalGate::whole_tool());
    let extra_gate_bytes = encode_approval_gate_map(&extra_gates).unwrap();
    attn.set_approval_gates_extension(extra_gate_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    // Should be whole-tool (stricter)
    assert!(child_gates.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_merge_per_arg_union() {
    // parent: exec={a}, child adds exec={b} → exec={a, b}
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_args = BTreeMap::new();
    parent_args.insert("a".into(), ArgApprovalGate::All);
    let mut parent_gates = ApprovalGateMap::new();
    parent_gates.insert("exec".into(), ToolApprovalGate::with_args(parent_args));
    let gate_bytes = encode_approval_gate_map(&parent_gates).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY, gate_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_args = BTreeMap::new();
    extra_args.insert("b".into(), ArgApprovalGate::All);
    let mut extra_gates = ApprovalGateMap::new();
    extra_gates.insert("exec".into(), ToolApprovalGate::with_args(extra_args));
    let extra_gate_bytes = encode_approval_gate_map(&extra_gates).unwrap();
    attn.set_approval_gates_extension(extra_gate_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    let gate = child_gates.get("exec").unwrap();
    let args = gate.args.as_ref().unwrap();
    assert!(args.contains_key("a"), "arg 'a' should be preserved");
    assert!(args.contains_key("b"), "arg 'b' should be added");
}

#[test]
fn test_gate_scoped_to_child_tools() {
    // parent: exec gate + delete gate, child drops delete → delete gate removed
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_gates = ApprovalGateMap::new();
    parent_gates.insert("exec".into(), ToolApprovalGate::whole_tool());
    parent_gates.insert("delete".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&parent_gates).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("delete", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY, gate_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    // Child only retains exec, not delete
    attn.retain_capability("exec");
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(
        child_gates.contains_tool("exec"),
        "exec gate should be inherited"
    );
    assert!(
        !child_gates.contains_tool("delete"),
        "delete gate should be scoped away"
    );
}

#[test]
fn test_gate_inherited_unchanged() {
    // attenuation without explicit gates: gate is preserved as-is
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_gates = ApprovalGateMap::new();
    parent_gates.insert("exec".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&parent_gates).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("read", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY, gate_bytes);
    let parent = builder.build(&root_kp).unwrap();

    // Attenuate without calling set_approval_gates_extension
    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(child_gates.contains_tool("exec"));
    assert!(child_gates.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_evaluate_approval_gates_fires_for_added_gate() {
    // Verify that evaluate_approval_gates() fires correctly on a child with an added gate
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();
    let parent = make_warrant_with_tools(&root_kp, &["exec"], None);

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut approval_gate_map = ApprovalGateMap::new();
    approval_gate_map.insert("exec".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&approval_gate_map).unwrap();
    attn.set_approval_gates_extension(gate_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_gates = tenuo::approval_gate::parse_approval_gate_map(
        child.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap();

    let args: HashMap<String, tenuo::constraints::ConstraintValue> = HashMap::new();
    let fires = evaluate_approval_gates(child_gates.as_ref(), "exec", &args).unwrap();
    assert!(fires, "gate should fire for exec");

    let no_fire = evaluate_approval_gates(child_gates.as_ref(), "read", &args).unwrap();
    assert!(!no_fire, "gate should not fire for tools not in gate map");
}

// ---------------------------------------------------------------------------
// Integration tests via OwnedIssuanceBuilder
// ---------------------------------------------------------------------------

#[test]
fn test_issuance_builder_adds_gate() {
    // Issuer warrant (no gates) → issued exec warrant gets explicit gate
    let issuer_kp = SigningKey::generate();
    let holder_kp = SigningKey::generate();

    let issuer = Warrant::builder()
        .r#type(WarrantType::Issuer)
        .issuable_tools(vec!["exec".to_string(), "read".to_string()])
        .ttl(Duration::from_secs(3600))
        .holder(issuer_kp.public_key())
        .build(&issuer_kp)
        .unwrap();

    let mut builder = OwnedIssuanceBuilder::new(issuer);
    builder.set_tool("exec", ConstraintSet::new());
    builder.set_holder(holder_kp.public_key());
    builder.set_ttl(Duration::from_secs(1800));

    let mut approval_gate_map = ApprovalGateMap::new();
    approval_gate_map.insert("exec".into(), ToolApprovalGate::whole_tool());
    let gate_bytes = encode_approval_gate_map(&approval_gate_map).unwrap();
    builder.set_approval_gates_extension(gate_bytes).unwrap();

    let issued = builder.build(&issuer_kp).unwrap();

    let issued_gates = tenuo::approval_gate::parse_approval_gate_map(
        issued.extension(tenuo::APPROVAL_GATE_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(issued_gates.contains_tool("exec"));
    assert!(issued_gates.get("exec").unwrap().is_whole_tool());

    // Evaluate gate
    let args: HashMap<String, tenuo::constraints::ConstraintValue> = HashMap::new();
    let fires = evaluate_approval_gates(Some(&issued_gates), "exec", &args).unwrap();
    assert!(fires, "gate should fire for exec");
}
