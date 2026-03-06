//! Integration tests for guard merge semantics.
//!
//! Guards are strictly monotonic: children can only add guards, never remove them.
//! When a child sets guards during attenuation or issuance, the result is the union
//! of inherited parent guards and the explicitly added guards, scoped to the child's
//! tool set.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tenuo::{
    constraints::ConstraintSet,
    crypto::SigningKey,
    guard::{encode_guard_map, evaluate_guards, merge_guard_maps, ArgGuard, GuardMap, ToolGuard},
    warrant::{OwnedAttenuationBuilder, OwnedIssuanceBuilder, Warrant, WarrantType},
};

// ---------------------------------------------------------------------------
// Unit tests: merge_guard_maps()
// ---------------------------------------------------------------------------

#[test]
fn test_unit_merge_guard_maps_both_empty() {
    let base = GuardMap::new();
    let additional = GuardMap::new();
    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.is_empty());
}

#[test]
fn test_unit_merge_guard_maps_base_only() {
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::whole_tool());
    let additional = GuardMap::new();
    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.contains_tool("exec"));
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_guard_maps_additional_only() {
    let base = GuardMap::new();
    let mut additional = GuardMap::new();
    additional.insert("read".into(), ToolGuard::whole_tool());
    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.contains_tool("read"));
}

#[test]
fn test_unit_merge_guard_maps_no_conflict() {
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::whole_tool());
    let mut additional = GuardMap::new();
    additional.insert("delete".into(), ToolGuard::whole_tool());
    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.contains_tool("exec"));
    assert!(merged.contains_tool("delete"));
}

#[test]
fn test_unit_merge_whole_tool_wins_over_per_arg_base_wins() {
    // base: whole-tool, additional: per-arg → whole-tool wins
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::whole_tool());

    let mut args = BTreeMap::new();
    args.insert("command".into(), ArgGuard::All);
    let mut additional = GuardMap::new();
    additional.insert("exec".into(), ToolGuard::with_args(args));

    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_whole_tool_wins_over_per_arg_additional_wins() {
    // base: per-arg, additional: whole-tool → whole-tool wins
    let mut args = BTreeMap::new();
    args.insert("command".into(), ArgGuard::All);
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::with_args(args));

    let mut additional = GuardMap::new();
    additional.insert("exec".into(), ToolGuard::whole_tool());

    let merged = merge_guard_maps(&base, &additional);
    assert!(merged.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_unit_merge_per_arg_union() {
    // base: exec={a}, additional: exec={b} → exec={a,b}
    let mut args_a = BTreeMap::new();
    args_a.insert("a".into(), ArgGuard::All);
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::with_args(args_a));

    let mut args_b = BTreeMap::new();
    args_b.insert("b".into(), ArgGuard::All);
    let mut additional = GuardMap::new();
    additional.insert("exec".into(), ToolGuard::with_args(args_b));

    let merged = merge_guard_maps(&base, &additional);
    let guard = merged.get("exec").unwrap();
    let args = guard.args.as_ref().unwrap();
    assert!(args.contains_key("a"), "arg 'a' should be in merged guard");
    assert!(args.contains_key("b"), "arg 'b' should be in merged guard");
}

#[test]
fn test_unit_merge_per_arg_base_survives_conflict() {
    // base: exec={a=All}, additional: exec={a=All} → exec={a=All} (base wins on duplicate)
    let mut args_a = BTreeMap::new();
    args_a.insert("a".into(), ArgGuard::All);
    let mut base = GuardMap::new();
    base.insert("exec".into(), ToolGuard::with_args(args_a));

    let mut args_b = BTreeMap::new();
    args_b.insert("a".into(), ArgGuard::All);
    let mut additional = GuardMap::new();
    additional.insert("exec".into(), ToolGuard::with_args(args_b));

    let merged = merge_guard_maps(&base, &additional);
    let guard = merged.get("exec").unwrap();
    let args = guard.args.as_ref().unwrap();
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
fn test_add_guard_on_parent_without_guards() {
    // parent: no guards, child adds exec=whole → child has exec guard
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();
    let parent = make_warrant_with_tools(&root_kp, &["exec", "read"], None);

    let mut builder = OwnedAttenuationBuilder::new(parent);
    builder.inherit_all();             // start with all parent tools
    builder.retain_capability("exec"); // narrow to just exec
    builder.set_holder(child_kp.public_key());
    builder.set_ttl(Duration::from_secs(1800));

    let mut guard_map = GuardMap::new();
    guard_map.insert("exec".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&guard_map).unwrap();
    builder.set_guards_extension(guard_bytes).unwrap();

    let child = builder.build(&root_kp).unwrap();

    // Verify guard is present in child
    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();
    assert!(child_guards.contains_tool("exec"));
    assert!(child_guards.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_merge_adds_to_existing_guards() {
    // parent: exec guard, child adds delete guard → child has exec+delete
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_guards = GuardMap::new();
    parent_guards.insert("exec".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&parent_guards).unwrap();

    // Create parent with guards via builder
    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("delete", ConstraintSet::new());
    builder = builder.capability("read", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::GUARD_EXTENSION_KEY, guard_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.retain_tools(&["exec".to_string(), "delete".to_string()]);
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_guards = GuardMap::new();
    extra_guards.insert("delete".into(), ToolGuard::whole_tool());
    let extra_bytes = encode_guard_map(&extra_guards).unwrap();
    attn.set_guards_extension(extra_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(child_guards.contains_tool("exec"), "exec guard should be inherited");
    assert!(child_guards.contains_tool("delete"), "delete guard should be added");
    // read was not in child tools, so its absence is fine (wasn't guarded anyway)
}

#[test]
fn test_merge_whole_tool_wins_over_per_arg() {
    // parent: exec=per_arg, child adds exec=whole → whole wins
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_args = BTreeMap::new();
    parent_args.insert("command".into(), ArgGuard::All);
    let mut parent_guards = GuardMap::new();
    parent_guards.insert("exec".into(), ToolGuard::with_args(parent_args));
    let guard_bytes = encode_guard_map(&parent_guards).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::GUARD_EXTENSION_KEY, guard_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_guards = GuardMap::new();
    extra_guards.insert("exec".into(), ToolGuard::whole_tool());
    let extra_bytes = encode_guard_map(&extra_guards).unwrap();
    attn.set_guards_extension(extra_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    // Should be whole-tool (stricter)
    assert!(child_guards.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_merge_per_arg_union() {
    // parent: exec={a}, child adds exec={b} → exec={a, b}
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_args = BTreeMap::new();
    parent_args.insert("a".into(), ArgGuard::All);
    let mut parent_guards = GuardMap::new();
    parent_guards.insert("exec".into(), ToolGuard::with_args(parent_args));
    let guard_bytes = encode_guard_map(&parent_guards).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::GUARD_EXTENSION_KEY, guard_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut extra_args = BTreeMap::new();
    extra_args.insert("b".into(), ArgGuard::All);
    let mut extra_guards = GuardMap::new();
    extra_guards.insert("exec".into(), ToolGuard::with_args(extra_args));
    let extra_bytes = encode_guard_map(&extra_guards).unwrap();
    attn.set_guards_extension(extra_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    let guard = child_guards.get("exec").unwrap();
    let args = guard.args.as_ref().unwrap();
    assert!(args.contains_key("a"), "arg 'a' should be preserved");
    assert!(args.contains_key("b"), "arg 'b' should be added");
}

#[test]
fn test_guard_scoped_to_child_tools() {
    // parent: exec guard + delete guard, child drops delete → delete guard removed
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_guards = GuardMap::new();
    parent_guards.insert("exec".into(), ToolGuard::whole_tool());
    parent_guards.insert("delete".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&parent_guards).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("delete", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::GUARD_EXTENSION_KEY, guard_bytes);
    let parent = builder.build(&root_kp).unwrap();

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    // Child only retains exec, not delete
    attn.retain_capability("exec");
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(child_guards.contains_tool("exec"), "exec guard should be inherited");
    assert!(!child_guards.contains_tool("delete"), "delete guard should be scoped away");
}

#[test]
fn test_guard_inherited_unchanged() {
    // attenuation without explicit guards: guard is preserved as-is
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();

    let mut parent_guards = GuardMap::new();
    parent_guards.insert("exec".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&parent_guards).unwrap();

    let mut builder = Warrant::builder();
    builder = builder.capability("exec", ConstraintSet::new());
    builder = builder.capability("read", ConstraintSet::new());
    builder = builder.ttl(Duration::from_secs(3600));
    builder = builder.holder(root_kp.public_key());
    builder = builder.extension(tenuo::GUARD_EXTENSION_KEY, guard_bytes);
    let parent = builder.build(&root_kp).unwrap();

    // Attenuate without calling set_guards_extension
    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(child_guards.contains_tool("exec"));
    assert!(child_guards.get("exec").unwrap().is_whole_tool());
}

#[test]
fn test_evaluate_guards_fires_for_added_guard() {
    // Verify that evaluate_guards() fires correctly on a child with an added guard
    let root_kp = SigningKey::generate();
    let child_kp = SigningKey::generate();
    let parent = make_warrant_with_tools(&root_kp, &["exec"], None);

    let mut attn = OwnedAttenuationBuilder::new(parent);
    attn.inherit_all();
    attn.set_holder(child_kp.public_key());
    attn.set_ttl(Duration::from_secs(1800));

    let mut guard_map = GuardMap::new();
    guard_map.insert("exec".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&guard_map).unwrap();
    attn.set_guards_extension(guard_bytes).unwrap();

    let child = attn.build(&root_kp).unwrap();

    let child_guards = tenuo::guard::parse_guard_map(
        child.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap();

    let args: HashMap<String, tenuo::constraints::ConstraintValue> = HashMap::new();
    let fires = evaluate_guards(child_guards.as_ref(), "exec", &args).unwrap();
    assert!(fires, "guard should fire for exec");

    let no_fire = evaluate_guards(child_guards.as_ref(), "read", &args).unwrap();
    assert!(!no_fire, "guard should not fire for tools not in guard map");
}

// ---------------------------------------------------------------------------
// Integration tests via OwnedIssuanceBuilder
// ---------------------------------------------------------------------------

#[test]
fn test_issuance_builder_adds_guard() {
    // Issuer warrant (no guards) → issued exec warrant gets explicit guard
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

    let mut guard_map = GuardMap::new();
    guard_map.insert("exec".into(), ToolGuard::whole_tool());
    let guard_bytes = encode_guard_map(&guard_map).unwrap();
    builder.set_guards_extension(guard_bytes).unwrap();

    let issued = builder.build(&issuer_kp).unwrap();

    let issued_guards = tenuo::guard::parse_guard_map(
        issued.extension(tenuo::GUARD_EXTENSION_KEY),
    )
    .unwrap()
    .unwrap();

    assert!(issued_guards.contains_tool("exec"));
    assert!(issued_guards.get("exec").unwrap().is_whole_tool());

    // Evaluate guard
    let args: HashMap<String, tenuo::constraints::ConstraintValue> = HashMap::new();
    let fires = evaluate_guards(Some(&issued_guards), "exec", &args).unwrap();
    assert!(fires, "guard should fire for exec");
}
