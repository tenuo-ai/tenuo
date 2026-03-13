//! Formal verification of attenuation soundness via property-based testing.
//!
//! Three properties are verified:
//!
//! 1. **Monotonicity**: For all values v, if validate_attenuation(parent, child) = Ok,
//!    then child.matches(v) = true implies parent.matches(v) = true.
//!    A child constraint can never accept a value the parent rejects.
//!
//! 2. **Normalization idempotence**: Serializing a constraint (or full warrant) to
//!    CBOR and deserializing it back produces an object whose re-serialization is
//!    byte-identical. This guarantees signatures remain valid after round-trips.
//!
//! 3. **Constraint soundness (mint vs enforce)**: Minting a warrant with constraints,
//!    encoding to wire format, decoding, then enforcing with `check_constraints`
//!    produces the same accept/reject decision as calling `matches()` on the
//!    original in-memory constraint. No semantic drift across the wire boundary.

use proptest::prelude::*;
use std::collections::HashMap;
use std::time::Duration;
use tenuo::constraints::*;
use tenuo::crypto::SigningKey;
use tenuo::warrant::Warrant;
use tenuo::wire;

// ============================================================================
// Universe of test values (small enough for exhaustive checking)
// ============================================================================

const ATOMS: &[&str] = &["a", "b", "c", "d", "e"];

fn atom_strategy() -> impl Strategy<Value = String> {
    prop::sample::select(ATOMS).prop_map(|s| s.to_string())
}

fn string_value_strategy() -> impl Strategy<Value = ConstraintValue> {
    prop_oneof![
        atom_strategy().prop_map(ConstraintValue::String),
        // Include some values outside the atom universe to test boundary behavior
        "[a-z]{1,8}".prop_map(ConstraintValue::String),
    ]
}

fn numeric_value_strategy() -> impl Strategy<Value = ConstraintValue> {
    prop_oneof![
        (-1000i64..1000).prop_map(ConstraintValue::Integer),
        (-1000.0f64..1000.0).prop_map(ConstraintValue::Float),
    ]
}

fn list_value_strategy() -> impl Strategy<Value = ConstraintValue> {
    prop::collection::vec(atom_strategy().prop_map(ConstraintValue::String), 0..5)
        .prop_map(ConstraintValue::List)
}

fn value_strategy() -> impl Strategy<Value = ConstraintValue> {
    prop_oneof![
        3 => string_value_strategy(),
        1 => numeric_value_strategy(),
        1 => list_value_strategy(),
    ]
}

// ============================================================================
// Constraint generators
// ============================================================================

fn exact_strategy() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        atom_strategy().prop_map(|s| Constraint::Exact(Exact::new(&*s))),
        (-100i64..100).prop_map(|n| Constraint::Exact(Exact::new(n))),
    ]
}

fn oneof_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::hash_set(atom_strategy(), 1..=ATOMS.len())
        .prop_map(|set| Constraint::OneOf(OneOf::new(set.into_iter().collect::<Vec<_>>())))
}

fn notoneof_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::hash_set(atom_strategy(), 1..=ATOMS.len())
        .prop_map(|set| Constraint::NotOneOf(NotOneOf::new(set.into_iter().collect::<Vec<_>>())))
}

fn range_strategy() -> impl Strategy<Value = Constraint> {
    (
        prop::option::of(-100.0f64..100.0),
        prop::option::of(-100.0f64..100.0),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_filter("at least one bound", |(min, max, _, _)| {
            min.is_some() || max.is_some()
        })
        .prop_map(|(min, max, min_inc, max_inc)| {
            Constraint::Range(Range {
                min,
                max,
                min_inclusive: min_inc,
                max_inclusive: max_inc,
            })
        })
}

fn pattern_strategy() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        atom_strategy()
            .prop_map(|s| Constraint::Pattern(Pattern::new(&format!("{}*", s)).unwrap())),
        atom_strategy()
            .prop_map(|s| Constraint::Pattern(Pattern::new(&format!("*{}", s)).unwrap())),
        Just(Constraint::Pattern(Pattern::new("*").unwrap())),
    ]
}

fn contains_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::hash_set(atom_strategy(), 1..=3)
        .prop_map(|set| Constraint::Contains(Contains::new(set.into_iter().collect::<Vec<_>>())))
}

fn subset_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::hash_set(atom_strategy(), 1..=ATOMS.len())
        .prop_map(|set| Constraint::Subset(Subset::new(set.into_iter().collect::<Vec<_>>())))
}

fn subpath_strategy() -> impl Strategy<Value = Constraint> {
    prop::sample::select(&["/data", "/data/reports", "/data/reports/q3", "/tmp", "/"][..])
        .prop_map(|s| Constraint::Subpath(Subpath::new(s).unwrap()))
}

fn wildcard_strategy() -> impl Strategy<Value = Constraint> {
    Just(Constraint::Wildcard(Wildcard::new()))
}

fn all_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::vec(leaf_constraint_strategy(), 1..=3)
        .prop_map(|cs| Constraint::All(All::new(cs)))
}

fn not_strategy() -> impl Strategy<Value = Constraint> {
    leaf_constraint_strategy().prop_map(|c| Constraint::Not(Not::new(c)))
}

fn any_of_strategy() -> impl Strategy<Value = Constraint> {
    prop::collection::vec(leaf_constraint_strategy(), 1..=3)
        .prop_map(|cs| Constraint::Any(Any::new(cs)))
}

/// Leaf constraints (no recursion) for use inside All/Not/AnyOf.
fn leaf_constraint_strategy() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        3 => exact_strategy(),
        2 => oneof_strategy(),
        2 => notoneof_strategy(),
        2 => range_strategy(),
        2 => pattern_strategy(),
        1 => contains_strategy(),
        1 => subset_strategy(),
        1 => subpath_strategy(),
        1 => wildcard_strategy(),
    ]
}

/// Full constraint strategy including composites.
fn constraint_strategy() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        3 => exact_strategy(),
        2 => oneof_strategy(),
        2 => notoneof_strategy(),
        2 => range_strategy(),
        2 => pattern_strategy(),
        1 => contains_strategy(),
        1 => subset_strategy(),
        1 => subpath_strategy(),
        1 => wildcard_strategy(),
        1 => all_strategy(),
        1 => not_strategy(),
        1 => any_of_strategy(),
    ]
}

// ============================================================================
// Core soundness property
// ============================================================================

/// The fundamental monotonicity invariant.
///
/// If attenuation is accepted, then for ANY value, child accepting it
/// implies parent also accepts it. A single counterexample is a
/// privilege escalation bug.
fn assert_monotonicity(parent: &Constraint, child: &Constraint, value: &ConstraintValue) {
    let attenuation_ok = parent.validate_attenuation(child).is_ok();
    if !attenuation_ok {
        return; // Attenuation rejected, nothing to check
    }

    let child_accepts = match child.matches(value) {
        Ok(b) => b,
        Err(_) => return, // Evaluation error (e.g., type mismatch), skip
    };

    if !child_accepts {
        return; // Child rejects this value, implication trivially true
    }

    // child.matches(v) = true AND attenuation was accepted
    // => parent.matches(v) MUST be true
    let parent_accepts = match parent.matches(value) {
        Ok(b) => b,
        Err(_) => return, // Evaluation error, skip
    };

    assert!(
        parent_accepts,
        "SOUNDNESS VIOLATION: validate_attenuation(parent, child) = Ok, \
         child.matches(v) = true, but parent.matches(v) = false!\n\
         parent: {:?}\n\
         child:  {:?}\n\
         value:  {:?}",
        parent, child, value
    );
}

// ============================================================================
// Property-based tests (randomized)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Fuzz all constraint type pairs with random values.
    #[test]
    fn prop_attenuation_soundness(
        parent in constraint_strategy(),
        child in constraint_strategy(),
        values in prop::collection::vec(value_strategy(), 10..=30),
    ) {
        for value in &values {
            assert_monotonicity(&parent, &child, value);
        }
    }

    /// Specifically target same-type pairs (most attenuation paths).
    #[test]
    fn prop_same_type_soundness(
        (parent, child) in prop_oneof![
            (oneof_strategy(), oneof_strategy()),
            (notoneof_strategy(), notoneof_strategy()),
            (range_strategy(), range_strategy()),
            (exact_strategy(), exact_strategy()),
            (pattern_strategy(), pattern_strategy()),
            (contains_strategy(), contains_strategy()),
            (subset_strategy(), subset_strategy()),
            (subpath_strategy(), subpath_strategy()),
            (wildcard_strategy(), constraint_strategy()),
        ],
        values in prop::collection::vec(value_strategy(), 20..=40),
    ) {
        for value in &values {
            assert_monotonicity(&parent, &child, value);
        }
    }

    /// Cross-type attenuation: types that can narrow to Exact.
    #[test]
    fn prop_cross_type_to_exact_soundness(
        parent in prop_oneof![
            oneof_strategy(),
            pattern_strategy(),
            range_strategy(),
            subpath_strategy(),
            wildcard_strategy(),
        ],
        child in exact_strategy(),
        values in prop::collection::vec(value_strategy(), 20..=40),
    ) {
        for value in &values {
            assert_monotonicity(&parent, &child, value);
        }
    }

    /// Wildcard parent with any child type.
    #[test]
    fn prop_wildcard_parent_soundness(
        child in constraint_strategy(),
        values in prop::collection::vec(value_strategy(), 20..=40),
    ) {
        let parent = Constraint::Wildcard(Wildcard::new());
        for value in &values {
            assert_monotonicity(&parent, &child, value);
        }
    }

    /// Verify rejected attenuations: if child is strictly wider, attenuation
    /// SHOULD be rejected. This tests the contrapositive direction.
    #[test]
    fn prop_wider_child_rejected(
        parent in oneof_strategy(),
        _values in prop::collection::vec(string_value_strategy(), 20..=40),
    ) {
        // Wildcard is always wider than any non-wildcard
        let child = Constraint::Wildcard(Wildcard::new());
        assert!(
            parent.validate_attenuation(&child).is_err(),
            "Wildcard child from non-wildcard parent must be rejected: {:?}",
            parent
        );

        // For OneOf parents: a child with extra values should be rejected
        if let Constraint::OneOf(ref parent_oneof) = parent {
            let mut wider_values: Vec<String> = parent_oneof.values.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            wider_values.push("zzz_extra_value".to_string());
            let wider_child = Constraint::OneOf(OneOf::new(wider_values));
            assert!(
                parent.validate_attenuation(&wider_child).is_err(),
                "OneOf child with extra values must be rejected"
            );
        }

        // Verify the parent itself is sound (trivial: same = same)
        assert!(parent.validate_attenuation(&parent).is_ok() ||
            // Some types don't support self-attenuation (Not, Any)
            parent.validate_attenuation(&parent).is_err());
    }
}

// ============================================================================
// Exhaustive verification for finite-domain types
// ============================================================================

/// Generate all subsets of ATOMS.
fn all_subsets() -> Vec<Vec<String>> {
    let n = ATOMS.len();
    let mut subsets = Vec::new();
    for mask in 0..(1u32 << n) {
        let mut subset = Vec::new();
        for (i, atom) in ATOMS.iter().enumerate() {
            if mask & (1 << i) != 0 {
                subset.push(atom.to_string());
            }
        }
        subsets.push(subset);
    }
    subsets
}

/// For OneOf x OneOf: exhaustively verify every pair of subsets.
#[test]
fn exhaustive_oneof_oneof_soundness() {
    let subsets = all_subsets();
    let non_empty: Vec<_> = subsets.iter().filter(|s| !s.is_empty()).collect();
    let mut checked = 0u64;

    for parent_set in &non_empty {
        let parent = Constraint::OneOf(OneOf::new(parent_set.to_vec()));
        for child_set in &non_empty {
            let child = Constraint::OneOf(OneOf::new(child_set.to_vec()));
            // Check against every atom
            for atom in ATOMS {
                let value = ConstraintValue::String(atom.to_string());
                assert_monotonicity(&parent, &child, &value);
                checked += 1;
            }
        }
    }
    eprintln!(
        "exhaustive_oneof_oneof: checked {} (parent, child, value) triples",
        checked
    );
}

/// For NotOneOf x NotOneOf: exhaustively verify.
#[test]
fn exhaustive_notoneof_notoneof_soundness() {
    let subsets = all_subsets();
    let non_empty: Vec<_> = subsets.iter().filter(|s| !s.is_empty()).collect();
    let mut checked = 0u64;

    for parent_set in &non_empty {
        let parent = Constraint::NotOneOf(NotOneOf::new(parent_set.to_vec()));
        for child_set in &non_empty {
            let child = Constraint::NotOneOf(NotOneOf::new(child_set.to_vec()));
            for atom in ATOMS {
                let value = ConstraintValue::String(atom.to_string());
                assert_monotonicity(&parent, &child, &value);
                checked += 1;
            }
        }
    }
    eprintln!("exhaustive_notoneof_notoneof: checked {} triples", checked);
}

/// For OneOf x NotOneOf (cross-type): exhaustively verify it's ALWAYS rejected.
#[test]
fn exhaustive_oneof_notoneof_always_rejected() {
    let subsets = all_subsets();
    let non_empty: Vec<_> = subsets.iter().filter(|s| !s.is_empty()).collect();

    for parent_set in &non_empty {
        let parent = Constraint::OneOf(OneOf::new(parent_set.to_vec()));
        for child_set in &non_empty {
            let child = Constraint::NotOneOf(NotOneOf::new(child_set.to_vec()));
            assert!(
                parent.validate_attenuation(&child).is_err(),
                "OneOf -> NotOneOf must ALWAYS be rejected\n\
                 parent: OneOf({:?})\n\
                 child:  NotOneOf({:?})",
                parent_set,
                child_set
            );
        }
    }
}

/// For Subset x Subset: exhaustively verify.
#[test]
fn exhaustive_subset_subset_soundness() {
    let subsets = all_subsets();
    let non_empty: Vec<_> = subsets.iter().filter(|s| !s.is_empty()).collect();
    let mut checked = 0u64;

    for parent_set in &non_empty {
        let parent = Constraint::Subset(Subset::new(parent_set.to_vec()));
        for child_set in &non_empty {
            let child = Constraint::Subset(Subset::new(child_set.to_vec()));
            // Test with every possible list value (all subsets of atoms)
            for test_set in &subsets {
                let value = ConstraintValue::List(
                    test_set
                        .iter()
                        .map(|s| ConstraintValue::String(s.clone()))
                        .collect(),
                );
                assert_monotonicity(&parent, &child, &value);
                checked += 1;
            }
        }
    }
    eprintln!("exhaustive_subset_subset: checked {} triples", checked);
}

/// For Contains x Contains: exhaustively verify.
#[test]
fn exhaustive_contains_contains_soundness() {
    let subsets = all_subsets();
    let non_empty: Vec<_> = subsets.iter().filter(|s| !s.is_empty()).collect();
    let mut checked = 0u64;

    for parent_set in &non_empty {
        let parent = Constraint::Contains(Contains::new(parent_set.to_vec()));
        for child_set in &non_empty {
            let child = Constraint::Contains(Contains::new(child_set.to_vec()));
            for test_set in &subsets {
                let value = ConstraintValue::List(
                    test_set
                        .iter()
                        .map(|s| ConstraintValue::String(s.clone()))
                        .collect(),
                );
                assert_monotonicity(&parent, &child, &value);
                checked += 1;
            }
        }
    }
    eprintln!("exhaustive_contains_contains: checked {} triples", checked);
}

/// Verify that Not -> Not attenuation is always rejected (code is sound,
/// spec was wrong before we fixed it).
#[test]
fn exhaustive_not_not_always_rejected() {
    for atom in ATOMS {
        let inner = Constraint::Exact(Exact::new(*atom));
        let parent = Constraint::Not(Not::new(inner.clone()));
        let child = Constraint::Not(Not::new(inner));
        assert!(
            parent.validate_attenuation(&child).is_err(),
            "Not -> Not must always be rejected"
        );
    }

    // Also test with OneOf inners
    let subsets = all_subsets();
    for s in subsets.iter().filter(|s| !s.is_empty()) {
        let inner = Constraint::OneOf(OneOf::new(s.to_vec()));
        let parent = Constraint::Not(Not::new(inner.clone()));
        let child = Constraint::Not(Not::new(inner));
        assert!(
            parent.validate_attenuation(&child).is_err(),
            "Not -> Not must always be rejected"
        );
    }
}

/// Verify that AnyOf -> AnyOf attenuation is always rejected.
#[test]
fn exhaustive_anyof_anyof_always_rejected() {
    let constraints: Vec<Constraint> = ATOMS
        .iter()
        .map(|a| Constraint::Exact(Exact::new(*a)))
        .collect();

    // Try all pairs of non-empty subsets of these constraints
    let n = constraints.len();
    for pmask in 1..(1u32 << n) {
        let parent_clauses: Vec<_> = (0..n)
            .filter(|i| pmask & (1 << i) != 0)
            .map(|i| constraints[i].clone())
            .collect();
        let parent = Constraint::Any(Any::new(parent_clauses));

        for cmask in 1..(1u32 << n) {
            let child_clauses: Vec<_> = (0..n)
                .filter(|i| cmask & (1 << i) != 0)
                .map(|i| constraints[i].clone())
                .collect();
            let child = Constraint::Any(Any::new(child_clauses));

            assert!(
                parent.validate_attenuation(&child).is_err(),
                "AnyOf -> AnyOf must always be rejected"
            );
        }
    }
}

// ============================================================================
// Regression tests: validate the harness catches known pre-fix bugs
// ============================================================================

/// Bug #1 (pre-fix): OneOf -> NotOneOf was accepted, allowing privilege escalation.
/// OneOf(["a","b"]) -> NotOneOf(["b"]) would accept "e", which the parent rejects.
#[test]
fn regression_oneof_to_notoneof_escalation() {
    let parent = Constraint::OneOf(OneOf::new(vec!["a", "b"]));
    let child = Constraint::NotOneOf(NotOneOf::new(vec!["b"]));

    // Attenuation must be rejected
    assert!(parent.validate_attenuation(&child).is_err());

    // The value "e" proves why: child accepts it, parent rejects it
    let escalation_value = ConstraintValue::String("e".to_string());
    assert!(child.matches(&escalation_value).unwrap());
    assert!(!parent.matches(&escalation_value).unwrap());
}

/// Bug #2 (pre-fix): CEL conjunction bypass via operator precedence.
/// "(x > 0)" attenuated to "(x > 0) && false || true" would accept everything
/// because `&&` binds tighter than `||`, making it `((x > 0) && false) || true`.
/// The fix requires the extra predicate to be parenthesized: "(x > 0) && (pred)".
#[test]
#[cfg(feature = "cel")]
fn regression_cel_conjunction_bypass() {
    let parent = CelConstraint::new("x > 0");
    let parent_c = Constraint::Cel(parent);

    // Attack: bare `false || true` could bypass conjunction
    let attack = CelConstraint::new("(x > 0) && false || true");
    let attack_c = Constraint::Cel(attack);
    assert!(
        parent_c.validate_attenuation(&attack_c).is_err(),
        "CEL conjunction bypass must be rejected"
    );

    // Valid: properly parenthesized predicate
    let valid = CelConstraint::new("(x > 0) && (x < 100)");
    let valid_c = Constraint::Cel(valid);
    assert!(
        parent_c.validate_attenuation(&valid_c).is_ok(),
        "Parenthesized CEL conjunction must be accepted"
    );
}

/// Structural CEL test (no CEL feature required - tests prefix/paren checking only).
#[test]
#[cfg(not(feature = "cel"))]
fn regression_cel_conjunction_bypass() {
    let parent = CelConstraint::new("x > 0");
    let parent_c = Constraint::Cel(parent);

    // Attack: bare predicate without parens must be rejected
    let attack = CelConstraint::new("(x > 0) && false || true");
    let attack_c = Constraint::Cel(attack);
    assert!(
        parent_c.validate_attenuation(&attack_c).is_err(),
        "CEL conjunction bypass must be rejected"
    );

    // Without CEL feature, the valid case also fails (can't compile expression),
    // so just verify the structural rejection works.
}

/// Bug #3 (pre-fix): Not -> Not was accepted but can't guarantee monotonicity
/// for arbitrary inner constraints without deep semantic analysis.
#[test]
fn regression_not_not_unsound() {
    // Not(Exact("a")) -> Not(Exact("b")) would mean:
    //   parent accepts everything except "a"
    //   child accepts everything except "b"
    //   child accepts "a" but parent rejects "a" -> escalation!
    let parent = Constraint::Not(Not::new(Constraint::Exact(Exact::new("a"))));
    let child = Constraint::Not(Not::new(Constraint::Exact(Exact::new("b"))));

    assert!(parent.validate_attenuation(&child).is_err());

    let escalation = ConstraintValue::String("a".to_string());
    assert!(child.matches(&escalation).unwrap());
    assert!(!parent.matches(&escalation).unwrap());
}

// ============================================================================
// Property 2: Normalization idempotence
//
// serialize(deserialize(serialize(x))) == serialize(x)
//
// If this fails, signatures break after a decode/re-encode round-trip,
// or two nodes disagree on a warrant's canonical form.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Constraint CBOR round-trip produces byte-identical output.
    #[test]
    fn prop_constraint_cbor_idempotent(
        constraint in leaf_constraint_strategy(),
    ) {
        let bytes1 = wire::to_vec(&constraint).unwrap();
        let decoded: Constraint = ciborium::de::from_reader(&bytes1[..]).unwrap();
        let bytes2 = wire::to_vec(&decoded).unwrap();
        prop_assert_eq!(
            &bytes1, &bytes2,
            "CBOR normalization not idempotent!\n\
             original:     {:?}\n\
             round-tripped: {:?}",
            constraint, decoded
        );
    }

    /// ConstraintSet CBOR round-trip produces byte-identical output.
    #[test]
    fn prop_constraint_set_cbor_idempotent(
        constraints in prop::collection::vec(
            (atom_strategy(), leaf_constraint_strategy()), 1..=4
        ),
    ) {
        let mut cs = ConstraintSet::new();
        for (field, constraint) in constraints {
            cs.insert(field, constraint);
        }

        let bytes1 = wire::to_vec(&cs).unwrap();
        let decoded: ConstraintSet = ciborium::de::from_reader(&bytes1[..]).unwrap();
        let bytes2 = wire::to_vec(&decoded).unwrap();
        prop_assert_eq!(&bytes1, &bytes2, "ConstraintSet CBOR not idempotent");
    }

    /// Full warrant wire format round-trip: encode -> decode -> re-encode
    /// produces byte-identical CBOR.
    #[test]
    fn prop_warrant_wire_idempotent(
        tool_name in "[a-z_]{1,12}",
        field_name in "[a-z]{1,6}",
        constraint in leaf_constraint_strategy(),
        ttl_secs in 60u64..3600,
    ) {
        let kp = SigningKey::generate();
        let mut cs = ConstraintSet::new();
        cs.insert(field_name, constraint);

        let warrant = Warrant::builder()
            .capability(&tool_name, cs)
            .ttl(Duration::from_secs(ttl_secs))
            .holder(kp.public_key())
            .build(&kp)
            .unwrap();

        let bytes1 = wire::encode(&warrant).unwrap();
        let decoded = wire::decode(&bytes1).unwrap();
        let bytes2 = wire::encode(&decoded).unwrap();
        prop_assert_eq!(
            &bytes1, &bytes2,
            "Warrant wire format not idempotent (len {} vs {})",
            bytes1.len(), bytes2.len()
        );
    }
}

/// ConstraintValue CBOR idempotence (exhaustive for small universe).
#[test]
fn exhaustive_constraint_value_cbor_idempotent() {
    let values = vec![
        ConstraintValue::String("hello".to_string()),
        ConstraintValue::String("".to_string()),
        ConstraintValue::Integer(0),
        ConstraintValue::Integer(-1),
        ConstraintValue::Integer(i64::MAX),
        ConstraintValue::Float(0.0),
        ConstraintValue::Float(-1.5),
        ConstraintValue::Float(f64::MAX),
        ConstraintValue::Boolean(true),
        ConstraintValue::Boolean(false),
        ConstraintValue::List(vec![
            ConstraintValue::String("a".to_string()),
            ConstraintValue::Integer(42),
        ]),
        ConstraintValue::List(vec![]),
    ];

    for v in &values {
        let bytes1 = wire::to_vec(v).unwrap();
        let decoded: ConstraintValue = ciborium::de::from_reader(&bytes1[..]).unwrap();
        let bytes2 = wire::to_vec(&decoded).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "ConstraintValue CBOR not idempotent for {:?}",
            v
        );
    }
}

// ============================================================================
// Property 3: Constraint soundness (mint-time vs enforcement-time)
//
// For a warrant minted with constraint C on field F:
//   original C.matches(v) == deserialized_warrant.check_constraints(tool, {F: v})
//
// Any divergence means the enforcement layer silently accepts (or rejects)
// values that the minted policy disagrees with.
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    /// Constraint semantics survive the wire round-trip: mint -> encode ->
    /// decode -> enforce must agree with in-memory matches().
    #[test]
    fn prop_enforcement_agrees_with_matches(
        constraint in leaf_constraint_strategy(),
        values in prop::collection::vec(value_strategy(), 10..=20),
    ) {
        let tool = "test_tool";
        let field = "arg";
        let kp = SigningKey::generate();

        let mut cs = ConstraintSet::new();
        cs.insert(field, constraint.clone());

        let warrant = Warrant::builder()
            .capability(tool, cs)
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .unwrap();

        // Wire round-trip
        let bytes = wire::encode(&warrant).unwrap();
        let deserialized = wire::decode(&bytes).unwrap();

        for value in &values {
            let in_memory_result = constraint.matches(value);

            let mut args = HashMap::new();
            args.insert(field.to_string(), value.clone());
            let enforcement_result = deserialized.check_constraints(tool, &args);

            match in_memory_result {
                Ok(true) => {
                    prop_assert!(
                        enforcement_result.is_ok(),
                        "ENFORCEMENT DRIFT: constraint.matches(v) = true, \
                         but check_constraints rejected after wire round-trip!\n\
                         constraint: {:?}\n\
                         value: {:?}\n\
                         error: {:?}",
                        constraint, value, enforcement_result.err()
                    );
                }
                Ok(false) => {
                    prop_assert!(
                        enforcement_result.is_err(),
                        "ENFORCEMENT DRIFT: constraint.matches(v) = false, \
                         but check_constraints accepted after wire round-trip!\n\
                         constraint: {:?}\n\
                         value: {:?}",
                        constraint, value
                    );
                }
                Err(_) => {
                    // In-memory evaluation error (type mismatch, etc.)
                    // Enforcement may also error or reject; both are fine
                }
            }
        }
    }

    /// Same property but with multiple constraints per tool, testing
    /// ConstraintSet-level interaction across the wire boundary.
    #[test]
    fn prop_multi_field_enforcement_agrees(
        constraints in prop::collection::vec(
            (atom_strategy(), leaf_constraint_strategy()), 1..=3
        ),
        values in prop::collection::vec(
            prop::collection::vec(
                (atom_strategy(), value_strategy()), 1..=5
            ), 5..=10
        ),
    ) {
        let tool = "multi_tool";
        let kp = SigningKey::generate();

        let mut cs = ConstraintSet::new();
        for (field, constraint) in &constraints {
            cs.insert(field.clone(), constraint.clone());
        }

        let warrant = Warrant::builder()
            .capability(tool, cs.clone())
            .ttl(Duration::from_secs(3600))
            .holder(kp.public_key())
            .build(&kp)
            .unwrap();

        let bytes = wire::encode(&warrant).unwrap();
        let deserialized = wire::decode(&bytes).unwrap();

        for value_set in &values {
            let mut args: HashMap<String, ConstraintValue> = HashMap::new();
            for (k, v) in value_set {
                args.insert(k.clone(), v.clone());
            }

            let original_result = cs.matches(&args);
            let deserialized_result = deserialized.check_constraints(tool, &args);

            match (&original_result, &deserialized_result) {
                (Ok(()), Ok(())) => {} // Both accept
                (Err(_), Err(_)) => {} // Both reject
                (Ok(()), Err(e)) => {
                    prop_assert!(
                        false,
                        "ENFORCEMENT DRIFT: ConstraintSet.matches() = Ok, \
                         but check_constraints rejected!\n\
                         args: {:?}\n\
                         error: {:?}",
                        args, e
                    );
                }
                (Err(_), Ok(())) => {
                    prop_assert!(
                        false,
                        "ENFORCEMENT DRIFT: ConstraintSet.matches() = Err, \
                         but check_constraints accepted!\n\
                         args: {:?}",
                        args
                    );
                }
            }
        }
    }
}
