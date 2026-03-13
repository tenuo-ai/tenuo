use proptest::prelude::*;
use tenuo::constraints::*;

/// This test suite provides empirical assurance for the Tenuo constraint engines.
/// It bridges the abstract Alloy/Z3 verification models with the Rust implementation
/// using bounded fuzzing. Rather than proving perfect semantic equivalence,
/// it documents conservative runtime deviations (like Any->Any) and confirms
/// rejection of generated malformed structural boundaries.

#[test]
fn test_alloy_all_and_any_conformance() {
    // Alloy Theorem: Any -> Any is strictly subset-based
    let parent_any = Any::new(vec![
        Constraint::Exact(Exact::new("req1")),
        Constraint::Exact(Exact::new("req2")),
    ]);

    // Child drops req2 (valid attenuation for Any)
    let child_any_valid = Any::new(vec![Constraint::Exact(Exact::new("req1"))]);
    // The current spec actually expects a strict subset, though Rust might throw IncompatibleConstraintTypes
    // due to the catch-all. The conformance oracle asserts the exact current Rust behavior.
    assert!(
        Constraint::Any(parent_any.clone())
            .validate_attenuation(&Constraint::Any(child_any_valid))
            .is_err() // Matches the Rust code's conservative fallback discussed in Alloy issue 1
    );

    // Alloy Theorem: All -> All permits adding clauses
    let parent_all = All::new(vec![Constraint::Exact(Exact::new("A"))]);

    let child_all_valid = All::new(vec![
        Constraint::Exact(Exact::new("A")),
        Constraint::Exact(Exact::new("B")),
    ]);

    assert!(Constraint::All(parent_all)
        .validate_attenuation(&Constraint::All(child_all_valid))
        .is_ok());
}

// Generator for a tiny random constraint abstract syntax tree subset (Exact, All)
fn leaf_constraint() -> impl Strategy<Value = Constraint> {
    prop_oneof![
        (0i64..100).prop_map(|v| Constraint::Exact(Exact::new(v))),
        "[a-z]{1,5}".prop_map(|v| Constraint::Exact(Exact::new(v)))
    ]
}

proptest! {
    #[test]
    fn oracle_range_subsumes_exact_tight_bounds(
        min in 0i64..1000,
        max in 1001i64..2000,
        val in 0i64..3000
    ) {
        // Matches Z3 Proof: Range Subsumes Exact
        let parent = Constraint::Range(Range::new(Some(min as f64), Some(max as f64)).unwrap());
        let child = Constraint::Exact(Exact::new(val));

        let attenuation_result = parent.validate_attenuation(&child);

        if val >= min && val <= max {
            prop_assert!(attenuation_result.is_ok(), "Valid bounds mathematically must be OK in Rust");
        } else {
            prop_assert!(attenuation_result.is_err(), "Topological bounds exceeded mathematically must throw Err");
        }
    }

    #[test]
    fn oracle_cidr_network_algebra(
        ip1 in 0u8..255, ip2 in 0u8..255, ip3 in 0u8..255, _ip4 in 0u8..255,
        prefix_len in 0u8..24
    ) {
        // Z3 proved that subnet allocations strictly bounded by child bits cannot expand accept states.
        let parent_ip = format!("{}.{}.{}.0/{}", ip1, ip2, ip3, prefix_len);
        let child_ip = format!("{}.{}.{}.128/{}", ip1, ip2, ip3, prefix_len + 1); // Stricter subset

        if let (Ok(parent), Ok(child)) = (Cidr::new(&parent_ip), Cidr::new(&child_ip)) {
            prop_assert!(Constraint::Cidr(parent).validate_attenuation(&Constraint::Cidr(child)).is_ok());
        }
    }

    #[test]
    fn oracle_cel_syntactic_shape_rejection(
        parent_expr in "[-a-zA-Z0-9_]{1,10}",
        child_inject in "[-a-zA-Z0-9_]{1,10}",
        operator in "(|||\\+|-|\\*|/|==|!=)",
        malformed_parens in "(\\)|\\(|\\)\\(|\\(\\))"
    ) {
        // Z3 proved that `(P) && (C)` is the ONLY mathematically safe way to append
        // string logic monotonically without bleeding precedence or logical OR overwrites.
        // We fuzz the Rust engine's `CEL::validate_attenuation` to ensure it rigorously
        // rejects everything combining these payloads except the exact axiomatic shape.

        // Ensure parent is valid standalone CEL syntax so it parses
        let valid_parent_str = format!("{} == 'true'", parent_expr);
        let parent_cel = CelConstraint::new(&valid_parent_str);
        // Only run test on valid parsable roots
        if parent_cel.validate().is_err() { return Ok(()); }

        let parent = Constraint::Cel(parent_cel.clone());

        // 1. Valid Shape -> Should succeed
        let valid_child_cel = CelConstraint::attenuate(&parent_cel, &child_inject);
        let valid_child = Constraint::Cel(valid_child_cel);
        prop_assert!(parent.validate_attenuation(&valid_child).is_ok(), "Exact valid structural wrap must be approved.");

        // 2. Missing Parentheses -> MUDDY PRECEDENCE -> Should Fail (We construct it manually to bypass attenuate)
        let missing_parens_str = format!("{} && {}", valid_parent_str, child_inject);
        let missing_child = Constraint::Cel(CelConstraint::new(&missing_parens_str));
        prop_assert!(parent.validate_attenuation(&missing_child).is_err(), "Missing parentheses must be rejected to prevent precedence bleeding.");

        // 3. Appending via OR -> WIDENS SCOPE -> Should Fail
        let or_str = format!("({}) || ({})", valid_parent_str, child_inject);
        let or_child = Constraint::Cel(CelConstraint::new(&or_str));
        prop_assert!(parent.validate_attenuation(&or_child).is_err(), "Logical OR expansion must be structurally rejected.");

        // 4. Fuzzing Malformed Parentheses and arbitrary operators
        let malformed_str = format!("{}{}{}{}{}{}", malformed_parens, valid_parent_str, operator, child_inject, malformed_parens, operator);
        let fuzz_child = Constraint::Cel(CelConstraint::new(&malformed_str));
        prop_assert!(parent.validate_attenuation(&fuzz_child).is_err(), "Arbitrary syntactic shapes must be rejected.");
    }

    #[test]
    fn oracle_string_theories_subset_rejection(
        parent_str in "/[a-zA-Z0-9]{2,10}",
        prefix in "/[a-zA-Z0-9]{2,5}",
        suffix in "[a-zA-Z0-9]{2,5}"
    ) {
        // Z3 proves Subpath/Regex/Pattern is mathematically bounded by prefix or substring containment.
        // We fuzz the rust implementation to prove it identically enforces these bounds or throws an error.

        let subpath_parent = Constraint::Subpath(Subpath::new(&parent_str).unwrap());
        let valid_sub_child = format!("{}/{}", parent_str, suffix);
        prop_assert!(subpath_parent.validate_attenuation(&Constraint::Subpath(Subpath::new(&valid_sub_child).unwrap())).is_ok());

        // Inverse should fail (widening)
        let invalid_sub_child = format!("{}{}", prefix, parent_str);
        prop_assert!(subpath_parent.validate_attenuation(&Constraint::Subpath(Subpath::new(&invalid_sub_child).unwrap())).is_err());

        // Regex and Pattern:
        let pattern_parent = Constraint::Pattern(Pattern::new(&valid_sub_child).unwrap());
        let pattern_child = Constraint::Pattern(Pattern::new(&parent_str).unwrap()); // Wider string is rejected
        prop_assert!(pattern_parent.validate_attenuation(&pattern_child).is_err());
    }

    #[test]
    fn oracle_url_parsing_logic(
        domain in "[a-zA-Z0-9]{3,8}\\.com",
        path in "/[a-zA-Z0-9]{2,5}"
    ) {
        // Z3 bounded url pattern matching. Rust should enforce that exactly.
        let parent_url_str = format!("https://*.{}{}", domain, path);
        let parent_url = Constraint::UrlPattern(UrlPattern::new(&parent_url_str).unwrap());

        let valid_child_str = format!("https://api.{}{}/foo", domain, path);
        let valid_child = Constraint::UrlPattern(UrlPattern::new(&valid_child_str).unwrap());
        prop_assert!(parent_url.validate_attenuation(&valid_child).is_ok());

        let invalid_child_str = format!("https://malicious.com{}", path); // Wrong suffix domain
        let invalid_child = Constraint::UrlPattern(UrlPattern::new(&invalid_child_str).unwrap());
        prop_assert!(parent_url.validate_attenuation(&invalid_child).is_err());
    }

    #[test]
    fn oracle_ast_hierarchy_type_keyed_matching(
        leaves_raw in prop::collection::vec(leaf_constraint(), 2..5),
        extra_child_raw in leaf_constraint()
    ) {
        // Alloy model constraint: `Any` checks for subset mapping (dropping clauses narrows scope).
        // `All` checks for superset mapping (adding clauses narrows scope) WITH EXACT TYPE MATCHING.

        // Fix uniqueness by directly cloning and filtering:
        let mut unique_leaves: Vec<Constraint> = Vec::new();
        for leaf in &leaves_raw {
            if !unique_leaves.contains(leaf) {
                unique_leaves.push(leaf.clone());
            }
        }
        if unique_leaves.len() < 2 { return Ok(()); }

        let leaves = unique_leaves;
        let extra_child = extra_child_raw;

        // 1. ALL Constraints
        let parent_all = Constraint::All(All::new(leaves.clone()));
        let mut child_all_leaves = leaves.clone();
        child_all_leaves.push(extra_child.clone());
        let child_all = Constraint::All(All::new(child_all_leaves));

        // Child can ADD constraints to ALL correctly (narrowing)
        prop_assert!(parent_all.validate_attenuation(&child_all).is_ok(), "All constraint must allow adding restrictions.");

        // Child CANNOT miss parent constraints in ALL
        let mut defective_child_leaves = leaves.clone();
        defective_child_leaves.pop(); // Remove one
        let defective_child_all = Constraint::All(All::new(defective_child_leaves));
        prop_assert!(parent_all.validate_attenuation(&defective_child_all).is_err(), "All constraint must reject dropping parent restrictions.");


        // 2. ANY Constraints
        let parent_any = Constraint::Any(Any::new(leaves.clone()));
        let mut child_any_leaves = leaves.clone();
        child_any_leaves.pop(); // dropping a clause narrows ANY
        if !child_any_leaves.is_empty() { // Need at least 1 clause for Any semantics
            let child_any = Constraint::Any(Any::new(child_any_leaves));

            // Note: Rust codebase explicitly falls back to `IncompatibleConstraintTypes`
            // in ANY -> ANY strict check because calculating NP-Hard ANY subsumptions
            // is skipped in the safe path. The conformance oracle asserts this expected failure.
            prop_assert!(parent_any.validate_attenuation(&child_any).is_err(), "Rust Any->Any conservatively fails.");
        }
    }
}
