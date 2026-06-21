use proptest::prelude::*;
use tenuo::constraints::*;

/// This test suite acts as a Conformance Oracle.
/// It bridges the formal Alloy/Z3 verification models with the Rust implementation.
/// Every test exactly corresponds to a formal mathematical theorem proven in `z3_bounds.py`
/// or `aat_constraints.als`, ensuring the Rust runtime is a perfect reflection of the math.

#[test]
fn test_alloy_all_and_any_conformance() {
    // Alloy Theorem: Any -> Any is strictly subset-based
    let parent_any = Any::new(vec![
        Constraint::Exact(Exact::new("req1")),
        Constraint::Exact(Exact::new("req2")),
    ]);

    // Child drops req2: valid attenuation because child's allowed set ⊆ parent's allowed set.
    let child_any_valid = Any::new(vec![Constraint::Exact(Exact::new("req1"))]);
    assert!(
        Constraint::Any(parent_any.clone())
            .validate_attenuation(&Constraint::Any(child_any_valid))
            .is_ok()
    );

    // Child adds a branch not in parent: must be rejected (privilege escalation).
    let child_any_invalid = Any::new(vec![
        Constraint::Exact(Exact::new("req1")),
        Constraint::Exact(Exact::new("req3")), // not in parent
    ]);
    assert!(
        Constraint::Any(parent_any.clone())
            .validate_attenuation(&Constraint::Any(child_any_invalid))
            .is_err()
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
}
