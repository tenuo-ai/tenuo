//! An integral number decides the same way however it is spelled.
//!
//! `1000` and `1000.0` are one JSON number. The signed argument map already
//! folds them together; matching must too, in both directions: an integer
//! rule against a float argument, and a float rule against an integer one.

use std::collections::{BTreeMap, HashMap};
use tenuo::{
    approval_gate::{
        approval_requirement, ApprovalGateMap, ApprovalRequirement, ArgApprovalGate,
        ToolApprovalGate,
    },
    constraints::{Constraint, ConstraintValue, Contains, Exact, Not, NotOneOf, OneOf, Subset},
    extraction::extract_json_path,
};

use ConstraintValue::{Float, Integer};

fn int_float_pairs() -> [(ConstraintValue, ConstraintValue); 2] {
    [
        (Integer(1000), Float(1000.0)),
        (Float(1000.0), Integer(1000)),
    ]
}

#[test]
fn value_equality_is_numeric() {
    assert_eq!(Integer(1), Float(1.0));
    assert_eq!(Float(-7.0), Integer(-7));
    assert_ne!(Integer(1), Float(1.5));
    assert_ne!(Integer(1), ConstraintValue::String("1".into()));
    // 2^63 is not an i64; i64::MAX must not equal it.
    assert_ne!(Integer(i64::MAX), Float(9223372036854775808.0));
    // Above 2^53 the float names one integer only.
    assert_ne!(Integer((1 << 53) + 1), Float((1u64 << 53) as f64));
    assert_eq!(
        ConstraintValue::List(vec![Integer(1), Float(2.0)]),
        ConstraintValue::List(vec![Float(1.0), Integer(2)])
    );
    let a: BTreeMap<String, ConstraintValue> = [("n".to_string(), Integer(3))].into();
    let b: BTreeMap<String, ConstraintValue> = [("n".to_string(), Float(3.0))].into();
    assert_eq!(ConstraintValue::Object(a), ConstraintValue::Object(b));
}

#[test]
fn equality_constraints_match_across_spellings() {
    for (rule, arg) in int_float_pairs() {
        let other = Integer(7);
        assert!(Exact::new(rule.clone()).matches(&arg).unwrap());
        assert!(OneOf::from_values(vec![rule.clone()])
            .matches(&arg)
            .unwrap());
        assert!(!NotOneOf::from_values(vec![rule.clone()])
            .matches(&arg)
            .unwrap());
        assert!(NotOneOf::from_values(vec![rule.clone()])
            .matches(&other)
            .unwrap());
        let not = Constraint::Not(Not::new(Constraint::Exact(Exact::new(rule.clone()))));
        assert!(!not.matches(&arg).unwrap());
        let list = ConstraintValue::List(vec![arg.clone()]);
        assert!(Contains::new(vec![rule.clone()]).matches(&list).unwrap());
        assert!(Subset::new(vec![rule.clone()]).matches(&list).unwrap());
    }
}

fn gate_on_amount(gate: ArgApprovalGate) -> ApprovalGateMap {
    let mut args = BTreeMap::new();
    args.insert("amount".to_string(), gate);
    let mut gates = ApprovalGateMap::new();
    gates.insert(
        "pay".to_string(),
        ToolApprovalGate {
            args: Some(args),
            message: None,
        },
    );
    gates
}

#[test]
fn approval_gate_fires_across_spellings() {
    for (rule, arg) in int_float_pairs() {
        let gates = gate_on_amount(ArgApprovalGate::Constraint(Constraint::Exact(Exact::new(
            rule.clone(),
        ))));
        let args: HashMap<String, ConstraintValue> = [("amount".to_string(), arg.clone())].into();
        assert!(
            matches!(
                approval_requirement(Some(&gates), "pay", &args).unwrap(),
                ApprovalRequirement::Required { .. }
            ),
            "gate {rule:?} must fire for {arg:?}"
        );

        // An exemption written one way exempts the value written the other.
        let gates = gate_on_amount(ArgApprovalGate::Exempt(Constraint::Exact(Exact::new(rule))));
        assert!(!matches!(
            approval_requirement(Some(&gates), "pay", &args).unwrap(),
            ApprovalRequirement::Required { .. }
        ));
    }
}

#[test]
fn extraction_folds_integral_floats() {
    let body = serde_json::json!({"amount": 1000.0, "rate": 0.5, "ids": [1.0, 2]});
    assert!(matches!(
        extract_json_path(&body, "amount"),
        Some(Integer(1000))
    ));
    assert!(matches!(extract_json_path(&body, "rate"), Some(Float(f)) if f == 0.5));
    match extract_json_path(&body, "ids") {
        Some(ConstraintValue::List(l)) => {
            assert!(matches!(l.as_slice(), [Integer(1), Integer(2)]))
        }
        other => panic!("expected list, got {other:?}"),
    }
}

#[cfg(feature = "cel")]
#[test]
fn cel_decides_the_same_for_either_spelling() {
    use tenuo::cel::evaluate_with_value_context;
    let eval = |arg: ConstraintValue, expr: &str| {
        let obj = ConstraintValue::Object([("amount".to_string(), arg)].into());
        evaluate_with_value_context(expr, &obj).unwrap()
    };
    for expr in [
        "amount == 1000",
        "amount != 1000",
        "amount in [1000]",
        "!(amount in [1000, 2000])",
        "amount == 1000.0",
        "amount >= 1000",
        "amount < 1000.5",
    ] {
        assert_eq!(
            eval(Integer(1000), expr),
            eval(Float(1000.0), expr),
            "{expr} must not depend on how 1000 is written"
        );
    }
    assert!(eval(Float(1000.0), "amount == 1000"));
    assert!(!eval(Float(1000.0), "amount != 1000"));
    assert!(eval(Float(0.5), "amount == 0.5"));
}
