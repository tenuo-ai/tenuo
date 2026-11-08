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

// ---------------------------------------------------------------------------
// Property: rewriting an argument's integers as floats, or its integral
// floats as integers, never changes a decision. The rule side is respelled
// too, so both directions are covered.
// ---------------------------------------------------------------------------

mod respelling {
    use super::*;
    use proptest::prelude::*;

    /// Integers, integral floats, fractional floats and a few strings, drawn
    /// from a small range so rules and arguments often hold the same number.
    fn scalar() -> impl Strategy<Value = ConstraintValue> {
        prop_oneof![
            (-20i64..20).prop_map(Integer),
            (-20i64..20).prop_map(|i| Float(i as f64)),
            (-40i64..40).prop_map(|i| Float(i as f64 / 2.0)),
            prop::sample::select(&["a", "b", "1"][..])
                .prop_map(|s| ConstraintValue::String(s.into())),
        ]
    }

    fn value() -> impl Strategy<Value = ConstraintValue> {
        prop_oneof![
            3 => scalar(),
            1 => prop::collection::vec(scalar(), 0..4).prop_map(ConstraintValue::List),
        ]
    }

    /// The same value with every integer written as a float and every
    /// integral float written as an integer.
    fn respell(v: &ConstraintValue) -> ConstraintValue {
        match v {
            Integer(i) => Float(*i as f64),
            Float(f) if f.fract() == 0.0 && f.abs() < 1e15 => Integer(*f as i64),
            ConstraintValue::List(l) => ConstraintValue::List(l.iter().map(respell).collect()),
            ConstraintValue::Object(m) => {
                ConstraintValue::Object(m.iter().map(|(k, v)| (k.clone(), respell(v))).collect())
            }
            other => other.clone(),
        }
    }

    /// Every value-equality rule built from `v` and `others`.
    fn rules(v: &ConstraintValue, others: &[ConstraintValue]) -> Vec<Constraint> {
        let mut set = vec![v.clone()];
        set.extend(others.iter().cloned());
        vec![
            Constraint::Exact(Exact::new(v.clone())),
            Constraint::OneOf(OneOf::from_values(set.clone())),
            Constraint::NotOneOf(NotOneOf::from_values(set.clone())),
            Constraint::Not(Not::new(Constraint::Exact(Exact::new(v.clone())))),
            Constraint::Contains(Contains::new(set.clone())),
            Constraint::Subset(Subset::new(set)),
        ]
    }

    fn decide(rule: &Constraint, arg: &ConstraintValue) -> Option<bool> {
        rule.matches(arg).ok()
    }

    fn gate_decision(rule: &Constraint, arg: &ConstraintValue) -> String {
        let gates = gate_on_amount(ArgApprovalGate::Constraint(rule.clone()));
        let args: HashMap<String, ConstraintValue> = [("amount".to_string(), arg.clone())].into();
        format!(
            "{:?}",
            approval_requirement(Some(&gates), "pay", &args).ok()
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn decisions_ignore_number_spelling(
            rule_value in value(),
            others in prop::collection::vec(scalar(), 0..3),
            arg in value(),
        ) {
            let respelled_arg = respell(&arg);
            for rule in rules(&rule_value, &others)
                .into_iter()
                .chain(rules(&respell(&rule_value), &others))
            {
                prop_assert_eq!(
                    decide(&rule, &arg),
                    decide(&rule, &respelled_arg),
                    "{:?} decided {:?} and {:?} differently", rule, arg, respelled_arg
                );
                prop_assert_eq!(
                    gate_decision(&rule, &arg),
                    gate_decision(&rule, &respelled_arg),
                    "gate {:?} decided {:?} and {:?} differently", rule, arg, respelled_arg
                );
            }
        }

        #[cfg(feature = "cel")]
        #[test]
        fn cel_ignores_number_spelling(n in -20i64..20, lit in -20i64..20) {
            use tenuo::cel::evaluate_with_value_context;
            for expr in [
                format!("value == {lit}"),
                format!("value != {lit}"),
                format!("value in [{lit}, 3]"),
                format!("value >= {lit}"),
            ] {
                prop_assert_eq!(
                    evaluate_with_value_context(&expr, &Integer(n)).ok(),
                    evaluate_with_value_context(&expr, &Float(n as f64)).ok(),
                    "`{}` with {}", expr, n
                );
            }
        }
    }
}

/// The shared `_meta.tenuo` vectors list argument JSON that must sign alike
/// (`{"n":1}` and `{"n":1.0}`). They must also authorize alike, whether a
/// rule sees the signed map or the extracted one.
#[test]
fn shared_equivalent_vectors_authorize_alike() {
    use tenuo::meta_envelope::args_from_json;
    let suite: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/tenuo-meta-conformance.json"
    ))
    .unwrap();
    let extracted = |text: &str| -> HashMap<String, ConstraintValue> {
        let json: serde_json::Value = serde_json::from_str(text).unwrap();
        json.as_object()
            .unwrap()
            .keys()
            .filter_map(|k| extract_json_path(&json, k).map(|v| (k.clone(), v)))
            .collect()
    };
    let mut checked = 0;
    for case in suite["valid"].as_array().unwrap() {
        let (args, equivalent) = (
            case["args"].as_str().unwrap(),
            case["equivalent"].as_str().unwrap(),
        );
        let views = [
            ("signed args", args_from_json(args).unwrap()),
            ("signed equivalent", args_from_json(equivalent).unwrap()),
            ("extracted args", extracted(args)),
            ("extracted equivalent", extracted(equivalent)),
        ];
        let reference = &views[0].1;
        for (key, value) in reference {
            let rules = [
                Constraint::Exact(Exact::new(value.clone())),
                Constraint::NotOneOf(NotOneOf::from_values(vec![value.clone()])),
            ];
            for rule in &rules {
                let expected = rule.matches(value).unwrap();
                for (name, view) in &views {
                    let got = view.get(key).map(|v| rule.matches(v).unwrap());
                    assert_eq!(
                        got,
                        Some(expected),
                        "{name} of {args} / {equivalent}: {rule:?} on `{key}`"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 0, "no vector arguments were checked");
}
