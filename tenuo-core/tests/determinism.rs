use proptest::prelude::*;
use rand::seq::SliceRandom;
use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::Duration;
use tenuo::approval::compute_request_hash;
use tenuo::approval_gate::{
    evaluate_approval_gates, ApprovalGateMap, ArgApprovalGate, ToolApprovalGate,
};
use tenuo::{Authorizer, ConstraintSet, ConstraintValue, SigningKey, Warrant};

const SHUFFLE_RUNS: usize = 16;

fn scalar_value_strategy() -> impl Strategy<Value = ConstraintValue> {
    prop_oneof![
        any::<bool>().prop_map(ConstraintValue::Boolean),
        (-100_000i64..=100_000i64).prop_map(ConstraintValue::Integer),
        (-10_000.0f64..10_000.0f64)
            .prop_filter("finite float", |f| f.is_finite())
            .prop_map(ConstraintValue::Float),
        "[a-zA-Z0-9_\\-]{0,16}".prop_map(ConstraintValue::String),
    ]
}

fn value_strategy() -> impl Strategy<Value = ConstraintValue> {
    let list_item = scalar_value_strategy();
    prop_oneof![
        scalar_value_strategy(),
        prop::collection::vec(list_item, 0..=4).prop_map(ConstraintValue::List),
    ]
}

fn args_strategy() -> impl Strategy<Value = BTreeMap<String, ConstraintValue>> {
    prop::collection::btree_map("[a-z][a-z0-9_]{0,10}", value_strategy(), 0..=10)
}

fn shuffled_hashmaps(
    args: &BTreeMap<String, ConstraintValue>,
    count: usize,
) -> Vec<HashMap<String, ConstraintValue>> {
    let entries: Vec<(String, ConstraintValue)> =
        args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut shuffled = entries.clone();
        shuffled.shuffle(&mut rand::rng());
        let mut map = HashMap::with_capacity(shuffled.len());
        for (k, v) in shuffled {
            map.insert(k, v);
        }
        out.push(map);
    }
    out
}

fn assert_all_equal<T: PartialEq + std::fmt::Debug>(items: &[T], label: &str) {
    assert!(!items.is_empty(), "{label}: expected non-empty output");
    for i in 1..items.len() {
        assert_eq!(items[i], items[0], "{label}: output differs at index {i}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    #[test]
    fn parallel_shuffled_maps_produce_identical_outputs(
        args in args_strategy(),
        timestamp in 1_700_000_000i64..1_900_000_000i64,
    ) {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let tool_name = "determinism.tool";

        let warrant = Warrant::builder()
            .capability(tool_name, ConstraintSet::new())
            .ttl(Duration::from_secs(600))
            .holder(holder.public_key())
            .build(&issuer)
            .expect("warrant should build");

        let mut gated_args = BTreeMap::new();
        gated_args.insert("k0".to_string(), ArgApprovalGate::All);
        let approval_gate_map = ApprovalGateMap(BTreeMap::from([(
            tool_name.to_string(),
            ToolApprovalGate::with_args(gated_args),
        )]));

        let sign_outputs = thread::scope(|scope| {
            let shuffled = shuffled_hashmaps(&args, SHUFFLE_RUNS);
            let mut handles = Vec::with_capacity(SHUFFLE_RUNS);
            for map in shuffled {
                let warrant = &warrant;
                let holder = &holder;
                handles.push(scope.spawn(move || {
                    warrant
                        .sign_with_timestamp(holder, tool_name, &map, Some(timestamp))
                        .expect("sign should succeed")
                        .to_bytes()
                        .to_vec()
                }));
            }
            handles.into_iter().map(|h| h.join().expect("join")).collect::<Vec<_>>()
        });
        assert_all_equal(&sign_outputs, "sign");

        let dedup_outputs = thread::scope(|scope| {
            let shuffled = shuffled_hashmaps(&args, SHUFFLE_RUNS);
            let mut handles = Vec::with_capacity(SHUFFLE_RUNS);
            for map in shuffled {
                let warrant = &warrant;
                handles.push(scope.spawn(move || warrant.dedup_key(tool_name, &map)));
            }
            handles.into_iter().map(|h| h.join().expect("join")).collect::<Vec<_>>()
        });
        assert_all_equal(&dedup_outputs, "dedup_key");

        let request_hash_outputs = thread::scope(|scope| {
            let shuffled = shuffled_hashmaps(&args, SHUFFLE_RUNS);
            let mut handles = Vec::with_capacity(SHUFFLE_RUNS);
            for map in shuffled {
                let warrant = &warrant;
                let holder_pk = holder.public_key();
                handles.push(scope.spawn(move || {
                    compute_request_hash(
                        &warrant.id().to_string(),
                        tool_name,
                        &map,
                        Some(&holder_pk),
                    )
                    .to_vec()
                }));
            }
            handles.into_iter().map(|h| h.join().expect("join")).collect::<Vec<_>>()
        });
        assert_all_equal(&request_hash_outputs, "compute_request_hash");

        let approval_gate_outputs = thread::scope(|scope| {
            let shuffled = shuffled_hashmaps(&args, SHUFFLE_RUNS);
            let mut handles = Vec::with_capacity(SHUFFLE_RUNS);
            for map in shuffled {
                let approval_gate_map = &approval_gate_map;
                handles.push(scope.spawn(move || {
                    evaluate_approval_gates(Some(approval_gate_map), tool_name, &map)
                        .expect("approval gate evaluation should succeed")
                }));
            }
            handles.into_iter().map(|h| h.join().expect("join")).collect::<Vec<_>>()
        });
        assert_all_equal(&approval_gate_outputs, "evaluate_approval_gates");
    }
}

#[test]
fn parallel_check_chain_with_pop_args_serializes_identically() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let tool_name = "determinism.chain";
    let timestamp = chrono::Utc::now().timestamp();

    let warrant = Warrant::builder()
        .capability(tool_name, ConstraintSet::new())
        .ttl(Duration::from_secs(600))
        .holder(holder.public_key())
        .build(&issuer)
        .expect("warrant should build");
    let chain = vec![warrant.clone()];

    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());

    let args = BTreeMap::from([
        ("a".to_string(), ConstraintValue::Integer(1)),
        ("b".to_string(), ConstraintValue::String("x".to_string())),
        ("c".to_string(), ConstraintValue::Boolean(true)),
    ]);

    let outputs = thread::scope(|scope| {
        let shuffled = shuffled_hashmaps(&args, SHUFFLE_RUNS);
        let mut handles = Vec::with_capacity(SHUFFLE_RUNS);
        for map in shuffled {
            let warrant = &warrant;
            let holder = &holder;
            let authorizer = &authorizer;
            let chain = &chain;
            handles.push(scope.spawn(move || {
                let signature = warrant
                    .sign_with_timestamp(holder, tool_name, &map, Some(timestamp))
                    .expect("sign should succeed");

                let result = authorizer
                    .check_chain_with_pop_args(chain, tool_name, &map, &map, Some(&signature), &[])
                    .expect("authorization should succeed");

                let mut bytes = Vec::new();
                ciborium::ser::into_writer(&result, &mut bytes)
                    .expect("result serialization should succeed");
                bytes
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect::<Vec<_>>()
    });

    assert_all_equal(&outputs, "check_chain_with_pop_args result serialization");
}
