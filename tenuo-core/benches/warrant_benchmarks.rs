//! Benchmarks for Tenuo warrant operations and constraint types.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{Cidr, ConstraintSet, ConstraintValue, Exact, Pattern, Range, UrlPattern},
    crypto::SigningKey,
    warrant::Warrant,
    wire,
};

fn benchmark_warrant_creation(c: &mut Criterion) {
    let keypair = SigningKey::generate();

    c.bench_function("warrant_create_minimal", |b| {
        b.iter(|| {
            Warrant::builder()
                .capability("test", ConstraintSet::new())
                .ttl(Duration::from_secs(60))
                .authorized_holder(keypair.public_key())
                .build(black_box(&keypair))
                .unwrap()
        })
    });

    c.bench_function("warrant_create_with_constraints", |b| {
        let constraints_template = ConstraintSet::from_iter(vec![
            (
                "cluster".to_string(),
                Pattern::new("staging-*").unwrap().into(),
            ),
            (
                "version".to_string(),
                Pattern::new("1.28.*").unwrap().into(),
            ),
            (
                "replicas".to_string(),
                Range::new(Some(1.0), Some(10.0)).unwrap().into(),
            ),
        ]);

        b.iter(|| {
            Warrant::builder()
                .capability("upgrade_cluster", constraints_template.clone())
                .ttl(Duration::from_secs(600))
                .authorized_holder(keypair.public_key())
                .build(black_box(&keypair))
                .unwrap()
        })
    });

    c.bench_function("warrant_create_multi_tool", |b| {
        let constraints_template = ConstraintSet::from_iter(vec![(
            "path".to_string(),
            Pattern::new("/data/*").unwrap().into(),
        )]);

        b.iter(|| {
            let mut builder = Warrant::builder()
                .ttl(Duration::from_secs(600))
                .authorized_holder(keypair.public_key());

            for i in 0..10 {
                builder = builder.capability(format!("tool_{}", i), constraints_template.clone());
            }

            builder.build(black_box(&keypair)).unwrap()
        })
    });
}

fn benchmark_warrant_verification(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability(
            "test",
            ConstraintSet::from_iter(vec![(
                "cluster".to_string(),
                Pattern::new("staging-*").unwrap().into(),
            )]),
        )
        .ttl(Duration::from_secs(600))
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let public_key = keypair.public_key();

    c.bench_function("warrant_verify", |b| {
        b.iter(|| warrant.verify(black_box(&public_key)).unwrap())
    });
}

fn benchmark_warrant_authorization(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let constraints = ConstraintSet::from_iter(vec![
        (
            "cluster".to_string(),
            Pattern::new("staging-*").unwrap().into(),
        ),
        (
            "version".to_string(),
            Pattern::new("1.28.*").unwrap().into(),
        ),
    ]);

    let warrant = Warrant::builder()
        .capability("upgrade_cluster", constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut args = HashMap::new();
    args.insert(
        "cluster".to_string(),
        ConstraintValue::String("staging-web".to_string()),
    );
    args.insert(
        "version".to_string(),
        ConstraintValue::String("1.28.5".to_string()),
    );

    // Create PoP signature for the benchmark
    let pop_sig = warrant
        .create_pop_signature(&keypair, "upgrade_cluster", &args)
        .unwrap();

    c.bench_function("warrant_authorize", |b| {
        b.iter(|| {
            warrant
                .authorize(
                    black_box("upgrade_cluster"),
                    black_box(&args),
                    Some(black_box(&pop_sig)),
                )
                .unwrap()
        })
    });
}

fn benchmark_warrant_attenuation(c: &mut Criterion) {
    let parent_keypair = SigningKey::generate();
    let _child_keypair = SigningKey::generate(); // Unused with new delegation API

    let parent_constraints = ConstraintSet::from_iter(vec![(
        "cluster".to_string(),
        Pattern::new("staging-*").unwrap().into(),
    )]);

    let parent = Warrant::builder()
        .capability("upgrade_cluster", parent_constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(parent_keypair.public_key())
        .build(&parent_keypair)
        .unwrap();

    c.bench_function("warrant_attenuate", |b| {
        let child_constraints_template = ConstraintSet::from_iter(vec![(
            "cluster".to_string(),
            Exact::new("staging-web").into(),
        )]);

        b.iter(|| {
            parent
                .attenuate()
                .capability("upgrade_cluster", child_constraints_template.clone())
                .build(black_box(&parent_keypair)) // Parent signs (they hold the warrant)
                .unwrap()
        })
    });
}

fn benchmark_constraint_evaluation(c: &mut Criterion) {
    let pattern = Pattern::new("staging-*").unwrap();
    let exact = Exact::new("staging-web");
    let range = Range::new(Some(0.0), Some(100.0)).unwrap();

    let matching_val = ConstraintValue::String("staging-web".to_string());
    let number_val = ConstraintValue::Float(50.0);

    let mut group = c.benchmark_group("constraints");

    group.bench_function("pattern_match", |b| {
        b.iter(|| pattern.matches(black_box(&matching_val)).unwrap())
    });

    group.bench_function("exact_match", |b| {
        b.iter(|| exact.matches(black_box(&matching_val)).unwrap())
    });

    group.bench_function("range_check", |b| {
        b.iter(|| range.matches(black_box(&number_val)).unwrap())
    });

    group.finish();
}

fn benchmark_wire_encoding(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let constraints = ConstraintSet::from_iter(vec![
        (
            "cluster".to_string(),
            Pattern::new("staging-*").unwrap().into(),
        ),
        (
            "version".to_string(),
            Pattern::new("1.28.*").unwrap().into(),
        ),
    ]);

    let warrant = Warrant::builder()
        .capability("upgrade_cluster", constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    c.bench_function("wire_encode", |b| {
        b.iter(|| wire::encode(black_box(&warrant)).unwrap())
    });

    let encoded = wire::encode(&warrant).unwrap();

    c.bench_function("wire_decode", |b| {
        b.iter(|| wire::decode(black_box(&encoded)).unwrap())
    });

    c.bench_function("wire_encode_base64", |b| {
        b.iter(|| wire::encode_base64(black_box(&warrant)).unwrap())
    });

    let base64_encoded = wire::encode_base64(&warrant).unwrap();

    c.bench_function("wire_decode_base64", |b| {
        b.iter(|| wire::decode_base64(black_box(&base64_encoded)).unwrap())
    });
}

fn benchmark_deep_delegation_chain(c: &mut Criterion) {
    let keypair = SigningKey::generate();

    c.bench_function("delegation_chain_depth_8", |b| {
        b.iter(|| {
            let mut warrant = Warrant::builder()
                .capability("test", ConstraintSet::new())
                .ttl(Duration::from_secs(3600))
                .authorized_holder(keypair.public_key())
                .build(&keypair)
                .unwrap();

            // Create chain of depth 8 (max allowed)
            for _ in 0..8 {
                warrant = warrant.attenuate().inherit_all().build(&keypair).unwrap();
            }
            warrant
        })
    });
}

fn benchmark_authorization_denials(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let wrong_keypair = SigningKey::generate();

    let constraints = ConstraintSet::from_iter(vec![(
        "path".to_string(),
        Pattern::new("/data/*").unwrap().into(),
    )]);

    let warrant = Warrant::builder()
        .capability("read_file", constraints)
        .ttl(Duration::from_secs(600))
        .authorized_holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Benchmark 1: Wrong tool (fast path - should fail early)
    let valid_args = HashMap::from([(
        "path".to_string(),
        ConstraintValue::String("/data/report.txt".to_string()),
    )]);
    let pop_sig = warrant
        .create_pop_signature(&keypair, "read_file", &valid_args)
        .unwrap();

    c.bench_function("authorize_deny_wrong_tool", |b| {
        b.iter(|| {
            let result = warrant.authorize(
                black_box("write_file"), // Wrong tool
                black_box(&valid_args),
                Some(black_box(&pop_sig)),
            );
            assert!(result.is_err());
        })
    });

    // Benchmark 2: Constraint violation (mid path - pattern matching fails)
    let invalid_args = HashMap::from([(
        "path".to_string(),
        ConstraintValue::String("/etc/passwd".to_string()),
    )]);
    let invalid_pop = warrant
        .create_pop_signature(&keypair, "read_file", &invalid_args)
        .unwrap();

    c.bench_function("authorize_deny_constraint_violation", |b| {
        b.iter(|| {
            let result = warrant.authorize(
                black_box("read_file"),
                black_box(&invalid_args),
                Some(black_box(&invalid_pop)),
            );
            assert!(result.is_err());
        })
    });

    // Benchmark 3: Invalid PoP signature (crypto path - signature verification fails)
    let wrong_pop = warrant
        .create_pop_signature(&wrong_keypair, "read_file", &valid_args)
        .unwrap();

    c.bench_function("authorize_deny_invalid_pop", |b| {
        b.iter(|| {
            let result = warrant.authorize(
                black_box("read_file"),
                black_box(&valid_args),
                Some(black_box(&wrong_pop)),
            );
            assert!(result.is_err());
        })
    });

    // Benchmark 4: Missing PoP signature
    c.bench_function("authorize_deny_missing_pop", |b| {
        b.iter(|| {
            let result = warrant.authorize(
                black_box("read_file"),
                black_box(&valid_args),
                None, // No PoP
            );
            assert!(result.is_err());
        })
    });
}

fn benchmark_cidr_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr");

    group.bench_function("create_ipv4", |b| {
        b.iter(|| Cidr::new(black_box("10.0.0.0/8")).unwrap())
    });

    group.bench_function("create_ipv6", |b| {
        b.iter(|| Cidr::new(black_box("2001:db8::/32")).unwrap())
    });

    let cidr = Cidr::new("10.0.0.0/8").unwrap();
    let ip_in = ConstraintValue::String("10.50.1.2".to_string());

    group.bench_function("matches_ipv4", |b| {
        b.iter(|| cidr.matches(black_box(&ip_in)).unwrap())
    });

    group.finish();
}

fn benchmark_url_pattern_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_pattern");

    group.bench_function("create", |b| {
        b.iter(|| UrlPattern::new(black_box("https://api.example.com/v1/*")).unwrap())
    });

    let pattern = UrlPattern::new("https://*.example.com/v1/*").unwrap();
    let url_match = "https://api.example.com/v1/users";

    group.bench_function("matches", |b| {
        b.iter(|| pattern.matches_url(black_box(url_match)).unwrap())
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_warrant_creation,
    benchmark_warrant_verification,
    benchmark_warrant_authorization,
    benchmark_authorization_denials,
    benchmark_warrant_attenuation,
    benchmark_wire_encoding,
    benchmark_deep_delegation_chain,
    benchmark_constraint_evaluation,
    benchmark_cidr_operations,
    benchmark_url_pattern_operations,
);

criterion_main!(benches);
