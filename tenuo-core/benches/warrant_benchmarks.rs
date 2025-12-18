//! Benchmarks for Tenuo warrant operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{ConstraintValue, Exact, Pattern, Range},
    crypto::SigningKey,
    warrant::Warrant,
    wire,
};

fn benchmark_warrant_creation(c: &mut Criterion) {
    let keypair = SigningKey::generate();

    c.bench_function("warrant_create_minimal", |b| {
        b.iter(|| {
            Warrant::builder()
                .tool("test")
                .ttl(Duration::from_secs(60))
                .authorized_holder(keypair.public_key())
                .build(black_box(&keypair))
                .unwrap()
        })
    });

    c.bench_function("warrant_create_with_constraints", |b| {
        b.iter(|| {
            Warrant::builder()
                .tool("upgrade_cluster")
                .constraint("cluster", Pattern::new("staging-*").unwrap())
                .constraint("version", Pattern::new("1.28.*").unwrap())
                .constraint("replicas", Range::new(Some(1.0), Some(10.0)).unwrap())
                .ttl(Duration::from_secs(600))
                .authorized_holder(keypair.public_key())
                .build(black_box(&keypair))
                .unwrap()
        })
    });
}

fn benchmark_warrant_verification(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let warrant = Warrant::builder()
        .tool("test")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
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
    let warrant = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .constraint("version", Pattern::new("1.28.*").unwrap())
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
    let child_keypair = SigningKey::generate();

    let parent = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .ttl(Duration::from_secs(600))
        .authorized_holder(parent_keypair.public_key())
        .build(&parent_keypair)
        .unwrap();

    c.bench_function("warrant_attenuate", |b| {
        b.iter(|| {
            parent
                .attenuate()
                .constraint("cluster", Exact::new("staging-web"))
                .build(black_box(&child_keypair), black_box(&parent_keypair))
                .unwrap()
        })
    });
}

fn benchmark_wire_encoding(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let warrant = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .constraint("version", Pattern::new("1.28.*").unwrap())
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
                .tool("test")
                .ttl(Duration::from_secs(3600))
                .authorized_holder(keypair.public_key())
                .build(&keypair)
                .unwrap();

            // Create chain of depth 8 (max allowed)
            for _ in 0..8 {
                warrant = warrant.attenuate().build(&keypair, &keypair).unwrap();
            }
            warrant
        })
    });
}

fn benchmark_authorization_denials(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let wrong_keypair = SigningKey::generate();

    let warrant = Warrant::builder()
        .tool("read_file")
        .constraint("path", Pattern::new("/data/*").unwrap())
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

criterion_group!(
    benches,
    benchmark_warrant_creation,
    benchmark_warrant_verification,
    benchmark_warrant_authorization,
    benchmark_authorization_denials,
    benchmark_warrant_attenuation,
    benchmark_wire_encoding,
    benchmark_deep_delegation_chain,
);

criterion_main!(benches);
