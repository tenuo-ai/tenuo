//! Benchmarks for Tenuo warrant operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use tenuo_core::{
    constraints::{ConstraintValue, Exact, Pattern, Range},
    crypto::Keypair,
    warrant::Warrant,
    wire,
};

fn benchmark_warrant_creation(c: &mut Criterion) {
    let keypair = Keypair::generate();

    c.bench_function("warrant_create_minimal", |b| {
        b.iter(|| {
            Warrant::builder()
                .tool("test")
                .ttl(Duration::from_secs(60))
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
                .constraint("replicas", Range::new(Some(1.0), Some(10.0)))
                .ttl(Duration::from_secs(600))
                .build(black_box(&keypair))
                .unwrap()
        })
    });
}

fn benchmark_warrant_verification(c: &mut Criterion) {
    let keypair = Keypair::generate();
    let warrant = Warrant::builder()
        .tool("test")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .ttl(Duration::from_secs(600))
        .build(&keypair)
        .unwrap();

    let public_key = keypair.public_key();

    c.bench_function("warrant_verify", |b| {
        b.iter(|| warrant.verify(black_box(&public_key)).unwrap())
    });
}

fn benchmark_warrant_authorization(c: &mut Criterion) {
    let keypair = Keypair::generate();
    let warrant = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .constraint("version", Pattern::new("1.28.*").unwrap())
        .ttl(Duration::from_secs(600))
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

    c.bench_function("warrant_authorize", |b| {
        b.iter(|| {
            warrant
                .authorize(black_box("upgrade_cluster"), black_box(&args), None)
                .unwrap()
        })
    });
}

fn benchmark_warrant_attenuation(c: &mut Criterion) {
    let parent_keypair = Keypair::generate();
    let child_keypair = Keypair::generate();

    let parent = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .ttl(Duration::from_secs(600))
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
    let keypair = Keypair::generate();
    let warrant = Warrant::builder()
        .tool("upgrade_cluster")
        .constraint("cluster", Pattern::new("staging-*").unwrap())
        .constraint("version", Pattern::new("1.28.*").unwrap())
        .ttl(Duration::from_secs(600))
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
    let keypair = Keypair::generate();

    c.bench_function("delegation_chain_depth_10", |b| {
        b.iter(|| {
            let mut warrant = Warrant::builder()
                .tool("test")
                .ttl(Duration::from_secs(3600))
                .build(&keypair)
                .unwrap();

            for _ in 0..10 {
                warrant = warrant.attenuate().build(&keypair, &keypair).unwrap();
            }
            warrant
        })
    });
}

criterion_group!(
    benches,
    benchmark_warrant_creation,
    benchmark_warrant_verification,
    benchmark_warrant_authorization,
    benchmark_warrant_attenuation,
    benchmark_wire_encoding,
    benchmark_deep_delegation_chain,
);

criterion_main!(benches);
