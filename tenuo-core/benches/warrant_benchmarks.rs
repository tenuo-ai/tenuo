//! Benchmarks for Tenuo warrant operations and constraint types.
//!
//! # Methodology notes (read before interpreting numbers)
//!
//! - Criterion defaults (3 s warmup, 5 s measurement, 100 samples) are used
//!   for sub-millisecond benches. `chain_verify` bumps `measurement_time` to
//!   10 s because its deepest variants (depth 32/64) run in the milliseconds
//!   and need more samples to stabilize.
//! - Primitive benches (`constraints/*`, `cidr/*`, `url_pattern/*`, `subpath/*`,
//!   `url_safe/*`, `authorize_deny_*`) use a single fixed input per benchmark.
//!   They are intentionally a "per-primitive ceiling": they warm the regex,
//!   CIDR, and URL parser caches and then measure the fast path. Do not quote
//!   them as representative policy cost.
//! - `authorize_no_crypto/mixed_{allow,deny}` rotate across a small input pool
//!   via `iter_batched` so the caches cannot fully warm on a single value pair.
//!   These are the numbers to cite when comparing to Cedar / OPA or describing
//!   realistic policy evaluation cost.
//! - `chain_verify` is measured in two variants: `shared_key` (every link signed
//!   by the same keypair, which is the protocol *floor* because Ed25519 batch
//!   verification can collapse scalars on repeated public keys) and
//!   `distinct_keys` (every link signed by a different keypair, which is what
//!   real delegation chains look like). Cite `distinct_keys` as the realistic
//!   number.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use std::collections::HashMap;
use std::time::Duration;
use tenuo::{
    constraints::{
        Cidr, ConstraintSet, ConstraintValue, Exact, Pattern, Range, Subpath, UrlPattern, UrlSafe,
    },
    crypto::SigningKey,
    planes::DataPlane,
    warrant::Warrant,
    wire,
};

fn benchmark_warrant_creation(c: &mut Criterion) {
    let keypair = SigningKey::generate();
    let holder_pk = keypair.public_key();
    let ttl_short = Duration::from_secs(60);
    let ttl_long = Duration::from_secs(600);

    c.bench_function("warrant_create_minimal", |b| {
        b.iter(|| {
            Warrant::builder()
                .capability("test", ConstraintSet::new())
                .ttl(ttl_short)
                .holder(holder_pk.clone())
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
                .ttl(ttl_long)
                .holder(holder_pk.clone())
                .build(black_box(&keypair))
                .unwrap()
        })
    });

    c.bench_function("warrant_create_multi_tool", |b| {
        let constraints_template = ConstraintSet::from_iter(vec![(
            "path".to_string(),
            Pattern::new("/data/*").unwrap().into(),
        )]);
        // Precompute tool names so we don't allocate 10 strings per iteration.
        let tool_names: Vec<String> = (0..10).map(|i| format!("tool_{}", i)).collect();

        b.iter(|| {
            let mut builder = Warrant::builder().ttl(ttl_long).holder(holder_pk.clone());

            for name in &tool_names {
                builder = builder.capability(name.as_str(), constraints_template.clone());
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
        .holder(keypair.public_key())
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
        .holder(keypair.public_key())
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
    let pop_sig = warrant.sign(&keypair, "upgrade_cluster", &args).unwrap();

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
        .holder(parent_keypair.public_key())
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

/// Measure the authorize path with crypto stripped out.
///
/// `check_constraints` performs exactly what `authorize` does *minus* PoP
/// signature verification: tool-name lookup + full `ConstraintSet::matches`
/// loop over every constraint on the warrant. The delta between this and
/// `warrant_authorize` is the cost of the Ed25519 PoP verify on the hot path.
///
/// # Primitive ceiling: `constraints_N`
///
/// Sweeps 1/2/5/10 simple `Pattern` constraints on the happy path with stable
/// inputs. This is a *best-case* number: only one constraint type, trivial
/// prefix globs, no failure path. Useful for showing per-constraint marginal
/// cost but *not* representative of a production warrant.
///
/// # Realistic mix: `mixed_allow` / `mixed_deny`
///
/// Six-constraint warrant reflecting a plausible production capability
/// (one each of `Exact`, `Pattern`, `Range`, `Cidr`, `UrlPattern`, `Subpath`).
/// Inputs are rotated across iterations via `iter_batched` so the regex/DNS
/// caches can't fully warm on a single value pair. Both the allow path (all
/// constraints match) and a deny path (one constraint fails) are measured.
/// Cite these numbers, not `constraints_N`, when comparing against Cedar/OPA
/// or quoting a representative policy-only cost.
fn benchmark_constraint_authorize_no_crypto(c: &mut Criterion) {
    let keypair = SigningKey::generate();

    let mut group = c.benchmark_group("authorize_no_crypto");

    // --- Primitive ceiling: sweep over simple Pattern constraints -----------
    for &n_constraints in &[1usize, 2, 5, 10] {
        let mut constraints_vec = Vec::with_capacity(n_constraints);
        let mut args = HashMap::with_capacity(n_constraints);
        for i in 0..n_constraints {
            let field = format!("field_{}", i);
            let pattern = format!("value-{}-*", i);
            let matching = format!("value-{}-ok", i);
            constraints_vec.push((field.clone(), Pattern::new(&pattern).unwrap().into()));
            args.insert(field, ConstraintValue::String(matching));
        }
        let constraints = ConstraintSet::from_iter(constraints_vec);

        let warrant = Warrant::builder()
            .capability("test_tool", constraints)
            .ttl(Duration::from_secs(600))
            .holder(keypair.public_key())
            .build(&keypair)
            .unwrap();

        group.bench_function(format!("constraints_{}", n_constraints), |b| {
            b.iter(|| {
                warrant
                    .check_constraints(black_box("test_tool"), black_box(&args))
                    .unwrap()
            })
        });
    }

    // --- Realistic mix: 6 distinct constraint types -------------------------
    //
    // Mirrors the shape of a plausible infra-ops capability: deploy-like
    // operation with environment pinning, cluster/region glob, replica range,
    // source-IP CIDR gate, callback URL pattern, and filesystem subpath.
    let mixed_constraints = ConstraintSet::from_iter(vec![
        ("environment".to_string(), Exact::new("production").into()),
        (
            "cluster".to_string(),
            Pattern::new("us-west-*").unwrap().into(),
        ),
        (
            "replicas".to_string(),
            Range::new(Some(1.0), Some(100.0)).unwrap().into(),
        ),
        (
            "source_ip".to_string(),
            Cidr::new("10.0.0.0/8").unwrap().into(),
        ),
        (
            "target_url".to_string(),
            UrlPattern::new("https://api.example.com/v1/*")
                .unwrap()
                .into(),
        ),
        (
            "file_path".to_string(),
            Subpath::new("/data").unwrap().into(),
        ),
    ]);
    let mixed_warrant = Warrant::builder()
        .capability("deploy_service", mixed_constraints)
        .ttl(Duration::from_secs(600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Small pool of valid argument bundles. Rotating across iterations keeps
    // the regex engine and IP parser from caching a single hot pair.
    let allow_pool: Vec<HashMap<String, ConstraintValue>> = vec![
        HashMap::from([
            (
                "environment".to_string(),
                ConstraintValue::String("production".to_string()),
            ),
            (
                "cluster".to_string(),
                ConstraintValue::String("us-west-2".to_string()),
            ),
            ("replicas".to_string(), ConstraintValue::Float(10.0)),
            (
                "source_ip".to_string(),
                ConstraintValue::String("10.0.1.2".to_string()),
            ),
            (
                "target_url".to_string(),
                ConstraintValue::String("https://api.example.com/v1/users".to_string()),
            ),
            (
                "file_path".to_string(),
                ConstraintValue::String("/data/reports/q1.csv".to_string()),
            ),
        ]),
        HashMap::from([
            (
                "environment".to_string(),
                ConstraintValue::String("production".to_string()),
            ),
            (
                "cluster".to_string(),
                ConstraintValue::String("us-west-1".to_string()),
            ),
            ("replicas".to_string(), ConstraintValue::Float(50.0)),
            (
                "source_ip".to_string(),
                ConstraintValue::String("10.42.99.17".to_string()),
            ),
            (
                "target_url".to_string(),
                ConstraintValue::String("https://api.example.com/v1/orders/123".to_string()),
            ),
            (
                "file_path".to_string(),
                ConstraintValue::String("/data/exports/2026/jan.json".to_string()),
            ),
        ]),
        HashMap::from([
            (
                "environment".to_string(),
                ConstraintValue::String("production".to_string()),
            ),
            (
                "cluster".to_string(),
                ConstraintValue::String("us-west-3".to_string()),
            ),
            ("replicas".to_string(), ConstraintValue::Float(1.0)),
            (
                "source_ip".to_string(),
                ConstraintValue::String("10.200.0.1".to_string()),
            ),
            (
                "target_url".to_string(),
                ConstraintValue::String("https://api.example.com/v1/health".to_string()),
            ),
            (
                "file_path".to_string(),
                ConstraintValue::String("/data/logs/audit.log".to_string()),
            ),
        ]),
    ];
    let allow_pool_clone = allow_pool.clone();

    group.bench_function("mixed_allow", |b| {
        let mut idx = 0usize;
        b.iter_batched(
            || {
                let args = allow_pool_clone[idx % allow_pool_clone.len()].clone();
                idx = idx.wrapping_add(1);
                args
            },
            |args| {
                mixed_warrant
                    .check_constraints(black_box("deploy_service"), black_box(&args))
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    // Deny path: same warrant, one constraint flipped to fail. We rotate which
    // field fails so we don't always fail on the same index in BTreeMap order.
    let deny_pool: Vec<HashMap<String, ConstraintValue>> = vec![
        {
            let mut a = allow_pool[0].clone();
            a.insert(
                "replicas".to_string(),
                ConstraintValue::Float(500.0), // out of Range(1..100)
            );
            a
        },
        {
            let mut a = allow_pool[1].clone();
            a.insert(
                "source_ip".to_string(),
                ConstraintValue::String("192.168.1.1".to_string()), // outside 10.0.0.0/8
            );
            a
        },
        {
            let mut a = allow_pool[2].clone();
            a.insert(
                "target_url".to_string(),
                ConstraintValue::String("https://evil.example.com/v1/exfil".to_string()),
            );
            a
        },
        {
            let mut a = allow_pool[0].clone();
            a.insert(
                "file_path".to_string(),
                ConstraintValue::String("/etc/passwd".to_string()), // outside /data subpath
            );
            a
        },
    ];

    group.bench_function("mixed_deny", |b| {
        let mut idx = 0usize;
        b.iter_batched(
            || {
                let args = deny_pool[idx % deny_pool.len()].clone();
                idx = idx.wrapping_add(1);
                args
            },
            |args| {
                let result =
                    mixed_warrant.check_constraints(black_box("deploy_service"), black_box(&args));
                assert!(result.is_err());
            },
            BatchSize::SmallInput,
        )
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
        .holder(keypair.public_key())
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
                .holder(keypair.public_key())
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

/// Build a pre-signed delegation chain where every link is signed by the
/// *same* keypair (holder == issuer at every hop). This is the protocol floor
/// for `verify_chain`: Ed25519 batch verification does a multi-scalar
/// multiplication over `(A_i, h_i, s_i, R_i)` tuples, and when all `A_i` are
/// the same public key the MSM can collapse scalar coefficients on `A`.
/// Real delegation chains have distinct `A_i` at every link; use
/// `build_chain_distinct_keys` for that. Kept for parity with older numbers
/// and to bound the best-case side.
fn build_chain_shared_key(keypair: &SigningKey, depth: usize) -> Vec<Warrant> {
    assert!((1..=64).contains(&depth), "depth must be in [1, 64]");
    let mut chain = Vec::with_capacity(depth);
    let root = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(keypair)
        .unwrap();
    chain.push(root);
    for _ in 1..depth {
        let next = chain
            .last()
            .unwrap()
            .attenuate()
            .inherit_all()
            .build(keypair)
            .unwrap();
        chain.push(next);
    }
    chain
}

/// Build a pre-signed delegation chain where each link is signed by a
/// distinct keypair, matching a real delegation flow
/// (control-plane -> orchestrator -> planner -> ...). Every hop contributes a
/// distinct public key to the `verify_batch` MSM, so this is the
/// realistic-cost variant of `chain_verify`.
///
/// Structure:
/// - `keys[0]` signs the root; the root's holder is `keys[1]`.
/// - For `i` in `1..depth`, `keys[i]` signs `chain[i]` whose holder is
///   `keys[i + 1]` (or `keys[i]` for the leaf).
/// - Only `keys[0]` needs to be trusted in the `DataPlane`.
fn build_chain_distinct_keys(depth: usize) -> (Vec<SigningKey>, Vec<Warrant>) {
    assert!((1..=64).contains(&depth), "depth must be in [1, 64]");
    // For depth N we need N signing keys (one per link) plus one more to be
    // the leaf's holder. Use N + 1 to cover the leaf's holder cleanly.
    let keys: Vec<SigningKey> = (0..=depth).map(|_| SigningKey::generate()).collect();

    let mut chain = Vec::with_capacity(depth);
    let root = Warrant::builder()
        .capability("test", ConstraintSet::new())
        .ttl(Duration::from_secs(3600))
        .holder(keys[1].public_key())
        .build(&keys[0])
        .unwrap();
    chain.push(root);
    for i in 1..depth {
        let parent = chain.last().unwrap().clone();
        let next = parent
            .attenuate()
            .inherit_all()
            .holder(keys[i + 1].public_key())
            .build(&keys[i])
            .unwrap();
        chain.push(next);
    }
    (keys, chain)
}

/// Measure the hot-path cost of verifying a *pre-built* delegation chain at
/// various depths. This is what a gateway or authorizer sidecar pays on every
/// call when presented with a N-link chain; it is distinct from the one-shot
/// construction cost measured in `benchmark_deep_delegation_chain`.
///
/// Reports two variants per depth:
/// - `shared_key/depth_N` — protocol floor (single keypair throughout).
/// - `distinct_keys/depth_N` — realistic cost (N distinct keypairs, matching
///   a real agent delegation topology). Cite this one.
fn benchmark_chain_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_verify");
    // Deeper variants run in the milliseconds; give Criterion more samples so
    // CV stabilizes for the numbers we put in api-reference.md.
    group
        .measurement_time(Duration::from_secs(10))
        .sample_size(50);

    let shared_keypair = SigningKey::generate();
    let mut shared_plane = DataPlane::new();
    shared_plane.trust_issuer("root", shared_keypair.public_key());

    for &depth in &[1usize, 4, 8, 12, 16, 32, 64] {
        let chain = build_chain_shared_key(&shared_keypair, depth);
        group.bench_function(format!("shared_key/depth_{}", depth), |b| {
            b.iter(|| shared_plane.verify_chain(black_box(&chain)).unwrap())
        });

        let (keys, chain) = build_chain_distinct_keys(depth);
        let mut plane = DataPlane::new();
        plane.trust_issuer("root", keys[0].public_key());
        group.bench_function(format!("distinct_keys/depth_{}", depth), |b| {
            b.iter(|| plane.verify_chain(black_box(&chain)).unwrap())
        });
    }
    group.finish();
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
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Benchmark 1: Wrong tool (fast path - should fail early)
    let valid_args = HashMap::from([(
        "path".to_string(),
        ConstraintValue::String("/data/report.txt".to_string()),
    )]);
    let pop_sig = warrant.sign(&keypair, "read_file", &valid_args).unwrap();

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
    let invalid_pop = warrant.sign(&keypair, "read_file", &invalid_args).unwrap();

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
        .sign(&wrong_keypair, "read_file", &valid_args)
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

fn benchmark_subpath_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("subpath");

    group.bench_function("create", |b| {
        b.iter(|| Subpath::new(black_box("/data/uploads")).unwrap())
    });

    let subpath = Subpath::new("/data").unwrap();
    let valid_path = ConstraintValue::String("/data/file.txt".to_string());
    let nested_path = ConstraintValue::String("/data/a/b/c/d/e/file.txt".to_string());
    let traversal_path = ConstraintValue::String("/data/../etc/passwd".to_string());
    let encoded_traversal = ConstraintValue::String("/data/..%2f..%2fetc/passwd".to_string());

    group.bench_function("matches_valid", |b| {
        b.iter(|| subpath.matches(black_box(&valid_path)).unwrap())
    });

    group.bench_function("matches_nested", |b| {
        b.iter(|| subpath.matches(black_box(&nested_path)).unwrap())
    });

    group.bench_function("blocks_traversal", |b| {
        b.iter(|| {
            let result = subpath.matches(black_box(&traversal_path)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("encoded_traversal_path", |b| {
        b.iter(|| {
            // Note: Subpath doesn't URL-decode, so percent-encoded sequences are treated literally.
            // This tests performance, not blocking behavior. URL-decoding should happen in the
            // application layer before passing paths to Subpath.
            let result = subpath.matches(black_box(&encoded_traversal)).unwrap();
            let _ = result;
        })
    });

    group.finish();
}

fn benchmark_url_safe_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_safe");

    group.bench_function("create_default", |b| b.iter(UrlSafe::new));

    group.bench_function("create_with_domains", |b| {
        b.iter(|| UrlSafe::with_domains(vec!["*.example.com", "api.trusted.io"]))
    });

    let url_safe = UrlSafe::new();
    let public_url = "https://api.example.com/v1/users";
    let metadata_url = "http://169.254.169.254/latest/meta-data/";
    let private_ip_url = "http://10.0.1.50:8080/admin";
    let loopback_url = "http://127.0.0.1:3000/internal";
    let localhost_url = "http://localhost:8080/api";
    let ipv6_mapped_url = "http://[::ffff:169.254.169.254]/metadata";
    let octal_ip_url = "http://0251.0376.0251.0376/metadata"; // Octal encoding of 169.254.169.254

    group.bench_function("allows_public_url", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(public_url)).unwrap();
            assert!(result);
        })
    });

    group.bench_function("blocks_metadata", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(metadata_url)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("blocks_private_ip", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(private_ip_url)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("blocks_loopback", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(loopback_url)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("blocks_localhost", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(localhost_url)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("blocks_ipv6_mapped", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(ipv6_mapped_url)).unwrap();
            assert!(!result);
        })
    });

    group.bench_function("blocks_octal_encoding", |b| {
        b.iter(|| {
            let result = url_safe.is_safe(black_box(octal_ip_url)).unwrap();
            // Octal IP may be normalized by url crate - just measure performance
            let _ = result;
        })
    });

    // Benchmark with domain allowlist
    let url_safe_restricted = UrlSafe::with_domains(vec!["*.example.com"]);
    let allowed_domain = "https://api.example.com/resource";
    let blocked_domain = "https://api.attacker.com/exfil";

    group.bench_function("domain_allowlist_allowed", |b| {
        b.iter(|| {
            let result = url_safe_restricted
                .is_safe(black_box(allowed_domain))
                .unwrap();
            assert!(result);
        })
    });

    group.bench_function("domain_allowlist_blocked", |b| {
        b.iter(|| {
            let result = url_safe_restricted
                .is_safe(black_box(blocked_domain))
                .unwrap();
            assert!(!result);
        })
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
    benchmark_chain_verification,
    benchmark_constraint_evaluation,
    benchmark_constraint_authorize_no_crypto,
    benchmark_cidr_operations,
    benchmark_url_pattern_operations,
    benchmark_subpath_operations,
    benchmark_url_safe_operations,
);

criterion_main!(benches);
