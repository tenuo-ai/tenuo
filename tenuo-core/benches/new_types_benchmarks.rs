use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tenuo::{
    constraints::{Cidr, ConstraintValue, UrlPattern},
};

fn benchmark_cidr_operations(c: &mut Criterion) {
    c.bench_function("cidr_create_ipv4", |b| {
        b.iter(|| Cidr::new(black_box("10.0.0.0/8")).unwrap())
    });

    c.bench_function("cidr_create_ipv6", |b| {
        b.iter(|| Cidr::new(black_box("2001:db8::/32")).unwrap())
    });

    let cidr = Cidr::new("10.0.0.0/8").unwrap();
    let ip_in = ConstraintValue::String("10.50.1.2".to_string());
    
    c.bench_function("cidr_matches_ipv4_success", |b| {
        b.iter(|| cidr.matches(black_box(&ip_in)).unwrap())
    });
}

fn benchmark_url_operations(c: &mut Criterion) {
    c.bench_function("url_pattern_create", |b| {
        b.iter(|| UrlPattern::new(black_box("https://api.example.com/v1/*")).unwrap())
    });

    let pattern = UrlPattern::new("https://*.example.com/v1/*").unwrap();
    let url_match = "https://api.example.com/v1/users";
    
    c.bench_function("url_matches_success", |b| {
        b.iter(|| pattern.matches_url(black_box(url_match)).unwrap())
    });
}

criterion_group!(
    benches,
    benchmark_cidr_operations,
    benchmark_url_operations,
);

criterion_main!(benches);
