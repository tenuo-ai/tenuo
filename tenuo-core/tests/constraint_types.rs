//! Tests for constraint types that were missing coverage.
//!
//! These tests ensure all 16 constraint types from protocol-spec-v1.md
//! are properly tested in the Rust core, covering both:
//! - `matches()` (authorization-time enforcement)
//! - `validate_attenuation()` (delegation-time monotonicity) via Warrant chains

use std::time::Duration;
use tenuo::{
    constraints::{Cidr, ConstraintSet, Subpath, UrlPattern, UrlSafe},
    crypto::SigningKey,
    warrant::Warrant,
    wire, All, Any, Constraint, Contains, Exact, Not, NotOneOf, OneOf, Pattern, Range, Subset,
};

// =============================================================================
// Cidr Constraint Tests (Type ID: 8)
// =============================================================================

#[test]
fn test_cidr_ipv4_basic_matching() {
    let cidr = Cidr::new("10.0.0.0/8").unwrap();
    let constraint = Constraint::Cidr(cidr);

    // Should match IPs within the range
    assert!(constraint.matches(&"10.0.0.1".into()).unwrap());
    assert!(constraint.matches(&"10.255.255.255".into()).unwrap());
    assert!(constraint.matches(&"10.123.45.67".into()).unwrap());

    // Should not match IPs outside the range
    assert!(!constraint.matches(&"11.0.0.1".into()).unwrap());
    assert!(!constraint.matches(&"192.168.1.1".into()).unwrap());
    assert!(!constraint.matches(&"9.255.255.255".into()).unwrap());
}

#[test]
fn test_cidr_ipv4_specific_subnet() {
    let cidr = Cidr::new("192.168.1.0/24").unwrap();
    let constraint = Constraint::Cidr(cidr);

    assert!(constraint.matches(&"192.168.1.0".into()).unwrap());
    assert!(constraint.matches(&"192.168.1.255".into()).unwrap());
    assert!(constraint.matches(&"192.168.1.100".into()).unwrap());

    assert!(!constraint.matches(&"192.168.0.1".into()).unwrap());
    assert!(!constraint.matches(&"192.168.2.1".into()).unwrap());
}

#[test]
fn test_cidr_ipv6_basic_matching() {
    let cidr = Cidr::new("2001:db8::/32").unwrap();
    let constraint = Constraint::Cidr(cidr);

    assert!(constraint.matches(&"2001:db8::1".into()).unwrap());
    assert!(constraint
        .matches(&"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".into())
        .unwrap());

    assert!(!constraint.matches(&"2001:db9::1".into()).unwrap());
    assert!(!constraint.matches(&"::1".into()).unwrap());
}

#[test]
fn test_cidr_invalid_network() {
    // Invalid CIDR notation
    assert!(Cidr::new("not-a-cidr").is_err());
    assert!(Cidr::new("10.0.0.0/33").is_err()); // Invalid prefix for IPv4
    assert!(Cidr::new("10.0.0.0/-1").is_err());
}

#[test]
fn test_cidr_in_warrant_constraint_set() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert("source_ip", Cidr::new("10.0.0.0/8").unwrap());

    let warrant = Warrant::builder()
        .capability("network_call", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Verify the constraint is in the warrant
    assert!(warrant.capabilities().unwrap().contains_key("network_call"));
}

#[test]
fn test_cidr_attenuation_narrowing() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent has broad network
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("ip", Cidr::new("10.0.0.0/8").unwrap());

    let parent = Warrant::builder()
        .capability("api_call", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child narrows to specific subnet - this should succeed
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("ip", Cidr::new("10.1.0.0/16").unwrap());

    let child_result = parent
        .attenuate()
        .capability("api_call", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(child_result.is_ok(), "Narrowing CIDR should be allowed");
}

// =============================================================================
// UrlPattern Constraint Tests (Type ID: 9)
// =============================================================================

#[test]
fn test_urlpattern_basic_matching() {
    let pattern = UrlPattern::new("https://example.com/*").unwrap();
    let constraint = Constraint::UrlPattern(pattern);

    assert!(constraint.matches(&"https://example.com/".into()).unwrap());
    assert!(constraint
        .matches(&"https://example.com/api/v1".into())
        .unwrap());
    assert!(constraint
        .matches(&"https://example.com/users/123".into())
        .unwrap());

    // Wrong scheme
    assert!(!constraint.matches(&"http://example.com/".into()).unwrap());
    // Wrong host
    assert!(!constraint.matches(&"https://evil.com/".into()).unwrap());
}

#[test]
fn test_urlpattern_wildcard_subdomain() {
    let pattern = UrlPattern::new("https://*.example.com/*").unwrap();
    let constraint = Constraint::UrlPattern(pattern);

    assert!(constraint
        .matches(&"https://api.example.com/".into())
        .unwrap());
    assert!(constraint
        .matches(&"https://www.example.com/path".into())
        .unwrap());

    // Wrong domain
    assert!(!constraint.matches(&"https://api.evil.com/".into()).unwrap());
}

#[test]
fn test_urlpattern_path_constraints() {
    let pattern = UrlPattern::new("https://api.example.com/v1/*").unwrap();
    let constraint = Constraint::UrlPattern(pattern);

    assert!(constraint
        .matches(&"https://api.example.com/v1/users".into())
        .unwrap());
    assert!(constraint
        .matches(&"https://api.example.com/v1/orders/123".into())
        .unwrap());

    // Wrong path prefix
    assert!(!constraint
        .matches(&"https://api.example.com/v2/users".into())
        .unwrap());
    assert!(!constraint
        .matches(&"https://api.example.com/admin".into())
        .unwrap());
}

#[test]
fn test_urlpattern_in_warrant() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert(
        "endpoint",
        UrlPattern::new("https://api.example.com/*").unwrap(),
    );

    let warrant = Warrant::builder()
        .capability("http_request", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    assert!(warrant.capabilities().unwrap().contains_key("http_request"));
}

// =============================================================================
// Any (OR Composite) Constraint Tests (Type ID: 13)
// =============================================================================

#[test]
fn test_any_basic_or_logic() {
    let any_constraint = Constraint::Any(Any::new([
        Constraint::Exact(Exact::new("value1")),
        Constraint::Exact(Exact::new("value2")),
        Constraint::Exact(Exact::new("value3")),
    ]));

    // Should match any of the values
    assert!(any_constraint.matches(&"value1".into()).unwrap());
    assert!(any_constraint.matches(&"value2".into()).unwrap());
    assert!(any_constraint.matches(&"value3".into()).unwrap());

    // Should not match other values
    assert!(!any_constraint.matches(&"value4".into()).unwrap());
    assert!(!any_constraint.matches(&"other".into()).unwrap());
}

#[test]
fn test_any_with_mixed_constraint_types() {
    let any_constraint = Constraint::Any(Any::new([
        Constraint::Exact(Exact::new("exact_match")),
        Constraint::Pattern(Pattern::new("prefix_*").unwrap()),
        Constraint::Range(Range::new(Some(0.0), Some(100.0)).unwrap()),
    ]));

    // Match via exact
    assert!(any_constraint.matches(&"exact_match".into()).unwrap());

    // Match via pattern
    assert!(any_constraint.matches(&"prefix_something".into()).unwrap());

    // Match via range
    assert!(any_constraint.matches(&50.0.into()).unwrap());

    // No match
    assert!(!any_constraint.matches(&"no_match".into()).unwrap());
    assert!(!any_constraint.matches(&200.0.into()).unwrap());
}

#[test]
fn test_any_empty_always_fails() {
    let any_constraint = Constraint::Any(Any::new([]));

    // Empty Any should never match (OR of nothing is false)
    assert!(!any_constraint.matches(&"anything".into()).unwrap());
    assert!(!any_constraint.matches(&42.0.into()).unwrap());
}

#[test]
fn test_any_in_warrant() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert(
        "env",
        Any::new([
            Constraint::Exact(Exact::new("dev")),
            Constraint::Exact(Exact::new("staging")),
        ]),
    );

    let warrant = Warrant::builder()
        .capability("deploy", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    assert!(warrant.capabilities().unwrap().contains_key("deploy"));
}

#[test]
fn test_any_attenuation() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent allows dev, staging, prod
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "env",
        Any::new([
            Constraint::Exact(Exact::new("dev")),
            Constraint::Exact(Exact::new("staging")),
            Constraint::Exact(Exact::new("prod")),
        ]),
    );

    let parent = Warrant::builder()
        .capability("deploy", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child narrows to only dev and staging (removes prod)
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "env",
        Any::new([
            Constraint::Exact(Exact::new("dev")),
            Constraint::Exact(Exact::new("staging")),
        ]),
    );

    let child_result = parent
        .attenuate()
        .capability("deploy", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        child_result.is_ok(),
        "Any narrowing (subset of branches) must be a valid attenuation: {:?}",
        child_result.err()
    );
}

#[test]
fn test_any_attenuation_identity() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let env_any = Any::new([
        Constraint::Exact(Exact::new("dev")),
        Constraint::Exact(Exact::new("staging")),
    ]);

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("env", env_any.clone());

    let parent = Warrant::builder()
        .capability("deploy", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("env", env_any);

    let child_result = parent
        .attenuate()
        .capability("deploy", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        child_result.is_ok(),
        "Any identity pass-through must be valid: {:?}",
        child_result.err()
    );
}

#[test]
fn test_any_attenuation_escalation_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("env", Any::new([Constraint::Exact(Exact::new("dev"))]));

    let parent = Warrant::builder()
        .capability("deploy", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child tries to add "prod" which parent never allowed
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "env",
        Any::new([
            Constraint::Exact(Exact::new("dev")),
            Constraint::Exact(Exact::new("prod")),
        ]),
    );

    let child_result = parent
        .attenuate()
        .capability("deploy", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        child_result.is_err(),
        "Any escalation (adding a new branch) must be rejected"
    );
}

// =============================================================================
// Wire Format Round-Trip Tests
// =============================================================================

#[test]
fn test_cidr_wire_roundtrip() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert("ip", Cidr::new("192.168.0.0/16").unwrap());

    let warrant = Warrant::builder()
        .capability("network", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Serialize and deserialize
    let encoded = wire::encode(&warrant).unwrap();
    let decoded = wire::decode(&encoded).unwrap();

    // Verify constraint is preserved
    let caps = decoded.capabilities().unwrap();
    assert!(caps.contains_key("network"));

    // Get the constraint and test it
    let network_caps = caps.get("network").unwrap();
    let ip_constraint = network_caps.get("ip").unwrap();

    assert!(ip_constraint.matches(&"192.168.1.100".into()).unwrap());
    assert!(!ip_constraint.matches(&"10.0.0.1".into()).unwrap());
}

#[test]
fn test_urlpattern_wire_roundtrip() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert("url", UrlPattern::new("https://api.example.com/*").unwrap());

    let warrant = Warrant::builder()
        .capability("fetch", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let encoded = wire::encode(&warrant).unwrap();
    let decoded = wire::decode(&encoded).unwrap();

    let caps = decoded.capabilities().unwrap();
    let url_constraint = caps.get("fetch").unwrap().get("url").unwrap();

    assert!(url_constraint
        .matches(&"https://api.example.com/data".into())
        .unwrap());
    assert!(!url_constraint
        .matches(&"https://evil.com/steal".into())
        .unwrap());
}

#[test]
fn test_any_wire_roundtrip() {
    let keypair = SigningKey::generate();

    let mut constraints = ConstraintSet::new();
    constraints.insert(
        "status",
        Any::new([
            Constraint::Exact(Exact::new("pending")),
            Constraint::Exact(Exact::new("approved")),
        ]),
    );

    let warrant = Warrant::builder()
        .capability("update_order", constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let encoded = wire::encode(&warrant).unwrap();
    let decoded = wire::decode(&encoded).unwrap();

    let caps = decoded.capabilities().unwrap();
    let status_constraint = caps.get("update_order").unwrap().get("status").unwrap();

    assert!(status_constraint.matches(&"pending".into()).unwrap());
    assert!(status_constraint.matches(&"approved".into()).unwrap());
    assert!(!status_constraint.matches(&"rejected".into()).unwrap());
}

// =============================================================================
// Not Constraint Attenuation Tests (Type ID: 14)
// =============================================================================

#[test]
fn test_not_attenuation_identity() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let inner = Not::new(Constraint::Exact(Exact::new("admin")));

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("role", inner.clone());

    let parent = Warrant::builder()
        .capability("admin_panel", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("role", inner);

    let result = parent
        .attenuate()
        .capability("admin_panel", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "Not identity pass-through must be valid: {:?}",
        result.err()
    );
}

#[test]
fn test_not_attenuation_wider_inner_valid() {
    // Parent: Not(Exact("admin")) — excludes only "admin"
    // Child:  Not(OneOf(["admin","root"])) — excludes more, so child is MORE restrictive
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("role", Not::new(Constraint::Exact(Exact::new("admin"))));

    let parent = Warrant::builder()
        .capability("access", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "role",
        Not::new(Constraint::OneOf(OneOf::new(vec!["admin", "root"]))),
    );

    let result = parent
        .attenuate()
        .capability("access", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "Not(Exact) -> Not(OneOf[superset]) must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_not_attenuation_narrower_inner_rejected() {
    // Parent: Not(OneOf(["admin","root"])) — excludes two values
    // Child:  Not(Exact("admin")) — excludes only one, accepts more values → escalation
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "role",
        Not::new(Constraint::OneOf(OneOf::new(vec!["admin", "root"]))),
    );

    let parent = Warrant::builder()
        .capability("access", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("role", Not::new(Constraint::Exact(Exact::new("admin"))));

    let result = parent
        .attenuate()
        .capability("access", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "Not(OneOf[wide]) -> Not(Exact) must be rejected (child accepts more values)"
    );
}

// =============================================================================
// UrlSafe Constraint Attenuation Tests (allow_ports gap)
// =============================================================================

#[test]
fn test_urlsafe_attenuation_port_narrowing_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent_safe = {
        let mut u = UrlSafe::new();
        u.allow_ports = Some(vec![443, 8443]);
        u
    };

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("url", parent_safe);

    let parent = Warrant::builder()
        .capability("fetch", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child narrows to only port 443
    let child_safe = {
        let mut u = UrlSafe::new();
        u.allow_ports = Some(vec![443]);
        u
    };

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("url", child_safe);

    let result = parent
        .attenuate()
        .capability("fetch", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "UrlSafe port subset must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_urlsafe_attenuation_port_escalation_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent_safe = {
        let mut u = UrlSafe::new();
        u.allow_ports = Some(vec![443]);
        u
    };

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("url", parent_safe);

    let parent = Warrant::builder()
        .capability("fetch", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child drops the port allowlist entirely (allows any port — widening)
    let child_safe = UrlSafe::new();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("url", child_safe);

    let result = parent
        .attenuate()
        .capability("fetch", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "Dropping allow_ports from parent must be rejected (privilege escalation)"
    );
}

#[test]
fn test_urlsafe_attenuation_port_new_port_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent_safe = {
        let mut u = UrlSafe::new();
        u.allow_ports = Some(vec![443]);
        u
    };

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("url", parent_safe);

    let parent = Warrant::builder()
        .capability("fetch", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child adds port 80 which parent never allowed
    let child_safe = {
        let mut u = UrlSafe::new();
        u.allow_ports = Some(vec![443, 80]);
        u
    };

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("url", child_safe);

    let result = parent
        .attenuate()
        .capability("fetch", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "Adding a new port not in parent allow_ports must be rejected"
    );
}

// =============================================================================
// Subpath Case-Sensitivity Attenuation Tests
// =============================================================================

#[test]
fn test_subpath_case_sensitive_to_insensitive_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent_path = Subpath::with_options("/data", true, true).unwrap();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("path", parent_path);

    let parent = Warrant::builder()
        .capability("read_file", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child switches to case-insensitive — WIDER (accepts paths differing only by case)
    let child_path = Subpath::with_options("/data", false, true).unwrap();
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("path", child_path);

    let result = parent
        .attenuate()
        .capability("read_file", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "case-sensitive parent -> case-insensitive child must be rejected (child accepts more paths)"
    );
}

#[test]
fn test_subpath_case_insensitive_to_sensitive_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let parent_path = Subpath::with_options("/data", false, true).unwrap();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("path", parent_path);

    let parent = Warrant::builder()
        .capability("read_file", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child switches to case-sensitive — NARROWER (accepts fewer paths)
    let child_path = Subpath::with_options("/data", true, true).unwrap();
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("path", child_path);

    let result = parent
        .attenuate()
        .capability("read_file", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "case-insensitive parent -> case-sensitive child must be valid (child is more restrictive): {:?}",
        result.err()
    );
}

// =============================================================================
// NotOneOf Attenuation Tests (Type ID: 6)
// =============================================================================

#[test]
fn test_notoneof_attenuation_adding_exclusions_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent excludes only "admin"
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("role", NotOneOf::new(vec!["admin"]));

    let parent = Warrant::builder()
        .capability("action", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child excludes "admin" AND "root" — more restrictive
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("role", NotOneOf::new(vec!["admin", "root"]));

    let result = parent
        .attenuate()
        .capability("action", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "NotOneOf adding more exclusions must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_notoneof_attenuation_removing_exclusion_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent excludes "admin" AND "root"
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("role", NotOneOf::new(vec!["admin", "root"]));

    let parent = Warrant::builder()
        .capability("action", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child only excludes "admin" — drops "root", accepting more values
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("role", NotOneOf::new(vec!["admin"]));

    let result = parent
        .attenuate()
        .capability("action", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "NotOneOf removing an exclusion must be rejected (child accepts more values)"
    );
}

// =============================================================================
// Contains Attenuation Tests (Type ID: 11)
// =============================================================================

#[test]
fn test_contains_attenuation_adding_required_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent requires "read" scope
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("scopes", Contains::new(["read"]));

    let parent = Warrant::builder()
        .capability("api_call", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child requires "read" AND "audit" — more restrictive
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("scopes", Contains::new(["read", "audit"]));

    let result = parent
        .attenuate()
        .capability("api_call", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "Contains adding more required values must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_contains_attenuation_removing_required_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent requires "read" AND "audit"
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("scopes", Contains::new(["read", "audit"]));

    let parent = Warrant::builder()
        .capability("api_call", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child drops "audit" requirement — less restrictive
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("scopes", Contains::new(["read"]));

    let result = parent
        .attenuate()
        .capability("api_call", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "Contains removing a required value must be rejected"
    );
}

// =============================================================================
// Subset Attenuation Tests (Type ID: 12)
// =============================================================================

#[test]
fn test_subset_attenuation_narrowing_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("methods", Subset::new(["GET", "POST", "PUT"]));

    let parent = Warrant::builder()
        .capability("api_call", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child restricts to read-only
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("methods", Subset::new(["GET"]));

    let result = parent
        .attenuate()
        .capability("api_call", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "Subset narrowing must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_subset_attenuation_adding_value_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert("methods", Subset::new(["GET"]));

    let parent = Warrant::builder()
        .capability("api_call", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child adds DELETE — not in parent
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert("methods", Subset::new(["GET", "DELETE"]));

    let result = parent
        .attenuate()
        .capability("api_call", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "Subset adding a value not in parent must be rejected"
    );
}

// =============================================================================
// All Constraint Attenuation Tests (Type ID: 12)
// =============================================================================

#[test]
fn test_all_attenuation_adding_clause_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent: All([OneOf(["read","write"])])
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "op",
        All::new([Constraint::OneOf(OneOf::new(vec!["read", "write"]))]),
    );

    let parent = Warrant::builder()
        .capability("storage", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child: All([OneOf(["read","write"]), Exact("read")]) — more restrictive (AND narrows)
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "op",
        All::new([
            Constraint::OneOf(OneOf::new(vec!["read", "write"])),
            Constraint::Exact(Exact::new("read")),
        ]),
    );

    let result = parent
        .attenuate()
        .capability("storage", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "All adding a clause must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_all_attenuation_dropping_clause_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    // Parent: All([OneOf(["read","write"]), Pattern("log-*")])
    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "op",
        All::new([
            Constraint::OneOf(OneOf::new(vec!["read", "write"])),
            Constraint::Pattern(Pattern::new("log-*").unwrap()),
        ]),
    );

    let parent = Warrant::builder()
        .capability("storage", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    // Child drops the Pattern clause — less restrictive
    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "op",
        All::new([Constraint::OneOf(OneOf::new(vec!["read", "write"]))]),
    );

    let result = parent
        .attenuate()
        .capability("storage", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_err(),
        "All dropping a clause must be rejected (less restrictive than parent)"
    );
}

// =============================================================================
// Range Constraint Attenuation Tests (Type ID: 7)
// =============================================================================

#[test]
fn test_range_attenuation_narrowing_valid() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "size_bytes",
        Range::new(Some(0.0), Some(10_000_000.0)).unwrap(),
    );

    let parent = Warrant::builder()
        .capability("upload", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "size_bytes",
        Range::new(Some(0.0), Some(1_000_000.0)).unwrap(),
    );

    let result = parent
        .attenuate()
        .capability("upload", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(
        result.is_ok(),
        "Range narrowing must be valid attenuation: {:?}",
        result.err()
    );
}

#[test]
fn test_range_attenuation_widening_rejected() {
    let keypair = SigningKey::generate();
    let child_keypair = SigningKey::generate();

    let mut parent_constraints = ConstraintSet::new();
    parent_constraints.insert(
        "size_bytes",
        Range::new(Some(0.0), Some(1_000_000.0)).unwrap(),
    );

    let parent = Warrant::builder()
        .capability("upload", parent_constraints)
        .ttl(Duration::from_secs(3600))
        .holder(keypair.public_key())
        .build(&keypair)
        .unwrap();

    let mut child_constraints = ConstraintSet::new();
    child_constraints.insert(
        "size_bytes",
        Range::new(Some(0.0), Some(10_000_000.0)).unwrap(),
    );

    let result = parent
        .attenuate()
        .capability("upload", child_constraints)
        .holder(child_keypair.public_key())
        .build(&keypair);

    assert!(result.is_err(), "Range widening must be rejected");
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_cidr_single_host() {
    // /32 is a single host
    let cidr = Cidr::new("10.0.0.1/32").unwrap();
    let constraint = Constraint::Cidr(cidr);

    assert!(constraint.matches(&"10.0.0.1".into()).unwrap());
    assert!(!constraint.matches(&"10.0.0.2".into()).unwrap());
}

#[test]
fn test_any_single_option() {
    // Any with single option is effectively Exact
    let any_constraint = Constraint::Any(Any::new([Constraint::Exact(Exact::new("only_option"))]));

    assert!(any_constraint.matches(&"only_option".into()).unwrap());
    assert!(!any_constraint.matches(&"other".into()).unwrap());
}

#[test]
fn test_nested_any_in_all() {
    use tenuo::All;

    // All([Any([a, b]), Any([c, d])]) = (a OR b) AND (c OR d)
    let constraint = Constraint::All(All::new([
        Constraint::Any(Any::new([
            Constraint::Exact(Exact::new("a")),
            Constraint::Exact(Exact::new("b")),
        ])),
        Constraint::Any(Any::new([
            Constraint::Exact(Exact::new("c")),
            Constraint::Exact(Exact::new("d")),
        ])),
    ]));

    // Only matches if value satisfies both Any constraints
    // Since these are different values, nothing matches both
    // This is a constraint that can't be satisfied with a single value
    assert!(!constraint.matches(&"a".into()).unwrap());
    assert!(!constraint.matches(&"c".into()).unwrap());
}
