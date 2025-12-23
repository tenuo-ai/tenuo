# Environment Context Constraints Specification

**Status**: Conceptual Exploration  
**Target**: Tenuo Core & SDKs  
**Author**: Tenuo  
**Date**: 2025-12-23

## 1. Overview

This document explores a mechanism for Tenuo to enforce authorization constraints based on the **runtime execution environment** (e.g., client IP, time of day, geolocation). This would allow "Context-Aware Capabilities" where authority is attenuated by the context in which it is exercised.

**Key Concepts Explored**:
1.  **Architecture**: "Context Pulling" - Integrations (FastAPI/LangChain) pull environment data and pass it to the Authorizer. The Core remains pure.
2.  **Performance**: Leveraging zero-overhead checks for users not using the feature.
3.  **Security**: Fail-closed logic when constraints are present but environment validation is missing.
4.  **Critical Extensions**: A mechanism to ensure older verifiers fail securely when encountering unknown mandatory constraints.

## 2. Protocol Design Proposal

### 2.1 Extension Schema

We are proposing the use of the reserved extension key `environment`. Additionally, to prevent "fail-open" vulnerability on older verifiers, we introduce `critical_extensions`.

```json
{
  "critical_extensions": ["environment"],
  "extensions": {
    "environment": {
      "ip": { "cidr": "10.0.0.0/24" },
      "time_utc": { "time_range": { "start": "2023-01-01T09:00:00Z", "end": "2023-01-01T17:00:00Z" } },
      "geo_country": { "oneof": ["US", "CA", "UK"] }
    }
  }
}
```

*Note: IPv6 is fully supported: `{"ip": { "cidr": "2001:db8::/32" }}`*

### 2.2 Standard Context Keys (Registry)

To prevent arbitrary or ambiguous keys ("vibes_check"), we define a strict registry of supported environment keys. Custom keys must use an `x-` prefix.

| Key | Type | Source | Required Format | Description |
|-----|------|--------|-----------------|-------------|
| `ip` | String | Request | CIDR / IP Address | Client IP address. |
| `time_utc` | String | Server Clock | ISO 8601 UTC | Current server time in UTC (e.g. `2023-01-01T12:00:00Z`). |
| `geo_country` | String | IP Lookup | ISO 3166-1 alpha-2 | 2-letter country code (e.g. `US`, `FR`). |
| `x-*` | Any | Custom | Any | Reserved for custom private extensions. Supports Pattern, Exact, OneOf, Range. |

**Validation Rule**: The Authorizer MUST fail if the `environment` map contains any non-prefixed key not in this registry.

### 2.3 Strong Typing Strategy
To avoid "stringly typed" security pitfalls (e.g., regex bypasses on IPs), we explicitly reject generic constraints for sensitive fields in favor of dedicated primitives:

1.  **CIDR (Classless Inter-Domain Routing)**: Used for `ip`. Performs bitmask matching rather than string comparison. Supports IPv4 and IPv6 universally.
2.  **TimeRange**: Dedicated time interval type for `time_utc`. Handles ISO 8601 parsing, timezone normalization (must be UTC), and clock skew buffers natively.

**Scope Note**: For v0.2, `time_utc` supports **absolute time ranges only** (e.g., "Access allowed until 5 PM today"). Recurring time windows (e.g., "9-5 Mon-Fri") are out of scope but on the v0.3 roadmap.

### 2.4 IPv6 Normalization

IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) MUST be normalized to IPv4 (`10.0.0.1`) before matching. This ensures consistent behavior regardless of the network stack's address representation.

```
Input: ::ffff:10.0.0.1
Normalized: 10.0.0.1
Matches: 10.0.0.0/24 ✅
```

### 2.5 Custom Extension Examples

The `x-*` prefix allows application-specific context without polluting the standard registry:

```json
{
  "environment": {
    "x-tenant-id": { "exact": "acme-corp" },
    "x-region": { "oneof": ["us-east-1", "us-west-2"] },
    "x-user-tier": { "oneof": ["enterprise", "premium"] }
  }
}
```

Common use cases:
- **Multi-tenant SaaS**: `x-tenant-id` for data isolation
- **Data residency**: `x-region` for compliance (GDPR, etc.)
- **Feature gating**: `x-user-tier` for tiered access

### 2.6 Backward Compatibility & Security (Critical Extensions)
The `critical_extensions` field is a list of extension keys that the verifier **MUST** understand.

- **Old Verifier**: Reads `critical_extensions: ["environment"]`. Does not understand `environment`. **FAILS CLOSED** (Authorization Error).
- **New Verifier**: Reads `critical_extensions: ["environment"]`. Understands `environment`. Proceeds to check constraints.

This prevents replay attacks where a restricted warrant (e.g., IP-bound) is used against an old verifier that would otherwise ignore the restriction.

## 3. Attenuation Semantics

Environment constraints follow the same monotonic attenuation rules as tool constraints: **children can only narrow, never expand**.

### 3.1 CIDR Attenuation

A child warrant can narrow the IP range but never expand it:

```
Parent: ip: 10.0.0.0/16
Child:  ip: 10.0.1.0/24  ✅ Allowed (subset)
Child:  ip: 10.0.0.0/8   ❌ Denied (superset)
Child:  ip: 192.168.0.0/16 ❌ Denied (disjoint)
```

**Implementation**: CIDR containment check using standard bitmask comparison.

### 3.2 Time Range Attenuation

A child warrant can narrow the time window:

```
Parent: time_utc: 2024-01-01T00:00:00Z to 2024-12-31T23:59:59Z
Child:  time_utc: 2024-06-01T00:00:00Z to 2024-06-30T23:59:59Z  ✅ Subset
Child:  time_utc: 2023-01-01T00:00:00Z to 2024-12-31T23:59:59Z  ❌ Starts earlier
```

### 3.3 OneOf Attenuation

A child can remove options but never add:

```
Parent: geo_country: ["US", "CA", "UK"]
Child:  geo_country: ["US", "CA"]  ✅ Subset
Child:  geo_country: ["US", "FR"]  ❌ "FR" not in parent
```

### 3.4 Extra Context Keys

Context may contain keys not referenced in the warrant. These are **ignored** (same as extra args in tool authorization). This allows integrations to always provide full context without worrying about warrant-specific requirements.

```python
# Context has ip, time_utc, geo_country, x-tenant-id
context = {"ip": "10.0.0.5", "time_utc": "...", "geo_country": "US", "x-tenant-id": "acme"}

# Warrant only requires ip
warrant.environment = {"ip": {"cidr": "10.0.0.0/24"}}

# Authorization succeeds - extra keys ignored
```

---

## 4. Architecture & API

### 4.1 Trust Model

> [!CAUTION]
> **⚠️ #1 FOOTGUN**: If your integration lies about the context, Tenuo will authorize the request. This is by design—Tenuo validates constraints, not truth.

The Authorizer **trusts the Integration layer** (e.g., the Tenuo SDK running in the application) to provide accurate context.

> [!WARNING]
> **Trust Boundary**: Tenuo Core validates *constraints* against *context*. It cannot validate the *veracity* of the context itself.
> If a malicious or compromised integration provides `{"ip": "10.0.0.1"}` when the real IP is `203.0.113.99`, Tenuo will authorize the request.
>
> In high-security environments, context should be derived from trusted infrastructure (e.g., mTLS certificates, upstream load balancer headers) and not user input.

### 4.2 Context Pulling

**Rust Core Signature**:
```rust
fn verify(warrant: &Warrant, tool: &str, args: &Args, context: Option<&HashMap<String, String>>) -> Result<bool>
```
*Note: Context keys are raw data (e.g., `ip: "10.0.0.5"`). Warrant constraints define the rule (e.g., `cidr: "10.0.0.0/24"`). The Authorizer checks if the value satisfies the constraint.*

**Python SDK (Integration Layer)**:
The integration (e.g., FastAPI middleware) is responsible for populating the context.

```python
# FastAPI Integration Example
context = {
    "ip": request.client.host,
    "time_utc": datetime.utcnow().isoformat() + "Z", # ISO 8601 strict
    "geo_country": geo_db.lookup(request.client.host)
}

# Pass pure data to Authorizer
authorizer.verify(warrant, tool, args, context=context)
```

## 5. Builder Usage (Phase 3)

We will introduce a fluent API for adding environment constraints. The builder automatically handles adding "environment" to `critical_extensions`.

```python
# .environment() implicitly adds "environment" to critical_extensions
warrant = Warrant.builder() \
    .capability("read_file", {"path": Pattern("/data/*")}) \
    .environment(
        ip=CIDR("10.0.0.0/24"), 
        geo_country=OneOf(["US", "CA"])
    ) \
    .holder(agent_kp.public_key) \
    .ttl(300) \
    .issue(issuer_kp)
```

## 6. Security Considerations

### 6.1 Fail Closed Logic
Authorization fails if and only if **environment constraints are present in the warrant** but cannot be satisfied.

Logic:
1.  **Critical Check**: If `critical_extensions` contains unknown keys -> **FAIL**.
2.  **Constraint Check**: 
    - If `environment` extension present:
        - If `enable_environment` is False (server config) -> **FAIL**.
        - If key required by warrant is missing in `context` -> **FAIL**.
        - If constraint check fails -> **FAIL**.

### 6.2 Trusted Sources
**WARNING**: Developers must only map environment variables from **trusted sources**.
-   **IP**: Use `request.client.host` only if behind a trusted proxy/load balancer. Do NOT trust `X-Forwarded-For` blindly.
-   **Geo**: Perform lookup server-side based on trusted IP.
-   **Time**: Use server clock, never client clock.

### 6.3 Time & Clock Skew
Time in distributed systems is unreliable.
-   **Format**: Enforce strict **ISO 8601** (UTC, 'Z' suffix) for all time comparisons.
-   **Buffer**: Implementation includes configurable clock skew buffer (default: 5 seconds). Should be configurable per-deployment and emit warnings if observed skew approaches the buffer.

### 6.4 Geo Lookup Latency

Geo database lookups can add latency (1-10ms for local DB, 50-200ms for API).

**Recommendations**:
- Pre-resolve geo at request ingress (load balancer, API gateway)
- Use local MaxMind/IP2Location database, not external API
- Cache results by IP with reasonable TTL (1 hour)
- If `geo_country` constraint present but no provider configured → **FAIL CLOSED**

### 6.5 Explicit Enable Flag

To prevent accidental fail-open when environment constraints are deployed before context providers, verifiers MUST explicitly opt-in:

```python
# Verifier must explicitly enable environment checking
authorizer = Authorizer(
    enable_environment=True,  # Required to process environment constraints
    geo_provider=maxmind_db,  # Required if geo_country constraints used
)
```

If `enable_environment=False` (default) and a warrant contains environment constraints, authorization **FAILS**.

## 7. Performance Considerations

### 7.1 Zero-Cost for Non-Users

Users not using environment constraints pay nothing:
- Single `critical_extensions.is_empty()` check (~1ns)
- No context parsing or validation

### 7.2 Constraint Check Costs

| Operation | Estimated Cost | Notes |
|-----------|----------------|-------|
| CIDR match | ~50ns | Bitmask comparison |
| TimeRange check | ~100ns | ISO 8601 parse + compare |
| OneOf lookup | ~20ns/item | HashSet lookup |
| Context assembly | Variable | Moved to integration layer |

**Note**: These are estimates. Actual benchmarks will be provided in Phase 1.

## 8. Future Work (v0.3+)

### 8.1 Recurring Time Windows

Enterprise use case: "Access allowed 9 AM - 5 PM, Monday-Friday, in user's timezone"

Proposed syntax:
```json
{
  "time_recurring": {
    "hours": "09:00-17:00",
    "days": ["mon", "tue", "wed", "thu", "fri"],
    "timezone": "America/New_York"
  }
}
```

**Complexity**: Requires timezone database, DST handling. Deferred to v0.3.

### 8.2 Request Rate Context

Stateful context like "requests in last N seconds" is out of scope for stateless warrants but could be provided by the integration:

```python
context = {
    "x-request-rate-1m": "42",  # Integration tracks this
}
```

## 9. Implementation Plan

### Phase 1: Core Support (Rust)
-   Add `critical_extensions` validation logic.
-   Update `verify` / `authorize` to accept `context` map.
-   Implement `CIDR` and `TimeRange` constraint types.
-   Add IPv6 normalization for v4-mapped addresses.
-   Benchmark constraint check performance.
    ```rust
    // Proposed Enum Changes
    enum Constraint {
        // ... existing variants
        Cidr(IpNet),
        TimeRange { start: DateTime<Utc>, end: DateTime<Utc> },
    }
    ```

### Phase 2: Python SDK
-   Update `Authorizer.verify` to accept `context` kwarg.
-   Add helpers for common context extraction in `tenuo.integration`.
-   Add `enable_environment` flag to Authorizer.

### Phase 3: Builder Support
-   Add `.environment()` and `.require_extensions()` methods to Warrant Builder.
-   Auto-add "environment" to `critical_extensions` when `.environment()` is called.

### Phase 4: Integrations
-   Update FastAPI to auto-populate context (IP, time).
-   Add geo provider abstraction (MaxMind, IP2Location).
-   Document trust boundaries in integration guides.
