# Tenuo Host Interface (THI) Specification

> **Status: Optional Tier — Stateful Extensions**
> 
> This document specifies the Host Interface for deployments that require stateful features: revocation, rate limiting, and replay protection. These features require infrastructure dependencies (Redis, PostgreSQL, etc.) and add latency. 
>
> **Core verification remains 100% offline.** Stateful extensions are opt-in via warrant extensions and are only checked when explicitly requested. Most use cases are well-served by short TTLs and PoP timestamp windows alone.

Version: 0.3.1
Status: Optional Tier (stateful extensions)
Last Updated: 2026-01-13

---

## 1. Philosophy: Math vs Physics

Tenuo separates verification into two domains:

**The Core (Math):** Cryptographic verification and constraint evaluation. Stateless, deterministic, CPU-bound. Runs anywhere—WASM, microcontrollers, air-gapped systems.

**The Host (Physics):** Real-world state checks—time, revocation, rate limits, replay protection. Requires I/O, storage, synchronization. Infrastructure-dependent.

### The Golden Rule

> The Core never waits for the Host unless the Warrant explicitly requests it.

Stateless warrants verify in microseconds with zero I/O. Stateful features are opt-in via extensions and incur the cost of their dependencies.

---

## 2. Interface Contract

A compliant Tenuo Host MUST provide the following operations. Implementations MAY be backed by Redis, PostgreSQL, in-memory maps, SQLite, or hardware security modules.

### 2.1 Nonce Store (Replay Protection)

**Purpose:** Prevent replay attacks for one-time-use warrants.

```rust
async fn check_nonce(
    &self,
    namespace: &[u8; 32],  // SHA256(warrant_id)
    nonce: &[u8],          // Caller-provided unique value
    ttl: Duration,         // Expiration (≤ warrant TTL)
) -> Result<NonceResult, HostError>;

enum NonceResult {
    /// Nonce is new and has been recorded.
    Accepted,
    /// Nonce was already used.
    Replay { first_seen: Option<u64> },
}
```

**Behavior:**

1. Construct storage key: `namespace || nonce`
2. Atomically check-and-set:
   - If key exists → return `Replay`
   - If key is new → store with TTL, return `Accepted`

**Requirements:**

| Property | Requirement |
|----------|-------------|
| Consistency | Strongly consistent (linearizable) |
| Failure mode | Fail closed |
| Key size | ≤ 32 + 64 = 96 bytes |
| TTL precision | Seconds |

**Namespace construction:**

```rust
let namespace = SHA256(warrant.id.as_bytes());
```

This scopes nonces to individual warrants, preventing cross-warrant collision.

> **Warrant ID requirements:** Warrant IDs MUST contain at least 128 bits of cryptographic randomness (e.g., UUIDv4, `tenuo_core::random_id()`). Sequential or predictable IDs risk namespace collision attacks where an attacker pre-populates nonces for future warrants.

---

### 2.2 Counter Store (Rate Limiting)

**Purpose:** Enforce request rate limits within time windows.

```rust
async fn increment_counter(
    &self,
    key: RateLimitKey,
    window: Duration,
    limit: u64,
) -> Result<CounterResult, HostError>;

struct RateLimitKey {
    pub namespace: [u8; 32],  // SHA256(warrant_id || ":" || tool_name)
    pub bucket: u64,          // floor(now_secs / window_secs)
}

enum CounterResult {
    /// Request allowed, returns current count.
    Allowed { count: u64, remaining: u64 },
    /// Rate limit exceeded.
    Exceeded { count: u64, retry_after: Duration },
}
```

**Behavior:**

1. Construct bucket key: `namespace || bucket`
2. Atomically increment counter
3. Set TTL to `window * 2` on first write (allows for clock skew)
4. Return count and compare against limit

**Window semantics:** Fixed windows aligned to Unix epoch. Bucket = `floor(timestamp / window_seconds)`.

> **Note:** Fixed windows allow 2× burst at boundaries. 
>
> **Example:** With a 60-second window and limit of 100:
> - 09:59:59 → 100 requests (bucket 999)
> - 10:00:01 → 100 requests (bucket 1000)
> - **Result:** 200 requests in 2 seconds
>
> This is **acceptable behavior** for most use cases. For stricter enforcement, implementations MAY use sliding windows or token bucket algorithms internally while maintaining this interface.

**Requirements:**

| Property | Requirement |
|----------|-------------|
| Consistency | Eventual consistency acceptable |
| Failure mode | Configurable (see §4) |
| Counter overflow | Saturate at `u64::MAX` |

**Key construction:**

```rust
// Use separator to prevent collision
let namespace = SHA256(warrant.id.as_bytes() || b":" || tool_name.as_bytes());
let bucket = now_unix_secs / window.as_secs();
```

> **Rationale for separator:** Prevents ambiguous concatenation where `id="abc", tool="def"` and `id="ab", tool="cdef"` would both produce `"abcdef"`. The `:` separator ensures unique namespaces.

---

### 2.3 Revocation Registry

**Purpose:** Emergency invalidation of compromised warrants or keys.

```rust
async fn is_revoked(
    &self,
    subject: RevocationSubject,
) -> Result<RevocationResult, HostError>;

enum RevocationSubject {
    /// Specific warrant by ID
    WarrantId([u8; 32]),     // SHA256(warrant_id)
    /// All warrants from issuer
    IssuerKey([u8; 32]),     // SHA256(issuer_pubkey)
    /// All warrants to holder
    HolderKey([u8; 32]),     // SHA256(holder_pubkey)
    /// All warrants delegated BY this key (chain revocation)
    DelegatorKey([u8; 32]), // SHA256(delegator_pubkey)
}

enum RevocationResult {
    /// Subject is not revoked.
    Valid,
    /// Subject is revoked.
    Revoked { reason: Option<String>, revoked_at: u64 },
    /// Registry unavailable, using cached data.
    ValidCached { cache_age: Duration },
}
```

**Behavior:**

1. Check local cache first
2. If cache miss or stale, query registry
3. Return result with provenance

**Requirements:**

| Property | Requirement |
|----------|-------------|
| Consistency | Bounded staleness (see below) |
| Failure mode | Stale-cache fallback |
| Cache TTL | Configurable, default 60 seconds |
| Max staleness | Configurable, default 5 minutes |

**Bounded staleness model:**

```
┌─────────────────────────────────────────────────────────┐
│                    Cache States                         │
├─────────────────────────────────────────────────────────┤
│  Fresh (< cache_ttl)     → Return cached, no I/O       │
│  Stale (< max_staleness) → Return cached, refresh async│
│  Expired (≥ max_staleness) → Block on refresh          │
│  Registry down + fresh   → Return cached               │
│  Registry down + stale   → Return cached + warning     │
│  Registry down + expired → FAIL CLOSED                 │
└─────────────────────────────────────────────────────────┘
```

> **Rationale:** Pure fail-open allows attackers to use revoked warrants by DoS-ing the registry. Bounded staleness provides availability while limiting the revocation propagation window.

#### Safety Valve: Un-revokable Keys

> **⚠️ CRITICAL:** Revoking root keys via `IssuerKey` would immediately halt the entire system.

**Implementations MUST implement a whitelist of un-revokable keys:**

```rust
struct RevocationConfig {
    /// Keys that cannot be revoked (e.g., root CA keys)
    pub protected_keys: HashSet<PublicKey>,
}

async fn revoke_key(&self, key: PublicKey, reason: String, revoker: PublicKey) -> Result<()> {
    if self.config.protected_keys.contains(&key) {
        return Err(RevocationError::ProtectedKey(
            "Cannot revoke protected root key"
        ));
    }
    
    // Audit: log revocation event (symmetric with un-revocation)
    self.audit_log.record(RevocationEvent {
        subject: RevocationSubject::from_key(key),
        action: RevocationAction::Revoke,
        actor: revoker,
        reason: reason.clone(),
        timestamp: now_unix_secs(),
    }).await?;
    
    // Proceed with revocation
    self.registry.insert(key, reason).await
}
```

**Recommended protected keys:**
- Root CA keys (trusted roots in verifier configuration)
- Emergency recovery keys
- System service keys

**Operational guidance:**
- Protected keys SHOULD be configured at deployment time
- Changes to protected key list SHOULD require manual intervention
- Revocation attempts on protected keys SHOULD trigger alerts

#### Un-Revocation Path

Revocations are not always permanent. A key may be revoked prematurely (false positive) or a compromised key may be rotated and re-secured.

```rust
async fn un_revoke(
    &self,
    subject: RevocationSubject,
    auth: UnRevocationAuth,
    reason: String,
) -> Result<(), HostError>;

struct UnRevocationAuth {
    /// Signature by authorized un-revoker (e.g., root key or designated recovery key)
    pub signature: [u8; 64],
    /// Timestamp of authorization
    pub authorized_at: u64,
    /// Optional: require N-of-M signatures for high-value subjects
    pub additional_signatures: Vec<[u8; 64]>,
}
```

**Requirements:**

| Property | Requirement |
|----------|-------------|
| Authorization | MUST be signed by designated recovery key(s) |
| Audit | MUST log: subject, un-revoker identity, timestamp, reason |
| Propagation | MUST propagate at same speed as revocations |
| CRL update | MUST be reflected in next CRL generation |

**Operational guidance:**
- Un-revocation SHOULD require higher authorization than revocation (e.g., N-of-M signatures)
- Un-revocation SHOULD trigger alerts for manual review
- Implementations SHOULD rate-limit un-revocation to prevent abuse

> **Security note:** Un-revocation is a high-risk operation. A compromised recovery key could re-enable revoked warrants. Consider requiring multi-signature authorization for production deployments.

#### Offline Revocation Lists (CRL)

For distributed or partially-connected deployments, implementations MAY support signed Certificate Revocation Lists:

```rust
struct SignedRevocationList {
    /// List of revoked subjects
    pub entries: Vec<RevocationEntry>,
    /// Timestamp of list generation
    pub issued_at: u64,
    /// Expiration (verifiers MUST reject lists past this time)
    pub expires_at: u64,
    /// Signature by registry authority
    pub signature: [u8; 64],
}

struct RevocationEntry {
    pub subject: RevocationSubject,
    pub revoked_at: u64,
    pub reason: Option<String>,
}
```

**Distribution methods:**
- HTTP polling (`GET /revocations/list.cbor`)
- Push via message queue (Kafka, NATS)
- Embedded in deployment artifacts (air-gapped systems)

**Verification:** Verifier checks signature against known registry public key, rejects expired lists, and uses entries as a local cache.

> **Known Limitation: CRL Freshness Gap**
> 
> CRLs introduce a freshness gap between revocation and propagation. A warrant revoked at T=0 may remain usable until the next CRL is generated and distributed (e.g., T+5min). This is an inherent trade-off of offline-capable revocation.
>
> **Mitigations:**
> - Short CRL validity periods (e.g., 5 minutes) reduce the gap but increase distribution overhead
> - Critical systems SHOULD use online checks (`tenuo.strict_revocable`) for high-value warrants
> - CRL expiration MUST be enforced: verifiers reject lists past `expires_at`

---

### 2.4 Health Check

**Purpose:** Circuit breaker integration and observability.

```rust
async fn health(&self) -> HostHealth;

struct HostHealth {
    pub status: HostStatus,
    pub nonce_store: ComponentHealth,
    pub counter_store: ComponentHealth,
    pub revocation_registry: ComponentHealth,
}

enum HostStatus {
    Healthy,
    Degraded,
    Unavailable,
}

struct ComponentHealth {
    pub available: bool,
    pub latency_p99: Option<Duration>,
    pub error_rate: Option<f64>,
}
```

---

## 3. Extension Schema

Stateful features are triggered by reserved extensions in the warrant payload. Extensions use CBOR encoding.

### 3.1 `tenuo.nonce`

Enables replay protection for this warrant.

```
CBOR Map {
    0: nonce (bytes, 16-64),   // Caller-provided unique value
    1: ttl_secs (u64),         // Optional, defaults to warrant TTL
}
```

**Verification logic:**

```rust
if let Some(ext) = warrant.extensions.get("tenuo.nonce") {
    let nonce_ext: NonceExtension = cbor::decode(ext)?;
    let ttl = nonce_ext.ttl_secs
        .map(Duration::from_secs)
        .unwrap_or(warrant.remaining_ttl());
    
    match host.check_nonce(warrant.namespace(), &nonce_ext.nonce, ttl).await? {
        NonceResult::Accepted => { /* continue */ }
        NonceResult::Replay { .. } => return Err(VerifyError::ReplayDetected),
    }
}
```

### 3.2 `tenuo.rate_limit`

Enables rate limiting for tool invocations.

```
CBOR Map {
    0: limit (u64),            // Max requests per window
    1: window_secs (u64),      // Window duration
    2: scope (u8),             // 0=per-warrant, 1=per-tool, 2=per-holder
}
```

**Scope values:**

| Value | Scope | Namespace |
|-------|-------|-----------|
| 0 | Per-warrant | `SHA256(warrant_id)` |
| 1 | Per-tool | `SHA256(warrant_id \|\| tool_name)` |
| 2 | Per-holder | `SHA256(holder_pubkey \|\| tool_name)` |

> **Note on per-holder scope:** A holder's rate limit is shared across *all* warrants they hold for a given tool. This is intentional: it prevents circumvention by requesting multiple warrants. However, it also means a legitimate holder with multiple valid warrants from different issuers shares one quota. Choose scope based on your trust model.

**Verification logic:**

```rust
if let Some(ext) = warrant.extensions.get("tenuo.rate_limit") {
    let rl: RateLimitExtension = cbor::decode(ext)?;
    let namespace = compute_namespace(rl.scope, &warrant, tool_name);
    let window = Duration::from_secs(rl.window_secs);
    
    match host.increment_counter(namespace, window, rl.limit).await? {
        CounterResult::Allowed { .. } => { /* continue */ }
        CounterResult::Exceeded { retry_after, .. } => {
            return Err(VerifyError::RateLimited { retry_after });
        }
    }
}
```

### 3.3 `tenuo.revocable`

Marks warrant as subject to revocation checks. Presence triggers check; no payload required.

```
CBOR null  // Or simply: extension key exists with empty value
```

**Verification logic:**

```rust
if warrant.extensions.contains_key("tenuo.revocable") {
    match host.is_revoked(RevocationSubject::WarrantId(warrant.id_hash())).await? {
        RevocationResult::Valid | RevocationResult::ValidCached { .. } => { /* continue */ }
        RevocationResult::Revoked { reason, .. } => {
            return Err(VerifyError::Revoked { reason });
        }
    }
}
```

> **Note:** Revocation checks MAY also be performed unconditionally by policy, independent of this extension.

### 3.4 `tenuo.strict_revocable`

For high-security warrants where 5-minute staleness is unacceptable. Forces synchronous revocation check with zero cache tolerance.

```
CBOR null
```

**Verification logic:**

```rust
if warrant.extensions.contains_key("tenuo.strict_revocable") {
    // Force synchronous check, bypass cache
    match host.is_revoked_sync(RevocationSubject::WarrantId(warrant.id_hash())).await? {
        RevocationResult::Valid => { /* continue */ }
        RevocationResult::Revoked { reason, .. } => {
            return Err(VerifyError::Revoked { reason });
        }
        RevocationResult::ValidCached { .. } => {
            // Strict mode rejects cached results
            return Err(VerifyError::RevocationCheckFailed {
                reason: "Strict mode requires fresh revocation check".into()
            });
        }
    }
}
```

**Use cases:**
- Root warrants with broad authority
- Warrants granting access to sensitive resources
- Emergency response workflows

**Trade-off:** Higher latency (network round-trip required) and availability risk (registry must be reachable).

### 3.5 `tenuo.chain_revocable`

Check revocation status of all keys in the delegation chain, not just the warrant itself.

```
CBOR null
```

**Verification logic:**

```rust
if warrant.extensions.contains_key("tenuo.chain_revocable") {
    // Build list of all subjects to check
    let mut subjects = vec![RevocationSubject::WarrantId(warrant.id_hash())];
    
    // Add every delegator in the chain (root to leaf order)
    for delegator in warrant.chain.delegators() {
        subjects.push(RevocationSubject::DelegatorKey(delegator.pubkey_hash()));
    }
    
    // Single batch call instead of O(n) sequential calls
    let results = host.is_revoked_batch(&subjects).await?;
    
    // Fail fast on any revocation
    for (subject, result) in subjects.iter().zip(results) {
        if let RevocationResult::Revoked { reason, .. } = result {
            return Err(VerifyError::Revoked { subject: subject.clone(), reason });
        }
    }
}
```

> **Implementation note:** Use the batch API (§7) to check the entire chain in a single round-trip. This reduces latency from O(n) network calls to O(1) for chains of any depth.

**Chain Traversal Semantics:**

| Term | Definition |
|------|------------|
| `delegators()` | All keys that signed a delegation in the chain, excluding the final holder |
| Traversal order | Root → Leaf (issuer first, most recent delegator last) |
| Stop on first revocation | Yes (fail fast) |

**Scope clarification:**

- `DelegatorKey(X)` revokes all warrants where X appears **anywhere** in the delegation chain as a delegator
- This is broader than `IssuerKey(X)`, which only revokes warrants where X is the **original issuer**
- A single compromised delegator revokes all downstream warrants, regardless of how many hops

**Edge cases:**

| Scenario | Behavior |
|----------|----------|
| Root key revoked via `DelegatorKey` | All warrants in the system become invalid |
| Intermediate delegator revoked | All warrants delegated from that point onward are invalid |
| Multiple paths to same warrant | Any revoked path invalidates the warrant |

> **Performance note:** Chain revocation requires O(n) revocation checks where n is the chain length. For deep delegation chains (n > 5), consider caching chain validity or using short TTLs instead.

**Use case:** If an orchestrator key is compromised, all warrants it delegated become invalid immediately, even if those specific warrants weren't individually revoked.

---

## 4. Failure Modes

Each host operation has a configurable failure mode:

```rust
struct HostConfig {
    pub nonce_failure_mode: FailureMode,      // Default: Closed
    pub counter_failure_mode: FailureMode,    // Default: Open
    pub revocation_failure_mode: FailureMode, // Default: StaleCache
}

enum FailureMode {
    /// Reject request if host unavailable.
    Closed,
    /// Allow request if host unavailable.
    Open,
    /// Use stale cached data if available, else closed.
    StaleCache { max_staleness: Duration },
}
```

**Recommended defaults:**

| Operation | Default | Rationale |
|-----------|---------|-----------|
| Nonce | Closed | Replay protection is security-critical |
| Counter | Open | Availability over rate accuracy |
| Revocation | StaleCache(5min) | Balance security and availability |

---

## 5. Verification Flow

```
                    ┌─────────────────┐
                    │  Start Verify   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Signature Valid?│
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │ No                          │ Yes
              ▼                             ▼
        ┌──────────┐               ┌────────────────┐
        │  REJECT  │               │Constraints OK? │
        └──────────┘               └───────┬────────┘
                                           │
                            ┌──────────────┴──────────────┐
                            │ No                          │ Yes
                            ▼                             ▼
                      ┌──────────┐              ┌─────────────────┐
                      │  REJECT  │              │Has Stateful Ext?│
                      └──────────┘              └────────┬────────┘
                                                         │
                                          ┌──────────────┴──────────────┐
                                          │ No                          │ Yes
                                          ▼                             ▼
                                   ┌────────────┐              ┌────────────────┐
                                   │ACCEPT(fast)│              │  Host Checks   │
                                   └────────────┘              └───────┬────────┘
                                                                       │
                                                        ┌──────────────┴──────────────┐
                                                        │ Pass                        │ Fail
                                                        ▼                             ▼
                                                 ┌────────────┐                ┌──────────┐
                                                 │ACCEPT(slow)│                │  REJECT  │
                                                 └────────────┘                └──────────┘
```

**Performance expectation:**

| Path | Latency |
|------|---------|
| Fast (no stateful ext) | < 100 μs |
| Slow (with host calls) | 1-10 ms |

---

## 6. Clock Synchronization

Host operations depend on time for:
- Nonce TTL expiration
- Rate limit window bucketing
- Cache staleness checks

**Requirements:**

| Component | Clock Requirement |
|-----------|-------------------|
| Verifier | NTP synced, ±2 seconds accuracy |
| Host backend | NTP synced, ±2 seconds accuracy |
| Cross-DC deployments | ±5 seconds tolerance built into window overlaps |

**Mitigations:**

1. Nonce TTL should be ≥ 10 seconds (absorbs drift)
2. Rate limit windows get 2× TTL in storage (handles boundary cases)
3. Cache ages computed from local monotonic clock, not wall time

---

## 7. Batch Operations

For high-throughput scenarios, implementations SHOULD provide batch variants:

```rust
#[async_trait]
pub trait TenuoHostBatch: TenuoHost {
    /// Batch nonce check. Returns results in same order as input.
    async fn check_nonces_batch(
        &self,
        checks: &[NonceCheck],
    ) -> Result<Vec<NonceResult>, HostError>;
    
    /// Batch revocation check.
    async fn is_revoked_batch(
        &self,
        subjects: &[RevocationSubject],
    ) -> Result<Vec<RevocationResult>, HostError>;
}

struct NonceCheck {
    pub namespace: [u8; 32],
    pub nonce: Vec<u8>,
    pub ttl: Duration,
}
```

**Implementation note:** Redis MGET/MSETNX, PostgreSQL batch INSERT with ON CONFLICT, etc.

---

## 8. Minimal Host (No-Op)

For testing, embedded systems, or stateless deployments:

```rust
pub struct MinimalHost;

#[async_trait]
impl TenuoHost for MinimalHost {
    async fn check_nonce(&self, ..) -> Result<NonceResult, HostError> {
        Ok(NonceResult::Accepted)  // Replay protection disabled
    }
    
    async fn increment_counter(&self, ..) -> Result<CounterResult, HostError> {
        Ok(CounterResult::Allowed { count: 0, remaining: u64::MAX })
    }
    
    async fn is_revoked(&self, ..) -> Result<RevocationResult, HostError> {
        Ok(RevocationResult::Valid)  // Revocation disabled
    }
    
    async fn health(&self) -> HostHealth {
        HostHealth {
            status: HostStatus::Healthy,
            // All components report healthy but limited
            ..
        }
    }
}
```

**Warning:** MinimalHost disables security features. Use only for:
- Unit tests
- Air-gapped systems with physical security
- Development/debugging

---

## 9. Reference Implementations

| Backend | Nonce | Counter | Revocation | Notes |
|---------|-------|---------|------------|-------|
| Redis | SETNX + EXPIRE | INCR + EXPIRE | SET membership | Recommended for production |
| PostgreSQL | INSERT ON CONFLICT | UPSERT | Table lookup | Better durability |
| SQLite | INSERT OR IGNORE | UPSERT | Table lookup | Single-node only |
| In-Memory | HashMap + cleanup | HashMap | HashSet | Testing only |
| DynamoDB | PutItem conditional | UpdateItem ADD | GetItem | AWS-native |

---

## 10. Observability

Implementations SHOULD emit metrics:

| Metric | Type | Labels |
|--------|------|--------|
| `tenuo_host_operation_duration_seconds` | Histogram | `operation`, `result` |
| `tenuo_host_operation_total` | Counter | `operation`, `result` |
| `tenuo_host_cache_hit_total` | Counter | `cache_type` |
| `tenuo_host_circuit_breaker_state` | Gauge | `component` |

**Recommended labels:**

- `operation`: `check_nonce`, `increment_counter`, `is_revoked`
- `result`: `success`, `replay`, `exceeded`, `revoked`, `error`
- `cache_type`: `revocation`, `counter`

---

## Changelog

- **0.3.1** — Added: warrant ID randomness requirement (prevents namespace collision attacks), revocation audit trail (symmetric with un-revocation), batch API integration for chain revocation (O(1) round-trips)
- **0.3** — Reframed as "Optional Tier" (not "not planned"). Added: `DelegatorKey` for chain revocation, `tenuo.strict_revocable` for zero-staleness checks, `tenuo.chain_revocable` with tightened semantics (traversal order, scope, edge cases), un-revocation path with N-of-M authorization, CRL freshness gap documented as known limitation, per-holder rate limit scope clarification
- **0.2** — Added bounded staleness for revocation, CBOR extension schemas, batch operations, clock sync guidance, observability hooks
- **0.1** — Initial draft
