# Tenuo Wire Format Specification

> ⚠️ **Internal Design Document**
> 
> This is an internal specification for implementers building cross-language compatibility.
> For user-facing documentation, see [/docs](/docs). Details may be outdated.

Version: 0.1
Status: Reference  
Last Updated: 2025-12-26

---

## Overview

This specification defines the wire format for Tenuo warrants. These decisions are baked into v0.1 and cannot change without a major version bump.

**Design principles:**

1. **Verify before deserialize** — Check signatures against raw bytes, not re-serialized data
2. **Fail closed** — Unknown fields/types reject, not ignore
3. **Extensibility hooks** — Add fields now, implement features later
4. **Algorithm agility** — Don't hardcode key sizes or algorithms

---

## 1. Envelope Pattern

Warrants use an envelope structure that separates the signed payload from the signature.

```rust
/// Outer envelope (what goes on the wire)
pub struct SignedWarrant {
    /// Envelope format version
    pub envelope_version: u8,
    
    /// Raw CBOR bytes of WarrantPayload
    pub payload: Vec<u8>,
    
    /// Signature computed over `payload` bytes
    pub signature: Signature,
}

/// Inner payload (deserialized from SignedWarrant.payload)
pub struct WarrantPayload {
    pub version: u8,
    pub id: WarrantId,
    pub warrant_type: WarrantType,
    pub tools: BTreeMap<String, ConstraintSet>,
    pub holder: PublicKey,
    pub issuer: PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_depth: u8,
    pub parent_hash: Option<[u8; 32]>,          // SHA256(parent payload bytes)
    pub extensions: BTreeMap<String, Vec<u8>>,
    
    // Auth-critical optional fields (validated like core fields)
    pub issuable_tools: Option<Vec<String>>,
    pub max_issue_depth: Option<u32>,
    pub constraint_bounds: Option<ConstraintSet>,
    pub required_approvers: Option<Vec<PublicKey>>,
    pub min_approvals: Option<u32>,
    pub clearance: Option<Clearance>,
    pub depth: u32,
}
```

### Why an envelope?

**The problem with in-band signatures:**

```
❌ In-band: signature inside the struct

Signer                            Verifier
  |                                  |
  | serialize(fields 0-8)            |
  | sign(bytes) → sig                |
  | serialize(fields 0-8 + sig)      |
  |                                  |
  |---------- wire bytes ----------->|
  |                                  |
  |                     deserialize(all)
  |                     strip signature field
  |                     RE-serialize(fields 0-8)  ← DANGER
  |                     verify(new_bytes, sig)
```

If the verifier's CBOR library serializes differently than the signer's (different integer widths, array encodings, map ordering), the bytes differ and verification fails. This is a canonicalization bug. It is subtle, hard to debug, breaks cross-language compatibility.

**The envelope solution:**

```
✓ Envelope: signature outside the payload

Signer                            Verifier
  |                                  |
  | serialize(payload) → bytes       |
  | sign(bytes) → sig                |
  | envelope(bytes, sig)             |
  |                                  |
  |---------- wire bytes ----------->|
  |                                  |
  |                     unwrap → (bytes, sig)
  |                     verify(bytes, sig)  ← SAME BYTES
  |                     deserialize(bytes) → payload
```

The verifier checks the signature against the exact bytes that were signed. No re-serialization. No canonicalization dependency.

**Additional benefit:** Signature verification happens before expensive deserialization. Invalid signatures are rejected without parsing the payload.

---

## 2. Verification Flow

```rust
fn verify(
    signed: &SignedWarrant,
    trusted_roots: &[PublicKey],
) -> Result<WarrantPayload, VerificationError> {
    
    // 1. Check envelope version
    if signed.envelope_version != 1 {
        return Err(VerificationError::UnsupportedEnvelopeVersion);
    }
    
    // 2. Extract issuer public key from raw payload
    //    (minimal parsing, just enough to get the key)
    let issuer = extract_issuer(&signed.payload)?;
    
    // 3. Verify signature over the domain-separated preimage
    //    preimage = b"tenuo-warrant-v1" || envelope_version || payload_bytes
    //    NO re-serialization — use payload bytes directly
    let preimage = build_preimage(signed.envelope_version, &signed.payload);
    issuer.verify(&preimage, &signed.signature)?;
    
    // 4. Now safe to deserialize (signature is valid)
    let payload: WarrantPayload = cbor::deserialize(&signed.payload)?;
    
    // 5. Check payload version
    if payload.version != 1 {
        return Err(VerificationError::UnsupportedPayloadVersion);
    }
    
    // 6. Validate trust chain, TTL, constraints, etc.
    validate_payload(&payload, trusted_roots)?;
    
    Ok(payload)
}
```

### Chain attenuation rules
### Testable Invariants

**Every implementation MUST verify these properties.** Tests should reference these invariants by number.

#### I1: Delegation Authority
```
child.issuer == parent.holder
```

**Rationale:** The parent's holder is the entity authorized to delegate. This establishes clear audit trail: "parent.holder delegated to child.holder".

**Why this matters:**
- Audit clarity: "Who authorized this delegation?"
- Trust model: Authority flows from issuer (who authorized) to holder (who can use)
- Industry standard: Matches X.509, Macaroons, SPIFFE, UCAN

**Enforcement points:**
1. **Builder**: `AttenuationBuilder::build()` MUST use parent's holder keypair to sign
2. **Verifier**: `verify_chain_link()` MUST check `child.issuer() == parent.holder()`

**Test requirement:**
```rust
assert_eq!(child.issuer(), parent.holder(), "Invariant I1 violated");
```

#### I2: Depth Monotonicity
```
child.depth == parent.depth + 1
child.depth <= MAX_DELEGATION_DEPTH (64)
child.depth <= parent.max_depth
```

**Rationale:** Prevents unbounded chains (DoS) and enforces delegation limits.

**Depth semantics:** `max_depth` is an absolute ceiling, not a remaining count. A warrant is terminal (cannot delegate further) when `depth >= max_depth`. The conditions above show validity; the verifier rejects when `child.depth > parent.max_depth`.

**Enforcement points:**
1. **Builder**: Increment depth, check against limits
2. **Verifier**: Validate depth increment and limits

#### I3: TTL Monotonicity
```
child.expires_at <= parent.expires_at
child.ttl <= MAX_WARRANT_TTL_SECS (90 days)
```

**Rationale:** Authority cannot outlive its source. Prevents time-based privilege escalation.

**Enforcement points:**
1. **Builder**: Cap child TTL at parent's remaining time
2. **Verifier**: Check expiration doesn't exceed parent

#### I4: Capability Monotonicity
```
child.tools ⊆ parent.tools
∀ tool ∈ child.tools: child.constraints[tool] ⊑ parent.constraints[tool]
```

**Rationale:** Principle of Least Authority (POLA) - capabilities only shrink.

**Enforcement points:**
1. **Builder**: Validate tool subset and constraint narrowing
2. **Verifier**: Check monotonicity for each tool

#### I5: Cryptographic Linkage
```
child.parent_hash == SHA256(parent.payload_bytes)
verify(parent.issuer, parent.signature_preimage, parent.signature)
verify(child.issuer, child.signature_preimage, child.signature)
```

**Rationale:** Prevents chain tampering and warrant forgery.

**Enforcement points:**
1. **Builder**: Compute parent_hash from parent payload
2. **Verifier**: Verify hash matches and signatures valid

#### I6: Holder Binding (Proof-of-Possession)
```
pop_signature = sign(holder_private_key, challenge)
verify(warrant.holder, challenge, pop_signature)
```

**Rationale:** Prevents warrant theft - holder must prove key possession.

**Enforcement points:**
1. **Execution**: Holder creates PoP signature for each action
2. **Verifier**: Validate PoP against warrant.holder (not issuer!)

### Verification Checklist

Implementations MUST verify ALL invariants. Missing checks create security vulnerabilities.

| Invariant | Builder | Verifier | Test |
|-----------|---------|----------|------|
| I1: Delegation Authority | ✅ Sign with parent.holder | ✅ Check issuer == parent.holder | ✅ Required |
| I2: Depth Monotonicity | ✅ Increment & validate | ✅ Check depth rules | ✅ Required |
| I3: TTL Monotonicity | ✅ Cap at parent TTL | ✅ Check expiration | ✅ Required |
| I4: Capability Monotonicity | ✅ Validate narrowing | ✅ Check tool/constraint subset | ✅ Required |
| I5: Cryptographic Linkage | ✅ Compute parent_hash | ✅ Verify hash & signatures | ✅ Required |
| I6: Holder Binding | N/A | ✅ Verify PoP signature | ✅ Required |

### Common Implementation Errors

**❌ Error 1: Child signs own warrant**
```rust
// WRONG - violates I1
let child = parent.grant_builder()
    .holder(child_key.public_key())
    .build(&child_key);  // Child signs - WRONG!
```

**✅ Correct:**
```rust
let child = parent.grant_builder()
    .holder(child_key.public_key())
    .build(&parent_key);  // Parent's holder signs - CORRECT
```

**❌ Error 2: Missing issuer check in verifier**
```rust
// WRONG - violates I1 verification
fn verify_chain_link(parent, child) {
    check_parent_hash(parent, child);  // ✅
    check_depth(parent, child);        // ✅
    // Missing: check child.issuer == parent.holder  ❌
}
```

**✅ Correct:**
```rust
fn verify_chain_link(parent, child) {
    check_parent_hash(parent, child);
    check_depth(parent, child);
    assert_eq!(child.issuer(), parent.holder());  // ✅ I1
}
```

**❌ Error 3: Verifying PoP against issuer**
```rust
// WRONG - violates I6
verify(child.issuer(), pop_challenge, pop_sig);  // ❌
```

**✅ Correct:**
```rust
verify(child.holder(), pop_challenge, pop_sig);  // ✅
```

> **Note:** For details on how delegation is cryptographically proven, see the "Cryptographic Proof of Delegation" section in [`protocol.md`](protocol.md#cryptographic-proof-of-delegation).

---

## 3. Version Fields

Two version fields for independent evolution:

| Field | Location | Purpose |
|-------|----------|---------|
| `envelope_version` | SignedWarrant | Envelope structure changes |
| `version` | WarrantPayload | Payload schema changes |

```rust
pub struct SignedWarrant {
    /// Envelope version. Currently 1.
    /// Increment if: signature algorithm selection changes,
    /// envelope fields change, or wrapper structure changes.
    pub envelope_version: u8,
    // ...
}

pub struct WarrantPayload {
    /// Payload version. Currently 1.
    /// Increment if: payload fields change, semantics change,
    /// or new required fields are added.
    pub version: u8,
    // ...
}
```

**Version handling rules:**

| Version seen | Behavior |
|--------------|----------|
| `0` | Invalid, reject |
| `1` | Current, process normally |
| `2+` | Unknown, reject (until verifier upgraded) |

**Rationale:** Envelope version lets us change the crypto wrapper (e.g., switch to COSE_Sign1) without touching payload parsing. Payload version lets us change warrant semantics without touching signature verification.

---

## 4. Algorithm Agility

Public keys and signatures are self-describing.

```rust
#[repr(u8)]
pub enum Algorithm {
    /// Ed25519: 32-byte public keys, 64-byte signatures
    Ed25519 = 1,
    
    // Reserved for future use:
    // Ed448 = 2,
    // Dilithium2 = 3,  // Post-quantum
    // Dilithium3 = 4,
}

pub struct PublicKey {
    /// Algorithm identifier
    pub algorithm: Algorithm,
    
    /// Raw key bytes (length depends on algorithm)
    pub bytes: Vec<u8>,
}

pub struct Signature {
    /// Algorithm identifier (must match issuer's public key)
    pub algorithm: Algorithm,
    
    /// Raw signature bytes (length depends on algorithm)
    pub bytes: Vec<u8>,
}
```

### Signature domain separation

- The signature preimage MUST be `b"tenuo-warrant-v1" || envelope_version || payload_bytes`.
- Algorithms that support contexts (e.g., Ed25519ctx/Ed25519ph) MUST use the context string `tenuo-warrant-v1`.
- Verifiers MUST reject signatures that omit the required domain separation or that use a different context.
- Verification step: reconstruct the preimage from the received `envelope_version` and raw `payload` bytes; verify the signature against that exact preimage before deserializing.

**Validation rules:**

| Check | Failure |
|-------|---------|
| Unknown algorithm ID | Reject |
| Key length doesn't match algorithm | Reject |
| Signature algorithm ≠ key algorithm | Reject |

**Key sizes by algorithm:**

| Algorithm | Public Key | Signature |
|-----------|------------|-----------|
| Ed25519 | 32 bytes | 64 bytes |
| Dilithium2 | 1,312 bytes | 2,420 bytes |

**Rationale:** Hardcoding `[u8; 32]` for keys prevents migration to post-quantum algorithms. The extra byte for algorithm ID costs nothing and enables future-proofing.

---

## 5. Timestamps

All timestamps are Unix seconds (not milliseconds).

```rust
pub struct WarrantPayload {
    /// When the warrant was issued (Unix seconds)
    pub issued_at: u64,
    
    /// When the warrant expires (Unix seconds)
    pub expires_at: u64,
    // ...
}
```

**Rules:**

| Field | Validation |
|-------|------------|
| `issued_at` | Must be ≤ current time + clock tolerance |
| `expires_at` | Must be > current time |
| `expires_at` | Must be > `issued_at` |
| `expires_at` | Must be ≤ parent's `expires_at` (if attenuated) |

**Why seconds, not milliseconds:**

- `u64` seconds covers 584 billion years — sufficient
- Simpler mental math when debugging
- Matches Unix timestamp convention
- Avoids confusion between seconds/milliseconds

**Clock tolerance for TTL validation:** ±30 seconds to handle clock skew.

**PoP replay window:** 120 seconds (30s window × 4 max windows) - see Proof-of-Possession section.

### Integer Value Limits

All integer values in warrants (timestamps, constraint bounds, depth, counts, etc.) MUST fit within the **signed 64-bit range**: −2^63 to 2^63−1.

**Rules:**

| Scenario | Behavior |
|----------|----------|
| Integer within i64 range | ✓ Valid |
| Integer outside i64 range | ✗ Reject warrant |
| CBOR bignum (tag 2/3) | ✗ Reject warrant |

**Rationale:**

- **JavaScript safety**: JS `Number` only has safe integers up to 2^53; WASM bindings use BigInt for i64
- **Cross-language consistency**: Rust uses `i64`, Python has arbitrary precision, Go uses `int64`
- **CBOR allows arbitrary precision**: Without this limit, a malicious warrant could contain 128-bit integers that break some implementations

**Large value escape hatch**: Integers outside i64 range (e.g., snowflake IDs, UUIDs as integers) MUST be encoded as bytes (big-endian) or string. Verifiers will treat these as opaque values for `Exact`/`OneOf` matching.

**Note on Range constraints**: Range bounds use `f64` internally, which loses precision for integers > 2^53. For snowflake IDs or other large integers, use `Exact` or `OneOf` constraints instead.

## 6. Constraint Types

```rust
#[repr(u8)]
pub enum ConstraintType {
    // Standard constraints (1-127)
    Exact = 1,
    Pattern = 2,
    Range = 3,
    OneOf = 4,
    Regex = 5,
    // 6 is reserved for future IntRange with i64 bounds
    NotOneOf = 7,
    Cidr = 8,
    UrlPattern = 9,
    Contains = 10,
    Subset = 11,
    All = 12,
    Any = 13,
    Not = 14,
    Cel = 15,
    Wildcard = 16,
    // Future standard types: 17-127
    
    // Experimental / private use (128-255)
    // See "Constraint Type Ranges" below
}

pub enum Constraint {
    /// Exact string match
    Exact(String),
    
    /// Glob pattern (*, **, ?)
    Pattern(String),
    
    /// Numeric range (uses f64; see precision note below)
    Range {
        min: Option<f64>,
        max: Option<f64>,
        min_inclusive: bool,
        max_inclusive: bool,
    },
    
    /// Value must be in list
    OneOf(Vec<String>),
    
    /// Regular expression match
    Regex(String),

    /// Value must NOT be in excluded set
    NotOneOf(Vec<String>),

    /// IP/network must be within CIDR
    Cidr(String),

    /// URL must match pattern (scheme/host/path)
    UrlPattern(String),

    /// List must contain all listed values
    Contains(Vec<String>),

    /// List must be a subset of allowed values
    Subset(Vec<String>),

    /// All nested constraints must pass (AND)
    All(Vec<Constraint>),

    /// At least one nested constraint must pass (OR)
    Any(Vec<Constraint>),

    /// Negation (NOT) of a constraint
    Not(Box<Constraint>),

    /// CEL expression (must return bool)
    Cel(String),

    /// Wildcard (matches anything)
    Wildcard,
    
    /// Unknown constraint type (deserialized but not understood)
    Unknown {
        type_id: u8,
        payload: Vec<u8>,
    },
}
```

**Wire type IDs and serialization (standard 1–127):**

| ID | Type | Serialization shape | Notes |
|----|------|---------------------|-------|
| 1 | Exact | string | Exact value match |
| 2 | Pattern | string | Glob (`*`, `?`, `**`) |
| 3 | Range | map {min?: f64, max?: f64, min_inclusive?: bool, max_inclusive?: bool} | Numeric bounds (see precision note) |
| 4 | OneOf | array<string> | Allowed set |
| 5 | Regex | string | Pattern as string |
| 6 | (reserved) | — | Reserved for future IntRange with i64 bounds |
| 7 | NotOneOf | array<string> | Excluded set |
| 8 | Cidr | string | CIDR notation |
| 9 | UrlPattern | string | URL pattern (scheme/host/path) |
| 10 | Contains | array<string> | List must contain all |
| 11 | Subset | array<string> | List must be subset of allowed |
| 12 | All | array<Constraint> | AND of children |
| 13 | Any | array<Constraint> | OR of children |
| 14 | Not | Constraint | Negation of child |
| 15 | Cel | string | CEL expression, must return bool |
| 16 | Wildcard | null/empty | Matches anything |

**Range precision note:** `Range` (ID 3) uses `f64` bounds. Converting `i64` values larger than 2^53 (9,007,199,254,740,992) to `f64` loses precision. For practical use cases (monetary amounts, counts, file sizes), this is not a concern. For very large integer constraints (e.g., snowflake IDs), use `Exact` or `OneOf` instead.

**Reserved ID 6:** Reserved for a future `IntRange` type with `i64` bounds if precise large-integer range comparisons are needed. Currently, `Range` (ID 3) handles both integer and float values with `f64` precision.

**Attenuation semantics:** For containment/attenuation rules (what “stricter” means), see `docs/constraints.md` (Attenuation Compatibility Matrix). Minimal reminders for some types:
- `NotOneOf`: child must exclude >= parent’s exclusions (never remove exclusions).
- `Contains`: child must require a superset of parent’s required elements.
- `Subset`: child’s allowed set must be ⊆ parent’s allowed set.
- `All`: child may add more clauses; existing clauses must not be weakened.
- `Any`: child may remove clauses; remaining clauses must not be weakened.
- `Not`: negation of a stricter constraint remains stricter only if the inner constraint is stricter.
- `Cel`: child must conjoin with parent (logical AND); never replace/loosen parent expression.

### Constraint Type Ranges

| Range | Purpose |
|-------|---------|
| 0 | Reserved (invalid) |
| 1–127 | Standard constraints (defined by Tenuo spec) |
| 128–255 | Experimental / private use |

**Standard range (1–127):** Constraints defined in this specification and future Tenuo releases. All compliant verifiers must implement these.

**Experimental range (128–255):** For internal testing, proprietary extensions, or organization-specific constraints. These are expected to fail authorization on standard verifiers. Use them when:

- Testing new constraint types before proposing for standardization
- Building proprietary extensions that don't need interoperability
- Organization-internal constraints

### Unknown constraint handling

When a verifier encounters an unrecognized constraint type ID, it must:

1. **Deserialize** into `Constraint::Unknown { type_id, payload }`
2. **Preserve** the data (don't strip it)
3. **Fail authorization** — `Unknown.check()` always returns `false`

```rust
impl Constraint {
    pub fn check(&self, value: &Value) -> bool {
        match self {
            Self::Exact(expected) => value.as_str() == Some(expected),
            Self::Pattern(pattern) => glob_match(pattern, value),
            Self::Range { min, max, .. } => check_range(value, *min, *max),
            Self::OneOf(allowed) => allowed.contains(&value.to_string()),
            Self::Regex(pattern) => regex_match(pattern, value),
            // ... other constraint types ...
            
            // Unknown constraints ALWAYS fail (fail closed)
            Self::Unknown { .. } => false,
        }
    }
}
```

**Why fail closed:**

| Approach | Problem |
|----------|---------|
| Ignore unknown | Security hole — skips restrictions |
| Crash on unknown | Brittle — can't deploy new constraints gradually |
| Strip unknown | Breaks signature — payload was signed with them |
| **Fail closed** | ✓ Safe and forward-compatible |

### Numeric constraint domains

- `Range` uses `f64` bounds with configurable inclusivity (`min_inclusive`, `max_inclusive`).
- NaN and infinite values are invalid and must be rejected.
- For integers larger than 2^53, use `Exact` or `OneOf` to avoid precision loss.

**Deployment scenario (example):**

1. v0.2 adds a new constraint type `GeoFence` (type ID = 17)
2. Issuer creates warrant with `GeoFence("us-east-1")`
3. Old verifier (v0.1) sees type ID 17, deserializes as `Unknown`
4. Authorization check fails (safe default)
5. Old verifier upgraded to v0.2, now understands `GeoFence`
6. Authorization check passes

---

## 7. Tool-Scoped Constraints

Constraints are scoped per-tool, not global.

```rust
pub struct WarrantPayload {
    /// Map of tool name → constraints for that tool
    pub tools: BTreeMap<String, ConstraintSet>,
    // ...
}

pub struct ConstraintSet {
    /// Map of argument name → constraint
    pub constraints: BTreeMap<String, Constraint>,
}
```

**Example:**

```rust
let payload = WarrantPayload {
    tools: btreemap! {
        "read_file" => ConstraintSet {
            constraints: btreemap! {
                "path" => Constraint::Pattern("/data/*"),
            },
        },
        "search" => ConstraintSet {
            constraints: btreemap! {
                "query" => Constraint::Pattern("*public*"),
            },
        },
        "ping" => ConstraintSet {
            constraints: btreemap! {},  // Explicitly unconstrained
        },
    },
    // ...
};
```

**Rules:**

| Scenario | Behavior |
|----------|----------|
| Tool in warrant, all constraints pass | ✓ Authorized |
| Tool in warrant, constraint fails | ✗ Denied |
| Tool not in warrant | ✗ Denied |
| Tool in warrant with empty constraints | ✓ Authorized (explicitly unconstrained) |

**Rationale:** Prevents ambiguity when tools have different argument schemas. A `path` constraint on `read_file` shouldn't silently skip when `search` (which has no `path` argument) is called.

---

## 8. Extensions Bag

A signed-but-ignored metadata field for application data.

```rust
pub struct WarrantPayload {
    /// Application metadata. Signed but not interpreted by Tenuo.
    pub extensions: BTreeMap<String, Vec<u8>>,
    // ...
}
```

**Rules:**

1. Extensions are included in signature (part of payload)
2. Core verifier never interprets extension contents
3. Unknown keys are preserved, not stripped
4. Empty map is valid (and default)
5. Values are raw bytes — applications parse them

**Reserved key prefixes:**

| Prefix | Owner |
|--------|-------|
| `tenuo:*` | Reserved for future Tenuo use |
| Other | Application-defined |

**Recommended key format:** Reverse domain notation (`com.example.trace_id`)

**Example use cases:**

```rust
extensions: btreemap! {
    "com.example.trace_id" => b"abc123".to_vec(),
    "com.example.billing_tag" => b"team-ml".to_vec(),
    "com.example.request_id" => uuid.as_bytes().to_vec(),
}
```

**Why `Vec<u8>` instead of `String` or JSON:**

- Applications can embed any format (Protobuf, JSON, CBOR, encrypted blobs)
- No parsing overhead in Tenuo
- No charset/encoding issues
- Tenuo doesn't need to understand the data, just sign it

---

## 9. Reserved Tool Namespaces

The `tenuo:` tool name prefix is reserved for framework use.

```rust
impl WarrantPayload {
    pub fn validate(&self) -> Result<(), ValidationError> {
        for tool in self.tools.keys() {
            if tool.starts_with("tenuo:") {
                return Err(ValidationError::ReservedToolName(tool.clone()));
            }
        }
        Ok(())
    }
}
```

**Reserved prefixes:**

| Prefix | Purpose |
|--------|---------|
| `tenuo:` | Future framework features |

**Potential future uses:**

- `tenuo:revoke` — Inline revocation directive
- `tenuo:require_mfa` — Enforcement flag
- `tenuo:audit` — Force audit log entry

**Rationale:** Prevents collision between user-defined tools and future framework features, while staying minimally opinionated about naming conventions.

---

## 10. Serialization Format

Warrants are serialized as CBOR (RFC 8949).

**Envelope (SignedWarrant):**

```
CBOR Array [
    0: envelope_version (u8),
    1: payload (bytes),
    2: signature (Signature),
]
```

**Signature:**

```
CBOR Array [
    0: algorithm (u8),
    1: bytes (bytes),
]
```

**PublicKey:**

```
CBOR Array [
    0: algorithm (u8),
    1: bytes (bytes),
]
```

**WarrantId:**

```
CBOR Bytes (length = 16)  // UUID bytes, big-endian
```

**WarrantType:**

```
CBOR Unsigned integer (u8)  // enumerated as in code
```

**Payload (WarrantPayload):**

```
CBOR Map {
    0: version (u8),
    1: id (bytes, 16),
    2: warrant_type (u8),
    3: tools (map<string, constraint_set>),
    4: holder (public_key),
    5: issuer (public_key),
    6: issued_at (u64),
    7: expires_at (u64),
    8: max_depth (u8),
    9: parent_hash (bytes, optional)  // SHA256(parent payload bytes)
    10: extensions (map<string, bytes>),

    // Auth-critical additional fields (validated like core fields)
    11: issuable_tools (array<string>, optional),
    13: max_issue_depth (u32, optional),
    14: constraint_bounds (constraint_set, optional),
    15: required_approvers (array<public_key>, optional),
    16: min_approvals (u32, optional),
    17: clearance (u8 enum, optional),
    18: depth (u32, default=0),
}
```

**Metadata (not auth-critical):**

- `session_id`, `agent_id` are carried in `extensions` under reserved keys: `tenuo.session_id`, `tenuo.agent_id`.

**Rules:**

1. Envelope uses array (fixed field order)
2. Payload uses map with integer keys (allows sparse fields)
3. `BTreeMap` for deterministic key ordering within maps
4. Unknown payload keys MUST be rejected unless they are under `extensions`
5. Duplicate map keys are invalid and MUST be rejected
6. Deterministic CBOR (RFC 8949) MUST be used: no indefinite-length items; canonical map key ordering; shortest-length integer encodings

**Why CBOR:**

- Compact binary format
- Self-describing (no schema required)
- Deterministic serialization possible
- Wide language support
- Used by COSE, WebAuthn, FIDO2

### Extension Value Encoding

Extension values MUST be CBOR-encoded. The outer `extensions` map uses string keys and byte values, where each value is a CBOR-encoded structure.

**Example:**
```rust
// Extension definition
struct RateLimitExtension {
    limit: u64,
    window_secs: u64,
    scope: u8,
}

// Encoding
let ext = RateLimitExtension { limit: 5, window_secs: 60, scope: 0 };
let cbor_bytes = cbor::encode(&ext)?;

// Storage in warrant
extensions.insert("tenuo.rate_limit", cbor_bytes);
```

**Extension key namespaces:**

- **`tenuo.*`** - Reserved for framework use. Current extensions: `tenuo.session_id`, `tenuo.agent_id` (metadata only).
- **User-defined** - Use reverse domain notation: `com.example.trace_id`, `org.acme.workflow_id`

Verifiers SHOULD reject warrants with unknown `tenuo.*` extensions to fail closed.

---

## 11. Warrant Stack (Transport)

For transport/storage of a warrant chain, use a `WarrantStack`:

```rust
type WarrantStack = Vec<SignedWarrant>; // CBOR Array of Warrants
```

- **Order**: Root → Leaf (Root at index 0, Leaf at index N-1).
- **Semantics**: Used for "Disconnected Verification" where the verifier does not know the intermediate delegates.

### 11.1 Disambiguation (Array vs. Array)
Both `SignedWarrant` and `WarrantStack` are represented as CBOR Arrays.
- `SignedWarrant`: `Array(3)` where element 0 is `envelope_version` (**Integer**).
- `WarrantStack`: `Array(N)` where element 0 is a `SignedWarrant` (**Array**).

**Parsers MUST inspect the first element** to distinguish them:
- If index 0 is an **Integer** $\rightarrow$ It is a `SignedWarrant`.
- If index 0 is an **Array** $\rightarrow$ It is a `WarrantStack`.

### Verification (stack)

1.  **Check limits:** `stack.len()` MUST NOT exceed `MAX_CHAIN_DEPTH`; total encoded size MUST NOT exceed 64 KB.
2.  **Iterate:** Validate each link $i$ against $i-1$.
    - $i=0$: Must be signed by a trusted root.
    - $i>0$: 
        - `stack[i].issuer` == `stack[i-1].holder` (Delegation Authority).
        - `stack[i].parent_hash` == SHA256(`stack[i-1].payload`).
        - `stack[i].depth` == `stack[i-1].depth + 1`.
3.  **Result:** The verified leaf is `stack[N-1]`.

---

## 12. Encoding and Representation

### 12.1 Base64 Encoding (Wire Transport)

When warrants are transmitted in text contexts (HTTP headers, JSON, logs), use:

- **Encoding:** Base64 URL-safe (RFC 4648 §5)
- **Padding:** No padding

```rust
// Encoding
let wire_bytes = cbor::serialize(&signed_warrant);
let text = base64::encode_config(&wire_bytes, base64::URL_SAFE_NO_PAD);

// Decoding
let wire_bytes = base64::decode_config(&text, base64::URL_SAFE_NO_PAD)?;
let signed_warrant: SignedWarrant = cbor::deserialize(&wire_bytes)?;
```

**Why URL-safe base64:**
- Safe in URLs, headers, filenames
- No `+` or `/` characters that need escaping
- Standard practice for tokens (JWT uses this)

### 12.2 Text Representation (PEM Armor)

For config files, logs, and human sharing, Tenuo supports three formats:

#### 1. Explicit Stack (Production Format)
Use for transporting full chains in a single PEM block.
- **Header:** `-----BEGIN TENUO WARRANT CHAIN-----`
- **Body:** Base64 of CBOR(Array<SignedWarrant>)
- **Result:** `WarrantStack`

```text
-----BEGIN TENUO WARRANT CHAIN-----
(Base64 of CBOR Array of SignedWarrants)
-----END TENUO WARRANT CHAIN-----
```

#### 2. Implicit Stack (UNIX Format)
Use for concatenating individual warrant files (e.g. `cat root.pem leaf.pem > chain.pem`).
- **Input:** Multiple `-----BEGIN TENUO WARRANT-----` blocks.
- **Result:** `WarrantStack` (constructed by parsing each block and appending to vector).

#### 3. Single Warrant (Leaf Format)
Use for individual warrants (e.g. root keys, intermediate tickets).
- **Header:** `-----BEGIN TENUO WARRANT-----`
- **Body:** Base64 of CBOR(SignedWarrant)
- **Result:** `WarrantStack` (containing 1 item).

```text
-----BEGIN TENUO WARRANT-----
(Base64 of CBOR SignedWarrant)
-----END TENUO WARRANT-----
```

**Key Formats:**
- Public Keys: Standard SPKI PEM (`-----BEGIN PUBLIC KEY-----`)
- Private Keys: Standard PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`)

### 12.3 PEM Transport Summary

### Single Warrant
```text
-----BEGIN TENUO WARRANT-----
<base64url>
-----END TENUO WARRANT-----
```

### Chain (SSL-style concatenation)
Concatenated PEM blocks. Order: Root → Leaf (parser handles either order; verification enforces strict hierarchy).

```text
-----BEGIN TENUO WARRANT-----
<root base64url>
-----END TENUO WARRANT-----
-----BEGIN TENUO WARRANT-----
<child base64url>
-----END TENUO WARRANT-----
```

### 12.4 File Format

- Extension: `.tenuo`
- MIMEType: `application/vnd.tenuo+cbor`
- Magic bytes (binary): `0x54 0x45 0x4E 0x55 0x01` ("TENU" + version)

**Rules:**
- File content is raw CBOR bytes (WarrantStack)
- Magic bytes appear at the **start of the file**, immediately followed by the CBOR bytes.
- Magic bytes are NOT used in PEM-armored text files (headers serve that purpose)

---

## 13. Size Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max warrant size | 64 KB | Prevents memory exhaustion |
| Max tools per warrant | 256 | Practical limit |
| Max constraints per tool | 64 | Practical limit |
| Max extension keys | 64 | Practical limit |
| Max extension value size | 8 KB | Prevents abuse |
| Max chain depth | 64 | Prevents DoS; typical chains are 3-5 levels |
| Max TTL | 90 days | Protocol ceiling; deployments can enforce stricter |
| Max tool name length | 256 bytes | Practical limit |
| Max constraint value length | 4 KB | Practical limit |

Verifiers must reject warrants exceeding these limits before full parsing.

**WarrantStack size:** The combined encoded size of a warrant plus its ancestors (see Section 11) MUST NOT exceed 256 KB.

---

## 14. Version Negotiation (Network Protocols)

> **Scope:** This section applies only to network protocols (sidecar, gateway, MCP proxy). Standalone warrant verification uses the version fields embedded in the warrant itself — there is no negotiation.

For network protocols where client and server communicate over a session:

```
Client                          Server
   |                               |
   |--- Supported: [1, 2] -------->|
   |                               |
   |<-- Selected: 1 ---------------|
   |                               |
   |--- Warrant (v1 format) ------>|
```

**Rules:**

1. Client sends list of supported protocol versions
2. Server selects highest mutually supported version
3. All subsequent messages use selected version
4. If no overlap, connection fails

**Note:** This negotiates the *protocol* version (how messages are framed and exchanged), not the *warrant* version. Warrant versions are self-describing via `envelope_version` and `version` fields.

---

## 14. Proof-of-Possession (PoP) Wire Format

PoP prevents stolen warrants from being used without the holder's private key.

### PoP Challenge Structure

```rust
const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";
PopChallenge = (warrant_id: String, tool: String, sorted_args: Vec<(String, Value)>, timestamp_window: i64)
Preimage = POP_CONTEXT || CBOR(PopChallenge)
```

**Serialization:**
- CBOR tuple (4 elements)
- `sorted_args`: Arguments sorted lexicographically by key
- `timestamp_window`: Floor division of Unix timestamp by 30 seconds, then multiply by 30
- **Domain separation:** Preimage is `b"tenuo-pop-v1" || CBOR(challenge)` to prevent cross-protocol reuse

**Creating PoP:**
```rust
const POP_CONTEXT: &[u8] = b"tenuo-pop-v1";

let now = Utc::now().timestamp();
let window_ts = (now / 30) * 30;  // 30-second buckets
let challenge = (warrant.id.to_hex(), tool, sorted_args, window_ts);
let challenge_bytes = cbor_serialize(&challenge);

// Prepend domain separation context
let mut preimage = POP_CONTEXT.to_vec();
preimage.extend_from_slice(&challenge_bytes);

let signature = holder_keypair.sign(&preimage);
```

**Verification:**
```rust
// Try current and previous windows (handles clock skew)
for i in 0..4 {  // max_windows = 4
    let window_ts = ((now / 30) - i) * 30;
    let challenge = (warrant.id.to_hex(), tool, sorted_args, window_ts);
    let challenge_bytes = cbor_serialize(&challenge);
    
    // Prepend domain separation context
    let mut preimage = POP_CONTEXT.to_vec();
    preimage.extend_from_slice(&challenge_bytes);
    
    if holder_pubkey.verify(&preimage, &signature).is_ok() {
        return Ok(());
    }
}
Err("PoP failed or expired")
```

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Context | `tenuo-pop-v1` | Domain separation |
| Window size | 30 seconds | Groups signatures into buckets |
| Max windows | 4 | ~2 minute total validity |
| Clock tolerance | ±30 seconds | Handles distributed clock skew |

---

## 15. Approval Wire Format (Multi-Sig)

Approvals are signed statements from external parties (humans, identity providers) authorizing an action.

### Approval Structure

```rust
pub struct Approval {
    request_hash: [u8; 32],     // H(warrant_id || tool || sorted(args) || holder)
    nonce: [u8; 16],            // Random, replay protection
    approver_key: PublicKey,
    external_id: String,        // e.g., "arn:aws:iam::123:user/admin"
    provider: String,           // e.g., "aws-iam"
    approved_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: Option<String>,
    signature: Signature,
}
```

### Signable Bytes

```
context || nonce || request_hash || external_id || approved_at || expires_at
```

Where:
- `context` = `b"tenuo-approval-v1"` (domain separation)
- `approved_at`, `expires_at` = little-endian i64 timestamps

**Serialization:** CBOR map with string keys (via serde).

---

## 16. Signed Revocation List (SRL) Wire Format

The Control Plane signs revocation lists; authorizers verify before use.

### SRL Payload

```rust
struct SrlPayload {
    revoked_ids: Vec<String>,   // Warrant IDs to revoke
    version: u64,               // Monotonic (anti-rollback)
    issued_at: DateTime<Utc>,
    issuer: PublicKey,
}
```

### Signed Structure

```rust
pub struct SignedRevocationList {
    payload: SrlPayload,
    signature: Signature,       // Over CBOR(payload)
}
```

**Serialization:** CBOR.

**Anti-rollback:** Authorizers MUST reject SRLs with `version < current_version`.

---

## 17. Revocation Request Wire Format

Authorized parties submit signed requests to revoke warrants.

### Structure

```rust
pub struct RevocationRequest {
    warrant_id: String,
    reason: String,
    requestor: PublicKey,
    requested_at: DateTime<Utc>,
    signature: Signature,
}
```

### Signable Bytes

```
CBOR((warrant_id, reason, requestor, requested_at.timestamp()))
```

**Authorization:**
| Requestor | Can Revoke |
|-----------|------------|
| Control Plane | Any warrant |
| Issuer | Warrants they issued |
| Holder | Their own warrant (surrender) |

**Replay protection:** Requests older than 5 minutes are rejected.

---

## Summary

| Feature | Implementation | v0.1 Default |
|---------|---------------|--------------|
| Envelope pattern | `SignedWarrant { payload, signature }` | ✓ |
| Envelope version | `envelope_version: u8` | `1` |
| Payload version | `version: u8` | `1` |
| Algorithm agility | `PublicKey { algorithm, bytes }` | Ed25519 (1) |
| Timestamps | `u64` | Unix seconds |
| Tool-scoped constraints | `BTreeMap<String, ConstraintSet>` | ✓ |
| Standard constraints | Type IDs 1–127 | ✓ |
| Experimental constraints | Type IDs 128–255 | Fail closed |
| Unknown constraints | `Constraint::Unknown` → fails | ✓ |
| Extensions | `BTreeMap<String, Vec<u8>>` | `{}` |
| Reserved namespace | `tenuo:*` only | Rejected |
| Serialization | CBOR | ✓ |
| Text encoding | Base64 URL-safe, no padding | ✓ |
| Parent pointer | `parent_hash = SHA256(payload_bytes)` | ✓ |
| Transport | `WarrantStack` (Root → Leaf) | ✓ |
| PoP challenge | CBOR tuple, 30s windows | ✓ |
| Approval | CBOR, 16-byte nonce | ✓ |
| SRL | CBOR, monotonic version | ✓ |
| RevocationRequest | CBOR tuple | ✓ |

---

## Changelog

- **0.1.1** — Added PoP, Approval, SRL, RevocationRequest wire formats
- **0.1** — Initial specification
