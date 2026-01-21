# Tenuo Wire Format Specification

**Version:** 1.0
**Status:** Normative
**Date:** 2025-01-01
**Documentation Revision:** 2 (2026-01-18)

**Related Documents:**
- [protocol-spec-v1.md](protocol-spec-v1.md) - Protocol Specification (concepts, invariants, algorithms)
- [test-vectors.md](test-vectors.md) - Byte-exact test vectors for validation

---

## Revision History

- **Rev 2** (2026-01-18): Documentation cleanup
  - One reference max_windows table
  - Added cross-references between test vectors and full constraint type list
  - Regenerated test vectors to match generator output
  - Clarified approval envelope structure to match warrant envelope pattern
  - **No protocol changes** - wire format remains v1.0

- **Rev 1** (2025-01-01): Initial release

---

## Overview

This specification defines the wire format for Tenuo warrants. These decisions are baked into v0.1 and cannot change without a major version bump.

**Design principles:**

1. **Verify before deserialize** - Check signatures against raw bytes, not re-serialized data
2. **Fail closed** - Unknown fields/types reject, not ignore
3. **Extensibility hooks** - Add fields now, implement features later
4. **Algorithm agility** - Don't hardcode key sizes or algorithms

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
    pub parent_hash: Option<[u8; 32]>,          // SHA256(parent payload bytes); None for root warrants
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
BAD: In-band signature inside the struct

Signer                            Verifier
  |                                  |
  | serialize(fields 0-8)            |
  | sign(bytes) -> sig               |
  | serialize(fields 0-8 + sig)      |
  |                                  |
  |           -- wire bytes ------>|
  |                                  |
  |                     deserialize(all)
  |                     strip signature field
  |                     RE-serialize(fields 0-8)  <- DANGER
  |                     verify(new_bytes, sig)
```

If the verifier's CBOR library serializes differently than the signer's (different integer widths, array encodings, map ordering), the bytes differ and verification fails. This is a canonicalization bug. It is subtle, hard to debug, breaks cross-language compatibility.

**The envelope solution:**

```
GOOD: Envelope with signature outside the payload

Signer                            Verifier
  |                                  |
  | serialize(payload) -> bytes      |
  | sign(bytes) -> sig               |
  | envelope(bytes, sig)             |
  |                                  |
  |           -- wire bytes ------>|
  |                                  |
  |                     unwrap -> (bytes, sig)
  |                     verify(bytes, sig)  <- SAME BYTES
  |                     deserialize(bytes) -> payload
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
    //    (see §4 "Signature domain separation" for normative details)
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

### Testable Invariants (Chain Attenuation Rules)

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
child.depth < parent.max_depth  (for delegation capability)
```

**Rationale:** Prevents unbounded chains (DoS) and enforces delegation limits.

**Depth semantics:** `max_depth` is an absolute ceiling, not a remaining count. A warrant is terminal (cannot delegate further) when `depth >= max_depth`. 

**Delegation capability:** A warrant can create children only if `depth < max_depth`. When `depth == max_depth`, the warrant can be used but cannot delegate further.

**Example:**
```
Root:   depth=0, max_depth=3  → Can delegate (0 < 3)
Child1: depth=1, max_depth=3  → Can delegate (1 < 3)
Child2: depth=2, max_depth=3  → Can delegate (2 < 3)
Child3: depth=3, max_depth=3  → TERMINAL: Can use, cannot delegate (3 >= 3)
```

**Enforcement points:**
1. **Builder**: Verify `parent.depth < parent.max_depth` (delegation allowed), increment depth, ensure `≤ 64`
2. **Verifier**: Reject if `child.depth != parent.depth + 1` or `child.depth > parent.max_depth`

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
| I1: Delegation Authority | Yes: Sign with parent.holder | Yes: Check issuer == parent.holder | Required |
| I2: Depth Monotonicity | Yes: Increment & validate | Yes: Check depth rules | Required |
| I3: TTL Monotonicity | Yes: Cap at parent TTL | Yes: Check expiration | Required |
| I4: Capability Monotonicity | Yes: Validate narrowing | Yes: Check tool/constraint subset | Required |
| I5: Cryptographic Linkage | Yes: Compute parent_hash | Yes: Verify hash & signatures | Required |
| I6: Holder Binding | N/A | Yes: Verify PoP signature | Required |

### Implementation Requirements

**Critical rules:**
- Builders MUST use the parent warrant holder's keypair to sign delegations (I1)
- Verifiers MUST check `child.issuer() == parent.holder()` (I1)  
- Proof-of-Possession signatures MUST be verified against the warrant holder's key, not the issuer's key (I6)

> **Note:** For details on how delegation is cryptographically proven, see the "Cryptographic Linkage (I5)" section in [protocol-spec-v1.md](protocol-spec-v1.md#46-cryptographic-linkage-invariant-i5).

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

- `u64` seconds covers 584 billion years - sufficient
- Simpler mental math when debugging
- Matches Unix timestamp convention
- Avoids confusion between seconds/milliseconds

**Clock tolerance:** TTL validation uses ±30 seconds; PoP verification uses ±60 seconds (default, configurable). See §15 for PoP configuration details.

### Integer Value Limits

All integer values in warrants MUST fit within the **signed 64-bit range**: −2^63 to 2^63−1.

**Rules by context:**

| Context | Range | Precision | Notes |
|---------|-------|-----------|-------|
| Timestamps, depth, counts | i64 (−2^63 to 2^63−1) | Exact | Wire encoding validated |
| Range constraint bounds | i64 range, f64 precision | Lossy for \|n\| > 2^53 | Use Exact/OneOf for large integers |
| Constraint values (Exact, OneOf) | i64 range | Exact | Opaque comparison |
| CBOR wire encoding | i64 range | Exact | Reject bignums (tag 2/3) |

**Validation rules:**

| Scenario | Behavior |
|----------|----------|
| Integer within i64 range | Valid |
| Integer outside i64 range | Reject warrant |
| CBOR bignum (tag 2/3) | Reject warrant |
| Range bound with \|value\| > 2^53 | Accept, but warn about precision loss |

**Rationale:**

- **JavaScript safety**: JS `Number` only has safe integers up to 2^53; WASM bindings use BigInt for i64
- **Cross-language consistency**: Rust uses `i64`, Python has arbitrary precision, Go uses `int64`
- **CBOR allows arbitrary precision**: Without this limit, a malicious warrant could contain 128-bit integers that break some implementations

**Large integer handling:**

- **Timestamps/counts**: Always use i64, never exceed 2^63−1
- **Range constraints**: Values between 2^53 and 2^63 are accepted but comparisons may be imprecise due to f64 conversion
- **Snowflake IDs**: Use `Exact` or `OneOf` constraints (compared as exact values, no precision loss)
- **UUIDs**: Encode as bytes (big-endian) or string, not integers

**Example:**
```rust
// GOOD: Snowflake ID in Exact constraint
"user_id": Exact("1234567890123456789")  // Compared as string, no loss

// BAD: Large integer in Range
"user_id": Range { min: 2^54, max: 2^55 }  // Precision loss in f64

// GOOD: Alternative for large ranges
"user_id": OneOf(["1234567890123456789", "1234567890123456790", ...])
```

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
    Subpath = 17,
    UrlSafe = 18,
    // Future standard types: 19-127
    
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

    /// Secure path containment (prevents path traversal)
    Subpath {
        root: String,
        case_sensitive: bool,  // Default: true
        allow_equal: bool,     // Default: true
    },

    /// SSRF-safe URL validation
    UrlSafe {
        schemes: Vec<String>,           // Default: ["http", "https"]
        allow_domains: Option<Vec<String>>,  // Domain allowlist
        allow_ports: Option<Vec<u16>>,  // Port allowlist
        block_private: bool,            // Default: true
        block_loopback: bool,           // Default: true
        block_metadata: bool,           // Default: true
        block_reserved: bool,           // Default: true
        block_internal_tlds: bool,      // Default: false
    },
    
    /// Unknown constraint type (deserialized but not understood)
    Unknown {
        type_id: u8,
        payload: Vec<u8>,
    },
}
```

**Wire type IDs and serialization (standard 1–127):**

All constraints serialize as `[type_id, value]` tuples. The `value` is the serde serialization of the constraint struct.

| ID | Type | Value Shape | Notes |
|----|------|-------------|-------|
| 1 | Exact | `{value: any}` | Exact value match |
| 2 | Pattern | `{pattern: string}` | Glob (`*`, `?`, `**`) |
| 3 | Range | `{min?: f64, max?: f64}` | Numeric bounds |
| 4 | OneOf | `{values: [any]}` | Allowed set |
| 5 | Regex | `{pattern: string}` | Regex pattern |
| 6 | (reserved) | - | Reserved for IntRange |
| 7 | NotOneOf | `{excluded: [any]}` | Excluded set |
| 8 | Cidr | `{network: string}` | CIDR notation |
| 9 | UrlPattern | `{pattern: string}` | URL pattern |
| 10 | Contains | `{required: [any]}` | List must contain all |
| 11 | Subset | `{allowed: [any]}` | List must be subset |
| 12 | All | `{constraints: [Constraint]}` | AND of children |
| 13 | Any | `{constraints: [Constraint]}` | OR of children |
| 14 | Not | `{constraint: Constraint}` | Negation |
| 15 | Cel | `{expr: string}` | CEL expression |
| 16 | Wildcard | `null` | Matches anything |
| 17 | Subpath | `{root: string, case_sensitive?: bool, allow_equal?: bool}` | Path containment |
| 18 | UrlSafe | `{schemes?: [string], allow_domains?: [string], ...}` | SSRF protection |

**Range precision note:** `Range` (ID 3) uses `f64` bounds. Converting `i64` values larger than 2^53 (9,007,199,254,740,992) to `f64` loses precision. For practical use cases (monetary amounts, counts, file sizes), this is not a concern. For very large integer constraints (e.g., snowflake IDs), use `Exact` or `OneOf` instead.

**Reserved ID 6:** Reserved for a future `IntRange` type with `i64` bounds if precise large-integer range comparisons are needed. Currently, `Range` (ID 3) handles both integer and float values with `f64` precision.

**Attenuation semantics:** For containment/attenuation rules (what “stricter” means), see the [Constraint Lattice](protocol-spec-v1.md#32-constraint-lattice) in protocol-spec-v1.md. Minimal reminders for some types:
- `NotOneOf`: child must exclude >= parent’s exclusions (never remove exclusions).
- `Contains`: child must require a superset of parent’s required elements.
- `Subset`: child’s allowed set must be ⊆ parent’s allowed set.
- `All`: child may add more clauses; existing clauses must not be weakened.
- `Any`: child may remove clauses; remaining clauses must not be weakened.
- `Not`: negation of a stricter constraint remains stricter only if the inner constraint is stricter.
- `Cel`: child must conjoin with parent (logical AND); never replace/loosen parent expression.

### Constraint Attenuation Matrix (Normative)

**Principle:** A child constraint is a valid attenuation if and only if it accepts a **subset** of values that the parent accepts. This is the POLA (Principle of Least Authority) guarantee.

**Matrix:** For each (Parent Type, Child Type) pair, the table shows whether attenuation is valid and the precise rule.

| Parent | Child | Valid | Rule |
|--------|-------|-------|------|
| **Wildcard** | Any | YES | Universal superset; any constraint is stricter |
| Any | **Wildcard** | NO | Would expand permissions |
| **Exact** | Exact | IFF | `child.value == parent.value` |
| **Exact** | Other | NO | Exact is terminal; cannot attenuate further |
| **Pattern** | Pattern | IFF | `child.matches ⊆ parent.matches` (see Pattern rules below) |
| **Pattern** | Exact | IFF | `parent.matches(child.value)` |
| **Regex** | Regex | IFF | `child.pattern == parent.pattern` (conservative; subset undecidable) |
| **Regex** | Exact | IFF | `parent.matches(child.value)` |
| **OneOf** | OneOf | IFF | `child.values ⊆ parent.values` |
| **OneOf** | Exact | IFF | `child.value ∈ parent.values` |
| **OneOf** | NotOneOf | IFF | `parent.values - child.excluded ≠ ∅` (MUST reject if empty; no valid values remain) |
| **NotOneOf** | NotOneOf | IFF | `parent.excluded ⊆ child.excluded` (can only add exclusions) |
| **Range** | Range | IFF | `child.min ≥ parent.min ∧ child.max ≤ parent.max` (see inclusivity rules) |
| **Range** | Exact | IFF | `parent.contains(child.value)` (numeric) |
| **Cidr** | Cidr | IFF | `child.network ⊆ parent.network` (subnet) |
| **Cidr** | Exact | IFF | `child.ip ∈ parent.network` |
| **UrlPattern** | UrlPattern | IFF | `child.matches ⊆ parent.matches` |
| **UrlPattern** | Exact | IFF | `parent.matches(child.url)` |
| **Contains** | Contains | IFF | `parent.required ⊆ child.required` (can only add requirements) |
| **Subset** | Subset | IFF | `child.allowed ⊆ parent.allowed` (can only shrink allowed set) |
| **All** | All | IFF | Each parent clause has corresponding child clause that is ≤ strict; may add clauses |
| **Any** | Any | IFF | Child clauses ⊆ parent clauses; remaining clauses not weakened |
| **Not** | Not | IFF | `child.inner` is valid attenuation of `parent.inner` |
| **Cel** | Cel | IFF | `child.expr == parent.expr + " && extra"` (conjunction only) |
| **Subpath** | Subpath | IFF | `child.root` is subpath of `parent.root` |
| **Subpath** | Exact | IFF | `parent.contains(child.path)` |
| **UrlSafe** | UrlSafe | IFF | All child restrictions ≥ parent restrictions (see field rules) |
| **UrlSafe** | Exact | IFF | `parent.is_safe(child.url)` |

**All unlisted (Parent, Child) pairs are INVALID and MUST be rejected.**

#### Pattern Attenuation Rules

| Parent Pattern | Child Pattern | Valid | Rule |
|----------------|---------------|-------|------|
| `"*"` | `"*"` | YES | Single wildcard, equal |
| `"*"` | Any other | IFF | Equal only (single wildcard is conservative) |
| `"prefix-*"` | `"prefix-more-*"` | YES | Child prefix extends parent |
| `"prefix-*"` | `"prefix-exact"` | YES | Exact value starts with prefix |
| `"*-suffix"` | `"*-more-suffix"` | YES | Child suffix extends parent |
| `"*-suffix"` | `"exact-suffix"` | YES | Exact value ends with suffix |
| `"prefix-*-suffix"` | Any | IFF | Equal only (bidirectional wildcards are conservative) |
| `"*mid*"` | Any | IFF | Equal only (internal wildcards are conservative) |
| `"exact"` | `"exact"` | YES | Literal match, equal |
| `"exact"` | Any other | NO | Exact is terminal |

#### Pattern Attenuation Limitations

Pattern constraints support different levels of attenuation based on wildcard count and position:

**Single Wildcard Patterns (Fully Supported for Attenuation):**

| Pattern Type | Example | Can Attenuate To | Notes |
|--------------|---------|------------------|-------|
| Prefix (wildcard at end) | `"staging-*"` | `"staging-web-*"`, `"staging-web"` | Child can extend prefix or remove wildcard |
| Suffix (wildcard at start) | `"*-safe"` | `"*-extra-safe"`, `"image-safe"` | Child can extend suffix or remove wildcard |
| Single wildcard alone | `"*"` | `"*"` only | Conservative: requires equality |
| Exact (no wildcard) | `"production"` | `"production"` only | Terminal: no further narrowing |

**Multiple Wildcard Patterns (Equality Only for Attenuation):**

| Pattern Type | Example | Can Attenuate To | Restriction |
|--------------|---------|------------------|-------------|
| Bidirectional | `"*-prod-*"`, `"*safe*"` | Identical pattern only | Multiple wildcards |
| Middle wildcard | `"prefix-*-suffix"` | Identical pattern only | Wildcard not at edge |
| Complex paths | `/data/*/file.txt` | Identical pattern only | Internal wildcard |
| Multiple in path | `/*/reports/*.pdf` | Identical pattern only | 2+ wildcards |
| URL patterns | `https://*.example.com/*` | Identical pattern only | 2+ wildcards total |

**Key constraint:** Patterns with 2 or more wildcards, or a wildcard in the middle, are classified as `Complex` and can ONLY attenuate to an exact copy of themselves. Any difference results in `PatternExpanded` error.

**Rationale:** Determining subset relationships for complex glob patterns is computationally undecidable. Tenuo uses a conservative approach: reject potentially unsafe attenuation rather than risk privilege escalation.

**Workarounds for complex pattern attenuation:**

1. **Use structured constraints instead of patterns:**
   ```
   Instead of: Pattern("https://*.example.com/*")
   Use: UrlPattern(host="*.example.com", path="/*")
   ```
   This separates concerns, allowing independent attenuation of host and path.

2. **Issue specific warrants per subdomain:**
   ```
   search_warrant: Pattern("https://search.example.com/*")
   api_warrant: Pattern("https://api.example.com/*")
   ```

3. **Use exact patterns in delegation:**
   ```
   parent: Pattern("https://search.example.com/*")  # 1 wildcard
   child: Pattern("https://search.example.com/api/*")  # Still 1 wildcard, can attenuate
   ```

**`**` (Double-Star) Pattern:** The `**` pattern is **reserved and discouraged**. While `**` conceptually means "match all paths," it creates security risks:
- **Overly permissive**: Makes it too easy to grant unrestricted access
- **Attenuation ambiguity**: Unclear if `**` is "broader" or "equal" to `*`
- **Foot-gun potential**: Users may use `**` when they mean specific scoping

**Recommended alternatives:**
- Use `Wildcard()` constraint for explicit unrestricted access
- Use specific patterns like `/data/*/file` or `/path/**/*.txt` for structured paths
- Implementations MAY reject `Pattern("**")` with an error directing users to `Wildcard()`

#### Bidirectional Wildcard Patterns

Patterns with wildcards on both sides of a substring (e.g., `"*mid*"`, `"*-prod-*"`, `"prefix-*-suffix"`) are **supported for matching** but require **exact equality for attenuation**.

**Pattern classification:**
- `"*mid*"` → Two wildcards (`*` at start and end) → **Complex** type
- `"prefix-*-suffix"` → Wildcard in middle → **Complex** type
- `/data/*/file.txt` → Wildcard surrounded by literals → **Complex** type
- `/*/reports/*.pdf` → Multiple wildcards → **Complex** type

**Matching behavior:** All these patterns work correctly for runtime matching using standard glob semantics.

**Attenuation behavior:** Complex patterns can ONLY attenuate to an identical pattern. Child patterns that differ in any way are rejected, even if logically narrower.

**Examples of valid attenuation:**
```python
parent: Pattern("*-prod-*")
child:  Pattern("*-prod-*")  # ✓ Identical pattern

parent: Pattern("*safe*")
child:  Pattern("*safe*")     # ✓ Identical pattern
```

**Examples of rejected attenuation:**
```python
parent: Pattern("*-prod-*")
child:  Pattern("db-prod-*")        # ✗ Different structure
child:  Pattern("*-prod-primary")   # ✗ Different structure
child:  Pattern("db-prod-primary")  # ✗ Different type (exact)

parent: Pattern("/data/*/file.txt")
child:  Pattern("/data/reports/file.txt")  # ✗ More specific but different type
```

**Rationale:** Determining subset relationships for complex glob patterns requires full pattern evaluation, which is undecidable in the general case. Requiring equality prevents attenuation bugs while still allowing useful matching patterns.

**When to use bidirectional wildcards:**
- ✅ Resource naming: `"*-prod-*"`, `"*-safe-*"`
- ✅ Content matching: `"*error*"`, `"*admin*"`
- ✅ File patterns: `"report-*-2024.pdf"`, `"/logs/*/error.log"`

**When NOT to use:**
- ❌ Need attenuation → Use simpler patterns (`"prefix-*"`, `"*-suffix"`)
- ❌ Complex logic → Use `Regex()` for clarity
- ❌ Unrestricted access → Use `Wildcard()`

**Conservative rule:** For patterns with multiple wildcards, internal wildcards, or complex structures, attenuation is only valid if the patterns are identical. Subset relationships for complex globs are undecidable without full evaluation.

#### Range Inclusivity Rules

| Parent | Child | Valid | Reason |
|--------|-------|-------|--------|
| `[0, 100]` (inclusive) | `[10, 90]` | YES | Bounds narrowed |
| `(0, 100)` (exclusive) | `[1, 99]` | YES | Exclusive to inclusive at different value OK |
| `(0, 100)` | `(0, 50)` | YES | Same exclusivity, narrower max |
| `(0, 100)` | `[0, 50]` | NO | Parent excludes `0`, child includes it |
| `[0, ∞)` | `[10, 100]` | YES | Adding upper bound is stricter |

#### UrlSafe Field Attenuation Rules

| Field | Rule |
|-------|------|
| `schemes` | Child must be subset of parent (fewer schemes allowed) |
| `allow_domains` | Child must be subset of parent (fewer domains) |
| `allow_ports` | Child must be subset of parent (fewer ports) |
| `block_private` | `false` to `true` only (can add blocks, not remove) |
| `block_loopback` | `false` to `true` only |
| `block_metadata` | `false` to `true` only |
| `block_reserved` | `false` to `true` only |

**Implementations MUST reject attenuations not explicitly permitted in this matrix.**

---

### Constraint Type Ranges

| Range | Purpose |
|-------|---------|
| 0 | Reserved (invalid) |
| 1–18 | Core constraints (implemented) |
| 19–32 | Reserved for common patterns |
| 33–127 | Future standard constraints |
| 128–255 | Experimental / private use |

**Reserved IDs (19-32):**

| ID | Reserved For | Status |
|----|--------------|--------|
| 19 | TimeWindow | Planned: day/hour-of-week constraints |
| 20 | GeoFence | Planned: lat/lon bounding box |
| 21 | RateLimit | Planned: call frequency limits |
| 22-32 | Future patterns | Unassigned |

**Standard range (1–127):** Constraints defined in this specification and future Tenuo releases. All compliant verifiers must implement these.

**Experimental range (128–255):** For internal testing, proprietary extensions, or organization-specific constraints. These fail authorization on standard verifiers. Use for:

- Testing new constraint types before proposing standardization
- Building proprietary extensions that don't need interoperability
- Organization-internal constraints

### Unknown constraint handling

When a verifier encounters an unrecognized constraint type ID, it must:

1. **Deserialize** into `Constraint::Unknown { type_id, payload }`
2. **Preserve** the data (don't strip it)
3. **Fail authorization** - `Unknown.check()` always returns `false`

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
| Ignore unknown | Security hole - skips restrictions |
| Crash on unknown | Brittle - can't deploy new constraints gradually |
| Strip unknown | Breaks signature - payload was signed with them |
| **Fail closed** | Safe and forward-compatible |

### Numeric constraint domains

- `Range` uses `f64` bounds with configurable inclusivity (`min_inclusive`, `max_inclusive`).
- NaN and infinite values are invalid and must be rejected.
- For integers larger than 2^53, use `Exact` or `OneOf` to avoid precision loss.

**Deployment scenario (example):**

1. v0.2 adds a new constraint type `GeoFence` (type ID = 20)
2. Issuer creates warrant with `GeoFence("us-east-1")`
3. Old verifier (v0.1) sees type ID 20, deserializes as `Unknown`
4. Authorization check fails (safe default)
5. Old verifier upgraded to v0.2, now understands `GeoFence`
6. Authorization check passes

---

## 7. Tool-Scoped Constraints

Constraints are scoped per-tool, not global.

```rust
pub struct WarrantPayload {
    /// Map of tool name to constraints for that tool
    pub tools: BTreeMap<String, ConstraintSet>,
    // ...
}

pub struct ConstraintSet {
    /// Map of argument name to constraint
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
| Tool in warrant, all constraints pass | Authorized |
| Tool in warrant, constraint fails | Denied |
| Tool not in warrant | Denied |
| Tool in warrant with empty constraints | Authorized (explicitly unconstrained) |

**Rationale:** Prevents ambiguity when tools have different argument schemas. A `path` constraint on `read_file` shouldn't silently skip when `search` (which has no `path` argument) is called.

---

## 8. Extensions Bag

A signed-but-inspectable metadata field for application data.

```rust
pub struct WarrantPayload {
    /// Application metadata. CBOR-encoded values signed with the warrant.
    pub extensions: BTreeMap<String, Vec<u8>>,
    // ...
}
```

**Rules:**

1. Extensions are included in signature (part of payload)
2. **Extension values MUST be CBOR-encoded**
3. Core verifier MAY introspect extension contents for known keys
4. Unknown keys are preserved, not stripped
5. Empty map is valid (and default)
6. Verifiers SHOULD reject warrants with unknown `tenuo.*` extensions to fail closed

**Reserved key prefixes:**

| Prefix | Owner |
|--------|-------|
| `tenuo.*` | Reserved for Tenuo-defined extensions |
| Other | Application-defined |

**Recommended key format:** Reverse domain notation (`com.example.trace_id`)

### Extension Value Encoding

Extension values MUST be CBOR-encoded. The outer `extensions` map uses string keys and byte values, where each value is a CBOR-encoded structure.

**Why CBOR for extension values:**

- **Consistency**: Entire Tenuo protocol uses CBOR
- **Future-proofing**: Enables monotonicity checks on extensions if needed
- **Cross-language**: CBOR libraries are universal
- **Self-describing**: Type-safe, prevents interpretation bugs
- **Encrypted data**: Wrap in struct: `{algorithm: "AES-256-GCM", ciphertext: bytes}`

**Example use cases:**

```rust
// Simple string
let trace_id = cbor::encode(&"abc123")?;
extensions.insert("com.example.trace_id", trace_id);

// Structured data
#[derive(Serialize)]
struct BillingTag {
    team: String,
    project: String,
}
let billing = BillingTag {
    team: "ml".into(),
    project: "research".into()
};
extensions.insert("com.example.billing", cbor::encode(&billing)?);

// Encrypted payload
#[derive(Serialize)]
struct EncryptedExtension {
    algorithm: String,    // e.g., "AES-256-GCM"
    ciphertext: Vec<u8>,
    key_id: String,
}
let encrypted = EncryptedExtension {
    algorithm: "AES-256-GCM".into(),
    ciphertext: aes_encrypt(&sensitive_data),
    key_id: "key-2024-01".into(),
};
extensions.insert("com.example.secret", cbor::encode(&encrypted)?);

// UUID as bytes
let uuid_bytes = uuid::Uuid::new_v4().as_bytes().to_vec();
extensions.insert("com.example.request_id", cbor::encode(&uuid_bytes)?);
```

**Tenuo-reserved extension keys:**

| Key | Purpose | Status |
|-----|---------|--------|
| `tenuo.session_id` | Session correlation | Implemented |
| `tenuo.agent_id` | Agent identification | Implemented |
| `tenuo.audit_id` | Audit trail correlation | Reserved |
| `tenuo.dedup_key` | Idempotency key | Reserved |
| `tenuo.rate_limit` | Rate limiting metadata | Reserved |
| `tenuo.trace_id` | Distributed tracing | Reserved |

**User-defined keys:** Use reverse domain notation (e.g., `com.example.trace_id`, `org.acme.workflow_id`)

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

- `tenuo:revoke` - Inline revocation directive
- `tenuo:require_mfa` - Enforcement flag
- `tenuo:audit` - Force audit log entry

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
    12: (reserved for future use),
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
5. Senders MUST NOT produce duplicate map keys (verifier behavior is undefined per RFC 8949 §5.6)
6. Deterministic CBOR (RFC 8949) MUST be used: no indefinite-length items; canonical map key ordering; shortest-length integer encodings

> [!NOTE]
> **Duplicate CBOR map keys:** Senders MUST NOT produce. Verifier behavior is undefined (RFC 8949 §5.6). We do not mandate rejection because: (1) many CBOR libraries lack duplicate detection, and (2) malicious issuer is out of scope. Implementations SHOULD reject if supported. See §20.6 "Parser Security" for additional CBOR security considerations.

**Why CBOR:**

- Compact binary format
- Self-describing (no schema required)
- Deterministic serialization possible
- Wide language support
- Used by COSE, WebAuthn, FIDO2

> **Extension Value Encoding:** All extension values MUST be CBOR-encoded. See §8 "Extensions Bag" for details and examples.

---

## 11. Warrant Stack (Transport)

For transport/storage of a warrant chain, use a `WarrantStack`:

```rust
type WarrantStack = Vec<SignedWarrant>; // CBOR Array of Warrants
```

- **Order**: Root -> Leaf (Root at index 0, Leaf at index N-1).
- **Semantics**: Used for "Disconnected Verification" where the verifier does not know the intermediate delegates.

### 11.1 Disambiguation (Array vs. Array)
Both `SignedWarrant` and `WarrantStack` are represented as CBOR Arrays.
- `SignedWarrant`: `Array(3)` where element 0 is `envelope_version` (**Integer**).
- `WarrantStack`: `Array(N)` where element 0 is a `SignedWarrant` (**Array**).

**Parsers MUST inspect the first element's CBOR major type** to distinguish them:
- If element 0 has major type 0 (unsigned integer) or 1 (negative integer) → `SignedWarrant`
- If element 0 has major type 4 (array) → `WarrantStack`
- Any other major type → Invalid, MUST reject

**CBOR major types reference (RFC 8949 §3):**
- Major type 0: unsigned integer (0..2^64-1)
- Major type 1: negative integer (-2^64..-1)
- Major type 4: array of data items

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
Concatenated PEM blocks. Order: Root -> Leaf (parser handles either order; verification enforces strict hierarchy).

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
| Max TTL | 90 days (7,776,000 seconds) | Protocol ceiling; deployments can enforce stricter |
| Max tool name length | 256 bytes | Practical limit |
| Max constraint value length | 4 KB | Practical limit |

Verifiers must reject warrants exceeding these limits before full parsing.

**WarrantStack size:** The combined encoded size of a warrant plus its ancestors (see Section 11) MUST NOT exceed 256 KB.

---

## 14. Version Negotiation (Network Protocols)

> **Scope:** This section applies only to network protocols (sidecar, gateway, MCP proxy). Standalone warrant verification uses the version fields embedded in the warrant itself - there is no negotiation.

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

## 15. Proof-of-Possession (PoP) Wire Format

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

**Verification (Bidirectional):**
```rust
// Try current, past, AND future windows (handles bidirectional clock skew)
// Order: [0, -1, +1, -2, +2, ...] to prefer closer windows
// max_windows is CONFIGURABLE (see configuration table below)

// Generate offset sequence: [0, -1, 1, -2, 2, -3, 3, ...]
let offsets = generate_offsets(max_windows);

for offset in offsets {
    let window_ts = ((now / 30) + offset) * 30;
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

**Offset generation algorithm:**
```rust
fn generate_offsets(max_windows: usize) -> Vec<i32> {
    let mut offsets = vec![0];  // Always start with current window
    let half = (max_windows / 2) as i32;
    
    for i in 1..=half {
        offsets.push(-i);  // Past window
        if offsets.len() < max_windows {
            offsets.push(i);   // Future window
        }
    }
    
    offsets
}

// Examples:
// max_windows=2: [0, -1]            (asymmetric: 1 past, 0 future)
// max_windows=3: [0, -1, 1]         (symmetric: 1 past, 1 future)
// max_windows=4: [0, -1, 1, -2]     (asymmetric: 2 past, 1 future)
// max_windows=5: [0, -1, 1, -2, 2]  (symmetric: 2 past, 2 future)
```

### Configuration

| Parameter | Default | Min | Max | Purpose |
|---------|-----|-----|---------|---------|
| Context | `tenuo-pop-v1` | - | - | Domain separation (REQUIRED) |
| Window size | 30 seconds | - | - | Groups signatures into buckets (FIXED) |
| **max_windows** | **5** | **2** | **10** | **Configurable clock skew tolerance** |

### Clock Tolerance Formula

Tolerance is calculated as `±(floor(max_windows / 2) × 30)` seconds.

| max_windows | Tolerance | Recommended For |
|-------------|-----------|-----------------|
| 2 | ±30s | High-security with strict NTP |
| **5** | **±60s** | **Modern cloud/data center (DEFAULT)** |
| 7 | ±90s | Edge/IoT with clock drift |
| 10 | ±150s | Legacy systems (max) |

Odd values (3, 5, 7) provide symmetric coverage; even values are asymmetric (checking one more past window than future).

**Configuration scope:**
- `max_windows` is a **verifier deployment setting** (not per-warrant or per-request)
- All verifiers in a deployment SHOULD use the same value for consistent behavior
- Holders create PoP signatures using current time; verifiers check N windows based on their configured `max_windows`
- No negotiation: verifiers either accept within their configured tolerance or reject

> **Security guidance:** Use the **smallest window that accommodates your deployment environment's clock skew**. Smaller windows reduce the replay attack surface. The default of `max_windows=5` (±60s) balances security with real-world clock variance. High-security environments with strict NTP should use `max_windows=2` or `3` (±30s).

> **Note:** Verification MUST check both past AND future windows to handle clock skew in either direction. Checking only past windows causes failures when the holder's clock is ahead of the verifier's.

**Implementation note:** Verifiers SHOULD check windows in order of likelihood (current, then alternating past/future: 0, -1, +1, -2, +2, ...) for performance, but MUST accept any valid window within the tolerance range. The specific order is an optimization, not a normative requirement.

**Deployment consistency:** All verifiers in a system SHOULD use the same `max_windows` value to ensure consistent authorization behavior. Inconsistent values can cause intermittent failures where some verifiers accept a PoP while others reject it. Monitor clock skew metrics to select the appropriate value for your environment.

**Configuration example:**
```bash
# Environment variable (recommended)
TENUO_POP_MAX_WINDOWS=5  # Default: 5, Range: 2-10

# Or in config file (YAML)
tenuo:
  pop:
    max_windows: 5        # Default: 5 (±60s tolerance)
    window_size: 30       # Fixed, not configurable
```

---

## 16. Approval Wire Format (Multi-Sig)

Approvals are signed statements from external parties (humans, identity providers) authorizing an action.

Following the envelope pattern (§1), approvals separate the signed payload from metadata and signature.

### Approval Envelope Pattern

```rust
/// Outer envelope (what goes on the wire)
pub struct SignedApproval {
    /// Approval format version
    pub approval_version: u8,
    
    /// Raw CBOR bytes of ApprovalPayload
    pub payload: Vec<u8>,
    
    /// Approver's public key (extracted for convenience; not signed)
    pub approver_key: PublicKey,
    
    /// Signature computed over domain-separated payload bytes
    pub signature: Signature,
}

/// Inner payload (deserialized from SignedApproval.payload)
pub struct ApprovalPayload {
    pub version: u8,
    pub request_hash: [u8; 32],      // H(warrant_id || tool || sorted(args) || holder)
    pub nonce: [u8; 16],             // Random, replay protection
    pub external_id: String,         // e.g., "arn:aws:iam::123:user/admin"
    pub approved_at: u64,            // Unix seconds
    pub expires_at: u64,             // Unix seconds
    pub extensions: BTreeMap<String, Vec<u8>>,  // Optional metadata (signed)
}

/// Metadata (not signed, for convenience/audit)
pub struct ApprovalMetadata {
    pub provider: String,            // e.g., "aws-iam", "okta", "yubikey"
    pub reason: Option<String>,      // Human-readable justification
}
```

**Rationale for envelope:**
- **Verify before deserialize**: Check signature against raw bytes (same as warrants)
- **Clear boundary**: What's signed vs. what's metadata is obvious
- **Extensibility**: Add metadata fields without changing signature format
- **Consistency**: Same pattern as `SignedWarrant`/`WarrantPayload`
- **No re-serialization**: Verify against exact bytes that were signed

### Field Semantics

**ApprovalPayload (signed):**
- `version`: Payload version (currently 1)
- `request_hash`: Binds approval to specific (warrant, tool, args, holder)
- `nonce`: 128-bit random; ensures uniqueness even for identical requests
- `external_id`: External identity for audit (e.g., email, ARN, employee ID)
- `approved_at`: When the approval was issued (Unix seconds)
- `expires_at`: When the approval expires (Unix seconds)
- `extensions`: Application-specific signed metadata (e.g., approval workflow ID, ticket number)

**SignedApproval (envelope):**
- `approval_version`: Envelope structure version (currently 1)
- `payload`: Raw CBOR bytes of `ApprovalPayload` (what gets signed)
- `approver_key`: Who signed this (verifier checks against `required_approvers`)
- `signature`: Signature over domain-separated preimage

**ApprovalMetadata (not signed):**
- `provider`: Identity provider system (e.g., "okta", "aws-iam", "manual")
- `reason`: Optional justification for audit trail

### Signature Preimage

```
preimage = b"tenuo-approval-v1" || approval_version || payload_bytes
```

Where:
- `b"tenuo-approval-v1"`: Domain separation context (17 bytes)
- `approval_version`: u8 (1 byte)
- `payload_bytes`: Raw CBOR serialization of `ApprovalPayload`

**Implementation:**
```rust
const APPROVAL_CONTEXT: &[u8] = b"tenuo-approval-v1";

// Signing
let payload = ApprovalPayload {
    version: 1,
    request_hash,
    nonce: rand::random(),
    external_id: "admin@company.com".into(),
    approved_at: Utc::now().timestamp() as u64,
    expires_at: (Utc::now() + Duration::minutes(5)).timestamp() as u64,
    extensions: BTreeMap::new(),
};

let payload_bytes = cbor::serialize(&payload)?;
let mut preimage = APPROVAL_CONTEXT.to_vec();
preimage.push(1);  // approval_version
preimage.extend_from_slice(&payload_bytes);

let signature = approver_keypair.sign(&preimage);

let signed_approval = SignedApproval {
    approval_version: 1,
    payload: payload_bytes,
    approver_key: approver_keypair.public_key(),
    signature,
};
```

### Verification Flow

```rust
fn verify(
    signed: &SignedApproval,
    required_approvers: &[PublicKey],
    request_hash: &[u8; 32],
) -> Result<ApprovalPayload, VerificationError> {
    
    // 1. Check envelope version
    if signed.approval_version != 1 {
        return Err(VerificationError::UnsupportedApprovalVersion);
    }
    
    // 2. Verify signature over domain-separated preimage
    let mut preimage = APPROVAL_CONTEXT.to_vec();
    preimage.push(signed.approval_version);
    preimage.extend_from_slice(&signed.payload);
    
    signed.approver_key.verify(&preimage, &signed.signature)?;
    
    // 3. Now safe to deserialize (signature is valid)
    let payload: ApprovalPayload = cbor::deserialize(&signed.payload)?;
    
    // 4. Check payload version
    if payload.version != 1 {
        return Err(VerificationError::UnsupportedPayloadVersion);
    }
    
    // 5. Validate approver is authorized
    if !required_approvers.contains(&signed.approver_key) {
        return Err(VerificationError::UnauthorizedApprover);
    }
    
    // 6. Check expiration
    let now = Utc::now().timestamp() as u64;
    if now >= payload.expires_at {
        return Err(VerificationError::ApprovalExpired);
    }
    
    // 7. Validate request binding
    if &payload.request_hash != request_hash {
        return Err(VerificationError::RequestHashMismatch);
    }
    
    Ok(payload)
}
```

### Serialization

**Envelope (SignedApproval):**
```
CBOR Array [
    0: approval_version (u8),
    1: payload (bytes),
    2: approver_key (PublicKey),
    3: signature (Signature),
]
```

**Payload (ApprovalPayload):**
```
CBOR Map {
    0: version (u8),
    1: request_hash (bytes, 32),
    2: nonce (bytes, 16),
    3: external_id (string),
    4: approved_at (u64),
    5: expires_at (u64),
    6: extensions (map<string, bytes>),
}
```

### Why Envelope Pattern

The envelope pattern provides several advantages for approvals:

| Aspect | Without Envelope | With Envelope |
|--------|------------------|---------------|
| **Consistency** | Different pattern from warrants | Matches `SignedWarrant` pattern |
| **Security boundary** | Unclear which fields are signed | Explicit: payload vs. metadata |
| **Extensibility** | Changing struct affects signatures | Add metadata without signature changes |
| **Re-serialization** | Must reconstruct signable bytes | Verify against exact bytes signed |
| **Field order** | Manual maintenance required | Automatic via CBOR |
| **Complexity** | Fewer structs initially | More structs, clearer semantics |

**Design principle alignment:** This follows the same principles outlined in §1 (Envelope Pattern):
- Verify before deserialize
- Fail closed on unknown versions
- Extensibility through metadata fields
- Algorithm agility (signature field is self-describing)

---

## 17. Signed Revocation List (SRL) Wire Format

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

## 18. Revocation Request Wire Format

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

## 19. Error Handling

All verifiers MUST return structured errors with machine-readable error codes. Error codes are organized by category (1000-2199) and map to appropriate HTTP status codes.

```rust
pub struct VerificationError {
    code: ErrorCode,     // Range 1000-2199 (see Appendix A)
    message: String,
    details: Option<HashMap<String, String>>,
}
```

**Common error categories:**
- 1000-1099: Envelope errors (malformed structure)
- 1100-1199: Signature errors (cryptographic verification)
- 1400-1499: Chain validation (delegation rules)
- 1500-1599: Authorization (constraint violations)

See [Appendix A](#appendix-a-error-code-reference) for the complete error code listing and HTTP mapping.

---

## 20. Security Considerations

### 20.1 Cryptographic Security

**Signature verification:**
- Implementations MUST use constant-time comparison for signature verification to prevent timing attacks
- Never re-serialize warrant payloads for verification; use the exact wire bytes
- Verify signatures before deserializing payloads to prevent parser exploits

**Random number generation:**
- PoP nonces, approval nonces, and warrant IDs MUST use cryptographically secure random number generators (CSPRNG)
- Never use predictable values (timestamps, counters) for nonces

**Key management:**
- Private keys MUST never appear in warrants
- Implementations SHOULD support hardware security modules (HSMs) for signing operations
- Key rotation: warrant chains break on key rotation; plan for re-issuance

### 20.2 Denial of Service Protection

**Size limits:**
- Enforce all limits in §13 before full parsing
- Reject oversized warrants at the transport layer when possible
- Set timeouts for verification operations (recommend: 100ms per warrant)

**Chain depth:**
- MAX_CHAIN_DEPTH (64) prevents stack exhaustion
- Implementations SHOULD impose stricter limits (recommend: 10) in production
- Track verification depth to prevent recursion attacks

**Computational complexity:**
- Regex constraints can cause ReDoS (Regular Expression Denial of Service)
- Implementations SHOULD impose regex timeout limits (recommend: 10ms)
- CEL expressions SHOULD have resource limits (recommend: 1000 operations)

### 20.3 Replay Attack Prevention

**PoP challenges:**
- Include timestamp windows to prevent replay
- Include tool name and arguments to prevent cross-request replay
- Include warrant ID to prevent cross-warrant replay
- **Window size configuration:** Use smallest `max_windows` (2-10) that accommodates clock skew; default 5 (±60s) balances security with real-world variance
- **Replay window:** Attacker can replay PoP within configured tolerance (default ±60s); monitor for suspicious patterns

**Approval nonces:**
- 16-byte nonces provide 128 bits of entropy
- Track used nonces within approval validity window (recommend: Redis with TTL)

**Revocation requests:**
- 5-minute expiration window limits replay risk
- Control Plane SHOULD track processed request IDs

### 20.4 Clock Skew and Time Validation

**Time comparisons:**
- Use clock tolerance (±30s for TTL, ±60s default for PoP) to handle legitimate skew
- Reject warrants with `issued_at` far in the future (recommend: >5 minutes)
- Log excessive clock skew for monitoring

**Timestamp validation order:**
1. Check `issued_at` is not too far in future
2. Check `expires_at > issued_at`
3. Check current time is within `[issued_at, expires_at]` ± tolerance

### 20.5 Constraint Validation

**Type confusion:**
- Validate constraint types match argument types
- Reject constraints that don't make semantic sense (e.g., Range on non-numeric)

**Attenuation validation:**
- Follow the normative attenuation matrix (§6.1)
- Reject any attenuation not explicitly permitted
- Conservative approach for complex patterns (require equality)

### 20.6 Parser Security

**CBOR parsing:**
- Use memory-safe CBOR libraries
- Set maximum recursion depth (recommend: 16)
- Reject duplicate map keys if supported by library
- Reject indefinite-length encodings (require deterministic CBOR)

**Integer overflow:**
- All integers must fit in i64 range
- Check for overflow when computing ranges or depths
- Reject bignums (CBOR tags 2/3)

### 20.7 Side-Channel Resistance

**Constant-time operations:**
- Signature verification (library-dependent)
- Warrant ID comparison
- Nonce comparison

**Avoid timing leaks:**
- Verify signatures before returning detailed error messages
- Don't leak which step of verification failed through timing

### 20.8 Key Compromise Scenarios

**Holder key compromise:**
- Attacker can use warrant but cannot issue new ones
- Mitigation: Revoke warrant via Control Plane
- Impact: Limited to compromised warrant's capabilities

**Issuer key compromise:**
- Attacker can issue arbitrary attenuations
- Mitigation: Revoke all warrants issued by compromised key
- Impact: Entire delegation subtree

**Root key compromise:**
- Attacker can issue arbitrary root warrants
- Mitigation: Rotate root keys, redistribute trust anchors
- Impact: Entire system (catastrophic)

### 20.9 Extension Security

**Unknown extensions:**
- Preserve but don't trust unknown extensions
- Fail closed for unknown `tenuo.*` extensions
- Don't use extensions for authorization decisions without validation

**Encrypted extensions:**
- Verify MAC/signature on encrypted data
- Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Include warrant ID in associated data to prevent cross-warrant attacks

### 20.10 Implementation Hardening

**Fail closed:**
- Unknown constraint types → deny
- Unknown warrant versions → deny
- Parse errors → deny
- Missing required fields → deny

**Input validation:**
- Validate all string lengths
- Validate all array/map sizes
- Validate public key and signature lengths match algorithm
- Reject invalid UTF-8 in strings

**Monitoring and logging:**
- Log all verification failures with error codes
- Monitor for suspicious patterns (repeated failures, unusual depths)
- Alert on revocations and key usage patterns

---

## 21. Conformance Testing

Implementations MUST pass all test vectors defined in [test-vectors.md](test-vectors.md) to claim conformance with this specification.

### Required Test Coverage

#### 21.1 Basic Operations
- [ ] Sign and verify a root warrant
- [ ] Sign and verify an attenuated warrant
- [ ] Verify a chain of 3+ warrants
- [ ] Reject expired warrants
- [ ] Reject warrants not yet valid
- [ ] Reject invalid signatures

#### 21.2 Envelope and Versioning
- [ ] Parse envelope version 1
- [ ] Reject envelope version 0
- [ ] Reject envelope version 2+
- [ ] Parse payload version 1
- [ ] Reject payload version 0
- [ ] Reject payload version 2+

#### 21.3 Algorithm Agility
- [ ] Sign and verify with Ed25519
- [ ] Reject unknown algorithm IDs
- [ ] Reject mismatched key/signature algorithms
- [ ] Reject invalid key lengths
- [ ] Reject invalid signature lengths

#### 21.4 Invariant Validation (Critical)
- [ ] I1: Reject if `child.issuer != parent.holder`
- [ ] I2: Reject if `child.depth != parent.depth + 1`
- [ ] I2: Reject if `child.depth > parent.max_depth`
- [ ] I2: Reject if `child.depth > MAX_DELEGATION_DEPTH`
- [ ] I3: Reject if `child.expires_at > parent.expires_at`
- [ ] I4: Reject if child has tools not in parent
- [ ] I4: Reject if child constraints are weaker than parent
- [ ] I5: Reject if `child.parent_hash != SHA256(parent.payload)`
- [ ] I6: Verify PoP signature with holder key (not issuer key)

#### 21.5 Constraint Types (All Standard Types 1-18)
For each constraint type, test:
- [ ] Valid constraint passes
- [ ] Invalid constraint fails
- [ ] Attenuation to same type
- [ ] Attenuation to compatible type (per matrix)
- [ ] Reject invalid attenuation

**Per-type tests:**
1. Exact: Match, mismatch
2. Pattern: `prefix-*`, `*-suffix`, bidirectional (`prefix-*-suffix`, `*mid*`), exact match
3. Range: Within, below, above, boundary conditions
4. OneOf: In set, not in set, empty set
5. Regex: Match, mismatch, invalid regex
6. (Reserved)
7. NotOneOf: Not excluded, excluded, empty exclusions
8. Cidr: In network, out of network, invalid CIDR
9. UrlPattern: Match, mismatch
10. Contains: All present, one missing, empty list
11. Subset: Subset valid, non-subset, empty list
12. All: All pass, one fails, empty list
13. Any: One passes, all fail, empty list
14. Not: Negation correct
15. Cel: Expression true, expression false, invalid CEL
16. Wildcard: Always matches
17. Subpath: Within, outside, traversal attempt
18. UrlSafe: Valid URL, private IP, metadata endpoint

#### 21.6 Edge Cases
- [ ] Empty tool map (valid)
- [ ] Empty constraint set (valid)
- [ ] Empty extensions map (valid)
- [ ] Maximum values (depth=64, TTL=90 days)
- [ ] Minimum values (depth=0)
- [ ] Very long tool names (up to 256 bytes)
- [ ] Very long constraint values (up to 4KB)
- [ ] Large integers (near i64 bounds)
- [ ] Parent hash with no parent (root warrant)

#### 21.7 Size Limits
- [ ] Reject warrant > 64 KB
- [ ] Reject chain > 256 KB
- [ ] Reject > 256 tools
- [ ] Reject > 64 constraints per tool
- [ ] Reject > 64 extension keys
- [ ] Reject extension value > 8 KB

#### 21.8 PoP Verification
- [ ] Valid PoP in current window
- [ ] Valid PoP in past windows (configurable depth)
- [ ] Valid PoP in future windows (configurable depth)
- [ ] Reject PoP outside configured tolerance (default ±60s)
- [ ] Respect max_windows configuration (default 5, range 2-10)
- [ ] Reject PoP with wrong holder key
- [ ] Verify domain separation (context string)

#### 21.9 Approval / Multi-Sig
- [ ] Create and verify SignedApproval with envelope pattern
- [ ] Verify approval signature against payload bytes
- [ ] Reject approval with unauthorized approver key
- [ ] Reject expired approval
- [ ] Reject approval with mismatched request_hash
- [ ] Validate approval nonce uniqueness
- [ ] Test approval extensions (signed metadata)
- [ ] Verify approval_version and payload version handling

#### 21.10 Serialization
- [ ] Round-trip: sign → serialize → deserialize → verify
- [ ] Deterministic CBOR (same input → same bytes)
- [ ] Reject indefinite-length encodings
- [ ] Reject duplicate map keys (if supported)
- [ ] Base64 URL-safe encoding/decoding
- [ ] PEM armor encoding/decoding

#### 21.11 Error Handling
- [ ] Return correct error codes (§19)
- [ ] Include descriptive error messages
- [ ] Don't leak sensitive data in errors

### Test Vector Format

Test vectors MUST include:
1. **Description**: What is being tested
2. **Input**: CBOR bytes (hex-encoded)
3. **Expected output**: Valid/invalid + error code if invalid
4. **Notes**: Any special considerations

**Example:**
```json
{
  "test_id": "basic_001_root_warrant",
  "description": "Valid root warrant with Ed25519 signature",
  "input_hex": "83010102...",
  "expected": "valid",
  "warrant_id": "a3d7f8b2-...",
  "holder": "ed25519:...",
  "tools": ["read_file"]
}
```

---

## Summary

| Feature | Implementation | v1.0 Default |
|---------|----------------|--------------|
| Envelope pattern | `SignedWarrant { payload, signature }` | Yes |
| Envelope version | `envelope_version: u8` | `1` |
| Payload version | `version: u8` | `1` |
| Algorithm agility | `PublicKey { algorithm, bytes }` | Ed25519 (1) |
| Timestamps | `u64` | Unix seconds |
| Tool-scoped constraints | `BTreeMap<String, ConstraintSet>` | Yes |
| Standard constraints | Type IDs 1-127 | Yes |
| Experimental constraints | Type IDs 128-255 | Fail closed |
| Unknown constraints | `Constraint::Unknown` -> fails | Yes |
| Extensions | `BTreeMap<String, Vec<u8>>` | `{}` |
| Reserved namespace | `tenuo:*` only | Rejected |
| Serialization | CBOR | Yes |
| Text encoding | Base64 URL-safe, no padding | Yes |
| Parent pointer | `parent_hash = SHA256(payload_bytes)` | Yes |
| Transport | `WarrantStack` (Root -> Leaf) | Yes |
| PoP challenge | CBOR tuple, 30s windows, configurable tolerance | Yes |
| Approval | Envelope pattern, CBOR payload | Yes |
| SRL | CBOR, monotonic version | Yes |
| RevocationRequest | CBOR tuple | Yes |

---

## References

### Normative

- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", October 2006. https://datatracker.ietf.org/doc/html/rfc4648
- **[RFC 8032]** Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017. https://datatracker.ietf.org/doc/html/rfc8032
- **[RFC 8949]** Bormann, C., Hoffman, P., "Concise Binary Object Representation (CBOR)", December 2020. https://datatracker.ietf.org/doc/html/rfc8949

### Informative

- **[Dennis1966]** Dennis, J.B., Van Horn, E.C., "Programming Semantics for Multiprogrammed Computations", Communications of the ACM, Vol. 9, No. 3, March 1966. https://doi.org/10.1145/365230.365252
- **[Macaroons]** Birgisson, A., Politz, J.G., Erlingsson, U., Taly, A., Vrable, M., Lentczner, M., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014. https://research.google/pubs/pub41892/

---

## Changelog

- **1.0.1** - Specification improvements (2026-01-16)
  - Clarified depth semantics (I2): terminal warrants and delegation capability
  - Enhanced integer value limits with context-specific precision rules
  - Improved constraint attenuation matrix: clarified OneOf→NotOneOf rejection rule
  - Clarified pattern attenuation rules: reserved `**` (discouraged for security), documented `*` and bidirectional wildcards behavior
  - **Made PoP max_windows configurable**: default 5 (±60s), range 2-10, with deployment guidance and corrected tolerance calculations
  - **Refactored Approval to envelope pattern**: Changed from flat struct to `SignedApproval` envelope for consistency with `SignedWarrant`; improves security boundaries and extensibility
  - Added CBOR major type precision to WarrantStack disambiguation
  - Added ConstraintType enum entries for Subpath (17) and UrlSafe (18)
  - **New §19**: Error Codes - machine-readable error codes with HTTP mapping
  - **New §20**: Security Considerations - comprehensive security guidance
  - **New §21**: Conformance Testing - required test coverage for implementations
  - Added explanation for different TTL vs PoP clock tolerances
  - Clarified max TTL as 7,776,000 seconds (90 days)
  - Added note about parent_hash being None for root warrants
- **1.0** - Promoted to normative specification (2026-01-10)
- **0.1.1** - Added PoP, Approval, SRL, RevocationRequest wire formats
- **0.1** - Initial specification

---

## Appendix A: Error Code Reference

### A.1 Error Code Enum

```rust
#[repr(u16)]
pub enum ErrorCode {
    // Envelope errors (1000-1099)
    UnsupportedEnvelopeVersion = 1000,
    InvalidEnvelopeStructure = 1001,
    
    // Signature errors (1100-1199)
    SignatureInvalid = 1100,
    SignatureAlgorithmMismatch = 1101,
    UnsupportedAlgorithm = 1102,
    InvalidKeyLength = 1103,
    InvalidSignatureLength = 1104,
    
    // Payload structure errors (1200-1299)
    UnsupportedPayloadVersion = 1200,
    InvalidPayloadStructure = 1201,
    MalformedCBOR = 1202,
    UnknownPayloadField = 1203,
    MissingRequiredField = 1204,
    
    // Temporal validation errors (1300-1399)
    WarrantExpired = 1300,
    WarrantNotYetValid = 1301,
    IssuedInFuture = 1302,
    TTLExceeded = 1303,
    
    // Chain validation errors (1400-1499)
    InvalidIssuer = 1400,
    ParentHashMismatch = 1401,
    DepthExceeded = 1402,
    DepthViolation = 1403,
    ChainTooLong = 1404,
    ChainBroken = 1405,
    UntrustedRoot = 1406,
    
    // Capability errors (1500-1599)
    ToolNotAuthorized = 1500,
    ConstraintViolation = 1501,
    InvalidAttenuation = 1502,
    CapabilityExpansion = 1503,
    UnknownConstraintType = 1504,
    
    // PoP errors (1600-1699)
    PopSignatureInvalid = 1600,
    PopExpired = 1601,
    PopChallengeInvalid = 1602,
    
    // Multi-sig errors (1700-1799)
    InsufficientApprovals = 1700,
    ApprovalInvalid = 1701,
    ApproverNotAuthorized = 1702,
    ApprovalExpired = 1703,
    UnsupportedApprovalVersion = 1704,
    ApprovalPayloadInvalid = 1705,
    ApprovalRequestHashMismatch = 1706,
    
    // Revocation errors (1800-1899)
    WarrantRevoked = 1800,
    SRLInvalid = 1801,
    SRLVersionRollback = 1802,
    
    // Size limit errors (1900-1999)
    WarrantTooLarge = 1900,
    ChainTooLarge = 1901,
    TooManyTools = 1902,
    TooManyConstraints = 1903,
    ExtensionTooLarge = 1904,
    ValueTooLarge = 1905,
    
    // Extension errors (2000-2099)
    ReservedExtensionKey = 2000,
    InvalidExtensionValue = 2001,
    
    // Reserved namespace errors (2100-2199)
    ReservedToolName = 2100,
}
```

### A.2 Protocol-Specific Representations

Different Tenuo protocols use different error code formats optimized for their context. All formats map to the canonical codes defined in §A.1.

#### Wire Format (CBOR Serialization)

Uses numeric codes 1000-2199 as defined in §A.1. This is the canonical representation.

#### HTTP API (Authorizer Binary)

Uses both numeric codes and kebab-case string names for maximum compatibility:

```json
{
  "authorized": false,
  "error": "constraint-violation",
  "error_code": 1501,
  "message": "Request does not satisfy warrant constraints",
  "warrant_id": "...",
  "tool": "...",
  "request_id": "..."
}
```

**Key mappings:**
- `1100` (SignatureInvalid) → `"signature-invalid"`
- `1300` (WarrantExpired) → `"warrant-expired"`
- `1501` (ConstraintViolation) → `"constraint-violation"`
- `1800` (WarrantRevoked) → `"warrant-revoked"`
- `1405` (ChainBroken) → `"chain-broken"`
- `1402` (DepthExceeded) → `"depth-exceeded"`

#### JSON-RPC (A2A Protocol)

Uses standard JSON-RPC negative codes (-32001 to -32099) with canonical code in data field:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32008,
    "message": "constraint_violation",
    "data": {
      "tenuo_code": 1501,
      "skill": "delete_database"
    }
  }
}
```

**Key mappings:**
- `-32002` (INVALID_SIGNATURE) ↔ `1100` (SignatureInvalid)
- `-32004` (EXPIRED) ↔ `1300` (WarrantExpired)
- `-32008` (CONSTRAINT_VIOLATION) ↔ `1501` (ConstraintViolation)
- `-32009` (REVOKED) ↔ `1800` (WarrantRevoked)
- `-32010` (CHAIN_INVALID) ↔ `1405` (ChainBroken)
- `-32016` (POP_FAILED) ↔ `1600` (PopSignatureInvalid)

Some A2A errors are protocol-specific (e.g., `-32001` MISSING_WARRANT, `-32005` AUDIENCE_MISMATCH) and have no wire format equivalent.

**Rationale:** Different protocols have different conventions:
- HTTP APIs benefit from human-readable kebab-case names in logs
- JSON-RPC follows RFC 4627 convention of negative error codes
- Wire format uses compact numeric codes for efficiency

All three representations are equally valid; the numeric codes 1000-2199 are canonical for cross-protocol compatibility.

### A.3 HTTP Status Code Mapping

| Error Code Range | HTTP Status | Meaning |
|-----------------|-------------|---------|
| 1000-1099 | 400 Bad Request | Malformed envelope |
| 1100-1199 | 401 Unauthorized | Signature verification failed |
| 1200-1299 | 400 Bad Request | Malformed payload |
| 1300-1399 | 401 Unauthorized | Temporal validation failed |
| 1400-1499 | 403 Forbidden | Chain validation failed |
| 1500-1599 | 403 Forbidden | Authorization denied |
| 1600-1699 | 401 Unauthorized | PoP verification failed |
| 1700-1799 | 403 Forbidden | Approval requirements not met |
| 1800-1899 | 401 Unauthorized | Warrant revoked |
| 1900-1999 | 413 Payload Too Large | Size limits exceeded |
| 2000-2099 | 400 Bad Request | Invalid extension |
| 2100-2199 | 400 Bad Request | Reserved namespace violation |

### A.4 Example Error Responses

**HTTP API (Authorizer):**

```json
{
  "authorized": false,
  "error": "constraint-violation",
  "error_code": 1501,
  "message": "Constraint not satisfied",
  "warrant_id": "a3d7f8b2-...",
  "tool": "delete_database",
  "request_id": "..."
}
```

**JSON-RPC (A2A):**

```json
{
  "jsonrpc": "2.0",
  "id": "123",
  "error": {
    "code": -32008,
    "message": "constraint_violation",
    "data": {
      "tenuo_code": 1501,
      "skill": "delete_database"
    }
  }
}
```

**Wire Format (CBOR):**

Error codes in CBOR use the numeric value directly:

```cbor
{
  1: 1501,                    // error_code (numeric)
  2: "Constraint not satisfied",  // message
  3: {                        // details (optional)
    "field": "amount",
    "reason": "Value exceeds maximum"
  }
}
```

The numeric code (1501) is the canonical representation that other protocols derive from.
