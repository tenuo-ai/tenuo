# Tenuo Wire Format Specification

Version: 0.1  
Status: Final Draft  
Last Updated: 2024-12-19

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
    pub parent: Option<WarrantId>,
    pub extensions: BTreeMap<String, Vec<u8>>,
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

If the verifier's CBOR library serializes differently than the signer's (different integer widths, array encodings, map ordering), the bytes differ and verification fails. This is a canonicalization bug — subtle, hard to debug, breaks cross-language compatibility.

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
    
    // 3. Verify signature against raw bytes
    //    NO re-serialization — use payload bytes directly
    issuer.verify(&signed.payload, &signed.signature)?;
    
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

**Rationale:** Envelope version lets you change the crypto wrapper (e.g., switch to COSE_Sign1) without touching payload parsing. Payload version lets you change warrant semantics without touching signature verification.

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

**Clock tolerance:** Implementations should allow ±120 seconds to handle clock skew.

---

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
    // Future standard types: 6-127
    
    // Experimental / private use (128-255)
    // See "Constraint Type Ranges" below
}

pub enum Constraint {
    /// Exact string match
    Exact(String),
    
    /// Glob pattern (*, **, ?)
    Pattern(String),
    
    /// Numeric range (inclusive)
    Range {
        min: Option<i64>,
        max: Option<i64>,
    },
    
    /// Value must be in list
    OneOf(Vec<String>),
    
    /// Regular expression match
    Regex(String),
    
    /// Unknown constraint type (deserialized but not understood)
    Unknown {
        type_id: u8,
        payload: Vec<u8>,
    },
}
```

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
            Self::Range { min, max } => check_range(value, *min, *max),
            Self::OneOf(allowed) => allowed.contains(&value.to_string()),
            Self::Regex(pattern) => regex_match(pattern, value),
            
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

**Deployment scenario:**

1. v0.2 adds `CIDR` constraint (type ID = 6)
2. Issuer creates warrant with `CIDR("10.0.0.0/8")`
3. Old verifier (v0.1) sees type ID 6, deserializes as `Unknown`
4. Authorization check fails (safe default)
5. Old verifier upgraded to v0.2, now understands CIDR
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
| `tenuo.` | Reserved for future Tenuo use |
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

**Note:** The `_` prefix is *not* reserved. Applications may freely use tool names starting with underscore (e.g., `_internal_helper`, `_debug_tool`).

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
    9: parent (bytes, 16, optional),
    10: extensions (map<string, bytes>),
}
```

**Rules:**

1. Envelope uses array (fixed field order)
2. Payload uses map with integer keys (allows sparse fields)
3. `BTreeMap` for deterministic key ordering within maps
4. Unknown fields at end of payload map are ignored but preserved in signature

**Why CBOR:**

- Compact binary format
- Self-describing (no schema required)
- Deterministic serialization possible
- Wide language support
- Used by COSE, WebAuthn, FIDO2

---

## 11. Base64 Encoding

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

---

## 12. Size Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max warrant size | 64 KB | Prevents memory exhaustion |
| Max tools per warrant | 256 | Practical limit |
| Max constraints per tool | 64 | Practical limit |
| Max extension keys | 64 | Practical limit |
| Max extension value size | 8 KB | Prevents abuse |
| Max chain depth | 64 | Prevents DoS in verification |
| Max tool name length | 256 bytes | Practical limit |
| Max constraint value length | 4 KB | Practical limit |

Verifiers must reject warrants exceeding these limits before full parsing.

---

## 13. Version Negotiation (Network Protocols)

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

---

## Changelog

- **0.1** — Initial specification
- **0.1.1** — Added envelope pattern, timestamp precision, size limits
- **0.1.2** — Removed `_` from reserved prefixes; added experimental constraint range (128–255); clarified version negotiation scope
