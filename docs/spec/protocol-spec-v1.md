# Tenuo Protocol Specification

**Version:** 1.0  
**Status:** Normative  
**Date:** 2026-01-01
**Documentation Revision:** 3 (2026-01-21)
**Authors:** Niki Aimable Niyikiza

**Related Documents:**
- [wire-format-v1.md](wire-format-v1.md) - Wire Format Specification (CBOR encoding, field IDs)
- [test-vectors.md](test-vectors.md) - Byte-exact test vectors for validation

---

## Revision History

- **Rev 3** (2026-01-21): Verification and enforcement. Confirmed normative invariants (I1-I6) against codebase and test vectors.
- **Rev 2** (2026-01-10): Reconciled with v1.0 wire format.
- **Rev 1** (2026-01-01): Initial release.

---

## Abstract

Tenuo is a capability-based authorization protocol for AI agent systems. It enables secure delegation of authority through cryptographically signed tokens called *warrants*, ensuring that compromised or misbehaving agents cannot exceed their granted permissions. Warrants support *attenuation* (authority can only shrink, never expand) and *proof-of-possession* (stolen tokens are useless without the holder's private key).

> **Normative Precedence:** In case of conflict between this document and [wire-format-v1.md](wire-format-v1.md), the wire format specification is authoritative for encoding details.

---

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

| Term | Definition |
|------|------------|
| **Warrant** | A signed capability token granting specific permissions to a holder |
| **Issuer** | The entity whose signature authorizes a warrant |
| **Holder** | The entity authorized to use a warrant (bound via public key) |
| **Verifier** | The entity validating the warrant chain and PoP (e.g., the Authorizer) |
| **Attenuation** | The process of creating a child warrant with reduced authority |
| **Delegation** | Granting authority to another entity via attenuation |
| **Proof-of-Possession (PoP)** | Cryptographic proof that the presenter controls the holder's private key |
| **Constraint** | A restriction on argument values (e.g., `Pattern("/data/*.pdf")`) |
| **Clearance** | A monotonic trust level (0-255) used to enforce provenance requirements |
| **Terminal** | A warrant state where `depth >= max_depth`, prohibiting further delegation |
| **Envelope** | The outer CBOR structure containing the payload and signature |
| **WarrantStack** | An ordered array of warrants from root to leaf for chain verification |
| **Control Plane** | The trusted root authority that issues initial warrants |
| **Trusted Root** | A public key the verifier trusts as a chain anchor |

---

## 1. Threat Model

### 1.1 Protected Threats

| Threat | Mitigation |
|--------|------------|
| **Prompt injection** | Warrants constrain what tools/args are allowed regardless of agent intent |
| **Stolen warrant** | Proof-of-Possession requires holder's private key |
| **Privilege escalation** | Attenuation ensures child ⊆ parent authority |
| **Confused deputy** | PoP binds (warrant, tool, args) tuple to specific invocation |
| **Replay attack** | Time-windowed PoP signatures (~2 min validity) |
| **Chain forgery** | Cryptographic signatures at every delegation link |
| **Unbounded delegation** | MAX_DELEGATION_DEPTH (64) enforced |

### 1.2 Out of Scope

| Threat | Reason |
|--------|--------|
| **Key compromise** | Tenuo assumes holder keys are secure; revocation is optional |
| **Denial of service** | Rate limiting is application-layer concern |
| **Side channels** | Tenuo is a protocol, not an implementation |
| **Malicious Control Plane** | Root of trust; if compromised, all warrants are suspect |

### 1.3 Trust Assumptions

1. The Control Plane is trusted and issues only valid warrants
2. Cryptographic primitives (Ed25519, SHA-256) are secure
3. Clocks are synchronized within ±30 seconds
4. Private keys are protected by their holders

### 1.4 Invariants Summary

The protocol enforces six invariants during chain verification and authorization:

| ID | Name | Rule |
|----|------|------|
| I1 | Delegation Authority | `child.issuer == parent.holder` |
| I2 | Depth Monotonicity | `child.depth == parent.depth + 1` |
| I3 | TTL Monotonicity | `child.expires_at ≤ parent.expires_at` |
| I4 | Capability Monotonicity | `child.capabilities ⊆ parent.capabilities` |
| I5 | Cryptographic Linkage | `child.parent_hash == SHA256(parent.payload_bytes)` |
| I6 | Proof-of-Possession | PoP signature verifies under `warrant.holder` |

---

## 2. Warrant Model

### 2.1 Structure

A warrant is a signed envelope containing a payload:

```
SignedWarrant {
    envelope_version: u8,       // Currently 1
    payload: bytes,             // CBOR-encoded WarrantPayload
    signature: Signature,       // Over b"tenuo-warrant-v1" || envelope_version || payload
}
```

### 2.2 Warrant Types

| Type | Purpose | Use Case |
|------|---------|----------|
| **Execution** | Invoke specific tools with constraints | Worker agents |
| **Issuer** | Grant execution warrants to others | Orchestrators, planners |

### 2.3 Fields

#### 2.3.1 Common Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | u8 | Yes | Payload version (currently 1) |
| `id` | bytes[16] | Yes | UUIDv7 warrant identifier |
| `warrant_type` | u8 | Yes | 0 = Execution, 1 = Issuer |
| `holder` | PublicKey | Yes | Authorized user of this warrant |
| `issuer` | PublicKey | Yes | Signer of this warrant |
| `issued_at` | u64 | Yes | Unix timestamp (seconds) |
| `expires_at` | u64 | Yes | Unix timestamp (seconds) |
| `depth` | u32 | Yes | Current delegation depth (0 = root) |
| `max_depth` | u8 | Yes | Maximum allowed depth (ceiling) |
| `parent_hash` | bytes[32] | No | SHA-256 of parent's payload_bytes (null for root) |
| `clearance` | u8 | No | Privilege level (higher = more access) |
| `required_approvers` | array\<PublicKey\> | No | Keys that must approve execution |
| `min_approvals` | u32 | No | Threshold (default: all required_approvers) |
| `extensions` | map | No | Application-specific metadata |

> **Note:** Approvals are single-layer signatures. Unlike warrants, approvers cannot delegate their approval authority to sub-approvers. Each approval MUST be signed directly by a key in `required_approvers`.

> **Note:** `depth` is semantically bounded to `[0, 64]` regardless of wire width. Verifiers MUST reject warrants with `depth > MAX_DELEGATION_DEPTH (64)`.

#### 2.3.2 Execution Warrant Fields

| Field | Type | Description |
|-------|------|-------------|
| `tools` | map\<string, ConstraintSet\> | Tool name to argument constraints |

#### 2.3.3 Issuer Warrant Fields

| Field | Type | Description |
|-------|------|-------------|
| `issuable_tools` | array\<string\> | Tools this issuer can grant |
| `max_issue_depth` | u32 | Max depth for issued warrants |
| `constraint_bounds` | ConstraintSet | Limits on issued constraints |

> **Note:** `max_depth` is `u8` because MAX_DELEGATION_DEPTH is 64. The `depth` and `max_issue_depth` fields are `u32` for wire compatibility but are semantically bounded to [0, 64]. Verifiers MUST reject warrants with `depth > 64`.

### 2.4 Issuer Warrant Rules

- Issuer warrants MUST have an empty `tools` map
- `constraint_bounds` limits what constraints can be granted to issued warrants
- `max_issue_depth` limits the `max_depth` of issued warrants (not their `depth`)
- Issuer warrants can be attenuated to other issuer warrants (same rules apply)

**Example:** An issuer warrant with:
```json
"constraint_bounds": {"path": [2, {"pattern": "/data/*"}]}
```
can only issue execution warrants where `path` is *narrower* than `/data/*`:
- `Pattern("/data/reports/*")` - valid (subset of `/data/*`)
- `Exact("/data/q3.pdf")` - valid (single file within `/data/`)
- `Pattern("/logs/*")` - REJECTED (not within bounds)
- `Wildcard` - REJECTED (broader than bounds)
 
> **Enforcement:** Verifiers MUST reject any child warrant that exceeds the constraint bounds or depth limits defined by its parent Issuer warrant.


### 2.5 Example

```json
{
  "id": "01942b4e-7dec-7123-a765-00a0c91e6bf6",
  "warrant_type": 0,
  "tools": {
    "read_file": {"path": [1, "/data/q3.pdf"]}
  },
  "holder": {"algorithm": 1, "bytes": "abc..."},
  "issuer": {"algorithm": 1, "bytes": "xyz..."},
  "issued_at": 1736400000,
  "expires_at": 1736500000,
  "depth": 1,
  "max_depth": 3
}
```

---

## 3. Constraints

### 3.1 Constraint Types

| Type | ID | Wire Value | Description | Example |
|------|-----|------------|-------------|---------|
| Exact | 1 | `{value: any}` | Exact value match | `Exact("/data/report.pdf")` |
| Pattern | 2 | `{pattern: string}` | Glob pattern | `Pattern("/data/*.pdf")` |
| Range | 3 | `{min?, max?: f64}` | Numeric bounds | `Range(min=0, max=1000)` |
| OneOf | 4 | `{values: [any]}` | Set membership | `OneOf(["dev", "staging"])` |
| Regex | 5 | `{pattern: string}` | Regular expression | `Regex("^[a-z]+\\.pdf$")` |
| *Reserved* | 6 | - | Future IntRange (i64) | - |
| NotOneOf | 7 | `{excluded: [any]}` | Set exclusion | `NotOneOf(["prod"])` |
| Cidr | 8 | `{network: string}` | IP range | `Cidr("10.0.0.0/8")` |
| UrlPattern | 9 | `{pattern: string}` | URL matching. **Note**: `https://example.com/` (trailing slash) parses as "Any Path" (Wildcard). Use `https://example.com/*` to restrict to root. | `UrlPattern("https://*.example.com/*")` |
| Contains | 10 | `{required: [any]}` | List contains values | `Contains(["admin"])` |
| Subset | 11 | `{allowed: [any]}` | Array subset | `Subset(["read", "write"])` |
| All | 12 | `{constraints: [C]}` | Logical AND | `All([...])` |
| Any | 13 | `{constraints: [C]}` | Logical OR | `Any([...])` |
| Not | 14 | `{constraint: C}` | Logical NOT | `Not(Pattern("*.exe"))` |
| Cel | 15 | `{expr: string}` | CEL expression | `Cel("size < 1000000")` |
| Wildcard | 16 | `null` | Any value | `Wildcard()` |
| Subpath | 17 | `{root: string, ...}` | Path containment | `Subpath("/data")` |
| UrlSafe | 18 | `{schemes: ["https"], ...}` | SSRF protection | `UrlSafe()` |

> **Security Note (CEL):** CEL expressions execute in a sandbox with limited functions. Implementations SHOULD enforce execution timeouts (recommended: 10ms) and memory limits to prevent resource exhaustion attacks.

> **Security Note (Regex):** Regex patterns are vulnerable to ReDoS (catastrophic backtracking). Implementations SHOULD use bounded regex engines with backtrack limits or enforce execution timeouts.

### 3.2 Constraint Lattice

Constraints form a partial order. Attenuation moves toward more restrictive types:

```
                        Wildcard (⊤)
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
     Pattern              Range               OneOf             Subpath           UrlSafe
        │                    │                    │                    │                 │
        └────────────────────┼────────────────────┼────────────────────┼─────────────────┘
                             │
                          Exact (⊥)
```

**Validity rule:** A child constraint C_child is valid iff for all v: C_child(v) implies C_parent(v)

### 3.3 Serialization

Constraints are CBOR arrays: `[type_id, value]`

The `value` structure varies by type. For types with a single field, the value is inlined directly. For types with multiple fields, a map is used:

```
Exact(1):     [1, "/data/q3.pdf"]           // Inlined value
Pattern(2):   [2, {"pattern": "/data/*.pdf"}]
Range(3):     [3, {"min": 0, "max": 1000}]
OneOf(4):     [4, {"values": ["dev", "staging"]}]
Wildcard(16): [16, null]                    // No value needed
Subpath(17):  [17, {"root": "/data"}]
UrlSafe(18):  [18, {"schemes": ["https"], "block_private": true}]
```

### 3.4 Unknown Handling

| Location | Unknown Data | Behavior |
|----------|--------------|----------|
| Payload fields | Unknown CBOR keys | **REJECT** |
| Constraint type IDs | Unrecognized ID | Deserialize to Unknown, **FAIL** at authorization |
| Extension keys (`tenuo.*`) | Reserved namespace | **REJECT** (fail closed) |
| Extension keys (user-defined) | Any other key | **PRESERVE** (passthrough) |

If a constraint wire value is not of the expected CBOR type, it MUST be rejected.

Unknown constraints participate in attenuation checks as opaque values and MUST NOT be removed or weakened.

### 3.5 Constraint Type Registry

| Range | Allocation |
|-------|------------|
| 1-18 | Core (this spec) |
| 19-127 | Reserved (future specs) |
| 128-255 | Experimental (fail closed) |

---

## 4. Attenuation
 
> **Enforcement Lifecycle:**
> *   **At Attenuation (Issuer):** The issuer MUST ensure all generated child warrants satisfy these invariants.
> *   **At Verification (Verifier):** The verifier MUST strictly enforce all invariants defined below (I1-I5). Any violation MUST result in chain rejection.


### 4.1 Delegation Authority (Invariant I1)

```
child.issuer == parent.holder
```

The parent's holder is the only entity authorized to delegate. This establishes an unambiguous audit trail.

### 4.2 Monotonicity Invariant (I4)

Every dimension MUST satisfy: **child ⊆ parent**

| Dimension | Rule | Violation |
|-----------|------|-----------|
| Capabilities | child_caps ⊆ parent_caps | Cannot add tools or widen constraints |
| TTL | child_expires ≤ parent_expires | Cannot extend |
| Depth | child_depth == parent_depth + 1 | Must increment exactly |
| Clearance | child_clearance ≤ parent_clearance | Cannot escalate privilege |

**Clearance semantics:**
- Single global scalar per warrant (not tool-scoped)
- Default value is 0 if absent
- Higher numbers mean more privilege
- Tool requirements compare against it monotonically

### 4.3 Depth Limits (Invariant I2)

```
child.depth == parent.depth + 1
child.depth <= MAX_DELEGATION_DEPTH (64)
child.depth <= parent.max_depth
```

**Note:** `max_depth` is an absolute ceiling, not a remaining count. A warrant is terminal when `depth >= max_depth`.

### 4.4 TTL Monotonicity (Invariant I3)

```
child.expires_at <= parent.expires_at
child.ttl <= MAX_WARRANT_TTL_SECS (90 days)
```

### 4.5 Required Narrowing

Every delegation SHOULD narrow at least one dimension:
- `tools` set is a strict subset, OR
- Any constraint becomes strictly stronger, OR
- `expires_at` decreases, OR
- `clearance` decreases

This is guidance, not a verifier invariant.

### 4.6 Cryptographic Linkage (Invariant I5)

```
child.parent_hash == SHA256(parent.payload_bytes)
```

Every child warrant is cryptographically bound to its parent via hash of the parent's payload. This prevents **chain splicing attacks**, where an attacker attempts to "reparent" a valid child warrant to a different, less restrictive parent warrant (e.g., swapping a production parent for a staging parent) to bypass attenuation or context restrictions.

---

## 5. Chain Verification

### 5.1 WarrantStack Model

Delegation chains are verified using a WarrantStack - an ordered array from root to leaf:

```
WarrantStack = [SignedWarrant, SignedWarrant, ...]  // Root -> Leaf
```

### 5.2 Verification Algorithm

> **Critical: Verify-before-deserialize.** For every SignedWarrant:
> 1. Extract (envelope_version, payload_bytes, signature)
> 2. Verify signature against raw payload_bytes BEFORE deserializing
> 3. Only after verification, parse payload fields

```python
def verify_chain(stack: list[Warrant], trusted_roots: set[PublicKey]) -> bool:
    if not stack:
        raise ChainVerificationFailed("Empty stack")
    
    # Root must be from trusted issuer
    if stack[0].issuer() not in trusted_roots:
        raise ChainNotAnchored("Root issuer not trusted")
    
    # Verify each link
    for i in range(1, len(stack)):
        parent, child = stack[i-1], stack[i]
        
        # I1: Delegation authority
        assert child.issuer() == parent.holder()
        
        # I2: Depth monotonicity
        assert child.depth() == parent.depth() + 1
        assert child.depth() <= parent.max_depth()
        
        # I3: TTL monotonicity
        assert child.expires_at() <= parent.expires_at()
        
        # I4: Capability attenuation
        assert child.capabilities() <= parent.capabilities()
        
        # I5: Cryptographic linkage
        assert child.parent_hash() == SHA256(parent.payload_bytes())
        
        # Signature verification (with domain separation)
        preimage = b"tenuo-warrant-v1" + bytes([child.envelope_version()]) + child.payload_bytes()
        verify(child.issuer(), preimage, child.signature())
    
    return True
```

### 5.3 Trust Anchors

Root warrants are NOT required to be self-signed. Trust is established by:

```python
if chain[0].issuer() not in verifier.trusted_roots:
    raise ChainNotAnchored("root issuer not trusted")
```

| Question | Answer |
|----------|--------|
| What makes a root trusted? | Root's issuer is in verifier's trusted_roots |
| Must issuer == holder? | No. Self-signing is common but not required |
| How to rotate? | Add new key to trusted_roots, issue new warrants, remove old |

### 5.4 Cycle Protection

| Pattern | Status |
|---------|--------|
| Same warrant ID twice | BLOCKED (cycle detection) |
| Holder A->B->A (different warrants) | ALLOWED (monotonicity makes it safe) |
| Self-issuance | BLOCKED (violates separation of duties; issuer cannot grant execution to themselves) |

---

## 6. Authorization Logic

Authorization applies a verified chain to a specific request:

```python
def authorize(warrant, tool, args, pop_signature, approvals=[], tool_reqs={}):
    """Check if a request is authorized by the warrant.
    
    Args:
        tool_reqs: Maps tool names to required clearance level (u8).
                   Default requirement is 0 if not specified.
    Precondition: warrant's chain has already passed verify_chain().
    """
    # 1. Check tool is allowed
    if tool not in warrant.tools():
        raise ToolNotAllowed(tool)
    
    # 2. Check clearance meets tool requirements
    required_clearance = tool_reqs.get(tool, 0)
    if warrant.clearance() < required_clearance:
        raise InsufficientClearance(f"Have {warrant.clearance()}, need {required_clearance}")
    
    # 3. Check constraints are satisfied
    for arg_name, arg_value in args.items():
        constraint = warrant.constraint_for(tool, arg_name)
        if not constraint.satisfied_by(arg_value):
            raise ConstraintNotSatisfied(arg_name, arg_value, constraint)
    
    # 4. Check warrant not expired
    if now() > warrant.expires_at():
        raise WarrantExpired()
    
    # 5. Verify Proof-of-Possession (§7)
    verify_pop(warrant, pop_signature, tool, args)
    
    # 6. Multi-sig enforcement (if required)
    if warrant.required_approvers():
        valid = count_valid_approvals(warrant, tool, args, approvals)
        if valid < warrant.min_approvals():
            raise InsufficientApprovals(f"Got {valid}, need {warrant.min_approvals()}")
    
    return True
```

**Key distinction:**
- **Chain verification** (§5): Validates signatures, invariants, linkage - no request context
- **Authorization** (§6): Applies warrant to (tool, args, approvals) - requires request context

---

## 7. Proof-of-Possession

### 7.1 Challenge Structure

```
PopChallenge = (warrant_id, tool, sorted_args, timestamp_window)
Preimage = b"tenuo-pop-v1" || CBOR(PopChallenge)
```

| Field | Type | Description |
|-------|------|-------------|
| warrant_id | string | Hex-encoded UUID of the warrant |
| tool | string | Tool being invoked |
| sorted_args | array | `[(key, value), ...]` sorted lexicographically by key |
| timestamp_window | i64 | `floor(now / 30) * 30` |

**Domain separation:** The `tenuo-pop-v1` prefix prevents cross-protocol signature reuse.

### 7.2 Signature Verification (Invariant I6)

```python
POP_CONTEXT = b"tenuo-pop-v1"

def verify_pop(warrant, signature, tool, args, max_windows=5):
    """
    Verify Proof-of-Possession signature.

    Args:
        max_windows: Configurable clock skew tolerance
                     - Default: 5 (±60s, recommended for production)
                     - Min: 2 (±30s, controlled environments only)
                     - Max: 10 (±150s, protocol ceiling)
    """
    now = int(time.time())
    sorted_args = sorted(args.items())

    # Check windows: 0 (current), -1 (past), +1 (future), -2, +2...
    for i in range(max_windows):
        offset = 0 if i == 0 else ((i + 1) // 2) * (-1 if i % 2 == 1 else 1)
        window = ((now // 30) + offset) * 30

        challenge = (warrant.id, tool, sorted_args, window)
        preimage = POP_CONTEXT + cbor_serialize(challenge)

        if warrant.holder.verify(preimage, signature):
            return True

    return False
```

### 7.3 Time Window Enforcement

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Context | `tenuo-pop-v1` | Domain separation (FIXED) |
| Window size | 30 seconds | Groups signatures into buckets (FIXED) |
| Max windows | **5** (default) | **Configurable** clock skew tolerance (range: 2-10) |
| Clock tolerance | ±60 seconds (default) | Handles distributed clock skew |

**Configuration guidance:**

| max_windows | Tolerance | Recommended For |
|-------------|-----------|-----------------|
| 2 | ±30s | High-security with strict NTP (minimal) |
| 3 | ±30s | Tight control, modern data centers with NTP |
| **5** | **±60s** | **Modern cloud/data center (RECOMMENDED DEFAULT)** |
| 7 | ±90s | Edge/IoT with occasional NTP drift |
| 10 | ±150s | Legacy systems, unreliable clocks (maximum) |

> **Security principle:** Use the smallest `max_windows` value that accommodates your deployment environment. Smaller windows reduce replay attack surface.

### 7.4 Replay Protection

Tenuo is **stateless by design**. The Verifier does not track used PoP signatures. Defense layers:

| Layer | Protection |
|-------|------------|
| Short TTL | Warrants expire in minutes |
| PoP binding | Signature covers (warrant, tool, args, window) |
| Holder key | Attacker needs private key to use stolen PoP |
| Time windows | ±60s default (configurable 30s-150s) |

> **SHOULD:** For high-value operations (financial transactions, irreversible actions), applications SHOULD implement server-side idempotency. The recommended **dedup key** is a hash of `(warrant_id, tool, canonical_args)` and SHOULD be checked before execution to prevent replay of the same request. SDKs provide a `dedup_key()` helper for this purpose.

### 7.5 PoP Configuration

The `max_windows` parameter (default 5, range 2-10) configures clock skew tolerance for Proof-of-Possession verification:

- **Default 5 (±60s):** Recommended for modern cloud/data center deployments
- **High-security 2 (±30s):** For financial transactions with strict NTP
- **Edge/IoT 7 (±90s):** For environments with unreliable time sync
- **Maximum 10 (±150s):** Only for legacy systems (indicates clock problems)

**Configuration:**
```python
from tenuo import Authorizer

authorizer = Authorizer(pop_max_windows=5)  # Default
```

See [wire-format-v1.md §15](wire-format-v1.md#15-proof-of-possession-pop-wire-format) for complete configuration details, tolerance calculations, and deployment guidance.

---

## 8. Serialization

### 8.1 Wire Format

```
SignedWarrant = CBOR Array [
    0: envelope_version (u8),
    1: payload (bytes),
    2: signature (Signature),
]

Signature = CBOR Array [
    0: algorithm (u8),  // 1 = Ed25519
    1: bytes (bytes),
]

WarrantPayload = CBOR Map {
    0: version,
    1: id,
    2: warrant_type,
    3: tools,
    4: holder,
    5: issuer,
    6: issued_at,
    7: expires_at,
    8: max_depth,
    9: parent_hash,         // SHA256 of parent payload (optional)
    10: extensions,
    11: issuable_tools,     // Issuer warrants only (optional)
    12: (reserved),
    13: max_issue_depth,    // Issuer warrants only (optional)
    14: constraint_bounds,  // Issuer warrants only (optional)
    15: required_approvers, // Multi-sig (optional)
    16: min_approvals,      // Multi-sig threshold (optional)
    17: clearance,          // Privilege level (optional)
    18: depth,              // Current delegation depth
    // session_id is stored in extensions["tenuo.session_id"]
}
```

### 8.2 Deterministic CBOR Requirements (RFC 8949 §4.2)

- Map keys: Sorted by byte-wise lexicographic order
- Integers: Minimal encoding
- No indefinite-length arrays or maps
- Floats: IEEE 754 binary64
- **Duplicate map keys: Senders MUST NOT produce; verifier behavior is undefined** (see wire-format-v1.md)

Verifiers MUST reject non-deterministic encodings. Signatures are computed over deterministic CBOR only.

### 8.3 Transport Encoding

- **Binary:** Raw CBOR
- **Text:** Base64 URL-safe, no padding (RFC 4648 §5)

### 8.4 PEM Armor

```
-----BEGIN TENUO WARRANT-----
(Base64 of CBOR SignedWarrant)
-----END TENUO WARRANT-----
```

### 8.5 Signature Preimage

Warrant signatures are computed over:

```
preimage = b"tenuo-warrant-v1" || envelope_version || payload_bytes
```

This domain separation prevents cross-protocol signature reuse.

---

## 9. Protocol Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| MAX_DELEGATION_DEPTH | 64 | Prevents unbounded chains |
| MAX_WARRANT_TTL_SECS | 90 days | Protocol ceiling |
| MAX_WARRANT_SIZE | 64 KB | Memory exhaustion |
| MAX_STACK_SIZE | 256 KB | Chain size limit |
| PoP Window | 30 seconds | Replay protection (FIXED) |
| PoP Max Windows (Default) | 5 | Clock skew tolerance (RECOMMENDED: ±60s) |
| PoP Max Windows (Min) | 2 | Minimum allowed (±30s) |
| PoP Max Windows (Max) | 10 | Protocol ceiling (±150s) |

---

## 10. Error Codes

| Code | Description |
|------|-------------|
| `chain_not_anchored` | Root issuer not in trusted_roots |
| `signature_invalid` | Cryptographic verification failed |
| `warrant_expired` | Current time > expires_at |
| `depth_exceeded` | Depth > max_depth or > MAX_DELEGATION_DEPTH |
| `ttl_exceeded` | Child expires after parent |
| `attenuation_invalid` | Child capabilities exceed parent |
| `pop_failed` | PoP signature invalid or expired |
| `tool_not_allowed` | Tool not in warrant's capabilities |
| `constraint_not_satisfied` | Argument violates constraint |
| `unknown_field` | Payload contains unknown CBOR keys |
| `self_issuance` | Holder cannot delegate to themselves (child.holder == parent.holder) |
| `revoked` | Warrant ID appears in active Signed Revocation List |

---

## 11. Revocation

### 11.1 Design Philosophy

Tenuo favors **short TTLs over revocation**. A 5-minute warrant that expires naturally is simpler and safer than a 24-hour warrant that might need revocation.

However, revocation is provided for cases where:
- Warrants have longer TTLs for operational reasons
- Key compromise is detected
- Policy violations require immediate termination

### 11.2 Signed Revocation List (SRL)

A Signed Revocation List is a verifier-side structure:

```
SignedRevocationList {
    version: u64,               // Monotonically increasing
    issued_at: u64,             // Unix timestamp
    issuer: PublicKey,          // Control Plane key
    warrant_ids: array<string>, // Revoked warrant IDs
    signature: Signature,       // Signed by Control Plane
}
```

**Properties:**
- **Signed** by the Control Plane (same trust anchor as warrants)
- **Versioned** for update ordering; verifier MUST reject rollback to older version
- **Additive** - revocations are never removed; new SRLs only add entries

### 11.3 Revocation Request

Authorized parties can request revocation:

| Requestor | Can Revoke |
|-----------|------------|
| Warrant holder | Their own warrant (surrender) |
| Warrant issuer | Warrants they issued |
| Control Plane | Any warrant |

```
RevocationRequest {
    warrant_id: string,
    requestor: PublicKey,
    reason: string,
    timestamp: u64,
    signature: Signature,
}
```

### 11.4 Verifier Behavior

Verifiers receiving an SRL MUST:
1. Verify the SRL signature against the Control Plane key
2. Check that SRL version is ≥ current version (no rollback)
3. Reject any warrant whose ID appears in the SRL

### 11.5 Design Trade-offs

| Approach | Tenuo Choice | Rationale |
|----------|--------------|-----------|
| Online revocation check | No | Breaks stateless verifier design |
| Bloom filters | No | False positives unacceptable |
| Full SRL at verifiers | Yes | Simple, deterministic |
| Delta updates | Optional | Implementation detail |

---

## 12. Security Considerations

### 12.1 Cryptographic Assumptions

- Ed25519 signatures are unforgeable (128-bit security)
- SHA-256 is collision-resistant
- UUIDv7 provides sufficient entropy for warrant IDs

### 12.2 Implementation Pitfalls

| Pitfall | Consequence | Mitigation |
|---------|-------------|------------|
| Deserialize before verify | Signature bypass | Verify raw bytes first |
| Missing I1 check | Unauthorized delegation | Always verify child.issuer == parent.holder |
| PoP against issuer | Holder bypass | Always verify against warrant.holder |
| Strip unknown fields | Signature invalidation | Preserve and reject |

### 12.3 Deployment Considerations

- Use short TTLs (5-15 minutes) rather than revocation when possible
- Pin trusted_roots explicitly
- Log all authorization decisions for audit
- Consider SRL for high-security deployments

### 12.4 Common Misconfigurations

> [!CAUTION]
> The following configurations create security vulnerabilities:

| Misconfiguration | Risk | Mitigation |
|------------------|------|------------|
| Empty `trusted_roots` | Accepts any chain | Always configure trusted root keys |
| Missing PoP verification | Token theft | Require PoP for all agent requests |
| TTL > 1 hour | Revocation window too large | Use 5-15 minute TTLs |
| Ignoring unknown fields | Forward compatibility issues | Fail closed on unknown |
| Skipping depth check | Unbounded delegation | Enforce MAX_DELEGATION_DEPTH |
| Clearance not enforced | Privilege escalation | Verify clearance ≥ required |

---

## 13. Algorithm Agility

### 13.1 Current Algorithms

| Purpose | Algorithm | ID |
|---------|-----------|-----|
| Signatures | Ed25519 | 1 |
| Hashing | SHA-256 | - |

### 13.2 Extension Path

The `algorithm` field in Signature and PublicKey enables future algorithms:

| ID | Algorithm | Status |
|----|-----------|--------|
| 1 | Ed25519 | Required |
| 2 | Ed448 | Reserved |
| 3-4 | ML-DSA (Dilithium) | Reserved (post-quantum) |

Verifiers MUST reject unknown algorithm IDs.

> [!NOTE]
> **Quantum Threats:** Ed25519 is vulnerable to quantum attacks (Shor's algorithm). Algorithm IDs 3-4 are reserved for NIST-approved post-quantum algorithms (ML-DSA/Dilithium). Deployments requiring long-term security (>10 years) should plan migration paths and ensure verifiers already reject unknown IDs.

---

## Appendix A: Test Vectors

Test vectors are provided in [test-vectors.md](test-vectors.md). They include:

- **A.1** Minimal valid execution warrant
- **A.3** Valid 3-level chain (root -> orchestrator -> worker)
- **A.4** Invalid chain (I1 violation)
- **A.5** Invalid chain (expired warrant)
- **A.6** PoP verification case

Each test vector includes:
- Fixed key material (deterministic seeds)
- Fixed timestamps
- Payload CBOR (hex)
- Signature (hex)

---

## Appendix B: Prior Art

| System | Relationship to Tenuo |
|--------|-----------------------|
| **Macaroons** | Inspiration for attenuation; Tenuo adds PoP and structured constraints |
| **Biscuit** | Similar datalog-based approach; Tenuo is simpler, focused on AI agents |
| **UCAN** | JWT-based; Tenuo uses CBOR for compactness |
| **CaMeL** | Academic inspiration; Tenuo is production-focused implementation |
| **OAuth 2.0** | Identity-based; Tenuo is capability-based |

---

## Appendix C: Scope Boundaries

| Tenuo Owns | Tenuo Does NOT Own |
|------------|--------------------|
| Warrant format | Tool implementations |
| Constraint evaluation | Argument extraction |
| Chain verification | Transport security (TLS) |
| PoP verification | Key management |
| Attenuation rules | Policy authoring UI |

---

## References

### Normative

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, March 1997. https://datatracker.ietf.org/doc/html/rfc2119
- **[RFC 4648]** Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", October 2006. https://datatracker.ietf.org/doc/html/rfc4648
- **[RFC 8032]** Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017. https://datatracker.ietf.org/doc/html/rfc8032
- **[RFC 8949]** Bormann, C., Hoffman, P., "Concise Binary Object Representation (CBOR)", December 2020. https://datatracker.ietf.org/doc/html/rfc8949

### Informative

- **[Dennis1966]** Dennis, J.B., Van Horn, E.C., "Programming Semantics for Multiprogrammed Computations", Communications of the ACM, Vol. 9, No. 3, March 1966. https://doi.org/10.1145/365230.365252
- **[Macaroons]** Birgisson, A., Politz, J.G., Erlingsson, U., Taly, A., Vrable, M., Lentczner, M., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014. https://research.google/pubs/pub41892/
