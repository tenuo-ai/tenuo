---
title: Protocol
description: How Tenuo works - warrant model, constraints, verification
---

# Tenuo Protocol

> How does Tenuo work? Technical details for implementers and security reviewers.

---

## Warrant Model

### Warrant Structure

On the wire, warrants use the CBOR envelope defined in `docs/wire-format-spec.md`:

- Envelope: CBOR array `[envelope_version, payload_bytes, signature]`
- Payload: CBOR map (integer keys) with `version`, `id`, `warrant_type`, `tools`, `holder`, `issuer`, `issued_at`, `expires_at`, `max_depth`, `parent`, `extensions`
- Signature preimage: `b"tenuo-warrant-v1" || envelope_version || payload_bytes` (verified against raw bytes before deserializing)
- Unknown payload fields are rejected unless under `extensions`; deterministic CBOR is required

Conceptually (in memory), a warrant has:

```
Warrant {
    id: bytes[16] (UUID)
    type: "execution" | "issuer"
    version: int
    
    issuer: PublicKey (who authorized this warrant)
    holder: PublicKey (who can use this warrant, PoP binding)
    
    # Execution warrants
    capabilities: Map<string, ConstraintSet>  # tool_name → constraints
    
    # Issuer warrants
    issuable_tools: string[]
    trust_ceiling: TrustLevel
    constraint_bounds: ConstraintSet (optional)
    max_issue_depth: int (optional)
    
    # Common
    issued_at: timestamp
    expires_at: timestamp
    max_depth: int
    depth: int (current delegation depth, 0 = root)
    session_id: string (in extensions, audit only)
    
    # Linkage (for chain verification via WarrantStack)
    parent_hash: bytes[32] (SHA256 of parent's payload_bytes, null for root)
}
```

**Key fields:**
- `issuer`: Who authorized this warrant (for root: self-signed; for delegated: parent's holder)
- `holder`: Who can use this warrant (must provide PoP signature)

### Warrant Types

| Type | Authority | Use Case |
|------|-----------|----------|
| **Execution** | Invoke tools | Workers, executors |
| **Issuer** | Grant execution warrants | Planners, orchestrators |

### Execution Warrant

Authority to invoke specific tools with specific constraints:

```python
from tenuo import Warrant, Constraints, Exact

execution_warrant = Warrant.issue(
    capabilities=Constraints.for_tool("read_file", {
        "path": Exact("/data/q3.pdf")
    }),
    keypair=issuer_keypair,
    holder=worker_public_key,
    ttl_seconds=60,
)
```

### Issuer Warrant

Authority to issue execution warrants (cannot execute tools directly):

```python
issuer_warrant = Warrant.issue_issuer(
    keypair=control_plane_keypair,
    holder=planner_pubkey,
    issuable_tools=["read_file", "send_email", "query_db"],
    max_issue_depth=1,
    ttl_seconds=3600,
)
```

---

## Constraint Types

### Available Types (most → least restrictive)

| Type | Description | Example |
|------|-------------|---------|
| `Exact` | Single value | `Exact("/data/q3.pdf")` |
| `OneOf` | Enumerated set | `OneOf(["dev", "staging"])` |
| `Pattern` | Glob pattern | `Pattern("/data/*.pdf")` |
| `Range` | Numeric bounds | `Range(max=1000)` |
| `Regex` | Regular expression | `Regex(r"^[a-z]+\.pdf$")` |
| `Wildcard` | Any value | `Wildcard()` (implicit when no constraint) |

### Constraint Lattice

Constraints form a partial order. Attenuation can only move **toward more restrictive types**:

```
                        Wildcard (⊤)
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
    Pattern              Range/Cidr          OneOf/NotOneOf
        │                    │                    │
      Regex            UrlPattern            Contains/Subset
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
                         Exact (⊥)

Logical operators: All (AND), Any (OR)
Complex: CEL (conjunction with parent)
```

**Key relationships:**
- **Wildcard** is the universal parent (⊤) - can attenuate to any type
- **Exact** is the universal child (⊥) - most restrictive
- **Cross-type attenuation** is allowed when child value satisfies parent constraint
- **Not** does not support attenuation (use positive constraints instead)

### Constraint Serialization (CBOR)

Constraints are serialized as CBOR arrays `[type_id, value]`:

```
Exact(1):    [1, "/data/q3.pdf"]
Pattern(2):  [2, {"pattern": "/data/*.pdf"}]
Range(3):    [3, {"min": 0, "max": 1000}]
OneOf(4):    [4, {"values": ["dev", "staging"]}]
Regex(5):    [5, {"pattern": "^[a-z]+\\.pdf$"}]
Wildcard(16): [16, {}]
```

**Note:** Type ID 6 is reserved for a future `IntRange` type with `i64` bounds. Currently, `Range` (ID 3) handles all numeric constraints using `f64` bounds. For values > 2^53, use `Exact` or `OneOf` to avoid precision loss.

See `docs/wire-format-spec.md` §6 for complete type ID assignments (1-16).

For debugging, use `tenuo inspect` to view constraints as JSON.

---

## Attenuation Rules

### Delegation Authority

When attenuating a warrant (delegating to another entity):

**The parent's holder signs the child warrant:**
```rust
// Parent's holder signs the child warrant
let child = parent.attenuate()
    .holder(child_kp.public_key())
    .build(&parent_kp)?;  // parent_kp is parent's holder keypair

// Result:
// child.issuer == parent.holder ✅  (delegation authority)
// child.holder == child_kp.public_key ✅  (who can use it)
```

**This creates a cryptographically provable delegation chain:**
- `child.issuer` is set to `parent.holder` (who authorized the delegation)
- `child.signature` is created by parent's holder (proves authorization)
- `child.parent_hash` links to parent (prevents reuse)

**Audit trail:** "parent.holder delegated to child.holder"

See [`wire-format-spec.md` Invariant I1](wire-format-spec.md#i1-delegation-authority) for enforcement requirements.

### Monotonicity Invariant

**Every dimension must satisfy: child ⊆ parent**

| Dimension | Rule | Violation |
|-----------|------|-----------|
| Capabilities | `child_caps ⊆ parent_caps` | Cannot add tools or widen constraints |
| TTL | `child_expires ≤ parent_expires` | Cannot extend |
| Depth | `child_depth < parent_depth` | Cannot increase |

### Constraint Attenuation Rules

| Parent Type | Valid Child Types | Check |
|-------------|-------------------|-------|
| `Wildcard` | Any type | Universal parent - always valid |
| `Pattern` | Pattern, Exact | Child pattern is subset of parent |
| `Regex` | Regex (same), Exact | Child regex must match parent or be exact value |
| `Exact` | Exact (same value) | `child.value == parent.value` |
| `OneOf` | OneOf, NotOneOf, Exact | `child.values ⊆ parent.values` or carve holes |
| `NotOneOf` | NotOneOf | `parent.excluded ⊆ child.excluded` (more exclusions) |
| `Range` | Range, Exact | `child.min >= parent.min && child.max <= parent.max` |
| `Cidr` | Cidr, Exact | Child network is subnet of parent |
| `UrlPattern` | UrlPattern, Exact | Child pattern is narrower (scheme/host/port/path) |
| `Contains` | Contains | `parent.required ⊆ child.required` (more requirements) |
| `Subset` | Subset | `child.allowed ⊆ parent.allowed` (fewer allowed) |
| `All` | All | Child may add more constraints |
| `Any` | Any | Child may remove alternatives |
| `CEL` | CEL | Child must be `(parent) && new_predicate` |

**Note:** `Not` constraint does not support attenuation. See `docs/constraints.md` for detailed attenuation rules.

### Required Narrowing

Every delegation **must narrow at least one dimension**:

```python
# POLA: Child starts with NO capabilities, must explicitly grant them

# Explicit capability (recommended)
parent.attenuate().capability("read_file", {}).delegate(parent_kp)

# Or inherit all, then narrow
parent.attenuate().inherit_all().tools(["read_file"]).delegate(parent_kp)
parent.attenuate().inherit_all().ttl(60).delegate(parent_kp)
parent.attenuate().inherit_all().terminal().delegate(parent_kp)
```

---

## Chain Verification

### WarrantStack Model

Delegation chains are verified using a **WarrantStack** - an ordered array of warrants from root to leaf. Each warrant links to its parent via `parent_hash` (SHA256 of parent's payload bytes).

```
WarrantStack {
    ancestors: Warrant[]  # [root, ..., parent]
    target: Warrant       # The leaf warrant being verified
}
```

### Chain Verification

Verification walks the stack, checking each link:

```python
def verify_chain(stack: list[Warrant], trusted_roots: set[PublicKey]) -> bool:
    """Verify a complete delegation chain.
    
    Checks all invariants from wire-format-spec.md (I1-I6).
    """
    if not stack:
        raise ChainVerificationFailed("Empty stack")
    
    root = stack[0]
    
    # Root must be from trusted issuer
    if root.issuer() not in trusted_roots:
        raise ChainNotAnchored("Root issuer not trusted")
    
    # Walk the chain, verifying each link
    for i in range(1, len(stack)):
        parent = stack[i - 1]
        child = stack[i]
        
        # I1: Delegation Authority (wire-format-spec.md)
        # Child's issuer must be parent's holder (proves delegation)
        if child.issuer() != parent.holder():
            raise ChainVerificationFailed(
                f"I1 violated: child.issuer ({child.issuer()}) != parent.holder ({parent.holder()})"
            )
        
        # I2: Depth Monotonicity
        # Depth must increment by exactly 1
        if child.depth() != parent.depth() + 1:
            raise ChainVerificationFailed(
                f"I2 violated: child.depth ({child.depth()}) != parent.depth + 1 ({parent.depth() + 1})"
            )
        # Depth must not exceed protocol maximum
        if child.depth() > MAX_DELEGATION_DEPTH:
            raise ChainVerificationFailed(
                f"I2 violated: depth {child.depth()} exceeds MAX_DELEGATION_DEPTH ({MAX_DELEGATION_DEPTH})"
            )
        # Depth must not exceed parent's max_depth
        if child.depth() > parent.max_depth():
            raise ChainVerificationFailed(
                f"I2 violated: depth {child.depth()} exceeds parent.max_depth ({parent.max_depth()})"
            )
        
        # I3: TTL Monotonicity
        # Child cannot outlive parent
        if child.expires_at() > parent.expires_at():
            raise ChainVerificationFailed(
                f"I3 violated: child.expires_at ({child.expires_at()}) > parent.expires_at ({parent.expires_at()})"
            )
        
        # I4: Capability Monotonicity
        # Tools and constraints can only narrow (checked in verify_attenuation)
        verify_attenuation(parent, child)
        
        # I5: Cryptographic Linkage
        # Parent hash must match SHA256 of parent's payload
        expected_hash = sha256(parent.payload_bytes())
        if child.parent_hash() != expected_hash:
            raise ChainVerificationFailed("I5 violated: parent_hash mismatch")
        
        # Signature must be valid (proves issuer authorized it)
        # Note: child.issuer() == parent.holder() per I1, so this proves parent's holder signed
        verify(child.issuer(), child.signature_preimage(), child.signature())
    
    return True
```

**Note:** Invariant I6 (Proof-of-Possession) is checked separately during tool execution, not during chain verification.

### Chain Must End at Trusted Root

The verification **must fail** if the root warrant's issuer is not in the configured `trusted_roots` set.

### Cryptographic Proof of Delegation

**Every delegation in the chain is cryptographically provable.**

When a parent delegates to a child, the relationship is proven by three properties:

1. **Delegation authority**: `child.issuer == parent.holder`
2. **Signature proof**: `verify(child.issuer, child.signature_preimage, child.signature)`
3. **Chain linkage**: `child.parent_hash == SHA256(parent.payload_bytes)`

**Together, these prove:**
- The parent's holder authorized the delegation (not just anyone)
- The authorization is cryptographically signed (can't be forged)
- The child warrant is bound to the specific parent (can't be reused)

#### Example: Three-Level Chain

```
Root Warrant:
  issuer: A (self-signed root)
  holder: A
  signature: sign(A_private, root.payload)
  ✅ Proves: A created this root warrant

Child Warrant:
  issuer: A (parent's holder)
  holder: B
  signature: sign(A_private, child.payload)
  parent_hash: SHA256(root.payload)
  ✅ Proves: A delegated to B

Grandchild Warrant:
  issuer: B (parent's holder)
  holder: C
  signature: sign(B_private, grandchild.payload)
  parent_hash: SHA256(child.payload)
  ✅ Proves: B delegated to C
```

#### Verification Algorithm

For each link `parent → child`:

```python
# 1. Verify delegation authority
assert child.issuer() == parent.holder()

# 2. Verify signature proves issuer authorized it
preimage = child.signature_preimage()
verify(child.issuer(), preimage, child.signature())

# 3. Verify cryptographic linkage to parent
expected_hash = sha256(parent.payload_bytes())
assert child.parent_hash() == expected_hash

# Result: Cryptographic proof that parent.holder delegated to child.holder
```

**Security property:** An attacker cannot:
- Forge a delegation (requires parent's private key)
- Reuse a delegation for a different parent (parent_hash binds it)
- Claim delegation from wrong entity (issuer field is signed)

#### Comparison to Other Systems

| System | Delegation Proof |
|--------|------------------|
| **X.509** | Intermediate CA signs child cert; `child.issuer == parent.subject` |
| **Macaroons** | Parent signs caveat; discharge macaroon proves delegation |
| **SPIFFE** | Parent SVID signs child SVID; `child.issuer == parent.subject` |
| **UCAN** | Parent DID signs child UCAN; `child.issuer == parent.audience` |
| **Tenuo** | Parent holder signs child; `child.issuer == parent.holder` |

All follow the same pattern: **parent's holder/subject signs child warrant/certificate**.

---

## Proof-of-Possession (PoP)

### Purpose

PoP ensures stolen warrants are useless without the holder's private key.

### PoP Challenge Structure

```
PopChallenge = (warrant_id, tool, sorted_args, timestamp_window)
```

| Field | Type | Description |
|-------|------|-------------|
| `warrant_id` | string | UUID of the warrant being used |
| `tool` | string | Tool name being invoked |
| `sorted_args` | array of (key, value) | Arguments sorted by key |
| `timestamp_window` | int | Time window (floor division by 30s) |

### Creating PoP

```python
def create_pop(warrant, keypair, tool, args) -> Signature:
    # Sort args by key for deterministic serialization
    sorted_args = sorted(args.items(), key=lambda x: x[0])
    
    # Time-bound to 30-second window
    now = int(time.time())
    timestamp_window = (now // 30) * 30
    
    # Build challenge tuple
    challenge = (warrant.id, tool, sorted_args, timestamp_window)
    
    # Serialize with Deterministic CBOR
    challenge_bytes = cbor_serialize(challenge)
    
    # Sign
    return keypair.sign(challenge_bytes)
```

### Verifying PoP

```python
def verify_pop(warrant, signature, tool, args, max_windows=4) -> bool:
    now = int(time.time())
    sorted_args = sorted(args.items(), key=lambda x: x[0])
    
    # Try current and recent time windows (handles clock skew)
    for i in range(max_windows):
        timestamp_window = ((now // 30) - i) * 30
        challenge = (warrant.id, tool, sorted_args, timestamp_window)
        challenge_bytes = cbor_serialize(challenge)
        
        if warrant.holder.verify(challenge_bytes, signature):
            return True
    
    return False
```

### Time Window Design

| Parameter | Default | Purpose |
|-----------|---------|---------|
| Window size | 30 seconds | Groups signatures into buckets |
| Max windows | 4 | ~2 minute total validity |
| Clock tolerance | ±30 seconds | Handles distributed clock skew |

**Trade-off**: Larger windows allow more clock skew but increase replay risk. Within the ~2 minute window, a captured PoP can be replayed for the **same** (warrant, tool, args) tuple.

**Replay Mitigation**: The `Authorizer` is stateless by design. For sensitive operations, use `warrant.dedup_key(tool, args)` to implement application-level deduplication. See [Security: Replay Protection](./security#replay-protection--statelessness) for implementation guidance.

---

## Protocol Limits

Hard limits prevent abuse and ensure verification terminates:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_DELEGATION_DEPTH` | 16 | Max warrant depth (typical chains are 3-5 levels) |
| `MAX_WARRANT_TTL_SECS` | 90 days | Protocol ceiling for warrant lifetime |
| `MAX_WARRANT_SIZE` | 64 KB | Prevents memory exhaustion |
| `MAX_STACK_SIZE` | 64 KB | Max WarrantStack encoded size |
| `MAX_CONSTRAINT_DEPTH` | 16 | Prevents stack overflow in nested constraints |
| PoP Timestamp Window | 30s | Replay protection (~2 min with 4 windows) |

### Enforcement

```python
def verify_limits(stack: list[Warrant]) -> None:
    if len(stack) > MAX_DELEGATION_DEPTH:
        raise ChainTooLong()
    
    for warrant in stack:
        if len(serialize(warrant)) > MAX_WARRANT_SIZE:
            raise WarrantTooLarge()
```

---

## Reserved Namespaces

### Tool Name Prefix: `tenuo:`

Tool names starting with `tenuo:` are **reserved for framework use** and will be rejected during warrant creation:

```python
# ❌ This will fail
warrant = Warrant.builder().capability("tenuo:revoke", {})
# Error: Reserved tool namespace

# ✅ Use your own namespace
warrant = Warrant.builder().capability("my_app:revoke", {})
```

**Rationale**: Prevents collision between user-defined tools and future framework features.

**Potential future uses**:
- `tenuo:revoke` — Inline revocation directive
- `tenuo:audit` — Audit logging trigger

### Extension Keys: `tenuo.*`

Extension keys starting with `tenuo.*` are **reserved for framework use**:

```python
# Current framework extensions (metadata only):
extensions = {
    "tenuo.session_id": cbor.encode("session-123"),
    "tenuo.agent_id": cbor.encode("agent-worker-1"),
}
```

**Extension value encoding:** All extension values MUST be CBOR-encoded. See `wire-format-spec.md` §10 for encoding rules.

**Fail-closed behavior:** Verifiers SHOULD reject warrants with unknown `tenuo.*` extensions to fail closed. This prevents forward compatibility issues where newer warrant features are silently ignored by older verifiers.

**User-defined extensions:** Use reverse domain notation (e.g., `com.example.trace_id`, `org.acme.workflow_id`).
- `tenuo:require_mfa` — Enforcement flag
- `tenuo:audit` — Force audit log entry

### Extension Key Prefix: `tenuo.`

Extension keys starting with `tenuo.` are reserved for Tenuo metadata:

```python
# Reserved for framework
warrant.extension("tenuo.session_id", b"sess_123")  # Framework use only

# ✅ Use reverse domain notation for your extensions
warrant.extension("com.example.trace_id", b"abc123")
```

**Recommended format**: Reverse domain notation (`com.example.key_name`)

---

## Cycle Protection

### Layer 1: Warrant ID Tracking

During verification, each warrant ID is tracked. If same ID appears twice → fail.

```
stack[0].id -> seen
stack[1].id -> seen  
stack[2].id -> ERROR if already seen
```

### Layer 2: Depth Limits

Even if cycles somehow formed, verification stops at depth 16.

### Layer 3: Monotonic Attenuation

Holder cycling (A→B→A) creates 3 **different** warrants, each strictly weaker. Safe by design.

### Layer 4: Terminal Warrants

A warrant with `depth >= max_depth` cannot delegate further. Cryptographically enforced.

### What's Blocked vs Allowed

| Pattern | Status | Reason |
|---------|--------|--------|
| Same warrant ID twice | [BLOCKED] | Cycle detection |
| Holder A->B->A (different warrants) | [ALLOWED] | Monotonicity makes it safe |
| Self-issuance (issuer warrant) | [BLOCKED] | Privilege escalation |
| Chain > 16 depth | [BLOCKED] | DoS protection |

### Scaling Delegation (Trust Anchors)

The 16-depth limit is generous for typical hierarchies. You can also distribute intermediate CA keys (Trust Anchors) to the Authorizer for verification shortcuts.

**Example**:
`Global Key` → `Region Key` → `Cluster Key` → `Namespace Key` → `Pod Key` → `Agent Key`

If your Authorizer trusts the `Cluster Key`, verification can start there. This is useful for multi-tenant deployments where different teams manage their own key hierarchies.

> **Distributing Trust**: Adding a key to `trusted_issuers` allows verification to anchor at that point.

---

## Serialization

### Wire Format

Tenuo uses **Deterministic CBOR (RFC 8949)** for all cryptographic operations:

| Context | Format | Rationale |
|---------|--------|-----------|
| Warrant payload signing | Deterministic CBOR | Compact, consistent across implementations |
| PoP challenge signing | Deterministic CBOR | Timestamp-bound challenge |
| Wire transport | CBOR + Base64 (URL-safe) | Header-safe encoding |
| Audit logs | JSON | Human-readable, standard tooling |
| CLI output | JSON | Human-readable debugging |

### Deterministic CBOR Rules (RFC 8949 §4.2)

- **Map keys**: Sorted by byte-wise lexicographic order (using `BTreeMap`)
- **Integers**: Minimal encoding (smallest CBOR type that fits)
- **No indefinite-length**: All arrays and maps use definite length
- **Floats**: IEEE 754 binary64 representation

### Key Principle: Sign Bytes, Not Objects

For PoP signatures, the challenge is serialized to bytes once, then signed:

```python
# Client
challenge = (warrant_id, tool, sorted_args, timestamp_window)
challenge_bytes = cbor_serialize(challenge)  # Deterministic
signature = keypair.sign(challenge_bytes)

# Server (reconstructs same challenge structure)
challenge = (warrant_id, tool, sorted_args, timestamp_window)
reconstructed_bytes = cbor_serialize(challenge)  # Same deterministic output
verify(reconstructed_bytes, signature, holder_pubkey)
```

**Safety**: Since both client and server use the same Rust/ciborium implementation via PyO3 bindings, serialization is guaranteed identical. For non-Rust clients, use the same CBOR library and sorting rules.

### Cryptographic Values

- Ed25519 public keys: 32 bytes
- Ed25519 signatures: 64 bytes
- Wire encoding: URL-safe Base64 (no padding)

---

## Authorization Flow

### Full Check Sequence

1. **Chain**: Verify signatures back to trusted root
2. **Tool**: Requested tool in warrant's allowed tools
3. **Constraints**: Args satisfy warrant constraints
4. **TTL**: Warrant not expired
5. **PoP**: Proof-of-possession signature valid
6. **Revocation** (optional): Warrant ID not in SRL

### Example

```python
result = authorizer.check(
    warrant=warrant,
    tool="read_file",
    args={"path": "/data/q3.pdf"},
    pop=pop_signature,
)

if result.authorized:
    # Execute tool
else:
    raise AuthorizationError(result.reason)
```

---

## Audit Logging

All authorization decisions logged as structured JSON:

```json
{
  "event_type": "authorization_success",
  "warrant_id": "wrt_xyz789",
  "session_id": "sess_task123",
  "tool": "read_file",
  "args": {"path": "/data/alpha/report.csv"},
  "@timestamp": "2024-01-15T10:30:00Z"
}
```

Event types:
- `authorization_success` / `authorization_failure`
- `warrant_issued` / `warrant_attenuated`
- `pop_verified` / `pop_failed`

---

## Revocation (Optional)

### Signed Revocation List (SRL)

For emergency warrant cancellation:

```python
async def srl_sync_loop():
    while True:
        response = await http.get(SRL_URL)
        srl = SignedRevocationList.from_bytes(response.content)
        atomic_write("/var/run/tenuo/srl", srl.to_bytes())
        await asyncio.sleep(30)
```

### Authorizer with SRL

```python
authorizer = Authorizer(
    srl_path="/var/run/tenuo/srl",
)
```

---

## Implementation Requirements

All Tenuo implementations MUST:

1. **Verify chain ends at trusted root** - Hard fail if not anchored
2. **Enforce PoP on every authorization** - No exceptions
3. **Enforce protocol limits** - Chain length, warrant size
4. **Use Deterministic CBOR (RFC 8949)** - Sorted keys, minimal integers
5. **Reconstruct challenge identically** - Same serialization on both sides
6. **Log all authorization decisions** - Allow and deny
7. **Prevent self-issuance** - Issuer cannot grant to self
8. **Enforce monotonicity** - Every dimension checked

### Cross-Language Compatibility

For non-Rust implementations:

1. Use a CBOR library that supports deterministic encoding
2. Sort map keys by byte-wise lexicographic order
3. Use minimal integer encoding
4. Use `BTreeMap` (or equivalent ordered map) for constraint sets
5. Test serialization output against reference Rust implementation

---

## See Also

- [Concepts](./concepts) - Why Tenuo? Problem/solution overview
- [API Reference](./api-reference) - Function signatures
- [Constraints](./constraints) - Constraint types and usage
- [Security](./security) - Detailed threat model
