---
title: Protocol
description: How Tenuo works - warrant model, constraints, verification
---

# Tenuo Protocol

> How does Tenuo work? Technical details for implementers and security reviewers.

---

## Warrant Model

### Warrant Structure

A warrant is a self-contained capability token with the following fields:

```
Warrant {
    id: string (uuid)
    type: "execution" | "issuer"
    version: int
    
    holder: PublicKey (mandatory - PoP binding)
    
    # Execution warrants
    tools: string[]
    constraints: Map<string, Constraint>
    
    # Common
    issued_at: timestamp
    expires_at: timestamp
    max_depth: int
    session_id: string (audit only)
    
    # Chain (embedded for self-contained verification)
    issuer_chain: ChainLink[]
    signature: bytes
}
```

### Warrant Types

| Type | Authority | Use Case |
|------|-----------|----------|
| **Execution** | Invoke tools | Workers, executors |
| **Issuer** | Grant execution warrants | Planners, orchestrators |

### Execution Warrant

Authority to invoke specific tools with specific constraints:

```python
execution_warrant = Warrant.issue(
    tools=["read_file"],
    keypair=issuer_keypair,
    holder=worker_public_key,
    constraints={"path": Exact("/data/q3.pdf")},
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
          ┌─────────────┼─────────────┐
          │             │             │
       Pattern        Range        OneOf
          │             │             │
        Regex           │             │
          │             │             │
          └─────────────┼─────────────┘
                        │
                     Exact (⊥)
```

### Constraint Serialization (CBOR)

Constraints are serialized as tagged CBOR maps:

```
Exact:    {type: "exact", value: "/data/q3.pdf"}
Pattern:  {type: "pattern", value: "/data/*.pdf"}
Range:    {type: "range", min: 0, max: 1000}
OneOf:    {type: "one_of", values: ["dev", "staging"]}
Regex:    {type: "regex", value: "^[a-z]+\\.pdf$"}
Wildcard: {type: "wildcard"}
```

For debugging, use `tenuo inspect` to view constraints as JSON.

---

## Attenuation Rules

### Monotonicity Invariant

**Every dimension must satisfy: child ⊆ parent**

| Dimension | Rule | Violation |
|-----------|------|-----------|
| Tools | `child_tools ⊆ parent_tools` | Cannot add tools |
| Constraints | `child_constraint ⊆ parent_constraint` | Cannot widen |
| TTL | `child_expires ≤ parent_expires` | Cannot extend |
| Depth | `child_depth < parent_depth` | Cannot increase |

### Constraint Attenuation Rules

| Parent Type | Valid Child Types | Check |
|-------------|-------------------|-------|
| `Wildcard` | Any | Always valid |
| `Pattern` | Pattern, Exact | Child matches subset |
| `Range` | Range, Exact | `child.min >= parent.min && child.max <= parent.max` |
| `OneOf` | OneOf, Exact | `child.values ⊆ parent.values` |
| `Exact` | Exact (same value) | `child.value == parent.value` |

### Required Narrowing

Every delegation **must narrow at least one dimension**:

```python
# Fails - no narrowing
parent.attenuate().delegate_to(worker)  # NarrowingRequired error

# Succeeds
parent.attenuate().tool("read_file").delegate_to(worker)
parent.attenuate().ttl(seconds=60).delegate_to(worker)
parent.attenuate().terminal().delegate_to(worker)
```

---

## Chain Verification

### ChainLink Structure

Each warrant embeds its issuer chain for self-contained verification:

```
ChainLink {
    issuer_id: string (warrant ID of issuer)
    issuer_pubkey: PublicKey
    
    # Embedded scope (for attenuation verification)
    issuer_type: "execution" | "issuer"
    issuer_tools: string[]
    issuer_constraints: Map<string, Constraint>
    issuer_expires_at: timestamp
    issuer_max_depth: int
    
    signature: bytes (over child warrant)
}
```

### Self-Contained Verification

Verification requires **no external fetches**:

```python
def verify_chain(warrant: Warrant, trusted_roots: set[PublicKey]) -> bool:
    """Verify using ONLY embedded data."""
    current = warrant
    
    for link in warrant.issuer_chain:
        # 1. Verify signature FIRST
        if not link.issuer_pubkey.verify(serialize(current), link.signature):
            raise ChainVerificationFailed("Invalid signature")
        
        # 2. Check if trusted root
        if link.issuer_pubkey in trusted_roots:
            return True
        
        # 3. Verify attenuation (monotonicity)
        verify_attenuation(link, current)
        
        current = link
    
    raise ChainNotAnchored("Chain does not reach trusted root")
```

### Chain Must End at Trusted Root

The verification loop **must fail** if it does not end at a key in the configured `trusted_roots` set.

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
| Clock tolerance | ±60 seconds | Handles distributed clock skew |

**Trade-off**: Larger windows allow more clock skew but increase replay risk. Within the ~2 minute window, a captured PoP can be replayed for the **same** (warrant, tool, args) tuple.

**Mitigation**: Use `warrant.dedup_key(tool, args)` as a cache key with 120s TTL for deduplication.

---

## Protocol Limits

Hard limits prevent abuse and ensure verification terminates:

| Limit | Value | Purpose |
|-------|-------|---------|
| `MAX_DELEGATION_DEPTH` | 64 | Max warrant depth counter |
| `MAX_ISSUER_CHAIN_LENGTH` | 8 | Max embedded chain links (DoS protection) |
| `MAX_WARRANT_SIZE` | 1 MB | Prevents memory exhaustion |
| `MAX_CONSTRAINT_DEPTH` | 16 | Prevents stack overflow in nested constraints |
| PoP Timestamp Window | 30s | Replay protection (~2 min with 4 windows) |

### Enforcement

```python
def verify_limits(warrant: Warrant) -> None:
    if len(warrant.issuer_chain) > MAX_ISSUER_CHAIN_LENGTH:
        raise ChainTooLong()
    
    if len(serialize(warrant)) > MAX_WARRANT_SIZE:
        raise WarrantTooLarge()
```

---

## Cycle Protection

### Layer 1: Warrant ID Tracking

During verification, each warrant ID is tracked. If same ID appears twice → fail.

```
chain[0].id → seen
chain[1].id → seen  
chain[2].id → ERROR if already seen
```

### Layer 2: Chain Length Limits

Even if cycles somehow formed, verification stops at 8 links.

### Layer 3: Monotonic Attenuation

Holder cycling (A→B→A) creates 3 **different** warrants, each strictly weaker. Safe by design.

### Layer 4: Terminal Warrants

A warrant with `max_depth = 0` cannot delegate further. Cryptographically enforced.

### What's Blocked vs Allowed

| Pattern | Status | Reason |
|---------|--------|--------|
| Same warrant ID twice | ❌ Blocked | Cycle detection |
| Holder A→B→A (different warrants) | ✅ Allowed | Monotonicity makes it safe |
| Self-issuance (issuer warrant) | ❌ Blocked | Privilege escalation |
| Chain > 8 links | ❌ Blocked | DoS protection |

---

## Serialization

### Wire Format

Tenuo uses **Deterministic CBOR (RFC 8949)** for all cryptographic operations:

| Context | Format | Rationale |
|---------|--------|-----------|
| Warrant payload signing | Deterministic CBOR | Compact, consistent across implementations |
| ChainLink signing | Deterministic CBOR | Binds issuer scope to child |
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

1. **Verify chain ends at trusted root** — Hard fail if not anchored
2. **Enforce PoP on every authorization** — No exceptions
3. **Enforce protocol limits** — Chain length, warrant size
4. **Use Deterministic CBOR (RFC 8949)** — Sorted keys, minimal integers
5. **Reconstruct challenge identically** — Same serialization on both sides
6. **Log all authorization decisions** — Allow and deny
7. **Prevent self-issuance** — Issuer cannot grant to self
8. **Enforce monotonicity** — Every dimension checked

### Cross-Language Compatibility

For non-Rust implementations:

1. Use a CBOR library that supports deterministic encoding
2. Sort map keys by byte-wise lexicographic order
3. Use minimal integer encoding
4. Use `BTreeMap` (or equivalent ordered map) for constraint sets
5. Test serialization output against reference Rust implementation

---

## See Also

- [Concepts](./concepts) — Why Tenuo? Problem/solution overview
- [API Reference](./api-reference) — Function signatures
- [Constraints](./constraints) — Constraint types and usage
- [Security](./security) — Detailed threat model
