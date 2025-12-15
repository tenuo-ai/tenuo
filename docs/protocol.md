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

### Serialization

```json
{"type": "exact", "value": "/data/q3.pdf"}
{"type": "pattern", "value": "/data/*.pdf"}
{"type": "range", "min": 0, "max": 1000}
{"type": "one_of", "values": ["dev", "staging"]}
{"type": "regex", "value": "^[a-z]+\\.pdf$"}
{"type": "wildcard"}
```

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

### PoP Payload

```python
PopPayload {
    warrant_id: str       # Which warrant
    tool: str             # Which tool being invoked
    args: dict            # Arguments (actual values)
    timestamp: int        # Unix timestamp (seconds)
    nonce: bytes          # 16 random bytes
}
```

### Creating PoP

```python
def create_pop(warrant, keypair, tool, args) -> PopToken:
    # Build payload
    payload = PopPayload(
        warrant_id=warrant.id,
        tool=tool,
        args=args,
        timestamp=int(time.time()),
        nonce=os.urandom(16),
    )
    
    # Canonical JSON (sorted keys, no whitespace)
    signed_bytes = canonical_json(payload).encode('utf-8')
    
    # Sign
    signature = keypair.sign(signed_bytes)
    
    return PopToken(signed_bytes=signed_bytes, signature=signature)
```

### Verifying PoP

```python
def verify_pop(warrant, pop, tool, args, max_age_seconds=60) -> bool:
    # 1. Verify signature FIRST (over raw bytes)
    if not warrant.holder.verify(pop.signed_bytes, pop.signature):
        return False
    
    # 2. Deserialize AFTER signature verified
    payload = json.loads(pop.signed_bytes)
    
    # 3. Check warrant ID, tool, args match
    if payload["warrant_id"] != warrant.id:
        return False
    if payload["tool"] != tool:
        return False
    if payload["args"] != args:
        return False
    
    # 4. Check timestamp freshness
    age = time.time() - payload["timestamp"]
    if age > max_age_seconds or age < -60:  # 60s clock skew
        return False
    
    return True
```

### Key Principle: Sign Bytes, Not Objects

The signer sends **exact bytes** they signed. The verifier hashes those bytes directly, never reconstructing JSON. This ensures cross-language compatibility.

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

| Context | Format | Rationale |
|---------|--------|-----------|
| Warrant signing | Canonical JSON | Consistent across implementations |
| PoP verification | Raw bytes passthrough | Avoids JSON disagreements |
| Wire transport | Base64 (URL-safe) | Header-safe encoding |

### Canonical JSON Rules

- Keys sorted alphabetically (recursive)
- No whitespace: `separators=(',', ':')`
- No floats (all numbers are integers)
- UTF-8 encoding
- Null values omitted

### Cryptographic Values

Ed25519 keys (32 bytes) and signatures (64 bytes) as URL-safe Base64.

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
4. **Use canonical JSON for signing** — Sorted keys, no whitespace
5. **Use raw bytes passthrough for PoP verification** — Never reconstruct
6. **Log all authorization decisions** — Allow and deny
7. **Prevent self-issuance** — Issuer cannot grant to self
8. **Enforce monotonicity** — Every dimension checked

---

## See Also

- [Concepts](./concepts.md) — Why Tenuo? Problem/solution overview
- [API Reference](./api-reference.md) — Function signatures
- [Constraints](./constraints.md) — Constraint types and usage
- [Security](./security.md) — Detailed threat model
