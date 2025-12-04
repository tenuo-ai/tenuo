# Tenuo

**Agent Capability Flow Control**

> **Python User?** You probably want the SDK: [**tenuo-python**](https://github.com/tenuo/tenuo-python) *(coming soon)*
>
> This repo contains the high-performance Rust core used by the SDK.

Tenuo provides cryptographically-enforced capability attenuation for AI agent workflows. Unlike traditional IAM systems that answer "Who are you?", Tenuo answers:

> "Does this actor hold a valid, scoped, unexpired token for this specific action?"

## Quick Start (Docker)

```bash
# Run the multi-agent demo (recommended)
docker compose up orchestrator worker

# Or run the full stack including HTTP servers
docker compose up
```

## Multi-Agent Demo

The demo runs two containerized agents that demonstrate the complete Tenuo workflow:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ORCHESTRATOR (tenuo-orchestrator binary)                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Simulates receiving a root warrant from Control Plane               ││
│  │    • cluster: staging-* (Pattern)                                      ││
│  │    • action: * (Wildcard - can be narrowed to any type)                ││
│  │    • budget: ≤$10,000 (Range)                                          ││
│  │    • max_depth: 3 (policy limit on delegation depth)                   ││
│  │                                                                         ││
│  │ 2. Creates WORKER's keypair (for holder binding)                       ││
│  │                                                                         ││
│  │ 3. Attenuates the warrant for the worker:                              ││
│  │    • cluster: staging-web (Exact, narrowed from Pattern)               ││
│  │    • action: [upgrade, restart] (OneOf, narrowed from Wildcard)        ││
│  │    • budget: ≤$1,000 (Range, reduced)                                  ││
│  │    • authorized_holder: worker's public key (holder-bound)             ││
│  │    • agent_id: agt_worker_001 (traceability)                           ││
│  │                                                                         ││
│  │ 4. Writes chain + worker keypair to shared volume                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                    │                                        │
│                     (shared Docker volume)                                  │
│                                    ▼                                        │
│  WORKER (tenuo-worker binary)                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Loads chain.json and worker.key (its private key)                   ││
│  │                                                                         ││
│  │ 2. Verifies the complete delegation chain:                             ││
│  │    • Root signed by trusted issuer? ✓                                  ││
│  │    • Constraints only narrow? ✓                                        ││
│  │    • All signatures valid? ✓                                           ││
│  │                                                                         ││
│  │ 3. Signs each request (Proof-of-Possession):                           ││
│  │    signature = sign(tool + args) with worker.key                       ││
│  │                                                                         ││
│  │ 4. Authorization results:                                              ││
│  │    ✓ upgrade staging-web ($500)  → ALLOWED                             ││
│  │    ✗ upgrade staging-db          → BLOCKED (wrong cluster)            ││
│  │    ✗ upgrade with $5,000         → BLOCKED (exceeds budget)           ││
│  │    ✗ stolen warrant              → BLOCKED (no private key for PoP)   ││
│  │                                                                         ││
│  │ 5. Multi-sig demo (sensitive actions):                                 ││
│  │    ✗ delete without approval     → BLOCKED (0/1 approvals)            ││
│  │    ✓ delete with admin approval  → ALLOWED (1/1 approvals)            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- **Holder binding**: Stolen warrants are useless without the worker's private key
- **Offline verification**: Worker never contacts Control Plane
- **Cryptographic authority**: Chain proves delegation path
- **Full traceability**: Every action has `warrant_id`, `agent_id`, `session_id`
- **Multi-sig**: Sensitive actions require explicit approval signatures

### Multi-Agent Patterns

Tenuo supports arbitrary delegation depth (configurable, protocol max 64 levels):

```
Control Plane → Orchestrator → Worker A → Sub-Agent A1
                            ↘ Worker B → Sub-Agent B1
                            ↘ Worker C
```

Each level can only **narrow** capabilities. Worker A cannot grant Sub-Agent A1 permissions it doesn't have.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CONTROL PLANE (Cluster A - secure, isolated)                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │  • Holds root private key (HSM in production)                          ││
│  │  • Issues warrants via HTTP API                                         ││
│  │  • Manages approval workflows (v2)                                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                              │                                              │
│                              │  ┌──────────────────────────────────────┐    │
│                              │  │ PUBLIC KEY DISTRIBUTION              │    │
│                              │  │ • Baked into container image, OR     │    │
│                              │  │ • Fetched ONCE at startup            │    │
│                              │  │ • NO runtime dependency              │    │
│                              │  └──────────────────────────────────────┘    │
│                              ▼                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  DATA PLANE (Clusters B, C, D... - edge, untrusted network)                │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                         ││
│  │  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓  ││
│  │  ┃  ⚡ OFFLINE VERIFICATION - NO NETWORK CALLS TO CONTROL PLANE ⚡   ┃  ││
│  │  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛  ││
│  │                                                                         ││
│  │  • Only has public key (cannot forge warrants)                         ││
│  │  • Authorizes actions locally in <100μs                                ││
│  │  • Can attenuate warrants for sub-agents                               ││
│  │  • Works during Control Plane outages                                  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## What Does a Warrant Look Like?

A warrant is a compact, signed token. Here's what you get when you issue one:

```bash
# Issue a warrant
curl -X POST http://localhost:8080/v1/warrants \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "upgrade_cluster",
    "constraints": {
      "cluster": {"type": "pattern", "value": "staging-*"},
      "version": {"type": "pattern", "value": "1.28.*"}
    },
    "ttl_seconds": 3600
  }'
```

**Constraint JSON format** (HTTP API uses explicit typing):

| Rust Builder | JSON Equivalent |
|--------------|-----------------|
| `Wildcard::new()` | `{"type": "wildcard"}` |
| `Pattern::new("staging-*")` | `{"type": "pattern", "value": "staging-*"}` |
| `Exact::new("staging-web")` | `{"type": "exact", "value": "staging-web"}` |
| `Range::max(10000.0)` | `{"type": "range", "max": 10000}` |
| `OneOf::new(["a", "b"])` | `{"type": "one_of", "values": ["a", "b"]}` |
| `NotOneOf::new(["prod"])` | `{"type": "not_one_of", "excluded": ["prod"]}` |

**Response:**

```json
{
  "warrant": "g6JpZHgndG51X3dydF8xMjM0NTY3ODkwYWJjZGVm...",
  "id": "tnu_wrt_a1b2c3d4e5f6",
  "expires_at": "2024-12-03T15:30:00Z",
  "tool": "upgrade_cluster"
}
```

The `warrant` field is a **Base64-encoded CBOR blob** (~200-500 bytes). It's:
- **Not a JWT** - More compact, no JSON overhead
- **Self-contained** - Includes signature, constraints, and expiration
- **Header-safe** - Fits in HTTP headers, gRPC metadata, or message queues

**Wire format breakdown:**

```
┌─────────────────────────────────────────────────────────────────┐
│  CBOR Envelope                                                  │
│  ├── version: 1                                                 │
│  └── payload: (CBOR-encoded WarrantPayload)                    │
│       ├── id: "tnu_wrt_..."                                    │
│       ├── tool: "upgrade_cluster"                              │
│       ├── constraints: { cluster: Pattern("staging-*"), ... }  │
│       ├── expires_at: 1701617400                               │
│       ├── depth: 0                                             │
│       ├── max_depth: 4 (optional, policy limit)                │
│       ├── parent_id: null                                      │
│       ├── session_id: "sess_abc123" (optional)                 │
│       ├── agent_id: "agt_xyz789" (optional)                    │
│       ├── issuer: <32-byte public key>                         │
│       ├── authorized_holder: <32-byte public key> (optional)   │
│       ├── required_approvers: [<pubkey>, ...] (optional)       │
│       ├── min_approvals: 2 (optional, M-of-N threshold)        │
│       └── signature: <64-byte Ed25519 signature>               │
└─────────────────────────────────────────────────────────────────┘
```

## Integration Modes

Tenuo supports multiple integration patterns:

| Mode | Use Case | Latency | Example |
|------|----------|---------|---------|
| **Library** | Embed directly in your Rust/Python app | ~20μs | `use tenuo_core::Authorizer` |
| **Sidecar** | Kubernetes pod with shared localhost | ~100μs | `localhost:9090/authorize` |
| **Gateway** | Centralized auth at ingress | ~1ms | Envoy/Nginx filter |

### Library (Recommended for Performance)

```rust
use tenuo_core::{Authorizer, Warrant};

// Initialize once at startup
let authorizer = Authorizer::from_bytes(&public_key_bytes)?;

// Check every request (< 100μs)
authorizer.check(&warrant, "upgrade_cluster", &args, signature.as_ref())?;
```

### Sidecar (Kubernetes)

```yaml
# Your pod spec
containers:
  - name: my-agent
    # ... your agent container
  - name: tenuo-authorizer
    image: tenuo/authorizer:latest
    env:
      - name: TENUO_TRUSTED_KEYS
        valueFrom:
          secretKeyRef:
            name: tenuo-keys
            key: public-key
```

Your agent calls `localhost:9090/authorize` - no cross-network latency.

### Gateway (Centralized)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GATEWAY PATTERN                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Client/Agent ──▶ Gateway (Envoy/Nginx) ──▶ Backend Service               │
│        │               │                                                    │
│        │               │ 1. Extract warrant from header                    │
│        ├── Warrant     │ 2. Extract PoP signature (if holder-bound)        │
│        ├── PoP Sig     │ 3. Verify chain + authorize action                │
│        └── Request     │ 4. Forward or reject (401/403)                    │
│                        │                                                    │
│                        └── Trusted public key (baked in config)            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

The gateway pattern is useful when:
- You want centralized authorization policy
- Backend services shouldn't know about Tenuo
- You need request-level audit logging at the edge

## The Key Insight

A **warrant** is a cryptographically-signed token that says:

> "The holder is authorized to call tool X with arguments matching constraints Y, until time Z."

**Capabilities can only shrink.** When Agent A delegates to Agent B:

```
Root Warrant:        { cluster: "*" }           ← Can upgrade ANY cluster
    ↓ attenuate
Orchestrator:        { cluster: "staging-*" }   ← Only staging clusters  
    ↓ attenuate
Worker:              { cluster: "staging-web" } ← Only this ONE cluster
```

The worker **cannot** widen its scope. This is cryptographically enforced - the signature covers the constraints, so any modification invalidates the warrant.

## Holder Binding (Proof-of-Possession)

Warrants can be **bearer tokens** (anyone with the warrant can use it) or **holder-bound** (requires proof of key ownership):

```rust
// Orchestrator binds warrant to worker's public key
let worker_keypair = Keypair::generate();
let worker_warrant = root_warrant.attenuate()
    .constraint("cluster", Exact::new("staging-web"))
    .authorized_holder(worker_keypair.public_key())  // ← BINDING
    .agent_id("agt_a1b2c3d4")                        // ← TRACEABILITY
    .build(&orchestrator_keypair)?;

// Worker MUST sign each request to prove possession
let signature = warrant.create_pop_signature(&my_keypair, tool, &args);
warrant.authorize(tool, &args, Some(&signature))?;
```

**Why this matters:** If an attacker steals a holder-bound warrant, they can't use it without also stealing the corresponding private key. This prevents warrant theft from becoming a security breach.

| Mode | Security | Use Case |
|------|----------|----------|
| **Bearer** (`authorized_holder: None`) | Token = access | Short-lived tokens, internal services |
| **Holder-bound** (`authorized_holder: Some(pk)`) | Token + key = access | Delegated agents, external workers |

## Traceability

Every warrant includes UUIDs for audit trails:

| Field | Format | Purpose |
|-------|--------|---------|
| `warrant.id` | `tnu_wrt_<uuid>` | Unique warrant identifier |
| `warrant.agent_id` | `agt_<uuid>` or custom | Agent instance identifier |
| `warrant.session_id` | User-defined | Request/session grouping |
| `warrant.parent_id` | `tnu_wrt_<uuid>` | Delegation chain linkage |

## API Reference

### Control Plane HTTP API

```bash
# Health check
curl http://localhost:8080/health
# → {"status": "healthy"}

# Get public key (share with data planes at deploy time)
curl http://localhost:8080/v1/public-key
# → {"public_key": "02b04e930d436f40552de8e2fd3222a9840c8343..."}
```

### Data Plane CLI

```bash
# Verify and authorize (completely offline)
echo $WARRANT | tenuo-authorizer verify \
  --tool upgrade_cluster \
  --arg cluster=staging-web \
  --arg version=1.28.5 \
  --output json

# → {"authorized": true, "warrant_id": "tnu_wrt_...", "expires_at": "..."}
# → {"authorized": false, "error": "constraint 'cluster' not satisfied: ..."}
```

### Library Usage (Rust)

```rust
use tenuo_core::{DataPlane, Pattern, Exact, Keypair, Warrant};
use std::collections::HashMap;
use std::time::Duration;

// === CONTROL PLANE (secure environment) ===
let keypair = Keypair::generate();

// Issue warrant with policy limit: max 3 delegation levels
let root_warrant = Warrant::builder()
    .tool("upgrade_cluster")
    .constraint("cluster", Pattern::new("staging-*")?)
    .ttl(Duration::from_secs(3600))
    .max_depth(3)  // Policy limit: only 3 levels of delegation allowed
    .build(&keypair)?;

// === ORCHESTRATOR (attenuate for sub-agent) ===
let orchestrator_keypair = Keypair::generate();
let worker_warrant = root_warrant.attenuate()
    .constraint("cluster", Exact::new("staging-web"))  // Narrow scope
    .ttl(Duration::from_secs(600))                     // Shorter TTL
    .build(&orchestrator_keypair)?;

// === DATA PLANE (edge/agent - only has public key) ===
let mut data_plane = DataPlane::new();
data_plane.trust_issuer("control", keypair.public_key());

// Verify the full chain (offline - no network call)
let chain = vec![root_warrant.clone(), worker_warrant.clone()];
data_plane.verify_chain(&chain)?;

// Authorize action against the leaf warrant
let mut args = HashMap::new();
args.insert("cluster".to_string(), "staging-web".into());  // ConstraintValue::String

// For holder-bound warrants, worker must sign with their key (Proof-of-Possession)
// Note: In practice, the worker receives their keypair separately from the warrant
let worker_keypair = Keypair::generate();  // In reality, created by orchestrator and shared securely
let signature = worker_warrant.create_pop_signature(
    &worker_keypair,  // Worker proves they hold the key bound to the warrant
    "upgrade_cluster",
    &args,
)?;
data_plane.check_chain(&chain, "upgrade_cluster", &args, Some(&signature))?;
```

## Constraint Types

| Type | Syntax | Description | Security Note |
|------|--------|-------------|---------------|
| `Wildcard` | `*` | Matches anything | Universal superset, for root warrants |
| `Pattern` | `staging-*` | **Glob** matching (NOT regex) | Safe from ReDoS attacks |
| `Exact` | `staging-web` | Exact string match | Most restrictive |
| `OneOf` | `["a", "b", "c"]` | Value must be in set | Order-independent |
| `NotOneOf` | `!["prod", "secure"]` | Value must NOT be in set | "Carving holes" from allowlist |
| `Range` | `{min: 0, max: 10000}` | Numeric bounds (inclusive) | Supports floats |
| `Regex` | `/^staging-\d+$/` | Full regex (use carefully) | Compiled & cached |
| `CEL` | `amount < 1000 && approver != ''` | Complex expressions | Full CEL language |

**Attenuation rules:**
- `Wildcard`: Can attenuate to **any** constraint type (it's the universal superset)
- `Pattern`: Child pattern must be more specific (`staging-*` → `staging-web-*` ✓)
- `Range`: Child range must be narrower (`max: 10000` → `max: 5000` ✓)
- `OneOf`: Child set must be a subset (`["a","b","c"]` → `["a","b"]` ✓)
- `NotOneOf`: Child must exclude MORE values (`!["a"]` → `!["a","b"]` ✓)

**Safe negation with `NotOneOf`:**
```rust
// Root: Allow all staging clusters (whitelist)
.constraint("cluster", Pattern::new("staging-*")?)

// Child: Exclude the DB cluster ("carving a hole")
.constraint("cluster", NotOneOf::new(vec!["staging-db"]))
```

> **Never start with negation!** Use `Wildcard` or positive constraints in root warrants.
> `NotOneOf` is for "carving holes" from an existing allowlist.

## Key Invariants

| Invariant | Description |
|-----------|-------------|
| **Monotonicity** | Capabilities can only shrink during delegation. Cryptographically enforced. |
| **Offline Verification** | Data plane never contacts Control Plane at runtime. Zero network dependency. |
| **Bounded Depth** | Protocol cap of 64 levels. Policy-configurable via `max_depth` per warrant. |
| **Cryptographic Integrity** | Ed25519 signatures with `tenuo-warrant-v1` context prefix. Prevents cross-protocol attacks. |
| **Clock Tolerance** | 30-second default grace period for clock skew (configurable). Handles distributed clock drift. |

## Deployment

### Kubernetes

```bash
# Deploy control plane (secure namespace, RBAC-protected)
kubectl apply -f tenuo-core/deploy/kubernetes/control-plane.yaml

# Add authorizer sidecar to your agent pods
kubectl apply -f tenuo-core/deploy/kubernetes/data-plane-sidecar.yaml
```

### Docker

```bash
# Build images
docker build -f tenuo-core/deploy/docker/Dockerfile.control -t tenuo/control .
docker build -f tenuo-core/deploy/docker/Dockerfile.authorizer -t tenuo/authorizer .

# Generate a keypair (run once, save securely!)
# Option 1: Use the Tenuo CLI
cargo run --bin tenuo -- keygen
# → SECRET_KEY=f07521a0719ae0a02b8acfa92e6e779f9c3ef082...
# → PUBLIC_KEY=02b04e930d436f40552de8e2fd3222a9840c8343...

# Option 2: Use openssl (secret key only, derive public key at runtime)
openssl rand -hex 32

# Run control plane (with your generated secret key)
docker run -e TENUO_SECRET_KEY=<secret_hex> -p 8080:8080 tenuo/control

# Run authorizer (with the corresponding public key)
docker run -e TENUO_TRUSTED_KEYS=<public_hex> tenuo/authorizer verify ...
```

## Project Structure

```
tenuo/
├── docker-compose.yml          # Development stack + multi-agent demo
├── scripts/
│   └── dev-setup.sh            # Generate keys, start containers
└── tenuo-core/                 # Rust implementation
    ├── src/
    │   ├── lib.rs              # Library exports
    │   ├── warrant.rs          # Warrant type & builder
    │   ├── constraints.rs      # Pattern, Exact, Range, CEL, etc.
    │   ├── crypto.rs           # Ed25519 signing with context
    │   ├── planes.rs           # ControlPlane, DataPlane, Authorizer
    │   ├── cel.rs              # CEL expression evaluation
    │   ├── wire.rs             # CBOR serialization
    │   └── bin/
    │       ├── control.rs      # Control Plane HTTP server
    │       ├── authorizer.rs   # Data Plane CLI
    │       ├── orchestrator.rs # Demo: delegation agent
    │       └── worker.rs       # Demo: constrained agent
    ├── tests/
    │   ├── integration.rs      # End-to-end workflow tests
    │   └── invariants.rs       # Property-based tests (proptest)
    └── deploy/
        ├── docker/             # Dockerfiles for all components
        └── kubernetes/         # Production K8s manifests
```

## Performance

Measured on Apple M1:

| Operation | Latency | Notes |
|-----------|---------|-------|
| Warrant verification | ~15μs | Ed25519 verify |
| Constraint check | ~2μs | Pattern matching |
| Full `check()` | ~20μs | Verify + authorize |
| Chain verification (3 levels) | ~50μs | 3 signatures |
| Batch verification (20 sigs) | ~100μs | `verify_batch()` |
| CBOR encode | ~5μs | ~300 byte output |
| CBOR decode | ~8μs | With validation |

## Security Properties

| Property | Description |
|----------|-------------|
| **Domain Separation** | Signatures include context prefix to prevent cross-protocol reuse |
| **Canonical Encoding** | Deterministic serialization ensures consistent warrant IDs |
| **Batch Verification** | ~3x faster for deep chains (use `verify_batch()`) |
| **Cycle Detection** | Chain verification rejects circular delegations |
| **Session Binding** | Optional strict mode isolates warrants per-session |

### Environment Isolation

Use different Control Plane keys per environment:

```rust
// PRODUCTION - unique keypair
let prod_cp = ControlPlane::generate();
let prod_authorizer = Authorizer::new(prod_cp.public_key());

// DEVELOPMENT - different keypair  
let dev_cp = ControlPlane::generate();

// Dev warrant fails in prod - issuer not trusted
let dev_warrant = dev_cp.issue_warrant(...);
prod_authorizer.verify(&dev_warrant); // ERROR: "issuer not trusted"
```

## Multi-Sig Approvals

Tenuo supports M-of-N approval schemes for sensitive actions. This is useful when:

- Certain actions require human approval (human-in-the-loop)
- Multiple parties must agree before an action proceeds
- Compliance requires multi-party authorization

### Creating a Multi-Sig Warrant

```rust
use tenuo_core::{Warrant, Keypair};

let admin1 = Keypair::generate();
let admin2 = Keypair::generate();
let admin3 = Keypair::generate();

// Require 2-of-3 admin approvals for this warrant
let warrant = Warrant::builder()
    .tool("delete_database")
    .ttl(Duration::from_secs(300))
    .required_approvers(vec![
        admin1.public_key(),
        admin2.public_key(), 
        admin3.public_key(),
    ])
    .min_approvals(2)  // 2-of-3 threshold
    .build(&issuer_keypair)?;
```

### Approving an Action

```rust
use tenuo_core::{Authorizer, Approval, compute_request_hash};

// Worker prepares the action
let args = HashMap::new();

// Request hash includes the holder key (prevents approval theft)
let request_hash = compute_request_hash(
    warrant.id().as_str(),
    "delete_database",
    &args,
    warrant.authorized_holder(),  // Binds approval to this holder
);

// Admin1 creates an approval (offline)
let approval1 = Approval::create(
    &admin1_keypair,
    request_hash,
    "admin1@company.com",
    "aws-iam",
    Duration::from_secs(300),
)?;

// Admin2 creates an approval (offline)  
let approval2 = Approval::create(
    &admin2_keypair,
    request_hash,
    "admin2@company.com", 
    "aws-iam",
    Duration::from_secs(300),
)?;

// Authorize (unified API handles both PoP and multi-sig)
authorizer.authorize(
    &warrant,
    "delete_database",
    &args,
    holder_signature.as_ref(),  // PoP
    &[approval1, approval2],    // Multi-sig
)?;
```

### Multi-Sig Monotonicity

When attenuating warrants, multi-sig requirements can only become **stricter**:

| Attenuation | Allowed? | Reason |
|-------------|----------|--------|
| Add more approvers | ✅ | More restrictive |
| Raise threshold (1→2) | ✅ | More restrictive |
| Remove approvers | ❌ | Violates monotonicity |
| Lower threshold (2→1) | ❌ | Violates monotonicity |

```rust
// Root requires 1-of-2 approvals
let root = Warrant::builder()
    .required_approvers(vec![admin1.public_key(), admin2.public_key()])
    .min_approvals(1)
    .build(&issuer)?;

// Child can ADD approvers and RAISE threshold
let child = root.attenuate()
    .add_approvers(vec![admin3.public_key()])  // Now 3 approvers
    .raise_min_approvals(2)                     // Now 2-of-3 required
    .build(&delegator)?;

// Cannot REMOVE approvers or LOWER threshold - build() would fail
```

### Multi-Sig Security

Approvals are cryptographically bound to prevent theft:

| Attack | Protection |
|--------|------------|
| **Approval theft** | `request_hash` includes `authorized_holder` - stolen approvals only work for intended holder |
| **Replay attack** | Hash includes `warrant_id + tool + args` - approvals are request-specific |
| **Expired approvals** | `expires_at` checked with clock tolerance |
| **DoS via flood** | Approval count limited to `2 × required_approvers.len()` |
| **Duplicate approvals** | Same approver counted only once via `HashSet` deduplication |
| **Bypass multi-sig** | Unified `authorize()` API - no code path skips approval check |

**Why Independent Signatures?** We use independent Ed25519 signatures (similar to Bitcoin multi-sig) rather than threshold schemes like Shamir or FROST. This ensures no secret is ever reconstructed, no interactive coordination is required between approvers, verification stays 100% offline, and each approver is individually traceable for audit. The trade-off is signature size (M × 64 bytes vs. a single aggregated signature), which is acceptable for our use case.

### Notary Registry (Identity Mapping)

The `NotaryRegistry` maps enterprise identities to cryptographic keys:

```rust
use tenuo_core::approval::{NotaryRegistry, KeyBinding};

let mut registry = NotaryRegistry::new();

// Register AWS IAM users
registry.register_provider("aws-iam", "AWS IAM Identity Provider");

// Map an IAM user to their Tenuo key
registry.register_key(KeyBinding {
    id: "kb_abc123".into(),
    external_id: "arn:aws:iam::123456789:user/admin".into(),
    provider: "aws-iam".into(),
    public_key: admin_keypair.public_key(),
    display_name: Some("Alice Admin".into()),
    registered_by: "terraform".into(),
    // ...
})?;

// Look up key by external identity
let key = registry.get_key("aws-iam", "arn:aws:iam::123456789:user/admin")?;
```

**Notary Philosophy**: Tenuo stays "pure" (offline, math-only) while identity providers act as notaries that map enterprise identities to cryptographic keys.

### Future Considerations

| Feature | Use Case |
|---------|----------|
| Merkle Roots | Authorize large document sets (RAG security) without bloating headers |
| OAuth RAR Bridge | Embed Tenuo warrants inside OAuth tokens for ecosystem compatibility |
| DID Support | Cross-organization federation without shared infrastructure |

## License

Apache-2.0
