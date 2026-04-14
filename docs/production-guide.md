---
title: Going to Production
description: Enforcement modes, gradual rollout, key management, and production patterns
---

# Going to Production

This guide covers moving from `dev_mode=True` to a production deployment. If you haven't used Tenuo yet, start with the [Quick Start](./quickstart).

## Enforcement Modes

Tenuo supports three modes for gradual adoption:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `enforce` | Block unauthorized requests | Production (default) |
| `audit` | Log violations but allow execution | Discovery, gradual adoption |
| `permissive` | Log + warn header, allow execution | Development, testing |

```python
from tenuo import configure, SigningKey

configure(
    issuer_key=SigningKey.from_env("ISSUER_KEY"),
    mode="audit",  # Start here
    trusted_roots=[control_plane_pubkey],
)
```

Check the current mode programmatically:

```python
from tenuo import is_audit_mode, is_enforce_mode, should_block_violation

if is_audit_mode():
    print("Violations logged but not blocked")
```

## Gradual Rollout

**Step 1: Deploy in audit mode.** All tool calls are logged but never blocked. Analyze logs to see what would be denied.

```python
configure(issuer_key=SigningKey.generate(), mode="audit", dev_mode=True)
```

**Step 2: Add `@guard` to critical tools.**

```python
@guard(tool="delete_file")
def delete_file(path: str): ...
```

In audit mode, this still allows execution but logs authorization checks.

**Step 3: Test with scoped warrants.**

```python
with mint_sync(Capability("delete_file", path=Subpath("/tmp"))):
    delete_file("/tmp/test.txt")  # Allowed
    delete_file("/etc/passwd")    # Logged as violation
```

**Step 4: Enable enforce mode.** Roll out to a subset of traffic first if needed.

```python
configure(mode="enforce", trusted_roots=[control_plane_pubkey])
```

> **Tip:** Use `why_denied(tool, args)` to debug specific failures during rollout.

## Key Management

### Development

In development, generate ephemeral keys:

```python
from tenuo import SigningKey, configure

configure(issuer_key=SigningKey.generate(), dev_mode=True)
```

### Production

In production, keys come from your control plane or secret management:

```python
from tenuo import SigningKey, PublicKey

issuer_key = SigningKey.from_env("ISSUER_KEY")          # Base64-encoded
trusted_root = PublicKey.from_env("TRUSTED_ROOT_PUBKEY") # Issuer's public key
```

### Environment Variables

For 12-factor apps, configure via environment:

```python
from tenuo import auto_configure

auto_configure()  # Reads TENUO_* environment variables
```

| Variable | Description |
|----------|-------------|
| `TENUO_ISSUER_KEY` | Base64-encoded signing key |
| `TENUO_MODE` | `enforce` (default), `audit`, or `permissive` |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys |
| `TENUO_DEV_MODE` | `1` for development mode |

For Temporal-specific key management (e.g., `TENUO_KEY_<key_id>`), see the [Temporal Guide](./temporal).

### Tenuo Cloud (Recommended)

**[Tenuo Cloud](https://cloud.tenuo.ai)** handles key issuance, warrant minting, rotation, revocation (SRL), and audit as a managed control plane — so you don't have to build and operate these yourself. Connect your agents with a connect token:

```bash
export TENUO_CONNECT_TOKEN="tenuo_ct_..."   # From the Tenuo Cloud dashboard
export TENUO_API_KEY="tc_..."               # Included in the connect token
```

The SDK reads these automatically. Tenuo Cloud manages root keys, mints warrants on behalf of your orchestrators, rotates keys on schedule, publishes revocation lists, and indexes audit receipts across all workflows.

With Tenuo Cloud, you skip the manual key management, rotation, and audit infrastructure described below. The self-hosted patterns are for teams that need full control or have on-prem requirements.

> **[Request early access →](https://tenuo.ai/early-access.html)**

## Production Patterns (Self-Hosted)

### Pattern 1: Keys Separate from Warrants (Recommended)

```python
from tenuo import Warrant, SigningKey, Pattern

key = SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tool("search")
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

headers = warrant.headers(key, "search", {"query": "test"})

# Delegation with attenuation
worker_key = SigningKey.generate()
child = (warrant.grant_builder()
    .capability("search", query=Pattern("safe*"))
    .holder(worker_key.public_key)
    .ttl(300)
    .grant(key))
```

### Pattern 2: BoundWarrant (For Repeated Operations)

```python
from tenuo import Warrant, SigningKey

key = SigningKey.from_env("MY_KEY")
warrant = (Warrant.mint_builder()
    .tool("process")
    .holder(key.public_key)
    .ttl(3600)
    .mint(key))

bound = warrant.bind(key)

for item in items:
    headers = bound.headers("process", {"item": item})
    # Make API call with headers...

# BoundWarrant should NOT be stored in state/cache (contains key)
```

### Pattern 3: Environment-Based Setup

```python
from tenuo import auto_configure, guard, mint_sync, Capability

auto_configure()

@guard(tool="search")
def search(query: str) -> str:
    return f"Results for {query}"

with mint_sync(Capability("search")):
    search("hello")
```

## Low-Level API

For deployments needing explicit keypair management across trust boundaries.

### 1. Create a Warrant

```python
from tenuo import SigningKey, Warrant, Pattern, Range, PublicKey

issuer_key = SigningKey.from_env("ISSUER_KEY")
orchestrator_pubkey = PublicKey.from_env("ORCH_PUBKEY")

warrant = (Warrant.mint_builder()
    .capability("manage_infrastructure",
        cluster=Pattern("staging-*"),
        replicas=Range.max_value(15))
    .holder(orchestrator_pubkey)
    .ttl(3600)
    .mint(issuer_key))
```

### 2. Delegate with Attenuation

```python
orchestrator_key = SigningKey.from_env("ORCH_KEY")
worker_pubkey = PublicKey.from_env("WORKER_PUBKEY")

worker_warrant = (warrant.grant_builder()
    .capability("manage_infrastructure",
        cluster=Pattern("staging-web"),
        replicas=Range.max_value(10))
    .holder(worker_pubkey)
    .ttl(300)
    .grant(orchestrator_key))
```

### 3. Authorize an Action

```python
worker_key = SigningKey.from_env("WORKER_KEY")
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = worker_warrant.sign(worker_key, "manage_infrastructure", args)

authorized = worker_warrant.allows("manage_infrastructure", args)
print(f"Authorized: {authorized}")  # True
```

## Combining Integrations

| Combination | Use When |
|-------------|----------|
| **OpenAI + A2A** | Workers are separate OpenAI services |
| **ADK + A2A** | ADK orchestrator delegates to various worker services |
| **Temporal + MCP** | Durable workflows calling MCP tool servers |
| **OpenAI + ADK + A2A** | Mixed runtimes in distributed system |

**Rule of thumb**: Same language + same process = runtime integration only. Cross-service = add [A2A](./a2a).

## Next Steps

- **[Constraint Types](./constraints)** — `Subpath`, `Pattern`, `Range`, `UrlSafe`, `Exact`, and more
- **[Security Model](./security)** — threat model, PoP mechanics, delegation chain verification
- **[API Reference](./api-reference)** — full `Warrant`, `SigningKey`, `BoundWarrant` API
- **[Debugging](./debugging)** — troubleshooting common issues
