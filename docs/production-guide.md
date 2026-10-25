---
title: Going to Production
description: Enforcement modes, gradual rollout, key management, and production patterns
---

# Going to Production

This guide covers moving from `dev_mode=True` to a production deployment. If you haven't used Tenuo yet, start with the [Quick Start](./quickstart).

## Enforcement Modes

Tenuo has two modes:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `enforce` | Block unauthorized requests | Production (default) |
| `observe` | Run the full check, log what would be denied, allow execution | Discovery, gradual adoption |

`audit` and `permissive` are accepted aliases of `observe`.

In observe mode every denial, including a bad signature or untrusted root, is logged as one `WARNING` (`OBSERVE: would deny <tool>: <reason>`) with structured fields: `tool`, `args_keys`, `arg_types` (value type names, never values), `error_type`, `constraint_violated`, `denial_reason`, `warrant_id`. The result is returned as allowed with `observed=True` and the denial details kept, and receipts still record it as a denial. Approval gates are not prompted; the call is recorded with `error_type="approval_required"` and proceeds.

If you sign receipts, an observed denial is a **deny** receipt with `enforced=false`, so a receipt stream always shows which denials were let through. Enforced receipts omit the field. Upgrade receipt verifiers before you turn observe mode on: tenuo 0.3.2 and older reject receipts that carry `enforced`.

```python
from tenuo import configure, SigningKey

configure(
    issuer_key=SigningKey.from_env("ISSUER_KEY"),
    mode="observe",  # Start here
    trusted_roots=[control_plane_pubkey],
)
```

Check the current mode programmatically:

```python
from tenuo import is_observe_mode, is_enforce_mode, should_block_violation

if is_observe_mode():
    print("Violations logged but not blocked")
```

## Gradual Rollout

**Step 1: Deploy in observe mode.** All tool calls are logged but never blocked. Analyze logs to see what would be denied. Configure the same trusted roots you will enforce with, so the log shows the denials you would really get.

```python
configure(mode="observe", trusted_roots=[control_plane_pubkey])
```

Or, if your app calls `auto_configure()`, from the environment:

```bash
export TENUO_MODE=observe
export TENUO_TRUSTED_ROOTS="<root public key>"
```

Each `OBSERVE: would deny` line names the tool, the argument keys and types, and the `error_type`. Use them to tighten the policy: a `tool_not_allowed` line means the warrant needs that tool, and a `constraint_violation` line names the argument in `constraint_violated`. `untrusted_issuer` or `chain_missing` means trust is misconfigured, not the policy; see [Trusted Roots and Delegation Chains](#trusted-roots-and-delegation-chains).

**Step 2: Add `@guard` to critical tools.**

```python
@guard(tool="delete_file")
def delete_file(path: str): ...
```

In observe mode, this still allows execution but logs what would have been denied.

**Step 3: Test with scoped warrants.**

```python
with mint_sync(Capability("delete_file", path=Subpath("/tmp"))):
    delete_file("/tmp/test.txt")  # Allowed
    delete_file("/etc/passwd")    # Logged as violation
```

**Step 4: Enable enforce mode.** Roll out to a subset of traffic first if needed. Observe mode is meant for a rollout window, not a permanent setting: leave it on and nothing is enforced.

```python
configure(mode="enforce", trusted_roots=[control_plane_pubkey])
```

`configure(...)` replaces the whole configuration, so pass the trusted roots again when you switch modes. With `auto_configure()`, set `TENUO_MODE=enforce` (or unset it) and restart.

> **Tip:** Use `why_denied(tool, args)` to debug specific failures during rollout.

## Trusted Roots and Delegation Chains

Configure **only root keys** as trusted roots: the key of whatever mints your top-level warrants (your control plane or issuer). A verifier then accepts any warrant delegated from that root, at any depth, without knowing the intermediate keys.

To do that it needs the whole chain. A delegated warrant carries a hash of its parent (`parent_hash`), not the parent itself, and the verifier never fetches parents. So every delegated call must present the root-to-leaf chain as one WarrantStack:

- HTTP, FastAPI and A2A: `X-Tenuo-Warrant` carries the stack. `warrant.headers(..., warrant_chain=[root_warrant])` builds it, and `grant()` / `chain_scope()` fill it in for you.
- MCP: `_meta.tenuo.warrant` carries the stack.
- Temporal: the `x-tenuo-warrant-chain` header, set by `warrant_chain=` on the start APIs.
- Framework adapters: pass `warrant_chain=[...]` (parents root-first, excluding the leaf) or a stack token.

A delegated warrant presented alone fails closed (`chain_missing` / `UntrustedRoot`). Do not fix that by adding the orchestrator's key to `trusted_roots`. That quietly promotes the key to a root: the verifier stops checking that the warrant narrows the real root's authority, and the key can mint anything. Trusted roots must come from your configuration, never from anything in the request.

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
| `TENUO_MODE` | `enforce` (default) or `observe` (`audit` and `permissive` are aliases) |
| `TENUO_TRUSTED_ROOTS` | Comma-separated public keys |
| `TENUO_DEV_MODE` | `1` for development mode |

For Temporal-specific key management (e.g., `TENUO_KEY_<key_id>`), see the [Temporal Guide](./temporal).

### Managed control plane for enterprise operations

As more teams use Tenuo, the hard problem becomes operating authority
consistently: who can mint production warrants, how trust roots and keys rotate,
how revocation lists reach every worker, how approvals are routed, and how audit
receipts are searched across services and business units.

**[Tenuo Cloud](https://cloud.tenuo.ai)** provides that managed control plane
for teams that want centralized enterprise control instead of building and
operating those pieces themselves. Connect your agents with a connect token:

```bash
export TENUO_CONNECT_TOKEN="tenuo_ct_..."   # From the Tenuo Cloud dashboard
export TENUO_API_KEY="tc_..."               # Included in the connect token
```

The SDK reads these automatically. Tenuo Cloud manages root keys, mints warrants on behalf of your orchestrators, rotates keys on schedule, publishes revocation lists, routes approvals, and indexes audit receipts across all workflows.

With a managed control plane, you skip the manual key management, rotation,
approval, revocation, and audit infrastructure described below. The self-hosted
patterns are for teams that need full control or have on-prem requirements.

> **[Schedule a demo / request access →](https://tenuo.ai/early-access.html)**

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

bound = warrant.bind(key, trusted_roots=[key.public_key])

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

The verifier trusts only the issuer's root key and checks the whole chain, root first:

```python
import time
from tenuo import Authorizer

worker_key = SigningKey.from_env("WORKER_KEY")
args = {"cluster": "staging-web", "replicas": 5}
pop_sig = worker_warrant.sign(worker_key, "manage_infrastructure", args, int(time.time()))

authorizer = Authorizer(trusted_roots=[issuer_key.public_key])
authorizer.check_chain([warrant, worker_warrant], "manage_infrastructure", args,
                       signature=bytes(pop_sig))  # raises on denial

# The leaf alone is rejected: its issuer (the orchestrator) is not a root
# authorizer.check_chain([worker_warrant], ...)  -> UntrustedRoot
```

`worker_warrant.allows(tool, args)` only checks constraints. It verifies no signatures and no chain, so use it for previews, never to authorize.

## Combining Integrations

| Combination | Use When |
|-------------|----------|
| **OpenAI + A2A** | Workers are separate OpenAI services |
| **ADK + A2A** | ADK orchestrator delegates to various worker services |
| **Temporal + MCP** | Durable workflows calling MCP tool servers |
| **OpenAI + ADK + A2A** | Mixed runtimes in distributed system |

**Rule of thumb**: Same language + same process = runtime integration only. Cross-service = add [A2A](./a2a).

### Cross-namespace Temporal (Nexus)

If your Temporal workers call across Namespaces with Nexus, the handler worker needs three things before it is safe to ship. The first one is required: a worker that serves Nexus operations without it denies every request.

1. **Set `TenuoPluginConfig.nexus_endpoint`** to the endpoint name this worker serves.
2. **Build the worker with `TenuoWorkerInterceptor`** (or `TenuoTemporalPlugin`). Inbound Nexus starts are then authorized even if a handler is missing its `@tenuo_nexus_operation` decorator.
3. **Keep backing workflows unreachable by untrusted clients.** They are an implementation detail of the handler, and starting one directly skips the Nexus verifier.

```python
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    nexus_endpoint="billing-prod",   # required for Nexus handler workers
)
```

Turning on `nexus_pop_replay_protection` adds one more requirement: a fleet running more than one worker also needs a shared owner-aware `pop_dedup_store`, because the in-process default only suppresses replays on a single worker.

Full setup, the workflow-backed operation path, and the complete pre-ship checklist are in [Temporal Nexus Authorization](./temporal-nexus).

## Next Steps

- **[Temporal Nexus Authorization](./temporal-nexus)** — cross-namespace setup, workflow-backed operations, production checklist
- **[Constraint Types](./constraints)** — `Subpath`, `Pattern`, `Range`, `UrlSafe`, `Exact`, and more
- **[Security Model](./security)** — threat model, PoP mechanics, delegation chain verification
- **[API Reference](./api-reference)** — full `Warrant`, `SigningKey`, `BoundWarrant` API
- **[Debugging](./debugging)** — troubleshooting common issues
