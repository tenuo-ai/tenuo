---
title: Temporal Integration
description: Warrant-based authorization for durable workflows
---

# Tenuo Temporal Integration

> **Status**: Implemented (Activity authorization + PoP + Delegation)

## Overview

Tenuo integrates with [Temporal](https://temporal.io) to bring warrant-based authorization to durable workflows. Activities are transparently authorized against the workflow's warrant without code changes to your activity definitions.

**Key Features:**
- **Activity-level authorization**: Each activity execution is authorized against warrant constraints
- **Proof-of-Possession (PoP)**: Ed25519 signature verification when `trusted_roots` is configured
- **Warrant propagation**: Warrants flow through workflow headers automatically
- **Child workflow delegation**: Attenuate warrants when spawning child workflows via `tenuo_execute_child_workflow()`
- **Delegation chain verification**: Full chain-of-trust validation back to trusted roots
- **Signal & update guards**: Restrict which signals and updates a workflow accepts
- **Nexus header propagation**: Warrant context flows through Nexus operations
- **PoP replay protection**: In-memory dedup cache prevents signature replay attacks
- **Continue-as-new support**: Warrant headers survive workflow continuation
- **Fail-closed**: Missing or invalid warrants block execution by default
- **🔒 Secure key management**: Private keys NEVER transmitted in headers - resolved from Vault/KMS/Secret Manager
- **Enterprise key resolvers**: `VaultKeyResolver`, `AWSSecretsManagerKeyResolver`, `GCPSecretManagerKeyResolver`, `CompositeKeyResolver`

---

## Installation

```bash
uv pip install "tenuo[temporal]"
```

Requires Temporal server running locally or in production.

---

## Quick Start

### Basic Workflow Protection

```python
from datetime import timedelta
from pathlib import Path
from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

from tenuo import SigningKey, Warrant
from tenuo_core import Subpath
from tenuo.temporal import (
    AuthorizedWorkflow,
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    tenuo_execute_activity,
)

# Define protected activities (no Tenuo-specific code needed)
@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()

@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"

# Define workflow — use AuthorizedWorkflow for automatic PoP calculation
@workflow.defn
class DataProcessingWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, input_path: str, output_path: str) -> str:
        # Automatic PoP signature generation via self.execute_authorized_activity
        data = await self.execute_authorized_activity(
            read_file,
            args=[input_path],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )

        processed = data.upper()
        
        await self.execute_authorized_activity(
            write_file,
            args=[output_path, processed],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )

        return f"Processed {len(data)} bytes"

# Setup
async def main():
    # Client interceptor injects warrant headers into workflow start
    client_interceptor = TenuoClientInterceptor()

    # IMPORTANT: Configure KeyResolver for secure key management
    # Workers use this to fetch signing keys from secure storage
    from tenuo.temporal import VaultKeyResolver

    key_resolver = VaultKeyResolver(
        url="https://vault.company.com:8200",
        path_template="production/tenuo/{key_id}",
        cache_ttl=300,  # Cache keys for 5 minutes
    )
    client = await Client.connect("localhost:7233",
                                  interceptors=[client_interceptor])

    # Generate keys
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Issue warrant using the builder API
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/data/input"))
        .capability("write_file", path=Subpath("/data/output"))
        .ttl(3600)
        .mint(control_key)
    )

    # Configure worker interceptor with full PoP verification
    interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            trusted_roots=[control_key.public_key],  # enables Authorizer + PoP
        )
    )

    # Start worker with interceptor and sandbox passthrough
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner, SandboxRestrictions,
    )

    async with Worker(
        client,
        task_queue="data-processing",
        workflows=[DataProcessingWorkflow],
        activities=[read_file, write_file],
        interceptors=[interceptor],
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                "tenuo", "tenuo_core",  # Required for PoP signing
            )
        ),
    ):
        # Set warrant headers (only key_id, NOT the private key)
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent-key-1")  # ✅ Only key ID transmitted
        )
        result = await client.execute_workflow(
            DataProcessingWorkflow.run,
            args=["/data/input/report.txt", "/data/output/report.txt"],
            id="process-001",
            task_queue="data-processing",
        )
```

> **Important:** `tenuo` and `tenuo_core` must be configured as passthrough modules in Temporal's workflow sandbox. Without this, PoP verification will fail with `ImportError: PyO3 modules compiled for CPython 3.8 or older may only be initialized once per interpreter process`.

> **🔒 Security:** Private keys are **NEVER** transmitted in headers. Only the `key_id` is sent. Workers use `KeyResolver` to fetch the actual signing key from secure storage (Vault, AWS Secrets Manager, GCP Secret Manager, etc.).

**What happens:**
1. `TenuoClientInterceptor` injects warrant + key_id into workflow headers (NO private key)
2. Workflow inbound interceptor extracts Tenuo headers and propagates them to activities
3. Each activity call triggers `KeyResolver.resolve(key_id)` to fetch the signing key from secure storage
4. PoP signature is computed locally on the worker using the resolved key
5. Activity inbound interceptor verifies warrant, PoP, and constraints
6. Activity executes only if all checks pass

This works in both single-process demos and distributed deployments where client and worker run in separate processes.

---

## Configuration

### Key Management (REQUIRED)

**🔒 Security Requirement:** Tenuo NEVER transmits private keys in headers. Workers must be configured with a `KeyResolver` to fetch signing keys from secure storage.

#### Production: Vault

```python
from tenuo.temporal import VaultKeyResolver, TenuoInterceptorConfig

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    path_template="production/tenuo/{key_id}",  # e.g., "production/tenuo/agent-2024"
    token=None,  # Uses VAULT_TOKEN env var
    mount="secret",  # KV secrets engine mount
    cache_ttl=300,  # Cache keys for 5 minutes
)

config = TenuoInterceptorConfig(
    key_resolver=resolver,  # ✅ REQUIRED
    trusted_roots=[root_key.public_key],
)
```

Store keys in Vault:
```bash
# Store signing key in Vault
vault kv put secret/production/tenuo/agent-2024 \
  data=@signing_key.bin
```

#### Production: AWS Secrets Manager

```python
from tenuo.temporal import AWSSecretsManagerKeyResolver

resolver = AWSSecretsManagerKeyResolver(
    secret_prefix="tenuo/keys/",  # e.g., "tenuo/keys/agent-2024"
    region_name="us-west-2",
    cache_ttl=300,
)

config = TenuoInterceptorConfig(key_resolver=resolver)
```

Store keys in AWS:
```bash
# Store signing key in AWS Secrets Manager
aws secretsmanager create-secret \
  --name tenuo/keys/agent-2024 \
  --secret-binary fileb://signing_key.bin \
  --region us-west-2
```

#### Production: GCP Secret Manager

```python
from tenuo.temporal import GCPSecretManagerKeyResolver

resolver = GCPSecretManagerKeyResolver(
    project_id="my-project",
    secret_prefix="tenuo-keys-",  # e.g., "tenuo-keys-agent-2024"
    cache_ttl=300,
)

config = TenuoInterceptorConfig(key_resolver=resolver)
```

Store keys in GCP:
```bash
# Store signing key in GCP Secret Manager
gcloud secrets create tenuo-keys-agent-2024 \
  --data-file=signing_key.bin \
  --project=my-project
```

#### Development: Environment Variables

```python
from tenuo.temporal import EnvKeyResolver

# ⚠️ DEVELOPMENT ONLY - DO NOT USE IN PRODUCTION
# A WARNING is emitted at first key resolution unless TENUO_ENV=development.
resolver = EnvKeyResolver(
    prefix="TENUO_KEY_",
    warn_in_production=True,  # Default; set False to suppress explicitly
)

config = TenuoInterceptorConfig(key_resolver=resolver)
```

Set environment variable:
```bash
# Export base64-encoded signing key
export TENUO_KEY_agent1=$(cat signing_key.bin | base64)
# Suppress the production warning in local dev:
export TENUO_ENV=development
```

> **Warning:** `EnvKeyResolver` is for development only. In production, use Vault, AWS Secrets Manager, or GCP Secret Manager.

#### Composite Resolver (Fallback Chain)

```python
from tenuo.temporal import CompositeKeyResolver, VaultKeyResolver, EnvKeyResolver

resolver = CompositeKeyResolver(
    resolvers=[
        VaultKeyResolver(url="https://vault.company.com"),  # Try Vault first
        EnvKeyResolver(),                                    # Fallback to env vars
    ],
    warn_on_fallback=True,  # Log a WARNING whenever a fallback resolver is used
)

config = TenuoInterceptorConfig(key_resolver=resolver)
```

### Interceptor Config

```python
from tenuo.temporal import TenuoInterceptorConfig

config = TenuoInterceptorConfig(
    key_resolver=EnvKeyResolver(),        # Required: key resolution strategy
    on_denial="raise",                    # "raise" | "log" | "skip"
    trusted_roots=[control_key.public_key],  # Enables Authorizer + PoP verification
    strict_mode=True,                     # Raise ValueError at startup if trusted_roots absent
    require_warrant=True,                 # Fail-closed: deny if no warrant
    block_local_activities=True,          # Prevent local activity bypass
    redact_args_in_logs=True,             # Prevent secret leaks in logs
    max_chain_depth=10,                   # Max delegation depth
    audit_callback=on_audit,              # Optional audit event handler
    metrics=TenuoMetrics(),               # Optional Prometheus metrics
    authorized_signals=["approve"],       # Optional signal allowlist
    authorized_updates=["update_config"], # Optional update allowlist
)
```

> **Production hardening:** Set `strict_mode=True` in production configs. It raises `ValueError` at worker startup if `trusted_roots` is absent, preventing accidental deployment in lightweight (no-PoP) mode.

### Denial Handling

Control what happens when authorization fails:

```python
# "raise" (default): raise ConstraintViolation — workflow fails fast
# "log":             log the denial and continue execution
# "skip":            silently return None
config = TenuoInterceptorConfig(
    key_resolver=resolver,
    on_denial="raise",
)
```


---

## Proof-of-Possession

When `trusted_roots` is configured, Tenuo enforces PoP verification for all activity executions. The challenge is a CBOR-serialized tuple of `(warrant_id, tool, sorted_args, window_ts)` signed with the holder's Ed25519 key.

### Two patterns for PoP

**AuthorizedWorkflow** (recommended) validates headers at workflow start and provides `self.execute_authorized_activity()`:

```python
@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

**tenuo_execute_activity()** is a free function for advanced use cases (multi-warrant workflows, per-stage delegation) where you need explicit control:

```python
from tenuo.temporal import tenuo_execute_activity

@workflow.defn
class PipelineWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        return await tenuo_execute_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
```

Both automatically sign PoP challenges — you never need to call `warrant.sign()` directly in Temporal workflows.

### PoP Challenge Format

The PoP signature is computed deterministically by the Rust core:

```
domain_context = b"tenuo-pop-v1"
window_ts      = (unix_now // 30) * 30          # 30-second bucket
challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
preimage       = domain_context || challenge_data
signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes
```

In Python, this is a single call:

```python
pop_signature = warrant.sign(signing_key, "read_file", {"path": "/data/file.txt"})
# Returns 64 raw bytes; valid for 4 windows (2 minutes)
```

`tenuo_execute_activity()` handles this automatically. You only need `warrant.sign()` directly if building custom tooling outside of Temporal.

---

## Child Workflow Delegation

Attenuate warrants when spawning child workflows with `tenuo_execute_child_workflow()`:

```python
from tenuo.temporal import tenuo_execute_child_workflow

@workflow.defn
class ParentWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Parent has: read_file + write_file

        # Child gets only read_file with reduced TTL
        result = await tenuo_execute_child_workflow(
            ChildWorkflow.run,
            tools=["read_file"],   # Subset of parent tools
            ttl_seconds=60,        # Shorter than parent
            args=["/data/input"],
            id=f"child-{workflow.info().workflow_id}",
            task_queue=workflow.info().task_queue,
        )
        return result
```

The wrapper calls `attenuated_headers()` internally and injects the attenuated warrant via the outbound workflow interceptor — Temporal's `execute_child_workflow()` does not accept a `headers` kwarg directly.

### Delegation Chain Verification

When warrants are attenuated, the full delegation chain is propagated via the `x-tenuo-warrant-chain` header. The activity interceptor calls `Authorizer.check_chain()` to verify every link in the chain back to a trusted root, ensuring no intermediate warrant was forged or widened.

---

## Signal & Update Authorization

Control which signals and workflow updates are allowed:

```python
config = TenuoInterceptorConfig(
    key_resolver=EnvKeyResolver(),
    on_denial="raise",
    trusted_roots=[control_key.public_key],
    authorized_signals=["approve", "reject"],     # Only these signals allowed
    authorized_updates=["update_config"],          # Only these updates allowed
)
```

Unrecognized signals raise `ConstraintViolation`. Unrecognized updates are rejected at the validator stage before the handler runs. When set to `None` (default), all signals and updates pass through for backward compatibility.

---

## Nexus Operation Headers

When starting Nexus operations from a Tenuo-protected workflow, the outbound interceptor automatically propagates warrant headers to the Nexus service. Headers are base64-encoded into Nexus's string-based header format.

---

## PoP Replay Protection

The activity interceptor maintains an in-memory dedup cache to detect replayed PoP signatures within the same time window. Each unique `(warrant, tool, args, workflow_id, activity_id)` combination is tracked. Retries (`attempt > 1`) bypass dedup since Temporal legitimately re-delivers the same activity. The cache is periodically evicted (every 60 seconds) and hard-capped at 10,000 entries to prevent unbounded memory growth.

> **Distributed deployments:** The dedup cache is **process-local**. In a horizontally scaled worker fleet (multiple replicas), a captured PoP token could be replayed against a different replica within the warrant TTL window. For single-process workers or development, the in-memory cache is sufficient. For multi-replica production deployments, plan to implement a shared dedup backend (e.g., Redis) when this replay surface becomes a concern.

---

## Decorators

### @tool() - Activity-to-Tool Mapping

Map activity names to different tool names in warrants:

```python
from tenuo.temporal import tool

@activity.defn
@tool("read_file")
async def fetch_document(doc_id: str) -> str:
    """Activity name is 'fetch_document', warrant checks 'read_file'."""
    return await storage.get(doc_id)
```

### @unprotected - Local Activities

Mark activities as safe for local execution (bypass interceptor):

```python
from tenuo.temporal import unprotected

@activity.defn
@unprotected
async def get_config_value(key: str) -> str:
    """Internal config lookup - no warrant needed."""
    return config[key]

# Can be used as local activity
await workflow.execute_local_activity(
    get_config_value,
    args=["database_url"],
)
```

### workflow_grant() - Scoped In-Workflow Grants

Issue a narrowed warrant for a single tool within a running workflow:

```python
from tenuo.temporal import workflow_grant

@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        # Issue a 60-second, read-only grant for exactly one tool,
        # narrower than the workflow's own warrant.
        file_warrant = workflow_grant(
            "read_file",
            constraints={"path": path},  # Must be keys the parent already has
            ttl_seconds=60,
        )
        # file_warrant is a Warrant object; use it in a custom activity call
        # or pass it via tenuo_headers() to an external service.
        ...
```

> `workflow_grant()` is useful when you need to hand off a scoped credential to a sub-process or external call. Constraint keys in `constraints` must already exist in the parent warrant; introducing new keys raises `ConstraintViolation`.

---

## Audit Events

Subscribe to authorization decisions:

```python
from tenuo.temporal import TemporalAuditEvent

def on_audit(event: TemporalAuditEvent):
    if event.decision == "ALLOW":
        logger.info(
            f"Allowed: {event.tool} in {event.workflow_type} "
            f"(warrant: {event.warrant_id})"
        )
    else:
        logger.warning(
            f"Denied: {event.tool} in {event.workflow_type} - "
            f"{event.denial_reason}"
        )

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    audit_callback=on_audit,
    audit_allow=True,   # Log allowed actions
    audit_deny=True,    # Log denied actions
)
```

---

## Observability

### Prometheus Metrics

```python
from tenuo.temporal import TenuoMetrics

metrics = TenuoMetrics(prefix="tenuo_temporal")

config = TenuoInterceptorConfig(
    key_resolver=resolver,
    metrics=metrics,
)

# Exposes metrics at /metrics:
# - tenuo_temporal_activities_authorized_total{tool, workflow_type}
# - tenuo_temporal_activities_denied_total{tool, reason, workflow_type}
# - tenuo_temporal_authorization_latency_seconds_bucket{tool}
```

---

## Security Model

### Fail-Closed by Default

All security checks default to deny:

| Check | Missing/Invalid | Behavior |
|-------|----------------|----------|
| Warrant header | Missing | Denied (require_warrant=True) |
| Warrant expired | Expired | Raises WarrantExpired |
| Tool not in warrant | Not allowed | Raises ConstraintViolation |
| Constraint violated | Args don't match | Raises ConstraintViolation |
| PoP signature | Missing/invalid | Raises PopVerificationError |
| Local activity | Protected function | Raises LocalActivityError |

### Replay Safety

PoP challenges use 30-second time-window bucketing (`floor(unix_now / 30) * 30`) for replay tolerance. Signatures remain valid for 4 windows (2 minutes). The `tenuo_execute_activity()` helper handles PoP signing inside the workflow sandbox, and the workflow outbound interceptor injects signed headers into Temporal's native activity header propagation. This means authorization works correctly even in distributed deployments where the client and worker run in separate processes.

---

## Exceptions

All exceptions include `error_code` for wire format compatibility:

```python
from tenuo.temporal import (
    ConstraintViolation,      # error_code: "CONSTRAINT_VIOLATED"
    WarrantExpired,           # error_code: "WARRANT_EXPIRED"
    ChainValidationError,     # error_code: "CHAIN_INVALID"
    PopVerificationError,     # error_code: "POP_VERIFICATION_FAILED"
    LocalActivityError,       # error_code: "LOCAL_ACTIVITY_BLOCKED"
    KeyResolutionError,       # error_code: "KEY_NOT_FOUND"
)
```

---

## Best Practices

1. **Use AuthorizedWorkflow** as your base class for fail-fast validation and automatic PoP
2. **Use tenuo_execute_activity()** for advanced multi-warrant or delegation patterns
3. **Always configure passthrough modules** (`tenuo`, `tenuo_core`) in the workflow sandbox
4. **Set `strict_mode=True`** in production to fail fast if `trusted_roots` is accidentally omitted
5. **Set up VaultKeyResolver** (or AWS/GCP) for production key management; never use `EnvKeyResolver` in production
6. **Enable audit logging** to track authorization decisions
7. **Use @unprotected** sparingly - only for truly internal operations
8. **Attenuate warrants** for child workflows to enforce least privilege
9. **Keep TTLs short** for sensitive operations (minutes, not hours)

---

## Examples

| Example | Description |
|---------|-------------|
| [`authorized_workflow_demo.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/authorized_workflow_demo.py) | **Recommended starting point.** AuthorizedWorkflow base class with parallel reads and fail-fast validation |
| [`demo.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/demo.py) | Lower-level `tenuo_execute_activity()` API with sequential + parallel reads |
| [`multi_warrant.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/multi_warrant.py) | Multi-tenant isolation: separate warrants per workflow |
| [`delegation.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/delegation.py) | Per-stage pipeline authorization with least-privilege warrants |

### Per-Stage Pipeline (from delegation.py)

Each pipeline stage gets its own tightly-scoped warrant:

```python
# Ingest warrant: read-only
ingest_warrant = (
    Warrant.mint_builder()
    .holder(ingest_key.public_key)
    .capability("read_file", path=Subpath("/data/source"))
    .capability("list_directory", path=Subpath("/data/source"))
    .ttl(600)
    .mint(control_key)
)

# Transform warrant: write-only
transform_warrant = (
    Warrant.mint_builder()
    .holder(transform_key.public_key)
    .capability("write_file", path=Subpath("/data/output"), content=Pattern("*"))
    .ttl(600)
    .mint(control_key)
)

# Switch warrant between stages
client_interceptor.set_headers(tenuo_headers(ingest_warrant, "ingest"))
data = await client.execute_workflow(IngestWorkflow.run, ...)

client_interceptor.set_headers(tenuo_headers(transform_warrant, "transform"))
await client.execute_workflow(TransformWorkflow.run, ...)
```

---

## Comparison with Other Integrations

| Integration | Use Case | Durable | PoP | Delegation |
|-------------|----------|---------|-----|------------|
| **OpenAI** | Streaming agents | No | Optional | No |
| **LangChain** | Tool chains | No | Optional | Via context |
| **CrewAI** | Multi-agent crews | No | Yes (Tier 2) | Yes |
| **Temporal** | Long-running workflows | Yes | Mandatory | Yes |

Temporal integration is designed for workflows that may run for hours or days, with full replay support and durable state.

---

## More Information

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal)
