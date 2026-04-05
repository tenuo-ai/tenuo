---
title: Temporal Integration
description: Warrant-based authorization for durable workflows
---

# Tenuo Temporal Integration

> **Available in `tenuo[temporal]`**

## Overview

Tenuo integrates with [Temporal](https://temporal.io) to bring warrant-based authorization to durable workflows. Activities are transparently authorized against the workflow's warrant without code changes to your activity definitions.

**Key Features:**
- **Activity-level authorization**: Each activity execution is authorized against warrant constraints
- **Proof-of-Possession (PoP)**: Ed25519 signature verification for every warranted activity (requires `trusted_roots` on the worker config)
- **Warrant propagation**: Warrants flow through workflow headers automatically
- **Child workflow delegation**: Attenuate warrants when spawning child workflows via `tenuo_execute_child_workflow()`
- **Delegation chain verification**: Full chain-of-trust validation back to trusted roots
- **Signal & update guards**: Restrict which signals and updates a workflow accepts
- **Nexus header propagation**: Warrant context flows through Nexus operations
- **PoP replay protection**: Default in-process dedup plus PoP time-window verification (clock skew); optional **`PopDedupStore`** for fleet-wide dedup ([Security considerations](#security-considerations))
- **Continue-as-new support**: Warrant headers survive workflow continuation
- **Fail-closed**: Missing or invalid warrants block execution by default
- **Secure key management**: Private keys NEVER transmitted in headers - resolved from Vault/KMS/Secret Manager
- **Enterprise key resolvers**: `VaultKeyResolver`, `AWSSecretsManagerKeyResolver`, `GCPSecretManagerKeyResolver`, `CompositeKeyResolver`

Temporal ensures your workflows survive failures. Tenuo ensures every activity your workflow dispatches is authorized against the warrant the issuer approved. Together they give you durable execution with cryptographic least privilege.

---

## Installation

```bash
uv pip install "tenuo[temporal]"
```

Requires Temporal server running locally or in production.

---

## Onboarding checklist

Follow this order the first time you integrate Tenuo with Temporal. The **Quick Start** and **Configuration** sections below go deeper; the [`tenuo.temporal`](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-python/tenuo/temporal.py) module docstring has a **Troubleshooting** table for common failures.

1. **Install**: `uv pip install "tenuo[temporal]"` (see [Installation](#installation)). You need the **`tenuo_core` native extension** (PyO3). If prebuilt wheels are missing for your platform, build from the repo with `maturin develop` in `tenuo-python`.

2. **Temporal server**: Run a dev server (e.g. `temporal server start-dev`). See [examples/temporal README](../tenuo-python/examples/temporal/README.md).

3. **Keys for PoP**: Create issuer (`control_key`) and holder (`agent_key`) `SigningKey` values. Expose the holder key to the worker via a `KeyResolver` (development: `EnvKeyResolver` + `TENUO_KEY_<key_id>`: see [Development: Environment Variables](#development-environment-variables)).

4. **Mint a warrant**: Use `Warrant.mint_builder()` (or `Warrant.issue`) so capabilities match your activity names and argument constraints (e.g. `path=Subpath(...)`). In production, warrants are typically minted by Tenuo Cloud on behalf of your workflows, separating authorization policy from application code and giving your security team control over what gets issued without touching workflow definitions.

5. **Worker config**: `Worker(..., interceptors=[TenuoPlugin(TenuoPluginConfig(...))])` with:
   - `key_resolver`: resolves `key_id` from headers to the holder signing key
   - `trusted_roots`: **required** (e.g. `[control_key.public_key]`, or set `tenuo.configure(trusted_roots=[...])` before constructing the config)
   - `activity_fns`: **required when** the warrant uses **named field constraints** and you call `workflow.execute_activity()` without a reliable activity function reference; use the **same** callables as `Worker(activities=[...])`
   - `strict_mode=True`: recommended when using named constraints with transparent `execute_activity` (fail-fast instead of only logging)

6. **Workflow sandbox passthrough (required)**: Use `SandboxedWorkflowRunner` with `SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")`. Omitting this causes `ImportError: PyO3 modules may only be initialized once...`.

7. **Client**: Attach `TenuoClientInterceptor` to `Client.connect(..., interceptors=[...])`. Ensure headers are bound before start: **`execute_workflow_authorized(...)`** (recommended for concurrent clients) **or** `set_headers_for_workflow(workflow_id, tenuo_headers(warrant, key_id))` then `execute_workflow`.

8. **Run the sample**: From the repo: `cd tenuo-python/examples/temporal && python demo.py` (Temporal in another terminal). Then try `multi_warrant.py` and `delegation.py`.

9. **Verify with tests**: Without a Temporal server: `cd tenuo-python && pytest tests/e2e/test_temporal_e2e.py`. With the in-process Temporal test server (CI-style): `pytest tests/e2e/test_temporal_live.py tests/e2e/test_temporal_replay.py -m temporal_live` (see the `temporal-integration` job in `.github/workflows/ci.yml`).

---

## Quick Start

### Basic Workflow Protection

> **Development quick start:** this example uses `EnvKeyResolver`, which reads signing keys from environment variables. It requires no external services and is the fastest way to get running locally. For production, swap in `VaultKeyResolver`, `AWSSecretsManagerKeyResolver`, or `GCPSecretManagerKeyResolver`. See [Key Management](#key-management-required).

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
    TenuoPlugin,
    TenuoPluginConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    execute_workflow_authorized,
    tenuo_headers,
)

# Define protected activities (no Tenuo-specific code needed)
@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()

@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"

# Define workflow  -- use AuthorizedWorkflow for automatic PoP calculation
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
    # Generate issuer (control) key and holder (agent) key
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # EnvKeyResolver reads TENUO_KEY_<key_id> from environment.
    # Register the agent key before starting the worker:
    import os, base64
    os.environ["TENUO_KEY_agent-key-1"] = base64.b64encode(bytes(agent_key.to_bytes())).decode()

    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])

    # Issue warrant using the builder API
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/data/input"))
        .capability("write_file", path=Subpath("/data/output"))
        .ttl(3600)
        .mint(control_key)
    )
    # In production, warrants are typically minted by Tenuo Cloud on behalf of your
    # workflows: scoped to the specific task, delegated to the correct holder key,
    # and managed without embedding issuance logic in application code. This separates
    # authorization policy from application code and gives your security team
    # visibility and control over what gets issued.

    # Configure worker interceptor with full PoP verification
    interceptor = TenuoPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            trusted_roots=[control_key.public_key],  # required: Authorizer + PoP
            strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
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
        result = await execute_workflow_authorized(
            client=client,
            client_interceptor=client_interceptor,
            workflow_run_fn=DataProcessingWorkflow.run,
            workflow_id="process-001",
            warrant=warrant,
            key_id="agent-key-1",
            args=["/data/input/report.txt", "/data/output/report.txt"],
            task_queue="data-processing",
        )
```

> **Security:** Private keys are **NEVER** transmitted in headers. Only the `key_id` is sent. Workers use `KeyResolver` to fetch the actual signing key from secure storage (Vault, AWS Secrets Manager, GCP Secret Manager, etc.).

**What happens:**
1. `TenuoClientInterceptor` injects warrant + key_id into workflow headers (NO private key)
2. Workflow inbound interceptor extracts Tenuo headers and propagates them to activities
3. Each activity call triggers `KeyResolver.resolve(key_id)` to fetch the signing key from secure storage
4. PoP signature is computed locally on the worker using the resolved key
5. Activity inbound interceptor verifies warrant, PoP, and constraints
6. Activity executes only if all checks pass

This works in both single-process demos and distributed deployments where client and worker run in separate processes.

> **Required passthrough modules:** `tenuo` and `tenuo_core` must be configured as passthrough modules in Temporal's workflow sandbox. Without this, the worker starts and connects normally but **every workflow execution fails on its first task**. No activities are ever scheduled. The worker continues polling and appears healthy from the outside; the failure only appears as workflow task errors in Temporal Web.
>
> Error you will see in Temporal Web:
>
> ```
> ImportError: PyO3 modules may only be initialized once per interpreter process
> ```
>
> **Why this is necessary:** Unlike OTel's `TracingInterceptor` (pure Python), Tenuo computes the Proof-of-Possession signature *inside the workflow sandbox* at `execute_activity()` dispatch time. This commits the exact tool name and arguments the workflow authorised; moving signing outside the sandbox would eliminate this guarantee. `tenuo_core` is a PyO3 Rust extension that cannot be re-imported in a sub-interpreter, so both modules must be declared passthrough. See [Sandbox passthrough explained](#sandbox-passthrough-explained) for the full failure sequence and diagnostic steps.

---

## API Ergonomics

Use one of these patterns based on your needs:

### Recommended (default): `execute_workflow_authorized(...)`

The safest way to start authorized workflows. Binds headers to a specific workflow ID and executes immediately.

```python
result = await execute_workflow_authorized(
    client=client,
    client_interceptor=client_interceptor,
    workflow_run_fn=DataProcessingWorkflow.run,
    workflow_id="process-001",
    warrant=warrant,
    key_id="agent-key-1",
    args=["/data/input/report.txt", "/data/output/report.txt"],
    task_queue="data-processing",
)
```

### Advanced: `set_headers_for_workflow(...)` + `client.execute_workflow(...)`

Use this when you need manual control over start timing or custom wrappers.

```python
client_interceptor.set_headers_for_workflow(
    "process-001",
    tenuo_headers(warrant, "agent-key-1"),
)
result = await client.execute_workflow(
    DataProcessingWorkflow.run,
    id="process-001",
    args=["/data/input/report.txt", "/data/output/report.txt"],
    task_queue="data-processing",
)
```

### Deprecated: `set_headers(...)`

`set_headers(...)` remains for backward compatibility but is deprecated for concurrent usage. Prefer workflow-ID-bound APIs.

---

## Cross-Process Contract

For distributed deployments (separate client and worker processes), the integration contract is:

| Component | Responsibility | Required |
|-----------|----------------|----------|
| Client | Start workflows with Tenuo headers (`execute_workflow_authorized` or `set_headers_for_workflow`) | Yes |
| Workflow worker | Register `TenuoPlugin` and passthrough modules (`tenuo`, `tenuo_core`) | Yes |
| Activity worker | Receive propagated headers and enforce PoP/constraints | Yes |
| Key management | Resolve `key_id` to signing key using `KeyResolver` | Yes |
| Trusted roots | Provide `trusted_roots` (or global `configure(trusted_roots=...)`); optional `strict_mode=True` for PoP signing strictness | Yes |
| `activity_fns` | Same callables as `Worker(activities=...)` when warrants use **named** field constraints and you use transparent `execute_activity` | When applicable (see below) |

If any required part is missing, execution fails closed.

---

## Activity registry (`activity_fns`) and PoP argument names

### Why this matters

Each activity call gets a **Proof-of-Possession (PoP)** signature over a canonical payload that includes the **tool name** and a **sorted argument dictionary**. Warrant field constraints (for example `path=Subpath("/data")` on `read_file`) are checked against that same dictionary. The keys in the dict must therefore match the **Python parameter names** of the activity (e.g. `path`), not generic placeholders.

When your workflow calls `workflow.execute_activity(...)`, the outbound interceptor must build `args_dict` from the activity’s positional `args` tuple. It does that by resolving the **activity function** and using `inspect.signature` to map positions to names.

### Resolution order (function reference)

The worker resolves the callable in this order:

1. **`input.fn`**: supplied by the Temporal Python SDK on some versions/paths when using the real `execute_activity` pipeline.
2. **`tenuo_execute_activity(...)`**: Tenuo records the function reference for that call.
3. **`TenuoPluginConfig.activity_fns`**: explicit registry: activity type name (e.g. `read_file`) → the same function object you registered on the worker.
4. **Fallback:** `arg0`, `arg1`, …: used only when (1)–(3) are all unavailable.

Step (4) is **correct** when the warrant only allows the tool **without** per-field constraints (signing and verification both use `arg0`, …). Step (4) is **wrong** when the warrant has **named** constraints: verification expects `path`, but signing used `arg0`, so PoP/constraint checks **do not line up** with the warrant.

### What Tenuo does at runtime

If the interceptor would sign with **only** `arg0`/`arg1`/… **and** the warrant has **non-empty field constraints** for that activity type, the worker:

- Logs a **warning** (default), telling you to set `activity_fns` or use `tenuo_execute_activity`.
- Raises **`TenuoContextError`** (fail-fast) when **`strict_mode=True`** on `TenuoPluginConfig`, so misconfigured production workers fail immediately instead of issuing bad PoP material.

### What you should configure

| Warrant shape | Transparent `execute_activity` | Recommendation |
|---------------|-------------------------------|----------------|
| Tool-only (`capability("echo")` with no fields) | Yes | `activity_fns` optional; `arg0` fallback is consistent. |
| Named fields (`capability("read_file", path=...)`) | Yes | Set **`activity_fns`** to the **same** list as `Worker(activities=...)`, unless you have verified `input.fn` is always set in your SDK version. |
| Named fields | Using **`tenuo_execute_activity`** | Registry not required for that call path; function reference is recorded. |

### Example (`activity_fns` aligned with the worker)

```python
from temporalio.worker import Worker
from tenuo.temporal import TenuoPlugin, TenuoPluginConfig, EnvKeyResolver

activities = [read_file, write_file]

interceptor = TenuoPlugin(
    TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[control_key.public_key],
        strict_mode=True,
        activity_fns=activities,  # same objects as Worker(activities=...)
    )
)

async with Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=activities,
    interceptors=[interceptor],
    workflow_runner=...,
):
    ...
```

For full narrative and troubleshooting text, see the module docstring in `tenuo.temporal` (**Activity registry (`activity_fns`) and PoP argument names** and **Troubleshooting**).

---

## Configuration

### Key Management (REQUIRED)

**Security Requirement:** Tenuo NEVER transmits private keys in headers. Workers must be configured with a `KeyResolver` to fetch signing keys from secure storage.

#### Production: Vault

```python
from tenuo.temporal import VaultKeyResolver, TenuoPluginConfig

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    path_template="production/tenuo/{key_id}",  # e.g., "production/tenuo/agent-2024"
    token=None,  # Uses VAULT_TOKEN env var
    mount="secret",  # KV secrets engine mount
    cache_ttl=300,  # Cache keys for 5 minutes
)

config = TenuoPluginConfig(
    key_resolver=resolver,  # REQUIRED
    trusted_roots=[root_key.public_key],
    strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
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

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
)
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

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
)
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

# DEVELOPMENT ONLY - DO NOT USE IN PRODUCTION
# A WARNING is emitted at first key resolution unless TENUO_ENV=development.
resolver = EnvKeyResolver(
    prefix="TENUO_KEY_",
    warn_in_production=True,  # Default; set False to suppress explicitly
)

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],  # required (or call tenuo.configure(trusted_roots=[...]) first)
    # strict_mode: optional: set True if you use named warrant constraints with transparent execute_activity
)
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

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
)
```

> **Tenuo Cloud alternative:** If you prefer not to operate your own KMS or Vault deployment, Tenuo Cloud provides managed key issuance and rotation. Signing keys are created, scoped, and rotated in the Cloud dashboard; workers resolve them without any additional key infrastructure on your side.

### Worker plugin config (`TenuoPluginConfig`)

```python
from tenuo.temporal import TenuoPluginConfig

config = TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),        # Required: key resolution strategy
    on_denial="raise",                    # "raise" | "log" | "skip"
    dry_run=False,                        # Shadow mode only; never for production
    trusted_roots=[control_key.public_key],  # Enables Authorizer + PoP verification
    strict_mode=True,                     # Fail-fast on ambiguous PoP when using named constraints
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

> **Production hardening:** Every Temporal worker must supply `trusted_roots` (or set them once via `tenuo.configure(trusted_roots=[...])`). Without them, `TenuoPluginConfig` raises `ConfigurationError` at construction time. Use `strict_mode=True` to fail fast when PoP signing would use positional args while the warrant has named field constraints.

### Denial Handling

Control what happens when authorization fails:

```python
# "raise" (default): raise TemporalConstraintViolation
# "log":             log denial and block (return None)
# "skip":            silently block (return None)
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    on_denial="raise",
)
```

### Dry run (staging only, not production)

Use `dry_run=True` to run in shadow mode while you validate policies. In this mode,
authorization denials are recorded (audit/log), but activities are still executed.

```python
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    dry_run=True,   # shadow mode for rollout validation only
    on_denial="raise",  # ignored for authorization denials while dry_run=True
)
```

> **Warning:** `dry_run=True` disables enforcement for authorization denials. Use only in non-production environments.


---

## Sandbox passthrough explained

Temporal's Python SDK re-imports all workflow code in an isolated sandbox on every worker task to enforce replay determinism. Modules declared as **passthrough** are shared from the host process instead of being re-imported.

**Why Tenuo needs it:** Tenuo signs the Proof-of-Possession challenge inside the workflow sandbox at `execute_activity()` dispatch time, committing the exact tool and arguments the workflow authorised, using the deterministic `workflow.now()` clock. This lets the activity worker detect argument tampering in transit. Because this signing uses `tenuo_core` (a PyO3 Rust extension), and PyO3 cannot be re-initialised in a sub-interpreter, both modules must be declared passthrough.

**If you omit the passthrough**, the failure is not at startup. The worker connects and polls normally:

| Step | Result |
|------|--------|
| Worker starts and connects | ✅ No error |
| First workflow task executes | ❌ `ImportError: PyO3 modules may only be initialized once per interpreter process` |
| Subsequent workflow tasks | All fail identically |
| Activities | Never scheduled: workflow tasks fail before `execute_activity()` is reached |

The worker **appears healthy** from monitoring while workflow executions are silently dead. Diagnose via Temporal Web → find the workflow → look for repeated `WorkflowTaskFailed` events.

---

## Compatibility

| Component | Supported | Notes |
|-----------|-----------|-------|
| Temporal Python SDK | `temporalio>=1.4.0` | Tested in CI with live Temporal integration job |
| Python | 3.9 - 3.14 | Full matrix in CI; Temporal live tests run on Python 3.12 |
| Runtime mode | Single-process and distributed client/worker | Both supported |

Feature availability may depend on SDK surface area. Core activity/workflow authorization and child-workflow delegation are primary supported paths.

---

## Proof-of-Possession

With `trusted_roots` in place (required for workers), Tenuo enforces PoP verification for all activity executions that carry a warrant. The challenge is a CBOR-serialized tuple of `(warrant_id, tool, sorted_args, window_ts)` signed with the holder's Ed25519 key.

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
from datetime import timedelta
from temporalio.common import RetryPolicy
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

Both automatically sign PoP challenges; you never need to call `warrant.sign()` directly in Temporal workflows.

### PoP Challenge Format

The PoP signature is computed deterministically by the Rust core:

```
domain_context = b"tenuo-pop-v1"
window_ts      = (unix_now // 30) * 30          # 30-second bucket
challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
preimage       = domain_context || challenge_data
signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes
```

In Python, this is a single call. Only needed for custom tooling outside of Temporal; `tenuo_execute_activity()` handles it automatically inside workflows:

```python
import time
pop_signature = warrant.sign(signing_key, "read_file", {"path": "/data/file.txt"}, int(time.time()))
# Returns 64 raw bytes; verifier accepts multiple 30s-aligned windows (default: 5 windows, ~±60s skew band)
```


---

## Security considerations

This section covers what the Temporal integration assumes, what it protects against, and what remains your operational responsibility. For the broader Tenuo security model, see [Security Model](./security.md).

**Temporal's security vs. Tenuo's security.** Temporal Cloud provides infrastructure-level security: encrypted payloads, RBAC, namespace isolation, SOC 2. Tenuo operates at the authorization layer above that: each Activity is authorized against a cryptographically signed warrant before it executes, regardless of who has access to the Temporal cluster. The two are complementary: cluster access control and per-action authorization are different security properties. A Temporal namespace admin with full cluster access still cannot cause an activity to execute outside the warrant's constraints, because Tenuo's authorization check happens on the worker, not on the Temporal service.

**In-process enforcement (no runtime service dependency).** Tenuo's authorization runs entirely within your worker process using `tenuo_core`, a compiled Rust library. There is no Tenuo SaaS call, no external auth service, no network round-trip at enforcement time. The warrant is verified cryptographically in-process using Ed25519 (FIPS 186-4 compatible). This means Tenuo adds no external dependency to your critical path. If Tenuo's distribution infrastructure is unreachable, workers already running with the compiled extension continue enforcing authorization normally.

**Private key data residency.** Private signing keys never leave your infrastructure. `KeyResolver` fetches them from your Vault, AWS Secrets Manager, or GCP Secret Manager on your own network at signing time. No private key material is transmitted to the Temporal cluster or any Tenuo endpoint.

### Trust boundaries

| Component | Role in this integration |
|-----------|---------------------------|
| **Issuer / control plane** | Mints warrants and defines capabilities. Its public keys are configured as **`trusted_roots`** (or via **`trusted_roots_provider`**) on workers. Compromise here affects all downstream authorization. |
| **Temporal service** | Schedules workflow and activity tasks and carries headers. Tenuo assumes Temporal is operated with appropriate **access control** (namespaces, mTLS, etc.). This integration does not replace Temporal’s own security posture. |
| **Workflow workers** | Run workflow code in a sandbox; outbound interceptors sign PoP using keys resolved via **`KeyResolver`**. Compromise of a worker process that can resolve holder keys allows PoP for those keys. |
| **Activity workers** | Verify warrants, PoP, and constraints before running activities. Must have **`trusted_roots`** (or dynamic provider) aligned with who is allowed to mint warrants. |
| **Clients** | Attach warrant headers when starting workflows (`execute_workflow_authorized`, `set_headers_for_workflow`, etc.). Compromise of the client or its stored warrants allows starting workflows the issuer already permitted. |

**Private keys:** Holder signing keys are **not** sent in headers; only **`key_id`** and warrant material. Workers load private keys through **`KeyResolver`** (Vault, cloud secret managers, env for dev).

### Threat model: protections we intend to provide

These are the main abuse cases the integration is designed to address:

1. **Activity execution without a valid warrant**: Default **`require_warrant=True`** denies activities that lack Tenuo headers (unless you explicitly opt out).
2. **Forged or tampered warrant bytes**: Warrants are parsed and validated in **`tenuo_core`**; chain validation ties delegated warrants back to **trusted roots**.
3. **Execution with a warrant but without holder PoP**: **PoP** binds the activity tool name and canonical argument map to the warrant holder’s key; missing or wrong signatures fail verification.
4. **Arguments outside warrant constraints**: Field constraints (e.g. **`Subpath`**) are enforced against the same argument map used for PoP.
5. **Over-broad or long-lived credentials**: Use short **TTLs**, **delegation** / **`workflow_grant`** for least privilege, and **`authorized_signals` / `authorized_updates`** to narrow workflow surface area where configured.
6. **Accidental mis-signing (named constraints vs positional args)**: **`strict_mode=True`** fails fast when transparent **`execute_activity`** would produce **`arg0`-style** maps that cannot satisfy named warrant constraints (see [Activity registry](#activity-registry-activity_fns-and-pop-argument-names)).

### Threat model: clock skew and PoP time windows

Verification does **not** depend on a single instant match. The **`Authorizer`** in **`tenuo_core`** checks PoP using **multiple aligned time windows** around the **verifier’s** clock (bidirectional skew tolerance). When the Temporal worker constructs **`Authorizer(trusted_roots=...)`** without extra arguments, defaults are:

- **`pop_window_secs=30`**, **`pop_max_windows=5`**: on the order of **±60 seconds** of effective skew tolerance for typical defaults (wider windows increase both skew tolerance and **replay opportunity**).
- **`clock_tolerance_secs=30`**: applied to **warrant lifetime / expiry** semantics, separate from PoP window bucketing.

Workflow-side signing uses **deterministic** timestamps where required for **Temporal replay**; workers still verify against **their** wall clock in these windows. See also [PoP Replay Protection](#pop-replay-protection) and [Proof-of-Possession](#proof-of-possession).

### Threat model: replay and horizontal workers

Two layers matter:

1. **Cryptographic validity**: A PoP signature is only valid within the **PoP window configuration** above; it is not a one-time nonce at the crypto layer.
2. **Dedup**: After a successful verify, the activity interceptor records a **dedup key** (warrant facet + workflow id + run id + activity id) for **`attempt <= 1`** to catch **reuse within the warrant’s dedup TTL**. Temporal retries with **`attempt > 1`** intentionally **skip** dedup.

The default dedup backend is **in-memory per process** (`InMemoryPopDedupStore`). It does **not** synchronize across pods; another replica may accept the same logical first attempt if both see it. For fleet-wide replay suppression, implement **`PopDedupStore`** (e.g. Redis **`SET NX`** with TTL aligned to dedup policy) and set **`TenuoPluginConfig.pop_dedup_store`**.

### Threat model: trusted root rotation

Static **`trusted_roots`** require a **rolling restart** (or redeploy) to pick up new issuer keys. For rotation without full restarts, use **`trusted_roots_provider`** plus **`trusted_roots_refresh_interval_secs`**. During rotation, the provider should return **overlapping** old and new issuer public keys so in-flight warrants still verify. On refresh failure, the worker **retains the previous `Authorizer`** and logs a warning (fail-safe vs blast-radius trade-off).

### Threat model: out of scope or requires broader controls

- **Compromised Temporal service or namespace admin** scheduling arbitrary tasks: address with Temporal security, not Tenuo alone. Note: the `activity_id` included in PoP dedup keys is *not* part of the signed PoP CBOR challenge (which only covers `warrant_id`, `tool`, `sorted_args`, and `window_ts`). An attacker with direct gRPC access to the Temporal server could randomize `activity_id` to bypass per-key dedup and replay a captured PoP within the time window. This requires bypassing Temporal’s own mTLS and RBAC. Treat Temporal as a trusted boundary and enforce standard cluster access hardening. Dedup is defense-in-depth within that boundary, not a primary control against crafted tasks.
- **Compromised worker host** with access to **`KeyResolver`** secrets: can sign valid PoP for those keys; use HSM/KMS, minimal identity, and hardening as for any secret-bearing workload.
- **Malicious workflow code** in your repository: Tenuo constrains what **activities** run under a warrant; it does not sandbox arbitrary Python in your own workflow logic beyond Temporal’s sandbox rules.
- **`dry_run=True`**: **Disables enforcement** for staging only; never use in production.
- **Local activities**: Bypass the activity interceptor unless the function is marked **[`@unprotected`](#unprotected---local-activities)** (which declares explicitly that no warrant is required for that activity) and **`block_local_activities`** allows the path you intend.

### Temporal activity retries and PoP time-drift

**Key consideration for workflows with long retry windows.**

PoP is signed at `workflow.now()` when the activity is first scheduled. When Temporal retries an activity, it reuses headers from the original `ACTIVITY_TASK_SCHEDULED` history event; the workflow outbound interceptor is **not** re-invoked. With the default `pop_max_windows=5` and `pop_window_secs=30`, the effective verification window is ±60 seconds. An activity retried more than ~90 seconds after its first scheduling will fail PoP verification.

Intentional fail-closed behaviour: the PoP window ensures replayed signatures cannot be accepted indefinitely. The trade-off: workflows with `RetryPolicy(maximum_attempts=10)` and multi-minute backoffs will hit this limit.

**Solutions by use case:**

| Retry pattern | Recommended approach |
|---------------|---------------------|
| Short retries (< 60s backoff) | Default config works: no action needed |
| Long retries (minutes to hours) | Set `TenuoPluginConfig.retry_pop_max_windows` (e.g. `120` for up to 1 hour) |
| Unbounded retries / very long backoffs | Structure as child workflows so each retry dispatch generates a fresh PoP |
| **Durable workflows (hours/days)** | **Warrant TTL = workflow duration + `retry_pop_max_windows` = max backoff interval only + control plane auto-revocation on completion** |

```python
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    retry_pop_max_windows=120,   # 120 × 30s = 3600s: covers up to 1 hour of retries
)
```

When `retry_pop_max_windows` is not set and a retry arrives, the interceptor logs a `DEBUG` advisory:
```
Activity '...' is a retry (attempt=2). If this fails with PopVerificationError,
set TenuoPluginConfig.retry_pop_max_windows to accommodate Temporal's retry time offset.
```

**For truly durable workflows (hours or days), use warrant TTL as the primary time boundary.** The PoP time-window is a short-term replay guard; for long-running pipelines the correct security scope is the warrant lifetime:

1. Mint a warrant whose TTL matches the expected workflow duration (e.g. `.ttl(14400)` for a 4-hour pipeline).
2. Set `retry_pop_max_windows` large enough to cover only the **maximum Temporal retry backoff interval**, not the total run duration. If max backoff is 10 minutes, `retry_pop_max_windows=20`. The PoP being hours old is fine because the warrant's expiry is the meaningful time boundary.
3. **Auto-revoke on completion** via the control plane: when the workflow finishes (success or failure), remove the issuer key from the `trusted_roots_provider` output. Within one refresh interval (~30–60s), the Authorizer on every worker rejects all warrants from that issuer, even if the warrant's TTL has not elapsed yet. This closes the window where a captured credential could be replayed against a workflow that already completed.

This three-part pattern (long-lived warrant, interval-only retry window, control-plane revocation) is the production-grade model for durable agentic workflows. It keeps the security guarantee on the warrant's authorization scope while removing the operational friction of managing PoP timing across multi-hour executions.

### Access revocation and incident response

When a warrant or signing key is suspected compromised, the revocation path does not require a full redeployment:

| Mechanism | Latency | How |
|-----------|---------|-----|
| **Warrant TTL expiry** | Passive: warrant stops being accepted at expiry | Mint short-lived warrants (minutes for sensitive operations, hours for low-risk) |
| **Remove trusted root** | Next `trusted_roots_provider` refresh interval (e.g. 30–60s) | Remove the compromised issuer key from the provider's output; all warrants issued by that root are rejected on the next Authorizer rebuild: no worker restart |
| **Revoke holder key** | Immediate on next warrant check | Remove the key from the `KeyResolver` backend; the next `resolve(key_id)` call fails, blocking PoP computation on the outbound interceptor |

For the fastest response, use `trusted_roots_provider` with a short `trusted_roots_refresh_interval_secs` (e.g. 30 seconds). A compromised issuer key can be removed from your key store and propagated to all workers within one refresh interval. No rolling restart needed.

> **Tenuo Cloud** manages trusted root distribution and rotation as a first-class primitive, removing the need to operate your own provider service. When a workflow completes or a credential is revoked, the Cloud control plane pushes the updated root set to all workers automatically.

### Fail-closed defaults (summary)

| Check | Missing / invalid | Default behavior |
|-------|-------------------|------------------|
| Warrant header | Missing | Denied when **`require_warrant=True`** |
| Warrant expired | Expired | **`WarrantExpired`** |
| Tool / constraints | Not allowed or args mismatch | **`TemporalConstraintViolation`** / core constraint errors |
| PoP signature | Missing or invalid | **`PopVerificationError`** |
| Protected activity as local activity | Not **`@unprotected`** | **`LocalActivityError`** |

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

The wrapper calls `attenuated_headers()` internally and injects the attenuated warrant via the outbound workflow interceptor. Temporal's `execute_child_workflow()` does not accept a `headers` kwarg directly.

### Delegation Chain Verification

When warrants are attenuated, the full delegation chain is propagated via the `x-tenuo-warrant-chain` header. The activity interceptor calls `Authorizer.check_chain()` to verify every link in the chain back to a trusted root, ensuring no intermediate warrant was forged or widened.

---

## Signal & Update Authorization

Control which signals and workflow updates are allowed:

```python
config = TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),
    on_denial="raise",
    trusted_roots=[control_key.public_key],
    authorized_signals=["approve", "reject"],     # Only these signals allowed
    authorized_updates=["update_config"],          # Only these updates allowed
)
```

Unrecognized signals raise `TemporalConstraintViolation`. Unrecognized updates are rejected at the validator stage before the handler runs. When set to `None` (default), all signals and updates pass through for backward compatibility.

---

## Nexus Operation Headers

When starting Nexus operations from a Tenuo-protected workflow, the outbound interceptor automatically propagates warrant headers to the Nexus service. Headers are base64-encoded into Nexus's string-based header format.

---

## PoP Replay Protection

The activity interceptor runs **dedup after** PoP verification. The default store is **`InMemoryPopDedupStore`**: a thread-safe, **process-local** map. Each dedup key includes the warrant’s logical facet (via **`dedup_key(tool, args)`**), **`workflow_id`**, **`workflow_run_id`**, and **`activity_id`**. Temporal retries with **`attempt > 1`** bypass dedup so legitimate redelivery is not blocked. The default store evicts periodically (every 60 seconds) and caps size at **10,000** entries.

**Pluggable backend:** Set **`TenuoPluginConfig.pop_dedup_store`** to a shared implementation of **`PopDedupStore`** when you need **fleet-wide** replay suppression (see [Security considerations](#security-considerations)).

> **Distributed deployments:** Without a shared **`PopDedupStore`**, dedup state is **not** replicated across worker pods. Treat that as an explicit trade-off: cryptographic PoP windows still bound signature age, but **duplicate first attempts** on different replicas within the dedup TTL are not suppressed by the default store.

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

By default, `TenuoPlugin` blocks all activities used as local activities unless they are explicitly opted out. Use `@unprotected` to declare that a specific activity intentionally runs without a warrant, typically for internal, non-sensitive operations (config lookups, metrics, logging helpers). Every `@unprotected` activity is a deliberate hole in your authorization perimeter; document the reason at the call site.

```python
from tenuo.temporal import unprotected

@activity.defn
@unprotected
async def get_config_value(key: str) -> str:
    """Internal config lookup: no warrant needed; read-only, non-sensitive."""
    return config[key]

# Can be used as local activity (bypasses worker interceptor)
await workflow.execute_local_activity(
    get_config_value,
    args=["database_url"],
)
```

> Activities not marked `@unprotected` that are called via `workflow.execute_local_activity()` will raise `LocalActivityError` at runtime. Intentional fail-closed behaviour: local activities bypass the inbound interceptor, so Tenuo cannot enforce warrant constraints without this explicit opt-out.

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

> `workflow_grant()` is useful when you need to hand off a scoped credential to a sub-process or external call. Constraint keys in `constraints` must already exist in the parent warrant; introducing new keys raises `TemporalConstraintViolation`.

---

## Audit Events

Every authorization decision emits a structured `TemporalAuditEvent` with full context. This provides the per-action audit trail required by SOC 2 CC6.8 (logging of logical access to systems), PCI DSS Requirement 10.2 (audit trail for privileged access), and HIPAA §164.312(b) (audit controls for PHI access).

Each event captures:
- **Who**: `warrant_id`, `workflow_id`, `workflow_run_id`: identifies the agent and the specific execution
- **What**: `tool`, `arguments` (redacted by default), `warrant_capabilities`: the specific action and scope
- **When**: `timestamp` (UTC)
- **Decision**: `ALLOW` or `DENY`, with `denial_reason` and `constraint_violated` for denials
- **Context**: `workflow_type`, `activity_id`, `task_queue`, `tenuo_version`

```python
from tenuo.temporal import TemporalAuditEvent

def on_audit(event: TemporalAuditEvent):
    # Structured logging: forward to Splunk, Datadog, CloudWatch, etc.
    record = event.to_dict()
    audit_logger.info(record)

    # Or handle allow/deny separately
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

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    audit_callback=on_audit,
    audit_allow=True,   # Log allowed actions (recommended for compliance)
    audit_deny=True,    # Log denied actions
    redact_args_in_logs=True,  # Replace argument values with "[REDACTED]" in logs
)
```

`TemporalAuditEvent.to_dict()` returns a plain dict suitable for structured log ingestion. Set `redact_args_in_logs=True` (default) to prevent argument values from appearing in log pipelines when processing sensitive data.

> **At scale:** Tenuo Cloud indexes receipts across all your workflows and provides a queryable audit trail: which agent invoked which tool, under which warrant, through which delegation chain, at what time. For compliance-sensitive deployments this replaces custom audit log infrastructure and makes it straightforward to answer "what did this agent do last Tuesday?" across an entire fleet.

---

## Observability

### Prometheus Metrics

```python
from tenuo.temporal import TenuoMetrics

metrics = TenuoMetrics(prefix="tenuo_temporal")

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    metrics=metrics,
)

# Exposes metrics at /metrics:
# - tenuo_temporal_activities_authorized_total{tool, workflow_type}
# - tenuo_temporal_activities_denied_total{tool, reason, workflow_type}
# - tenuo_temporal_authorization_latency_seconds_bucket{tool}
```

### Suggested Alerts

For production integration monitoring, alert on:

- sustained increase in `*_activities_denied_total`
- spikes in `POP_VERIFICATION_FAILED` / replay-related denials
- key resolver failures (`KEY_NOT_FOUND`, resolver exceptions)
- sudden drop in authorized activity volume

---

## Security Model

See **[Security considerations](#security-considerations)** for the full threat model, trust boundaries, PoP time windows, dedup semantics, and root rotation. The [Failure Semantics](#failure-semantics-integrator-view) table maps exceptions to integration handling.

---

## Exceptions

All exceptions include `error_code` for wire format compatibility:

```python
from tenuo.temporal import (
    TemporalConstraintViolation,  # error_code: "CONSTRAINT_VIOLATED"
    WarrantExpired,               # error_code: "WARRANT_EXPIRED"
    ChainValidationError,         # error_code: "CHAIN_INVALID"
    PopVerificationError,         # error_code: "POP_VERIFICATION_FAILED"
    LocalActivityError,           # error_code: "LOCAL_ACTIVITY_BLOCKED"
    KeyResolutionError,           # error_code: "KEY_NOT_FOUND"
)
```

## Failure Semantics (Integrator View)

| Failure Type | Where It Surfaces | Typical Exception | Recommended Handling |
|--------------|-------------------|-------------------|----------------------|
| Missing/invalid warrant headers | Activity execution | `TemporalConstraintViolation` / `ChainValidationError` | Treat as non-retryable config/integration error |
| Invalid PoP or replay | Activity execution | `PopVerificationError` | Non-retryable unless request context is regenerated |
| Expired warrant | Activity execution | `WarrantExpired` | Refresh/mint new warrant, then retry |
| Key resolution failure | Activity execution | `KeyResolutionError` | Retry only for transient backend failures |
| Missing `trusted_roots` | Config / worker startup | `ConfigurationError` | Pass `trusted_roots` or call `tenuo.configure(trusted_roots=[...])` |

When `dry_run=True`, these authorization denials are converted to audit/log-only
signals and execution continues. Use this only for staging validation and rollout
analysis, never as a production steady state.

---

## Troubleshooting

For the full module-level troubleshooting entries, see the `tenuo.temporal` module docstring. The table below covers the most common integration errors.

| Error | Cause | Fix |
|-------|-------|-----|
| Worker starts but all workflow tasks fail with `ImportError: PyO3 modules may only be initialized once per interpreter process` | Missing `with_passthrough_modules("tenuo", "tenuo_core")` | Add `SandboxedWorkflowRunner(restrictions=SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core"))` to `Worker`. See [Sandbox passthrough explained](#sandbox-passthrough-explained). |
| `ConfigurationError: TenuoPluginConfig requires trusted_roots` | `TenuoPluginConfig` constructed before `tenuo.configure(trusted_roots=[...])` and no explicit `trusted_roots=` | Pass `trusted_roots=[control_key.public_key]` to `TenuoPluginConfig`, or call `tenuo.configure(trusted_roots=[...])` before constructing the config |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without warrant headers | Use `execute_workflow_authorized(...)` or call `set_headers_for_workflow(workflow_id, tenuo_headers(warrant, key_id))` before `execute_workflow` |
| `KeyResolutionError: Cannot resolve key: <id>` | Signing key not found by `KeyResolver` | For `EnvKeyResolver`: check `TENUO_KEY_<key_id>` is set and is a valid base64-encoded key. For cloud resolvers: check secret name, permissions, and region |
| `TemporalConstraintViolation: No warrant provided` | `TenuoClientInterceptor` not in the client's interceptor list, or headers cleared before workflow start | Verify `client_interceptor` is passed to `Client.connect(interceptors=[...])` and headers are set before the workflow starts |
| `PopVerificationError: replay detected` | Same activity attempt reached multiple workers (in-memory dedup does not span pods) | Expected in multi-replica deployments without a shared `PopDedupStore`. Configure `pop_dedup_store=<redis-backed impl>` on `TenuoPluginConfig` for fleet-wide suppression |
| `PopVerificationError` on a Temporal **retry** (attempt ≥ 2) | PoP timestamp stale: Temporal reuses original `ACTIVITY_TASK_SCHEDULED` headers; outbound interceptor not re-invoked on retry | Set `TenuoPluginConfig.retry_pop_max_windows` (e.g. `120` for 1-hour retry window). See [Temporal activity retries and PoP time-drift](#temporal-activity-retries-and-pop-time-drift) |
| Warning: `PoP signing … positional argument keys (arg0, …)` | Warrant uses named field constraints but the activity function reference is unavailable to the outbound interceptor | Add `activity_fns=[my_activity, ...]` to `TenuoPluginConfig` (same list as `Worker(activities=...)`), or call the activity via `tenuo_execute_activity()` |
| `TenuoContextError` raised instead of the above warning | `strict_mode=True` is set | Same fix as above; `strict_mode` converts the warning into a hard error for production correctness |
| `WarrantExpired` | Warrant TTL elapsed before or during workflow execution | Mint a new warrant with a longer `ttl()`, or refresh the warrant at workflow start |
| Activity denied despite a warrant that looks correct | PoP argument keys or tool name mismatch between signer and verifier | Check worker logs for the outbound interceptor warning about positional vs. named keys; also verify `tool_mappings` if activity type differs from warrant tool name |

---

## Best Practices

1. **Use AuthorizedWorkflow** as your base class for fail-fast validation and automatic PoP
2. **Use `tenuo_execute_activity()`** for cases where you need explicit per-call warrant or key control: multi-warrant workflows, per-stage delegation, or when `AuthorizedWorkflow` is not your base class
3. **Always configure passthrough modules** (`tenuo`, `tenuo_core`) in the workflow sandbox
4. **Set `strict_mode=True`** in production if you use named warrant constraints with transparent `execute_activity` (fail-fast on ambiguous PoP signing)
5. **Set up VaultKeyResolver** (or AWS/GCP) for production key management; never use `EnvKeyResolver` in production. Tenuo Cloud provides managed key issuance and rotation as an alternative to operating your own KMS integration.
6. **Enable audit logging** to track authorization decisions; forward `event.to_dict()` to your SIEM or log aggregator for compliance audit trails
7. **Use [`@unprotected`](#unprotected---local-activities) sparingly**: only for truly internal, non-sensitive operations; every unprotected activity is a hole in your authorization perimeter. Tenuo Cloud's dashboard surfaces unprotected activity volume alongside authorized activity volume, making it straightforward to identify coverage gaps across your workflow fleet without instrumenting each worker individually
8. **Attenuate warrants** for child workflows to enforce least privilege
9. **Keep TTLs short** for sensitive operations (minutes, not hours): short TTLs are your primary access revocation mechanism
10. **Never run `dry_run=True` in production** - use it only for staging rollout validation
11. **Multi-tenant worker fleets**: create one `TenuoPluginConfig` per tenant task queue with that tenant's `trusted_roots`. Each config produces a separate `Authorizer` instance; warrants from one tenant's issuer are cryptographically rejected by another tenant's worker even if both run on the same machine
12. **Use `trusted_roots_provider` + short `trusted_roots_refresh_interval_secs`** (e.g. 30s) in production: enables sub-minute access revocation without rolling restarts when a key or issuer is compromised

---

## Migration Path (from plain Temporal)

1. **Worker hardening**: add `TenuoPlugin` + sandbox passthrough modules.
2. **Start path**: switch workflow start calls to `execute_workflow_authorized(...)`.
3. **Progressive rollout**: enable on one task queue/tenant, then expand.

### Rollback

If needed, you can temporarily route traffic to an unprotected queue while preserving the existing workflow code. Keep this as an operational fallback, not a steady-state mode.

---

## Integration QA Coverage

Current test coverage is split across:

- `tenuo-python/tests/e2e/test_temporal_live.py` and `test_temporal_replay.py`: in-process Temporal test server, serialization/header propagation, delegation, continue-as-new, replay (`pytest -m temporal_live`, as in CI)
- `tenuo-python/tests/e2e/test_temporal_e2e.py`: mocked Temporal infrastructure with real Tenuo objects: outbound/inbound interceptors, PoP, constraints, child headers, Nexus header path

Together these cover protocol-level behavior and worker/client integration without requiring a manually started Temporal cluster for the bulk of the suite.

---

## Examples

| Example | Description |
|---------|-------------|
| [`demo.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/demo.py) | **Recommended starting point.** Includes transparent `workflow.execute_activity()` and `AuthorizedWorkflow` patterns |
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
client_interceptor.set_headers_for_workflow(
    "ingest-run-001",
    tenuo_headers(ingest_warrant, "ingest"),
)
data = await client.execute_workflow(IngestWorkflow.run, id="ingest-run-001", ...)

client_interceptor.set_headers_for_workflow(
    "transform-run-001",
    tenuo_headers(transform_warrant, "transform"),
)
await client.execute_workflow(TransformWorkflow.run, id="transform-run-001", ...)
```

---

## Comparison with Other Integrations

Temporal, Tenuo, and observability tools operate at different layers of an agentic system. None substitutes for the other.

| Layer | What it solves | Provided by |
|-------|----------------|-------------|
| **Execution reliability** | Retries, state persistence, fault tolerance, replay | Temporal |
| **Agent authorization** | What each agent may do, with what arguments, under whose delegation | Tenuo |
| **Observability** | Tracing, evals, audit logs | OpenTelemetry / Braintrust |

Temporal makes agentic workflows durable. Tenuo makes them authorized. This integration enforces both at every activity boundary, without changes to your workflow code.

For reference, Tenuo's authorization model across integrations:

| Integration | Use Case | Durable | PoP | Delegation |
|-------------|----------|---------|-----|------------|
| **OpenAI** | Streaming agents | No | Optional | No |
| **LangChain** | Tool chains | No | Optional | Via context |
| **CrewAI** | Multi-agent crews | No | Yes (Tier 2) | Yes |
| **Temporal** | Long-running workflows | Yes | Mandatory | Yes |

The Temporal integration is the only path where PoP is mandatory: durable workflows have the strongest threat model (history replay, distributed execution, long-lived warrant exposure).

---

## More Information

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal)
