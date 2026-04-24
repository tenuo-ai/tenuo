---
title: Temporal Integration Reference
description: Deep reference for Tenuo's Temporal integration — production config, security model, troubleshooting
---

# Temporal Integration Reference

> This is the deep reference for Tenuo's Temporal integration. For the getting-started guide, see **[Temporal Integration](./temporal.md)**.

---

## Tenuo concepts for Temporal developers

If you're coming from Temporal's RBAC or namespace-based access control, here's the mental model shift:

| Temporal concept | Tenuo equivalent |
|-----------------|------------------|
| Namespace / RBAC ("this service can run activities in namespace X") | **Trusted roots**: issuer public keys whose warrants workers accept (who may grant). |
| Activity type permission | **Warrant capability**: named tool in the signed token; name matches activity type (or `@tool()` mapping). |
| Activity input args | **Constraints**: optional rules in the warrant (e.g. `path=Subpath("/data/")`). Args outside them are denied before the activity runs. |
| "I am in namespace X, so I can run activity Y" | **Warrant holder**: the key pair allowed to hold this warrant; only it can sign PoP for dispatches. |

**Two keys, two roles:**

```
Issuer (control_key)                Holder (agent_key)
────────────────────                ─────────────────
Owned by: authorization team        Owned by: worker / CI / agent process
Lives in: Vault, KMS, CI secret,    Lives in: worker's KeyResolver (Vault, etc.)
          or Tenuo Cloud
Used to: mint warrants               Used to: sign PoP on each activity dispatch
If compromised: rotate trusted root  If compromised: rotate key_id + re-issue warrant
```

The issuer key never touches the worker. The holder key never leaves the worker. Headers carry only the holder `key_id` and warrant material, not private keys.

---

## Path to production

Checklist for moving past local demos (each item stands alone; links go deeper):

1. **Issuer vs holder keys** — Issuer (`control_key`) only mints warrants; the holder key is resolved on the worker via a production [`KeyResolver`](#key-management-required) (Vault, AWS Secrets Manager, or GCP Secret Manager), not [`EnvKeyResolver`](#development-environment-variables).
2. **Preload if you still use env keys in lower envs** — Call [`preload_keys`](#development-environment-variables) with every holder `key_id` **before** `Worker(...)`, because PoP signing runs in the workflow sandbox where `os.environ` is unavailable for non-determinism reasons.
3. **Sandbox passthrough** — `TenuoTemporalPlugin` handles this automatically. If using `TenuoWorkerInterceptor` manually, you must set `SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")` so PyO3 can load once; without it, workflow tasks fail with `ImportError: PyO3 modules may only be initialized once...` ([details](#sandbox-passthrough-explained)).
4. **Named argument constraints** — If the warrant constrains fields like `path=` or `bucket=`, set [`activity_fns`](#activity-registry-activity_fns-and-pop-argument-names) to the **same** callables as `Worker(activities=[...])`, or use `tenuo_execute_activity()`, so PoP can name arguments correctly.
5. **Starting workflows under concurrency** — Prefer `execute_workflow_authorized(...)` so Tenuo headers are bound to `workflow_id` and are not mixed across parallel starts.
6. **Authorized child workflows** — Use only `tenuo_execute_child_workflow()`; the stock `workflow.execute_child_workflow()` does not propagate warrant headers.
7. **Replicas and PoP replay** — If more than one worker replica can observe the same first activity attempt, use a shared [`PopDedupStore`](#pop-replay-protection); if Temporal retries span longer than your PoP time window, tune [`retry_pop_max_windows`](#temporal-activity-retries-and-pop-time-drift).
8. **Issuer rotation without full redeploy** — Use a [`trusted_roots_provider`](#trusted-root-rotation) with a short refresh interval so new issuer keys propagate quickly.

---

## Package layout

All documented symbols can be imported from the top-level package (`from tenuo.temporal import X`). The package uses lazy loading so only the symbols you reference are imported. For direct imports in library or internal code, the canonical submodule homes are:

| Submodule | Key symbols |
|-----------|------------|
| `tenuo.temporal._config` | `TenuoPluginConfig` |
| `tenuo.temporal._resolvers` | `KeyResolver`, `EnvKeyResolver`, `VaultKeyResolver`, `AWSSecretsManagerKeyResolver`, `GCPSecretManagerKeyResolver`, `CompositeKeyResolver` |
| `tenuo.temporal._headers` | `tenuo_headers` |
| `tenuo.temporal._workflow` | `execute_workflow_authorized`, `start_workflow_authorized`, `tenuo_execute_activity`, `tenuo_execute_child_workflow`, `AuthorizedWorkflow`, `current_warrant`, `current_key_id`, `workflow_grant`, `set_activity_approvals` |
| `tenuo.temporal._client` | `TenuoClientInterceptor`, `TenuoWarrantContextPropagator`, `tenuo_warrant_context` |
| `tenuo.temporal._interceptors` | `TenuoWorkerInterceptor` |
| `tenuo.temporal._dedup` | `PopDedupStore`, `InMemoryPopDedupStore` |
| `tenuo.temporal._decorators` | `tool`, `unprotected` |
| `tenuo.temporal._observability` | `TemporalAuditEvent`, `TenuoMetrics` |
| `tenuo.temporal._constants` | `TENUO_WARRANT_HEADER`, `TENUO_KEY_ID_HEADER`, `TENUO_POP_HEADER`, `TENUO_COMPRESSED_HEADER` |
| `tenuo.temporal.exceptions` | `TenuoContextError`, `PopVerificationError`, `TemporalConstraintViolation`, `WarrantExpired`, `ChainValidationError`, `LocalActivityError`, `KeyResolutionError` |
| `tenuo.temporal_plugin` | `TenuoTemporalPlugin` |

---

## `TenuoWorkerInterceptor` (manual setup)

> Renamed from `TenuoPlugin` to `TenuoWorkerInterceptor`. The old name is still importable from `tenuo.temporal` but emits a `DeprecationWarning` — it was a Temporal SDK `WorkerInterceptor`, not a Temporal SDK `Plugin`, and the resemblance to `TenuoTemporalPlugin` (the recommended entry point; see [docs/temporal.md](./temporal.md)) caused real misconfiguration.

For cases where you need manual control over interceptors and the sandbox runner (instead of `TenuoTemporalPlugin`):

```python
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions
from tenuo import SigningKey
from tenuo.temporal import (
    TenuoWorkerInterceptor,
    TenuoPluginConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    TENUO_TEMPORAL_ACTIVITIES,
)

control = SigningKey.generate()

client_interceptor = TenuoClientInterceptor()
client = await Client.connect("localhost:7233", interceptors=[client_interceptor])

config = TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),
    trusted_roots=[control.public_key],
)

# Pass the same task_queue the Worker uses; the interceptor self-registers
# this config under that queue so workflow_grant / tenuo_execute_child_workflow
# can find the right key resolver when minting attenuated warrants.
worker_interceptor = TenuoWorkerInterceptor(config, task_queue="q")

sandbox_runner = SandboxedWorkflowRunner(
    restrictions=SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")
)
worker = Worker(
    client,
    task_queue="q",
    workflows=[...],
    # TENUO_TEMPORAL_ACTIVITIES is required — the plugin path injects it
    # automatically, manual setups must splat it in by hand. Without it,
    # workflow_grant() and tenuo_execute_child_workflow(constraints=...)
    # have no mint activity to dispatch against and fail at runtime.
    activities=[*my_activities, *TENUO_TEMPORAL_ACTIVITIES],
    interceptors=[worker_interceptor],
    workflow_runner=sandbox_runner,
)
```

> **`task_queue=` is required for delegation.** If you omit it, basic
> authorization (activity PoP, constraint matching) still works, but
> calls to `workflow_grant()`, `tenuo_execute_child_workflow(constraints=...)`,
> or `delegate_warrant()` will fail with a `TenuoContextError` the first
> time a workflow tries to mint an attenuated warrant. The error message
> names the remediation exactly — either pass `task_queue=` to the
> interceptor (as above) or call `register_worker_config(config,
> task_queue="q")` before `Worker(...)` starts. The plugin path
> (`TenuoTemporalPlugin`) handles this automatically; the kwarg only
> matters here.
>
> If you need to construct the interceptor before knowing the queue
> (dynamic worker orchestration, test harnesses), use the helper:
>
> ```python
> from tenuo.temporal import register_worker_config
>
> worker_interceptor = TenuoWorkerInterceptor(config)
> # ... later, when the queue is known ...
> register_worker_config(config, task_queue="q")
> ```

---

## API Ergonomics

### Recommended: `execute_workflow_authorized(...)`

The safest way to start authorized workflows. Binds headers to a specific workflow ID and executes immediately. When the client was created with `TenuoTemporalPlugin`, the interceptor is discovered automatically — no need to pass `client_interceptor`.

```python
result = await execute_workflow_authorized(
    client=client,
    workflow_run_fn=DataProcessingWorkflow.run,
    workflow_id="process-001",
    warrant=warrant,
    key_id="agent-key-1",
    args=["/data/input/report.txt", "/data/output/report.txt"],
    task_queue="data-processing",
)
```

### Long-running workflows: `start_workflow_authorized(...)`

For workflows where you need a handle to signal, query, or await later (human-in-the-loop gates, multi-day pipelines):

```python
handle = await start_workflow_authorized(
    client=client,
    workflow_run_fn=ApprovalWorkflow.run,
    workflow_id="approval-001",
    warrant=warrant,
    key_id="agent-key-1",
    args=[request_data],
    task_queue="approvals",
)

# Signal later
await handle.signal(ApprovalWorkflow.approve, decision)
result = await handle.result()
```

Same header binding as `execute_workflow_authorized()` — but returns a `WorkflowHandle` immediately instead of blocking on the result.

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

For distributed deployments (separate client and worker processes):

| Component | Responsibility | Required |
|-----------|----------------|----------|
| Client | Start workflows with Tenuo headers (`execute_workflow_authorized` or `set_headers_for_workflow`) | Yes |
| Workflow worker | Register `TenuoWorkerInterceptor` and passthrough modules (`tenuo`, `tenuo_core`) | Yes |
| Activity worker | Receive propagated headers and enforce PoP/constraints | Yes |
| Key management | Resolve `key_id` to signing key using `KeyResolver` | Yes |
| Trusted roots | Provide `trusted_roots` (or global `configure(trusted_roots=...)`) | Yes |
| `activity_fns` | Same callables as `Worker(activities=...)` when warrants use **named** field constraints | When applicable |
| Child workflows | Start authorized children only with `tenuo_execute_child_workflow()` | When using child workflows |

---

## Configuration

### Key Management (REQUIRED)

Tenuo NEVER transmits private keys in headers. Workers must be configured with a `KeyResolver` to fetch signing keys from secure storage.

#### Production: Vault

```python
from tenuo.temporal import VaultKeyResolver, TenuoPluginConfig

resolver = VaultKeyResolver(
    url="https://vault.company.com:8200",
    path_template="production/tenuo/{key_id}",
    token=None,        # Uses VAULT_TOKEN env var
    mount="secret",
    cache_ttl=300,
)

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,
)
```

Store keys in Vault:
```bash
vault kv put secret/production/tenuo/agent-2024 \
  key=@signing_key.b64
```

#### Production: AWS Secrets Manager

```python
from tenuo.temporal import AWSSecretsManagerKeyResolver

resolver = AWSSecretsManagerKeyResolver(
    secret_prefix="tenuo/keys/",
    region_name="us-west-2",
    cache_ttl=300,
)

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,
)
```

Store keys in AWS:
```bash
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
    secret_prefix="tenuo-keys-",
    cache_ttl=300,
)

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    strict_mode=True,
)
```

Store keys in GCP:
```bash
gcloud secrets create tenuo-keys-agent-2024 \
  --data-file=signing_key.bin \
  --project=my-project
```

#### Development: Environment Variables

```python
from tenuo.temporal import EnvKeyResolver

resolver = EnvKeyResolver(
    prefix="TENUO_KEY_",
    warn_in_production=True,
)

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
)
```

`EnvKeyResolver` maps `key_id` to environment variables using the convention **`TENUO_KEY_<key_id>`**:

| `key_id` | Environment variable | Format |
|---|---|---|
| `"agent1"` | `TENUO_KEY_agent1` | Base64 or hex (auto-detected) |
| `"my-service"` | `TENUO_KEY_my-service` | Base64 or hex (auto-detected) |

```bash
# From an existing key file:
export TENUO_KEY_agent1=$(cat signing_key.bin | base64)

# Or generate one inline:
export TENUO_KEY_agent1=$(python -c "from tenuo import SigningKey; import base64; k=SigningKey.generate(); print(base64.b64encode(k.secret_key_bytes()).decode())")

export TENUO_ENV=development   # suppress production warning
```

`TenuoTemporalPlugin` calls `preload_all()` automatically, scanning all `TENUO_KEY_*` variables into an in-memory cache before the sandbox activates. If using `TenuoWorkerInterceptor` manually, call `resolver.preload_all()` before `Worker(...)` — PoP signing runs inside the workflow sandbox where `os.environ` is blocked.

> **Warning:** `EnvKeyResolver` is for development only. In production, use Vault, AWS Secrets Manager, or GCP Secret Manager.

#### `KeyResolver` and the workflow sandbox

PoP signing runs inside `_TenuoWorkflowOutboundInterceptor.start_activity`, which is **inside the workflow sandbox**. That means the sandbox determinism and I/O restrictions apply to whatever the resolver's `resolve_sync` does on each call. Pure-memory resolvers are safe; I/O-bound resolvers must be preloaded at worker startup and must return from their in-memory cache inside the sandbox.

| Resolver | Safe inside sandbox as-is? | How to make it safe |
|----------|---------------------------|--------------------|
| `EnvKeyResolver` | Yes — only if `preload_all()` ran outside the sandbox. `TenuoTemporalPlugin` does this automatically; manual `TenuoWorkerInterceptor` users must call it. `os.environ` reads from inside the sandbox will fail. |
| `DictKeyResolver` | Yes — pure in-memory lookup. |
| `VaultKeyResolver` | No — does HTTP on cache miss. | Warm the cache at worker startup by issuing one `resolve_sync(key_id)` per key *before* `Worker(...)` is created; tune `cache_ttl` > workflow lifetime. |
| `AWSSecretsManagerKeyResolver` | No — does boto3 network I/O on cache miss. | Same warmup + cache-TTL strategy. |
| `GCPSecretManagerKeyResolver` | No — does gRPC on cache miss. | Same warmup + cache-TTL strategy. |
| `CompositeKeyResolver` | Inherits from whichever child resolver it falls through to. | Put an in-memory / preloaded resolver first so the common path stays in the sandbox. |

A sandbox violation surfaces as `temporalio.worker.workflow_sandbox.RestrictedWorkflowAccessError`, wrapped by our interceptor as a non-retryable `TenuoContextError`. If you see this on a live workflow, the fix is almost always "preload before the sandbox activates" or "extend `cache_ttl`" — not "turn off the sandbox".

Note: `SigningKey.__repr__` is explicitly redacted (prints `SigningKey(public_key=…, secret=[REDACTED])`), so a surprise `logger.info(f"{sk}")` or `ApplicationError(str(resolver))` will not leak secret bytes into Temporal history or the Temporal Web UI.

#### Composite Resolver (Fallback Chain)

```python
from tenuo.temporal import CompositeKeyResolver, VaultKeyResolver, EnvKeyResolver

resolver = CompositeKeyResolver(
    resolvers=[
        VaultKeyResolver(url="https://vault.company.com"),
        EnvKeyResolver(),
    ],
    warn_on_fallback=True,
)
```

> **Tenuo Cloud alternative:** If you prefer not to operate your own KMS or Vault, Tenuo Cloud provides managed key issuance and rotation.

### Worker plugin config (`TenuoPluginConfig`)

```python
from tenuo.temporal import TenuoPluginConfig

config = TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),
    on_denial="raise",                         # "raise" | "log" | "skip"
    dry_run=False,                             # Shadow mode only; never for production
    trusted_roots=[control_key.public_key],
    strict_mode=True,                          # Fail-fast on ambiguous PoP with named constraints
    require_warrant=True,                      # Fail-closed: deny if no warrant
    block_local_activities=True,               # Prevent local activity bypass
    redact_args_in_logs=True,                  # Prevent secret leaks in logs
    max_chain_depth=10,                        # Max delegation depth
    audit_callback=on_audit,                   # Optional audit event handler
    metrics=TenuoMetrics(),                    # Optional Prometheus metrics
    authorized_signals=["approve"],            # Optional signal allowlist
    authorized_updates=["update_config"],      # Optional update allowlist
)
```

> **Production hardening:** Every worker must supply `trusted_roots` (or call `tenuo.configure(trusted_roots=[...])`). Without them, `TenuoPluginConfig` raises `ConfigurationError` at construction time.

### Denial Handling

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

### Dry run (staging only)

`dry_run=True` records authorization denials but still executes activities. Use only for rollout validation.

```python
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[root_key.public_key],
    dry_run=True,
)
```

> **Warning:** `dry_run=True` disables enforcement. Never use in production.

---

## Activity registry (`activity_fns`) and PoP argument names

### Why this matters

Each activity call gets a PoP signature over a payload that includes the **tool name** and a **sorted argument dictionary**. When your warrant has named field constraints (e.g. `path=Subpath("/data")`), the argument dict keys must match the Python parameter names.

### Resolution order (function reference)

1. **`input.fn`**: supplied by the Temporal Python SDK when available.
2. **`tenuo_execute_activity(...)`**: Tenuo records the function reference for that call.
3. **`TenuoPluginConfig.activity_fns`**: explicit registry (activity type name → function).
4. **Fallback:** `arg0`, `arg1`, … — correct for tool-only capabilities, wrong for named constraints.

### What to configure

| Warrant shape | Transparent `execute_activity` | Recommendation |
|---------------|-------------------------------|----------------|
| Tool-only (no fields) | Yes | `activity_fns` optional |
| Named fields (`path=...`) | Yes | Set `activity_fns` to the same list as `Worker(activities=[...])` |
| Named fields | Using `tenuo_execute_activity` | Registry not required |

```python
activities = [read_file, write_file]

interceptor = TenuoWorkerInterceptor(
    TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[control_key.public_key],
        strict_mode=True,
        activity_fns=activities,
    ),
    task_queue="my-queue",
)

async with Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[*activities, *TENUO_TEMPORAL_ACTIVITIES],
    interceptors=[interceptor],
    workflow_runner=...,
):
    ...
```

---

## Sandbox passthrough explained

Temporal's Python SDK re-imports workflow code in an isolated sandbox on every task. Tenuo signs PoP inside the sandbox at `execute_activity()` dispatch time using `tenuo_core` (a PyO3 Rust extension). Both `tenuo` and `tenuo_core` must be declared passthrough.

**If you omit the passthrough:**

| Step | Result |
|------|--------|
| Worker starts and connects | No error |
| First workflow task executes | **Fails:** `ImportError: PyO3 modules may only be initialized once per interpreter process` |
| Subsequent workflow tasks | All fail identically |
| Activities | Never scheduled |

The worker **appears healthy** while workflow executions are dead. Diagnose via Temporal Web → find the workflow → look for repeated `WorkflowTaskFailed` events.

---

## Compatibility

| Component | Supported | Notes |
|-----------|-----------|-------|
| Temporal Python SDK | `temporalio>=1.23.0` | `TenuoTemporalPlugin` needs `SimplePlugin` (1.23+) |
| Python | 3.10 – 3.14 | `temporalio` itself requires 3.10+, so the Temporal integration does too |
| Runtime mode | Single-process and distributed | Both supported |

---

## Proof-of-Possession

With `trusted_roots` in place, Tenuo enforces PoP for all warranted activity executions. The challenge is a CBOR-serialized tuple signed with Ed25519:

```
domain_context = b"tenuo-pop-v1"
window_ts      = (unix_now // 30) * 30          # 30-second bucket
challenge_data = CBOR( (warrant_id, tool, sorted_args, window_ts) )
preimage       = domain_context || challenge_data
signature      = Ed25519.sign(signing_key, preimage)   # 64 bytes
```

Two patterns for PoP:

**`AuthorizedWorkflow`** validates headers at workflow start:

```python
@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file, args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

**`tenuo_execute_activity()`** is a free function for advanced use cases:

```python
from tenuo.temporal import tenuo_execute_activity

return await tenuo_execute_activity(
    read_file, args=[path],
    start_to_close_timeout=timedelta(seconds=30),
)
```

Both automatically sign PoP; you never call `warrant.sign()` directly in workflows.

---

## Security considerations

This section covers the full threat model, trust boundaries, PoP windows, dedup, root rotation, revocation, and retry drift.

**Temporal's security vs. Tenuo's security.** Temporal Cloud provides infrastructure-level security: encrypted payloads, RBAC, namespace isolation, SOC 2. Tenuo operates at the authorization layer above that: each Activity is authorized against a signed warrant before it executes, regardless of who has Temporal cluster access. A namespace admin cannot cause an activity to execute outside warrant constraints, because authorization runs on the worker.

**In-process enforcement.** Tenuo runs entirely within your worker process using `tenuo_core`. No SaaS call, no network round-trip at verify time. If Tenuo's distribution infrastructure is unreachable, workers already running continue enforcing normally.

### Trust boundaries

| Component | Role |
|-----------|------|
| **Issuer / control plane** | Mints warrants; public keys configured as `trusted_roots` on workers. Compromise affects all downstream authorization. |
| **Temporal service** | Schedules tasks and carries headers. Tenuo assumes Temporal is operated with appropriate access control. |
| **Workflow workers** | Sign PoP using keys from `KeyResolver`. Compromise allows PoP for those keys. |
| **Activity workers** | Verify warrants, PoP, and constraints. Must have `trusted_roots` aligned with authorized issuers. |
| **Clients** | Attach warrant headers when starting workflows. Compromise allows starting workflows the issuer already permitted. |

### Protections

1. **Activity without valid warrant**: Denied when `require_warrant=True` (default).
2. **Forged or tampered warrant**: Chain validation ties delegated warrants back to trusted roots.
3. **Execution without holder PoP**: PoP binds tool name and argument map to the holder's key.
4. **Arguments outside constraints**: Field constraints enforced against the same argument map used for PoP.
5. **Over-broad credentials**: Short TTLs, delegation / `workflow_grant` for least privilege, signal/update guards.
6. **Mis-signing (named vs positional args)**: `strict_mode=True` fails fast on ambiguous PoP.

### Clock skew and PoP time windows

Verification checks PoP using multiple aligned time windows around the verifier's clock:

- `pop_window_secs=30`, `pop_max_windows=5`: ~±60 seconds effective skew tolerance.
- `clock_tolerance_secs=30`: applied to warrant lifetime/expiry, separate from PoP bucketing.

Workflow-side signing uses deterministic timestamps for Temporal replay; workers verify against their wall clock.

### Replay and horizontal workers

1. **Cryptographic validity**: PoP is valid within the window configuration; not a one-time nonce.
2. **Dedup**: After verification, a dedup key (warrant facet + workflow id + run id + activity id) is recorded for `attempt <= 1`. Retries with `attempt > 1` bypass dedup.

Default dedup is **in-memory per process** (`InMemoryPopDedupStore`). For fleet-wide suppression, implement `PopDedupStore` (e.g. Redis `SET NX`) and set `TenuoPluginConfig.pop_dedup_store`.

### Trusted root rotation

Static `trusted_roots` require a restart to pick up new issuer keys. For rotation without restarts, use `trusted_roots_provider` + `trusted_roots_refresh_interval_secs`. During rotation, return overlapping old and new issuer keys. On refresh failure, the worker retains the previous `Authorizer` and logs a warning.

### Out of scope

- **Compromised Temporal service**: address with Temporal security, not Tenuo alone.
- **Compromised worker host** with `KeyResolver` access: use HSM/KMS and minimal identity.
- **Malicious workflow code**: Tenuo constrains activities, not arbitrary Python in workflows.
- **`dry_run=True`**: disables enforcement; staging only.
- **Local activities**: bypass the interceptor unless `@unprotected` and `block_local_activities` allows it.

### Temporal activity retries and PoP time-drift

PoP is signed at `workflow.now()` when the activity is first scheduled. Temporal retries reuse headers from the original `ACTIVITY_TASK_SCHEDULED` event. The first-attempt verifier uses `pop_max_windows=5` (~±60 s); retries use the laxer `retry_pop_max_windows`, which defaults to **40** (±20 min) — sized against Temporal's default retry policy (`initial_interval=1s`, `backoff_coefficient=2`, `max_interval=100s`) so ten retries at ~13 min still verify.

| Retry pattern | Recommended approach |
|---------------|---------------------|
| Default Temporal retry policy | Default `retry_pop_max_windows=40` (±20 min) works |
| Long retries (> 20 min) | Bump `retry_pop_max_windows` (e.g. `120` for 1 h, `480` for 4 h) |
| Unbounded retries | Structure as child workflows for fresh PoP per retry |
| Durable workflows (hours/days) | Long warrant TTL + `retry_pop_max_windows` sized to max backoff + auto-revoke on completion |

```python
config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    retry_pop_max_windows=120,   # 120 × 30s = 3600s
)
```

### Warrant TTL vs. workflow lifetime

The warrant's `expires_at` is checked by the **activity** interceptor (on the activity worker, wall-clock). It is NOT checked inside the workflow sandbox during replay — `_TenuoWorkflowInboundInterceptor` only enforces signal / update allowlists, and `_TenuoWorkflowOutboundInterceptor` signs PoP against `workflow.now()`, which is deterministic across replays. So a Temporal replay 3 days after the fact will re-sign PoP at the original workflow time and never raise `WarrantExpired` from the replay path itself.

What the TTL **does** bound is how long activities scheduled by that workflow can continue to dispatch. A workflow that runs for 30 days under a 1-hour warrant will start seeing activity denials (`WarrantExpired`) ~1 hour in, even though the workflow object itself is still valid. Pick one of:

- **Short workflows (< TTL):** mint a warrant whose TTL covers the worst-case workflow duration including retries and timer sleeps.
- **Long workflows (> a single warrant can safely cover):** treat the warrant like a short-lived session token. Use one of:
  - `workflow_grant(...)` to mint a narrower per-phase warrant inside the workflow (requires the parent warrant to be an issuer).
  - `tenuo_execute_child_workflow(...)` to spawn child workflows each with their own freshly-minted warrant.
  - A resolver-side key rotation so `retry_pop_max_windows` extends the PoP window for durable retries (see previous section).
- **Unbounded workflows:** structure work as a series of child workflows rather than a single long-lived parent so each fresh warrant is scoped to a bounded unit of work.

### Temporal event history overhead

Each activity dispatch and each child-workflow start injects the Tenuo headers into the event payload, so every Tenuo-protected call adds per-event overhead to Temporal's event history (capped at 50,000 events / 2 MB by default, up to ~50 MB absolute depending on server config).

Approximate size per activity, with gzip compression enabled (the default):

| Component | Uncompressed | Compressed (gzip, level 9) |
|-----------|--------------|---------------------------|
| Root-only warrant | ~1 KB | ~500 B |
| 3-hop delegated warrant | ~4 KB | ~800 B – 1.2 KB |
| 10-hop delegated warrant | ~12 KB | ~2 – 3 KB |
| PoP signature (`x-tenuo-pop`) | 88 B (64 B + base64) | Not worth compressing |
| Misc headers (key id, arg keys, compressed flag) | ~100 B | ~100 B |

**Worked example.** A single workflow that dispatches 200 activities with a 3-hop warrant: `200 × (~1.2 KB warrant + ~100 B misc + ~90 B PoP) ≈ 280 KB` of Tenuo overhead in history. Well under the 2 MB limit, but non-trivial for `archival` replay costs and for workflows that also carry large user payloads.

Operational guidance:

1. **Keep chains short.** Prefer `workflow_grant(...)` (one issuer hop, attenuates in-process) over passing a delegated warrant through multiple external hops before it hits a worker.
2. **Watch `workflow.info().history_size_bytes`** in Temporal ≥ 1.22 and alert at, say, 1 MB; Tenuo headers are one of several contributors but one of the easier to attribute.
3. **Structure very-long workflows as parent/child.** Each child gets a fresh history budget. Pairs well with the TTL guidance above.

> **Planned for v0.2 — `warrant_hash` + worker-side LRU cache.** Activities would carry only the PoP signature plus a `warrant_hash` reference; the receiving worker resolves the full warrant from an in-process LRU (falling back to re-fetching from the source, e.g. Tenuo Cloud). This keeps per-event headers flat (~200 B) regardless of chain depth. Tracking: `temporal/warrant-cache-reference`.

### Access revocation

| Mechanism | Latency | How |
|-----------|---------|-----|
| **Warrant TTL expiry** | Passive | Mint short-lived warrants |
| **Remove trusted root** | Next provider refresh (30-60s) | Remove issuer key from provider output |
| **Revoke holder key** | Immediate on next resolve | Remove key from `KeyResolver` backend |

> **Tenuo Cloud** manages root distribution and rotation as a first-class primitive.

### Fail-closed defaults

| Check | Missing / invalid | Default behavior |
|-------|-------------------|------------------|
| Warrant header | Missing | Denied when `require_warrant=True` |
| Warrant expired | Expired | `WarrantExpired` |
| Tool / constraints | Not allowed | `TemporalConstraintViolation` |
| PoP signature | Missing or invalid | `PopVerificationError` |
| Protected local activity | Not `@unprotected` | `LocalActivityError` |

---

## Child Workflow Delegation

> **Important:** `workflow.execute_child_workflow()` does **not** propagate Tenuo warrant headers. Use `tenuo_execute_child_workflow()`.

```python
from tenuo.temporal import tenuo_execute_child_workflow

result = await tenuo_execute_child_workflow(
    ChildWorkflow.run,
    tools=["read_file"],
    ttl_seconds=60,
    args=["/data/input"],
    id=f"child-{workflow.info().workflow_id}",
    task_queue=workflow.info().task_queue,
)
```

### Delegation Chain Verification

When warrants are attenuated, the full chain is propagated via `x-tenuo-warrant-chain`. The activity interceptor calls `Authorizer.check_chain()` to verify every link back to a trusted root.

---

## Signal & Update Authorization

```python
config = TenuoPluginConfig(
    key_resolver=EnvKeyResolver(),
    on_denial="raise",
    trusted_roots=[control_key.public_key],
    authorized_signals=["approve", "reject"],
    authorized_updates=["update_config"],
)
```

Unrecognized signals raise `TemporalConstraintViolation`. When set to `None` (default), all signals and updates pass through.

---

## Nexus Operation Headers

**Not currently propagated.** Tenuo's outbound workflow interceptor does not inject warrant headers into `start_nexus_operation` calls today; the stock Temporal interceptor chain handles Nexus dispatch as a plain passthrough. The reason is simple: Tenuo does not yet ship an **inbound** Nexus interceptor in any SDK — including Python — so any headers we injected on the outbound side would have no consumer. Injecting them would burn history bytes without actually authorizing the operation. The cross-SDK encoding concern (see below) is real but secondary — the primary gap is the missing inbound half.

### Intended encoding (when this ships)

Whenever the inbound interceptor lands, the outbound side will need to encode warrant/PoP bytes into Nexus' string-map header channel. The following is the shape the previous speculative implementation used and the shape a future revision is expected to keep — recorded here so handlers in other SDKs have something stable to decode against once the integration is wired:

- Nexus headers are HTTP-shaped (`Mapping[str, str]`), unlike the activity/child-workflow/continue-as-new channels which use `Mapping[str, temporalio.api.common.v1.Payload]`. Raw warrant/PoP bytes must therefore be base64-encoded per-header.
- Encoding: [RFC 4648 §4 standard base64, padded](https://datatracker.ietf.org/doc/html/rfc4648#section-4), as produced by Python's `base64.b64encode(raw_bytes).decode()`.
- Header layout:

  | Header key (`tenuo.temporal._constants`) | Wire name            | Payload                                                      |
  |------------------------------------------|----------------------|--------------------------------------------------------------|
  | `TENUO_WARRANT_HEADER`                   | `x-tenuo-warrant`    | base64(raw warrant bytes, possibly gzip-compressed — see `TENUO_COMPRESSED_HEADER`) |
  | `TENUO_KEY_ID_HEADER`                    | `x-tenuo-key-id`     | base64(UTF-8 bytes of the key id)                            |
  | `TENUO_POP_HEADER`                       | `x-tenuo-pop`        | base64(raw 64-byte Ed25519 signature)                        |
  | `TENUO_COMPRESSED_HEADER`                | `x-tenuo-compressed` | base64(`b"1"`) when present — signals gzip before base64     |

Handler-side decoding (for reference, when the outbound path ships) in Go:

```go
import "encoding/base64"

warrantBytes, err := base64.StdEncoding.DecodeString(headers["x-tenuo-warrant"])
keyIdBytes,   err := base64.StdEncoding.DecodeString(headers["x-tenuo-key-id"])
popBytes,     err := base64.StdEncoding.DecodeString(headers["x-tenuo-pop"])
// If x-tenuo-compressed is present, gunzip warrantBytes before verification.
```

TypeScript (`Buffer.from(headers["x-tenuo-warrant"], "base64")`) follows the same pattern.

---

## PoP Replay Protection

The activity interceptor runs dedup after PoP verification. Default: `InMemoryPopDedupStore` (thread-safe, process-local, 10,000-entry cap, ~3-4 MB). Temporal retries with `attempt > 1` bypass dedup.

**Memory footprint:** ~3-4 MB at cap. For lower footprint, implement a custom `PopDedupStore`.

**Pluggable backend:** Set `TenuoPluginConfig.pop_dedup_store` for fleet-wide replay suppression.

> Without a shared `PopDedupStore`, dedup is single-process only. PoP windows still bound signature age.

---

## Decorators

### @tool() - Activity-to-Tool Mapping

```python
from tenuo.temporal import tool

@activity.defn
@tool("read_file")
async def fetch_document(doc_id: str) -> str:
    """Activity name is 'fetch_document', warrant checks 'read_file'."""
    return await storage.get(doc_id)
```

### @unprotected - Local Activities

```python
from tenuo.temporal import unprotected

@activity.defn
@unprotected
async def get_config_value(key: str) -> str:
    """Internal config lookup: no warrant needed."""
    return config[key]
```

> Activities not marked `@unprotected` that are called via `execute_local_activity()` will raise `LocalActivityError`.

### current_warrant() and current_key_id()

Read the active warrant and signing key ID from within workflow code:

```python
from tenuo.temporal import current_warrant, current_key_id

warrant = current_warrant()    # Raises TenuoContextError if no warrant
key_id = current_key_id()      # Raises TenuoContextError if no key ID
```

### tool_mappings - Config-Driven Name Mapping

```python
TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    tool_mappings={
        "log_ticket_outcome": "audit_log",
        "send_notification":  "notify",
    },
)
```

Both `tool_mappings` and `@tool()` can coexist; `tool_mappings` takes precedence.

### set_activity_approvals() - Pre-Supply Multisig Approvals

Call from a workflow before `workflow.execute_activity()` when the warrant has guards that require approval. The outbound interceptor attaches the approvals to the next activity dispatch.

```python
from tenuo.temporal import set_activity_approvals

set_activity_approvals([signed_approval_1, signed_approval_2])
await workflow.execute_activity(
    transfer_funds,
    args=[account, amount],
    start_to_close_timeout=timedelta(seconds=30),
)
```

### tenuo_warrant_context() - Warrant Context for Plain Client Calls

Async context manager that sets the active warrant for `client.execute_workflow()` or `client.start_workflow()` without using `execute_workflow_authorized()`. Useful when you need full control over the Temporal client call.

```python
from tenuo.temporal import tenuo_warrant_context

async with tenuo_warrant_context(warrant, key_id="agent1"):
    result = await client.execute_workflow(
        MyWorkflow.run,
        id="wf-123",
        args=["/data/report.txt"],
        task_queue="my-queue",
    )
```

### workflow_grant() - Scoped In-Workflow Grants

```python
from tenuo.temporal import workflow_grant

file_warrant = await workflow_grant(
    "read_file",
    constraints={"path": path},
    ttl_seconds=60,
)
```

Constraint keys must already exist in the parent warrant.

---

## Audit Events

Every authorization decision emits a `TemporalAuditEvent`. Supports SOC 2 CC6.8, PCI DSS 10.2, and HIPAA audit controls.

Each event captures: `warrant_id`, `workflow_id`, `workflow_run_id`, `tool`, `arguments` (redacted by default), `timestamp`, `decision` (`ALLOW`/`DENY`), `denial_reason`.

```python
from tenuo.temporal import TemporalAuditEvent

def on_audit(event: TemporalAuditEvent):
    audit_logger.info(event.to_dict())

config = TenuoPluginConfig(
    key_resolver=resolver,
    trusted_roots=[issuer_public_key],
    audit_callback=on_audit,
    audit_allow=True,
    audit_deny=True,
    redact_args_in_logs=True,
)
```

> **Tenuo Cloud** indexes audit receipts across all workflows and provides a queryable trail.

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

# Registers:
# - tenuo_temporal_activities_authorized_total{tool, workflow_type}
# - tenuo_temporal_activities_denied_total{tool, reason, workflow_type}
# - tenuo_temporal_authorization_latency_seconds_bucket{tool}
```

### Suggested Alerts

- Sustained increase in `*_activities_denied_total`
- Spikes in `POP_VERIFICATION_FAILED` / replay-related denials
- Key resolver failures (`KEY_NOT_FOUND`)
- Sudden drop in authorized activity volume

### Activity Summaries (Temporal Web UI)

`TenuoTemporalPlugin` enriches every authorized activity with a human-readable summary in the Event History.

| Activity kind | Summary rendered in UI |
|---|---|
| User activity (`read_file`) | `[tenuo.TenuoTemporalPlugin] read_file` |
| User activity with `tool_mappings` (`fetch_doc` → `read_file`) | `[tenuo.TenuoTemporalPlugin] read_file` |
| Internal warrant mint (local activity) | `[tenuo.TenuoTemporalPlugin] attenuate(read_file, list_directory)` |

Pass a `summary` to `tenuo_execute_activity()` and Tenuo preserves it:

```python
await tenuo_execute_activity(
    read_file,
    args=["/data/report.txt"],
    start_to_close_timeout=timedelta(seconds=30),
    summary="monthly sales report",
)
# UI shows: [tenuo.TenuoTemporalPlugin] read_file: monthly sales report
```

Summaries are capped at 200 bytes. Avoid sensitive data.

---

## Exceptions

The main authorization exceptions include `error_code` for wire format compatibility:

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

## Failure Semantics

Authorization failures are wrapped in `ApplicationError(non_retryable=True)` to prevent retrying permanent denials.

| Failure Type | Typical Exception | Retryable? |
|--------------|-------------------|------------|
| Missing/invalid warrant | `TemporalConstraintViolation` / `ChainValidationError` | **No** |
| Invalid PoP or replay | `PopVerificationError` | **No** |
| Expired warrant | `WarrantExpired` | **No** — mint a new warrant |
| Local activity without `@unprotected` | `LocalActivityError` | **No** |
| Key resolution failure | `KeyResolutionError` | Retry only for transient backend failures |
| Missing `trusted_roots` | `ConfigurationError` | Fix config |

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: PyO3 modules may only be initialized once...` | Missing passthrough | Add `with_passthrough_modules("tenuo", "tenuo_core")` ([details](#sandbox-passthrough-explained)) |
| `ConfigurationError: requires trusted_roots` | No `trusted_roots` on config | Pass `trusted_roots=` or call `tenuo.configure(trusted_roots=[...])` first |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without warrant | Use `execute_workflow_authorized(...)` |
| `TenuoContextError: no TenuoPluginConfig registered for task_queue=...` | Manual setup; mint activity dispatched but not registered | Pass `task_queue=` to `TenuoWorkerInterceptor(...)` **and** splat `TENUO_TEMPORAL_ACTIVITIES` into `Worker(activities=[...])` |
| `KeyResolutionError: Cannot resolve key` | Key not found | Check `TENUO_KEY_*` / Vault path; call `preload_keys()` before `Worker(...)` |
| `TemporalConstraintViolation: No warrant provided` | Client interceptor missing | Verify `client_interceptor` in `Client.connect(interceptors=[...])` |
| `PopVerificationError: replay detected` | Multi-replica without shared dedup | Configure `pop_dedup_store` for fleet-wide suppression |
| `PopVerificationError` on retry (attempt >= 2) | PoP timestamp stale | Set `retry_pop_max_windows` ([details](#temporal-activity-retries-and-pop-time-drift)) |
| Warning: `positional argument keys (arg0, …)` | Named constraints but no function reference | Set `activity_fns` or use `tenuo_execute_activity()` |
| `WarrantExpired` | TTL elapsed | Mint with longer `ttl()` |
| Child has no authorization | Started with `execute_child_workflow()` | Use `tenuo_execute_child_workflow()` |
| `TenuoArgNormalizationError` | Unsupported arg type (`set`, `datetime`, etc.) | Convert to `@dataclass` or `dict` |
| `TenuoPreValidationError: unknown field` | Warrant has fewer fields than activity | Declare all args with `Wildcard()` for unconstrained fields |

---

## Constraint Types for AI Agent Workflows

```python
from tenuo import (
    Subpath, UrlSafe, UrlPattern, Exact, Range, OneOf, AnyOf,
    CEL, Wildcard, Regex, NotOneOf, Pattern,
)
```

| Constraint | Description | Example |
|------------|-------------|---------|
| `Wildcard()` | Any value; attenuates to any type. **Use for unconstrained fields.** | `path=Wildcard()` |
| `Exact("value")` | Single literal | `format=Exact("json")` |
| `Subpath("/prefix/")` | Path prefix match | `path=Subpath("/data/reports/")` |
| `UrlSafe(allow_schemes=..., allow_domains=..., block_private=True)` | Structured URL validation with SSRF protection (scheme, domain, private-IP blocking) | `url=UrlSafe(allow_schemes=["https"], allow_domains=["api.example.com"])` |
| `UrlPattern("https://*.example.com/*")` | URL glob match (simpler but no SSRF protection) | `url=UrlPattern("https://*.wikipedia.org/*")` |
| `Pattern("glob*")` | String glob; attenuates to narrower globs only | `query=Pattern("search:*")` |
| `Range(min, max)` | Numeric range `[min, max]` | `max_length=Range(100, 5000)` |
| `OneOf(["a", "b"])` | Fixed set | `format=OneOf(["markdown", "json"])` |
| `NotOneOf(["a", "b"])` | Deny set | `tone=NotOneOf(["aggressive"])` |
| `AnyOf([c1, c2])` | Match any sub-constraint | `path=AnyOf([Subpath("/data/"), Subpath("/tmp/")])` |
| `Regex(r"^CUST-\d{6}$")` | Regex match | `customer_id=Regex(r"^CUST-[0-9]{6}$")` |
| `CEL("expression")` | CEL expression (requires `cel` feature) | `context=CEL('size(value) <= 2000')` |

> **Zero-trust mode:** When ANY argument is constrained, ALL others must also be declared. Use `Wildcard()` for unconstrained fields.

> **Attenuation:** `Wildcard()` can attenuate to any type. `Pattern("*")` can only narrow to globs.

For the full constraint reference, see [`docs/constraints.md`](./constraints.md).

---

## Best Practices

1. **Production keys**: Vault, AWS Secrets Manager, or GCP Secret Manager; not `EnvKeyResolver`.
2. **Sandbox passthrough**: always `with_passthrough_modules("tenuo", "tenuo_core")`.
3. **Named fields**: set `activity_fns` or use `tenuo_execute_activity()` or `strict_mode=True`.
4. **`AuthorizedWorkflow`**: use when missing headers should fail at workflow start.
5. **Child workflows**: only `tenuo_execute_child_workflow()`.
6. **Start path**: prefer `execute_workflow_authorized(...)` (blocks on result) or `start_workflow_authorized(...)` (returns handle) under concurrency.
7. **Audit**: wire `audit_callback` and keep `redact_args_in_logs=True`.
8. **`@unprotected`**: limit to internal, low-risk local activities.
9. **TTLs**: short for sensitive work; combine with `trusted_roots_provider`.
10. **Never `dry_run=True` in production.**
11. **Multi-tenant**: separate configs per tenant with distinct `trusted_roots`.
12. **Scale**: shared `PopDedupStore`; `retry_pop_max_windows` for long retries.

---

## Migration Path (from plain Temporal)

1. **Plugin**: add `TenuoTemporalPlugin` to `Client.connect(plugins=[...])` — this handles interceptors, sandbox passthrough, and key preloading in one step. (For manual control, use `TenuoWorkerInterceptor` + `SandboxedWorkflowRunner` instead; see [examples README](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal).)
2. **Client**: start workflows with `execute_workflow_authorized(...)` (or `start_workflow_authorized(...)` for the signal/query pattern).
3. **Children**: replace `execute_child_workflow()` with `tenuo_execute_child_workflow()`.
4. **Rollout**: one task queue or tenant first, then expand.

### Rollback

Route traffic to an unprotected queue while preserving workflow code. Keep as an operational fallback, not steady state.

---

## Examples

### Per-stage pipeline (from `delegation.py`)

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
    .capability("write_file", path=Subpath("/data/output"), content=Wildcard())
    .ttl(600)
    .mint(control_key)
)
```

---

## Integration QA Coverage

- `tests/e2e/test_temporal_live.py`, `test_temporal_replay.py`: in-process Temporal test server, serialization, delegation, continue-as-new, replay
- `tests/e2e/test_temporal_e2e.py`: mocked Temporal with real Tenuo objects: interceptors, PoP, constraints, child headers

---

## More Information

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal)
