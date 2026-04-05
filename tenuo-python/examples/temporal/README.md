# Tenuo Temporal Integration Examples

Warrant-based authorization for Temporal workflows and activities with **transparent PoP**.

## Prerequisites

1. **Temporal Server**

```bash
brew install temporal            # macOS
temporal server start-dev        # Start dev server
```

2. **Python Dependencies**

```bash
pip install "tenuo[temporal]"
```

## Examples

Three examples showing a clean progression from basic transparent authorization to advanced patterns:

| Example | Concept | What it demonstrates |
|---------|---------|---------------------|
| [`demo.py`](demo.py) | **Transparent authorization** | Standard `workflow.execute_activity()`, zero workflow changes, sequential + parallel reads, unauthorized access denial |
| [`multi_warrant.py`](multi_warrant.py) | **Multi-tenant isolation** | Identical workflow code for different tenants, isolation via warrant only, cross-access denial |
| [`delegation.py`](delegation.py) | **Inline attenuation** | Per-stage pipeline authorization with attenuated child workflows via `tenuo_execute_child_workflow()` |

### Quick start

```bash
temporal server start-dev        # Terminal 1
python demo.py                   # Terminal 2
```

## Transparent Authorization Pattern

Recommended start path: use `execute_workflow_authorized(...)` for deterministic header binding in concurrent clients.

```python
result = await execute_workflow_authorized(
    client=client,
    client_interceptor=client_interceptor,
    workflow_run_fn=MyWorkflow.run,
    workflow_id="wf-123",
    warrant=warrant,
    key_id="agent1",
    args=[path],
    task_queue="my-queue",
)
```

Inside workflows, the registered Tenuo interceptors (from `TenuoPlugin`) compute Proof-of-Possession signatures transparently — use standard Temporal APIs:

```python
@workflow.defn
class MyWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        # Standard Temporal API - no Tenuo imports needed!
        return await workflow.execute_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=30),
        )
```

The interceptor automatically:
- Computes PoP with deterministic timestamps (`workflow.now()`)
- Injects warrant and PoP into activity headers
- Works with `asyncio.gather()` for parallel activities
- Ensures replay safety

### Activity registry (`activity_fns`) — when you **must** set it

PoP signs a canonical **argument dictionary**. If your warrant uses **named field constraints** (for example `capability("read_file", path=Subpath("/data/..."))`), that dict must use **real parameter names** (`path`), not placeholders (`arg0`, `arg1`, …).

The outbound interceptor learns parameter names from, in order:

1. The Temporal SDK’s `input.fn` (when present)
2. `tenuo_execute_activity()` (records the function for that call)
3. **`TenuoPluginConfig.activity_fns`** — pass the **same** callables as `Worker(activities=[...])`
4. Otherwise it falls back to `arg0`, `arg1`, …

If (4) happens while your warrant has field constraints for that tool, verification will not match the warrant. The worker **logs a warning**; with **`strict_mode=True`** it **raises** instead so you fix config before production.

**Rule of thumb:** warrants with `path=`, `message=`, etc. → set `activity_fns=activities` next to your `TenuoPlugin` config (see `demo.py`). Tool-only capabilities (no per-field constraints) do not require it.

See also: the **Activity registry (`activity_fns`) and PoP argument names** section in [`docs/temporal.md`](../../../docs/temporal.md) (repository root).

### When to use Tenuo-specific functions

Most workflows use standard `workflow.execute_activity()` via `AuthorizedWorkflow`. Use `tenuo_execute_activity()` when you need explicit per-call warrant control:
- Multi-warrant workflows where different activities run under different warrants
- Per-stage delegation where you narrow the warrant before each stage
- Any workflow that does not extend `AuthorizedWorkflow` but needs transparent PoP

For child workflows with attenuated scope, use `tenuo_execute_child_workflow()` instead (it handles the warrant narrowing and header injection together):

```python
# Only needed for per-child authorization decisions
await tenuo_execute_child_workflow(
    ReaderChild.run,
    args=[source_dir],
    id=f"reader-{workflow.info().workflow_id}",
    tools=["read_file", "list_directory"],  # Subset of parent's tools
    ttl_seconds=60,                          # Scoped lifetime
)
```

This is an authorization decision (choosing what scope and duration to delegate), not infrastructure.

**How it works:**
1. Reads the parent warrant from workflow context
2. Derives a narrowed child warrant internally (monotonic attenuation)
3. Validates that requested tools are a subset of parent's tools
4. Injects the attenuated child warrant via the outbound interceptor
5. Child workflow receives ONLY the narrowed capabilities

The child never sees the parent's full warrant - it's attenuated before injection.

## Worker setup (required)

Tenuo's core is a PyO3 Rust extension. Unlike pure-Python integrations (e.g. OpenTelemetry's `TracingInterceptor`), Tenuo signs the Proof-of-Possession challenge *inside the workflow sandbox* at `execute_activity()` dispatch time, committing the exact tool and arguments the workflow is authorising. Because PyO3 extensions cannot be re-imported per sandbox task, both `tenuo` and `tenuo_core` must be declared as passthrough modules:

```python
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner, SandboxRestrictions,
)

from tenuo.temporal import EnvKeyResolver, TenuoPlugin, TenuoPluginConfig

interceptor = TenuoPlugin(
    TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        on_denial="raise",
        trusted_roots=[control_key.public_key],  # required (or tenuo.configure(trusted_roots=[...]) before building config)
        strict_mode=True,  # optional: fail-fast on ambiguous PoP with named constraints
    )
)

worker = Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[read_file],
    interceptors=[interceptor],
    workflow_runner=SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",  # Required: PyO3 extension cannot be re-imported per sandbox task
        )
    ),
)
```

Omitting this causes `ImportError: PyO3 modules may only be initialized once per interpreter process`. The worker starts and connects normally but all workflow tasks fail — see [docs/temporal.md — Sandbox passthrough explained](../../../docs/temporal.md#sandbox-passthrough-explained) for the failure sequence and diagnostic steps.

## Architecture

```
Client                    Workflow                    Activity
  |                          |                           |
  |-- set_headers_for_workflow() |                      |
  |-- execute_workflow() --->|                           |
  |                          |                           |
  |                    Inbound interceptor:              |
  |                    Extract Tenuo headers             |
  |                          |                           |
  |                    workflow.execute_activity()       |
  |                          |                           |
  |                    Outbound interceptor:             |
  |                    Compute PoP (transparent)         |
  |                    Inject headers into activity  --->|
  |                          |                           |
  |                          |    Activity interceptor:  |
  |                          |    Verify warrant chain   |
  |                          |    Verify PoP signature   |
  |                          |    Check constraints      |
  |                          |                           |
  |                          |<--- Execute if OK --------|
```

Headers propagate through Temporal's native header mechanism,
so this works in distributed deployments (separate client/worker processes).

The key innovation: PoP computation happens **transparently** in the outbound
interceptor using `workflow.now()` for deterministic replay. Workflow code uses
standard Temporal APIs with zero Tenuo imports.

## Security defaults

All security features are fail-closed:

- `require_warrant=True` — activities without warrants are denied
- `block_local_activities=True` — prevents bypass via local activities
- `redact_args_in_logs=True` — prevents secret leaks in logs
- `trusted_roots` is required (or set via `tenuo.configure(trusted_roots=[...])`); PoP is always verified for warranted activities

## Testing

```bash
cd tenuo-python
pytest tests/e2e/test_temporal_e2e.py -v   # mocked Temporal integration tests (no server)
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ConfigurationError` … `trusted_roots` | `TenuoPluginConfig` built without roots and no global `configure` | Pass `trusted_roots=[control_key.public_key]` or call `tenuo.configure(trusted_roots=[...])` before constructing the config |
| `ImportError: PyO3 modules ... initialized once` | Missing passthrough modules | Add `with_passthrough_modules("tenuo", "tenuo_core")` to sandbox config |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without headers | Use `execute_workflow_authorized(...)` or call `set_headers_for_workflow(workflow_id, tenuo_headers(...))` before `execute_workflow` |
| `TemporalConstraintViolation: No warrant provided` | Headers not reaching worker | Ensure `TenuoClientInterceptor` is in the client's interceptor list |
| `PopVerificationError: replay detected` | Same activity attempt reached two workers (fleet-wide dedup not configured) | Expected with in-memory dedup and multiple worker pods; configure `pop_dedup_store` with a shared backend for fleet-wide suppression |
| `KeyResolutionError: Cannot resolve key: <id>` | Signing key not found by `KeyResolver` | For `EnvKeyResolver`: check `TENUO_KEY_<key_id>` is set and base64-encoded correctly. For cloud resolvers: verify secret name, permissions, and region |
| Warning: `PoP signing … uses positional argument keys (arg0, …)` | Warrant uses named field constraints but activity function reference not available | Add `activity_fns=[read_file, ...]` to `TenuoPluginConfig` (same list as `Worker(activities=...)`), or use `tenuo_execute_activity()` |
| `TenuoContextError` (in `strict_mode`) | Same as above but fail-fast is on | See above; remove `strict_mode=True` temporarily to diagnose, then fix `activity_fns` |
| Activity denied despite valid warrant | PoP computation failed silently | Check worker logs for WARNING/ERROR messages from outbound interceptor; verify `key_id` matches a key accessible to `KeyResolver` |

## Learn More

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Temporal Integration Docs](https://tenuo.ai/temporal)
- [Tenuo Core Concepts](https://tenuo.ai/concepts)
