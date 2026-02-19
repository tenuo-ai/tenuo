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

The TenuoInterceptor computes Proof-of-Possession signatures transparently - just use standard Temporal APIs:

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

### When to use Tenuo-specific functions

Most workflows use standard `workflow.execute_activity()`. The only exception is **inline attenuation** for child workflows:

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
2. Calls `parent_warrant.attenuate(tools=..., ttl_seconds=...)` internally
3. Validates that requested tools are a subset of parent's tools
4. Injects the attenuated child warrant via the outbound interceptor
5. Child workflow receives ONLY the narrowed capabilities

The child never sees the parent's full warrant - it's attenuated before injection.

## Worker setup (required)

Tenuo's core is a PyO3 native module that must bypass Temporal's workflow sandbox:

```python
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner, SandboxRestrictions,
)

interceptor = TenuoInterceptor(
    TenuoInterceptorConfig(
        key_resolver=EnvKeyResolver(),
        on_denial="raise",
        trusted_roots=[control_key.public_key],
        audit_callback=on_audit,
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
            "tenuo", "tenuo_core",  # Required for PoP
        )
    ),
)
```

## Architecture

```
Client                    Workflow                    Activity
  |                          |                           |
  |-- set_headers()          |                           |
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
- PoP verification is mandatory when `trusted_roots` is set

## Testing

```bash
cd tenuo-python
pytest tests/test_temporal_e2e.py -v    # 31 integration tests
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: PyO3 modules ... initialized once` | Missing passthrough modules | Add `with_passthrough_modules("tenuo", "tenuo_core")` to sandbox config |
| `TenuoContextError: No Tenuo headers in store` | Workflow started without headers | Call `client_interceptor.set_headers(tenuo_headers(...))` before `execute_workflow` |
| `ConstraintViolation: No warrant provided` | Headers not reaching worker | Ensure `TenuoClientInterceptor` is in the client's interceptor list |
| Activity denied despite valid warrant | PoP computation failed | Check worker logs for WARNING messages from outbound interceptor |

## Learn More

- [Temporal Documentation](https://docs.temporal.io)
- [Tenuo Temporal Integration Docs](https://tenuo.ai/temporal)
- [Tenuo Core Concepts](https://tenuo.ai/concepts)
