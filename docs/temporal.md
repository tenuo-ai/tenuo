---
title: Tenuo Integration
description: Warrant-based authorization for Temporal AI agent workflows
---

# Tenuo integration

Tenuo provides cryptographic authorization for AI agent workflows. Each Activity execution is verified against a signed **warrant** that specifies which tools the agent may call, with what arguments, and under whose delegation. Authorization is enforced transparently by the worker interceptor — activity definitions require no changes.

If you're building agentic systems on Temporal, Tenuo lets you ship agents that are constrained by design: an agent can only do what its warrant allows, and every action is cryptographically attributable to the entity that authorized it. Verification and Proof-of-Possession signing run in-process with no external service dependency at runtime.

## Prerequisites

- Familiarity with Temporal. If you're new, start with [Understanding Temporal](https://learn.temporal.io/getting_started/) or the Temporal 101 course.
- A running Temporal cluster (local `temporal server start-dev` or Temporal Cloud).
- Python 3.9+.

## Install

```bash
uv pip install "tenuo[temporal]"
```

This installs `tenuo_core`, a compiled Rust extension with prebuilt wheels for common platforms.

## Configure Workers to use Tenuo

Add the `TenuoTemporalPlugin` to your Client. The plugin wires client interceptors, worker interceptors, and the workflow sandbox runner in one step.

```python
from temporalio.client import Client
from temporalio.worker import Worker

from tenuo.temporal import TenuoPluginConfig, EnvKeyResolver
from tenuo.temporal_plugin import TenuoTemporalPlugin

plugin = TenuoTemporalPlugin(
    TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[issuer_public_key],
    )
)

client = await Client.connect("localhost:7233", plugins=[plugin])
worker = Worker(
    client,
    task_queue="my-queue",
    workflows=[MyWorkflow],
    activities=[read_file, write_file],
)
```

Set `TENUO_KEY_<key_id>` environment variables with your base64-encoded holder signing keys. For production, use `VaultKeyResolver` or `AWSSecretsManagerKeyResolver` instead. **[Tenuo Cloud](https://cloud.tenuo.ai)** handles key issuance, warrant minting, rotation, and audit for teams that prefer a managed control plane. See the [reference](./temporal-reference.md#key-management-required) for key management details.

> **Important:** Pass the plugin on `Client.connect(plugins=[plugin])` only. Workers created from that client automatically merge client plugins — do not duplicate.

## Start an authorized workflow

Pass a warrant and key ID when starting a workflow. The warrant defines what the agent is allowed to do — your control plane or policy layer mints it.

```python
from tenuo.temporal import execute_workflow_authorized

result = await execute_workflow_authorized(
    client=client,
    client_interceptor=plugin.client_interceptor,
    workflow_run_fn=MyWorkflow.run,
    workflow_id="process-001",
    warrant=warrant,
    key_id="agent1",
    args=["/data/input/report.txt"],
    task_queue="my-queue",
)
```

## Define activities and workflows

Activity definitions stay unchanged — no Tenuo imports needed:

```python
from pathlib import Path
from temporalio import activity, workflow
from datetime import timedelta

@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()

@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"
```

Use `AuthorizedWorkflow` to fail fast if warrant headers are missing, or use plain `workflow.execute_activity()` — the interceptor handles authorization either way:

```python
from tenuo.temporal import AuthorizedWorkflow

@workflow.defn
class MyWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, input_path: str) -> str:
        data = await self.execute_authorized_activity(
            read_file,
            args=[input_path],
            start_to_close_timeout=timedelta(seconds=30),
        )
        return data.upper()
```

## How it works

```mermaid
sequenceDiagram
    participant C as Client
    participant T as Temporal
    participant WW as Workflow Worker
    participant KR as KeyResolver
    participant AW as Activity Worker

    C->>T: execute_workflow(headers: warrant + key_id)
    T->>WW: workflow task
    WW->>KR: resolve(key_id)
    KR-->>WW: signing_key — never transmitted
    Note over WW: PoP = sign(warrant_id, tool, sorted_args, window_ts)
    WW->>AW: activity headers (warrant + PoP)
    Note over AW: verify warrant chain → trusted_roots
    Note over AW: verify PoP signature + constraints
    AW->>AW: execute activity (authorized)
```

The signing key is resolved on the **worker** and never leaves it. PoP is computed at **schedule time** (binding exact tool and args), then verified on the **activity worker** before execution. This works in both single-process demos and distributed deployments.

## Child workflow delegation

Attenuate warrants when spawning child workflows so children get least-privilege access:

```python
from tenuo.temporal import tenuo_execute_child_workflow

@workflow.defn
class ParentWorkflow:
    @workflow.run
    async def run(self) -> str:
        # Parent has read_file + write_file.
        # Child gets only read_file with a shorter TTL.
        return await tenuo_execute_child_workflow(
            ChildWorkflow.run,
            tools=["read_file"],
            ttl_seconds=60,
            args=["/data/input"],
            id=f"child-{workflow.info().workflow_id}",
            task_queue=workflow.info().task_queue,
        )
```

> **Important:** `workflow.execute_child_workflow()` does **not** propagate warrant headers. Always use `tenuo_execute_child_workflow()` for authorized children.

## Security

**Fail-closed by default.** Missing or invalid warrants block execution. Each activity dispatch includes a Proof-of-Possession (PoP) signature binding the tool name and arguments to the holder key. Enforcement is in-process (no Tenuo network hop at verify time).

**Private keys never leave your infrastructure.** Only the `key_id` and warrant material travel in Temporal headers. Workers resolve signing keys from your Vault, AWS Secrets Manager, GCP Secret Manager, or (for development) environment variables via `KeyResolver`. No private key material is transmitted to the Temporal cluster or any Tenuo endpoint.

**Warrant chain verification.** When warrants are attenuated (e.g. for child workflows), the full delegation chain is validated back to trusted roots, ensuring no intermediate warrant was forged or widened.

| Check | Missing / invalid | Default behavior |
|-------|-------------------|------------------|
| Warrant header | Missing | Denied (`require_warrant=True`) |
| Warrant expired | Expired | `WarrantExpired` |
| Tool / constraints | Args outside scope | `TemporalConstraintViolation` |
| PoP signature | Missing or invalid | `PopVerificationError` |

Authorization failures are wrapped in Temporal's `ApplicationError(non_retryable=True)` to prevent retrying permanent denials.

**Trust boundaries:**

| Component | Role |
|-----------|------|
| **Issuer / control plane** | Mints warrants; public keys configured as `trusted_roots` on workers |
| **Temporal service** | Schedules tasks and carries headers; Tenuo does not replace Temporal's own security |
| **Workflow workers** | Sign PoP using keys from `KeyResolver`; sandbox passthrough required for `tenuo_core` |
| **Activity workers** | Verify warrants, PoP, and constraints before running activities |

For the full threat model, PoP time windows, replay protection, root rotation, and revocation, see [Temporal Integration Reference](./temporal-reference.md#security-considerations).

## Activity summaries in the Temporal Web UI

The plugin enriches every authorized activity with a human-readable summary in the Temporal Web UI's Event History:

| Activity kind | Summary in UI |
|---|---|
| User activity | `[tenuo.TenuoTemporalPlugin] read_file` |
| With user summary | `[tenuo.TenuoTemporalPlugin] read_file: monthly report` |
| Internal warrant mint | `[tenuo.TenuoTemporalPlugin] attenuate(read_file, list_directory)` |

```python
from tenuo.temporal import tenuo_execute_activity

await tenuo_execute_activity(
    read_file,
    args=["/data/report.txt"],
    start_to_close_timeout=timedelta(seconds=30),
    summary="monthly sales report",
)
```

## Runnable examples

These scripts under [`tenuo-python/examples/temporal/`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal) are the fastest path to a working demo. Run `temporal server start-dev` in one terminal, then run the Python file in another.

| Example | What it shows |
|---------|---------------|
| [`demo.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/demo.py) | **Start here.** Transparent `execute_activity()` and `AuthorizedWorkflow` in one place |
| [`delegation.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/delegation.py) | Per-stage pipeline with least-privilege warrants |
| [`multi_warrant.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/multi_warrant.py) | Multi-tenant isolation: same workflow, different warrants |
| [`cloud_iam_layering.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/cloud_iam_layering.py) | Temporal + MCP + S3 with per-tenant prefixes |
| [`temporal_mcp_layering.py`](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal/temporal_mcp_layering.py) | Temporal + MCP over stdio |

## Next steps

- **[Temporal Integration Reference](./temporal-reference.md)** — production checklist, key management (Vault, AWS, GCP), sandbox details, PoP mechanics, configuration reference, constraint types, troubleshooting, and the full threat model.
- [Tenuo Core Concepts](./concepts.md)
- [Security Model](./security.md)
- [Example Code](https://github.com/tenuo-ai/tenuo/tree/main/tenuo-python/examples/temporal)
