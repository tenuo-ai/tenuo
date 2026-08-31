---
title: Temporal Quickstart
description: Run your first Tenuo-authorized Temporal workflow locally
---

# Temporal Quickstart

This quickstart runs one local Temporal workflow with Tenuo authorization. You
will see one allowed Activity and one denied Activity so the enforcement
boundary is obvious.

You will run:

```text
Client -> Temporal Workflow -> Tenuo-protected Activity
```

The warrant allows the workflow to read files under `/tmp/tenuo-temporal-demo`.
When the workflow tries to read another path, the Activity worker denies it
before user Activity code runs.

## 1. Start Temporal

In terminal 1:

```bash
temporal server start-dev
```

If you do not have the Temporal CLI yet, install it from the
[Temporal CLI docs](https://docs.temporal.io/cli#install).

## 2. Install Tenuo with Temporal support

In terminal 2:

```bash
python -m venv .venv
source .venv/bin/activate
pip install "tenuo[temporal]"
```

## 3. Save the example

Create `temporal_tenuo_quickstart.py`:

```python
import asyncio
import base64
import logging
import os
import uuid
from datetime import timedelta
from pathlib import Path

from temporalio import activity, workflow
from temporalio.client import Client, WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.worker import Worker

from tenuo import SigningKey, Subpath, Warrant
from tenuo.temporal import (
    AuthorizedWorkflow,
    EnvKeyResolver,
    InMemoryPopDedupStore,
    TenuoPluginConfig,
    TenuoTemporalPlugin,
    execute_workflow_authorized,
)


DATA_DIR = Path("/tmp/tenuo-temporal-demo")
TASK_QUEUE = "tenuo-temporal-quickstart"

logging.getLogger("temporalio.worker").setLevel(logging.CRITICAL)
logging.getLogger("temporalio.worker._activity").setLevel(logging.CRITICAL)


@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


@workflow.defn
class ReadFileWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, path: str) -> str:
        return await self.execute_authorized_activity(
            read_file,
            args=[path],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


async def run_one(client: Client, warrant, path: str) -> str:
    return await execute_workflow_authorized(
        client=client,
        workflow_run_fn=ReadFileWorkflow.run,
        workflow_id=f"read-file-{uuid.uuid4().hex[:8]}",
        warrant=warrant,
        key_id="agent1",
        args=[path],
        task_queue=TASK_QUEUE,
        execution_timeout=timedelta(seconds=30),
        retry_policy=RetryPolicy(maximum_attempts=1),
    )


def print_failure(exc: BaseException) -> None:
    cause = exc
    while cause is not None:
        print(f"{type(cause).__name__}: {cause}")
        cause = getattr(cause, "cause", None)


async def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    allowed_path = DATA_DIR / "allowed.txt"
    denied_path = Path("/tmp/tenuo-denied.txt")
    allowed_path.write_text("hello from an authorized Temporal Activity\n")
    denied_path.write_text("this file is outside the warrant scope\n")

    # Demo keys. In production, the issuer key belongs to your control plane,
    # and holder keys are resolved from Vault, AWS Secrets Manager, GCP Secret
    # Manager, KMS/HSM-backed signers, or Tenuo Cloud.
    issuer_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode("ascii")

    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath(str(DATA_DIR)))
        .ttl(300)
        .mint(issuer_key)
    )

    plugin = TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[issuer_key.public_key],
            activity_fns=[read_file],
            strict_mode=True,
            # Local demo only. Use Redis/Memcached/etc. for multi-worker
            # production replay protection.
            pop_dedup_store=InMemoryPopDedupStore(),
        )
    )

    client = await Client.connect("localhost:7233", plugins=[plugin])

    async with Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[ReadFileWorkflow],
        activities=[read_file],
    ):
        print("Allowed run:")
        result = await run_one(client, warrant, str(allowed_path))
        print(result.strip())

        print("\nDenied run:")
        logging.disable(logging.ERROR)
        try:
            await run_one(client, warrant, str(denied_path))
        except WorkflowFailureError as exc:
            print_failure(exc)
        finally:
            logging.disable(logging.NOTSET)


if __name__ == "__main__":
    asyncio.run(main())
```

## 4. Run it

In terminal 2:

```bash
python temporal_tenuo_quickstart.py
```

Expected output:

```text
Allowed run:
hello from an authorized Temporal Activity

Denied run:
WorkflowFailureError: Workflow execution failed
ActivityError: Activity task failed
ApplicationError: constraint_violation: Constraint 'path' not satisfied: ...
```

The exact denial text varies slightly by Temporal SDK version, but the nested
`ApplicationError` should mention `constraint_violation` because the `path`
argument was outside the warrant's allowed `Subpath`.

## What just happened

1. The client started a workflow with a signed warrant and a holder `key_id`.
2. The workflow scheduled `read_file`.
3. Tenuo's workflow interceptor signed proof-of-possession for the exact
   Activity name and arguments.
4. Tenuo's Activity interceptor verified the warrant, holder proof, expiry,
   trusted root, and `path` constraint.
5. The allowed path ran; the out-of-scope path was denied before `read_file`
   executed.

The Activity definition did not need any Tenuo-specific code. The enforcement
comes from the Temporal plugin and the warrant.

## Common first-run issues

| Symptom | Fix |
|---|---|
| `Connection refused` | Make sure `temporal server start-dev` is running. |
| `No Tenuo headers` | Start workflows with `execute_workflow_authorized(...)` or another authorized start helper. |
| `Cannot resolve key: agent1` | Set `TENUO_KEY_agent1` before constructing the plugin. This example does that for you. |
| `PyO3 modules may only be initialized once` | Use `TenuoTemporalPlugin`; it configures workflow sandbox passthrough automatically. |
| Denial says an argument is missing | Add the Activity callable to `activity_fns=[...]` so named warrant constraints match Python parameter names. |

## Next steps

- [Temporal Integration](./temporal.md) — the main guide.
- [Temporal Integration Reference](./temporal-reference.md) — production
  configuration, replay safety, revocation, approvals, and troubleshooting.
- [Tenuo for Temporal Nexus](./temporal-nexus-use-cases.md) — cross-namespace
  and cross-organization examples.
