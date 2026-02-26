"""
Multi-Warrant Workflows with Temporal - Transparent Authorization

Demonstrates multi-tenant isolation: different warrants for different workflows
running concurrently on the same worker. Each workflow receives its own scoped
warrant via TenuoClientInterceptor:

  - Workflow A: can read /tmp/tenuo-demo/project-a/**
  - Workflow B: can read /tmp/tenuo-demo/project-b/**

Neither can access the other's directory.

KEY POINT: The workflow code is identical for both tenants. Isolation comes
entirely from the warrant assigned at workflow start, not from code changes.
Both workflows use standard workflow.execute_activity() - the TenuoInterceptor
handles authorization transparently.

Requirements:
    temporal server start-dev   # Terminal 1
    python multi_warrant.py     # Terminal 2
"""

import asyncio
import base64
import logging
import os
import uuid
from datetime import timedelta
from pathlib import Path

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

from tenuo import SigningKey, Warrant
from tenuo_core import Subpath
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    TemporalAuditEvent,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)


# -- Activities ---------------------------------------------------------------

@activity.defn
async def list_directory(path: str) -> list[str]:
    return sorted(str(p) for p in Path(path).iterdir() if p.is_file())


@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


# -- Workflow -----------------------------------------------------------------

@workflow.defn
class ScopedReadWorkflow:
    """Reads all .txt files within its warrant-scoped directory.

    Uses standard workflow.execute_activity() - the TenuoInterceptor
    handles authorization transparently. This same workflow code works
    for all tenants; isolation comes from the warrant, not the code.
    """

    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)

        # Standard Temporal API - interceptor handles PoP transparently
        files = await workflow.execute_activity(
            list_directory, args=[data_dir],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=no_retry,
        )

        contents = []
        for f in files:
            if f.endswith(".txt"):
                # Same standard API - works identically for all tenants
                text = await workflow.execute_activity(
                    read_file, args=[f],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=no_retry,
                )
                contents.append(f"{Path(f).name}: {len(text)} chars")

        return f"Read {len(contents)} files from {Path(data_dir).name}"


# -- Audit callback -----------------------------------------------------------

def on_audit(event: TemporalAuditEvent):
    symbol = "ALLOW" if event.decision == "ALLOW" else "DENY"
    logger.info(f"  [{symbol}] {event.tool} (wf={event.workflow_id})")


# -- Main ---------------------------------------------------------------------

async def main():
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])
    logger.info("Connected to Temporal server")

    control_key = SigningKey.generate()
    agent_a_key = SigningKey.generate()
    agent_b_key = SigningKey.generate()

    os.environ["TENUO_KEY_agentA"] = base64.b64encode(agent_a_key.secret_key_bytes()).decode()
    os.environ["TENUO_KEY_agentB"] = base64.b64encode(agent_b_key.secret_key_bytes()).decode()

    # -- Mint two warrants with disjoint scopes --
    warrant_a = (
        Warrant.mint_builder()
        .holder(agent_a_key.public_key)
        .capability("list_directory", path=Subpath("/tmp/tenuo-demo/project-a"))
        .capability("read_file", path=Subpath("/tmp/tenuo-demo/project-a"))
        .ttl(3600)
        .mint(control_key)
    )

    warrant_b = (
        Warrant.mint_builder()
        .holder(agent_b_key.public_key)
        .capability("list_directory", path=Subpath("/tmp/tenuo-demo/project-b"))
        .capability("read_file", path=Subpath("/tmp/tenuo-demo/project-b"))
        .ttl(3600)
        .mint(control_key)
    )

    logger.info(f"Warrant A ({warrant_a.id}): scope /tmp/tenuo-demo/project-a")
    logger.info(f"Warrant B ({warrant_b.id}): scope /tmp/tenuo-demo/project-b")

    # -- Demo data --
    for project in ("project-a", "project-b"):
        d = Path(f"/tmp/tenuo-demo/{project}")
        d.mkdir(parents=True, exist_ok=True)
        (d / "readme.txt").write_text(f"README for {project}")
        (d / "data.txt").write_text(f"Data for {project}")

    task_queue = f"multi-warrant-{uuid.uuid4().hex[:8]}"

    worker_interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
            activity_fns=[list_directory, read_file],
        )
    )

    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")
    )

    async with Worker(
        client, task_queue=task_queue,
        workflows=[ScopedReadWorkflow],
        activities=[list_directory, read_file],
        interceptors=[worker_interceptor],
        workflow_runner=sandbox_runner,
    ):
        logger.info("Worker started\n")

        # --- Workflow A: reads project-a ---
        logger.info("=== Workflow A: reading project-a ===")
        client_interceptor.set_headers(tenuo_headers(warrant_a, "agentA"))
        result_a = await client.execute_workflow(
            ScopedReadWorkflow.run,
            args=["/tmp/tenuo-demo/project-a"],
            id=f"wf-a-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result A: {result_a}\n")

        # --- Workflow B: reads project-b ---
        logger.info("=== Workflow B: reading project-b ===")
        client_interceptor.set_headers(tenuo_headers(warrant_b, "agentB"))
        result_b = await client.execute_workflow(
            ScopedReadWorkflow.run,
            args=["/tmp/tenuo-demo/project-b"],
            id=f"wf-b-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result B: {result_b}\n")

        # --- Cross-access: Workflow A tries project-b (should be denied) ---
        logger.info("=== Cross-access: Warrant A on project-b (should be denied) ===")
        client_interceptor.set_headers(tenuo_headers(warrant_a, "agentA"))
        try:
            from temporalio.client import WorkflowFailureError
            await client.execute_workflow(
                ScopedReadWorkflow.run,
                args=["/tmp/tenuo-demo/project-b"],
                id=f"wf-cross-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
            )
            logger.error("BUG: cross-access should have been denied")
        except (WorkflowFailureError, Exception) as e:
            logger.info(f"Correctly denied cross-access: {type(e).__name__}\n")

    logger.info("Done. Multi-warrant isolation verified.")


if __name__ == "__main__":
    asyncio.run(main())
