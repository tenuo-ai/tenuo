"""
Warrant Delegation Patterns with Temporal

Demonstrates warrant delegation patterns for multi-stage workflows.

NOTE: All workflows use standard workflow.execute_activity() - the interceptor
handles PoP transparently. The ONLY Tenuo-specific call is tenuo_execute_child_workflow()
in OrchestratorWorkflow, which exists because choosing what scope to delegate to a
child is an authorization decision, not infrastructure.

  Pattern 1 — Per-stage warrant rotation:
     A pipeline with distinct stages (ingest, transform) where each stage
     gets a fresh, tightly-scoped warrant minted by the control plane.
     Best when stages are independent and run as separate workflow invocations.

  Pattern 2 — Inline attenuation:
     An orchestrator workflow with a broad warrant delegates narrower
     warrants to child workflows via tenuo_execute_child_workflow().
     The outbound interceptor injects attenuated headers into the child.

Requirements:
    temporal server start-dev   # Terminal 1
    python delegation.py        # Terminal 2
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

from tenuo import SigningKey, Warrant, Pattern
from tenuo_core import Subpath
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    tenuo_headers,
    tenuo_execute_child_workflow,
    TemporalAuditEvent,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)


# =============================================================================
# Activities
# =============================================================================

@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


@activity.defn
async def write_file(path: str, content: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes"


@activity.defn
async def list_directory(path: str) -> list[str]:
    return sorted(str(p) for p in Path(path).iterdir() if p.is_file())


# =============================================================================
# Pattern 1: Per-Stage Warrant Rotation
# =============================================================================

@workflow.defn
class IngestWorkflow:
    """Stage 1: Reads source files. Warrant scoped to read_file only.

    Uses standard workflow.execute_activity() - interceptor handles PoP.
    """

    @workflow.run
    async def run(self, source_dir: str) -> list[str]:
        no_retry = RetryPolicy(maximum_attempts=1)
        files = await workflow.execute_activity(
            list_directory, args=[source_dir],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=no_retry,
        )
        results = []
        for f in files:
            content = await workflow.execute_activity(
                read_file, args=[f],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
            results.append(content)
        return results


@workflow.defn
class TransformWorkflow:
    """Stage 2: Writes transformed output. Warrant scoped to write_file only.

    Uses standard workflow.execute_activity() - interceptor handles PoP.
    """

    @workflow.run
    async def run(self, output_dir: str, data: list[str]) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        for i, content in enumerate(data):
            transformed = content.upper()
            await workflow.execute_activity(
                write_file,
                args=[f"{output_dir}/output_{i}.txt", transformed],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
        return f"Transformed {len(data)} files to {output_dir}"


# =============================================================================
# Pattern 2: Inline Attenuation (Orchestrator -> Child Workflows)
# =============================================================================
#
# The orchestrator holds a broad warrant (read + write + list).
# It spawns child workflows with narrowed scope using tenuo_execute_child_workflow().
# Each child can only do what the orchestrator explicitly grants.
# This happens inside the workflow — no client-side warrant rotation needed.


@workflow.defn
class ReaderChild:
    """Child workflow that can only read. Gets attenuated warrant from parent.

    Uses standard workflow.execute_activity() - interceptor handles PoP.
    The attenuated warrant comes from tenuo_execute_child_workflow() in the parent.
    """

    @workflow.run
    async def run(self, source_dir: str) -> list[str]:
        no_retry = RetryPolicy(maximum_attempts=1)
        files = await workflow.execute_activity(
            list_directory, args=[source_dir],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=no_retry,
        )
        results = []
        for f in files:
            content = await workflow.execute_activity(
                read_file, args=[f],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
            results.append(content)
        return results


@workflow.defn
class WriterChild:
    """Child workflow that can only write. Gets attenuated warrant from parent.

    Uses standard workflow.execute_activity() - interceptor handles PoP.
    The attenuated warrant comes from tenuo_execute_child_workflow() in the parent.
    """

    @workflow.run
    async def run(self, output_dir: str, data: list[str]) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        for i, content in enumerate(data):
            await workflow.execute_activity(
                write_file,
                args=[f"{output_dir}/result_{i}.txt", content.upper()],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=no_retry,
            )
        return f"Wrote {len(data)} files to {output_dir}"


@workflow.defn
class OrchestratorWorkflow:
    """Broad warrant (read + write + list). Delegates narrower warrants to children.

    Uses tenuo_execute_child_workflow() to make authorization decisions about
    what scope to delegate to each child. This is the ONLY Tenuo-specific call
    in this example - everything else uses standard workflow.execute_activity().

    HOW IT WORKS:
    1. This workflow receives a broad warrant (read + write + list) from the client
    2. tenuo_execute_child_workflow() reads that parent warrant from context
    3. It calls parent_warrant.attenuate(tools=..., ttl_seconds=...) internally
    4. The attenuated child warrant is injected into the child workflow via interceptor
    5. Child workflow receives ONLY the narrowed capabilities
    """

    @workflow.run
    async def run(self, source_dir: str, output_dir: str) -> str:
        # AUTHORIZATION DECISION: Grant reader child only read + list, 60-second TTL
        # tenuo_execute_child_workflow() reads the parent warrant from context,
        # attenuates it to only these tools, and injects it into the child
        data = await tenuo_execute_child_workflow(
            ReaderChild.run,
            args=[source_dir],
            id=f"reader-{workflow.info().workflow_id}",
            tools=["read_file", "list_directory"],  # Subset of parent's tools
            ttl_seconds=60,                          # Shorter than parent
        )

        # AUTHORIZATION DECISION: Grant writer child only write, 60-second TTL
        # Parent had (read + write + list), child gets ONLY (write)
        result = await tenuo_execute_child_workflow(
            WriterChild.run,
            args=[output_dir, data],
            id=f"writer-{workflow.info().workflow_id}",
            tools=["write_file"],     # Just write, no read or list
            ttl_seconds=60,
        )

        return result


# =============================================================================
# Audit
# =============================================================================

def on_audit(event: TemporalAuditEvent):
    symbol = "ALLOW" if event.decision == "ALLOW" else "DENY "
    logger.info(f"  [{symbol}] {event.tool} (wf={event.workflow_id})")


# =============================================================================
# Main
# =============================================================================

async def main():
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])
    logger.info("Connected to Temporal server")

    control_key = SigningKey.generate()
    ingest_key = SigningKey.generate()
    transform_key = SigningKey.generate()

    os.environ["TENUO_KEY_ingest"] = base64.b64encode(ingest_key.secret_key_bytes()).decode()
    os.environ["TENUO_KEY_transform"] = base64.b64encode(transform_key.secret_key_bytes()).decode()

    data_dir = Path("/tmp/tenuo-demo/pipeline")
    source_dir = data_dir / "source"
    output_dir = data_dir / "output"
    source_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    (source_dir / "doc1.txt").write_text("hello world")
    (source_dir / "doc2.txt").write_text("temporal is great")

    task_queue = f"delegation-{uuid.uuid4().hex[:8]}"

    # -- Mint stage-specific warrants (principle of least privilege) --

    # Ingest warrant: read-only access to source directory
    ingest_warrant = (
        Warrant.mint_builder()
        .holder(ingest_key.public_key)
        .capability("read_file", path=Subpath(str(source_dir)))
        .capability("list_directory", path=Subpath(str(source_dir)))
        .ttl(600)
        .mint(control_key)
    )

    # Transform warrant: write-only access to output directory
    transform_warrant = (
        Warrant.mint_builder()
        .holder(transform_key.public_key)
        .capability("write_file", path=Subpath(str(output_dir)), content=Pattern("*"))
        .ttl(600)
        .mint(control_key)
    )

    logger.info(f"Ingest warrant:    {ingest_warrant.id} (read {source_dir})")
    logger.info(f"Transform warrant: {transform_warrant.id} (write {output_dir})")

    worker_interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
        )
    )

    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("tenuo", "tenuo_core")
    )

    async with Worker(
        client, task_queue=task_queue,
        workflows=[IngestWorkflow, TransformWorkflow, OrchestratorWorkflow, ReaderChild, WriterChild],
        activities=[read_file, write_file, list_directory],
        interceptors=[worker_interceptor],
        workflow_runner=sandbox_runner,
    ):
        logger.info("Worker started\n")

        # =============================================================
        # Pattern 1: Per-stage warrant rotation (client-side minting)
        # =============================================================

        logger.info("=== Pattern 1: Per-Stage Warrant Rotation ===\n")

        # -- Stage 1: Ingest (read-only warrant) --
        logger.info("  Stage 1: Ingest (read-only)")
        client_interceptor.set_headers(tenuo_headers(ingest_warrant, "ingest", ingest_key))
        data = await client.execute_workflow(
            IngestWorkflow.run,
            args=[str(source_dir)],
            id=f"ingest-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"  Ingested {len(data)} files")

        # -- Stage 2: Transform (write-only warrant) --
        logger.info("  Stage 2: Transform (write-only)")
        client_interceptor.set_headers(tenuo_headers(transform_warrant, "transform", transform_key))
        result = await client.execute_workflow(
            TransformWorkflow.run,
            args=[str(output_dir), data],
            id=f"transform-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"  Result: {result}")

        # -- Verify: transform warrant cannot read source --
        logger.info("  Verify: transform warrant cannot read (should be denied)")
        try:
            from temporalio.client import WorkflowFailureError
            await client.execute_workflow(
                IngestWorkflow.run,
                args=[str(source_dir)],
                id=f"bad-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
            )
            logger.error("  BUG: should have been denied")
        except (WorkflowFailureError, Exception) as e:
            logger.info(f"  Correctly denied: {type(e).__name__}")

        logger.info("")

        # =============================================================
        # Pattern 2: Inline attenuation via tenuo_execute_child_workflow()
        # =============================================================

        logger.info("=== Pattern 2: Inline Attenuation ===\n")
        logger.info("  tenuo_execute_child_workflow() narrows the parent warrant")
        logger.info("  and injects attenuated headers via the outbound interceptor.\n")

        # Mint a broad warrant covering read + write + list
        orchestrator_key = SigningKey.generate()
        os.environ["TENUO_KEY_orchestrator"] = base64.b64encode(
            orchestrator_key.secret_key_bytes()
        ).decode()

        broad_warrant = (
            Warrant.mint_builder()
            .holder(orchestrator_key.public_key)
            .capability("read_file", path=Subpath(str(data_dir)))
            .capability("write_file", path=Subpath(str(data_dir)), content=Pattern("*"))
            .capability("list_directory", path=Subpath(str(data_dir)))
            .ttl(600)
            .mint(control_key)
        )
        logger.info(f"  Broad warrant: {broad_warrant.id} (read + write + list)")

        # The orchestrator narrows scope for each child via tenuo_execute_child_workflow()
        output2_dir = data_dir / "output2"
        output2_dir.mkdir(parents=True, exist_ok=True)

        client_interceptor.set_headers(
            tenuo_headers(broad_warrant, "orchestrator", orchestrator_key)
        )
        result = await client.execute_workflow(
            OrchestratorWorkflow.run,
            args=[str(source_dir), str(output2_dir)],
            id=f"orchestrator-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"  Result: {result}")

    # -- Verify output --
    logger.info("\nOutput files (Pattern 1):")
    for p in sorted(output_dir.iterdir()):
        logger.info(f"  {p.name}: {p.read_text()!r}")

    logger.info("\nOutput files (Pattern 2):")
    for p in sorted((data_dir / "output2").iterdir()):
        logger.info(f"  {p.name}: {p.read_text()!r}")

    logger.info("\nDone. Both patterns verified.")


if __name__ == "__main__":
    asyncio.run(main())
