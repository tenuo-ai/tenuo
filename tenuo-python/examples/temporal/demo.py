"""
Tenuo-Temporal Integration Demo - Transparent Authorization

Demonstrates TRANSPARENT warrant-based authorization for Temporal workflows.

Two patterns are shown side-by-side:

  Pattern A — Standard Temporal API (zero workflow changes):
    workflow.execute_activity() works exactly as normal. The TenuoPlugin
    intercepts each call, computes PoP inline with deterministic timing,
    and injects warrant + signature into activity headers. No Tenuo imports
    needed in the workflow.

  Pattern B — AuthorizedWorkflow base class (recommended):
    Extends AuthorizedWorkflow and uses self.execute_authorized_activity().
    Validates warrant headers at workflow start (fail-fast), then signs
    each activity via the same transparent PoP mechanism.

Both patterns enforce the same warrant constraints — the choice is a matter
of preference and how early you want a missing-warrant error to surface.

IMPORTANT — Do NOT call warrant.sign() directly in workflows:
  ❌ BAD:  pop = warrant.sign(key, tool, args, timestamp)  # Non-deterministic!
  ✅ GOOD: await workflow.execute_activity(...)            # Interceptor handles it

Requirements:
    uv pip install "tenuo[temporal]"

Usage:
    temporal server start-dev   # Terminal 1
    python demo.py              # Terminal 2
"""

import asyncio
import base64
import logging
import os
import uuid
from datetime import timedelta
from pathlib import Path

# Temporal imports
try:
    from temporalio import activity, workflow
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.common import RetryPolicy
    from temporalio.worker import Worker
except ImportError:
    raise SystemExit("Install temporalio: uv pip install temporalio")

# Tenuo imports
from tenuo import Pattern, Subpath

from tenuo import SigningKey, Warrant
from tenuo.temporal import (
    AuthorizedWorkflow,
    EnvKeyResolver,
    TemporalAuditEvent,
    TenuoPluginConfig,
    TenuoTemporalPlugin,
    execute_workflow_authorized,
    tenuo_headers,
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)


# =============================================================================
# Activities (Tools)
# =============================================================================

@activity.defn
async def read_file(path: str) -> str:
    """Read file contents — protected by Tenuo warrant (read_file capability)."""
    return Path(path).read_text()


@activity.defn
async def write_file(path: str, content: str) -> str:
    """Write file — protected by Tenuo warrant (write_file capability)."""
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes to {path}"


@activity.defn
async def list_directory(path: str) -> list[str]:
    """List directory — protected by Tenuo warrant (list_directory capability)."""
    return sorted(str(p) for p in Path(path).iterdir() if p.is_file())


# =============================================================================
# Pattern A — Standard Temporal API (authorization is transparent)
# =============================================================================

@workflow.defn
class ResearchWorkflow:
    """Lists and reads all .txt files in the warranted directory.

    Uses standard workflow.execute_activity() — no Tenuo imports needed.
    The TenuoPlugin computes PoP transparently for every activity call.
    """

    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)

        files = await workflow.execute_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=no_retry,
        )

        results = []
        for file_path in files:
            if file_path.endswith(".txt"):
                content = await workflow.execute_activity(
                    read_file,
                    args=[file_path],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=no_retry,
                )
                results.append(f"{file_path}: {len(content)} chars")

        return f"Processed {len(results)} files"


# =============================================================================
# Pattern B — AuthorizedWorkflow (recommended base class)
# =============================================================================

@workflow.defn
class ProcessAndWriteWorkflow(AuthorizedWorkflow):
    """Reads files and writes a summary — uses AuthorizedWorkflow base class.

    AuthorizedWorkflow validates warrant headers at workflow start (fail-fast
    if headers are missing) and provides self.execute_authorized_activity()
    as a named alternative to workflow.execute_activity().

    Both read_file and write_file capabilities must be in the warrant.
    """

    @workflow.run
    async def run(self, data_dir: str, output_path: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)

        files = await self.execute_authorized_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=no_retry,
        )

        lines = []
        for file_path in files:
            if file_path.endswith(".txt"):
                content = await self.execute_authorized_activity(
                    read_file,
                    args=[file_path],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=no_retry,
                )
                lines.append(f"{Path(file_path).name}: {len(content)} chars")

        summary = "\n".join(lines)
        await self.execute_authorized_activity(
            write_file,
            args=[output_path, summary],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=no_retry,
        )

        return f"Wrote summary of {len(lines)} files to {output_path}"


# =============================================================================
# Audit callback
# =============================================================================

def on_audit(event: TemporalAuditEvent):
    if event.decision == "ALLOW":
        logger.info(f"  ALLOW  {event.tool} (warrant: {event.warrant_id})")
    else:
        logger.warning(f"  DENY   {event.tool} — {event.denial_reason}")


# =============================================================================
# Main
# =============================================================================

async def main():
    # --- Key generation (in production: Vault / KMS) ---
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Publish agent key for the worker's EnvKeyResolver
    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()

    # --- Plugin setup (handles interceptors, sandbox passthrough, and key preloading) ---
    plugin = TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
            strict_mode=True,
        )
    )

    client = await Client.connect("localhost:7233", plugins=[plugin])
    logger.info("Connected to Temporal server")

    # --- Demo data ---
    demo_dir = Path("/tmp/tenuo-demo")
    demo_dir.mkdir(exist_ok=True)
    (demo_dir / "paper1.txt").write_text("Content of paper 1")
    (demo_dir / "paper2.txt").write_text("Content of paper 2")
    (demo_dir / "notes.txt").write_text("Research notes")

    # --- Mint warrant: read + write + list scoped to demo_dir ---
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file",      path=Subpath("/tmp/tenuo-demo"))
        .capability("write_file",     path=Subpath("/tmp/tenuo-demo"), content=Pattern("*"))
        .capability("list_directory", path=Subpath("/tmp/tenuo-demo"))
        .ttl(3600)
        .mint(control_key)
    )
    logger.info(f"Minted warrant {warrant.id}")
    logger.info(f"  Tools:   {warrant.tools}")
    logger.info(f"  Expires: {warrant.expires_at()}")

    task_queue = f"tenuo-demo-{uuid.uuid4().hex[:8]}"

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[ResearchWorkflow, ProcessAndWriteWorkflow],
        activities=[read_file, write_file, list_directory],
    ):
        logger.info("Worker started\n")

        # ── Pattern A: Standard API, sequential read ─────────────────
        logger.info("=== Pattern A: Standard API — sequential read ===")
        result = await execute_workflow_authorized(
            client=client,
            workflow_run_fn=ResearchWorkflow.run,
            workflow_id=f"research-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            key_id="agent1",
            args=[str(demo_dir)],
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}\n")

        # ── Pattern B: AuthorizedWorkflow — read + write ──────────────
        logger.info("=== Pattern B: AuthorizedWorkflow — read + write ===")
        summary_path = str(demo_dir / "summary.txt")
        process_id = f"process-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
            process_id,
            tenuo_headers(warrant, "agent1"),
        )
        result = await client.execute_workflow(
            ProcessAndWriteWorkflow.run,
            args=[str(demo_dir), summary_path],
            id=process_id,
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}")
        logger.info(f"Summary written: {Path(summary_path).read_text()!r}\n")

        # ── Unauthorized access: path outside warrant scope ───────────
        logger.info("=== Unauthorized access (path=/etc — outside warrant scope) ===")
        unauth_id = f"unauth-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
            unauth_id,
            tenuo_headers(warrant, "agent1"),
        )
        try:
            await client.execute_workflow(
                ResearchWorkflow.run,
                args=["/etc"],
                id=unauth_id,
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied!")
        except WorkflowFailureError as e:
            logger.info(f"Correctly denied: {e.cause}")
        except Exception as e:
            logger.info(f"Correctly denied: {e}")


if __name__ == "__main__":
    asyncio.run(main())
