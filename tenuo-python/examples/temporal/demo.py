"""
Tenuo-Temporal Integration Demo - Transparent Authorization

Demonstrates TRANSPARENT warrant-based authorization for Temporal workflows.
Authorization is completely invisible - just use standard Temporal APIs!

Key features:
  - ✨ NO special wrapper functions needed (workflow.execute_activity just works!)
  - ✨ TenuoInterceptor handles PoP computation transparently
  - ✨ Works with standard Temporal code - zero changes to workflows
  - ✨ Parallel activities via asyncio.gather work perfectly
  - EnvKeyResolver resolves signing keys from environment variables
  - Full cryptographic chain-of-trust validation with PoP

IMPORTANT - Do NOT call warrant.sign() directly in workflows:
  ❌ BAD:  pop = warrant.sign(key, tool, args)  # Non-deterministic!
  ✅ GOOD: await workflow.execute_activity(...)  # Interceptor handles it

The TenuoInterceptor automatically computes PoP with deterministic timestamps
(workflow.now()) to ensure replay safety. Manual sign() calls will use
wall-clock time and cause replay failures.

Requirements:
    pip install temporalio tenuo

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
    from temporalio.client import Client
    from temporalio.common import RetryPolicy
    from temporalio.worker import Worker
except ImportError:
    raise SystemExit("Install temporalio: pip install temporalio")

# Tenuo imports
from tenuo_core import Subpath

from tenuo import SigningKey, Warrant
from tenuo.temporal import (
    EnvKeyResolver,
    TemporalAuditEvent,
    TenuoClientInterceptor,
    TenuoInterceptor,
    TenuoInterceptorConfig,
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
    """Read file — protected by Tenuo warrant."""
    return Path(path).read_text()


@activity.defn
async def write_file(path: str, content: str) -> str:
    """Write file — protected by Tenuo warrant."""
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes to {path}"


@activity.defn
async def list_directory(path: str) -> list[str]:
    """List directory — protected by Tenuo warrant."""
    return [str(p) for p in Path(path).iterdir()]


# =============================================================================
# Workflow — uses STANDARD Temporal API (authorization is transparent!)
# =============================================================================

@workflow.defn
class ResearchWorkflow:
    """Researches files within the scope authorized by its warrant.

    ✨ Notice: This is standard Temporal code! No Tenuo-specific functions.
    The TenuoInterceptor transparently computes PoP for every activity.
    """

    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)

        # ✨ Standard Temporal API - interceptor handles PoP transparently
        files = await workflow.execute_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=no_retry,
        )

        results = []
        for file_path in files:
            if file_path.endswith(".txt"):
                # ✨ Again, standard API - no Tenuo imports needed!
                content = await workflow.execute_activity(
                    read_file,
                    args=[file_path],
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=no_retry,
                )
                results.append(f"{file_path}: {len(content)} chars")

        return f"Processed {len(results)} files"


@workflow.defn
class ParallelResearchWorkflow:
    """Reads multiple files in parallel — each gets its own PoP signature.

    ✨ Parallel activities just work! The interceptor computes PoP inline
    for each activity call, so there's no queue races or signature collision.
    """

    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        timeout = timedelta(seconds=30)

        # ✨ Standard asyncio.gather with standard Temporal API
        # Each interceptor call computes its own PoP - no shared state!
        contents = await asyncio.gather(
            workflow.execute_activity(
                read_file, args=[f"{data_dir}/paper1.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
            workflow.execute_activity(
                read_file, args=[f"{data_dir}/paper2.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
            workflow.execute_activity(
                read_file, args=[f"{data_dir}/notes.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
        )

        total = sum(len(c) for c in contents)
        return f"Parallel read {len(contents)} files ({total} chars)"


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
    # --- Client setup (production TenuoClientInterceptor) ---
    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect(
        "localhost:7233", interceptors=[client_interceptor],
    )
    logger.info("Connected to Temporal server")

    # --- Key generation (in production: Vault / KMS) ---
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    # Publish agent key for the worker's EnvKeyResolver
    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()

    # --- Mint warrant ---
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/tmp/tenuo-demo"))
        .capability("list_directory", path=Subpath("/tmp/tenuo-demo"))
        .ttl(3600)
        .mint(control_key)
    )
    logger.info(f"Minted warrant {warrant.id}")
    logger.info(f"  Tools:   {warrant.tools}")
    logger.info(f"  Expires: {warrant.expires_at()}")

    # Unique task queue per run avoids interference from old Temporal tasks
    task_queue = f"tenuo-demo-{uuid.uuid4().hex[:8]}"

    # --- Demo data ---
    demo_dir = Path("/tmp/tenuo-demo")
    demo_dir.mkdir(exist_ok=True)
    (demo_dir / "paper1.txt").write_text("Content of paper 1")
    (demo_dir / "paper2.txt").write_text("Content of paper 2")
    (demo_dir / "notes.txt").write_text("Research notes")

    # --- Worker setup with production TenuoInterceptor ---
    # Pre-load keys to avoid os.environ access inside Temporal's workflow sandbox
    key_resolver = EnvKeyResolver()
    key_resolver.preload_keys(["agent1"])  # Cache before workflow execution

    worker_interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=key_resolver,
            on_denial="raise",
            audit_callback=on_audit,
            trusted_roots=[control_key.public_key],
            activity_fns=[read_file, write_file, list_directory],
        )
    )

    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner,
        SandboxRestrictions,
    )
    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core",
        )
    )

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[ResearchWorkflow, ParallelResearchWorkflow],
        activities=[read_file, write_file, list_directory],
        interceptors=[worker_interceptor],
        workflow_runner=sandbox_runner,
    ):
        logger.info("Worker started\n")

        # ── Authorized sequential access ─────────────────────────
        logger.info("=== Sequential access (path=/tmp/tenuo-demo) ===")
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent1")
        )

        result = await client.execute_workflow(
            ResearchWorkflow.run,
            args=[str(demo_dir)],
            id=f"research-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}\n")

        # ── Parallel activity execution ──────────────────────────
        logger.info("=== Parallel activities (asyncio.gather) ===")
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent1")
        )

        result = await client.execute_workflow(
            ParallelResearchWorkflow.run,
            args=[str(demo_dir)],
            id=f"parallel-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
        )
        logger.info(f"Result: {result}\n")

        # ── Unauthorized access ──────────────────────────────────
        logger.info("=== Unauthorized access (path=/etc) ===")
        try:
            from temporalio.client import WorkflowFailureError
            await client.execute_workflow(
                ResearchWorkflow.run,
                args=["/etc"],  # outside warrant scope
                id=f"unauth-{uuid.uuid4().hex[:8]}",
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied!")
        except WorkflowFailureError as e:
            logger.info(f"Correctly denied: {e.cause}")
        except Exception as e:
            logger.info(f"Correctly denied: {e}")


if __name__ == "__main__":
    asyncio.run(main())
