"""
Tenuo-Temporal Integration Example

This example demonstrates how to use Tenuo's warrant-based authorization
with Temporal's durable workflow orchestration.

Requirements:
    pip install temporalio tenuo-python

Usage:
    # Start Temporal server (dev mode)
    temporal server start-dev

    # Run this example
    python temporal_example.py
"""

import asyncio
import logging
from datetime import timedelta
from pathlib import Path

# Temporal imports
try:
    from temporalio import activity, workflow
    from temporalio.client import Client
    from temporalio.worker import Worker
except ImportError:
    print("Please install temporalio: pip install temporalio")
    raise

# Tenuo imports
from tenuo_core import SigningKey, IssuanceBuilder
from tenuo.temporal import (
    TenuoInterceptor,
    TenuoInterceptorConfig,
    EnvKeyResolver,
    tenuo_headers,
    current_warrant,
    TemporalAuditEvent,
    ConstraintViolation,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# Activities (Tools)
# =============================================================================

@activity.defn
async def read_file(path: str) -> str:
    """Read file contents - protected by Tenuo."""
    logger.info(f"Reading file: {path}")
    return Path(path).read_text()


@activity.defn
async def write_file(path: str, content: str) -> str:
    """Write file contents - protected by Tenuo."""
    logger.info(f"Writing file: {path}")
    Path(path).write_text(content)
    return f"Wrote {len(content)} bytes to {path}"


@activity.defn
async def list_directory(path: str) -> list[str]:
    """List directory contents - protected by Tenuo."""
    logger.info(f"Listing directory: {path}")
    return [str(p) for p in Path(path).iterdir()]


# =============================================================================
# Workflows
# =============================================================================

@workflow.defn
class ResearchWorkflow:
    """A workflow that researches files within an allowed scope."""

    @workflow.run
    async def run(self, data_dir: str) -> str:
        # Get the warrant for this workflow
        warrant = current_warrant()
        logger.info(f"Workflow running with warrant: {warrant.id()}")
        logger.info(f"Allowed tools: {warrant.tools()}")

        # List files in the data directory
        files = await workflow.execute_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timedelta(seconds=30),
        )

        # Read each file
        results = []
        for file_path in files:
            if file_path.endswith(".txt"):
                content = await workflow.execute_activity(
                    read_file,
                    args=[file_path],
                    start_to_close_timeout=timedelta(seconds=30),
                )
                results.append(f"{file_path}: {len(content)} chars")

        return f"Processed {len(results)} files"


# =============================================================================
# Audit Callback
# =============================================================================

def on_audit(event: TemporalAuditEvent):
    """Log audit events to console."""
    if event.decision == "ALLOW":
        logger.info(
            f"✅ ALLOW: {event.tool} in {event.workflow_type} "
            f"(warrant: {event.warrant_id})"
        )
    else:
        logger.warning(
            f"❌ DENY: {event.tool} in {event.workflow_type} - "
            f"{event.denial_reason}"
        )


# =============================================================================
# Main
# =============================================================================

async def main():
    """Run the example workflow."""
    # Connect to Temporal
    client = await Client.connect("localhost:7233")
    logger.info("Connected to Temporal server")

    # Generate keys for this example
    # In production, these would come from Vault/KMS
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    logger.info("Generated signing keys")

    # Create a warrant authorizing the agent
    # This would normally be issued by a control plane
    from tenuo_core import Subpath

    warrant = (
        IssuanceBuilder()
        .holder(agent_key.public_key())
        .capability("read_file", {"path": Subpath("/tmp/tenuo-demo")})
        .capability("list_directory", {"path": Subpath("/tmp/tenuo-demo")})
        .ttl(3600)  # 1 hour
        .mint(control_key)
    )
    logger.info(f"Created warrant: {warrant.id()}")
    logger.info(f"  Tools: {warrant.tools()}")
    logger.info(f"  Expires: {warrant.expires_at()}")

    # Set up the key resolver
    # For this example, we use EnvKeyResolver
    import os
    import base64

    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()

    # Create the interceptor
    interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            audit_callback=on_audit,
        )
    )

    # Create demo data
    demo_dir = Path("/tmp/tenuo-demo")
    demo_dir.mkdir(exist_ok=True)
    (demo_dir / "paper1.txt").write_text("Content of paper 1")
    (demo_dir / "paper2.txt").write_text("Content of paper 2")
    (demo_dir / "notes.txt").write_text("Research notes")

    # Start the worker with Tenuo interceptor
    async with Worker(
        client,
        task_queue="tenuo-demo-queue",
        workflows=[ResearchWorkflow],
        activities=[read_file, write_file, list_directory],
        interceptors=[interceptor],
    ):
        logger.info("Worker started, executing workflow...")

        # Execute the workflow with the warrant
        result = await client.execute_workflow(
            ResearchWorkflow.run,
            args=[str(demo_dir)],
            id="research-demo-001",
            task_queue="tenuo-demo-queue",
            headers=tenuo_headers(warrant, "agent1"),
        )

        logger.info(f"Workflow completed: {result}")

        # Try to access a file outside the allowed scope - should fail
        logger.info("\n--- Attempting unauthorized access ---")
        try:
            # This should be blocked by Tenuo
            await client.execute_workflow(
                ResearchWorkflow.run,
                args=["/etc"],  # Not in allowed path
                id="research-demo-002",
                task_queue="tenuo-demo-queue",
                headers=tenuo_headers(warrant, "agent1"),
            )
        except ConstraintViolation as e:
            logger.warning(f"Access correctly denied: {e}")


if __name__ == "__main__":
    asyncio.run(main())
