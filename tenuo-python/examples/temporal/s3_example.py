"""
Tenuo + Temporal: Constraining Cloud API Access

The worker process has broad IAM permissions to read any object in an S3
bucket. Tenuo enforces at the activity dispatch layer that this specific
workflow can only read objects within an allowed key prefix — before boto3
is ever called.

Key insight: infrastructure permissions (IAM role) and application-level
authorization (Tenuo warrant) are independent layers. A valid IAM session
does not automatically mean the workflow is allowed to access that resource.

Scenario:
  - Worker IAM role: s3:GetObject on my-data-bucket/* (all objects)
  - Tenant A's warrant: read_s3_object on my-data-bucket/data/tenant-a/*
  - Result: accessing data/tenant-b/ is denied by Tenuo before S3 is called

Requirements:
    pip install "tenuo[temporal]" boto3

Usage:
    temporal server start-dev          # Terminal 1
    AWS_PROFILE=your-profile python s3_example.py   # Terminal 2

    To run without real AWS credentials, set TENUO_DEMO_DRY_RUN=1 and the
    S3 activity will be mocked.
"""

import asyncio
import base64
import logging
import os
import uuid
from datetime import timedelta

try:
    from temporalio import activity, workflow
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.common import RetryPolicy
    from temporalio.worker import Worker
except ImportError:
    raise SystemExit("Install temporalio: pip install temporalio")

from tenuo_core import Exact, Subpath

from tenuo import SigningKey, Warrant
from tenuo.temporal import (
    TenuoClientInterceptor,
    TenuoPlugin,
    TenuoPluginConfig,
    TemporalAuditEvent,
    execute_workflow_authorized,
    EnvKeyResolver,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
logging.getLogger("temporalio.activity").setLevel(logging.ERROR)
logging.getLogger("temporalio.worker").setLevel(logging.ERROR)

DRY_RUN = os.environ.get("TENUO_DEMO_DRY_RUN") == "1"


# =============================================================================
# Activity — worker has broad IAM access, but Tenuo gates dispatch
# =============================================================================

@activity.defn
async def read_s3_object(bucket: str, key: str) -> str:
    """Read an S3 object.

    The worker's IAM role grants s3:GetObject on the entire bucket.
    Tenuo enforces prefix-level restrictions BEFORE this function runs.
    """
    if DRY_RUN:
        return f"[dry-run] would read s3://{bucket}/{key}"

    try:
        import boto3  # type: ignore[import-not-found]
        s3 = boto3.client("s3")
        response = s3.get_object(Bucket=bucket, Key=key)
        return response["Body"].read().decode("utf-8")
    except ImportError:
        return f"[boto3 not installed] s3://{bucket}/{key}"


# =============================================================================
# Workflow — standard Temporal API, zero Tenuo-specific code
# =============================================================================

@workflow.defn
class S3ReaderWorkflow:
    """Reads an S3 object. Authorization is enforced transparently by Tenuo."""

    @workflow.run
    async def run(self, bucket: str, key: str) -> str:
        return await workflow.execute_activity(
            read_s3_object,
            args=[bucket, key],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


# =============================================================================
# Audit
# =============================================================================

def on_audit(event: TemporalAuditEvent) -> None:
    if event.decision == "ALLOW":
        logger.info("  ALLOW  bucket=%r key=%r", *list(event.arguments.values())[:2])
    else:
        logger.warning(
            "  DENY   %s — %s", event.tool, event.denial_reason
        )


# =============================================================================
# Main
# =============================================================================

async def main() -> None:
    BUCKET = "my-data-bucket"
    ALLOWED_PREFIX = "data/tenant-a/"

    # --- Keys ---
    control_key = SigningKey.generate()   # Issuer: authorization team
    agent_key = SigningKey.generate()     # Holder: this worker process

    os.environ["TENUO_KEY_agent1"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()

    # --- Warrant: tenant A can only read objects inside data/tenant-a/ ---
    # The worker's IAM role covers the whole bucket; the warrant narrows that.
    warrant = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability(
            "read_s3_object",
            bucket=Exact(BUCKET),          # must be this exact bucket
            key=Subpath(ALLOWED_PREFIX),   # key must start with this prefix
        )
        .ttl(3600)
        .mint(control_key)
    )
    logger.info(
        "Warrant %s — bucket=%r key prefix=%r", warrant.id, BUCKET, ALLOWED_PREFIX
    )

    task_queue = f"s3-demo-{uuid.uuid4().hex[:8]}"

    key_resolver = EnvKeyResolver()
    key_resolver.preload_keys(["agent1"])

    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    worker_interceptor = TenuoPlugin(
        TenuoPluginConfig(
            key_resolver=key_resolver,
            on_denial="raise",
            trusted_roots=[control_key.public_key],
            strict_mode=True,
            activity_fns=[read_s3_object],  # required: warrant uses named constraints
            audit_callback=on_audit,
        )
    )

    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[S3ReaderWorkflow],
        activities=[read_s3_object],
        interceptors=[worker_interceptor],
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                "tenuo", "tenuo_core"
            )
        ),
    ):
        logger.info("Worker started (IAM role: s3:GetObject on %s/*)\n", BUCKET)

        # --- Authorized: key is within the allowed prefix ---
        logger.info("=== Authorized access (key within warrant prefix) ===")
        result = await execute_workflow_authorized(
            client=client,
            client_interceptor=client_interceptor,
            workflow_run_fn=S3ReaderWorkflow.run,
            workflow_id=f"s3-allowed-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            key_id="agent1",
            args=[BUCKET, f"{ALLOWED_PREFIX}report.csv"],
            task_queue=task_queue,
        )
        logger.info("Result: %s\n", result)

        # --- Blocked: key is outside the allowed prefix ---
        # The worker's IAM role WOULD allow this — Tenuo blocks it first.
        logger.info("=== Denied access (key outside warrant prefix) ===")
        logger.info("Worker IAM role permits this; Tenuo warrant does not.")
        denied_id = f"s3-denied-{uuid.uuid4().hex[:8]}"
        client_interceptor.set_headers_for_workflow(
            denied_id, __import__("tenuo.temporal", fromlist=["tenuo_headers"]).tenuo_headers(warrant, "agent1")
        )
        try:
            await client.execute_workflow(
                S3ReaderWorkflow.run,
                args=[BUCKET, "data/tenant-b/confidential.csv"],
                id=denied_id,
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied")
        except WorkflowFailureError as e:
            logger.info("Correctly denied — %s", e.cause)
        except Exception as e:
            logger.info("Correctly denied — %s", e)

        logger.info(
            "\nTenuo blocked access to data/tenant-b/ even though the worker's"
            " IAM role would have allowed it."
        )


if __name__ == "__main__":
    asyncio.run(main())
