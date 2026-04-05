"""
Tenuo + Temporal: IAM layering (infrastructure vs application authorization)

The worker process has broad IAM permissions to read any object in an S3
bucket. Tenuo enforces at the activity dispatch layer that this specific
workflow can only read objects within an allowed key prefix — before boto3
is ever called.

Key insight: infrastructure permissions (IAM role) and application-level
authorization (Tenuo warrant) are independent layers. A valid IAM session
does not automatically mean the workflow is allowed to access that resource.

Scenarios:
  - Worker IAM role: s3:GetObject on my-data-bucket/* (all objects)
  - Tenant A's warrant: read_s3_object on my-data-bucket/data/tenant-a/*
  - Tenant B's warrant: read_s3_object on my-data-bucket/data/tenant-b/*
  - Same IAM role for all runs; Tenuo isolates tenants at dispatch time

Requirements:
    uv pip install "tenuo[temporal]" boto3

Usage:
    temporal server start-dev          # Terminal 1
    AWS_PROFILE=your-profile python cloud_iam_layering.py   # Terminal 2

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
    raise SystemExit("Install temporalio: uv pip install temporalio")

from tenuo import Exact, SigningKey, Subpath, Warrant
from tenuo.temporal import (
    EnvKeyResolver,
    TenuoClientInterceptor,
    TenuoPlugin,
    TenuoPluginConfig,
    TemporalAuditEvent,
    execute_workflow_authorized,
    tenuo_headers,
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
class CloudIamLayeringWorkflow:
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
        logger.warning("  DENY   %s: %s", event.tool, event.denial_reason)


# =============================================================================
# Main
# =============================================================================

async def main() -> None:
    BUCKET = "my-data-bucket"
    TENANT_A_PREFIX = "data/tenant-a/"
    TENANT_B_PREFIX = "data/tenant-b/"
    # Object outside tenant A's warrant prefix (same worker IAM as allowed reads)
    key_outside_tenant_a = f"{TENANT_B_PREFIX}confidential.csv"

    # --- Keys ---
    control_key = SigningKey.generate()   # Issuer: authorization team
    agent_key_a = SigningKey.generate()   # Holder: tenant A workflow
    agent_key_b = SigningKey.generate()   # Holder: tenant B workflow

    os.environ["TENUO_KEY_agent_a"] = base64.b64encode(
        agent_key_a.secret_key_bytes()
    ).decode()
    os.environ["TENUO_KEY_agent_b"] = base64.b64encode(
        agent_key_b.secret_key_bytes()
    ).decode()

    # --- Warrants: each tenant only reads objects under their prefix ---
    warrant_tenant_a = (
        Warrant.mint_builder()
        .holder(agent_key_a.public_key)
        .capability(
            "read_s3_object",
            bucket=Exact(BUCKET),
            key=Subpath(TENANT_A_PREFIX),
        )
        .ttl(3600)
        .mint(control_key)
    )
    warrant_tenant_b = (
        Warrant.mint_builder()
        .holder(agent_key_b.public_key)
        .capability(
            "read_s3_object",
            bucket=Exact(BUCKET),
            key=Subpath(TENANT_B_PREFIX),
        )
        .ttl(3600)
        .mint(control_key)
    )
    logger.info(
        "Warrants %s (tenant A) and %s (tenant B) — bucket=%r",
        warrant_tenant_a.id,
        warrant_tenant_b.id,
        BUCKET,
    )

    task_queue = f"cloud-iam-demo-{uuid.uuid4().hex[:8]}"

    key_resolver = EnvKeyResolver()
    # EnvKeyResolver must cache holder keys before the worker starts: PoP signing
    # in the workflow sandbox calls resolve_sync(), which cannot read os.environ
    # there (non-deterministic). See EnvKeyResolver.preload_keys in tenuo.temporal.
    key_resolver.preload_keys(["agent_a", "agent_b"])

    from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

    worker_interceptor = TenuoPlugin(
        TenuoPluginConfig(
            key_resolver=key_resolver,
            on_denial="raise",
            trusted_roots=[control_key.public_key],
            strict_mode=True,
            activity_fns=[read_s3_object],
            audit_callback=on_audit,
        )
    )

    client_interceptor = TenuoClientInterceptor()
    client = await Client.connect("localhost:7233", interceptors=[client_interceptor])

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[CloudIamLayeringWorkflow],
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
        logger.info("=== Authorized access (tenant A, key within warrant prefix) ===")
        result = await execute_workflow_authorized(
            client=client,
            client_interceptor=client_interceptor,
            workflow_run_fn=CloudIamLayeringWorkflow.run,
            workflow_id=f"cloud-allowed-{uuid.uuid4().hex[:8]}",
            warrant=warrant_tenant_a,
            key_id="agent_a",
            args=[BUCKET, f"{TENANT_A_PREFIX}report.csv"],
            task_queue=task_queue,
        )
        logger.info("Result: %s\n", result)

        # --- Blocked: tenant A warrant, key outside tenant A prefix ---
        logger.info("=== Denied access (tenant A warrant, key outside its prefix) ===")
        logger.info("Worker IAM role permits this; Tenuo warrant does not.")
        denied_id = f"cloud-denied-outside-{uuid.uuid4().hex[:8]}"
        client_interceptor.set_headers_for_workflow(
            denied_id, tenuo_headers(warrant_tenant_a, "agent_a")
        )
        try:
            await client.execute_workflow(
                CloudIamLayeringWorkflow.run,
                args=[BUCKET, key_outside_tenant_a],
                id=denied_id,
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied")
        except WorkflowFailureError as e:
            logger.info("Correctly denied — %s", e.cause)
        except Exception as e:
            logger.info("Correctly denied — %s", e)

        # --- Cross-tenant: tenant B warrant cannot read tenant A's prefix ---
        logger.info(
            "=== Cross-tenant isolation (tenant B warrant, tenant A object) ==="
        )
        logger.info(
            "Same worker IAM; tenant B is not authorized for %r.",
            TENANT_A_PREFIX,
        )
        cross_id = f"cloud-denied-cross-{uuid.uuid4().hex[:8]}"
        client_interceptor.set_headers_for_workflow(
            cross_id, tenuo_headers(warrant_tenant_b, "agent_b")
        )
        try:
            await client.execute_workflow(
                CloudIamLayeringWorkflow.run,
                args=[BUCKET, f"{TENANT_A_PREFIX}other.csv"],
                id=cross_id,
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied")
        except WorkflowFailureError as e:
            logger.info("Correctly denied — %s", e.cause)
        except Exception as e:
            logger.info("Correctly denied — %s", e)


if __name__ == "__main__":
    asyncio.run(main())
