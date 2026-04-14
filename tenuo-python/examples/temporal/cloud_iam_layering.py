"""
Tenuo + Temporal + MCP + IAM: three enforcement layers

The worker process has broad IAM permissions to read any object in an S3 bucket.
This example adds **two** Tenuo boundaries before AWS:

1. **Temporal activity** — ``TenuoPlugin`` verifies warrant + PoP for
   ``read_s3_via_mcp`` with ``bucket`` / ``key`` before the activity runs.
2. **MCP tool** — ``MCPVerifier`` on ``cloud_iam_mcp_server.py`` verifies the
   same holder's warrant + PoP for ``s3_get_object`` before ``GetObject``.
3. **IAM** — AWS still enforces the worker role at the API.

So the activity never imports boto3: it only calls ``SecureMCPClient`` to invoke
``s3_get_object`` on the MCP server. Even trusted activity code cannot reach S3
except through MCP with an independently verified warrant.

This is the same Temporal→MCP pattern as ``temporal_mcp_layering.py`` (echo
server); here the tool is cloud-shaped (S3).

Scenarios:
  - Worker IAM: s3:GetObject on my-data-bucket/* (all objects)
  - Tenant A warrant: ``read_s3_via_mcp`` + ``s3_get_object`` on
    my-data-bucket/data/tenant-a/*
  - Tenant B warrant: same tools on my-data-bucket/data/tenant-b/*

Requirements:
  - Python 3.10+
  - uv pip install "tenuo[temporal,mcp]"
  - For real S3 (MCP server process): uv pip install boto3 and AWS credentials

Usage:
  temporal server start-dev          # Terminal 1
  AWS_PROFILE=your-profile python cloud_iam_layering.py   # Terminal 2

  Without AWS credentials:
  TENUO_DEMO_DRY_RUN=1 python cloud_iam_layering.py

  The MCP server subprocess skips boto3 in dry-run and returns a synthetic body.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, cast

if sys.version_info < (3, 10):
    raise SystemExit("This example requires Python 3.10+ (MCP SDK).")

try:
    from temporalio import activity, workflow
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.common import RetryPolicy
    from temporalio.worker import Worker
except ImportError:
    raise SystemExit("Install temporalio: uv pip install temporalio")

try:
    from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient
except ImportError:
    MCP_AVAILABLE = False
    SecureMCPClient = None  # type: ignore[misc, assignment]

from tenuo import Exact, SigningKey, Subpath, Warrant
from tenuo.decorators import key_scope, warrant_scope
from tenuo.temporal import (
    EnvKeyResolver,
    TemporalAuditEvent,
    TenuoPluginConfig,
    TenuoTemporalPlugin,
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

# Demo-only: activity reads warrant + key + server path from this dict (set in main()).
# Production: resolve via KeyResolver / policy service instead of process globals.
_ACTIVITY_MCP_CONTEXT: Dict[str, Any] = {}


def _register_activity_mcp_context(
    *,
    warrant: Warrant,
    signing_key: SigningKey,
    control_key: SigningKey,
    server_script: Path,
) -> None:
    _ACTIVITY_MCP_CONTEXT.clear()
    _ACTIVITY_MCP_CONTEXT.update(
        warrant=warrant,
        signing_key=signing_key,
        issuer_pk_hex=bytes(control_key.public_key_bytes()).hex(),
        server_script=server_script.resolve(),
    )


def _tool_result_to_text(blocks: Any) -> str:
    parts: list[str] = []
    for b in blocks or []:
        t = getattr(b, "text", None)
        if t:
            parts.append(str(t))
    return "\n".join(parts)


@activity.defn
async def read_s3_via_mcp(bucket: str, key: str) -> str:
    """Read S3 via MCP ``s3_get_object`` — Temporal Tenuo first, MCP Tenuo second."""
    if not MCP_AVAILABLE or SecureMCPClient is None:
        return "[skip] Install MCP: uv pip install 'tenuo[mcp]'"

    ctx = _ACTIVITY_MCP_CONTEXT
    warrant = ctx.get("warrant")
    signing_key = ctx.get("signing_key")
    issuer_hex = ctx.get("issuer_pk_hex")
    script = ctx.get("server_script")
    if not all((warrant, signing_key, issuer_hex, script)):
        return "[demo misconfig] activity MCP context not set"

    env = {
        **os.environ,
        "TENUO_CLOUD_IAM_MCP_TRUSTED_ROOT_HEX": str(issuer_hex),
    }
    if DRY_RUN:
        env["TENUO_DEMO_DRY_RUN"] = "1"

    async with SecureMCPClient(
        command=sys.executable,
        args=[str(script)],
        env=env,
        inject_warrant=True,
    ) as client:
        with warrant_scope(cast(Warrant, warrant)), key_scope(cast(SigningKey, signing_key)):
            blocks = await client.call_tool(
                "s3_get_object",
                {"bucket": bucket, "key": key},
                warrant_context=False,
                inject_warrant=True,
            )
    return _tool_result_to_text(blocks)


@workflow.defn
class CloudIamLayeringWorkflow:
    """Reads an S3 object through MCP. Authorization at Temporal + MCP."""

    @workflow.run
    async def run(self, bucket: str, key: str) -> str:
        return await workflow.execute_activity(
            read_s3_via_mcp,
            args=[bucket, key],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


def on_audit(event: TemporalAuditEvent) -> None:
    if event.decision == "ALLOW":
        logger.info("  ALLOW  %s", event.tool)
    else:
        logger.warning("  DENY   %s: %s", event.tool, event.denial_reason)


def _warrant_both(
    *,
    control_key: SigningKey,
    agent_key: SigningKey,
    bucket: str,
    key_prefix: str,
) -> Warrant:
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability(
            "read_s3_via_mcp",
            bucket=Exact(bucket),
            key=Subpath(key_prefix),
        )
        .capability(
            "s3_get_object",
            bucket=Exact(bucket),
            key=Subpath(key_prefix),
        )
        .ttl(3600)
        .mint(control_key)
    )


async def main() -> None:
    if not MCP_AVAILABLE:
        logger.error("MCP not available. Install: uv pip install 'tenuo[mcp]'")
        return

    BUCKET = "my-data-bucket"
    TENANT_A_PREFIX = "data/tenant-a/"
    TENANT_B_PREFIX = "data/tenant-b/"
    key_outside_tenant_a = f"{TENANT_B_PREFIX}confidential.csv"

    control_key = SigningKey.generate()
    agent_key_a = SigningKey.generate()
    agent_key_b = SigningKey.generate()

    os.environ["TENUO_KEY_agent_a"] = base64.b64encode(
        agent_key_a.secret_key_bytes()
    ).decode()
    os.environ["TENUO_KEY_agent_b"] = base64.b64encode(
        agent_key_b.secret_key_bytes()
    ).decode()
    os.environ.setdefault("TENUO_ENV", "development")

    server_script = Path(__file__).resolve().parent / "cloud_iam_mcp_server.py"
    if not server_script.is_file():
        logger.error("Missing %s", server_script)
        return

    warrant_tenant_a = _warrant_both(
        control_key=control_key,
        agent_key=agent_key_a,
        bucket=BUCKET,
        key_prefix=TENANT_A_PREFIX,
    )
    warrant_tenant_b = _warrant_both(
        control_key=control_key,
        agent_key=agent_key_b,
        bucket=BUCKET,
        key_prefix=TENANT_B_PREFIX,
    )
    # Temporal activity only — MCP should deny s3_get_object (mirrors temporal_mcp_layering).
    warrant_a_temporal_only = (
        Warrant.mint_builder()
        .holder(agent_key_a.public_key)
        .capability(
            "read_s3_via_mcp",
            bucket=Exact(BUCKET),
            key=Subpath(TENANT_A_PREFIX),
        )
        .ttl(3600)
        .mint(control_key)
    )

    logger.info(
        "Warrants %s (tenant A) and %s (tenant B) — bucket=%r (MCP server: %s)",
        warrant_tenant_a.id,
        warrant_tenant_b.id,
        BUCKET,
        "dry-run" if DRY_RUN else "live S3",
    )

    task_queue = f"cloud-iam-mcp-demo-{uuid.uuid4().hex[:8]}"
    plugin = TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            on_denial="raise",
            trusted_roots=[control_key.public_key],
            strict_mode=True,
            audit_callback=on_audit,
        )
    )
    client = await Client.connect("localhost:7233", plugins=[plugin])

    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[CloudIamLayeringWorkflow],
        activities=[read_s3_via_mcp],
    ):
        layers = "Temporal + MCP + IAM" if not DRY_RUN else "Temporal + MCP (dry-run) + IAM"
        logger.info("Worker started — %s — IAM role: s3:GetObject on %s/*\n", layers, BUCKET)

        # --- Authorized: both Temporal and MCP allow ---
        _register_activity_mcp_context(
            warrant=warrant_tenant_a,
            signing_key=agent_key_a,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Authorized (tenant A, key within prefix) ===")
        result = await execute_workflow_authorized(
            client=client,
            workflow_run_fn=CloudIamLayeringWorkflow.run,
            workflow_id=f"cloud-allowed-{uuid.uuid4().hex[:8]}",
            warrant=warrant_tenant_a,
            key_id="agent_a",
            args=[BUCKET, f"{TENANT_A_PREFIX}report.csv"],
            task_queue=task_queue,
        )
        logger.info("Result: %s\n", result)

        # --- Temporal denies: key outside tenant A prefix ---
        _register_activity_mcp_context(
            warrant=warrant_tenant_a,
            signing_key=agent_key_a,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Denied at Temporal (tenant A warrant, key outside prefix) ===")
        denied_id = f"cloud-denied-outside-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
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

        # --- Cross-tenant: Temporal denies ---
        _register_activity_mcp_context(
            warrant=warrant_tenant_b,
            signing_key=agent_key_b,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Cross-tenant (tenant B warrant, tenant A object) ===")
        cross_id = f"cloud-denied-cross-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
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

        # --- Temporal allows; MCP denies (no s3_get_object capability) ---
        _register_activity_mcp_context(
            warrant=warrant_a_temporal_only,
            signing_key=agent_key_a,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info(
            "=== Temporal allows activity; MCP denies tool (missing s3_get_object cap) ==="
        )
        wf_mcp = f"cloud-mcp-deny-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
            wf_mcp, tenuo_headers(warrant_a_temporal_only, "agent_a")
        )
        try:
            inner = await client.execute_workflow(
                CloudIamLayeringWorkflow.run,
                args=[BUCKET, f"{TENANT_A_PREFIX}report.csv"],
                id=wf_mcp,
                task_queue=task_queue,
            )
            if "MCP authorization denied" in str(inner) or "denied" in str(inner).lower():
                logger.info(
                    "MCP denied the tool call; activity returned server message (workflow ok): %s",
                    inner,
                )
            else:
                logger.info("Activity result: %s", inner)
        except WorkflowFailureError as e:
            logger.info("Workflow failed: %s", e.cause)


if __name__ == "__main__":
    asyncio.run(main())
