"""
Tenuo + Temporal + MCP: two authorization boundaries

**Cloud-shaped variant:** ``cloud_iam_layering.py`` uses the same Temporal→MCP
pattern with ``SecureMCPClient`` + ``cloud_iam_mcp_server.py`` (``s3_get_object``)
instead of the echo tool here.

This example shows defense in depth when a Temporal activity calls an MCP tool
over stdio:

1. **Temporal activity inbound** — ``TenuoWorkerInterceptor`` verifies warrant + PoP in
   Temporal headers before ``invoke_mcp_echo`` runs.
2. **MCP tools/call** — ``MCPVerifier`` on ``temporal_mcp_server.py`` verifies
   warrant + PoP in ``params._meta["tenuo"]`` before ``safe_echo`` runs.

The same holder key signs PoP for both layers. The warrant used inside the
activity must include a capability for the MCP tool name (``safe_echo``) as
well as the Temporal activity name (``invoke_mcp_echo``).

Requirements:
  - Python 3.10+
  - uv pip install "tenuo[temporal,mcp]"

Usage:
  Terminal 1: temporal server start-dev
  Terminal 2: python temporal_mcp_layering.py

This demo sets process-local warrant material for the activity (see
``_register_activity_mcp_context``). In production, load holder keys and
warrants from your KeyResolver / policy service instead.
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

from tenuo import SigningKey, Subpath, Warrant
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

# Demo-only: activity reads warrant + key + server path from this dict (set in main()).
# Resetting this between scenarios is unsafe under concurrent workflows (race on the
# shared dict). Production code should resolve holder keys via KeyResolver and obtain
# warrants from a policy or issuance service, not process globals.
_ACTIVITY_MCP_CONTEXT: Dict[str, Any] = {}

MSG_PREFIX = "demo/"


def _register_activity_mcp_context(
    *,
    warrant: Warrant,
    signing_key: SigningKey,
    control_key: SigningKey,
    server_script: Path,
) -> None:
    """Populate process-local context for ``invoke_mcp_echo`` (demo pattern)."""
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
async def invoke_mcp_echo(message: str) -> str:
    """Call MCP ``safe_echo`` via stdio. Tenuo gates Temporal first; MCP second."""
    if not MCP_AVAILABLE or SecureMCPClient is None:
        return "[skip] Install MCP: uv pip install 'tenuo[mcp]'"

    ctx = _ACTIVITY_MCP_CONTEXT
    warrant = ctx.get("warrant")
    signing_key = ctx.get("signing_key")
    issuer_hex = ctx.get("issuer_pk_hex")
    script = ctx.get("server_script")
    if not all((warrant, signing_key, issuer_hex, script)):
        return "[demo misconfig] activity MCP context not set"

    env = {**os.environ, "TENUO_TEMPORAL_MCP_TRUSTED_ROOT_HEX": str(issuer_hex)}

    async with SecureMCPClient(
        command=sys.executable,
        args=[str(script)],
        env=env,
        inject_warrant=True,
    ) as client:
        with warrant_scope(cast(Warrant, warrant)), key_scope(cast(SigningKey, signing_key)):
            blocks = await client.call_tool(
                "safe_echo",
                {"message": message},
                warrant_context=False,
                inject_warrant=True,
            )
    return _tool_result_to_text(blocks)


@workflow.defn
class TemporalMcpWorkflow:
    @workflow.run
    async def run(self, message: str) -> str:
        return await workflow.execute_activity(
            invoke_mcp_echo,
            args=[message],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


def on_audit(event: TemporalAuditEvent) -> None:
    if event.decision == "ALLOW":
        logger.info("  ALLOW  %s", event.tool)
    else:
        logger.warning("  DENY   %s: %s", event.tool, event.denial_reason)


async def main() -> None:
    if not MCP_AVAILABLE:
        logger.error("MCP not available. Install: uv pip install 'tenuo[mcp]'")
        return

    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    os.environ["TENUO_KEY_agent_mcp"] = base64.b64encode(
        agent_key.secret_key_bytes()
    ).decode()
    os.environ["TENUO_ENV"] = "development"

    server_script = Path(__file__).resolve().parent / "temporal_mcp_server.py"
    if not server_script.is_file():
        logger.error("Missing %s", server_script)
        return

    # Full warrant: Temporal activity + MCP tool (same message prefix).
    warrant_both = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("invoke_mcp_echo", message=Subpath(MSG_PREFIX))
        .capability("safe_echo", message=Subpath(MSG_PREFIX))
        .ttl(3600)
        .mint(control_key)
    )

    # Temporal-only: MCP server should deny safe_echo.
    warrant_temporal_only = (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("invoke_mcp_echo", message=Subpath(MSG_PREFIX))
        .ttl(3600)
        .mint(control_key)
    )

    task_queue = f"temporal-mcp-demo-{uuid.uuid4().hex[:8]}"
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
        workflows=[TemporalMcpWorkflow],
        activities=[invoke_mcp_echo],
    ):
        ok_msg = f"{MSG_PREFIX}hello"

        # --- Both boundaries allow ---
        _register_activity_mcp_context(
            warrant=warrant_both,
            signing_key=agent_key,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Both Temporal and MCP authorize ===")
        out = await execute_workflow_authorized(
            client=client,
            workflow_run_fn=TemporalMcpWorkflow.run,
            workflow_id=f"mcp-ok-{uuid.uuid4().hex[:8]}",
            warrant=warrant_both,
            key_id="agent_mcp",
            args=[ok_msg],
            task_queue=task_queue,
        )
        logger.info("Result: %s\n", out)

        # --- Temporal allows, MCP denies (no safe_echo capability) ---
        _register_activity_mcp_context(
            warrant=warrant_temporal_only,
            signing_key=agent_key,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Temporal allows activity; MCP denies tool (no safe_echo cap) ===")
        wf_mcp_deny = f"mcp-inner-deny-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
            wf_mcp_deny, tenuo_headers(warrant_temporal_only, "agent_mcp")
        )
        try:
            inner = await client.execute_workflow(
                TemporalMcpWorkflow.run,
                args=[ok_msg],
                id=wf_mcp_deny,
                task_queue=task_queue,
            )
            if isinstance(inner, str) and inner.startswith("MCP echo:"):
                logger.error("BUG: MCP should have denied (missing safe_echo capability)")
            else:
                logger.info(
                    "MCP denied the tool call and returned an error response; the activity "
                    "completed normally with that denial message (workflow still succeeded): %s",
                    inner,
                )
        except WorkflowFailureError as e:
            logger.info("Workflow failed: %s", e.cause)

        # --- Temporal denies (message outside Subpath) ---
        _register_activity_mcp_context(
            warrant=warrant_both,
            signing_key=agent_key,
            control_key=control_key,
            server_script=server_script,
        )
        logger.info("=== Temporal denies (message outside warrant prefix) ===")
        bad = "other/not-allowed"
        denied_id = f"mcp-temporal-deny-{uuid.uuid4().hex[:8]}"
        plugin.client_interceptor.set_headers_for_workflow(
            denied_id, tenuo_headers(warrant_both, "agent_mcp")
        )
        try:
            await client.execute_workflow(
                TemporalMcpWorkflow.run,
                args=[bad],
                id=denied_id,
                task_queue=task_queue,
            )
            logger.error("BUG: should have been denied at Temporal")
        except WorkflowFailureError as e:
            logger.info("Correctly denied at Temporal: %s", e.cause)


if __name__ == "__main__":
    asyncio.run(main())
