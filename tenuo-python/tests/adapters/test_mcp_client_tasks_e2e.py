"""
End-to-end: :class:`SecureMCPClient` drives MCP Tasks (SEP-2663) against a
FastMCP server guarded by :class:`TenuoMiddleware`, over stdio.

Requires the MCP SDK 2.x and FastMCP 4 with ``fastmcp-tasks``; skipped otherwise.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastmcp_tasks")

from tenuo import Capability, SigningKey, configure, mint  # noqa: E402
from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient  # noqa: E402
from tenuo.mcp._compat import MCP_V2  # noqa: E402

pytestmark = [
    pytest.mark.skipif(not (MCP_AVAILABLE and MCP_V2), reason="MCP SDK 2.x not installed"),
    pytest.mark.asyncio,
]

_SERVER = Path(__file__).resolve().parent.parent / "fixtures" / "fastmcp_tasks_e2e_server.py"


def _client(issuer: SigningKey, *, tasks: bool = True) -> SecureMCPClient:
    root = Path(__file__).resolve().parent.parent.parent
    env = {
        **os.environ,
        "TENUO_MCP_E2E_ISSUER_PUB": issuer.public_key.to_bytes().hex(),
        "PYTHONPATH": f"{root}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
    }
    return SecureMCPClient(
        command=sys.executable, args=[str(_SERVER)], env=env, inject_warrant=True, tasks=tasks
    )


def _text(blocks) -> str:
    return "".join(getattr(b, "text", str(b)) for b in blocks)


@pytest.fixture
def issuer() -> SigningKey:
    key = SigningKey.generate()
    configure(issuer_key=key, dev_mode=True)
    return key


async def test_call_tool_polls_a_task_to_its_result(issuer) -> None:
    async with _client(issuer) as client:
        async with mint(Capability("crunch")):
            raw = await client.call_tool("crunch", {"dataset": "d1"}, warrant_context=False)
    assert _text(raw) == "crunched d1"


async def test_call_tool_task_returns_a_signed_handle(issuer) -> None:
    async with _client(issuer) as client:
        async with mint(Capability("crunch")):
            task = await client.call_tool_task("crunch", {"dataset": "d2"}, warrant_context=False)
        # The handle keeps the creating warrant after the scope has closed.
        assert (await task.status()).task_id == task.task_id
        result = await task.result(timeout=30)
    assert _text(result.content) == "crunched d2"


async def test_cancel_is_signed_and_accepted(issuer) -> None:
    async with _client(issuer) as client:
        async with mint(Capability("slow")):
            task = await client.call_tool_task("slow", {}, warrant_context=False)
        await task.cancel()
        final = await task.wait(timeout=30)
    assert final.status == "cancelled"


async def test_without_tasks_the_server_runs_the_call_directly(issuer) -> None:
    async with _client(issuer, tasks=False) as client:
        async with mint(Capability("crunch")):
            raw = await client.call_tool("crunch", {"dataset": "d3"}, warrant_context=False)
        with pytest.raises(ConfigurationError):
            await client.call_tool_task("crunch", {"dataset": "d3"}, warrant_context=False)
    assert _text(raw) == "crunched d3"


async def test_unsigned_handle_is_denied(issuer) -> None:
    """A handle without the creating warrant cannot poll the task."""
    from mcp.shared.exceptions import MCPError

    from tenuo.mcp._tasks_client import TenuoTask

    async with _client(issuer) as client:
        async with mint(Capability("slow")):
            task = await client.call_tool_task("slow", {}, warrant_context=False)
        stranger = TenuoTask(client.session, "slow", task.created, chain=None, key=None)
        with pytest.raises(MCPError, match="No warrant"):
            await stranger.status()
        await asyncio.sleep(1.1)
        await task.cancel()
