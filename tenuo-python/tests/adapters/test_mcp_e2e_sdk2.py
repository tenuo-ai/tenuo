"""End-to-end coverage of :class:`~tenuo.mcp.SecureMCPClient` on MCP SDK 2.x.

The stdio fixtures under ``examples/mcp/`` drive the 1.x decorator API that 2.0
restructured, so ``test_mcp_integration.py`` is skipped on the 2.x line.  The
client itself is supported on both lines, though, and these tests keep it
covered against a real server rather than a patched transport.

The denial tests matter most.  MCP 2.0 renamed ``CallToolResult.isError`` to
``is_error``, so a client reading the old name saw ``False`` and handed a
server-side authorization denial back to the caller as a successful call.
Nothing caught it, because every existing denial test either stubbed the
response or blocked client-side before a request was sent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from .._mcp_sdk_support import MCP_SDK2_SERVER_AVAILABLE, MCP_SDK2_SERVER_SKIP_REASON

pytestmark = pytest.mark.skipif(
    not MCP_SDK2_SERVER_AVAILABLE, reason=MCP_SDK2_SERVER_SKIP_REASON
)

SERVER_SCRIPT = Path(__file__).resolve().parent.parent / "fixtures" / "mcp2_stdio_server.py"


def _client():
    from tenuo.mcp import SecureMCPClient

    return SecureMCPClient(command=sys.executable, args=[str(SERVER_SCRIPT)])


@pytest.mark.asyncio
async def test_client_connects_and_discovers_tools() -> None:
    async with _client() as client:
        assert client.session is not None
        names = [tool.name for tool in await client.get_tools()]

    assert "read_file" in names
    assert "list_directory" in names


@pytest.mark.asyncio
async def test_successful_call_returns_content(tmp_path: Path) -> None:
    target = tmp_path / "note.txt"
    target.write_text("hello from 2.x")

    async with _client() as client:
        content = await client.call_tool(
            "read_file", {"path": str(target)}, warrant_context=False
        )

    assert "hello from 2.x" in content[0].text


@pytest.mark.asyncio
async def test_server_denial_is_not_reported_as_success() -> None:
    """A denial must raise, never return content.

    This is the regression test for the fail-open: on 2.x the old
    ``getattr(response, "isError", False)`` check evaluated to ``False``, so this
    call returned the denial text as though the tool had run.
    """
    from tenuo.exceptions import MCPToolCallError

    async with _client() as client:
        with pytest.raises(MCPToolCallError) as excinfo:
            await client.call_tool(
                "always_denied", {"path": "/etc/passwd"}, warrant_context=False
            )

    assert excinfo.value.structured_content == {
        "tenuo": {"code": -32003, "tool": "always_denied"}
    }


@pytest.mark.asyncio
async def test_insufficient_approvals_denial_maps_to_approval_required() -> None:
    """``-32002`` is the retryable signal, so it must not collapse into a generic error."""
    from tenuo.mcp.server import MCPApprovalRequired

    async with _client() as client:
        with pytest.raises(MCPApprovalRequired) as excinfo:
            await client.call_tool(
                "needs_approval", {"path": "/etc/passwd"}, warrant_context=False
            )

    assert excinfo.value.got == 1
    assert excinfo.value.need == 2


@pytest.mark.asyncio
async def test_denial_can_be_returned_instead_of_raised() -> None:
    """``raise_on_tool_error=False`` still has to recognise the error to honour it."""
    async with _client() as client:
        content = await client.call_tool(
            "always_denied",
            {"path": "/etc/passwd"},
            warrant_context=False,
            raise_on_tool_error=False,
        )

    assert "not authorized" in content[0].text
