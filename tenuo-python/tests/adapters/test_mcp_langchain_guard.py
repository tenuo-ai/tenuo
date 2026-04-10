"""
Tests for SecureMCPClient session reconnection.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =============================================================================
# Tests: SecureMCPClient._is_connection_error()
# =============================================================================


class TestIsConnectionError:
    """_is_connection_error() identifies recoverable transport failures."""

    def test_eof_error_is_connection_error(self):
        from tenuo.mcp.client import SecureMCPClient

        assert SecureMCPClient._is_connection_error(EOFError()) is True

    def test_os_error_epipe_is_connection_error(self):
        from tenuo.mcp.client import SecureMCPClient

        err = OSError()
        err.errno = 32  # EPIPE
        assert SecureMCPClient._is_connection_error(err) is True

    def test_os_error_econnreset_linux_is_connection_error(self):
        from tenuo.mcp.client import SecureMCPClient

        err = OSError()
        err.errno = 104  # ECONNRESET on Linux
        assert SecureMCPClient._is_connection_error(err) is True

    def test_value_error_is_not_connection_error(self):
        from tenuo.mcp.client import SecureMCPClient

        assert SecureMCPClient._is_connection_error(ValueError("bad")) is False

    def test_runtime_error_is_not_connection_error(self):
        from tenuo.mcp.client import SecureMCPClient

        assert SecureMCPClient._is_connection_error(RuntimeError("boom")) is False

    def test_anyio_closed_resource_detected_by_name(self):
        """anyio.ClosedResourceError is detected via module+type name inspection."""
        from tenuo.mcp.client import SecureMCPClient

        FakeClosedResourceError = type(
            "ClosedResourceError",
            (Exception,),
            {"__module__": "anyio._backends._asyncio"},
        )
        exc = FakeClosedResourceError("connection closed")
        assert SecureMCPClient._is_connection_error(exc) is True


# =============================================================================
# Tests: SecureMCPClient session reconnection
# =============================================================================


@pytest.mark.asyncio
class TestReconnectResetsState:
    """_reconnect() resets session state and reconnects."""

    async def test_reconnect_resets_session(self):
        """After _reconnect(), session, tools, and wrapped_tools are reset then repopulated."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        # Simulate connected state
        client.session = MagicMock()
        client._tools = [MagicMock()]
        client._wrapped_tools = {"some_tool": MagicMock()}

        async def _fake_connect_unlocked():
            client.session = MagicMock()
            client._tools = []
            client._wrapped_tools = {}

        with patch.object(client, "_connect_unlocked", side_effect=_fake_connect_unlocked):
            with patch.object(client, "exit_stack") as mock_stack:
                mock_stack.aclose = AsyncMock()
                await client._reconnect()

        mock_stack.aclose.assert_awaited_once()
        assert client.session is not None


@pytest.mark.asyncio
class TestCallToolReconnects:
    """call_tool() retries once after a connection error."""

    async def test_reconnects_on_connection_error(self):
        """call_tool() retries after a connection error from session."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        call_count = 0

        async def _fake_call_tool(name, args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise EOFError("connection closed")
            result = MagicMock()
            result.content = "tool_result"
            return result

        mock_session = MagicMock()
        mock_session.call_tool = _fake_call_tool
        client.session = mock_session

        reconnect_called = False

        async def _fake_reconnect():
            nonlocal reconnect_called
            reconnect_called = True
            client.session = mock_session

        with patch.object(client, "_reconnect", side_effect=_fake_reconnect):
            with patch.object(client, "_is_connection_error", return_value=True):
                result = await client.call_tool(
                    "test_tool",
                    {"arg": "val"},
                    warrant_context=False,
                )

        assert result == "tool_result"
        assert reconnect_called is True
        assert call_count == 2

    async def test_does_not_retry_on_non_connection_error(self):
        """call_tool() propagates non-connection errors without retrying."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        call_count = 0

        async def _fake_call_tool(name, args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise ValueError("schema validation failed")

        mock_session = MagicMock()
        mock_session.call_tool = _fake_call_tool
        client.session = mock_session

        reconnect_called = False

        async def _fake_reconnect():
            nonlocal reconnect_called
            reconnect_called = True

        with patch.object(client, "_reconnect", side_effect=_fake_reconnect):
            with patch.object(client, "_is_connection_error", return_value=False):
                with pytest.raises(ValueError, match="schema validation failed"):
                    await client.call_tool(
                        "test_tool",
                        {"arg": "val"},
                        warrant_context=False,
                    )

        assert call_count == 1
        assert reconnect_called is False

    async def test_timeout_not_retried(self):
        """asyncio.TimeoutError is not treated as a connection error."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        call_count = 0

        async def _fake_call_tool(name, args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise asyncio.TimeoutError()

        mock_session = MagicMock()
        mock_session.call_tool = _fake_call_tool
        client.session = mock_session

        reconnect_called = False

        async def _fake_reconnect():
            nonlocal reconnect_called
            reconnect_called = True

        with patch.object(client, "_reconnect", side_effect=_fake_reconnect):
            with pytest.raises(asyncio.TimeoutError):
                await client.call_tool(
                    "test_tool",
                    {"arg": "val"},
                    warrant_context=False,
                )

        assert call_count == 1
        assert reconnect_called is False
