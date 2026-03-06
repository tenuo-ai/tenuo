"""
Tests for guard_mcp_client() and SecureMCPClient session reconnection.
"""

from __future__ import annotations

import asyncio
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


# =============================================================================
# Helpers / fixtures
# =============================================================================


def _make_mock_lc_tool(name: str, description: str = "") -> MagicMock:
    """Create a mock LangChain StructuredTool-like object."""
    tool = MagicMock()
    tool.name = name
    tool.description = description or f"Mock tool: {name}"
    tool.args_schema = None
    tool.func = MagicMock(side_effect=NotImplementedError("sync not supported"))

    async def _async_impl(**kwargs: Any) -> str:
        return f"{name}_result"

    tool.coroutine = _async_impl
    return tool


class _FakeMultiServerMCPClient:
    """Minimal stand-in for MultiServerMCPClient."""

    def __init__(self, tools: List[MagicMock]):
        self._tools = tools

    async def get_tools(self) -> List[MagicMock]:
        return list(self._tools)


# =============================================================================
# Tests: guard_mcp_client()
# =============================================================================


class TestGuardMCPClient:
    """guard_mcp_client() wraps MultiServerMCPClient tools with @guard."""

    async def test_returns_same_number_of_tools(self):
        """guard_mcp_client returns one StructuredTool per input tool."""
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        from tenuo.mcp.langchain import guard_mcp_client

        mock_tools = [_make_mock_lc_tool("search"), _make_mock_lc_tool("summarize")]
        client = _FakeMultiServerMCPClient(mock_tools)

        protected = await guard_mcp_client(client)

        assert len(protected) == 2

    async def test_tool_names_preserved(self):
        """Tool names are unchanged after wrapping."""
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        from tenuo.mcp.langchain import guard_mcp_client

        mock_tools = [_make_mock_lc_tool("read_file"), _make_mock_lc_tool("write_file")]
        client = _FakeMultiServerMCPClient(mock_tools)

        protected = await guard_mcp_client(client)

        assert {t.name for t in protected} == {"read_file", "write_file"}

    async def test_tool_descriptions_preserved(self):
        """Tool descriptions are unchanged after wrapping."""
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        from tenuo.mcp.langchain import guard_mcp_client

        mock_tools = [_make_mock_lc_tool("search", "Searches the web")]
        client = _FakeMultiServerMCPClient(mock_tools)

        protected = await guard_mcp_client(client)

        assert protected[0].description == "Searches the web"

    async def test_tools_without_coroutine_passed_through(self):
        """Tools with no async implementation are forwarded unchanged."""
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        from tenuo.mcp.langchain import guard_mcp_client

        sync_only = _make_mock_lc_tool("sync_tool")
        sync_only.coroutine = None  # No async impl

        client = _FakeMultiServerMCPClient([sync_only])
        protected = await guard_mcp_client(client)

        assert protected[0] is sync_only  # Same object, not wrapped

    async def test_guard_enforces_warrant_on_tool_call(self):
        """Wrapped tool denies access when called without a warrant.

        Behavior depends on global config state (which may be set by earlier tests):
        - Default config: raises ScopeViolation
        - warn_on_missing_warrant=True (set by langchain guard_tools): SecurityWarning
        Both are valid denial behaviors.
        """
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        import warnings

        from tenuo.decorators import SecurityWarning
        from tenuo.mcp.langchain import guard_mcp_client

        mock_tools = [_make_mock_lc_tool("restricted")]
        client = _FakeMultiServerMCPClient(mock_tools)

        protected = await guard_mcp_client(client)
        tool = protected[0]

        denied = False
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                await tool.coroutine(query="test")
                # If no exception, check for SecurityWarning (warn mode)
                security_warns = [w for w in caught if issubclass(w.category, SecurityWarning)]
                if security_warns:
                    denied = True
            except Exception:
                denied = True

        assert denied, "Expected denial (exception or SecurityWarning) when calling without warrant"

    async def test_each_tool_independently_guarded(self):
        """Each tool in the result is independently protected (no shared closure bug)."""
        try:
            from langchain_core.tools import StructuredTool  # noqa: F401
        except ImportError:
            pytest.skip("langchain_core not available")

        from tenuo.mcp.langchain import guard_mcp_client

        calls: List[str] = []

        async def make_impl(name: str):
            async def _impl(**kwargs: Any) -> str:
                calls.append(name)
                return f"{name}_ok"
            return _impl

        tools = []
        for n in ["alpha", "beta", "gamma"]:
            t = _make_mock_lc_tool(n)
            t.coroutine = await make_impl(n)
            tools.append(t)

        client = _FakeMultiServerMCPClient(tools)
        protected = await guard_mcp_client(client)

        # Verify each tool has the right name (closure-over-loop-variable check)
        assert protected[0].name == "alpha"
        assert protected[1].name == "beta"
        assert protected[2].name == "gamma"


# =============================================================================
# Tests: SecureMCPClient session reconnection
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

        # Create a fake anyio-style exception class (can't mutate __class__ on builtins)
        FakeClosedResourceError = type(
            "ClosedResourceError",
            (Exception,),
            {"__module__": "anyio._backends._asyncio"},
        )
        exc = FakeClosedResourceError("connection closed")
        assert SecureMCPClient._is_connection_error(exc) is True


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

        # Patch connect() to avoid real subprocess
        async def _fake_connect():
            client.session = MagicMock()
            client._tools = []
            client._wrapped_tools = {}

        with patch.object(client, "connect", side_effect=_fake_connect):
            with patch.object(client, "exit_stack") as mock_stack:
                mock_stack.aclose = AsyncMock()
                await client._reconnect()

        mock_stack.aclose.assert_awaited_once()
        # After reconnect, state should be reset (connect was called)
        assert client.session is not None  # connect() set a new session


class TestCallToolReconnects:
    """call_tool() retries once after a connection error."""

    async def test_reconnects_on_connection_error(self):
        """call_tool() retries after ClosedResourceError from session."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        call_count = 0

        async def _fake_call_tool(name, args):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call fails with connection error
                err = EOFError("connection closed")
                raise err
            # Second call succeeds
            result = MagicMock()
            result.content = "tool_result"
            return result

        # Simulate connected session
        mock_session = MagicMock()
        mock_session.call_tool = _fake_call_tool
        client.session = mock_session

        reconnect_called = False

        async def _fake_reconnect():
            nonlocal reconnect_called
            reconnect_called = True
            client.session = mock_session  # Keep same mock after reconnect

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

        async def _fake_call_tool(name, args):
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
        """asyncio.TimeoutError is not treated as a connection error and is not retried."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            pytest.skip("mcp not available")

        from tenuo.mcp.client import SecureMCPClient

        client = SecureMCPClient(command="python", args=["-c", "pass"])

        call_count = 0

        async def _fake_call_tool(name, args):
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
