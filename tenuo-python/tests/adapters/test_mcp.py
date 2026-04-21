import asyncio
import base64
import os
import tempfile
from contextlib import AsyncExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tenuo_core import CompiledMcpConfig, ExtractionResult, McpConfig

try:
    from tenuo.mcp.client import MCP_AVAILABLE, SecureMCPClient
except ImportError:
    MCP_AVAILABLE = False
    SecureMCPClient = None  # type: ignore

# Sample MCP Config YAML
SAMPLE_CONFIG = """
version: "1"
settings:
  trusted_issuers: []
tools:
  filesystem_read:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
"""


@pytest.fixture
def mcp_config_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(SAMPLE_CONFIG)
        path = f.name
    yield path
    os.unlink(path)


def test_load_mcp_config(mcp_config_file):
    """Test loading McpConfig from a file."""
    config = McpConfig.from_file(mcp_config_file)
    assert config is not None
    # We can't easily inspect the inner Rust struct fields from Python unless exposed,
    # but successful load is a good sign.


def test_compile_mcp_config(mcp_config_file):
    """Test compiling McpConfig."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    assert compiled is not None


def test_extract_constraints(mcp_config_file):
    """Test extracting constraints from arguments."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    # Valid arguments
    args = {"path": "/var/log/syslog", "maxSize": 5000}

    result = compiled.extract_constraints("filesystem_read", args)
    assert isinstance(result, ExtractionResult)
    assert result.tool == "filesystem_read"

    # Check extracted constraints
    # Note: result.constraints is a dict-like object (PyDict)
    constraints = dict(result.constraints)
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 5000


def test_extract_constraints_default_value(mcp_config_file):
    """Test extracting constraints with default values."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    # Missing optional arg (maxSize has default)
    args = {"path": "/var/log/syslog"}

    result = compiled.extract_constraints("filesystem_read", args)
    constraints = dict(result.constraints)
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 1048576  # Default value


def test_extract_constraints_missing_required(mcp_config_file):
    """Test extraction fails when required field is missing."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    # Missing required 'path'
    args = {"maxSize": 5000}

    with pytest.raises(Exception) as excinfo:
        compiled.extract_constraints("filesystem_read", args)

    # The error message comes from Rust, should mention missing field
    assert "Missing required field" in str(excinfo.value)


def test_extract_constraints_unknown_tool(mcp_config_file):
    """Test extraction fails for unknown tool."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    args = {"path": "/foo"}

    with pytest.raises(Exception) as excinfo:
        compiled.extract_constraints("unknown_tool", args)

    assert "Tool 'unknown_tool' not defined" in str(excinfo.value)


def test_extract_constraints_pure(mcp_config_file):
    """extract_constraints only extracts constraints — no warrant/signature handling."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    args = {"path": "/var/log/syslog", "maxSize": 5000}

    result = compiled.extract_constraints("filesystem_read", args)

    constraints = dict(result.constraints)
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 5000

    # Warrant/signature are always None — transport is handled by params._meta
    assert result.warrant_base64 is None
    assert result.signature_base64 is None
    assert result.approvals_base64 == []


# ---------------------------------------------------------------------------
# SecureMCPClient approval injection tests (unit — no real server needed)
# ---------------------------------------------------------------------------


def _make_client() -> "SecureMCPClient":
    """Build a SecureMCPClient instance without connecting to any server."""
    client = SecureMCPClient.__new__(SecureMCPClient)
    client.command = "python"
    client.args = []
    client.env = None
    client.config_path = None
    client.inject_warrant = False
    client.transport = "stdio"
    client.url = None
    client.headers = None
    client.timeout = 30.0
    client.sse_read_timeout = 300.0
    client.auth = None
    client.mcp_config = None
    client.compiled_config = None
    client.exit_stack = AsyncExitStack()
    client._tools = None
    client._wrapped_tools = {}
    client._approval_handler = None
    client._control_plane = None
    client._connect_lock = asyncio.Lock()

    mock_session = MagicMock()
    mock_session.call_tool = AsyncMock(return_value=MagicMock(content="result"))
    client.session = mock_session
    return client


def _mock_warrant_context():
    """Return (mock_warrant, mock_keypair, patchers) for warrant injection tests."""
    mock_warrant = MagicMock()
    mock_warrant.to_base64.return_value = "warrant_b64"
    mock_warrant.sign.return_value = b"pop_bytes"
    mock_warrant.is_expired.return_value = False
    mock_keypair = MagicMock()
    return mock_warrant, mock_keypair


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestCallToolApprovalsInjection:
    @pytest.mark.asyncio
    async def test_approvals_serialized_into_meta_tenuo(self):
        """Approvals are base64-encoded CBOR and injected via params._meta.tenuo."""
        client = _make_client()
        mock_warrant, mock_keypair = _mock_warrant_context()

        fake_approval = MagicMock()
        fake_approval.to_bytes.return_value = b"approval_cbor"

        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                {"path": "/data/file.txt"},
                warrant_context=False,
                inject_warrant=True,
                approvals=[fake_approval],
            )

        meta_injected = client.session.call_tool.call_args.kwargs.get("meta")
        assert meta_injected is not None
        assert "tenuo" in meta_injected
        assert "approvals" in meta_injected["tenuo"]
        expected = base64.b64encode(b"approval_cbor").decode("utf-8")
        assert meta_injected["tenuo"]["approvals"] == [expected]

    @pytest.mark.asyncio
    async def test_multiple_approvals_all_serialized(self):
        """All approvals in the list are serialized individually."""
        client = _make_client()
        mock_warrant, mock_keypair = _mock_warrant_context()

        approvals = [MagicMock(), MagicMock()]
        approvals[0].to_bytes.return_value = b"cbor_0"
        approvals[1].to_bytes.return_value = b"cbor_1"

        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                {"path": "/data/file.txt"},
                warrant_context=False,
                inject_warrant=True,
                approvals=approvals,
            )

        meta_injected = client.session.call_tool.call_args.kwargs.get("meta")
        assert meta_injected is not None
        assert meta_injected["tenuo"]["approvals"] == [
            base64.b64encode(b"cbor_0").decode("utf-8"),
            base64.b64encode(b"cbor_1").decode("utf-8"),
        ]

    @pytest.mark.asyncio
    async def test_no_approvals_omits_field(self):
        """When approvals=None (default), meta.tenuo.approvals is not included."""
        client = _make_client()
        mock_warrant, mock_keypair = _mock_warrant_context()

        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                {"path": "/data/file.txt"},
                warrant_context=False,
                inject_warrant=True,
            )

        meta_injected = client.session.call_tool.call_args.kwargs.get("meta")
        assert meta_injected is not None
        assert "tenuo" in meta_injected
        assert "approvals" not in meta_injected["tenuo"]

    @pytest.mark.asyncio
    async def test_approvals_not_injected_without_inject_warrant(self):
        """Approvals are only included when inject_warrant=True."""
        client = _make_client()

        fake_approval = MagicMock()
        fake_approval.to_bytes.return_value = b"approval_cbor"

        await client.call_tool(
            "read_file",
            {"path": "/data/file.txt"},
            warrant_context=False,
            inject_warrant=False,
            approvals=[fake_approval],
        )

        meta_injected = client.session.call_tool.call_args.kwargs.get("meta")
        assert meta_injected is None

    @pytest.mark.asyncio
    async def test_protected_tool_approvals_kwarg_forwarded(self):
        """_approvals kwarg on a protected tool call flows through to meta.tenuo.approvals."""
        from tenuo import SigningKey, configure
        from tenuo.decorators import key_scope, warrant_scope
        from tenuo_core import Warrant

        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        warrant = Warrant.issue(keypair, capabilities={"read_file": {}})

        client = _make_client()
        client.inject_warrant = True

        fake_mcp_tool = MagicMock()
        fake_mcp_tool.name = "read_file"
        fake_mcp_tool.description = "Read a file"
        fake_mcp_tool.inputSchema = {"properties": {"path": {"type": "string"}}, "required": ["path"]}

        protected = client.create_protected_tool(fake_mcp_tool)

        fake_approval = MagicMock()
        fake_approval.to_bytes.return_value = b"approval_cbor"

        with warrant_scope(warrant), key_scope(keypair):
            await protected(path="/data/file.txt", _approvals=[fake_approval])

        meta_injected = client.session.call_tool.call_args.kwargs.get("meta")
        assert meta_injected is not None
        assert "approvals" in meta_injected["tenuo"]
        expected = base64.b64encode(b"approval_cbor").decode("utf-8")
        assert meta_injected["tenuo"]["approvals"] == [expected]

    @pytest.mark.asyncio
    async def test_protected_tool_approvals_not_in_schema_args(self):
        """_approvals kwarg must not appear in the arguments forwarded to the server."""
        from tenuo import SigningKey, configure
        from tenuo.decorators import key_scope, warrant_scope
        from tenuo_core import Warrant

        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        warrant = Warrant.issue(keypair, capabilities={"read_file": {}})

        client = _make_client()
        client.inject_warrant = True

        fake_mcp_tool = MagicMock()
        fake_mcp_tool.name = "read_file"
        fake_mcp_tool.description = "Read a file"
        fake_mcp_tool.inputSchema = {"properties": {"path": {"type": "string"}}, "required": ["path"]}

        protected = client.create_protected_tool(fake_mcp_tool)

        fake_approval = MagicMock()
        fake_approval.to_bytes.return_value = b"bytes"

        with warrant_scope(warrant), key_scope(keypair):
            await protected(path="/data/file.txt", _approvals=[fake_approval])

        injected = client.session.call_tool.call_args[0][1]
        assert "_approvals" not in injected
        assert "_tenuo" not in injected


# ---------------------------------------------------------------------------
# PoP signing over extracted constraints (C1 fix verification)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestPopSignsRawWireArgs:
    """PoP is always computed over the raw wire args (with None values stripped),
    independently of whether the client has a CompiledMcpConfig loaded.

    The server performs any constraint extraction (field renaming, coercion)
    separately as part of its split-view authorize call, so client-side
    config is never needed for PoP byte parity with the server.
    """

    @pytest.mark.asyncio
    async def test_pop_signs_raw_wire_args_even_with_config_loaded(self):
        """With compiled_config loaded, sign() still receives raw args, not extracted ones."""
        client = _make_client()
        mock_warrant, mock_keypair = _mock_warrant_context()

        mock_extraction = MagicMock()
        mock_extraction.constraints = {"max_size": 2048, "path": "/data/log.txt"}
        mock_config = MagicMock()
        mock_config.extract_constraints.return_value = mock_extraction
        client.compiled_config = mock_config

        raw_args = {"path": "/data/log.txt", "maxSize": 2048}
        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                raw_args,
                warrant_context=False,
                inject_warrant=True,
            )

        # Extraction is never used by the signing path now — the server does it.
        mock_config.extract_constraints.assert_not_called()
        sign_call_args = mock_warrant.sign.call_args[0]
        assert sign_call_args[0] is mock_keypair  # key
        assert sign_call_args[1] == "read_file"  # tool_name
        assert sign_call_args[2] == raw_args  # raw wire args, not extracted

    @pytest.mark.asyncio
    async def test_pop_signs_raw_args_without_config(self):
        """Without compiled_config, warrant.sign() receives raw args (unchanged behavior)."""
        client = _make_client()
        assert client.compiled_config is None
        mock_warrant, mock_keypair = _mock_warrant_context()

        raw_args = {"path": "/data/log.txt", "maxSize": 2048}

        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                raw_args,
                warrant_context=False,
                inject_warrant=True,
            )

        sign_call_args = mock_warrant.sign.call_args[0]
        assert sign_call_args[2] == raw_args

    @pytest.mark.asyncio
    async def test_pop_signs_args_with_none_values_stripped(self):
        """None-valued wire args are stripped before signing (bridges Rust FFI
        which rejects None, and must match the server's identical stripping)."""
        client = _make_client()
        mock_warrant, mock_keypair = _mock_warrant_context()

        raw_args = {"path": "/data/log.txt", "encoding": None, "maxSize": 2048}

        with (
            patch("tenuo.mcp.client.warrant_scope", return_value=mock_warrant),
            patch("tenuo.mcp.client.key_scope", return_value=mock_keypair),
        ):
            await client.call_tool(
                "read_file",
                raw_args,
                warrant_context=False,
                inject_warrant=True,
            )

        sign_call_args = mock_warrant.sign.call_args[0]
        assert sign_call_args[2] == {"path": "/data/log.txt", "maxSize": 2048}
        assert "encoding" not in sign_call_args[2]


# ---------------------------------------------------------------------------
# Schema stripping with empty properties (H3 fix verification)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestSchemaStrippingEmptyProperties:
    """When a tool has no properties in its inputSchema, all args must be forwarded."""

    @pytest.mark.asyncio
    async def test_empty_properties_forwards_all_args(self):
        """Tool with empty inputSchema.properties doesn't strip arguments."""
        from tenuo import SigningKey, configure
        from tenuo.decorators import key_scope, warrant_scope
        from tenuo_core import Warrant

        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        warrant = Warrant.issue(keypair, capabilities={"search": {}})

        client = _make_client()
        client.inject_warrant = False

        fake_mcp_tool = MagicMock()
        fake_mcp_tool.name = "search"
        fake_mcp_tool.description = "Search"
        fake_mcp_tool.inputSchema = {"type": "object", "properties": {}}

        protected = client.create_protected_tool(fake_mcp_tool)

        with warrant_scope(warrant), key_scope(keypair):
            await protected(query="hello", limit=10)

        forwarded = client.session.call_tool.call_args[0][1]
        assert forwarded == {"query": "hello", "limit": 10}

    @pytest.mark.asyncio
    async def test_absent_properties_forwards_all_args(self):
        """Tool with no inputSchema at all doesn't strip arguments."""
        from tenuo import SigningKey, configure
        from tenuo.decorators import key_scope, warrant_scope
        from tenuo_core import Warrant

        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        warrant = Warrant.issue(keypair, capabilities={"ping": {}})

        client = _make_client()
        client.inject_warrant = False

        fake_mcp_tool = MagicMock()
        fake_mcp_tool.name = "ping"
        fake_mcp_tool.description = "Ping"
        fake_mcp_tool.inputSchema = None

        protected = client.create_protected_tool(fake_mcp_tool)

        with warrant_scope(warrant), key_scope(keypair):
            await protected(msg="hello")

        forwarded = client.session.call_tool.call_args[0][1]
        assert forwarded == {"msg": "hello"}

    @pytest.mark.asyncio
    async def test_populated_properties_still_strips(self):
        """Tool with declared properties still strips unknown keys."""
        from tenuo import SigningKey, configure
        from tenuo.decorators import key_scope, warrant_scope
        from tenuo_core import Warrant

        keypair = SigningKey.generate()
        configure(issuer_key=keypair, dev_mode=True)
        warrant = Warrant.issue(keypair, capabilities={"read_file": {}})

        client = _make_client()
        client.inject_warrant = False

        fake_mcp_tool = MagicMock()
        fake_mcp_tool.name = "read_file"
        fake_mcp_tool.description = "Read"
        fake_mcp_tool.inputSchema = {
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        }

        protected = client.create_protected_tool(fake_mcp_tool)

        with warrant_scope(warrant), key_scope(keypair):
            await protected(path="/data/f.txt", injected_evil="pwn")

        forwarded = client.session.call_tool.call_args[0][1]
        assert forwarded == {"path": "/data/f.txt"}
        assert "injected_evil" not in forwarded


# ---------------------------------------------------------------------------
# Transport validation tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestTransportValidation:
    def test_stdio_requires_command(self):
        with pytest.raises(ValueError, match="transport='stdio' requires 'command'"):
            SecureMCPClient(transport="stdio")

    def test_stdio_default_with_command(self):
        """Default transport is stdio; command is sufficient."""
        with pytest.raises(ValueError, match="requires 'command'"):
            SecureMCPClient()  # no command, default transport=stdio

    def test_sse_requires_url(self):
        with pytest.raises(ValueError, match="requires 'url'"):
            SecureMCPClient(transport="sse")

    def test_http_requires_url(self):
        with pytest.raises(ValueError, match="requires 'url'"):
            SecureMCPClient(transport="http")

    def test_sse_with_url_does_not_raise(self):
        """SSE transport with url passes validation (connect not called)."""
        import tenuo.mcp.client as _mod

        original = _mod.MCP_AVAILABLE
        _mod.MCP_AVAILABLE = True
        try:
            # __init__ will fail at session setup but should pass validation
            # We check that ValueError is NOT raised for url= provided
            try:
                SecureMCPClient(transport="sse", url="https://example.com/sse")
            except (ImportError, AttributeError, TypeError):
                pass  # expected — no real MCP session setup
            # If ValueError was raised, the test would have failed already
        finally:
            _mod.MCP_AVAILABLE = original

    @pytest.mark.asyncio
    async def test_connect_stdio_calls_stdio_client(self):
        """connect() uses stdio_client for transport='stdio'."""
        client = _make_client()

        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = MagicMock(tools=[])

        with (
            patch("tenuo.mcp.client.stdio_client") as mock_stdio,
            patch("tenuo.mcp.client.ClientSession", return_value=mock_session),
        ):
            mock_stdio.return_value.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
            mock_stdio.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)

            await client.connect()

        mock_stdio.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_sse_calls_sse_client(self):
        """connect() uses sse_client for transport='sse'."""
        client = _make_client()
        client.transport = "sse"
        client.url = "https://example.com/sse"

        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = MagicMock(tools=[])

        with (
            patch("tenuo.mcp.client.sse_client") as mock_sse,
            patch("tenuo.mcp.client.ClientSession", return_value=mock_session),
        ):
            mock_sse.return_value.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
            mock_sse.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)

            await client.connect()

        mock_sse.assert_called_once_with(
            url="https://example.com/sse",
            headers=None,
            timeout=30.0,
            sse_read_timeout=300.0,
            auth=None,
        )

    @pytest.mark.asyncio
    async def test_connect_http_calls_streamablehttp_client(self):
        """connect() uses streamablehttp_client for transport='http'."""
        client = _make_client()
        client.transport = "http"
        client.url = "https://example.com/mcp"
        client.headers = {"Authorization": "Bearer token"}

        mock_session_id = MagicMock()
        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = MagicMock(tools=[])

        with (
            patch("tenuo.mcp.client.streamablehttp_client") as mock_http,
            patch("tenuo.mcp.client.ClientSession", return_value=mock_session),
        ):
            mock_http.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_session_id)
            )
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)

            await client.connect()

        mock_http.assert_called_once_with(
            url="https://example.com/mcp",
            headers={"Authorization": "Bearer token"},
            timeout=30.0,
            sse_read_timeout=300.0,
            auth=None,
        )

    @pytest.mark.asyncio
    async def test_connect_http_discards_session_id_callback(self):
        """The session-ID callback (3rd element of streamablehttp_client tuple) is ignored."""
        client = _make_client()
        client.transport = "http"
        client.url = "https://example.com/mcp"

        session_id_called = []
        mock_session_id_cb = lambda: session_id_called.append(True)  # noqa: E731
        mock_read = MagicMock()
        mock_write = MagicMock()
        mock_session = AsyncMock()
        mock_session.list_tools.return_value = MagicMock(tools=[])

        with (
            patch("tenuo.mcp.client.streamablehttp_client") as mock_http,
            patch("tenuo.mcp.client.ClientSession", return_value=mock_session),
        ):
            mock_http.return_value.__aenter__ = AsyncMock(
                return_value=(mock_read, mock_write, mock_session_id_cb)
            )
            mock_http.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)

            await client.connect()

        # Callback should not have been invoked by the client
        assert session_id_called == []


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestCallToolIsErrorHandling:
    """``isError`` results: safe messages and optional MCPToolCallError (cf. FastMCP #3778)."""

    @pytest.mark.asyncio
    async def test_empty_error_content_raises_safe_message(self):
        from mcp.types import CallToolResult

        from tenuo.exceptions import MCPToolCallError

        client = _make_client()
        client.session.call_tool = AsyncMock(return_value=CallToolResult(content=[], isError=True))
        with pytest.raises(MCPToolCallError, match="returned an error"):
            await client.call_tool("t", {}, warrant_context=False)

    @pytest.mark.asyncio
    async def test_non_text_first_block_uses_fallback_message(self):
        from mcp.types import CallToolResult, ImageContent

        from tenuo.exceptions import MCPToolCallError

        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(
                content=[ImageContent(type="image", data="eHl6", mimeType="image/png")],
                isError=True,
            )
        )
        with pytest.raises(MCPToolCallError, match="returned an error"):
            await client.call_tool("t", {}, warrant_context=False)

    @pytest.mark.asyncio
    async def test_text_block_used_as_message(self):
        from mcp.types import CallToolResult, TextContent

        from tenuo.exceptions import MCPToolCallError

        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(
                content=[TextContent(type="text", text="specific failure")],
                isError=True,
            )
        )
        with pytest.raises(MCPToolCallError, match="specific failure"):
            await client.call_tool("t", {}, warrant_context=False)

    @pytest.mark.asyncio
    async def test_structured_content_approval_required_raises_typed(self):
        from mcp.types import CallToolResult, TextContent

        from tenuo.mcp.server import MCPApprovalRequired

        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(
                content=[TextContent(type="text", text="Approval required")],
                isError=True,
                structuredContent={"tenuo": {"code": -32002, "message": "Approval required"}},
            )
        )
        with pytest.raises(MCPApprovalRequired) as ri:
            await client.call_tool("t", {}, warrant_context=False)
        assert ri.value.tool_name == "t"
        assert ri.value.result.is_approval_required

    @pytest.mark.asyncio
    async def test_approval_required_extracts_request_hash(self):
        from mcp.types import CallToolResult, TextContent

        from tenuo.mcp.server import MCPApprovalRequired

        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(
                content=[TextContent(type="text", text="Approval required")],
                isError=True,
                structuredContent={
                    "tenuo": {
                        "code": -32002,
                        "message": "Approval required",
                        "request_hash": "deadbeef1234",
                    }
                },
            )
        )
        with pytest.raises(MCPApprovalRequired) as ri:
            await client.call_tool("t", {}, warrant_context=False)
        assert ri.value.request_hash == "deadbeef1234"
        assert ri.value.result.request_hash == "deadbeef1234"

    @pytest.mark.asyncio
    async def test_approval_required_no_hash_when_absent(self):
        from mcp.types import CallToolResult, TextContent

        from tenuo.mcp.server import MCPApprovalRequired

        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(
                content=[TextContent(type="text", text="Approval required")],
                isError=True,
                structuredContent={"tenuo": {"code": -32002, "message": "Approval required"}},
            )
        )
        with pytest.raises(MCPApprovalRequired) as ri:
            await client.call_tool("t", {}, warrant_context=False)
        assert ri.value.request_hash is None

    @pytest.mark.asyncio
    async def test_raise_on_tool_error_false_returns_content(self):
        from mcp.types import CallToolResult, TextContent

        blocks = [TextContent(type="text", text="err")]
        client = _make_client()
        client.session.call_tool = AsyncMock(
            return_value=CallToolResult(content=blocks, isError=True)
        )
        out = await client.call_tool("t", {}, warrant_context=False, raise_on_tool_error=False)
        assert out == blocks
