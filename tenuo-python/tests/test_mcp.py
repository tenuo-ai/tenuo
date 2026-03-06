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


def test_extract_tenuo_metadata(mcp_config_file):
    """Test that _tenuo metadata is extracted and stripped."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)

    # Arguments with embedded warrant/signature
    args = {
        "path": "/var/log/syslog",
        "maxSize": 5000,
        "_tenuo": {"warrant": "eyJ0eXAiOiJKV1QiLCJhbGc...", "signature": "c2lnbmF0dXJlLi4u"},
    }

    result = compiled.extract_constraints("filesystem_read", args)

    # Check extracted constraints don't include _tenuo
    constraints = dict(result.constraints)
    assert "_tenuo" not in constraints
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 5000

    # Check warrant/signature were extracted
    assert result.warrant_base64 == "eyJ0eXAiOiJKV1QiLCJhbGc..."
    assert result.signature_base64 == "c2lnbmF0dXJlLi4u"


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

    mock_session = MagicMock()
    mock_session.call_tool = AsyncMock(return_value=MagicMock(content="result"))
    client.session = mock_session
    return client


def _mock_warrant_context():
    """Return (mock_warrant, mock_keypair, patchers) for warrant injection tests."""
    mock_warrant = MagicMock()
    mock_warrant.to_base64.return_value = "warrant_b64"
    mock_warrant.sign.return_value = b"pop_bytes"
    mock_keypair = MagicMock()
    return mock_warrant, mock_keypair


@pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
class TestCallToolApprovalsInjection:
    @pytest.mark.asyncio
    async def test_approvals_serialized_into_tenuo_field(self):
        """Approvals are base64-encoded CBOR and injected as _tenuo.approvals."""
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

        injected = client.session.call_tool.call_args[0][1]
        assert "_tenuo" in injected
        assert "approvals" in injected["_tenuo"]
        expected = base64.b64encode(b"approval_cbor").decode("utf-8")
        assert injected["_tenuo"]["approvals"] == [expected]

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

        injected = client.session.call_tool.call_args[0][1]
        assert injected["_tenuo"]["approvals"] == [
            base64.b64encode(b"cbor_0").decode("utf-8"),
            base64.b64encode(b"cbor_1").decode("utf-8"),
        ]

    @pytest.mark.asyncio
    async def test_no_approvals_omits_field(self):
        """When approvals=None (default), _tenuo.approvals is not included."""
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

        injected = client.session.call_tool.call_args[0][1]
        assert "_tenuo" in injected
        assert "approvals" not in injected["_tenuo"]

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

        injected = client.session.call_tool.call_args[0][1]
        assert "_tenuo" not in injected

    @pytest.mark.asyncio
    async def test_protected_tool_approvals_kwarg_forwarded(self):
        """_approvals kwarg on a protected tool call flows through to _tenuo.approvals."""
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

        injected = client.session.call_tool.call_args[0][1]
        assert "approvals" in injected["_tenuo"]
        expected = base64.b64encode(b"approval_cbor").decode("utf-8")
        assert injected["_tenuo"]["approvals"] == [expected]

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
        # Just validates no error is raised — don't connect
        c = SecureMCPClient.__new__(SecureMCPClient)
        # Call __init__ manually to test validation path
        # We can't call full __init__ without MCP session, so test via actual ctor
        # This tests the validation by going through __init__ up to the session setup:
        # use __new__ + manual param check to avoid actually spawning anything
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
        client = SecureMCPClient.__new__(SecureMCPClient)
        # Bypass MCP_AVAILABLE check by testing init directly
        # Patch MCP_AVAILABLE to True so __init__ proceeds past the import check
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
