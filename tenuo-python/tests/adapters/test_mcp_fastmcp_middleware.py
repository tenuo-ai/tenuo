"""
Tests for :class:`tenuo.mcp.fastmcp_middleware.TenuoMiddleware`.

Requires the MCP SDK and FastMCP (3.x with mcp 1.x, or FastMCP 4.x with mcp 2.x).
The whole module is skipped when either dependency is unavailable.
"""

from __future__ import annotations

import base64
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from tenuo_core import Authorizer, SigningKey, Warrant

from tenuo import Pattern
from tenuo._pop_canonicalize import strip_none_values
from tenuo.mcp._compat import (
    build_request_params_meta,
    call_tool_result_is_error,
    call_tool_result_structured_content,
)
from tenuo.mcp.server import MCPVerifier

pytest.importorskip("mcp")
pytest.importorskip("fastmcp")
pytest.importorskip("fastmcp.server.middleware.middleware", exc_type=ImportError)

from mcp.types import (  # noqa: E402
    CallToolRequestParams,
    CallToolResult,
    TextContent,
)

from fastmcp.server.middleware.middleware import MiddlewareContext  # noqa: E402
from fastmcp.tools.base import ToolResult  # noqa: E402

from tenuo.mcp.fastmcp_middleware import (  # noqa: E402
    TenuoMiddleware,
    resolve_tool_call_meta_for_verify,
)


def _encode_warrant(warrant: Warrant) -> str:
    return warrant.to_base64()


def _encode_pop(warrant: Warrant, key: SigningKey, tool: str, args: dict) -> str:
    import time

    sig = warrant.sign(key, tool, args, int(time.time()))
    return base64.b64encode(bytes(sig)).decode()


def _make_meta(
    warrant: Warrant,
    key: SigningKey,
    tool: str,
    tool_args: Dict[str, Any],
) -> Any:
    tenuo: Dict[str, Any] = {
        "warrant": _encode_warrant(warrant),
        "signature": _encode_pop(warrant, key, tool, tool_args),
    }
    return build_request_params_meta({"tenuo": tenuo})


def _make_meta_strip_none(
    warrant: Warrant,
    key: SigningKey,
    tool: str,
    tool_args: Dict[str, Any],
) -> Any:
    """Build metadata using the same canonicalization as MCP client/server."""
    return _make_meta(warrant, key, tool, strip_none_values(tool_args))


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def simple_warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    return Warrant.issue(
        issuer_key,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=agent_key.public_key,
    )


def test_resolve_meta_from_params(
    simple_warrant: Warrant, agent_key: SigningKey
) -> None:
    args = {"path": "/data/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", args)
    params = CallToolRequestParams(name="read_file", arguments=args, _meta=meta)
    resolved = resolve_tool_call_meta_for_verify(params, None)
    assert resolved is not None
    assert "tenuo" in resolved


def test_resolve_meta_fallback_request_context(
    simple_warrant: Warrant, agent_key: SigningKey
) -> None:
    """Fallback when CallToolRequestParams.meta is empty but request context has it.

    FastMCP 3 exposed MCP SDK ``RequestContext`` via ``request_ctx``; FastMCP 4
    wraps meta on ``FastMCPRequestContext``. Both surfaces are ``.meta`` on the
    object returned by ``Context.request_context``, so a stand-in is enough here.
    """
    args = {"path": "/data/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", args)
    params = CallToolRequestParams(name="read_file", arguments=args)
    ctx = MagicMock()
    ctx.request_context.meta = meta
    resolved = resolve_tool_call_meta_for_verify(params, ctx)
    assert resolved is not None and "tenuo" in resolved


@pytest.mark.asyncio
async def test_middleware_denies_without_warrant(authorizer: Authorizer) -> None:
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mw = TenuoMiddleware(verifier)
    params = CallToolRequestParams(
        name="read_file", arguments={"path": "/data/x.txt"}
    )
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )

    async def boom(_: MiddlewareContext) -> ToolResult:
        raise AssertionError("call_next should not run")

    out = await mw.on_call_tool(ctx, boom)
    mcp_result = out.to_mcp_result()
    assert isinstance(mcp_result, CallToolResult)
    assert call_tool_result_is_error(mcp_result) is True
    structured = call_tool_result_structured_content(mcp_result)
    assert structured is not None
    tenuo = structured.get("tenuo")
    assert isinstance(tenuo, dict)
    assert tenuo.get("code") == -32001
    assert "message" in tenuo


@pytest.mark.asyncio
async def test_denial_return_matches_fastmcp_toolresult_contract(
    authorizer: Authorizer,
) -> None:
    """Regression guard: FastMCP 4 requires a real ``ToolResult`` denial.

    FastMCP 4's ``tools/call`` path only calls ``.to_mcp_result()`` when the
    middleware return is ``isinstance(..., ToolResult)``. A duck-typed wrapper
    is handed straight to the runner and raises
    ``handler returned _VerifierDenialToolReturn``. FastMCP 3 has no
    ``is_error`` on ``ToolResult``, so the duck-typed wrapper remains valid.
    """
    import inspect

    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mw = TenuoMiddleware(verifier)
    params = CallToolRequestParams(
        name="read_file", arguments={"path": "/data/x.txt"}
    )
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )

    async def boom(_: MiddlewareContext) -> ToolResult:
        raise AssertionError("call_next should not run")

    out = await mw.on_call_tool(ctx, boom)
    supports_is_error = "is_error" in inspect.signature(ToolResult.__init__).parameters

    if supports_is_error:
        assert isinstance(out, ToolResult), (
            "FastMCP 4+ denials must be ToolResult so call_tool normalizes "
            "via to_mcp_result(); duck-typed wrappers break the wire path"
        )
        assert out.is_error is True
        assert isinstance(out.structured_content, dict)
        assert out.structured_content.get("tenuo", {}).get("code") == -32001
    else:
        # FastMCP 3: duck-typed wrapper with to_mcp_result() is required.
        assert not isinstance(out, ToolResult)
        assert hasattr(out, "to_mcp_result")
        mcp_result = out.to_mcp_result()
        assert isinstance(mcp_result, CallToolResult)
        assert call_tool_result_is_error(mcp_result) is True


@pytest.mark.asyncio
async def test_middleware_accepts_and_strips_tenuo(
    authorizer: Authorizer,
    simple_warrant: Warrant,
    agent_key: SigningKey,
) -> None:
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mw = TenuoMiddleware(verifier)
    args = {"path": "/data/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", args)
    params = CallToolRequestParams(name="read_file", arguments=args, _meta=meta)
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )
    seen: dict[str, Any] = {}

    async def call_next(c: MiddlewareContext) -> ToolResult:
        seen["meta"] = c.message.meta
        seen["args"] = dict(c.message.arguments or {})
        return ToolResult(content=[TextContent(type="text", text="ok")])

    out = await mw.on_call_tool(ctx, call_next)
    assert seen["meta"] is None
    assert seen["args"].get("path") == "/data/x.txt"
    assert isinstance(out, ToolResult)


@pytest.mark.asyncio
async def test_middleware_denies_tampered_pop(
    authorizer: Authorizer,
    simple_warrant: Warrant,
    agent_key: SigningKey,
) -> None:
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mw = TenuoMiddleware(verifier)
    args = {"path": "/data/x.txt"}
    bad_args = {"path": "/other/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", bad_args)
    params = CallToolRequestParams(name="read_file", arguments=args, _meta=meta)
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )

    async def boom(_: MiddlewareContext) -> ToolResult:
        raise AssertionError("call_next should not run")

    out = await mw.on_call_tool(ctx, boom)
    res = out.to_mcp_result()
    assert call_tool_result_is_error(res) is True
    structured = call_tool_result_structured_content(res)
    assert structured is not None
    te = structured.get("tenuo")
    assert te.get("code") == -32001
    assert "Access denied" in (te.get("message") or "")


@pytest.mark.asyncio
async def test_middleware_accepts_none_optional_args(
    authorizer: Authorizer,
    simple_warrant: Warrant,
    agent_key: SigningKey,
) -> None:
    """Regression: None-valued args must not crash through middleware path."""
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True)
    mw = TenuoMiddleware(verifier)
    args = {"path": "/data/x.txt", "max_size": None}
    meta = _make_meta_strip_none(simple_warrant, agent_key, "read_file", args)
    params = CallToolRequestParams(name="read_file", arguments=args, _meta=meta)
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )
    seen: dict[str, Any] = {}

    async def call_next(c: MiddlewareContext) -> ToolResult:
        seen["args"] = dict(c.message.arguments or {})
        return ToolResult(content=[TextContent(type="text", text="ok")])

    out = await mw.on_call_tool(ctx, call_next)
    assert isinstance(out, ToolResult)
    # Middleware keeps original call args for handler; verifier strips internally.
    assert seen["args"]["path"] == "/data/x.txt"
    assert "max_size" in seen["args"]


class _RecordingControlPlane:
    """Minimal control plane stand-in for middleware tests."""

    def __init__(self) -> None:
        self.results: list[Any] = []

    def emit_for_enforcement(
        self,
        result: Any,
        chain_result: Any = None,
        *,
        latency_us: int = 0,
        **kwargs: Any,
    ) -> None:
        self.results.append(
            {"result": result, "chain_result": chain_result, "latency_us": latency_us}
        )


@pytest.mark.asyncio
async def test_middleware_forwards_control_plane_on_success(
    authorizer: Authorizer,
    simple_warrant: Warrant,
    agent_key: SigningKey,
) -> None:
    cp = _RecordingControlPlane()
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True, control_plane=cp)
    mw = TenuoMiddleware(verifier)
    args = {"path": "/data/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", args)
    params = CallToolRequestParams(name="read_file", arguments=args, _meta=meta)
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )

    async def call_next(c: MiddlewareContext) -> ToolResult:
        return ToolResult(content=[TextContent(type="text", text="ok")])

    await mw.on_call_tool(ctx, call_next)
    assert len(cp.results) == 1
    assert cp.results[0]["result"].allowed is True
    assert cp.results[0]["latency_us"] >= 0


@pytest.mark.asyncio
async def test_middleware_emits_control_plane_when_no_warrant(
    authorizer: Authorizer,
) -> None:
    """Missing warrant now emits a deny event for audit completeness."""
    cp = _RecordingControlPlane()
    verifier = MCPVerifier(authorizer=authorizer, require_warrant=True, control_plane=cp)
    mw = TenuoMiddleware(verifier)
    params = CallToolRequestParams(name="read_file", arguments={"path": "/data/x.txt"})
    ctx = MiddlewareContext(
        message=params,
        source="client",
        type="request",
        method="tools/call",
        fastmcp_context=None,
    )

    async def boom(_: MiddlewareContext) -> ToolResult:
        raise AssertionError("call_next should not run")

    await mw.on_call_tool(ctx, boom)
    assert len(cp.results) == 1
    assert cp.results[0]["result"].allowed is False
