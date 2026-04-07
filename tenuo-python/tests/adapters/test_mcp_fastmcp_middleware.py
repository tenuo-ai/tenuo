"""
Tests for :class:`tenuo.mcp.fastmcp_middleware.TenuoMiddleware`.

Requires the MCP SDK and FastMCP (``importorskip("mcp")`` then ``importorskip("fastmcp")``);
the whole module is skipped when MCP is unavailable (e.g. Python 3.9 matrix jobs).
"""

from __future__ import annotations

import base64
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
from tenuo_core import Authorizer, SigningKey, Warrant

from tenuo import Pattern
from tenuo.mcp.server import MCPVerifier

pytest.importorskip("mcp")
pytest.importorskip("fastmcp")

from mcp.server.lowlevel.server import request_ctx  # noqa: E402
from mcp.shared.context import RequestContext  # noqa: E402
from mcp.types import (  # noqa: E402
    CallToolRequestParams,
    CallToolResult,
    RequestParams,
    TextContent,
)

from fastmcp.server.context import Context  # noqa: E402
from fastmcp.server.middleware.middleware import MiddlewareContext  # noqa: E402
from fastmcp import FastMCP  # noqa: E402
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
) -> RequestParams.Meta:
    tenuo: Dict[str, Any] = {
        "warrant": _encode_warrant(warrant),
        "signature": _encode_pop(warrant, key, tool, tool_args),
    }
    return RequestParams.Meta.model_validate({"tenuo": tenuo})


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


@pytest.mark.asyncio
async def test_resolve_meta_fallback_request_context(
    simple_warrant: Warrant, agent_key: SigningKey
) -> None:
    args = {"path": "/data/x.txt"}
    meta = _make_meta(simple_warrant, agent_key, "read_file", args)
    rc = RequestContext(
        request_id=1,
        meta=meta,
        session=MagicMock(),
        lifespan_context={},
    )
    mcp = FastMCP("t")
    params = CallToolRequestParams(name="read_file", arguments=args)
    async with Context(fastmcp=mcp) as ctx:
        tok = request_ctx.set(rc)
        try:
            resolved = resolve_tool_call_meta_for_verify(params, ctx)
        finally:
            request_ctx.reset(tok)
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
    assert mcp_result.isError is True
    assert mcp_result.structuredContent is not None
    tenuo = mcp_result.structuredContent.get("tenuo")
    assert isinstance(tenuo, dict)
    assert tenuo.get("code") == -32001
    assert "message" in tenuo


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
    assert res.isError is True
    assert res.structuredContent is not None
    te = res.structuredContent.get("tenuo")
    assert te.get("code") == -32001
    assert "Access denied" in (te.get("message") or "")


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
async def test_middleware_skips_control_plane_when_no_warrant(
    authorizer: Authorizer,
) -> None:
    """Matches :class:`MCPVerifier` early deny (no warrant_id) — no audit emit."""
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
    assert cp.results == []
