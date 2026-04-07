"""
FastMCP middleware that delegates every ``tools/call`` authorization decision to
:class:`MCPVerifier`.

Verification semantics (warrant decoding, PoP, constraints, approvals) are
unchanged — this module only wires FastMCP's middleware hook to
:meth:`MCPVerifier.verify` and normalizes request metadata.

``CallToolRequestParams.meta`` (JSON ``_meta``) is the primary source. When
FastMCP builds an internal ``CallToolRequestParams`` without ``meta`` (common
on the wire path), metadata is taken from the current MCP
:class:`~mcp.shared.context.RequestContext` exposed by
:class:`fastmcp.server.context.Context` (``extra="allow"`` preserves
``tenuo``).
"""

from __future__ import annotations

from typing import Any, Optional

from .server import MCPVerificationResult, MCPVerifier

_MCP_INSTALL = 'pip install "tenuo[mcp]"'
_FASTMCP_INSTALL = 'pip install "tenuo[fastmcp]"'

try:
    import mcp.types as mt
    from mcp.types import RequestParams, TextContent
except ImportError as exc:
    raise ImportError(
        "tenuo.mcp.fastmcp_middleware requires the MCP SDK. "
        f"Install with: {_MCP_INSTALL} (or pip install mcp)."
    ) from exc

try:
    from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
except ImportError as exc:
    raise ImportError(
        "tenuo.mcp.fastmcp_middleware requires FastMCP (optional; not part of tenuo[mcp]). "
        f"Install with: {_FASTMCP_INSTALL} (or pip install fastmcp). "
        "The tenuo[mcp] extra installs only the official MCP SDK."
    ) from exc

__all__ = [
    "TenuoMiddleware",
    "resolve_tool_call_meta_for_verify",
]


def resolve_tool_call_meta_for_verify(
    params: mt.CallToolRequestParams,
    fastmcp_context: Any,
) -> Optional[dict[str, Any]]:
    """Resolve ``params._meta`` as a plain dict for :meth:`MCPVerifier.verify`.

    Order:

    1. ``params.meta`` (MCP SDK alias for JSON ``_meta``).
    2. Else ``fastmcp_context.request_context.meta`` when a request context is
       active (wire ``tools/call`` often populates this while the synthesized
       ``CallToolRequestParams`` omits ``meta``).

    Returns ``None`` when no metadata object is present.
    """
    meta_obj: Any = params.meta
    if meta_obj is None and fastmcp_context is not None:
        rc = fastmcp_context.request_context
        if rc is not None:
            meta_obj = rc.meta
    if meta_obj is None:
        return None
    if hasattr(meta_obj, "model_dump"):
        return meta_obj.model_dump(mode="python")
    if isinstance(meta_obj, dict):
        return dict(meta_obj)
    return None


def _strip_tenuo_meta(
    params: mt.CallToolRequestParams, clean_arguments: dict[str, Any]
) -> mt.CallToolRequestParams:
    """Replace arguments with verifier output and drop ``tenuo`` from ``meta``."""
    meta = params.meta
    if meta is None:
        return params.model_copy(update={"arguments": clean_arguments})
    trimmed = meta.model_dump(mode="python", exclude_none=True)
    trimmed.pop("tenuo", None)
    new_meta: RequestParams.Meta | None
    if trimmed:
        new_meta = RequestParams.Meta.model_validate(trimmed)
    else:
        new_meta = None
    return params.model_copy(update={"arguments": clean_arguments, "meta": new_meta})


class _VerifierDenialToolReturn:
    """Satisfies ``FastMCP.call_tool`` consumers that call ``.to_mcp_result()``."""

    __slots__ = ("_result",)

    def __init__(self, result: mt.CallToolResult) -> None:
        self._result = result

    def to_mcp_result(
        self,
    ) -> mt.CallToolResult:
        return self._result


def _denial_tool_return(verification: MCPVerificationResult) -> _VerifierDenialToolReturn:
    code = verification.jsonrpc_error_code or -32001
    message = verification.denial_reason or "Authorization denied"
    call = mt.CallToolResult(
        content=[TextContent(type="text", text=message)],
        isError=True,
        structuredContent={
            "tenuo": {
                "code": code,
                "message": message,
            }
        },
    )
    return _VerifierDenialToolReturn(call)


class TenuoMiddleware(Middleware):
    """Run :class:`MCPVerifier` on every ``tools/call`` before the tool runs.

    On success, forwards a copy of the request with
    :attr:`~MCPVerificationResult.clean_arguments` and ``tenuo`` removed from
    ``meta`` so handlers do not see warrant material. On failure, returns a
    tool result with ``isError=True`` (and structured ``tenuo`` diagnostics)
    without invoking the tool.

    Install early so downstream middleware and the tool see authorized
    arguments only::

        from fastmcp import FastMCP
        from tenuo.mcp import MCPVerifier, TenuoMiddleware

        verifier = MCPVerifier(authorizer=authorizer, config=config)
        mcp = FastMCP("app", middleware=[TenuoMiddleware(verifier)])

        @mcp.tool()
        async def read_file(path: str) -> str:
            return open(path).read()
    """

    def __init__(self, verifier: MCPVerifier) -> None:
        self._verifier = verifier

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, Any],
    ) -> Any:
        params = context.message
        name = params.name
        arguments = params.arguments or {}
        meta = resolve_tool_call_meta_for_verify(
            params, context.fastmcp_context
        )
        result = self._verifier.verify(name, arguments, meta=meta)
        if not result.allowed:
            return _denial_tool_return(result)
        new_message = _strip_tenuo_meta(params, result.clean_arguments)
        return await call_next(context.copy(message=new_message))
