"""
Middleware for the official MCP SDK's ``MCPServer`` and low-level ``Server``
(``mcp>=2.0``) that delegates every ``tools/call`` authorization decision to
:class:`MCPVerifier`.

Why a middleware and not a tool parameter
-----------------------------------------
``SecureMCPClient(inject_warrant="argument")`` carries the warrant envelope in
the reserved ``arguments._tenuo`` key for gateways that drop ``params._meta``.
A tool registered with the high-level ``@mcp.tool()`` decorator cannot receive
that key: the SDK builds a pydantic model from the function signature, pydantic
rejects field names with a leading underscore, and unknown arguments are pruned
before the handler runs. A ``ServerMiddleware`` runs *before* params validation,
so it can verify the envelope, whichever carrier it arrived in, and hand the
handler ``clean_arguments`` with the carrier removed. Tool signatures stay
plain.

Usage::

    from mcp.server.mcpserver import MCPServer
    from tenuo import Authorizer, PublicKey
    from tenuo.mcp import MCPVerifier, TenuoServerMiddleware

    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root_public_key]))
    mcp = MCPServer("app", middleware=[TenuoServerMiddleware(verifier)])

    @mcp.tool()
    def read_file(path: str) -> str:
        return open(path).read()

Denials never reach the tool. They are returned as a ``CallToolResult`` with
the error flag set, the reason as text content, and a ``tenuo`` block in
``structuredContent`` (``code``, ``message``, and ``request_hash`` /
``got`` / ``need`` for approval gates), the same shape the FastMCP
:class:`~tenuo.mcp.fastmcp_middleware.TenuoMiddleware` returns, so
:class:`~tenuo.mcp.SecureMCPClient` maps them to the same exceptions.

Every other method, and every notification, passes through untouched.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Optional

from .server import MCPVerificationResult, MCPVerifier

_MCP_INSTALL = 'pip install "tenuo[mcp]"'

try:
    from mcp.server.context import ServerRequestContext  # noqa: F401  (mcp >= 2.0)
    from mcp.types import TextContent

    from ._compat import make_error_call_tool_result, request_params_meta_as_dict
except ImportError as exc:
    raise ImportError(
        "tenuo.mcp.mcpserver_middleware requires the MCP SDK 2.x "
        f"(mcp.server.context.ServerMiddleware). Install with: {_MCP_INSTALL} "
        "and mcp>=2. On FastMCP use tenuo.mcp.TenuoMiddleware instead."
    ) from exc

__all__ = ["TenuoServerMiddleware", "TOOLS_CALL"]

#: The only method this middleware acts on.
TOOLS_CALL = "tools/call"


def _denial_result(verification: MCPVerificationResult) -> Any:
    code = verification.jsonrpc_error_code or -32001
    message = verification.denial_reason or "Authorization denied"
    tenuo_block: dict[str, Any] = {"code": code, "message": message}
    if verification.request_hash:
        tenuo_block["request_hash"] = verification.request_hash
    if verification.approval_metadata:
        meta = verification.approval_metadata
        if "got" in meta:
            tenuo_block["got"] = meta["got"]
        if "need" in meta:
            tenuo_block["need"] = meta["need"]
    return make_error_call_tool_result(
        content=[TextContent(type="text", text=message)],
        structured_content={"tenuo": tenuo_block},
    )


def _resolve_meta(ctx: Any, params: dict[str, Any]) -> Optional[dict[str, Any]]:
    """The request ``_meta`` as a plain dict, from the context or the raw params."""
    if ctx.meta is not None:
        return request_params_meta_as_dict(ctx.meta)
    raw = params.get("_meta")
    if isinstance(raw, dict):
        return dict(raw)
    return None


class TenuoServerMiddleware:
    """Verify every ``tools/call`` with :class:`MCPVerifier` before it is dispatched.

    On success the rest of the chain runs with a rewritten context: arguments
    are the verifier's ``clean_arguments`` (so the ``_tenuo`` carrier is gone)
    and the ``tenuo`` key is removed from ``_meta``. On failure the tool is not
    invoked and an error ``CallToolResult`` is returned.

    Install it on the server's ``middleware`` list. It is listed after the
    SDK's own built-ins, so it sees the raw inbound params exactly as the
    client sent them.
    """

    def __init__(self, verifier: MCPVerifier) -> None:
        self._verifier = verifier

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        if ctx.method != TOOLS_CALL or ctx.request_id is None:
            return await call_next(ctx)

        params = dict(ctx.params or {})
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(name, str) or (arguments is not None and not isinstance(arguments, dict)):
            # Malformed request: let the SDK's params validation report it.
            return await call_next(ctx)

        meta = _resolve_meta(ctx, params)
        verification = self._verifier.verify(name, dict(arguments or {}), meta=meta or None)
        if not verification.allowed:
            return _denial_result(verification)

        clean_meta = {k: v for k, v in (meta or {}).items() if k != "tenuo"} or None
        new_params: dict[str, Any] = {**params, "arguments": dict(verification.clean_arguments)}
        if "_meta" in new_params:
            if clean_meta:
                new_params["_meta"] = clean_meta
            else:
                new_params.pop("_meta")
        return await call_next(dataclasses.replace(ctx, params=new_params, meta=clean_meta))
