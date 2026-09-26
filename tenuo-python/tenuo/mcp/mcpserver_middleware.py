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
handler ``clean_arguments`` with the carrier removed. The ``tool`` decorator
then checks the actual arguments after SDK validation, immediately before the
effect. Tool signatures stay plain, but every decorated tool needs this guard.

Usage::

    from mcp.server.mcpserver import MCPServer
    from tenuo import Authorizer, PublicKey
    from tenuo.mcp import MCPVerifier, TenuoServerMiddleware

    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[root_public_key]))
    authorization = TenuoServerMiddleware(verifier)
    mcp = MCPServer("app", middleware=[authorization])

    @authorization.tool(mcp)
    def read_file(path: str) -> str:
        return open(path).read()

Denials never reach the tool. They are returned as a ``CallToolResult`` with
the error flag set, the reason as text content, and a ``tenuo`` block in
``structuredContent`` (``code``, ``message``, and ``request_hash`` /
``got`` / ``need`` for approval gates), the same shape the FastMCP
:class:`~tenuo.mcp.fastmcp_middleware.TenuoMiddleware` returns, so
:class:`~tenuo.mcp.SecureMCPClient` maps them to the same exceptions.

Every other method, and every notification, passes through untouched.

Argument contract
-----------------
Callers must explicitly supply the exact final arguments, including defaults.
Coercions, added defaults, custom-validator transformations, aliases that change
argument names, nulls, and non-JSON Python values fail closed. Values cannot be
removed from the proof just because the SDK fills them in. SDK ``Context`` is
trusted server injection and excluded; other injected values are not excluded.
Validators and dependency resolvers must not perform protected effects: those
belong in the guarded function body. Verification happens once, so nonce stores,
approval gates, receipts and audit callbacks are not repeated by the guard.

For a low-level ``Server`` only, ``raw_handler=True`` explicitly opts out of the
decorator requirement. Its owner must dispatch the clean argument map unchanged,
without schema defaulting, coercion, or post-verification transformations. Do not
use that option with ``MCPServer`` or other high-level tool dispatchers.
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
import json
from contextvars import ContextVar
from typing import Any, Callable, Optional, get_type_hints

import anyio

from .server import MCPVerificationResult, MCPVerifier

_MCP_INSTALL = 'pip install "tenuo[mcp]"'

try:
    from mcp.server.context import ServerRequestContext  # noqa: F401  (mcp >= 2.0)
    from mcp.server.mcpserver import Context
    from mcp.shared.exceptions import MCPError
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


def _argument_snapshot(arguments: dict[str, Any]) -> str:
    """Freeze values before SDK validation, without coercion or mutable aliases.

    Null is excluded because MCPVerifier's PoP canonicalization omits it.
    Non-JSON Python objects (including models, enums and tuples) are rejected
    rather than silently serialized into a different representation.
    """
    def check(value: Any) -> None:
        if type(value) in (str, int, float, bool):
            return
        if type(value) is list:
            for item in value:
                check(item)
            return
        if type(value) is dict and all(type(key) is str for key in value):
            for item in value.values():
                check(item)
            return
        raise ValueError("Tool arguments must be non-null JSON values")

    check(arguments)
    return json.dumps(arguments, sort_keys=True, allow_nan=False, separators=(",", ":"))


@dataclasses.dataclass
class _VerifiedCall:
    tool: str
    arguments: str
    claimed: bool = False


def _boundary_denial(tool: str, message: str) -> Any:
    return _denial_result(MCPVerificationResult(
        allowed=False, tool=tool, clean_arguments={}, constraints={},
        denial_reason=message, jsonrpc_error_code=-32001,
    ))


class _ArgumentBoundaryDenied(MCPError):
    """Escape SDK output-schema validation; middleware renders the denial.

    MCP 2.0 validates even error CallToolResults against the tool's success
    schema. Its dispatchers preserve MCPError, allowing us to return the
    structured authorization denial outside that validation step.
    """

    def __init__(self, tool: str, message: str) -> None:
        super().__init__(code=-32001, message=message)
        self.tool = tool
        self.reason = message


class TenuoServerMiddleware:
    """Verify every ``tools/call`` with :class:`MCPVerifier` before it is dispatched.

    On success the rest of the chain runs with a rewritten context: arguments
    are the verifier's ``clean_arguments`` (so the ``_tenuo`` carrier is gone)
    and the ``tenuo`` key is removed from ``_meta``. On failure the tool is not
    invoked and an error ``CallToolResult`` is returned.

    Install it on the server's ``middleware`` list and register tools with
    ``@middleware.tool(mcp)``. Unguarded tool names fail closed. Use
    ``@middleware.tool(mcp, name="alias")`` to rename a tool.
    It is listed after the SDK's own built-ins, so it sees the raw inbound params as the
    client sent them.
    """

    def __init__(self, verifier: MCPVerifier, *, raw_handler: bool = False) -> None:
        self._verifier = verifier
        self._raw_handler = raw_handler
        self._protected: dict[str, tuple[Any, Callable[..., Any]]] = {}
        self._server: Any = None
        self._call: ContextVar[Optional[_VerifiedCall]] = ContextVar("tenuo_mcp_call", default=None)

    def tool(self, server: Any, *, name: Optional[str] = None, **options: Any) -> Any:
        """Register a guarded tool through the SDK's public ``server.tool`` API.

        Use this instead of stacking a guard with ``@server.tool()``: registering
        the original function before wrapping it would leave the SDK executing
        an unguarded callback. Other SDK tool options are forwarded unchanged.
        """
        def register(fn: Callable[..., Any]) -> Any:
            tool = name or fn.__name__
            if self._raw_handler:
                raise ValueError("raw_handler=True is only for low-level dispatch, not decorated tools")
            if self._server is not None and self._server is not server:
                raise ValueError("Use a separate TenuoServerMiddleware for each MCPServer")
            # MCP 2.x silently retains the original callback on duplicate
            # registration. Never mark an existing unguarded callback protected.
            manager = getattr(server, "_tool_manager", None)
            if manager is None:
                raise TypeError("Unsupported MCPServer tool registry")
            if manager.get_tool(tool) is not None:
                raise ValueError(f"Tool {tool!r} is already registered")
            guarded = self._protect(fn, tool)
            server.tool(name=tool, **options)(guarded)
            if getattr(manager.get_tool(tool), "fn", None) is not guarded:
                raise ValueError("MCPServer did not register the guarded callback")
            self._server = server
            self._protected[tool] = (manager, guarded)
            return guarded

        return register

    def _protect(self, fn: Callable[..., Any], tool: str) -> Any:
        hints = get_type_hints(fn, include_extras=True)
        signature = inspect.signature(fn)
        signature = signature.replace(
            parameters=[p.replace(annotation=hints.get(p.name, p.annotation))
                        for p in signature.parameters.values()],
            return_annotation=hints.get("return", signature.return_annotation),
        )
        context_names = {
            p.name for p in signature.parameters.values()
            if p.annotation is Context or getattr(p.annotation, "__origin__", None) is Context
        }

        @functools.wraps(fn)
        async def guarded(*args: Any, **kwargs: Any) -> Any:
            call = self._call.get()
            if call is None or call.tool != tool or call.claimed:
                raise _ArgumentBoundaryDenied(tool, "No verified request for this protected tool")
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            effective = {key: value for key, value in bound.arguments.items() if key not in context_names}
            try:
                matches = _argument_snapshot(effective) == call.arguments
            except (TypeError, ValueError):
                matches = False
            if not matches:
                raise _ArgumentBoundaryDenied(tool, "Tool arguments changed after authorization; send exact final values")
            call.claimed = True
            if inspect.iscoroutinefunction(fn):
                return await fn(*args, **kwargs)
            return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))

        guarded.__signature__ = signature  # type: ignore[attr-defined]
        guarded.__annotations__ = hints
        return guarded

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

        if not self._raw_handler:
            registration = self._protected.get(name)
            if registration is None or getattr(registration[0].get_tool(name), "fn", None) is not registration[1]:
                return _boundary_denial(name, "Tool must be registered with TenuoServerMiddleware.tool")
        try:
            snapshot = _argument_snapshot(verification.clean_arguments)
        except (TypeError, ValueError):
            return _boundary_denial(name, "Tool arguments must be non-null JSON values")

        clean_meta = {k: v for k, v in (meta or {}).items() if k != "tenuo"} or None
        new_params: dict[str, Any] = {**params, "arguments": dict(verification.clean_arguments)}
        if "_meta" in new_params:
            if clean_meta:
                new_params["_meta"] = clean_meta
            else:
                new_params.pop("_meta")
        token = self._call.set(_VerifiedCall(name, snapshot))
        try:
            return await call_next(dataclasses.replace(ctx, params=new_params, meta=clean_meta))
        except _ArgumentBoundaryDenied as exc:
            return _boundary_denial(exc.tool, exc.reason)
        finally:
            self._call.reset(token)
