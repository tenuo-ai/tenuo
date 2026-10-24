"""
FastMCP middleware that delegates every ``tools/call`` authorization decision to
:class:`MCPVerifier`.

Verification semantics (warrant decoding, PoP, constraints, approvals) are
unchanged — this module only wires FastMCP's middleware hook to
:meth:`MCPVerifier.verify` and normalizes request metadata. The verifier also
accepts the gateway-compatible ``arguments._tenuo`` carrier; successful
verification removes it before FastMCP validates and invokes the tool.

``CallToolRequestParams.meta`` (JSON ``_meta``) is read first. On the wire
path FastMCP synthesizes the middleware's ``CallToolRequestParams`` without
``meta`` (FastMCP 3) or with only ``{"fastmcp": {"version": ...}}`` (FastMCP 4,
version-pinned calls), while the raw ``_meta`` — ``tenuo`` included — is
exposed by :attr:`fastmcp.server.context.Context.request_context` ``.meta``
(FastMCP 3: MCP SDK ``RequestContext``; FastMCP 4: ``FastMCPRequestContext``
wrapping the raw dict). Whenever ``params.meta`` lacks ``tenuo``, the request
context's meta is merged underneath it.

MCP Tasks (SEP-2663, FastMCP 4 with ``fastmcp-tasks``): when an authorized
``tools/call`` comes back as a task, the task id is bound to the creating
warrant and holder, and ``tasks/get``/``tasks/update``/``tasks/cancel`` must
present that warrant with a PoP over the request (see :mod:`tenuo.mcp.tasks`).
FastMCP 3 serves its older ``tasks/*`` handlers outside the middleware chain,
so this guard cannot see them there.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

from .server import MCPVerificationResult, MCPVerifier
from .tasks import (
    TASK_METHODS,
    InMemoryTaskBindingStore,
    TaskBindingStore,
    binding_for_created_task,
)

_MCP_INSTALL = 'pip install "tenuo[mcp]"'
_FASTMCP_INSTALL = 'pip install "tenuo[fastmcp]"'

try:
    import mcp.types as mt
    from mcp.types import TextContent

    from ._compat import (
        build_request_params_meta,
        make_error_call_tool_result,
        request_params_meta_as_dict,
    )
except ImportError as exc:
    raise ImportError(
        "tenuo.mcp.fastmcp_middleware requires the MCP SDK. "
        f"Install with: {_MCP_INSTALL} (or pip install mcp)."
    ) from exc

try:
    from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
    from fastmcp.tools.base import ToolResult
except ImportError as exc:
    raise ImportError(
        "tenuo.mcp.fastmcp_middleware requires FastMCP (optional; not part of tenuo[mcp]). "
        f"Install with: {_FASTMCP_INSTALL} (or pip install fastmcp). "
        "The tenuo[mcp] extra installs only the official MCP SDK."
    ) from exc

__all__ = [
    "TOOLRESULT_HAS_IS_ERROR",
    "TenuoMiddleware",
    "resolve_tool_call_meta_for_verify",
]

#: True when the installed FastMCP's ``ToolResult`` carries an ``is_error``
#: flag (FastMCP >= 3.4 and every 4.x). Earlier 3.x has no error flag there.
TOOLRESULT_HAS_IS_ERROR: bool = "is_error" in ToolResult.model_fields


def _meta_as_dict(meta_obj: Any) -> Optional[dict[str, Any]]:
    """Normalize a ``_meta`` object (SDK model, FastMCP 4 dict, or None)."""
    if meta_obj is None:
        return None
    if hasattr(meta_obj, "model_dump"):
        return meta_obj.model_dump(mode="python")
    if isinstance(meta_obj, dict):
        return dict(meta_obj)
    return None


def resolve_tool_call_meta_for_verify(
    params: mt.CallToolRequestParams,
    fastmcp_context: Any,
) -> Optional[dict[str, Any]]:
    """Resolve ``params._meta`` as a plain dict for :meth:`MCPVerifier.verify`.

    ``params.meta`` (MCP SDK alias for JSON ``_meta``) is read first. When it
    is absent or has no ``tenuo`` key and a request context is active,
    ``fastmcp_context.request_context.meta`` is merged underneath it (keys in
    ``params.meta`` win). FastMCP 3 synthesizes wire ``CallToolRequestParams``
    without ``meta``; FastMCP 4 stamps only ``{"fastmcp": {"version": ...}}``
    on version-pinned calls — in both cases the client's ``tenuo`` block lives
    only on the request context.

    Returns ``None`` when no metadata object is present anywhere.
    """
    resolved = _meta_as_dict(params.meta)
    if (resolved is None or "tenuo" not in resolved) and fastmcp_context is not None:
        rc = fastmcp_context.request_context
        ctx_meta = _meta_as_dict(rc.meta) if rc is not None else None
        if ctx_meta:
            resolved = {**ctx_meta, **(resolved or {})}
    return resolved


def _strip_tenuo_meta(
    params: mt.CallToolRequestParams,
    clean_arguments: dict[str, Any],
    resolved_meta: dict[str, Any] | None = None,
) -> mt.CallToolRequestParams:
    """Replace arguments with verifier output and drop ``tenuo`` from ``meta``.

    When ``params.meta`` was ``None`` but *resolved_meta* (obtained from the
    request context) contained ``tenuo``, the non-tenuo remainder is stamped
    onto the returned params so downstream middleware sees clean metadata.
    """
    meta = params.meta
    if meta is None:
        if resolved_meta and "tenuo" in resolved_meta:
            ctx_trimmed = {k: v for k, v in resolved_meta.items() if k != "tenuo"}
            return params.model_copy(
                update={
                    "arguments": clean_arguments,
                    "meta": build_request_params_meta(ctx_trimmed),
                }
            )
        return params.model_copy(update={"arguments": clean_arguments})
    trimmed = request_params_meta_as_dict(meta)
    trimmed.pop("tenuo", None)
    return params.model_copy(
        update={
            "arguments": clean_arguments,
            "meta": build_request_params_meta(trimmed),
        }
    )


class _DenialToolResult(ToolResult):
    """A real ``ToolResult`` that always serializes as an error ``CallToolResult``.

    Subclassing (rather than duck-typing ``to_mcp_result()``) keeps every
    consumer working on every FastMCP line: FastMCP 4 hands anything that is
    not ``isinstance(..., ToolResult)`` straight to the SDK runner, and
    FastMCP's bundled caching / response-limiting middleware read ``.content``,
    ``.structured_content`` and ``.meta`` directly. Overriding
    ``to_mcp_result()`` supplies ``isError`` on FastMCP < 3.4, whose
    ``ToolResult`` has no error flag and only emits a ``CallToolResult`` when
    ``meta`` is set.
    """

    def __init__(
        self,
        *,
        content: list[Any],
        structured_content: dict[str, Any],
    ) -> None:
        flags: dict[str, Any] = {"is_error": True} if TOOLRESULT_HAS_IS_ERROR else {}
        super().__init__(content=content, structured_content=structured_content, **flags)

    def to_mcp_result(self) -> mt.CallToolResult:
        return make_error_call_tool_result(
            content=list(self.content),
            structured_content=dict(self.structured_content or {}),
        )


def _denial_tool_return(verification: MCPVerificationResult) -> ToolResult:
    code = verification.jsonrpc_error_code or -32001
    message = verification.denial_reason or "Authorization denied"
    tenuo_block: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if verification.request_hash:
        tenuo_block["request_hash"] = verification.request_hash
    if verification.approval_metadata:
        meta = verification.approval_metadata
        if "got" in meta:
            tenuo_block["got"] = meta["got"]
        if "need" in meta:
            tenuo_block["need"] = meta["need"]
    return _DenialToolResult(
        content=[TextContent(type="text", text=message)],
        structured_content={"tenuo": tenuo_block},
    )


def _created_task_id(result: Any) -> Optional[str]:
    """The ``taskId`` when a ``tools/call`` outcome is a SEP-2663 task handle."""
    if isinstance(result, Mapping):
        if result.get("resultType") == "task" and isinstance(result.get("taskId"), str):
            return result["taskId"]
        return None
    if getattr(result, "result_type", None) == "task":
        task_id = getattr(result, "task_id", None)
        return task_id if isinstance(task_id, str) else None
    return None


def _jsonrpc_error(code: int, message: str, data: Optional[dict[str, Any]] = None) -> Exception:
    try:
        from mcp.shared.exceptions import MCPError  # type: ignore[attr-defined, unused-ignore]  # mcp 2.x

        return MCPError(code=code, message=message, data=data)
    except ImportError:
        from mcp.shared.exceptions import McpError  # type: ignore[attr-defined, unused-ignore]  # mcp 1.x

        return McpError(mt.ErrorData(code=code, message=message, data=data))


class TenuoMiddleware(Middleware):
    """Run :class:`MCPVerifier` on every ``tools/call`` before the tool runs.

    On success, forwards a copy of the request with
    :attr:`~MCPVerificationResult.clean_arguments`, ``tenuo`` removed from
    ``meta``, and ``_tenuo`` removed from arguments so handlers do not see
    warrant material. On failure, returns a
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

    When an authorized call runs as a task, the task id is bound to the
    creating warrant in *task_bindings*, and ``tasks/*`` requests for it are
    denied with a JSON-RPC error unless they present that warrant and a PoP
    over the request. Pass a shared :class:`~tenuo.mcp.tasks.TaskBindingStore`
    when several processes serve the same tasks.
    """

    def __init__(
        self,
        verifier: MCPVerifier,
        *,
        task_bindings: Optional[TaskBindingStore] = None,
    ) -> None:
        self._verifier = verifier
        self._task_bindings: TaskBindingStore = (
            task_bindings if task_bindings is not None else InMemoryTaskBindingStore()
        )

    async def on_request(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        if context.method not in TASK_METHODS:
            return await call_next(context)
        params = context.message
        if hasattr(params, "model_dump"):
            params = params.model_dump(by_alias=True, exclude_none=True)
        result = self._verifier.verify_task_request(
            context.method, params, bindings=self._task_bindings
        )
        if not result.allowed:
            raise _jsonrpc_error(
                result.jsonrpc_error_code or -32001,
                result.denial_reason or "Authorization denied",
                {"error_type": result.error_type} if result.error_type else None,
            )
        return await call_next(context)

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
        new_message = _strip_tenuo_meta(params, result.clean_arguments, resolved_meta=meta)
        outcome = await call_next(context.copy(message=new_message))
        task_id = _created_task_id(outcome)
        presented = getattr(result, "presented_chain", None)
        if task_id is not None and presented:
            self._task_bindings.put(binding_for_created_task(task_id, presented[-1]))
        return outcome
