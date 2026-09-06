"""Bridges the API differences between MCP SDK 1.x and 2.x.

MCP 2.0 made four changes that reach Tenuo:

- ``RequestParams.Meta`` (a Pydantic model) became a top-level
  ``RequestParamsMeta`` ``TypedDict``, so request metadata is a plain ``dict``
  at runtime instead of a model.
- ``CallToolResult`` fields were renamed to ``is_error`` and
  ``structured_content``, keeping ``isError`` / ``structuredContent`` only as
  serialization aliases. Construction by alias still works, attribute reads do
  not.
- ``streamablehttp_client`` was removed. Its replacement,
  ``streamable_http_client``, is a different API rather than a rename: it takes
  a caller-built ``AsyncClient`` instead of header, timeout, and auth
  arguments, and it yields ``(read, write)`` where 1.x yielded a third
  session-ID accessor.
- ``ClientSession.call_tool(meta=...)`` is annotated ``RequestParamsMeta``
  rather than ``dict``. That type is a ``TypedDict``, so a plain ``dict``
  remains correct on both lines and no bridging is needed.

Tenuo supports both SDK lines, so each difference is resolved here rather than
at the call sites.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Optional

import mcp.types as mt

__all__ = [
    "MCP_V2",
    "build_request_params_meta",
    "call_tool_result_is_error",
    "call_tool_result_structured_content",
    "make_error_call_tool_result",
    "open_streamable_http_transport",
    "request_params_meta_as_dict",
    "tool_input_schema",
]

#: True when the installed SDK is the 2.x line (top-level ``RequestParamsMeta``).
MCP_V2: bool = hasattr(mt, "RequestParamsMeta")


def request_params_meta_as_dict(meta: Any) -> dict[str, Any]:
    """Return request ``_meta`` as a plain dict, whichever SDK produced it."""
    if meta is None:
        return {}
    if isinstance(meta, dict):
        return dict(meta)
    return meta.model_dump(mode="python", exclude_none=True)


def build_request_params_meta(data: dict[str, Any]) -> Any:
    """Build a value assignable to ``CallToolRequestParams.meta``.

    Returns ``None`` for empty input so callers clear ``_meta`` rather than
    attaching an empty object.
    """
    if not data:
        return None
    if MCP_V2:
        return dict(data)
    # Resolved dynamically because 2.x drops the nested class entirely.
    legacy_meta = getattr(mt.RequestParams, "Meta")
    return legacy_meta.model_validate(data)


def make_error_call_tool_result(
    *,
    content: list[Any],
    structured_content: dict[str, Any],
) -> mt.CallToolResult:
    """Build an error result using whichever field names the SDK defines."""
    fields = mt.CallToolResult.model_fields
    is_error_field = "is_error" if "is_error" in fields else "isError"
    structured_field = (
        "structured_content" if "structured_content" in fields else "structuredContent"
    )
    kwargs: dict[str, Any] = {
        is_error_field: True,
        structured_field: structured_content,
    }
    return mt.CallToolResult(content=content, **kwargs)


def call_tool_result_is_error(result: Any) -> bool:
    """Report whether a tool result is an error.

    Both spellings are probed on every call. Binding only the installed SDK's
    name would fail open against a result built by the other line, and reading
    an error flag as ``False`` turns a server-side denial into an apparent
    success.
    """
    for name in ("is_error", "isError"):
        value = getattr(result, name, None)
        if value is not None:
            return value is True
    return False


def call_tool_result_structured_content(result: Any) -> Optional[dict[str, Any]]:
    """Return a tool result's structured content under either field name."""
    for name in ("structured_content", "structuredContent"):
        value = getattr(result, name, None)
        if value is not None:
            return value
    return None


def tool_input_schema(tool: Any) -> dict[str, Any]:
    """Return a tool's JSON input schema as a plain dict, or ``{}`` if it has none.

    The field is ``input_schema`` on SDK 2.x and ``inputSchema`` on 1.x; the 2.x
    name is probed first because FastMCP 4 warns on the legacy attribute. Only a
    real ``dict`` counts: a permissive ``__getattr__`` (proxies, mocks) must not
    be mistaken for a schema, since callers fail closed on declared properties.
    """
    for name in ("input_schema", "inputSchema"):
        schema = getattr(tool, name, None)
        if isinstance(schema, dict):
            return schema
    return {}


def _sdk_httpx_module() -> Any:
    """Return the HTTP library the installed SDK was built against.

    MCP 2.0 vendors its HTTP stack as ``httpx2``, and an ``httpx.Timeout`` is
    not interchangeable with an ``httpx2.Timeout``, so the timeout has to be
    built from whichever module the SDK itself imported.
    """
    import mcp.shared._httpx_utils as httpx_utils

    module = getattr(httpx_utils, "httpx2", None)
    if module is None:
        module = getattr(httpx_utils, "httpx", None)
    if module is None:  # pragma: no cover - unknown future SDK layout
        raise ImportError(
            "Could not determine the HTTP library used by the installed MCP SDK. "
            "Please report this with your `mcp` version."
        )
    return module


def _as_transport_triple(streams: Any) -> tuple[Any, Any, Any]:
    """Normalise yielded streams to ``(read, write, get_session_id)``.

    1.x supplies a session-ID accessor as a third element; 2.x yields only the
    two streams. Reading positionally keeps this correct for either arity.
    """
    get_session_id = streams[2] if len(streams) > 2 else (lambda: None)
    return streams[0], streams[1], get_session_id


@asynccontextmanager
async def open_streamable_http_transport(
    *,
    url: str,
    headers: Optional[dict[str, str]],
    timeout: Any,
    sse_read_timeout: Any,
    auth: Any,
) -> AsyncIterator[tuple[Any, Any, Any]]:
    """Open a StreamableHTTP transport, yielding ``(read, write, get_session_id)``.

    On MCP 1.x this delegates to ``streamablehttp_client``, which accepts the
    connection settings directly. On 2.x that helper is gone, so an
    ``AsyncClient`` carrying the same settings is built via the SDK's own
    factory and handed to ``streamable_http_client``.

    2.x also yields only ``(read, write)`` and no longer exposes the session ID,
    so a ``get_session_id`` returning ``None`` is substituted to keep the shape
    stable for callers.
    """
    try:
        from mcp.client.streamable_http import (  # type: ignore[import-not-found,attr-defined]
            streamablehttp_client,
        )
    except ImportError:
        pass
    else:
        async with streamablehttp_client(
            url=url,
            headers=headers,
            timeout=timeout,
            sse_read_timeout=sse_read_timeout,
            auth=auth,
        ) as streams:
            yield _as_transport_triple(streams)
            return

    from mcp.client.streamable_http import (  # type: ignore[import-not-found]
        streamable_http_client,
    )
    from mcp.shared._httpx_utils import (  # type: ignore[import-not-found]
        create_mcp_http_client,
    )

    httpx_module = _sdk_httpx_module()
    http_client = create_mcp_http_client(
        headers=headers,
        timeout=httpx_module.Timeout(timeout, read=sse_read_timeout),
        auth=auth,
    )
    async with http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            yield _as_transport_triple(streams)
