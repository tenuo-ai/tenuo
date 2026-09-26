"""Tests for :class:`tenuo.mcp.mcpserver_middleware.TenuoServerMiddleware`.

Two layers:

- unit tests drive the middleware with a hand-built ``ServerRequestContext`` and
  a recording ``call_next``, so the rewrite (arguments replaced, carriers
  stripped) and the denial result can be asserted exactly;
- end-to-end tests run a real stdio ``MCPServer`` whose tools have plain
  signatures, behind the middleware, and call it with
  :class:`~tenuo.mcp.SecureMCPClient` using both warrant carriers. That is the
  case the middleware exists for: on the official SDK a decorated tool cannot
  declare ``_tenuo`` (pydantic rejects the leading underscore), so without the
  middleware the argument carrier is pruned before the tool runs.

Requires the MCP SDK 2.x; skipped on 1.x, where ``ServerMiddleware`` does not exist.
"""

from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")
pytest.importorskip("mcp.server.context", reason="requires the MCP SDK 2.x server middleware")

from tenuo import Authorizer, Exact, HolderIdentity, Range, Runtime, SigningKey, Warrant  # noqa: E402
from tenuo.mcp import MCPVerifier, TenuoServerMiddleware  # noqa: E402
from tenuo.mcp._compat import call_tool_result_is_error, call_tool_result_structured_content  # noqa: E402

from mcp.server.context import ServerRequestContext  # noqa: E402

from .._mcp_sdk_support import MCP_SDK2_SERVER_AVAILABLE, MCP_SDK2_SERVER_SKIP_REASON  # noqa: E402

SERVER_SCRIPT = (
    Path(__file__).resolve().parent.parent / "fixtures" / "mcp2_mcpserver_middleware_server.py"
)


# --------------------------------------------------------------------------- helpers


def _warrant(root: SigningKey, holder, limit: float = 100) -> Warrant:
    return (
        Warrant.mint_builder()
        .capability("read_file", path=Exact("/data/a.txt"))
        .capability("argument_keys", path=Exact("/data/a.txt"))
        .capability("issue_refund", amount=Range.max_value(limit))
        .holder(holder)
        .ttl(300)
        .mint(root)
    )


def _envelope(warrant: Warrant, key: SigningKey, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    signature = warrant.sign(key, tool, args, int(time.time()))
    return {"warrant": warrant.to_base64(), "signature": base64.b64encode(bytes(signature)).decode()}


def _ctx(method: str, params: dict[str, Any] | None, *, meta=None, request_id: Any = 1) -> ServerRequestContext:
    return ServerRequestContext(
        session=MagicMock(),
        lifespan_context=None,
        protocol_version="2025-06-18",
        method=method,
        params=params,
        request_id=request_id,
        meta=meta,
    )


class _Recorder:
    def __init__(self) -> None:
        self.contexts: list[ServerRequestContext] = []

    async def __call__(self, ctx: ServerRequestContext) -> dict[str, Any]:
        self.contexts.append(ctx)
        return {"content": [{"type": "text", "text": "ran"}]}


@pytest.fixture
def keys():
    root = SigningKey.generate()
    holder = SigningKey.generate()
    return root, holder


@pytest.fixture
def middleware(keys):
    root, _ = keys
    return TenuoServerMiddleware(MCPVerifier(authorizer=Authorizer(trusted_roots=[root.public_key])))


# --------------------------------------------------------------------------- unit


@pytest.mark.asyncio
async def test_non_tool_methods_and_notifications_pass_through(middleware):
    recorder = _Recorder()
    listed = _ctx("tools/list", None)
    await middleware(listed, recorder)
    notified = _ctx("notifications/initialized", None, request_id=None)
    await middleware(notified, recorder)
    assert recorder.contexts == [listed, notified]


@pytest.mark.asyncio
async def test_meta_carrier_is_verified_and_stripped_before_the_handler(middleware, keys):
    root, holder = keys
    warrant = _warrant(root, holder.public_key)
    args = {"path": "/data/a.txt"}
    meta = {"tenuo": _envelope(warrant, holder, "read_file", args), "trace": "keep-me"}
    recorder = _Recorder()

    result = await middleware(_ctx("tools/call", {"name": "read_file", "arguments": args, "_meta": meta}, meta=meta), recorder)

    assert result == {"content": [{"type": "text", "text": "ran"}]}
    forwarded = recorder.contexts[0]
    assert forwarded.params["arguments"] == args
    assert forwarded.params["_meta"] == {"trace": "keep-me"}
    assert forwarded.meta == {"trace": "keep-me"}


@pytest.mark.asyncio
async def test_argument_carrier_is_verified_and_removed_from_arguments(middleware, keys):
    root, holder = keys
    warrant = _warrant(root, holder.public_key)
    args = {"path": "/data/a.txt"}
    wire_args = {**args, "_tenuo": _envelope(warrant, holder, "read_file", args)}
    recorder = _Recorder()

    await middleware(_ctx("tools/call", {"name": "read_file", "arguments": wire_args}), recorder)

    forwarded = recorder.contexts[0]
    assert forwarded.params["arguments"] == args
    assert "_tenuo" not in forwarded.params["arguments"]
    assert "_meta" not in forwarded.params
    assert forwarded.meta is None


@pytest.mark.asyncio
async def test_denial_returns_an_error_result_without_calling_the_handler(middleware, keys):
    root, holder = keys
    warrant = _warrant(root, holder.public_key)
    args = {"path": "/etc/passwd"}
    wire_args = {**args, "_tenuo": _envelope(warrant, holder, "read_file", args)}
    recorder = _Recorder()

    result = await middleware(_ctx("tools/call", {"name": "read_file", "arguments": wire_args}), recorder)

    assert recorder.contexts == []
    assert call_tool_result_is_error(result)
    block = call_tool_result_structured_content(result)["tenuo"]
    assert block["code"] == -32001  # access denied: constraint violation
    assert "path" in block["message"]


@pytest.mark.asyncio
async def test_missing_envelope_is_denied(middleware):
    recorder = _Recorder()
    result = await middleware(_ctx("tools/call", {"name": "read_file", "arguments": {"path": "/data/a.txt"}}), recorder)
    assert recorder.contexts == []
    assert call_tool_result_is_error(result)
    assert "No warrant" in call_tool_result_structured_content(result)["tenuo"]["message"]


@pytest.mark.asyncio
async def test_untrusted_root_is_denied(middleware, keys):
    _, holder = keys
    stranger = SigningKey.generate()
    forged = _warrant(stranger, holder.public_key, limit=1_000_000)
    args = {"path": "/data/a.txt"}
    wire_args = {**args, "_tenuo": _envelope(forged, holder, "read_file", args)}
    recorder = _Recorder()

    result = await middleware(_ctx("tools/call", {"name": "read_file", "arguments": wire_args}), recorder)

    assert recorder.contexts == []
    assert "not trusted" in call_tool_result_structured_content(result)["tenuo"]["message"]


@pytest.mark.asyncio
async def test_malformed_params_are_left_to_the_sdk(middleware):
    recorder = _Recorder()
    ctx = _ctx("tools/call", {"arguments": "not-a-dict"})
    await middleware(ctx, recorder)
    assert recorder.contexts == [ctx]


# --------------------------------------------------------------------------- end to end


pytestmark_e2e = pytest.mark.skipif(not MCP_SDK2_SERVER_AVAILABLE, reason=MCP_SDK2_SERVER_SKIP_REASON)


def _session(root: SigningKey):
    holder = HolderIdentity.generate()
    runtime = Runtime(holder, trusted_roots=[root.public_key])
    return runtime, runtime.session_from_wire(_warrant(root, holder.public_key).to_base64())


def _client(root: SigningKey, inject_warrant):
    from tenuo.mcp import SecureMCPClient

    # The stdio transport starts the server with a minimal environment; keep a
    # PYTHONPATH so an uninstalled checkout under test is importable there too.
    env = {"PYTHONPATH": os.environ["PYTHONPATH"]} if os.environ.get("PYTHONPATH") else None
    return SecureMCPClient(
        command=sys.executable,
        args=[str(SERVER_SCRIPT), root.public_key.to_bytes().hex()],
        env=env,
        inject_warrant=inject_warrant,
    )


@pytestmark_e2e
@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", [True, "argument"], ids=["_meta", "argument"])
async def test_plain_decorated_tool_runs_behind_the_middleware(carrier):
    root = SigningKey.generate()
    runtime, session = _session(root)
    async with _client(root, carrier) as client:
        with runtime.session_scope(session):
            content = await client.call_tool("read_file", {"path": "/data/a.txt"}, warrant_context=False)
            keys_seen = await client.call_tool("argument_keys", {"path": "/data/a.txt"}, warrant_context=False)
    assert content[0].text == "contents of /data/a.txt"
    # The handler never sees the carrier, whichever way it travelled.
    assert keys_seen[0].text == "arguments=['path'] meta=[]"


@pytestmark_e2e
@pytest.mark.asyncio
async def test_out_of_scope_call_is_refused_by_the_server_even_with_local_check_off():
    from tenuo.exceptions import MCPToolCallError

    root = SigningKey.generate()
    runtime, session = _session(root)
    async with _client(root, "argument") as client:
        with runtime.session_scope(session):
            with pytest.raises(MCPToolCallError) as excinfo:
                await client.call_tool("read_file", {"path": "/etc/passwd"}, warrant_context=False)
    assert excinfo.value.structured_content["tenuo"]["code"] == -32001


@pytestmark_e2e
@pytest.mark.asyncio
async def test_call_without_any_envelope_is_refused():
    from tenuo.exceptions import MCPToolCallError

    root = SigningKey.generate()
    async with _client(root, False) as client:
        with pytest.raises(MCPToolCallError) as excinfo:
            await client.call_tool("read_file", {"path": "/data/a.txt"}, warrant_context=False)
    assert "No warrant" in excinfo.value.structured_content["tenuo"]["message"]
