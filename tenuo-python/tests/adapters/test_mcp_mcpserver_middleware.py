"""Tests for :class:`tenuo.mcp.mcpserver_middleware.TenuoServerMiddleware`.

Two layers:

- unit tests drive the middleware with a hand-built ``ServerRequestContext`` and
  a recording ``call_next``, so the rewrite (arguments replaced, carriers
  stripped) and the denial result can be asserted exactly;
- end-to-end tests run a real stdio ``MCPServer`` whose guarded tools have plain
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
from typing import Annotated, Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("mcp")
pytest.importorskip("mcp.server.context", reason="requires the MCP SDK 2.x server middleware")

from tenuo import Authorizer, Exact, HolderIdentity, Range, Runtime, SigningKey, Warrant  # noqa: E402
from tenuo.mcp import MCPVerifier, TenuoServerMiddleware  # noqa: E402
from tenuo.mcp._compat import call_tool_result_is_error, call_tool_result_structured_content  # noqa: E402

from mcp.server.context import ServerRequestContext  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402
from pydantic import AfterValidator, Field  # noqa: E402

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
        .capability("default_refund", amount=Range.max_value(limit))
        .capability("validated_refund", amount=Range.max_value(limit))
        .capability("refund_effect_count", path=Exact("/data/a.txt"))
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
    # Recording call_next is a raw handler, not a decorated SDK tool.
    return TenuoServerMiddleware(MCPVerifier(authorizer=Authorizer(trusted_roots=[root.public_key])), raw_handler=True)


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


@pytest.fixture
def guarded_server(keys):
    root, _ = keys
    authorization = TenuoServerMiddleware(MCPVerifier(authorizer=Authorizer(trusted_roots=[root.public_key])))
    server = MCPServer("boundary-regression", middleware=[authorization])
    return server, authorization


async def _dispatch_tool(guarded_server, keys, args, *, limit=1000, carrier="argument"):
    server, authorization = guarded_server
    root, holder = keys
    warrant = _warrant(root, holder.public_key, limit=limit)
    envelope = _envelope(warrant, holder, "issue_refund", args)
    params = {"name": "issue_refund", "arguments": args}
    if carrier == "argument":
        params["arguments"] = {**args, "_tenuo": envelope}
    else:
        params["_meta"] = {"tenuo": envelope}

    async def dispatch(ctx):
        # The real SDK argument validation and tool-dispatch path.
        return await server.call_tool(ctx.params["name"], ctx.params["arguments"])

    return await authorization(_ctx("tools/call", params), dispatch)


@pytest.mark.asyncio
async def test_unprotected_decorated_tool_is_denied(guarded_server, keys):
    server, _ = guarded_server
    effects = []

    @server.tool()
    def issue_refund(amount: int) -> str:
        effects.append(amount)
        return "ran"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 1})
    assert call_tool_result_is_error(result)
    assert effects == []


@pytest.mark.asyncio
async def test_duplicate_registration_cannot_mark_raw_callback_protected(guarded_server, keys):
    server, authorization = guarded_server
    effects = []

    @server.tool()
    def issue_refund(amount: int) -> str:
        effects.append(amount)
        return "raw"

    with pytest.raises(ValueError, match="already registered"):
        authorization.tool(server)(issue_refund)
    result = await _dispatch_tool(guarded_server, keys, {"amount": 1})
    assert call_tool_result_is_error(result)
    assert effects == []


@pytest.mark.asyncio
async def test_replacing_guarded_registration_fails_closed(guarded_server, keys):
    server, authorization = guarded_server
    effects = []

    @authorization.tool(server)
    def issue_refund(amount: int) -> str:
        effects.append(amount)
        return "guarded"

    server.remove_tool("issue_refund")

    @server.tool(name="issue_refund")
    def raw(amount: int) -> str:
        effects.append(amount)
        return "raw"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 1})
    assert call_tool_result_is_error(result)
    assert effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["argument", "meta"])
async def test_omitted_default_cannot_add_authority(guarded_server, keys, carrier):
    server, authorization = guarded_server
    effects = []

    @authorization.tool(server)
    def issue_refund(amount: int, destination: str = "unapproved-account") -> str:
        effects.append((amount, destination))
        return "ran"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 1}, carrier=carrier)
    assert call_tool_result_is_error(result)
    assert effects == []


@pytest.mark.asyncio
async def test_explicit_signed_default_is_allowed_once(guarded_server, keys):
    server, authorization = guarded_server
    effects = []

    @authorization.tool(server)
    def issue_refund(amount: int = 10) -> str:
        effects.append(amount)
        return "ran"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 10}, limit=10)
    assert not call_tool_result_is_error(result)
    assert effects == [10]
    # Calling the protected function directly must not reuse a completed request.
    with pytest.raises(MCPError, match="No verified request"):
        await issue_refund(10)
    assert effects == [10]


@pytest.mark.asyncio
async def test_final_argument_check_does_not_consume_nonce_twice(guarded_server, keys):
    server, authorization = guarded_server
    store = MagicMock()
    store.check_and_record.return_value = True
    authorization._verifier._nonce_store = store
    effects = []

    @authorization.tool(server)
    def issue_refund(amount: int) -> str:
        effects.append(amount)
        return "ran"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 1})
    assert not call_tool_result_is_error(result)
    store.check_and_record.assert_called_once()
    assert effects == [1]


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["argument", "meta"])
async def test_validator_cannot_change_signed_amount(guarded_server, keys, carrier):
    server, authorization = guarded_server
    effects = []

    @authorization.tool(server)
    def issue_refund(amount: Annotated[int, AfterValidator(lambda value: value * 100)]) -> str:
        effects.append(amount)
        return "ran"

    result = await _dispatch_tool(guarded_server, keys, {"amount": 1}, limit=10, carrier=carrier)
    assert call_tool_result_is_error(result)
    assert "changed after authorization" in call_tool_result_structured_content(result)["tenuo"]["message"]
    assert effects == []


@pytest.mark.asyncio
async def test_stateful_default_factory_runs_only_once_and_cannot_reach_effect(guarded_server, keys):
    server, authorization = guarded_server
    effects, defaults = [], []

    def next_destination():
        defaults.append(1)
        return "unapproved-account"

    async def issue_refund(amount, destination):
        effects.append((amount, destination))
        return "ran"

    # Concrete annotations also exercise a locally defined default factory.
    issue_refund.__annotations__ = {"amount": int, "destination": str, "return": str}
    issue_refund.__defaults__ = (Field(default_factory=next_destination),)
    authorization.tool(server)(issue_refund)
    result = await _dispatch_tool(guarded_server, keys, {"amount": 1})
    assert call_tool_result_is_error(result)
    assert defaults == [1]
    assert effects == []


@pytest.mark.asyncio
async def test_concurrent_requests_keep_their_own_verified_arguments(guarded_server, keys):
    import asyncio

    server, authorization = guarded_server
    effects = []

    @authorization.tool(server, name="issue_refund")
    async def refund_alias(amount: int) -> str:
        await asyncio.sleep(0)
        effects.append(amount)
        return "ran"

    results = await asyncio.gather(*[
        _dispatch_tool(guarded_server, keys, {"amount": amount}) for amount in (1, 2)
    ])
    assert all(not call_tool_result_is_error(result) for result in results)
    assert sorted(effects) == [1, 2]


@pytest.mark.asyncio
async def test_in_place_validation_cannot_mutate_the_verified_snapshot(guarded_server, keys):
    from tenuo import AnyValue

    server, authorization = guarded_server
    root, holder = keys
    effects = []

    def mutate(values):
        values.append(999)
        return values

    async def issue_refund(amount):
        effects.append(amount)
        return "ran"

    issue_refund.__annotations__ = {"amount": Annotated[list[int], AfterValidator(mutate)], "return": str}
    authorization.tool(server)(issue_refund)
    warrant = Warrant.mint_builder().capability("issue_refund", amount=AnyValue()).holder(holder.public_key).ttl(300).mint(root)
    args = {"amount": [1]}
    envelope = _envelope(warrant, holder, "issue_refund", args)

    async def dispatch(ctx):
        return await server.call_tool("issue_refund", ctx.params["arguments"])

    result = await authorization(_ctx("tools/call", {"name": "issue_refund", "arguments": {**args, "_tenuo": envelope}}), dispatch)
    assert call_tool_result_is_error(result)
    assert effects == []


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


@pytestmark_e2e
@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", [True, "argument"], ids=["_meta", "argument"])
@pytest.mark.parametrize("tool", ["default_refund", "validated_refund"])
async def test_sdk_argument_changes_are_denied_over_stdio_with_zero_effects(carrier, tool):
    from tenuo.exceptions import MCPToolCallError

    root = SigningKey.generate()
    runtime, session = _session(root)
    async with _client(root, carrier) as client:
        with runtime.session_scope(session):
            with pytest.raises(MCPToolCallError) as excinfo:
                await client.call_tool(tool, {"amount": 1}, warrant_context=False)
            assert "changed after authorization" in excinfo.value.structured_content["tenuo"]["message"]
            result = await client.call_tool("refund_effect_count", {"path": "/data/a.txt"}, warrant_context=False)
            assert result[0].text == "0"
