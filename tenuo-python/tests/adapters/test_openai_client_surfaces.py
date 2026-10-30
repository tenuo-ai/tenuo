"""
guard() must verify every tool call a real OpenAI client can hand to the app.

These tests drive real ``openai.OpenAI`` / ``openai.AsyncOpenAI`` clients against
an in-process fake server (``httpx.MockTransport``) and run a small "app" that
executes whatever tool calls reach it. A forbidden call must never reach the
app's executor, whichever client surface or tool call type delivered it.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple

import pytest

openai = pytest.importorskip("openai")
httpx = pytest.importorskip("httpx")

from tenuo import NotOneOf, SigningKey, Subpath, Warrant  # noqa: E402
from tenuo.openai import (  # noqa: E402
    AuditEvent,
    MalformedToolCall,
    OpenAIConfigurationError,
    OpenAIConstraintViolation,
    ToolDenied,
    WarrantDenied,
    guard,
)

MSGS = [{"role": "user", "content": "do it"}]


# =============================================================================
# Fake OpenAI server
# =============================================================================


class FakeServer:
    """Serves scripted chat completions and Responses output over MockTransport."""

    def __init__(self) -> None:
        # One list of tool calls per choice; each call is a dict in wire format.
        self.choices: List[List[Dict[str, Any]]] = [[]]
        self.resp_items: List[Dict[str, Any]] = []
        self.chunk_size = 3
        self.split_name = False
        # Legacy ``functions=`` API: one function_call on choice 0.
        self.legacy_call: Optional[Tuple[str, str]] = None
        self.chat_sse_override: Optional[List[Dict[str, Any]]] = None

    # -- scripting -------------------------------------------------------------

    def function_calls(self, *calls: Tuple[str, str]) -> "FakeServer":
        self.choices = [[_fn(n, a) for n, a in calls]]
        self.resp_items = [
            {
                "type": "function_call",
                "id": f"fc_{i}",
                "call_id": f"call_{i}",
                "name": n,
                "arguments": a,
                "status": "completed",
            }
            for i, (n, a) in enumerate(calls)
        ]
        return self

    # -- wire format -----------------------------------------------------------

    def _chat_json(self) -> Dict[str, Any]:
        out = []
        for ci, calls in enumerate(self.choices):
            tcs = [dict(tc, id=f"call_{ci}_{i}") for i, tc in enumerate(calls)]
            out.append(
                {
                    "index": ci,
                    "finish_reason": "tool_calls" if tcs else "stop",
                    "message": {"role": "assistant", "content": None if tcs else "hi", "tool_calls": tcs or None},
                }
            )
        if self.legacy_call:
            name, args = self.legacy_call
            out[0]["finish_reason"] = "function_call"
            out[0]["message"].update(content=None, function_call={"name": name, "arguments": args})
        return {"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o", "choices": out}

    def _chat_sse(self) -> str:
        def chunk(ci: int, delta: Dict[str, Any], finish: Optional[str] = None) -> Dict[str, Any]:
            return {
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "gpt-4o",
                "choices": [{"index": ci, "delta": delta, "finish_reason": finish}],
            }

        if self.chat_sse_override is not None:
            return "".join(f"data: {json.dumps(e)}\n\n" for e in self.chat_sse_override) + "data: [DONE]\n\n"

        k = self.chunk_size
        events = []
        for ci in range(len(self.choices)):
            events.append(chunk(ci, {"role": "assistant", "content": "Sure, "}))
        for ci, calls in enumerate(self.choices):
            for i, tc in enumerate(calls):
                kind = tc["type"]
                name, data = tc[kind]["name"], tc[kind].get("arguments", tc[kind].get("input", ""))
                field_name = "arguments" if kind == "function" else "input"
                head = {"index": i, "id": f"call_{ci}_{i}", "type": kind}
                if self.split_name:
                    half = len(name) // 2
                    events.append(chunk(ci, {"tool_calls": [dict(head, **{kind: {"name": name[:half]}})]}))
                    events.append(chunk(ci, {"tool_calls": [{"index": i, kind: {"name": name[half:]}}]}))
                else:
                    events.append(chunk(ci, {"tool_calls": [dict(head, **{kind: {"name": name}})]}))
                for j in range(0, len(data), k):
                    events.append(chunk(ci, {"tool_calls": [{"index": i, kind: {field_name: data[j : j + k]}}]}))
        if self.legacy_call:
            name, data = self.legacy_call
            events.append(chunk(0, {"function_call": {"name": name}}))
            for j in range(0, len(data), k):
                events.append(chunk(0, {"function_call": {"arguments": data[j : j + k]}}))
        for ci, calls in enumerate(self.choices):
            finish = "function_call" if self.legacy_call and ci == 0 else ("tool_calls" if calls else "stop")
            events.append(chunk(ci, {}, finish))
        return "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"

    def _resp_json(self) -> Dict[str, Any]:
        return {
            "id": "resp_1",
            "object": "response",
            "created_at": 1,
            "model": "gpt-4o",
            "status": "completed",
            "output": self.resp_items,
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "tools": [],
            "error": None,
            "incomplete_details": None,
            "instructions": None,
            "metadata": {},
            "temperature": 1.0,
            "top_p": 1.0,
            "text": {"format": {"type": "text"}},
        }

    def handler(self, request: "httpx.Request") -> "httpx.Response":
        body = json.loads(request.content or b"{}")
        path = request.url.path
        if path.endswith("/chat/completions"):
            if body.get("stream"):
                return httpx.Response(
                    200, headers={"content-type": "text/event-stream"}, content=self._chat_sse().encode()
                )
            return httpx.Response(200, json=self._chat_json())
        if path.endswith("/responses"):
            return httpx.Response(200, json=self._resp_json())
        return httpx.Response(404, json={"error": {"message": "not found"}})

    def sync_client(self) -> Any:
        return openai.OpenAI(
            api_key="test",
            base_url="http://fake.local/v1",
            http_client=httpx.Client(transport=httpx.MockTransport(self.handler)),
        )

    def async_client(self) -> Any:
        return openai.AsyncOpenAI(
            api_key="test",
            base_url="http://fake.local/v1",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(self.handler)),
        )


def _fn(name: str, arguments: str) -> Dict[str, Any]:
    return {"type": "function", "function": {"name": name, "arguments": arguments}}


def _custom(name: str, text: str) -> Dict[str, Any]:
    return {"type": "custom", "custom": {"name": name, "input": text}}


def _chat_chunk(*choices: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": "gpt-4o",
        "choices": list(choices),
    }


# =============================================================================
# The "app": executes whatever tool calls reach it
# =============================================================================


def run_chat(resp: Any) -> List[str]:
    executed = []
    for choice in resp.choices:
        if choice.message.function_call:
            executed.append(choice.message.function_call.name)
        for tc in choice.message.tool_calls or []:
            executed.append(tc.custom.name if tc.type == "custom" else tc.function.name)
    return executed


def run_chat_stream(chunks: List[Any]) -> List[str]:
    """Accumulate like the OpenAI SDK: per (choice, tool index), names concatenated."""
    acc: Dict[Tuple[int, int], str] = {}
    for c in chunks:
        for ch in c.choices:
            fc = ch.delta.function_call
            if fc:
                acc.setdefault((ch.index, -1), "")
                acc[(ch.index, -1)] += fc.name or ""
            for tc in ch.delta.tool_calls or []:
                key = (ch.index, tc.index)
                acc.setdefault(key, "")
                part = tc.function if tc.function else getattr(tc, "custom", None)
                name = (part.get("name") if isinstance(part, dict) else getattr(part, "name", None)) if part else None
                if name:
                    acc[key] += name
    return list(acc.values())


def chat_stream_arguments(chunks: List[Any]) -> Dict[Tuple[int, int], str]:
    """Reconstruct argument strings exactly as an SDK consumer would."""
    acc: Dict[Tuple[int, int], str] = {}
    for chunk in chunks:
        for choice in chunk.choices:
            function_call = choice.delta.function_call
            if function_call:
                key = (choice.index, -1)
                acc[key] = acc.get(key, "") + (function_call.arguments or "")
            for tool_call in choice.delta.tool_calls or []:
                key = (choice.index, tool_call.index)
                part = tool_call.function if tool_call.function else getattr(tool_call, "custom", None)
                arguments = (
                    part.get("arguments") if isinstance(part, dict) else getattr(part, "arguments", None)
                ) if part else None
                acc[key] = acc.get(key, "") + (arguments or "")
    return acc


def run_responses(resp: Any) -> List[str]:
    executed = []
    for item in resp.output:
        if item.type in ("function_call", "custom_tool_call"):
            executed.append(item.name)
        elif item.type.endswith("_call") and getattr(item, "call_id", None):
            executed.append(item.type)
    return executed


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


FORBIDDEN = ("delete_file", '{"path": "/data/x"}')


def policy(**kw: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = dict(
        allow_tools=["search", "read_file"], constraints={"read_file": {"path": Subpath("/data")}}
    )
    base.update(kw)
    return base


# =============================================================================
# Derived clients and other client surfaces
# =============================================================================


class TestDerivedClients:
    def test_with_options_stays_guarded(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.sync_client(), **policy())
        derived = client.with_options(timeout=5)
        assert derived is not client and type(derived).__name__ == "GuardedClient"
        assert derived.session_id == client.session_id
        with pytest.raises(ToolDenied):
            run_chat(derived.chat.completions.create(model="m", messages=MSGS))

    def test_copy_stays_guarded(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_responses(client.copy(max_retries=0).responses.create(model="m", input="x"))

    def test_async_with_options_stays_guarded(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            return run_chat(await client.with_options(timeout=5).chat.completions.create(model="m", messages=MSGS))

        with pytest.raises(ToolDenied):
            asyncio.run(go())

    def test_with_options_skip_mode_drops_call(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN, ("search", "{}"))
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        resp = client.with_options(timeout=5).chat.completions.create(model="m", messages=MSGS)
        assert run_chat(resp) == ["search"]


STRICT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": n,
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    }
    for n in ("read_file", "delete_file")
]


class TestParseHelpers:
    def test_beta_parse_denied(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_chat(client.beta.chat.completions.parse(model="m", messages=MSGS, tools=STRICT_TOOLS))

    def test_beta_parse_async_denied(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            return run_chat(await client.beta.chat.completions.parse(model="m", messages=MSGS, tools=STRICT_TOOLS))

        with pytest.raises(ToolDenied):
            asyncio.run(go())

    def test_parse_allowed_passes(self, server: FakeServer) -> None:
        server.function_calls(("read_file", '{"path": "/data/a"}'))
        client = guard(server.sync_client(), **policy())
        resp = client.chat.completions.parse(model="m", messages=MSGS, tools=STRICT_TOOLS)
        assert run_chat(resp) == ["read_file"]

    def test_responses_parse_denied(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_responses(client.responses.parse(model="m", input="x"))


class TestUnverifiableSurfacesFailClosed:
    @pytest.mark.parametrize(
        "attr", ["conversations", "with_raw_response", "with_streaming_response", "post", "request", "realtime"]
    )
    def test_top_level(self, server: FakeServer, attr: str) -> None:
        client = guard(server.sync_client(), **policy())
        with pytest.raises(OpenAIConfigurationError) as exc:
            getattr(client, attr)
        assert exc.value.code == "CFG_005"
        assert not hasattr(client, attr)

    @pytest.mark.parametrize("attr", ["threads", "assistants", "realtime", "responses"])
    def test_beta_other_than_chat(self, server: FakeServer, attr: str) -> None:
        client = guard(server.sync_client(), **policy())
        with pytest.raises(OpenAIConfigurationError):
            getattr(client.beta, attr)

    def test_raw_post_never_reaches_server(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        client = guard(server.sync_client(), **policy())
        with pytest.raises(OpenAIConfigurationError):
            client.post("/chat/completions", body={"model": "m", "messages": MSGS}, cast_to=object)

    def test_non_tool_attributes_pass_through(self, server: FakeServer) -> None:
        raw = server.sync_client()
        client = guard(raw, **policy())
        assert client.api_key == "test"
        assert client.models is raw.models


# =============================================================================
# Non-function tool call types
# =============================================================================


class TestChatCustomToolCalls:
    def test_custom_call_denied_without_allowlist(self, server: FakeServer) -> None:
        server.choices = [[_custom("delete_file", "/data/x")]]
        client = guard(server.sync_client(), deny_tools=["other"])
        with pytest.raises(ToolDenied):
            run_chat(client.chat.completions.create(model="m", messages=MSGS))

    def test_custom_call_not_in_allowlist_denied(self, server: FakeServer) -> None:
        server.choices = [[_custom("delete_file", "/data/x")]]
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_chat(client.chat.completions.create(model="m", messages=MSGS))

    def test_custom_call_skip_mode_dropped(self, server: FakeServer) -> None:
        server.choices = [[_custom("delete_file", "/data/x"), _fn("search", "{}")]]
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        assert run_chat(client.chat.completions.create(model="m", messages=MSGS)) == ["search"]

    def test_custom_call_allowed_and_input_constrained(self, server: FakeServer) -> None:
        cfg = dict(allow_tools=["read_file"], constraints={"read_file": {"input": Subpath("/data")}})
        server.choices = [[_custom("read_file", "/data/a")]]
        assert run_chat(guard(server.sync_client(), **cfg).chat.completions.create(model="m", messages=MSGS)) == [
            "read_file"
        ]
        server.choices = [[_custom("read_file", "/etc/passwd")]]
        with pytest.raises(OpenAIConstraintViolation):
            run_chat(guard(server.sync_client(), **cfg).chat.completions.create(model="m", messages=MSGS))

    def test_streamed_custom_call_denied(self, server: FakeServer) -> None:
        server.choices = [[_custom("delete_file", "/data/x")]]
        client = guard(server.sync_client(), deny_tools=["other"])
        with pytest.raises(ToolDenied):
            run_chat_stream(list(client.chat.completions.create(model="m", messages=MSGS, stream=True)))


LOCAL_SHELL = {
    "type": "local_shell_call",
    "id": "ls_1",
    "call_id": "c1",
    "status": "completed",
    "action": {"type": "exec", "command": ["rm", "-rf", "/"], "env": {}},
}
APP_EXECUTED_ITEMS = {
    "custom_tool_call": {
        "type": "custom_tool_call",
        "id": "ct_1",
        "call_id": "c1",
        "name": "delete_file",
        "input": "/data/x",
    },
    "local_shell_call": LOCAL_SHELL,
    "tool_search_call": {
        "type": "tool_search_call",
        "id": "ts_1",
        "call_id": None,
        "execution": "client",
        "status": "completed",
        "arguments": {"query": "delete tools"},
    },
    "shell_call": {
        "type": "shell_call",
        "id": "sh_1",
        "call_id": "c1",
        "status": "completed",
        "action": {"commands": ["rm -rf /"], "timeout_ms": 1000, "max_output_length": 100},
    },
    "apply_patch_call": {
        "type": "apply_patch_call",
        "id": "ap_1",
        "call_id": "c1",
        "status": "completed",
        "operation": {"type": "delete_file", "path": "/etc/passwd"},
    },
    "computer_call": {
        "type": "computer_call",
        "id": "cu_1",
        "call_id": "c1",
        "status": "completed",
        "pending_safety_checks": [],
        "action": {"type": "click", "x": 1, "y": 2, "button": "left"},
    },
}


class TestResponsesAppExecutedItems:
    @pytest.mark.parametrize("kind", sorted(APP_EXECUTED_ITEMS))
    def test_denied_by_default(self, server: FakeServer, kind: str) -> None:
        server.resp_items = [APP_EXECUTED_ITEMS[kind]]
        client = guard(server.sync_client(), deny_tools=["other"])
        with pytest.raises(ToolDenied):
            run_responses(client.responses.create(model="m", input="x"))

    @pytest.mark.parametrize("kind", sorted(APP_EXECUTED_ITEMS))
    def test_async_skip_mode_drops_item(self, server: FakeServer, kind: str) -> None:
        server.resp_items = [APP_EXECUTED_ITEMS[kind]]
        client = guard(server.async_client(), **policy(on_denial="skip"))

        async def go() -> List[str]:
            return run_responses(await client.responses.create(model="m", input="x"))

        assert asyncio.run(go()) == []

    def test_local_shell_allowed_by_name_and_constrained(self, server: FakeServer) -> None:
        from tenuo import CEL

        server.resp_items = [dict(LOCAL_SHELL, action={"type": "exec", "command": ["ls"], "env": {}})]
        client = guard(server.sync_client(), allow_tools=["local_shell"])
        assert run_responses(client.responses.create(model="m", input="x")) == ["local_shell_call"]

        server.resp_items = [LOCAL_SHELL]
        cfg = {"local_shell": {"command": CEL("value == ['ls']"), "_allow_unknown": True}}
        client = guard(server.sync_client(), allow_tools=["local_shell"], constraints=cfg)
        with pytest.raises(OpenAIConstraintViolation):
            run_responses(client.responses.create(model="m", input="x"))

    def test_hosted_items_pass_through(self, server: FakeServer) -> None:
        server.resp_items = [
            {"type": "web_search_call", "id": "ws_1", "status": "completed", "action": {"type": "search", "query": "x"}},
            {
                "type": "tool_search_call",
                "id": "ts_1",
                "call_id": "server_call",
                "execution": "server",
                "status": "completed",
                "arguments": {"query": "safe tools"},
            },
        ]
        client = guard(server.sync_client(), **policy())
        resp = client.responses.create(model="m", input="x")
        assert [i.type for i in resp.output] == ["web_search_call", "tool_search_call"]

    def test_tier2_warrant_must_grant_local_shell(self, server: FakeServer) -> None:
        root, agent = SigningKey.generate(), SigningKey.generate()
        warrant = Warrant.mint_builder().capability("search").holder(agent.public_key).ttl(3600).mint(root)
        server.resp_items = [LOCAL_SHELL]
        client = guard(server.sync_client(), warrant=warrant, signing_key=agent, trusted_roots=[root.public_key])
        with pytest.raises(WarrantDenied):
            run_responses(client.responses.create(model="m", input="x"))


# =============================================================================
# Streaming: n>1 choices and split tool names
# =============================================================================


N2 = [[_fn("delete_file", '{"path": "/data/x"}')], [_fn("read_file", "")]]


class TestStreamingChoicesAndNames:
    def test_n2_raise_mode(self, server: FakeServer) -> None:
        server.choices = N2
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_chat_stream(list(client.chat.completions.create(model="m", messages=MSGS, stream=True, n=2)))

    def test_n2_skip_mode_keeps_other_choice(self, server: FakeServer) -> None:
        server.choices = [[_fn("delete_file", '{"path": "/data/x"}')], [_fn("search", "{}")]]
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        chunks = list(client.chat.completions.create(model="m", messages=MSGS, stream=True, n=2))
        assert run_chat_stream(chunks) == ["search"]

    def test_n2_async(self, server: FakeServer) -> None:
        server.choices = N2
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            stream = await client.chat.completions.create(model="m", messages=MSGS, stream=True, n=2)
            return run_chat_stream([c async for c in stream])

        with pytest.raises(ToolDenied):
            asyncio.run(go())

    def test_split_name_denylist(self, server: FakeServer) -> None:
        server.function_calls(FORBIDDEN)
        server.split_name = True
        client = guard(server.sync_client(), deny_tools=["delete_file"])
        with pytest.raises(ToolDenied):
            run_chat_stream(list(client.chat.completions.create(model="m", messages=MSGS, stream=True)))

    def test_split_name_async_allowlist_passes(self, server: FakeServer) -> None:
        server.function_calls(("read_file", '{"path": "/data/a"}'))
        server.split_name = True
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            stream = await client.chat.completions.create(model="m", messages=MSGS, stream=True)
            return run_chat_stream([c async for c in stream])

        assert asyncio.run(go()) == ["read_file"]

    @staticmethod
    def _invalid_index_event(location: str) -> Dict[str, Any]:
        tool_call = {
            "index": -1,
            "id": "call_bad",
            "type": "function",
            "function": {"name": "delete_file", "arguments": '{"path":"/data/x"}'},
        }
        choice_index = -1 if location == "choice" else 0
        return _chat_chunk(
            {
                "index": choice_index,
                "delta": {"tool_calls": [dict(tool_call, index=0 if location == "choice" else -1)]},
                "finish_reason": None,
            }
        )

    @pytest.mark.parametrize("location,expected_tool", [("choice", "unknown"), ("tool", "delete_file")])
    def test_negative_stream_index_is_rejected_and_audited(
        self, server: FakeServer, location: str, expected_tool: str
    ) -> None:
        events: List[AuditEvent] = []
        server.chat_sse_override = [self._invalid_index_event(location)]
        client = guard(server.sync_client(), deny_tools=["delete_file"], audit_callback=events.append)
        with pytest.raises(MalformedToolCall, match="stream index must be a non-negative integer"):
            list(client.chat.completions.create(model="m", messages=MSGS, stream=True))
        assert [(event.decision, event.tool_name) for event in events] == [("DENY", expected_tool)]

    @pytest.mark.parametrize("location,expected_tool", [("choice", "unknown"), ("tool", "delete_file")])
    def test_async_negative_stream_index_is_rejected_and_audited(
        self, server: FakeServer, location: str, expected_tool: str
    ) -> None:
        events: List[AuditEvent] = []
        server.chat_sse_override = [self._invalid_index_event(location)]
        client = guard(server.async_client(), deny_tools=["delete_file"], audit_callback=events.append)

        async def go() -> None:
            stream = await client.chat.completions.create(model="m", messages=MSGS, stream=True)
            [chunk async for chunk in stream]

        with pytest.raises(MalformedToolCall, match="stream index must be a non-negative integer"):
            asyncio.run(go())
        assert [(event.decision, event.tool_name) for event in events] == [("DENY", expected_tool)]

    def test_explicit_null_choice_index_cannot_alias_index_zero(self, server: FakeServer) -> None:
        events: List[AuditEvent] = []
        server.chat_sse_override = [
            _chat_chunk(
                {
                    "index": None,
                    "delta": {"function_call": {"name": "delete_file", "arguments": "{}"}},
                    "finish_reason": None,
                },
                {
                    "index": 0,
                    "delta": {"function_call": {"name": "_safe"}},
                    "finish_reason": None,
                },
            )
        ]
        # If null were normalized to zero, the guard would authorize the
        # combined name while an SDK consumer reconstructed delete_file.
        client = guard(server.sync_client(), allow_tools=["delete_file_safe"], audit_callback=events.append)
        with pytest.raises(MalformedToolCall, match="stream index must be a non-negative integer"):
            list(client.chat.completions.create(model="m", messages=MSGS, stream=True, n=2))
        assert [(event.decision, event.tool_name) for event in events] == [("DENY", "unknown")]

    def test_skip_preserves_allowed_fragments_in_mixed_choice_chunk(self, server: FakeServer) -> None:
        def choice(index: int, delta: Dict[str, Any], finish: Optional[str] = None) -> Dict[str, Any]:
            return {"index": index, "delta": delta, "finish_reason": finish}

        server.chat_sse_override = [
            _chat_chunk(
                choice(0, {"function_call": {"name": "delete_file"}}),
                choice(
                    1,
                    {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_allowed",
                                "type": "function",
                                "function": {"name": "read_file"},
                            }
                        ]
                    },
                ),
            ),
            _chat_chunk(
                choice(
                    1,
                    {"tool_calls": [{"index": 0, "function": {"arguments": '{"path":"/data/'}}]},
                )
            ),
            # This chunk contains a denied legacy fragment and an allowed
            # fragment. Dropping it would mutate the allowed path to /data/x.
            _chat_chunk(
                choice(0, {"function_call": {"arguments": '{"path":"/data/x"}'}}),
                choice(1, {"tool_calls": [{"index": 0, "function": {"arguments": "subdir/"}}]}),
            ),
            _chat_chunk(
                choice(1, {"tool_calls": [{"index": 0, "function": {"arguments": 'x"}'}}]}),
                choice(0, {}, "function_call"),
            ),
            _chat_chunk(choice(1, {}, "tool_calls")),
        ]
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        chunks = list(client.chat.completions.create(model="m", messages=MSGS, stream=True, n=2))

        assert chat_stream_arguments(chunks) == {(1, 0): '{"path":"/data/subdir/x"}'}
        assert not any(choice.delta.function_call for chunk in chunks for choice in chunk.choices)


# =============================================================================
# Legacy functions= / function_call responses
# =============================================================================


class TestLegacyFunctionCall:
    def test_denied(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_chat(client.chat.completions.create(model="m", messages=MSGS))

    def test_constraint_checked(self, server: FakeServer) -> None:
        server.legacy_call = ("read_file", '{"path": "/etc/passwd"}')
        client = guard(server.sync_client(), **policy())
        with pytest.raises(OpenAIConstraintViolation):
            run_chat(client.chat.completions.create(model="m", messages=MSGS))

    def test_allowed_call_passes(self, server: FakeServer) -> None:
        server.legacy_call = ("read_file", '{"path": "/data/a"}')
        client = guard(server.sync_client(), **policy())
        assert run_chat(client.chat.completions.create(model="m", messages=MSGS)) == ["read_file"]

    def test_skip_mode_drops_call(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        assert run_chat(client.chat.completions.create(model="m", messages=MSGS)) == []

    def test_malformed_arguments_dropped_in_skip_mode(self, server: FakeServer) -> None:
        server.legacy_call = ("read_file", '{"path": ')
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        assert run_chat(client.chat.completions.create(model="m", messages=MSGS)) == []

    def test_async_denied(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            return run_chat(await client.chat.completions.create(model="m", messages=MSGS))

        with pytest.raises(ToolDenied):
            asyncio.run(go())

    def test_stream_denied(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.sync_client(), **policy())
        with pytest.raises(ToolDenied):
            run_chat_stream(list(client.chat.completions.create(model="m", messages=MSGS, stream=True)))

    def test_stream_skip_mode_drops_call(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.sync_client(), **policy(on_denial="skip"))
        chunks = list(client.chat.completions.create(model="m", messages=MSGS, stream=True))
        assert run_chat_stream(chunks) == []
        assert not any(ch.delta.function_call for c in chunks for ch in c.choices)

    def test_stream_allowed_call_passes(self, server: FakeServer) -> None:
        server.legacy_call = ("read_file", '{"path": "/data/a"}')
        client = guard(server.sync_client(), **policy())
        assert run_chat_stream(list(client.chat.completions.create(model="m", messages=MSGS, stream=True))) == [
            "read_file"
        ]

    def test_async_stream_denied(self, server: FakeServer) -> None:
        server.legacy_call = FORBIDDEN
        client = guard(server.async_client(), **policy())

        async def go() -> List[str]:
            stream = await client.chat.completions.create(model="m", messages=MSGS, stream=True)
            return run_chat_stream([c async for c in stream])

        with pytest.raises(ToolDenied):
            asyncio.run(go())

    def test_stream_audited(self, server: FakeServer) -> None:
        events: List[AuditEvent] = []
        server.legacy_call = FORBIDDEN
        client = guard(server.sync_client(), **policy(audit_callback=events.append))
        with pytest.raises(ToolDenied):
            list(client.chat.completions.create(model="m", messages=MSGS, stream=True))
        assert [(e.decision, e.tool_name) for e in events] == [("DENY", "delete_file")]


# =============================================================================
# Denial text carries no argument values
# =============================================================================


class TestViolationTextHasNoValues:
    SECRET = "/etc/shadow-sk_live_123"

    def test_constraint_violation_message(self) -> None:
        err = OpenAIConstraintViolation("read_file", "path", self.SECRET, Subpath("/data"))
        assert self.SECRET not in str(err)
        assert "path" in str(err) and err.value == self.SECRET

    def test_type_mismatch_message(self) -> None:
        from tenuo import Range

        err = OpenAIConstraintViolation("f", "n", "sk_live_123", Range(0, 5), type_mismatch=True)
        assert "sk_live_123" not in str(err)

    def test_exclusion_constraint_does_not_echo_rejected_value(self) -> None:
        err = OpenAIConstraintViolation("f", "token", self.SECRET, NotOneOf([self.SECRET]))
        assert self.SECRET not in str(err)
        assert "NotOneOf" in str(err)

    def test_raising_constraint_keeps_value_out_of_text_and_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        class Exploding:
            def satisfies(self, value: Any) -> bool:
                raise RuntimeError(f"cannot check {value}")

        from tenuo.openai import verify_tool_call

        with caplog.at_level("DEBUG"), pytest.raises(OpenAIConstraintViolation) as exc:
            verify_tool_call("f", {"x": self.SECRET}, ["f"], None, {"f": {"x": Exploding()}}, None, None)
        assert self.SECRET not in str(exc.value)
        assert self.SECRET not in caplog.text
        assert "RuntimeError" in caplog.text

    def test_sync_verifier_internal_error_keeps_details_out_of_text_and_logs(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        class ExplodingConstraints(dict):
            def __contains__(self, key: object) -> bool:
                raise RuntimeError(f"cannot inspect {self_secret}")

        from tenuo.openai import verify_tool_call

        self_secret = self.SECRET
        with caplog.at_level("ERROR"), pytest.raises(OpenAIConstraintViolation) as exc:
            verify_tool_call(
                "f",
                {"x": self.SECRET},
                ["f"],
                None,
                {"f": ExplodingConstraints()},
            )
        assert self.SECRET not in str(exc.value)
        assert self.SECRET not in caplog.text
        assert "RuntimeError" in str(exc.value)
        assert "RuntimeError" in caplog.text

    def test_guarded_client_denial_logs_no_value(self, server: FakeServer, caplog: pytest.LogCaptureFixture) -> None:
        events: List[AuditEvent] = []
        server.function_calls(("read_file", json.dumps({"path": self.SECRET})))
        client = guard(server.sync_client(), **policy(on_denial="log", audit_callback=events.append))
        with caplog.at_level("DEBUG"):
            client.chat.completions.create(model="m", messages=MSGS)
        assert self.SECRET not in caplog.text
        assert all(self.SECRET not in e.reason for e in events)


# =============================================================================
# Audit events
# =============================================================================


class TestAuditCoverage:
    def _client(self, server: FakeServer, events: List[AuditEvent], async_: bool = False) -> Any:
        raw = server.async_client() if async_ else server.sync_client()
        return guard(raw, **policy(audit_callback=events.append))

    @pytest.mark.parametrize(
        "call,decision",
        [
            (("read_file", '{"path": "/data/a"}'), "ALLOW"),
            (FORBIDDEN, "DENY"),
            (("read_file", '{"path": "/data/a", "path": "/etc/x"}'), "DENY"),
            (("read_file", '{"path": '), "DENY"),
        ],
    )
    def test_stream_audited(self, server: FakeServer, call: Tuple[str, str], decision: str) -> None:
        events: List[AuditEvent] = []
        server.function_calls(call)
        client = self._client(server, events)
        try:
            list(client.chat.completions.create(model="m", messages=MSGS, stream=True))
        except (ToolDenied, MalformedToolCall):
            pass
        assert [(e.decision, e.tool_name) for e in events] == [(decision, call[0])]

    def test_async_stream_audited(self, server: FakeServer) -> None:
        events: List[AuditEvent] = []
        server.function_calls(("read_file", '{"path": "/data/a"}'))
        client = self._client(server, events, async_=True)

        async def go() -> None:
            stream = await client.chat.completions.create(model="m", messages=MSGS, stream=True)
            [c async for c in stream]

        asyncio.run(go())
        assert [(e.decision, e.tool_name) for e in events] == [("ALLOW", "read_file")]

    @pytest.mark.parametrize("surface", ["chat", "responses"])
    def test_duplicate_key_audited_non_stream(self, server: FakeServer, surface: str) -> None:
        events: List[AuditEvent] = []
        server.function_calls(("read_file", '{"path": "/data/a", "path": "/etc/x"}'))
        client = self._client(server, events)
        with pytest.raises(MalformedToolCall):
            if surface == "chat":
                client.chat.completions.create(model="m", messages=MSGS)
            else:
                client.responses.create(model="m", input="x")
        assert [(e.decision, e.tool_name) for e in events] == [("DENY", "read_file")]
