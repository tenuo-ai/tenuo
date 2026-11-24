"""The HTTP-level token meter, driven through httpx with no network."""

import gzip
import json
from types import SimpleNamespace

import httpx
import pytest

from tenuo import SigningKey, Warrant
from tenuo.budget import BudgetStore, TokenMeter, llm_capability
from tenuo.budget_http import (
    AsyncMeteredTransport,
    MeteredTransport,
    is_budget_error,
    metered_async_client,
    metered_client,
)

MODEL = "gpt-4o-mini"
INPUT = 30
CHAT = "https://provider.test/v1/chat/completions"
MESSAGES = [{"role": "user", "content": "hello there"}]


# ---------------------------------------------------------------------------
# A provider behind httpx.MockTransport
# ---------------------------------------------------------------------------


def sse(events, done=True):
    text = "".join(f"data: {json.dumps(e)}\n\n" for e in events)
    return (text + ("data: [DONE]\n\n" if done else "")).encode()


class Provider:
    """Answers the wire formats the meter knows, recording every request."""

    def __init__(self, generates=100, status=200, fail=None, chunk_size=None, gzip_stream=False):
        self.generates, self.status, self.fail = generates, status, fail
        self.chunk_size, self.gzip_stream = chunk_size, gzip_stream
        self.requests = []
        self.bodies = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method != "POST":
            return httpx.Response(200, json={"data": []})
        body = json.loads(request.content) if request.content else {}
        self.bodies.append(body)
        if self.fail is not None:
            raise self.fail
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"message": "nope"}})
        path = request.url.path
        if path.endswith("/messages"):
            return self._anthropic(body)
        if path.endswith("/responses"):
            return self._responses(body)
        return self._chat(body)

    def _stream(self, payload: bytes) -> httpx.Response:
        headers = {"content-type": "text/event-stream"}
        if self.gzip_stream:
            payload = gzip.compress(payload)
            headers["content-encoding"] = "gzip"
        size = self.chunk_size or len(payload)
        parts = [payload[i:i + size] for i in range(0, len(payload), size)]
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(b"") if not parts else _Chunks(parts))

    def _chat(self, body):
        cap = body.get("max_completion_tokens") or body.get("max_tokens") or 10**9
        out = min(self.generates, cap) * (body.get("n") or 1)
        usage = {"prompt_tokens": INPUT, "completion_tokens": out, "total_tokens": INPUT + out}
        if not body.get("stream"):
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}], "usage": usage})
        events = [{"choices": [{"index": 0, "delta": {"content": part}}]} for part in ("he", "llo")]
        if (body.get("stream_options") or {}).get("include_usage"):
            events.append({"choices": [], "usage": usage})
        return self._stream(sse(events))

    def _responses(self, body):
        out = min(self.generates, body.get("max_output_tokens") or 10**9)
        usage = {"input_tokens": INPUT, "output_tokens": out, "total_tokens": INPUT + out}
        if not body.get("stream"):
            return httpx.Response(200, json={"output": [], "usage": usage})
        return self._stream(sse([
            {"type": "response.output_text.delta", "delta": "hello"},
            {"type": "response.completed", "response": {"output": [], "usage": usage}},
        ], done=False))

    def _anthropic(self, body):
        out = min(self.generates, body["max_tokens"])
        if not body.get("stream"):
            return httpx.Response(200, json={
                "type": "message", "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 10, "cache_read_input_tokens": 15, "cache_creation_input_tokens": 5,
                          "output_tokens": out},
            })
        text = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in [
            {"type": "message_start", "message": {"usage": {
                "input_tokens": 10, "cache_read_input_tokens": 15, "cache_creation_input_tokens": 5, "output_tokens": 1}}},
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "ok"}},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": out}},
            {"type": "message_stop"},
        ])
        return self._stream(text.encode())


class _Chunks(httpx.SyncByteStream, httpx.AsyncByteStream):
    def __init__(self, parts):
        self.parts = parts
        self.closed = False

    def __iter__(self):
        yield from self.parts

    async def __aiter__(self):
        for part in self.parts:
            yield part

    def close(self):
        self.closed = True

    async def aclose(self):
        self.closed = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keys():
    return SimpleNamespace(issuer=SigningKey.generate(), lead=SigningKey.generate(), worker=SigningKey.generate())


def mint(keys, model=MODEL, **caps):
    return (
        Warrant.mint_builder()
        .capability("llm.chat", llm_capability(models=[model], **caps))
        .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
    )


def client_for(keys, warrant, provider, *, key=None, chain=None, store=None, events=None, **extra):
    meter = TokenMeter(store, input_estimator=lambda request: INPUT)
    http = metered_client(
        transport=httpx.MockTransport(provider), warrant=warrant, signing_key=key or keys.lead,
        trusted_roots=[keys.issuer.public_key], warrant_chain=chain, budget_store=meter,
        audit_callback=events.append if events is not None else None, **extra,
    )
    return http, meter


def chat(http, **extra):
    return http.post(CHAT, json={"model": MODEL, "messages": MESSAGES, **extra})


def used(meter, warrant):
    return meter.store.used(warrant.id)[warrant.id]


# ---------------------------------------------------------------------------
# Chat Completions
# ---------------------------------------------------------------------------


class TestChatCompletions:
    def test_caps_the_request_and_counts_the_response(self, keys):
        warrant = mint(keys, total_tokens=1000, max_tokens=400)
        provider, events = Provider(), []
        http, meter = client_for(keys, warrant, provider, events=events)

        response = chat(http)

        assert response.status_code == 200 and response.json()["usage"]["total_tokens"] == INPUT + 100
        assert provider.bodies[0]["max_completion_tokens"] == 400
        assert int(provider.requests[0].headers["content-length"]) == len(provider.requests[0].content)
        assert used(meter, warrant) == INPUT + 100
        (event,) = events
        assert (event.decision, event.tool_name, event.model) == ("ALLOW", "llm.chat", MODEL)
        assert event.usage["budget"] == [{"warrant_id": warrant.id, "used": INPUT + 100, "limit": 1000}]
        assert event.url == CHAT

    def test_callers_cap_name_is_kept_and_lowered_when_little_is_left(self, keys):
        warrant = mint(keys, total_tokens=200)
        provider = Provider(generates=500)
        http, meter = client_for(keys, warrant, provider)
        chat(http, max_tokens=500)
        assert provider.bodies[0]["max_tokens"] == 170 and "max_completion_tokens" not in provider.bodies[0]
        assert used(meter, warrant) == 200

    def test_older_cap_name_can_be_the_default(self, keys):
        warrant = mint(keys, total_tokens=1000, max_tokens=64)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider, chat_output_param="max_tokens")
        chat(http)
        assert provider.bodies[0]["max_tokens"] == 64 and "max_completion_tokens" not in provider.bodies[0]

    def test_spent_budget_is_refused_locally_as_403(self, keys):
        warrant = mint(keys, total_tokens=150)
        provider, events = Provider(), []
        http, meter = client_for(keys, warrant, provider, events=events)
        assert chat(http).status_code == 200  # 130 used

        refused = chat(http)

        assert refused.status_code == 403
        assert refused.headers["x-should-retry"] == "false"
        error = refused.json()["error"]
        assert error["code"] == "token_budget_exceeded" and "token budget reached" in error["message"]
        assert len(provider.requests) == 1  # never sent
        assert used(meter, warrant) == 130
        assert events[-1].decision == "DENY"
        assert events[-1].usage == {"budget": [{"warrant_id": warrant.id, "used": 130, "limit": 150}]}

    def test_model_outside_the_warrant_is_refused(self, keys):
        warrant = mint(keys, model="some-other-model", total_tokens=1000)
        provider = Provider()
        http, meter = client_for(keys, warrant, provider)
        refused = chat(http)
        assert refused.status_code == 403 and refused.json()["error"]["code"] == "model_call_denied"
        assert provider.requests == [] and used(meter, warrant) == 0

    def test_wrong_holder_key_is_refused(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider, key=keys.worker)
        assert chat(http).status_code == 403
        assert provider.requests == []

    def test_several_choices_are_reserved_for(self, keys):
        warrant = mint(keys, total_tokens=330)
        provider = Provider(generates=500)
        http, meter = client_for(keys, warrant, provider)
        chat(http, n=3, max_tokens=500)
        assert provider.bodies[0]["max_tokens"] == 100 and used(meter, warrant) == 330

    def test_other_request_fields_and_headers_survive(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider)
        http.post(CHAT + "?api-version=1", headers={"authorization": "Bearer abc", "x-custom": "1"},
                  json={"model": MODEL, "messages": MESSAGES, "temperature": 0.2, "tools": [{"type": "function"}]})
        sent = provider.requests[0]
        assert sent.headers["authorization"] == "Bearer abc" and sent.headers["x-custom"] == "1"
        assert sent.url.query == b"api-version=1"
        assert provider.bodies[0]["temperature"] == 0.2 and provider.bodies[0]["tools"] == [{"type": "function"}]
        assert provider.bodies[0]["messages"] == MESSAGES


class TestDelegation:
    def test_workers_spend_from_the_parent(self, keys):
        other = SigningKey.generate()
        root = mint(keys, total_tokens=300)

        def worker(holder):
            return (root.grant_builder().capability("llm.chat", llm_capability(models=[MODEL], total_tokens=250))
                    .holder(holder.public_key).ttl(600).grant(keys.lead))

        one, two = worker(keys.worker), worker(other)
        store, provider = BudgetStore(), Provider(generates=150)
        http_one, _ = client_for(keys, one, provider, key=keys.worker, chain=[root], store=store)
        http_two, _ = client_for(keys, two, provider, key=other, chain=[root], store=store)

        assert chat(http_one, max_tokens=150).status_code == 200  # 180 of the parent's 300
        assert chat(http_two, max_tokens=150).status_code == 200  # capped to 90
        assert provider.bodies[1]["max_tokens"] == 90
        refused = chat(http_two)
        assert refused.status_code == 403 and "delegated from" in refused.json()["error"]["message"]
        assert store.used(root.id, one.id, two.id) == {root.id: 300, one.id: 180, two.id: 120}


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


class TestStreams:
    @pytest.mark.parametrize("chunk_size", [None, 1, 7, 64])
    def test_usage_chunk_is_requested_counted_and_hidden(self, keys, chunk_size):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider(chunk_size=chunk_size)
        http, meter = client_for(keys, warrant, provider)

        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True}) as response:
            text = b"".join(response.iter_raw()).decode()

        assert provider.bodies[0]["stream_options"] == {"include_usage": True}
        assert provider.requests[0].headers["accept-encoding"] == "identity"
        assert '"usage"' not in text and text.count("data: ") == 3 and text.endswith("data: [DONE]\n\n")
        assert used(meter, warrant) == INPUT + 100

    def test_usage_chunk_is_kept_when_the_caller_asked(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider(chunk_size=5)
        http, meter = client_for(keys, warrant, provider)
        body = {"model": MODEL, "messages": MESSAGES, "stream": True, "stream_options": {"include_usage": True}}
        with http.stream("POST", CHAT, json=body) as response:
            text = b"".join(response.iter_raw())
        assert text == sse([{"choices": [{"index": 0, "delta": {"content": p}}]} for p in ("he", "llo")]
                           + [{"choices": [], "usage": {"prompt_tokens": INPUT, "completion_tokens": 100,
                                                        "total_tokens": INPUT + 100}}])
        assert used(meter, warrant) == INPUT + 100

    def test_stream_without_usage_is_charged_the_reservation(self, keys):
        warrant = mint(keys, total_tokens=1000)
        events = []
        http, meter = client_for(keys, warrant, Provider(), events=events)
        body = {"model": MODEL, "messages": MESSAGES, "stream": True, "max_tokens": 200,
                "stream_options": {"include_usage": False}}
        with http.stream("POST", CHAT, json=body) as response:
            response.read()
        assert used(meter, warrant) == INPUT + 200 and events[-1].usage["estimated"] is True

    def test_compressed_stream_passes_through_and_is_charged_the_reservation(self, keys):
        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider(gzip_stream=True))
        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True,
                                             "max_tokens": 200}) as response:
            text = response.read().decode()  # httpx decodes it for the caller as usual
        assert "hello" in text.replace('"}}]}\n\ndata: {"choices": [{"index": 0, "delta": {"content": "', "")
        assert used(meter, warrant) == INPUT + 200

    def test_abandoned_stream_is_charged_the_reservation(self, keys):
        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider(chunk_size=4))
        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True,
                                             "max_tokens": 200}) as response:
            next(response.iter_raw())
        assert used(meter, warrant) == INPUT + 200


# ---------------------------------------------------------------------------
# Other wire formats
# ---------------------------------------------------------------------------


class TestResponsesApi:
    URL = "https://provider.test/v1/responses"

    def test_plain(self, keys):
        warrant = mint(keys, total_tokens=1000, max_tokens=150)
        provider = Provider()
        http, meter = client_for(keys, warrant, provider)
        http.post(self.URL, json={"model": MODEL, "input": "hi"})
        assert provider.bodies[0]["max_output_tokens"] == 150 and used(meter, warrant) == INPUT + 100

    def test_stream_reads_usage_from_the_closing_event(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider(chunk_size=9)
        http, meter = client_for(keys, warrant, provider)
        with http.stream("POST", self.URL, json={"model": MODEL, "input": "hi", "stream": True}) as response:
            text = response.read().decode()
        assert "response.completed" in text and "stream_options" not in provider.bodies[0]
        assert used(meter, warrant) == INPUT + 100


class TestAnthropicMessages:
    URL = "https://api.anthropic.test/v1/messages"
    MODEL = "claude-opus-5-5"

    def body(self, **extra):
        return {"model": self.MODEL, "max_tokens": 1024, "system": "Be brief.", "messages": MESSAGES, **extra}

    def test_plain_counts_cached_input_too(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000, max_tokens=400)
        provider = Provider()
        http, meter = client_for(keys, warrant, provider)
        refused_cap = http.post(self.URL, json=self.body())  # asks for more than the warrant's per-call cap
        assert refused_cap.status_code == 403 and refused_cap.json()["type"] == "error"
        assert refused_cap.json()["error"]["code"] == "model_call_denied"

        response = http.post(self.URL, json=self.body(max_tokens=400))
        assert response.status_code == 200 and provider.bodies[0]["max_tokens"] == 400
        assert used(meter, warrant) == 30 + 100  # 10 fresh + 15 cache read + 5 cache write, plus output

    def test_cap_is_lowered_and_budget_refusal_has_the_anthropic_shape(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=180)
        provider = Provider(generates=500)
        http, meter = client_for(keys, warrant, provider)
        http.post(self.URL, json=self.body())
        assert provider.bodies[0]["max_tokens"] == 150 and used(meter, warrant) == 180
        refused = http.post(self.URL, json=self.body())
        assert refused.status_code == 403
        assert refused.json() == {"type": "error", "error": {
            "type": "permission_error", "code": "token_budget_exceeded", "message": refused.json()["error"]["message"]}}

    def test_stream_adds_input_from_the_first_event_and_output_from_the_last(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        provider = Provider(chunk_size=11)
        http, meter = client_for(keys, warrant, provider)
        with http.stream("POST", self.URL, json=self.body(stream=True, max_tokens=300)) as response:
            text = response.read().decode()
        assert "message_stop" in text and used(meter, warrant) == 30 + 100

    def test_a_stream_closed_midway_is_charged_its_reservation(self, keys):
        # The opening event reports one output token. Whatever was generated
        # before the client hung up, it was more than that.
        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        provider = Provider(chunk_size=40)
        http, meter = client_for(keys, warrant, provider)
        with http.stream("POST", self.URL, json=self.body(stream=True, max_tokens=300)) as response:
            next(response.iter_raw())
        assert used(meter, warrant) == INPUT + 300

    def test_a_stream_dropped_unread_is_settled_when_it_is_collected(self, keys):
        import gc

        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        events = []
        http, meter = client_for(keys, warrant, Provider(chunk_size=40), events=events)
        response = http.send(http.build_request("POST", self.URL, json=self.body(stream=True, max_tokens=300)), stream=True)
        assert not events
        del response
        gc.collect()
        assert [e.decision for e in events] == ["ALLOW"] and events[0].usage["estimated"] and used(meter, warrant) == INPUT + 300


# ---------------------------------------------------------------------------
# Failures
# ---------------------------------------------------------------------------


class TestFailures:
    def test_error_answer_gives_the_tokens_back_and_passes_through(self, keys):
        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider(status=429))
        response = chat(http)
        assert response.status_code == 429 and response.json() == {"error": {"message": "nope"}}
        assert "x-tenuo-denial" not in response.headers and used(meter, warrant) == 0

    def test_connection_never_made_gives_the_tokens_back(self, keys):
        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider(fail=httpx.ConnectError("refused")))
        with pytest.raises(httpx.ConnectError):
            chat(http)
        assert used(meter, warrant) == 0

    def test_a_request_the_client_would_not_send_gives_the_tokens_back(self, keys):
        h11 = pytest.importorskip("h11")
        # What a header with a line break in it raises: nothing was written to the provider.
        try:
            try:
                raise h11.LocalProtocolError("Illegal header value b'Bearer sk\\n'")
            except h11.LocalProtocolError as inner:
                raise httpx.LocalProtocolError("Illegal header value b'Bearer sk\\n'") from inner
        except httpx.LocalProtocolError as e:
            unsendable = e
        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider(fail=unsendable))
        with pytest.raises(httpx.LocalProtocolError):
            chat(http, max_tokens=200)
        assert used(meter, warrant) == 0
        # A protocol error from anywhere else may have come after the request went out.
        http, meter = client_for(keys, warrant, Provider(fail=httpx.LocalProtocolError("stream reset")))
        with pytest.raises(httpx.LocalProtocolError):
            chat(http, max_tokens=200)
        assert used(meter, warrant) == INPUT + 200

    def test_read_timeout_keeps_the_reservation(self, keys):
        warrant = mint(keys, total_tokens=1000)
        events = []
        http, meter = client_for(keys, warrant, Provider(fail=httpx.ReadTimeout("slow")), events=events)
        with pytest.raises(httpx.ReadTimeout):
            chat(http, max_tokens=200)
        assert used(meter, warrant) == INPUT + 200 and events[-1].usage["estimated"] is True

    def test_unreadable_store_blocks_the_call(self, keys):
        class Broken:
            def add(self, deltas, expires_at):
                raise OSError("disk gone")

            def used(self, keys):
                return {k: 0 for k in keys}

        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider, store=BudgetStore(backend=Broken()))
        with pytest.raises(OSError):
            chat(http)
        assert provider.requests == []


# ---------------------------------------------------------------------------
# What is and is not metered
# ---------------------------------------------------------------------------


class TestRouting:
    def test_get_requests_pass_through(self, keys):
        warrant = mint(keys, total_tokens=1)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider)
        assert http.get("https://provider.test/v1/models").status_code == 200
        assert len(provider.requests) == 1

    def test_unknown_post_is_refused_unless_listed(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider)
        refused = http.post("https://provider.test/v1/embeddings", json={"model": "e", "input": "x"})
        assert refused.status_code == 403 and refused.json()["error"]["code"] == "unmetered_endpoint"
        assert provider.requests == []

        allowed, meter = client_for(keys, warrant, provider, unmetered_paths=["/embeddings"])
        assert allowed.post("https://provider.test/v1/embeddings", json={"model": "e", "input": "x"}).status_code == 200
        assert used(meter, warrant) == 0

    def test_token_counting_endpoints_are_free(self, keys):
        warrant = mint(keys, total_tokens=1)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider)
        assert http.post("https://api.anthropic.test/v1/messages/count_tokens", json={}).status_code == 200

    def test_body_that_is_not_json_is_refused(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, _ = client_for(keys, warrant, provider)
        assert http.post(CHAT, content=b"not json").status_code == 403
        assert provider.requests == []

    def test_azure_style_path_is_recognized(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider()
        http, meter = client_for(keys, warrant, provider)
        http.post(f"https://x.test/openai/deployments/{MODEL}/chat/completions?api-version=2024", json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == INPUT + 100

    def test_needs_a_warrant_and_key(self, keys):
        with pytest.raises(ValueError):
            MeteredTransport(httpx.MockTransport(Provider()), warrant=None, signing_key=keys.lead)

    def test_monitor_only_changes_nothing_but_counts(self, keys):
        warrant = mint(keys, total_tokens=50)
        provider = Provider()
        meter = TokenMeter(enforce=False)
        http = metered_client(transport=httpx.MockTransport(provider), warrant=warrant, signing_key=keys.lead,
                              trusted_roots=[keys.issuer.public_key], budget_store=meter)
        for _ in range(2):
            assert chat(http).status_code == 200
        assert all("max_completion_tokens" not in b and "max_tokens" not in b for b in provider.bodies)
        assert used(meter, warrant) == 2 * (INPUT + 100)


class TestIsBudgetError:
    def test_recognizes_sdk_style_errors(self):
        assert is_budget_error(SimpleNamespace(code="token_budget_exceeded", __cause__=None, __context__=None))  # type: ignore[arg-type]

    def test_follows_the_cause_chain(self):
        inner = RuntimeError("x")
        inner.body = {"error": {"code": "token_budget_exceeded"}}  # type: ignore[attr-defined]
        try:
            try:
                raise inner
            except RuntimeError as e:
                raise ValueError("wrapped") from e
        except ValueError as outer:
            assert is_budget_error(outer)
        assert not is_budget_error(RuntimeError("something else"))


# ---------------------------------------------------------------------------
# Async
# ---------------------------------------------------------------------------


class TestAsync:
    def aclient(self, keys, warrant, provider):
        meter = TokenMeter(input_estimator=lambda request: INPUT)
        http = metered_async_client(transport=httpx.MockTransport(provider), warrant=warrant, signing_key=keys.lead,
                                    trusted_roots=[keys.issuer.public_key], budget_store=meter)
        return http, meter

    async def test_plain_and_refusal(self, keys):
        warrant = mint(keys, total_tokens=150)
        provider = Provider()
        http, meter = self.aclient(keys, warrant, provider)
        async with http:
            first = await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
            second = await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
        assert first.status_code == 200 and second.status_code == 403
        assert len(provider.requests) == 1 and used(meter, warrant) == INPUT + 100

    async def test_stream(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider = Provider(chunk_size=6)
        http, meter = self.aclient(keys, warrant, provider)
        async with http, http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True}) as r:
            text = (await r.aread()).decode()
        assert '"usage"' not in text and text.endswith("data: [DONE]\n\n")
        assert used(meter, warrant) == INPUT + 100

    async def test_transport_class_directly(self, keys):
        warrant = mint(keys, total_tokens=1000)
        transport = AsyncMeteredTransport(httpx.MockTransport(Provider()), warrant=warrant, signing_key=keys.lead,
                                          trusted_roots=[keys.issuer.public_key])
        async with httpx.AsyncClient(transport=transport) as http:
            await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
        assert transport.meter.store.used(warrant.id)[warrant.id] > 0


# ---------------------------------------------------------------------------
# The other HTTP library, and picking one for an SDK
# ---------------------------------------------------------------------------


class TestHttpx2:
    """Current OpenAI and Anthropic SDKs are built on httpx2, not httpx."""

    def setup_method(self):
        self.h2 = pytest.importorskip("httpx2")

    def provider(self):
        h2, calls = self.h2, []

        def handle(request):
            body = json.loads(request.content)
            calls.append(body)
            usage = {"prompt_tokens": INPUT, "completion_tokens": 100, "total_tokens": INPUT + 100}
            if body.get("stream"):
                return h2.Response(200, headers={"content-type": "text/event-stream"}, content=sse([
                    {"choices": [{"index": 0, "delta": {"content": "hi"}}]}, {"choices": [], "usage": usage}]))
            return h2.Response(200, json={"choices": [], "usage": usage})

        return h2.MockTransport(handle), calls

    def test_plain_stream_and_refusal(self, keys):
        warrant = mint(keys, total_tokens=270)  # two calls of 130 leave less than a third needs
        transport, calls = self.provider()
        meter = TokenMeter(input_estimator=lambda request: INPUT)
        http = metered_client(library=self.h2, transport=transport, warrant=warrant, signing_key=keys.lead,
                              trusted_roots=[keys.issuer.public_key], budget_store=meter)
        assert isinstance(http, self.h2.Client)

        assert http.post(CHAT, json={"model": MODEL, "messages": MESSAGES}).status_code == 200
        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True}) as response:
            text = response.read().decode()
        assert '"usage"' not in text and used(meter, warrant) == 2 * (INPUT + 100)

        refused = http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
        assert isinstance(refused, self.h2.Response) and refused.status_code == 403
        assert len(calls) == 2

    async def test_async(self, keys):
        warrant = mint(keys, total_tokens=1000)
        transport, _ = self.provider()
        meter = TokenMeter(input_estimator=lambda request: INPUT)
        http = metered_async_client(library=self.h2, transport=transport, warrant=warrant, signing_key=keys.lead,
                                    trusted_roots=[keys.issuer.public_key], budget_store=meter)
        async with http:
            await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == INPUT + 100


class TestSdkArgument:
    @pytest.mark.parametrize("name", ["openai", "anthropic"])
    def test_client_is_the_sdks_own_class_on_the_sdks_library(self, keys, name):
        sdk = pytest.importorskip(name)
        warrant = mint(keys, total_tokens=1000)
        common = dict(sdk=sdk, warrant=warrant, signing_key=keys.lead, trusted_roots=[keys.issuer.public_key])
        http, ahttp = metered_client(**common), metered_async_client(**common)
        assert isinstance(http, sdk.DefaultHttpxClient) and isinstance(ahttp, sdk.DefaultAsyncHttpxClient)
        # The SDK accepts it: constructing a client with a foreign library's client raises.
        client_class = sdk.OpenAI if name == "openai" else sdk.Anthropic
        client_class(api_key="unused", http_client=http)

    def test_unknown_meter_argument_is_rejected(self, keys):
        with pytest.raises(TypeError):
            MeteredTransport(httpx.MockTransport(Provider()), warrant=mint(keys), signing_key=keys.lead, budgt_store=1)


# ---------------------------------------------------------------------------
# Google generateContent (Gemini API and Vertex AI)
# ---------------------------------------------------------------------------


class GoogleProvider:
    def __init__(self, generates=100, chunk_size=None, thoughts=0):
        self.generates, self.chunk_size, self.thoughts = generates, chunk_size, thoughts
        self.requests, self.bodies = [], []

    def __call__(self, request):
        self.requests.append(request)
        body = json.loads(request.content)
        self.bodies.append(body)
        cap = (body.get("generationConfig") or {}).get("maxOutputTokens") or 10**9
        out = min(self.generates, cap)
        meta = {"promptTokenCount": INPUT, "candidatesTokenCount": out, "totalTokenCount": INPUT + out + self.thoughts}
        if self.thoughts:
            meta["thoughtsTokenCount"] = self.thoughts
        content = {"role": "model", "parts": [{"text": "ok"}]}
        chunk = {"candidates": [{"content": content, "finishReason": "STOP"}], "usageMetadata": meta}
        if ":streamGenerateContent" not in request.url.path:
            return httpx.Response(200, json=chunk)
        early = {"candidates": [{"content": content}],
                 "usageMetadata": {"promptTokenCount": INPUT, "candidatesTokenCount": 1, "totalTokenCount": INPUT + 1}}
        if request.url.params.get("alt") == "sse":
            payload = sse([early, chunk], done=False)
            size = self.chunk_size or len(payload)
            parts = [payload[i:i + size] for i in range(0, len(payload), size)]
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=_Chunks(parts))
        return httpx.Response(200, json=[early, chunk])


class TestGoogleGenerate:
    MODEL = "gemini-2.5-flash"
    URL = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
    STREAM = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:streamGenerateContent"
    BODY = {"contents": [{"role": "user", "parts": [{"text": "hello there"}]}]}

    def test_model_comes_from_the_path_and_the_cap_goes_in_generation_config(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000, max_tokens=400)
        provider, events = GoogleProvider(), []
        http, meter = client_for(keys, warrant, provider, events=events)
        response = http.post(self.URL, json={**self.BODY, "generationConfig": {"temperature": 0.1}})
        assert response.status_code == 200
        assert provider.bodies[0]["generationConfig"] == {"temperature": 0.1, "maxOutputTokens": 400}
        assert used(meter, warrant) == INPUT + 100
        assert events[0].model == self.MODEL and events[0].max_tokens == 400

    def test_other_model_in_the_path_is_refused_in_googles_error_shape(self, keys):
        warrant = mint(keys, model="gemini-other", total_tokens=1000)
        provider = GoogleProvider()
        http, _ = client_for(keys, warrant, provider)
        refused = http.post(self.URL, json=self.BODY)
        assert refused.status_code == 403 and provider.requests == []
        error = refused.json()["error"]
        assert (error["code"], error["status"]) == (403, "PERMISSION_DENIED")
        assert error["details"][0]["reason"] == "model_call_denied"

    def test_callers_cap_is_lowered_and_thinking_counts_as_output(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=200)
        provider, events = GoogleProvider(generates=500, thoughts=20), []
        http, meter = client_for(keys, warrant, provider, events=events)
        http.post(self.URL, json={**self.BODY, "generationConfig": {"maxOutputTokens": 500}})
        assert provider.bodies[0]["generationConfig"]["maxOutputTokens"] == 170
        assert events[0].usage["output_tokens"] == 190 and used(meter, warrant) == 220
        assert events[0].usage["over_budget"] == [warrant.id]  # the provider thought past the cap
        refused = http.post(self.URL, json=self.BODY)
        assert refused.json()["error"]["details"][0]["reason"] == "token_budget_exceeded"

    @pytest.mark.parametrize("chunk_size", [None, 3, 40])
    def test_sse_stream_takes_the_last_chunks_totals(self, keys, chunk_size):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        http, meter = client_for(keys, warrant, GoogleProvider(chunk_size=chunk_size))
        with http.stream("POST", self.STREAM + "?alt=sse", json=self.BODY) as response:
            text = response.read().decode()
        assert text.count("usageMetadata") == 2 and used(meter, warrant) == INPUT + 100

    def test_json_array_stream(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        http, meter = client_for(keys, warrant, GoogleProvider())
        assert len(http.post(self.STREAM, json=self.BODY).json()) == 2
        assert used(meter, warrant) == INPUT + 100

    def test_vertex_path_and_free_token_counting(self, keys):
        warrant = mint(keys, model=self.MODEL, total_tokens=1000)
        provider = GoogleProvider()
        http, meter = client_for(keys, warrant, provider)
        vertex = ("https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/google/models/"
                  f"{self.MODEL}:generateContent")
        assert http.post(vertex, json=self.BODY).status_code == 200 and used(meter, warrant) == INPUT + 100
        count = f"https://generativelanguage.googleapis.com/v1beta/models/{self.MODEL}:countTokens"
        assert http.post(count, json=self.BODY).status_code == 200 and used(meter, warrant) == INPUT + 100


# ---------------------------------------------------------------------------
# install(): no wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def installed(keys):
    from tenuo.budget_http import install, uninstall

    def do(warrant=None, key=None, **extra):
        return install(warrant=warrant, signing_key=key, trusted_roots=[keys.issuer.public_key],
                       budget_store=TokenMeter(input_estimator=lambda request: INPUT), **extra)

    yield do
    uninstall()


class TestInstall:
    OPENAI = "https://api.openai.com/v1/chat/completions"

    def plain_client(self, provider, lib=httpx):
        return lib.Client(transport=lib.MockTransport(provider))

    def test_any_client_is_metered_without_wiring(self, keys, installed):
        warrant = mint(keys, total_tokens=150)
        meter = installed(warrant, keys.lead)
        provider = Provider()
        http = self.plain_client(provider)
        assert http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES}).status_code == 200
        assert provider.bodies[0]["max_completion_tokens"] == 120  # 150 total, 30 of it input
        refused = http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES})
        assert refused.status_code == 403 and refused.json()["error"]["code"] == "token_budget_exceeded"
        assert len(provider.requests) == 1 and used(meter, warrant) == INPUT + 100

    def test_clients_made_before_install_are_metered_too(self, keys, installed):
        provider = Provider()
        http = self.plain_client(provider)
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead)
        http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == INPUT + 100

    def test_other_hosts_are_left_alone(self, keys, installed):
        warrant = mint(keys, total_tokens=1)
        meter = installed(warrant, keys.lead)
        seen = []

        def chat_app(request):  # some other service whose path happens to end in /messages
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True})

        http = httpx.Client(transport=httpx.MockTransport(chat_app))
        body = {"channel": "general", "text": "hello"}
        assert http.post("https://chat.example.test/api/messages", json=body).status_code == 200
        assert seen == [body] and used(meter, warrant) == 0

    def test_extra_hosts_and_subdomains(self, keys, installed):
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead, hosts=["gateway.internal:8080"])
        provider = Provider()
        http = self.plain_client(provider)
        http.post("http://gateway.internal:8080/v1/chat/completions", json={"model": MODEL, "messages": MESSAGES})
        http.post(f"https://myresource.openai.azure.com/openai/deployments/{MODEL}/chat/completions",
                  json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == 2 * (INPUT + 100)

    def test_each_agent_spends_from_the_warrant_in_scope(self, keys, installed):
        from tenuo import key_scope, warrant_scope

        other = SigningKey.generate()
        one = mint(keys, total_tokens=1000)
        two = (Warrant.mint_builder().capability("llm.chat", llm_capability(models=[MODEL], total_tokens=1000))
               .holder(other.public_key).ttl(600).mint(keys.issuer))
        meter = installed()  # no default credentials
        provider = Provider()
        http = self.plain_client(provider)
        request = {"model": MODEL, "messages": MESSAGES}

        no_warrant = http.post(self.OPENAI, json=request)
        assert no_warrant.status_code == 403 and "no warrant" in no_warrant.json()["error"]["message"]
        with warrant_scope(one), key_scope(keys.lead):
            http.post(self.OPENAI, json=request)
        with warrant_scope(two), key_scope(other):
            http.post(self.OPENAI, json=request)
            http.post(self.OPENAI, json=request)
        assert meter.store.used(one.id, two.id) == {one.id: INPUT + 100, two.id: 2 * (INPUT + 100)}
        assert len(provider.requests) == 3

    def test_explicitly_metered_client_is_not_counted_twice(self, keys, installed):
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead)
        http = metered_client(transport=httpx.MockTransport(Provider()), warrant=warrant, signing_key=keys.lead,
                              trusted_roots=[keys.issuer.public_key], budget_store=meter)
        http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == INPUT + 100

    def test_uninstall_restores_the_clients(self, keys, installed):
        from tenuo.budget_http import uninstall

        original = httpx.Client._transport_for_url
        warrant = mint(keys, total_tokens=1)
        installed(warrant, keys.lead)
        assert httpx.Client._transport_for_url is not original
        provider = Provider()
        http = self.plain_client(provider)
        assert http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES}).status_code == 403
        uninstall()
        assert httpx.Client._transport_for_url is original
        assert http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES}).status_code == 200

    def test_httpx2_clients(self, keys, installed):
        h2 = pytest.importorskip("httpx2")
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead)
        calls = []

        def handle(request):
            calls.append(json.loads(request.content))
            return h2.Response(200, json={"choices": [], "usage": {"prompt_tokens": INPUT, "completion_tokens": 100,
                                                                    "total_tokens": INPUT + 100}})

        h2.Client(transport=h2.MockTransport(handle)).post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES})
        assert "max_completion_tokens" in calls[0] and used(meter, warrant) == INPUT + 100

    async def test_async_clients(self, keys, installed):
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead)
        async with httpx.AsyncClient(transport=httpx.MockTransport(Provider())) as http:
            await http.post(self.OPENAI, json={"model": MODEL, "messages": MESSAGES})
        assert used(meter, warrant) == INPUT + 100


class TestWhatTheBodyDoesNotShowAtFirstGlance:
    def test_a_list_of_prompts_and_best_of_multiply_the_output(self, keys):
        warrant = mint(keys, total_tokens=100_000)
        provider = Provider()
        http, meter = client_for(keys, warrant, provider)
        url = "https://provider.test/v1/completions"
        reserved = []
        original = meter.store.add
        meter.store.add = lambda deltas, expires: (reserved.append(max(deltas.values())), original(deltas, expires))[1]
        http.post(url, json={"model": MODEL, "prompt": ["a", "b", "c"], "max_tokens": 50, "n": 2})
        http.post(url, json={"model": MODEL, "prompt": "one", "max_tokens": 50, "best_of": 4})
        http.post(url, json={"model": MODEL, "prompt": [1, 2, 3], "max_tokens": 50})  # one prompt, as token ids
        assert [r for r in reserved if r > 0] == [INPUT + 50 * 6, INPUT + 50 * 4, INPUT + 50]

    def test_a_redirect_is_not_charged_as_a_call(self, keys):
        warrant = mint(keys, total_tokens=1000)
        provider, hops = Provider(), []

        def redirect_once(request):
            hops.append(request.url.path)
            return httpx.Response(307, headers={"location": CHAT}) if len(hops) == 1 else provider(request)

        http, meter = client_for(keys, warrant, redirect_once)
        response = http.post(CHAT, json={"model": MODEL, "messages": MESSAGES}, follow_redirects=True)
        assert response.status_code == 200 and len(hops) == 2
        assert used(meter, warrant) == INPUT + 100  # one call, not two

    def test_a_total_below_its_parts_is_not_believed(self):
        from tenuo.budget import usage_counts

        assert usage_counts({"prompt_tokens": 30, "completion_tokens": 100, "total_tokens": 0}) == {
            "input_tokens": 30, "output_tokens": 100, "total_tokens": 130}


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------


def worker_of(keys, root, total):
    return (root.grant_builder().capability("llm.chat", llm_capability(models=[MODEL], total_tokens=total))
            .holder(keys.worker.public_key).ttl(600).grant(keys.lead))


class TestEdges:
    def test_parents_taken_from_chain_scope_are_charged_too(self, keys):
        from tenuo import chain_scope

        root = mint(keys, total_tokens=200)
        worker = worker_of(keys, root, 200)
        provider = Provider()
        http, meter = client_for(keys, worker, provider, key=keys.worker)  # no warrant_chain given to the client
        with chain_scope([root]):
            assert chat(http).status_code == 200
            assert used(meter, worker) == used(meter, root) == INPUT + 100
            meter.store.add({root.id: 60})  # someone else spends from the parent
            refused = chat(http)
        assert refused.status_code == 403 and "delegated from" in refused.json()["error"]["message"]

    def test_usage_above_a_reservation_is_not_lost_when_the_store_fails(self, keys):
        from tenuo.budget import InMemoryBudgetBackend

        class FailsOnce(InMemoryBudgetBackend):
            fail = False

            def add(self, deltas, expires_at):
                if self.fail:
                    self.fail = False
                    raise OSError("disk full")
                return super().add(deltas, expires_at)

        backend, caps = FailsOnce(), []

        def generous(request):  # a provider that goes far past the cap it was given, the first time
            cap = json.loads(request.content)["max_completion_tokens"]
            caps.append(cap)
            out = 500 if len(caps) == 1 else cap
            backend.fail = len(caps) == 1  # the write that follows the first response fails
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}],
                                             "usage": {"prompt_tokens": INPUT, "completion_tokens": out, "total_tokens": INPUT + out}})

        warrant = mint(keys, total_tokens=600)
        http, meter = client_for(keys, warrant, generous, store=BudgetStore(backend=backend))
        assert chat(http, max_completion_tokens=100).status_code == 200
        assert backend.used([warrant.id])[warrant.id] == INPUT + 100   # only the reservation reached the backend
        assert used(meter, warrant) == INPUT + 500                      # the rest is owed, and counted
        # The next call is planned against 530 of 600, not 130: it gets what is really left.
        assert chat(http, max_completion_tokens=100).status_code == 200 and caps == [100, 40]
        assert backend.used([warrant.id])[warrant.id] == 600            # and the debt went in with that write
        assert chat(http, max_completion_tokens=100).status_code == 403

    def test_a_failure_after_the_reservation_gives_it_back(self, keys, monkeypatch):
        from tenuo import budget_http

        warrant = mint(keys, total_tokens=1000)
        http, meter = client_for(keys, warrant, Provider())
        monkeypatch.setattr(budget_http._OpenAIChat, "write_cap", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
        with pytest.raises(RuntimeError):
            chat(http)
        assert used(meter, warrant) == 0

    def test_stream_options_that_are_not_an_object_are_left_for_the_provider(self, keys):
        warrant = mint(keys, total_tokens=1000)
        seen = []
        http, meter = client_for(keys, warrant, lambda r: (seen.append(json.loads(r.content)), httpx.Response(400, json={}))[1])
        assert chat(http, stream=True, stream_options="bad").status_code == 400
        assert seen[0]["stream_options"] == "bad" and used(meter, warrant) == 0

    def test_mounts_and_proxies_cannot_route_around_the_meter(self, keys):
        warrant = mint(keys, total_tokens=1000)
        common = dict(warrant=warrant, signing_key=keys.lead, trusted_roots=[keys.issuer.public_key])
        with pytest.raises(TypeError, match="mounts"):
            metered_client(mounts={"https://": httpx.HTTPTransport()}, **common)
        with pytest.raises(TypeError, match="proxy"):
            metered_client(proxy="http://proxy.internal:3128", **common)
        with pytest.raises(TypeError, match="proxy"):
            metered_async_client(proxy="http://proxy.internal:3128", **common)

    def test_monitor_only_forwards_what_it_cannot_count(self, keys):
        warrant = mint(keys, total_tokens=10)
        seen = []
        http = metered_client(
            transport=httpx.MockTransport(lambda r: (seen.append(r.url.path), httpx.Response(200, json={"data": []}))[1]),
            warrant=warrant, signing_key=keys.lead, trusted_roots=[keys.issuer.public_key], budget_store=TokenMeter(enforce=False))
        assert http.post("https://provider.test/v1/embeddings", json={"model": MODEL, "input": "x"}).status_code == 200
        assert http.post(CHAT, content=b"not json").status_code == 200
        assert seen == ["/v1/embeddings", "/v1/chat/completions"]

    def test_monitor_only_sends_a_stream_request_unchanged(self, keys):
        warrant = mint(keys, total_tokens=10)
        requests = []
        provider = Provider()

        def record(request):
            requests.append(request)
            return provider(request)

        meter = TokenMeter(enforce=False)
        http = metered_client(transport=httpx.MockTransport(record), warrant=warrant, signing_key=keys.lead,
                              trusted_roots=[keys.issuer.public_key], budget_store=meter)
        body = {"model": MODEL, "messages": MESSAGES, "stream": True}
        with http.stream("POST", CHAT, json=body, headers={"accept-encoding": "gzip"}) as response:
            response.read()
        assert json.loads(requests[0].content) == body                 # no stream_options added, no cap set
        assert requests[0].headers["accept-encoding"] == "gzip"        # and no header rewritten
        # A caller that asks for usage itself is counted.
        with http.stream("POST", CHAT, json={**body, "stream_options": {"include_usage": True}}) as response:
            response.read()
        assert used(meter, warrant) == INPUT + 100

    def test_async_calls_do_not_hold_the_event_loop_on_a_store_that_waits(self, keys):
        import asyncio
        import time

        from tenuo.budget import InMemoryBudgetBackend

        class Slow(InMemoryBudgetBackend):
            def add(self, deltas, expires_at):
                time.sleep(0.25)  # another writer has the file
                return super().add(deltas, expires_at)

        class SlowStore(BudgetStore):
            blocking = True

        warrant = mint(keys, total_tokens=1000)
        store = SlowStore(backend=Slow())
        meter = TokenMeter(store, input_estimator=lambda request: INPUT)

        async def main():
            stalls, last = [], time.monotonic()

            async def ticker():
                nonlocal last
                while True:
                    await asyncio.sleep(0.01)
                    stalls.append(time.monotonic() - last)
                    last = time.monotonic()

            task = asyncio.ensure_future(ticker())
            http = metered_async_client(transport=httpx.MockTransport(Provider()), warrant=warrant, signing_key=keys.lead,
                                        trusted_roots=[keys.issuer.public_key], budget_store=meter)
            response = await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})
            # A caller that gives up while its reservation is being written gets it back.
            doomed = asyncio.ensure_future(http.post(CHAT, json={"model": MODEL, "messages": MESSAGES}))
            await asyncio.sleep(0.05)
            doomed.cancel()
            await asyncio.sleep(0.8)
            task.cancel()
            await http.aclose()
            return response.status_code, max(stalls)

        status, longest = asyncio.run(main())
        assert status == 200 and longest < 0.15, f"the loop stalled for {longest:.2f}s"
        assert used(meter, warrant) == INPUT + 100  # the cancelled call left nothing behind


class TestInstallEdges:
    OPENAI = "https://api.openai.com/v1"

    def plain(self, handler):
        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_regional_vertex_hosts_are_metered(self, keys, installed):
        model = "gemini-2.5-flash"
        installed(mint(keys, model=model, total_tokens=1), keys.lead)
        seen = []
        http = self.plain(lambda r: (seen.append(r.url.host), httpx.Response(200, json={}))[1])
        url = (f"https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/"
               f"publishers/google/models/{model}:generateContent")
        refused = http.post(url, json={"contents": [{"role": "user", "parts": [{"text": "hello"}]}]})
        assert refused.status_code == 403 and not seen
        assert http.post("https://not-aiplatform.googleapis.com.example.test/v1/x", json={}).status_code == 200

    def test_without_credentials_a_post_that_cannot_be_counted_is_refused_too(self, keys, installed):
        installed(unmetered_paths=["/moderations"])  # no default warrant: callers bring one in scope
        seen = []
        http = self.plain(lambda r: (seen.append(r.url.path), httpx.Response(200, json={"data": []}))[1])
        refused = http.post(self.OPENAI + "/embeddings", json={"model": MODEL, "input": "x"})
        assert refused.status_code == 403 and refused.json()["error"]["code"] == "unmetered_endpoint"
        assert http.post(self.OPENAI + "/moderations", json={"input": "x"}).status_code == 200
        assert http.get(self.OPENAI + "/models").status_code == 200
        assert seen == ["/v1/moderations", "/v1/models"]

    def test_a_warrant_given_as_a_chain_or_encoded_is_taken_apart_first(self, keys, installed):
        root = mint(keys, total_tokens=1000)
        worker = worker_of(keys, root, 500)
        meter = installed([root, worker], keys.worker)
        http = self.plain(Provider())
        body = {"model": MODEL, "messages": MESSAGES}
        assert http.post(self.OPENAI + "/chat/completions", json=body).status_code == 200
        assert used(meter, worker) == used(meter, root) == INPUT + 100
        from tenuo.budget_http import install

        meter = install(warrant=root.to_base64(), signing_key=keys.lead, trusted_roots=[keys.issuer.public_key],
                        budget_store=TokenMeter(input_estimator=lambda request: INPUT))
        assert http.post(self.OPENAI + "/chat/completions", json=body).status_code == 200
        assert used(meter, root) == INPUT + 100


class TestMoreEdges:
    def test_a_wildcard_parents_budget_is_shared_by_its_delegates(self, keys):
        # The parent grants every tool, with one token total for all of it.
        root = (Warrant.mint_builder().capability("*", llm_capability(total_tokens=200))
                .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer))
        worker = (root.grant_builder().capability("llm.chat", llm_capability(total_tokens=200))
                  .holder(keys.worker.public_key).ttl(600).grant(keys.lead))
        http, meter = client_for(keys, worker, Provider(), key=keys.worker, chain=[root])
        assert [(lv.own, lv.limit) for lv in meter.levels(worker, [root])] == [(False, 200), (True, 200)]
        assert chat(http).status_code == 200 and used(meter, root) == INPUT + 100
        meter.store.add({root.id: 60})  # another delegate of the same parent
        refused = chat(http)
        assert refused.status_code == 403 and "delegated from" in refused.json()["error"]["message"]
        # The tool's own capability wins over the wildcard, as in the warrant check.
        both = (Warrant.mint_builder().capability("*", llm_capability(total_tokens=5))
                .capability("llm.chat", llm_capability(total_tokens=900))
                .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer))
        assert meter.levels(both)[0].limit == 900

    @pytest.mark.parametrize("usage", [{}, {"service_tier": "standard"}, {"input_tokens": None, "output_tokens": "many"}])
    def test_an_anthropic_usage_object_without_counts_keeps_the_reservation(self, keys, usage):
        model = "claude-sonnet-4-5"
        warrant = mint(keys, model=model, total_tokens=1000)
        events = []
        http, meter = client_for(
            keys, warrant, lambda r: httpx.Response(200, json={"type": "message", "content": [], "usage": usage}), events=events)
        response = http.post("https://provider.test/v1/messages",
                             json={"model": model, "max_tokens": 200, "messages": [{"role": "user", "content": "hello there"}]})
        assert response.status_code == 200 and used(meter, warrant) == INPUT + 200 and events[0].usage["estimated"]

    @pytest.mark.parametrize("meta", [{}, {"trafficType": "ON_DEMAND"}])
    def test_google_usage_metadata_without_counts_keeps_the_reservation(self, keys, meta):
        model = "gemini-2.5-flash"
        warrant = mint(keys, model=model, total_tokens=1000)
        events = []
        answer = {"candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP"}], "usageMetadata": meta}
        http, meter = client_for(keys, warrant, lambda r: httpx.Response(200, json=answer), events=events)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        response = http.post(url, json={"contents": [{"role": "user", "parts": [{"text": "hello there"}]}],
                                        "generationConfig": {"maxOutputTokens": 200}})
        assert response.status_code == 200 and used(meter, warrant) == INPUT + 200 and events[0].usage["estimated"]
        # The same in a completed stream.
        sse_url = url.replace(":generateContent", ":streamGenerateContent") + "?alt=sse"
        stream = httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse([answer], done=False))
        http, meter = client_for(keys, warrant, lambda r: stream)
        with http.stream("POST", sse_url, json={"contents": [{"role": "user", "parts": [{"text": "hello there"}]}],
                                                 "generationConfig": {"maxOutputTokens": 200}}) as streamed:
            streamed.read()
        assert used(meter, warrant) == INPUT + 200


class TestRefusalEventsAndClientSettings:
    def test_every_refusal_reaches_the_audit_callback_once(self, keys):
        warrant = mint(keys, total_tokens=INPUT + 100)
        events = []
        http, _ = client_for(keys, warrant, Provider(), events=events)
        assert http.post("https://provider.test/v1/embeddings", json={"model": MODEL, "input": "x"}).status_code == 403
        assert http.post(CHAT, content=b"not json", headers={"content-type": "application/json"}).status_code == 403
        assert chat(http).status_code == 200 and chat(http).status_code == 403  # the second is over budget
        assert chat(http, model="another-model").status_code == 403
        assert [e.decision for e in events] == ["DENY", "DENY", "ALLOW", "DENY", "DENY"]
        assert "/v1/embeddings" in events[0].reason and "not JSON" in events[1].reason
        assert events[3].usage["budget"][0]["warrant_id"] == warrant.id
        assert all(e.warrant_id == warrant.id for e in events)

    def test_refusals_without_a_warrant_in_scope_are_reported_too(self, keys, installed):
        events = []
        installed(audit_callback=events.append)
        http = httpx.Client(transport=httpx.MockTransport(Provider()))
        assert http.post("https://api.openai.com/v1/embeddings", json={"model": MODEL, "input": "x"}).status_code == 403
        assert http.post("https://api.openai.com/v1/chat/completions", json={"model": MODEL, "messages": MESSAGES}).status_code == 403
        assert [(e.decision, e.warrant_id) for e in events] == [("DENY", None), ("DENY", None)]
        assert events[0].url == "https://api.openai.com/v1/embeddings" and "no warrant" in events[1].reason

    def test_connection_settings_reach_the_transport_that_sends(self, keys):
        import ssl

        context = ssl.create_default_context()
        common = dict(warrant=mint(keys, total_tokens=1000), signing_key=keys.lead, trusted_roots=[keys.issuer.public_key])
        http = metered_client(verify=context, limits=httpx.Limits(max_connections=3), **common)
        pool = http._transport._inner._pool
        assert pool._max_connections == 3 and pool._ssl_context is context
        ahttp = metered_async_client(limits=httpx.Limits(max_connections=4), **common)
        assert ahttp._transport._inner._pool._max_connections == 4
        # With a transport of the caller's own, the settings belong on that transport.
        with pytest.raises(TypeError, match="limits"):
            metered_client(transport=httpx.MockTransport(Provider()), limits=httpx.Limits(max_connections=3), **common)

    @pytest.mark.parametrize("name", ["openai", "anthropic"])
    def test_the_sdks_connection_limits_are_kept(self, keys, name):
        sdk = pytest.importorskip(name)
        common = dict(sdk=sdk, warrant=mint(keys, total_tokens=1000), signing_key=keys.lead,
                      trusted_roots=[keys.issuer.public_key])
        wanted = sdk.DEFAULT_CONNECTION_LIMITS.max_connections
        assert metered_client(**common)._transport._inner._pool._max_connections == wanted
        assert metered_async_client(**common)._transport._inner._pool._max_connections == wanted

    async def test_one_transport_shared_by_a_sync_and_an_async_client(self, keys, installed):
        warrant = mint(keys, total_tokens=1000)
        meter = installed(warrant, keys.lead)
        shared = httpx.MockTransport(Provider())
        body = {"model": MODEL, "messages": MESSAGES}
        url = "https://api.openai.com/v1/chat/completions"
        with httpx.Client(transport=shared) as http:
            assert http.post(url, json=body).status_code == 200
        async with httpx.AsyncClient(transport=shared) as ahttp:
            assert (await ahttp.post(url, json=body)).status_code == 200
        with httpx.Client(transport=shared) as http:
            assert http.post(url, json=body).status_code == 200
        assert used(meter, warrant) == 3 * (INPUT + 100)


class TestBackgroundAndRequestIds:
    RESPONSES = "https://provider.test/v1/responses"

    def test_a_background_response_is_refused_under_a_budget(self, keys):
        warrant = mint(keys, total_tokens=1000)
        events, seen = [], []
        http, meter = client_for(keys, warrant, lambda r: (seen.append(r), httpx.Response(200, json={"status": "queued"}))[1],
                                 events=events)
        refused = http.post(self.RESPONSES, json={"model": MODEL, "input": "hello", "background": True})
        assert refused.status_code == 403 and refused.json()["error"]["code"] == "unmetered_endpoint"
        assert "background" in refused.json()["error"]["message"] and refused.headers["x-tenuo-denial"] == "unmetered_endpoint"
        assert not seen and used(meter, warrant) == 0
        assert [(e.decision, e.model) for e in events] == [("DENY", MODEL)]
        # background=False is an ordinary request.
        assert http.post(self.RESPONSES, json={"model": MODEL, "input": "hello", "background": False}).status_code == 200

    def test_only_watching_lets_a_background_response_through(self, keys):
        warrant = mint(keys, total_tokens=1000)
        meter = TokenMeter(enforce=False)
        http = metered_client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"status": "queued"})),
                              warrant=warrant, signing_key=keys.lead, trusted_roots=[keys.issuer.public_key],
                              budget_store=meter)
        assert http.post(self.RESPONSES, json={"model": MODEL, "input": "hello", "background": True}).status_code == 200

    @pytest.mark.parametrize("header", ["x-request-id", "request-id"])
    def test_the_providers_request_id_is_in_the_usage_event(self, keys, header):
        warrant = mint(keys, total_tokens=5000)
        events = []
        usage = {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
        http, _ = client_for(keys, warrant, lambda r: httpx.Response(200, headers={header: "req_abc123"}, json={"usage": usage}),
                             events=events)
        assert chat(http).status_code == 200
        assert events[0].decision == "ALLOW" and events[0].request_id == "req_abc123"

    def test_a_stream_and_a_call_without_an_id(self, keys):
        warrant = mint(keys, total_tokens=5000)
        events = []
        chunks = sse([{"choices": [{"delta": {"content": "hi"}}]},
                      {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}}])
        answers = iter([
            httpx.Response(200, headers={"content-type": "text/event-stream", "x-request-id": "req_stream"}, content=chunks),
            httpx.Response(200, json={"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}),
        ])
        http, _ = client_for(keys, warrant, lambda r: next(answers), events=events)
        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True}) as streamed:
            streamed.read()
        assert chat(http).status_code == 200
        assert [e.request_id for e in events] == ["req_stream", None]

    async def test_async_calls_carry_the_request_id_too(self, keys):
        warrant = mint(keys, total_tokens=5000)
        events = []
        usage = {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
        http = metered_async_client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, headers={"x-request-id": "req_async"}, json={"usage": usage})),
            warrant=warrant, signing_key=keys.lead, trusted_roots=[keys.issuer.public_key], audit_callback=events.append)
        assert (await http.post(CHAT, json={"model": MODEL, "messages": MESSAGES})).status_code == 200
        assert events[0].request_id == "req_async"


class TestOtherRequestFields:
    GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent"
    REQUESTS = {
        "chat": (CHAT, lambda t: {"model": MODEL, "messages": MESSAGES, "temperature": t}),
        "responses": ("https://provider.test/v1/responses", lambda t: {"model": MODEL, "input": "hello", "temperature": t}),
        "completions": ("https://provider.test/v1/completions", lambda t: {"model": MODEL, "prompt": "hello", "temperature": t}),
        "anthropic": ("https://provider.test/v1/messages",
                      lambda t: {"model": MODEL, "max_tokens": 50, "messages": MESSAGES, "temperature": t}),
        "gemini": (GEMINI, lambda t: {"contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                                      "generationConfig": {"temperature": t}}),
    }

    @pytest.mark.parametrize("wire", sorted(REQUESTS))
    def test_a_constraint_on_another_field_is_checked_on_every_format(self, keys, wire):
        from tenuo import Range

        capability = llm_capability(total_tokens=100_000, models=[MODEL])
        capability["temperature"] = Range(min=0, max=1)
        warrant = (Warrant.mint_builder().capability("llm.chat", capability)
                   .holder(keys.lead.public_key).ttl(600).mint(keys.issuer))
        seen = []
        http, _ = client_for(keys, warrant, lambda r: (seen.append(r), httpx.Response(200, json={}))[1])
        url, body = self.REQUESTS[wire]
        assert http.post(url, json=body(0.5)).status_code == 200 and len(seen) == 1
        refused = http.post(url, json=body(1.8))
        assert refused.status_code == 403 and "temperature" in refused.text and len(seen) == 1

    def test_warrants_are_told_apart_by_their_content(self, keys):
        from tenuo.budget_http import _warrant_key

        one, other = mint(keys, total_tokens=1000), mint(keys, total_tokens=2000)
        assert _warrant_key(one) != _warrant_key(other)
        assert _warrant_key(Warrant.from_base64(one.to_base64())) == _warrant_key(one)
        # The same id over different signed content is a different warrant.
        first = SimpleNamespace(id="tnu_wrt_same", to_base64=lambda: "first")
        second = SimpleNamespace(id="tnu_wrt_same", to_base64=lambda: "second")
        assert _warrant_key(first) != _warrant_key(second)


class TestTheRequestAsSent:
    RESPONSES = "https://provider.test/v1/responses"
    GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent"

    def warrant(self, keys, total, **fields):
        from tenuo import Range

        capability = llm_capability(total_tokens=total, models=[MODEL])
        capability.update({name: Range(min=low, max=high) for name, (low, high) in fields.items()})
        return (Warrant.mint_builder().capability("llm.chat", capability)
                .holder(keys.lead.public_key).ttl(600).mint(keys.issuer))

    def test_a_cap_the_warrant_fixes_is_not_lowered_behind_its_back(self, keys):
        # The warrant wants exactly 100 output tokens. With room for 100 the call runs as written.
        warrant = self.warrant(keys, INPUT + 100, max_output_tokens=(100, 100))
        sent = []
        http, meter = client_for(keys, warrant, lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1])
        body = {"model": MODEL, "input": "hello", "max_output_tokens": 100}
        assert http.post(self.RESPONSES, json=body).status_code == 200 and sent[0]["max_output_tokens"] == 100
        # With room for only 40 it would have to be sent with 40, which the warrant does not allow.
        warrant = self.warrant(keys, INPUT + 40, max_output_tokens=(100, 100))
        sent.clear()
        http, meter = client_for(keys, warrant, lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1])
        refused = http.post(self.RESPONSES, json=body)
        assert refused.status_code == 403 and "max_output_tokens" in refused.text
        assert not sent and used(meter, warrant) == 0

    def test_a_lowered_cap_inside_the_warrants_range_is_sent(self, keys):
        warrant = self.warrant(keys, INPUT + 40, max_output_tokens=(0, 500))
        sent = []
        http, _ = client_for(keys, warrant, lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1])
        assert http.post(self.RESPONSES, json={"model": MODEL, "input": "hello", "max_output_tokens": 100}).status_code == 200
        assert sent[0]["max_output_tokens"] == 40

    def test_gemini_settings_are_checked_as_sent(self, keys):
        body = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}], "generationConfig": {"maxOutputTokens": 150}}
        sent = []
        provider = lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1]  # noqa: E731
        http, _ = client_for(keys, self.warrant(keys, INPUT + 150, maxOutputTokens=(100, 200)), provider)
        assert http.post(self.GEMINI, json=body).status_code == 200
        assert sent[0]["generationConfig"]["maxOutputTokens"] == 150
        http, meter = client_for(keys, self.warrant(keys, INPUT + 40, maxOutputTokens=(100, 200)), provider)
        assert http.post(self.GEMINI, json=body).status_code == 403 and len(sent) == 1

    def test_the_callers_own_body_is_left_as_it_was(self, keys):
        warrant = mint(keys, total_tokens=INPUT + 40)
        sent = []
        http, _ = client_for(keys, warrant, lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1])
        assert chat(http, max_tokens=100, stream_options={"x": 1}).status_code == 200
        assert sent[0]["max_tokens"] == 40 and sent[0]["stream_options"] == {"x": 1}


class TestACapNamedMoreThanOneWay:
    GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent"
    CONTENTS = [{"role": "user", "parts": [{"text": "hello"}]}]

    def send(self, keys, url, body, total=1000, **caps):
        warrant = mint(keys, total_tokens=total, **caps)
        sent = []
        http, meter = client_for(keys, warrant, lambda r: (sent.append(json.loads(r.content)), httpx.Response(200, json={}))[1])
        assert http.post(url, json=body).status_code == 200
        return sent[0], used(meter, warrant)

    @pytest.mark.parametrize("first, second", [("max_completion_tokens", "max_tokens"), ("max_tokens", "max_completion_tokens")])
    def test_chat_with_both_cap_fields_is_held_to_the_smaller(self, keys, first, second):
        body = {"model": MODEL, "messages": MESSAGES, first: 50, second: 100_000}
        sent, reserved = self.send(keys, CHAT, body)
        assert sent["max_completion_tokens"] == sent["max_tokens"] == 50 and reserved == INPUT + 50
        # Lowered to what is left, on both.
        sent, reserved = self.send(keys, CHAT, body, total=INPUT + 20)
        assert sent["max_completion_tokens"] == sent["max_tokens"] == 20
        # Under a warrant with its own cap per call, the larger field does not ride along either.
        sent, _ = self.send(keys, CHAT, body, max_tokens=60)
        assert sent["max_completion_tokens"] == sent["max_tokens"] == 50

    def test_gemini_with_both_spellings_is_held_to_the_smaller(self, keys):
        body = {"contents": self.CONTENTS, "generationConfig": {"max_output_tokens": 50, "maxOutputTokens": 100_000}}
        sent, reserved = self.send(keys, self.GEMINI, body)
        assert sent["generationConfig"] == {"max_output_tokens": 50, "maxOutputTokens": 50} and reserved == INPUT + 50

    def test_gemini_with_both_settings_objects_is_held_to_the_smaller(self, keys):
        body = {"contents": self.CONTENTS, "generation_config": {"maxOutputTokens": 50, "candidateCount": 2},
                "generationConfig": {"maxOutputTokens": 100_000}}
        sent, reserved = self.send(keys, self.GEMINI, body)
        assert sent["generation_config"]["maxOutputTokens"] == sent["generationConfig"]["maxOutputTokens"] == 50
        assert reserved == INPUT + 2 * 50  # two candidates, wherever the count was written

    def test_gemini_settings_win_over_a_stray_field_of_the_same_name(self, keys):
        from tenuo import Range

        capability = llm_capability(total_tokens=1000, models=[MODEL])
        capability["temperature"] = Range(min=0, max=1)
        warrant = (Warrant.mint_builder().capability("llm.chat", capability)
                   .holder(keys.lead.public_key).ttl(600).mint(keys.issuer))
        http, _ = client_for(keys, warrant, lambda r: httpx.Response(200, json={}))
        body = {"contents": self.CONTENTS, "temperature": 0.5, "generationConfig": {"temperature": 1.8}}
        assert http.post(self.GEMINI, json=body).status_code == 403


class TestWhichModelRuns:
    AZURE = "https://res.openai.azure.com/openai/deployments/{}/chat/completions?api-version=2024-10-21"

    def client(self, keys, events=None, **caps):
        warrant = mint(keys, total_tokens=5000, **caps)
        sent = []
        http, _ = client_for(keys, warrant, lambda r: (sent.append(r), httpx.Response(200, json={}))[1], events=events)
        return http, sent

    def test_a_deployment_in_the_url_is_the_model_that_is_checked(self, keys):
        events = []
        http, sent = self.client(keys, events)
        # The body names an allowed model; the URL runs another deployment.
        refused = http.post(self.AZURE.format("gpt-4o-big"), json={"model": MODEL, "messages": MESSAGES})
        assert refused.status_code == 403 and not sent and events[-1].model == "gpt-4o-big"
        # An allowed deployment runs, with or without a model in the body.
        assert http.post(self.AZURE.format(MODEL), json={"messages": MESSAGES}).status_code == 200
        assert http.post(self.AZURE.format(MODEL), json={"model": MODEL, "messages": MESSAGES}).status_code == 200
        assert events[-1].model == MODEL and len(sent) == 2
        # A body that names a model the warrant does not allow is refused beside an allowed deployment too.
        refused = http.post(self.AZURE.format(MODEL), json={"model": "gpt-4o-big", "messages": MESSAGES})
        assert refused.status_code == 403 and "gpt-4o-big" in refused.text and len(sent) == 2

    def test_every_fallback_model_must_be_allowed(self, keys):
        events = []
        http, sent = self.client(keys, events)
        body = {"model": MODEL, "messages": MESSAGES, "models": ["vendor/large-model"]}
        refused = http.post("https://openrouter.ai/api/v1/chat/completions", json=body)
        assert refused.status_code == 403 and "vendor/large-model" in refused.text and not sent
        assert [e.decision for e in events] == ["DENY"]
        body["models"] = [MODEL]
        assert http.post("https://openrouter.ai/api/v1/chat/completions", json=body).status_code == 200

    def test_gemini_runs_the_model_in_the_url(self, keys):
        http, sent = self.client(keys)
        url = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"
        contents = [{"role": "user", "parts": [{"text": "hello"}]}]
        assert http.post(url.format(MODEL), json={"contents": contents, "model": "models/" + MODEL}).status_code == 200
        assert http.post(url.format(MODEL), json={"contents": contents, "model": "models/gemini-large"}).status_code == 403
        assert http.post(url.format("gemini-large"), json={"contents": contents}).status_code == 403 and len(sent) == 1

    def test_a_warrant_without_a_model_list_allows_any_of_them(self, keys):
        warrant = (Warrant.mint_builder().capability("llm.chat", llm_capability(total_tokens=5000))
                   .holder(keys.lead.public_key).ttl(600).mint(keys.issuer))
        http, _ = client_for(keys, warrant, lambda r: httpx.Response(200, json={}))
        body = {"model": "anything", "messages": MESSAGES, "models": ["something-else"]}
        assert http.post(self.AZURE.format("my-deployment"), json=body).status_code == 200


class TestRunningUsageInAStream:
    def chunks(self, finished):
        events = [{"choices": [{"index": 0, "delta": {"content": "one"}}],
                   "usage": {"prompt_tokens": 12, "completion_tokens": 1, "total_tokens": 13}},
                  {"choices": [{"index": 0, "delta": {"content": " two"}}],
                   "usage": {"prompt_tokens": 12, "completion_tokens": 2, "total_tokens": 14}}]
        if finished:
            events.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 12, "completion_tokens": 40, "total_tokens": 52}})
        return sse(events, done=finished)

    def run(self, keys, finished):
        warrant = mint(keys, total_tokens=5000)
        events = []
        stream = httpx.Response(200, headers={"content-type": "text/event-stream"}, content=self.chunks(finished))
        http, meter = client_for(keys, warrant, lambda r: stream, events=events)
        with http.stream("POST", CHAT, json={"model": MODEL, "messages": MESSAGES, "stream": True, "max_tokens": 200}) as streamed:
            streamed.read()
        return used(meter, warrant), events[-1].usage

    def test_a_running_count_is_not_taken_for_the_final_one(self, keys):
        # The stream ends before generation finished: the last running count is less than what was generated.
        total, usage = self.run(keys, finished=False)
        assert total == INPUT + 200 and usage["estimated"] is True

    def test_the_count_that_comes_with_the_finish_is_final(self, keys):
        total, usage = self.run(keys, finished=True)
        assert total == 52 and "estimated" not in usage


class TestStreamsWithSeveralChoices:
    GEMINI = "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":streamGenerateContent?alt=sse"

    def stream(self, keys, url, body, events, done=True):
        warrant = mint(keys, total_tokens=5000)
        seen = []
        answer = httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse(events, done=done))
        http, meter = client_for(keys, warrant, lambda r: answer, events=seen)
        with http.stream("POST", url, json=body) as streamed:
            streamed.read()
        return used(meter, warrant), seen[-1].usage

    def chat_events(self, second_finishes, usage_only=False):
        def chunk(index, text, finish=None, total=None):
            out = {"choices": [{"index": index, "delta": {"content": text}, "finish_reason": finish}]}
            if total is not None:
                out["usage"] = {"prompt_tokens": 12, "completion_tokens": total - 12, "total_tokens": total}
            return out

        running = None if usage_only else 20
        events = [chunk(0, "a", total=running), chunk(1, "b", total=running), chunk(0, "", "stop", total=None if usage_only else 30)]
        if second_finishes:
            events.append(chunk(1, "", "stop", total=None if usage_only else 95))
        if usage_only:
            events.append({"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 83, "total_tokens": 95}})
        return events

    BODY = {"model": MODEL, "messages": MESSAGES, "stream": True, "n": 2, "max_tokens": 100}

    def test_one_finished_choice_of_two_does_not_settle_the_stream(self, keys):
        total, usage = self.stream(keys, CHAT, self.BODY, self.chat_events(second_finishes=False), done=False)
        assert total == INPUT + 2 * 100 and usage["estimated"] is True

    def test_both_choices_finished_settles_on_the_last_count(self, keys):
        total, usage = self.stream(keys, CHAT, self.BODY, self.chat_events(second_finishes=True))
        assert total == 95 and "estimated" not in usage

    def test_a_usage_only_event_is_final_however_many_choices(self, keys):
        total, usage = self.stream(keys, CHAT, self.BODY, self.chat_events(second_finishes=True, usage_only=True))
        assert total == 95 and "estimated" not in usage

    def gemini_events(self, second_finishes):
        def chunk(index, finish, total):
            candidate = {"index": index, "content": {"role": "model", "parts": [{"text": "x"}]}}
            if finish:
                candidate["finishReason"] = "STOP"
            return {"candidates": [candidate],
                    "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": total - 12, "totalTokenCount": total}}

        events = [chunk(0, False, 20), chunk(1, False, 25), chunk(0, True, 30)]
        if second_finishes:
            events.append(chunk(1, True, 95))
        return events

    GEMINI_BODY = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}],
                   "generationConfig": {"candidateCount": 2, "maxOutputTokens": 100}}

    def test_one_finished_candidate_of_two_does_not_settle_the_stream(self, keys):
        total, usage = self.stream(keys, self.GEMINI, self.GEMINI_BODY, self.gemini_events(second_finishes=False), done=False)
        assert total == INPUT + 2 * 100 and usage["estimated"] is True

    def test_both_candidates_finished_settles_on_the_last_count(self, keys):
        total, usage = self.stream(keys, self.GEMINI, self.GEMINI_BODY, self.gemini_events(second_finishes=True), done=False)
        assert total == 95 and "estimated" not in usage
