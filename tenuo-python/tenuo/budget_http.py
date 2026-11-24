"""
Token budgets at the HTTP layer.

:mod:`tenuo.budget` counts tokens against the budget in a warrant. This module
puts that meter under the HTTP client, so it works with any SDK or framework
that lets you pass its HTTP client::

    import openai
    from tenuo.budget_http import metered_client, metered_async_client

    http = metered_client(sdk=openai, warrant=warrant, signing_key=key,
                          trusted_roots=[issuer.public_key], budget_store="budgets.db")

    openai.OpenAI(http_client=http)                  # OpenAI SDK, Agents SDK
    ChatOpenAI(http_client=http, ...)                # LangChain / LangGraph
    anthropic.Anthropic(http_client=metered_client(sdk=anthropic, ...))

SDKs are built on ``httpx`` or on ``httpx2`` depending on their version, and a
client from the wrong one is rejected. ``sdk=`` picks the library the SDK
uses and keeps the SDK's own timeouts and connection limits. Without it,
pass ``library=httpx2`` to choose, or get ``httpx`` when it is installed.

Every request to a model endpoint is authorized by the warrant before it is
sent, its output cap is lowered to what the budget has left, and the usage the
provider reports is counted when the response (or the end of its stream)
arrives. Nothing above the HTTP layer changes: responses pass through as they
came.

Wire formats understood: OpenAI Chat Completions, legacy Completions and
Responses, Anthropic Messages, and Google ``generateContent`` (Gemini API and
Vertex AI), recognized by request path. That covers OpenAI-compatible
providers and gateways as well.

No wiring at all
----------------
:func:`install` meters every ``httpx`` / ``httpx2`` client in the process, so
frameworks need no ``http_client`` argument::

    import tenuo.budget_http
    tenuo.budget_http.install(warrant=warrant, signing_key=key,
                              trusted_roots=[issuer.public_key], budget_store="budgets.db")

Only requests to known model providers are touched (see ``hosts``). The
warrant and key may also come from ``warrant_scope()`` / ``key_scope()``, so
agents in one process can each spend from their own.

Refusals
--------
A call the warrant refuses is answered locally with HTTP 403 in the provider's
own error shape, so each SDK raises its usual error type. The error code is
``token_budget_exceeded`` (the budget is spent) or ``model_call_denied`` (the
warrant refuses for another reason, such as the model). The response carries
``x-should-retry: false``. Use :func:`is_budget_error` to recognize it.

What is not metered
-------------------
``GET`` and other non-``POST`` requests pass through. A ``POST`` to a path this
module does not recognize is refused with 403 unless the path is listed in
``unmetered_paths``: an endpoint that spends tokens unseen would make the
budget meaningless. Token-counting endpoints are allowed.

Scope: the meter covers the clients built on this transport. A process that
holds the provider key can build another client, so keep the key with the
metered one. Passing ``transport=`` to httpx bypasses proxy settings from the
environment; give :func:`metered_client` an inner transport if you need one.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

try:  # either library will do; ``sdk=`` or ``library=`` picks per client
    import httpx as _default_http
except ImportError:  # pragma: no cover - exercised only where httpx is absent
    import httpx2 as _default_http  # type: ignore[no-redef,import-not-found]

from tenuo.budget import (
    BudgetExceeded,
    BudgetStore,
    MeteredCall,
    ModelCallDenied,
    TokenMeter,
)

logger = logging.getLogger("tenuo.budget")

__all__ = [
    "AsyncMeteredTransport",
    "DEFAULT_HOSTS",
    "MeterEvent",
    "MeteredTransport",
    "for_library",
    "install",
    "is_budget_error",
    "metered_async_client",
    "metered_client",
    "uninstall",
]

BUDGET_CODE = "token_budget_exceeded"
DENIED_CODE = "model_call_denied"
UNMETERED_CODE = "unmetered_endpoint"

# POST endpoints that never generate: counting tokens costs nothing.
_FREE_SUFFIXES = ("/count_tokens", "/input_tokens", ":countTokens", "/moderations")

# Hosts install() meters by default: a process-wide hook must leave every other
# HTTP call alone. Matched as the host itself or any subdomain of it.
DEFAULT_HOSTS = (
    "api.openai.com", "openai.azure.com", "services.ai.azure.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
    "openrouter.ai", "api.groq.com", "api.mistral.ai", "api.deepseek.com", "api.x.ai",
    "api.cohere.com", "api.together.xyz", "api.fireworks.ai",
)


@dataclass
class MeterEvent:
    """One decision or one finished model call, for audit and monitoring.

    Attributes:
        timestamp: Unix time of the event.
        decision: ``"ALLOW"`` (the call ran; ``usage`` holds what it used) or
            ``"DENY"`` (the call was refused and not sent).
        tool_name: Capability the call was checked against (``llm.chat``).
        model: Model named in the request.
        reason: Why it was refused, or ``"model call metered"``.
        warrant_id: The caller's warrant. ``None`` when a call was refused
            because no warrant was in scope.
        usage: Tokens used and each warrant's running total (see
            :meth:`tenuo.budget.MeteredCall.settle`).
        url: The endpoint called, without query string.
        max_tokens: The output cap the request was sent with, when one was set.
    """

    timestamp: float
    decision: str
    tool_name: str
    model: Optional[str]
    reason: str
    warrant_id: Optional[str]
    usage: Optional[Dict[str, Any]] = None
    url: str = ""
    max_tokens: Optional[int] = None


# ---------------------------------------------------------------------------
# Wire formats
# ---------------------------------------------------------------------------


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


class _Dialect:
    """How one wire format names the output cap and reports usage."""

    name = ""
    output_params: Tuple[str, ...] = ()
    error_shape = "openai"

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """The request as the meter reads it (model, prompt fields)."""
        return body

    def model(self, body: Mapping[str, Any], path: str) -> Optional[str]:
        value = body.get("model")
        return value if isinstance(value, str) else None

    def read_cap(self, body: Mapping[str, Any], default: str) -> Tuple[Optional[int], str]:
        """The output cap the caller set, and the field to write the cap to."""
        for name in self.output_params:
            if _positive_int(body.get(name)) is not None:
                return body[name], name
        return None, default

    def write_cap(self, body: Dict[str, Any], param: str, value: int) -> None:
        body[param] = value

    def choices(self, body: Mapping[str, Any]) -> int:
        return 1

    def wants_stream(self, body: Mapping[str, Any], path: str) -> bool:
        return body.get("stream") is True

    def prepare_stream(self, body: Dict[str, Any]) -> bool:
        """Make a streamed request report usage. True if an extra chunk must be hidden."""
        return False

    def response_usage(self, payload: Any) -> Any:
        return payload.get("usage") if isinstance(payload, Mapping) else None

    def event_usage(self, state: Dict[str, Any], event: Any) -> None:
        """Fold one stream event into ``state['usage']``.

        ``state['complete']`` is set once the figures are the stream's final
        ones. A stream that is dropped before then has no usable usage: what it
        reported so far is less than what was generated, so the reservation
        stands as the charge.
        """
        usage = event.get("usage") if isinstance(event, Mapping) else None
        if usage:
            state["usage"] = usage
            state["complete"] = True  # these formats report usage once, at the end

    def is_hidden_event(self, event: Any) -> bool:
        return False


class _OpenAIChat(_Dialect):
    name = "openai.chat"
    output_params: Tuple[str, ...] = ("max_completion_tokens", "max_tokens")

    def choices(self, body: Mapping[str, Any]) -> int:
        return _positive_int(body.get("n")) or 1

    def prepare_stream(self, body: Dict[str, Any]) -> bool:
        given = body.get("stream_options")
        if given is not None and not isinstance(given, Mapping):
            return False  # not valid: left for the provider to reject
        options = dict(given or {})
        if "include_usage" in options:
            return False
        options["include_usage"] = True
        body["stream_options"] = options
        return True

    def is_hidden_event(self, event: Any) -> bool:
        # The usage-only chunk that include_usage adds: no choices, just usage.
        return isinstance(event, Mapping) and event.get("usage") is not None and not event.get("choices")


class _OpenAICompletions(_OpenAIChat):
    name = "openai.completions"
    output_params = ("max_tokens",)

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"model": body.get("model"), "input": body.get("prompt")}

    def choices(self, body: Mapping[str, Any]) -> int:
        # One completion per prompt in a list, times n; best_of generates (and
        # bills) that many candidates for each.
        prompt = body.get("prompt")
        prompts = len(prompt) if isinstance(prompt, list) and prompt and not isinstance(prompt[0], int) else 1
        each = max(_positive_int(body.get("n")) or 1, _positive_int(body.get("best_of")) or 1)
        return max(1, prompts) * each


class _OpenAIResponses(_Dialect):
    name = "openai.responses"
    output_params = ("max_output_tokens",)

    def event_usage(self, state: Dict[str, Any], event: Any) -> None:
        # Usage arrives inside the closing event's response object.
        response = event.get("response") if isinstance(event, Mapping) else None
        if isinstance(response, Mapping) and response.get("usage"):
            state["usage"] = response["usage"]
            state["complete"] = True


class _AnthropicMessages(_Dialect):
    name = "anthropic.messages"
    output_params = ("max_tokens",)
    error_shape = "anthropic"

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "model": body.get("model"),
            "messages": body.get("messages"),
            "instructions": body.get("system"),
            "tools": body.get("tools"),
        }

    @staticmethod
    def _total(usage: Mapping[str, Any]) -> Optional[Dict[str, int]]:
        """Input, output and total from a usage object, or None when it holds no count at all."""
        seen = []

        def read(name: str) -> int:
            value = usage.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                seen.append(name)
                return int(value)
            return 0

        # Cached input is reported apart from input_tokens; all of it is input.
        inp = read("input_tokens") + read("cache_creation_input_tokens") + read("cache_read_input_tokens")
        out = read("output_tokens")
        if not seen:
            return None  # nothing was reported: the reservation stands, as for missing usage
        return {"input_tokens": inp, "output_tokens": out, "total_tokens": inp + out}

    def response_usage(self, payload: Any) -> Any:
        usage = payload.get("usage") if isinstance(payload, Mapping) else None
        return self._total(usage) if isinstance(usage, Mapping) else None

    def event_usage(self, state: Dict[str, Any], event: Any) -> None:
        if not isinstance(event, Mapping):
            return
        # message_start carries the input side, message_delta the running output.
        merged = state.setdefault("raw", {})
        message = event.get("message")
        if isinstance(message, Mapping) and isinstance(message.get("usage"), Mapping):
            merged.update({k: v for k, v in message["usage"].items() if v is not None})
        if isinstance(event.get("usage"), Mapping):
            merged.update({k: v for k, v in event["usage"].items() if v is not None})
        total = self._total(merged) if merged else None
        if total is not None:
            state["usage"] = total
        # message_start reports one output token; the real count comes with the
        # closing message_delta.
        if event.get("type") in ("message_delta", "message_stop"):
            state["complete"] = True


class _GoogleGenerate(_Dialect):
    """Gemini API and Vertex AI ``generateContent`` / ``streamGenerateContent``."""

    name = "google.generate"
    output_params = ("maxOutputTokens",)
    error_shape = "google"
    _MODEL = re.compile(r"/models/([^/:]+):")

    def model(self, body: Mapping[str, Any], path: str) -> Optional[str]:
        # The model is named in the URL, not the body.
        match = self._MODEL.search(path)
        return match.group(1) if match else super().model(body, path)

    @staticmethod
    def _config_key(body: Mapping[str, Any]) -> str:
        return "generation_config" if "generation_config" in body else "generationConfig"

    def _config(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        config = body.get(self._config_key(body))
        return config if isinstance(config, Mapping) else {}

    def read_cap(self, body: Mapping[str, Any], default: str) -> Tuple[Optional[int], str]:
        config = self._config(body)
        name = "max_output_tokens" if "max_output_tokens" in config else "maxOutputTokens"
        return _positive_int(config.get(name)), name

    def write_cap(self, body: Dict[str, Any], param: str, value: int) -> None:
        key = self._config_key(body)
        config = dict(self._config(body))
        config[param] = value
        body[key] = config

    def choices(self, body: Mapping[str, Any]) -> int:
        config = self._config(body)
        return _positive_int(config.get("candidateCount") or config.get("candidate_count")) or 1

    def wants_stream(self, body: Mapping[str, Any], path: str) -> bool:
        return ":streamGenerateContent" in path

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "messages": body.get("contents"),
            "instructions": body.get("systemInstruction") or body.get("system_instruction"),
            "tools": body.get("tools"),
        }

    @staticmethod
    def _total(meta: Mapping[str, Any]) -> Optional[Dict[str, int]]:
        """Input, output and total from usageMetadata, or None when it holds no count at all."""
        seen = []

        def read(name: str) -> int:
            value = meta.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                seen.append(name)
                return int(value)
            return 0

        inp = read("promptTokenCount") + read("toolUsePromptTokenCount")
        out = read("candidatesTokenCount") + read("thoughtsTokenCount")  # thinking is billed as output
        total = read("totalTokenCount") or inp + out
        if not seen:
            return None  # nothing was reported: the reservation stands, as for missing usage
        return {"input_tokens": inp, "output_tokens": out, "total_tokens": total}

    def response_usage(self, payload: Any) -> Any:
        # A stream without alt=sse arrives as one JSON array of chunks.
        chunks = payload if isinstance(payload, list) else [payload]
        for chunk in reversed(chunks):
            meta = chunk.get("usageMetadata") if isinstance(chunk, Mapping) else None
            if isinstance(meta, Mapping):
                return self._total(meta)
        return None

    def event_usage(self, state: Dict[str, Any], event: Any) -> None:
        meta = event.get("usageMetadata") if isinstance(event, Mapping) else None
        total = self._total(meta) if isinstance(meta, Mapping) else None
        if total is not None:
            state["usage"] = total  # cumulative: the last chunk has the totals
        candidates = event.get("candidates") if isinstance(event, Mapping) else None
        if isinstance(candidates, list) and any(isinstance(c, Mapping) and c.get("finishReason") for c in candidates):
            state["complete"] = True


_GOOGLE = _GoogleGenerate()

_DIALECTS: Tuple[Tuple[str, _Dialect], ...] = (
    ("/chat/completions", _OpenAIChat()),
    ("/responses", _OpenAIResponses()),
    ("/messages", _AnthropicMessages()),
    ("/completions", _OpenAICompletions()),
)


def _dialect_for(path: str) -> Optional[_Dialect]:
    path = path.rstrip("/")
    if path.endswith((":generateContent", ":streamGenerateContent")):
        return _GOOGLE
    for suffix, dialect in _DIALECTS:
        if path.endswith(suffix):
            return dialect
    return None


# ---------------------------------------------------------------------------
# Server-sent events
# ---------------------------------------------------------------------------

_EVENT_END = re.compile(rb"\r?\n\r?\n")


class _StreamTap:
    """Reads usage out of an event stream as it passes.

    Without ``hide`` the bytes are forwarded untouched and parsed on the side.
    With ``hide`` whole events are forwarded one at a time so that the usage
    chunk this module asked for can be left out.
    """

    def __init__(self, dialect: _Dialect, hide: bool, readable: bool) -> None:
        self._dialect = dialect
        self._hide = hide
        self._readable = readable
        self._buffer = b""
        self._state: Dict[str, Any] = {}

    @property
    def usage(self) -> Any:
        """The stream's usage, or None when it ended before reporting its final figures."""
        return self._state.get("usage") if self._state.get("complete") else None

    def feed(self, chunk: bytes) -> bytes:
        if not self._readable:
            return chunk
        self._buffer += chunk
        out: List[bytes] = []
        while True:
            match = _EVENT_END.search(self._buffer)
            if match is None:
                break
            raw, self._buffer = self._buffer[: match.end()], self._buffer[match.end():]
            if not self._observe(raw):
                out.append(raw)
        return b"".join(out) if self._hide else chunk

    def flush(self) -> bytes:
        rest, self._buffer = self._buffer, b""
        if not self._readable or not rest:
            return b""
        hidden = self._observe(rest)
        return b"" if (hidden or not self._hide) else rest

    def _observe(self, raw: bytes) -> bool:
        """Parse one event; True when it should be left out of the output."""
        data = b"\n".join(
            line[5:].lstrip(b" ") for line in raw.splitlines() if line.startswith(b"data:")
        )
        if not data or data == b"[DONE]":
            return False
        try:
            event = json.loads(data)
        except ValueError:
            return False
        try:
            self._dialect.event_usage(self._state, event)
        except Exception:
            logger.debug("could not read usage from a stream event", exc_info=True)
        return self._hide and self._dialect.is_hidden_event(event)


# ---------------------------------------------------------------------------
# The meter, independent of sync or async IO
# ---------------------------------------------------------------------------


def _send_event(callback: Optional[Callable[[MeterEvent], None]], *, decision: str, tool: str, model: Optional[str],
                reason: str, warrant_id: Optional[str], request: Any, usage: Optional[Dict[str, Any]] = None,
                max_tokens: Optional[int] = None) -> None:
    """Hand one event to the audit callback; a callback that raises does not change the outcome."""
    if callback is None:
        return
    event = MeterEvent(
        timestamp=time.time(), decision=decision, tool_name=tool, model=model, reason=reason,
        warrant_id=warrant_id, usage=usage, url=str(request.url.copy_with(query=None)), max_tokens=max_tokens,
    )
    try:
        callback(event)
    except Exception:
        logger.warning("Audit callback failed", exc_info=True)


def _refusal(http: Any, request: Any, dialect: Optional[_Dialect], code: str, message: str) -> Any:
    """A local 403 in the error shape of the provider the request was for."""
    if dialect is not None and dialect.error_shape == "anthropic":
        payload: Dict[str, Any] = {"type": "error", "error": {"type": "permission_error", "message": message, "code": code}}
    elif dialect is not None and dialect.error_shape == "google":
        payload = {"error": {"code": 403, "message": message, "status": "PERMISSION_DENIED",
                             "details": [{"reason": code, "domain": "tenuo"}]}}
    else:
        payload = {"error": {"message": message, "type": "tenuo_" + code, "param": None, "code": code}}
    return http.Response(
        403,
        headers={"content-type": "application/json", "x-should-retry": "false", "x-tenuo-denial": code},
        content=json.dumps(payload).encode(),
        request=request,
    )


@dataclass
class _Plan:
    """What to do with one outgoing request."""

    request: Any
    refusal: Optional[Any] = None
    call: Optional[MeteredCall] = None
    dialect: Optional[_Dialect] = None
    hide_usage: bool = False
    done: bool = field(default=False, repr=False)


class _Core:
    def __init__(
        self,
        *,
        http: Any,
        warrant: Any,
        signing_key: Any,
        trusted_roots: Optional[list],
        warrant_chain: Optional[Sequence[Any]],
        budget_store: Union[TokenMeter, BudgetStore, str, None],
        audit_callback: Optional[Callable[[MeterEvent], None]],
        unmetered_paths: Sequence[str],
        chat_output_param: str,
    ) -> None:
        from tenuo._enforcement import split_presented_warrant

        if warrant is None or signing_key is None:
            raise ValueError("a metered transport needs a warrant and its holder's signing key")
        self.http = http  # the httpx or httpx2 module this transport belongs to
        self.warrant, chain = split_presented_warrant(warrant, list(warrant_chain) if warrant_chain else None)
        self.chain = chain
        self.signing_key = signing_key
        self.trusted_roots = trusted_roots
        self.meter = TokenMeter.coerce(budget_store) or TokenMeter()
        self.audit_callback = audit_callback
        self.unmetered = tuple(p.rstrip("/") for p in unmetered_paths)
        self.chat_output_param = chat_output_param
        self.warrant_id = str(self.warrant.id)

    # -- before the request --------------------------------------------------

    def plan(self, request: Any) -> _Plan:
        if request.method.upper() != "POST":
            return _Plan(request)
        path = request.url.path.rstrip("/")
        if path.endswith(_FREE_SUFFIXES) or path.endswith(self.unmetered):
            return _Plan(request)
        dialect = _dialect_for(path)
        monitor = not self.meter.enforce
        if dialect is None:
            if monitor:
                return _Plan(request)  # nothing is refused when only watching
            return _Plan(request, refusal=self._refuse(
                request, None, UNMETERED_CODE,
                f"tenuo: {path} is not a model endpoint this meter understands, so it is refused under a token "
                "budget. List the path in unmetered_paths to let it through uncounted.",
            ))
        try:
            body = json.loads(request.read() or b"{}")
            if not isinstance(body, dict):
                raise ValueError("request body is not a JSON object")
        except ValueError:
            if monitor:
                return _Plan(request)
            return _Plan(request, refusal=self._refuse(
                request, dialect, UNMETERED_CODE,
                "tenuo: the request body is not JSON, so its tokens cannot be counted under a token budget.",
            ))

        requested, param = dialect.read_cap(body, self._default_param(dialect))
        model = dialect.model(body, path)
        streaming = dialect.wants_stream(body, path)
        view = dict(dialect.view(body))
        view["model"] = model
        # Parents not given to this meter are taken from chain_scope(), as the
        # warrant check does: the chain that is verified is the chain charged.
        chain = self.chain
        if chain is None:
            from tenuo.decorators import chain_scope

            chain = list(chain_scope() or []) or None
        try:
            call = self.meter.begin(
                self.warrant, chain, view,
                requested_output=requested, choices=dialect.choices(body),
                authorize=lambda tool, args: self._authorize(tool, args, chain),
            )
        except BudgetExceeded as e:
            snapshot: Dict[str, Any] = {"warrant_id": e.warrant_id, "used": e.used}
            if e.limit is not None:
                snapshot["limit"] = e.limit
            return _Plan(request, refusal=self._refuse(
                request, dialect, BUDGET_CODE, str(e), model, {"budget": [snapshot]}))
        except ModelCallDenied as e:
            reason = f"tenuo: model call refused by the warrant: {e}"
            return _Plan(request, refusal=self._refuse(request, dialect, DENIED_CODE, reason, model))

        if not call.enforced:
            # Only watching: the request goes out exactly as the caller wrote
            # it. Usage is recorded when the response carries it.
            return _Plan(request, call=call, dialect=dialect)
        try:
            hide = False
            dialect.write_cap(body, param, call.max_output)  # type: ignore[arg-type]
            if streaming:
                hide = dialect.prepare_stream(body)
            content = json.dumps(body, separators=(",", ":")).encode()
            headers = self.http.Headers(request.headers)
            headers["content-length"] = str(len(content))
            headers.pop("transfer-encoding", None)
            if streaming:
                # The event stream has to be readable here to find the usage in it.
                headers["accept-encoding"] = "identity"
            rewritten = self.http.Request(
                request.method, request.url, headers=headers, content=content, extensions=request.extensions
            )
        except BaseException:
            call.release()  # nothing will be sent: the reservation goes back
            raise
        return _Plan(rewritten, call=call, dialect=dialect, hide_usage=hide)

    def _default_param(self, dialect: _Dialect) -> str:
        if isinstance(dialect, _OpenAIChat) and self.chat_output_param in dialect.output_params:
            return self.chat_output_param
        return dialect.output_params[0]

    def _authorize(self, tool: str, args: Dict[str, Any], chain: Optional[Sequence[Any]] = None) -> Any:
        from tenuo._enforcement import enforce_tool_call
        from tenuo.config import resolve_trusted_roots

        return enforce_tool_call(
            tool_name=tool,
            tool_args=args,
            bound_warrant=self.warrant.bind(self.signing_key),
            trusted_roots=resolve_trusted_roots(self.trusted_roots),
            warrant_chain=list(chain) if chain else None,
        )

    def _refuse(self, request: Any, dialect: Optional[_Dialect], code: str, message: str,
                model: Optional[str] = None, usage: Optional[Dict[str, Any]] = None) -> Any:
        """The local 403 for a request, with its one DENY event."""
        self._emit("DENY", model, message, request, usage)
        return _refusal(self.http, request, dialect, code, message)

    # -- after the request ---------------------------------------------------

    def failed(self, plan: _Plan, error: BaseException) -> None:
        """The request raised instead of returning a response."""
        if plan.call is None or plan.done:
            return
        h = self.http
        never_sent = isinstance(error, (h.ConnectError, h.ConnectTimeout, h.PoolTimeout,
                                        h.UnsupportedProtocol, h.InvalidURL))
        if never_sent:
            self.release(plan)
        else:
            # Read timeout, dropped connection, cancellation: the provider may
            # have generated and billed. The reservation stands as the charge.
            self.settle(plan, None)

    def release(self, plan: _Plan) -> None:
        if plan.call is None or plan.done:
            return
        plan.done = True
        try:
            plan.call.release()
        except Exception:
            logger.warning("Token reservation could not be released", exc_info=True)

    def settle(self, plan: _Plan, usage: Any) -> None:
        if plan.call is None or plan.done:
            return
        plan.done = True
        try:
            record = plan.call.settle(usage)
        except Exception:
            # The reservation stays counted, which errs toward the budget.
            logger.warning("Token usage could not be recorded", exc_info=True)
            return
        self._emit("ALLOW", plan.call.model, "model call metered", plan.request, record, plan.call.max_output)

    def usage_from_body(self, plan: _Plan, body: bytes) -> Any:
        try:
            return plan.dialect.response_usage(json.loads(body))  # type: ignore[union-attr]
        except Exception:
            return None

    def tap(self, plan: _Plan, response: Any) -> _StreamTap:
        encoding = response.headers.get("content-encoding", "identity").lower()
        return _StreamTap(plan.dialect, plan.hide_usage, readable=encoding in ("", "identity"))  # type: ignore[arg-type]

    @staticmethod
    def is_event_stream(response: Any) -> bool:
        return "text/event-stream" in response.headers.get("content-type", "").lower()

    def plain_headers(self, response: Any, length: int) -> Any:
        """Headers for a body this module has already read and decoded."""
        headers = self.http.Headers(response.headers)
        for name in ("content-encoding", "transfer-encoding"):
            headers.pop(name, None)
        headers["content-length"] = str(length)
        return headers

    def _emit(self, decision: str, model: Optional[str], reason: str, request: Any,
              usage: Optional[Dict[str, Any]], max_tokens: Optional[int] = None) -> None:
        _send_event(self.audit_callback, decision=decision, tool=self.meter.tool, model=model, reason=reason,
                    warrant_id=self.warrant_id, request=request, usage=usage, max_tokens=max_tokens)


# ---------------------------------------------------------------------------
# Transports, built once per HTTP library
# ---------------------------------------------------------------------------

_CORE_DOC = """
    Args:
        transport: The transport that really sends requests. Defaults to the
            library's own.
        warrant: The caller's warrant, or its whole chain root first.
        signing_key: The warrant holder's key.
        trusted_roots: Issuer keys the chain must lead back to.
        warrant_chain: Parents of ``warrant``, root first. With them, calls
            also count against each parent's budget.
        budget_store: A ``TokenMeter`` or ``BudgetStore``, or a path for a
            SQLite store. Omit to count in memory.
        audit_callback: Called with a :class:`MeterEvent` per refusal and per
            finished call.
        unmetered_paths: Path endings of POST endpoints to let through
            uncounted (for example ``"/embeddings"``).
        chat_output_param: Field used to cap a Chat Completions request that
            sets none: ``"max_completion_tokens"`` (default) or ``"max_tokens"``
            for servers that only know the older name.
"""

_METER_KEYS = ("warrant", "signing_key", "trusted_roots", "warrant_chain", "budget_store", "audit_callback",
               "unmetered_paths", "chat_output_param")


def _make(http: Any) -> SimpleNamespace:
    """Define the transport classes on ``http`` (the httpx or httpx2 module)."""

    class SyncTapped(http.SyncByteStream):  # type: ignore[name-defined,misc]
        """Response stream that settles the call when it ends or is closed."""

        def __init__(self, inner: Any, tap: _StreamTap, finish: Callable[[Any], None]) -> None:
            self._inner, self._tap, self._finish = inner, tap, finish
            self._lock = threading.Lock()
            self._finished = False

        def __iter__(self) -> Iterator[bytes]:
            try:
                for chunk in self._inner:
                    out = self._tap.feed(chunk)
                    if out:
                        yield out
                tail = self._tap.flush()
                if tail:
                    yield tail
            finally:
                self._done()

        def close(self) -> None:
            try:
                self._inner.close()
            finally:
                self._done()

        def _done(self) -> None:
            with self._lock:
                if self._finished:
                    return
                self._finished = True
            self._finish(self._tap.usage)

        def __del__(self) -> None:
            # A response dropped without being read or closed: settle it (its
            # reservation stands as the charge) so the call is not left open.
            try:
                self._done()
            except Exception:
                pass

    class AsyncTapped(http.AsyncByteStream):  # type: ignore[name-defined,misc]
        def __init__(self, inner: Any, tap: _StreamTap, finish: Callable[[Any], None],
                     finish_async: Optional[Callable[[Any], Any]] = None) -> None:
            self._inner, self._tap, self._finish = inner, tap, finish
            self._finish_async = finish_async
            self._finished = False

        async def __aiter__(self) -> AsyncIterator[bytes]:
            try:
                async for chunk in self._inner:
                    out = self._tap.feed(chunk)
                    if out:
                        yield out
                tail = self._tap.flush()
                if tail:
                    yield tail
            finally:
                await self._adone()

        async def aclose(self) -> None:
            try:
                await self._inner.aclose()
            finally:
                await self._adone()

        async def _adone(self) -> None:
            if self._finished:
                return
            if self._finish_async is None:
                return self._done()
            self._finished = True
            await self._finish_async(self._tap.usage)

        def _done(self) -> None:
            if self._finished:
                return
            self._finished = True
            self._finish(self._tap.usage)

        def __del__(self) -> None:
            try:
                self._done()
            except Exception:
                pass

    class MeteredTransport(http.BaseTransport):  # type: ignore[name-defined,misc]
        __doc__ = "Counts and limits the tokens of model calls sent through a sync HTTP client.\n" + _CORE_DOC

        def __init__(self, transport: Any = None, **meter: Any) -> None:
            self._inner = transport if transport is not None else http.HTTPTransport()
            self._core = _Core(http=http, **_meter_args(meter))

        @property
        def meter(self) -> TokenMeter:
            return self._core.meter

        def handle_request(self, request: Any) -> Any:
            return send_sync(self._core, self._inner.handle_request, request)

        def close(self) -> None:
            self._inner.close()

    def send_sync(core: _Core, send: Callable[[Any], Any], request: Any) -> Any:
        """Meter one request sent with ``send``."""
        plan = core.plan(request)
        if plan.refusal is not None:
            return plan.refusal
        if plan.call is None:
            return send(plan.request)
        try:
            response = send(plan.request)
        except BaseException as e:
            core.failed(plan, e)
            raise
        if response.status_code >= 300:
            core.release(plan)  # an error or a redirect: nothing was generated by this request
            return response
        if core.is_event_stream(response):
            tapped = SyncTapped(response.stream, core.tap(plan, response), lambda usage: core.settle(plan, usage))
            return http.Response(response.status_code, headers=response.headers, stream=tapped,
                                 extensions=response.extensions, request=request)
        try:
            body = response.read()
        except BaseException as e:
            core.failed(plan, e)
            raise
        finally:
            response.close()
        core.settle(plan, core.usage_from_body(plan, body))
        return http.Response(response.status_code, headers=core.plain_headers(response, len(body)), content=body,
                             extensions=response.extensions, request=request)

    class AsyncMeteredTransport(http.AsyncBaseTransport):  # type: ignore[name-defined,misc]
        __doc__ = "Counts and limits the tokens of model calls sent through an async HTTP client.\n" + _CORE_DOC

        def __init__(self, transport: Any = None, **meter: Any) -> None:
            self._inner = transport if transport is not None else http.AsyncHTTPTransport()
            self._core = _Core(http=http, **_meter_args(meter))

        @property
        def meter(self) -> TokenMeter:
            return self._core.meter

        async def handle_async_request(self, request: Any) -> Any:
            return await send_async(self._core, self._inner.handle_async_request, request)

        async def aclose(self) -> None:
            await self._inner.aclose()

    async def send_async(core: _Core, send: Callable[[Any], Any], request: Any) -> Any:
        if request.method.upper() == "POST":
            await request.aread()  # the planner reads the body synchronously
        plan = await _plan_off_loop(core, request)
        if plan.refusal is not None:
            return plan.refusal
        if plan.call is None:
            return await send(plan.request)
        try:
            response = await send(plan.request)
        except BaseException as e:
            await _off_loop(core, core.failed, plan, e)
            raise
        if response.status_code >= 300:
            await _off_loop(core, core.release, plan)
            return response
        if core.is_event_stream(response):
            async def finish(usage: Any) -> None:
                await _off_loop(core, core.settle, plan, usage)

            tapped = AsyncTapped(response.stream, core.tap(plan, response), lambda usage: core.settle(plan, usage), finish)
            return http.Response(response.status_code, headers=response.headers, stream=tapped,
                                 extensions=response.extensions, request=request)
        try:
            body = await response.aread()
        except BaseException as e:
            await _off_loop(core, core.failed, plan, e)
            raise
        finally:
            await response.aclose()
        await _off_loop(core, core.settle, plan, core.usage_from_body(plan, body))
        return http.Response(response.status_code, headers=core.plain_headers(response, len(body)), content=body,
                             extensions=response.extensions, request=request)

    class AmbientTransport(http.BaseTransport):  # type: ignore[name-defined,misc]
        """What install() puts in front of a client's transport: meters with
        whatever warrant is in scope when a request is made."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def handle_request(self, request: Any) -> Any:
            installed = _INSTALLED
            if installed is None or not installed.covers(request):
                return self._inner.handle_request(request)
            core, refusal = installed.core_for(http, request)
            if refusal is not None:
                return refusal
            if core is None:
                return self._inner.handle_request(request)
            return send_sync(core, self._inner.handle_request, request)

        def close(self) -> None:
            self._inner.close()

    class AsyncAmbientTransport(http.AsyncBaseTransport):  # type: ignore[name-defined,misc]
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        async def handle_async_request(self, request: Any) -> Any:
            installed = _INSTALLED
            if installed is None or not installed.covers(request):
                return await self._inner.handle_async_request(request)
            core, refusal = installed.core_for(http, request)
            if refusal is not None:
                return refusal
            if core is None:
                return await self._inner.handle_async_request(request)
            return await send_async(core, self._inner.handle_async_request, request)

        async def aclose(self) -> None:
            await self._inner.aclose()

    return SimpleNamespace(
        http=http, MeteredTransport=MeteredTransport, AsyncMeteredTransport=AsyncMeteredTransport,
        AmbientTransport=AmbientTransport, AsyncAmbientTransport=AsyncAmbientTransport,
    )


def _meter_args(given: Dict[str, Any]) -> Dict[str, Any]:
    unknown = sorted(set(given) - set(_METER_KEYS))
    if unknown:
        raise TypeError(f"unexpected argument(s): {', '.join(unknown)}")
    args: Dict[str, Any] = dict(
        warrant=None, signing_key=None, trusted_roots=None, warrant_chain=None, budget_store=None,
        audit_callback=None, unmetered_paths=(), chat_output_param="max_completion_tokens",
    )
    args.update(given)
    return args


_BOUND: Dict[str, SimpleNamespace] = {}


def for_library(http: Any) -> SimpleNamespace:
    """The transport classes for one HTTP library (the ``httpx`` or ``httpx2`` module).

    Returns a namespace with ``MeteredTransport`` and ``AsyncMeteredTransport``.
    """
    name = http.__name__
    if name not in _BOUND:
        _BOUND[name] = _make(http)
    return _BOUND[name]


MeteredTransport = for_library(_default_http).MeteredTransport
AsyncMeteredTransport = for_library(_default_http).AsyncMeteredTransport


# ---------------------------------------------------------------------------
# Ready-made clients
# ---------------------------------------------------------------------------


def _library_of(client_class: Any) -> Any:
    """The HTTP library a client class is built on."""
    import importlib

    for base in client_class.__mro__:
        root = (base.__module__ or "").split(".")[0]
        if root in ("httpx", "httpx2"):
            return importlib.import_module(root)
    raise TypeError(f"{client_class!r} is not an httpx or httpx2 client")


_CONNECTION_SETTINGS = ("verify", "cert", "http1", "http2", "limits")


def _client(is_async: bool, sdk: Any, library: Any, transport: Any, kwargs: Dict[str, Any]) -> Any:
    for option in ("mounts", "proxy", "proxies"):
        if kwargs.get(option) is not None:
            # These give some requests a transport of their own, past the meter.
            raise TypeError(f"{option}= is not supported on a metered client: configure it on the transport "
                            "passed as transport=, which the meter wraps")
    meter = {k: kwargs.pop(k) for k in _METER_KEYS if k in kwargs}
    if sdk is not None:
        # The SDK's own client class keeps its timeouts and redirects.
        client_class = sdk.DefaultAsyncHttpxClient if is_async else sdk.DefaultHttpxClient
        http = library or _library_of(client_class)
    else:
        http = library or _default_http
        client_class = http.AsyncClient if is_async else http.Client
        kwargs.setdefault("timeout", http.Timeout(600.0, connect=5.0))
        kwargs.setdefault("follow_redirects", True)
    # A client does not apply its connection settings to a transport it is
    # handed, so they go to the transport that sends.
    connection = {k: kwargs[k] for k in _CONNECTION_SETTINGS if kwargs.get(k) is not None}
    if transport is not None:
        if connection:
            raise TypeError(f"{', '.join(sorted(connection))}= cannot be combined with transport=: configure the "
                            "transport you pass")
    else:
        if "trust_env" in kwargs:
            connection["trust_env"] = kwargs["trust_env"]
        sdk_limits = getattr(sdk, "DEFAULT_CONNECTION_LIMITS", None)
        if sdk_limits is not None:
            connection.setdefault("limits", sdk_limits)
        transport = (http.AsyncHTTPTransport if is_async else http.HTTPTransport)(**connection)
    bound = for_library(http)
    metered = (bound.AsyncMeteredTransport if is_async else bound.MeteredTransport)(transport, **meter)
    return client_class(transport=metered, **kwargs)


def metered_client(*, sdk: Any = None, library: Any = None, transport: Any = None, **kwargs: Any) -> Any:
    """A sync HTTP client whose model calls are metered against a warrant.

    Args:
        sdk: The SDK module the client is for (``openai``, ``anthropic``). The
            client is then that SDK's own default client on the right library.
        library: The ``httpx`` or ``httpx2`` module, to choose it yourself.
        transport: Inner transport that really sends requests. Without one,
            the client's connection settings (``verify``, ``cert``, ``http2``,
            ``limits``, ``trust_env``) configure the transport that is built;
            with one, set them on that transport.
        **kwargs: The arguments of :class:`MeteredTransport`; anything else
            goes to the client class.

    Hand the result to an SDK or framework as its ``http_client``.
    """
    return _client(False, sdk, library, transport, kwargs)


def metered_async_client(*, sdk: Any = None, library: Any = None, transport: Any = None, **kwargs: Any) -> Any:
    """An async HTTP client whose model calls are metered against a warrant.

    Same arguments as :func:`metered_client`. Give the sync and async clients
    the same ``budget_store`` so they share one count.
    """
    return _client(True, sdk, library, transport, kwargs)


# ---------------------------------------------------------------------------
# Process-wide install
# ---------------------------------------------------------------------------


class _Installation:
    def __init__(self, *, warrant: Any, signing_key: Any, warrant_chain: Optional[Sequence[Any]],
                 trusted_roots: Optional[list], budget_store: Any,
                 audit_callback: Optional[Callable[[MeterEvent], None]], hosts: Sequence[str],
                 unmetered_paths: Sequence[str], chat_output_param: str) -> None:
        self.warrant, self.signing_key = warrant, signing_key
        self.chain = list(warrant_chain) if warrant_chain else None
        self.meter = TokenMeter.coerce(budget_store) or TokenMeter()
        self.shared: Dict[str, Any] = dict(trusted_roots=trusted_roots, budget_store=self.meter, audit_callback=audit_callback,
                           unmetered_paths=unmetered_paths, chat_output_param=chat_output_param)
        self.hosts = tuple(h.lower() for h in (*DEFAULT_HOSTS, *hosts))
        self.unmetered = tuple(p.rstrip("/") for p in unmetered_paths)
        self.cores: Dict[Any, _Core] = {}
        self.patched: List[Tuple[Any, Any]] = []
        self.restore_genai = False
        self.lock = threading.Lock()

    def covers(self, request: Any) -> bool:
        if "*" in self.hosts:
            return True
        host = (request.url.host or "").lower()
        with_port = f"{host}:{request.url.port}" if request.url.port else host
        if any(host == h or host.endswith("." + h) or with_port == h for h in self.hosts):
            return True
        # Regional Vertex AI endpoints are named <region>-aiplatform.googleapis.com.
        return _VERTEX_HOST in self.hosts and host.endswith("-" + _VERTEX_HOST)

    def core_for(self, http: Any, request: Any) -> Tuple[Optional[_Core], Any]:
        """The meter for the warrant in scope, or a refusal when a model call has none."""
        from tenuo._enforcement import split_presented_warrant
        from tenuo.decorators import chain_scope, get_signing_key_context, get_warrant_context

        if request.method.upper() != "POST":
            return None, None
        warrant = get_warrant_context() or self.warrant
        key = get_signing_key_context() or self.signing_key
        if warrant is None or key is None:
            path = request.url.path.rstrip("/")
            if path.endswith(_FREE_SUFFIXES) or path.endswith(self.unmetered) or not self.meter.enforce:
                return None, None
            dialect = _dialect_for(path)
            if dialect is None:
                # The same answer as with credentials: a POST the meter cannot count does not go out.
                code = UNMETERED_CODE
                message = (f"tenuo: {path} is not a model endpoint this meter understands, so it is refused under a "
                           "token budget. List the path in unmetered_paths to let it through uncounted.")
            else:
                code = DENIED_CODE
                message = ("tenuo: model call refused: no warrant and signing key are in scope. Pass them to "
                           "install() or make the call inside warrant_scope() and key_scope().")
            _send_event(self.shared["audit_callback"], decision="DENY", tool=self.meter.tool, model=None,
                        reason=message, warrant_id=None, request=request)
            return None, _refusal(http, request, dialect, code, message)
        # A warrant may be presented as a list or an encoded chain: take it
        # apart before anything asks for its id.
        leaf, parents = split_presented_warrant(warrant, list(chain_scope() or self.chain or []) or None)
        cache_key = (http.__name__, _warrant_key(leaf), id(key), tuple(_warrant_key(w) for w in parents or ()))
        with self.lock:
            core = self.cores.get(cache_key)
            if core is None:
                if len(self.cores) >= 512:
                    self.cores.clear()
                core = _Core(http=http, warrant=leaf, signing_key=key, warrant_chain=parents, **self.shared)
                self.cores[cache_key] = core
        return core, None


_INSTALLED: Optional[_Installation] = None
_VERTEX_HOST = "aiplatform.googleapis.com"


def _warrant_key(warrant: Any) -> str:
    """A cache key for a warrant in whatever form it was presented."""
    return str(getattr(warrant, "id", None) or warrant)


async def _off_loop(core: _Core, fn: Callable[..., Any], *args: Any) -> Any:
    """Run a store operation off the asyncio event loop when the store can wait on something.

    A file-backed store can wait on another writer. Shielded: a caller that is
    cancelled must not leave the accounting half done.
    """
    if not core.meter.store.blocking:
        return fn(*args)
    import asyncio
    import contextvars

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return fn(*args)  # another async library: run it where we are
    context = contextvars.copy_context()
    return await asyncio.shield(loop.run_in_executor(None, lambda: context.run(fn, *args)))


async def _plan_off_loop(core: _Core, request: Any) -> _Plan:
    """Plan a request off the event loop; a reservation made for a caller that went away is given back."""
    if not core.meter.store.blocking:
        return core.plan(request)
    import asyncio
    import contextvars

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return core.plan(request)
    context = contextvars.copy_context()
    future = loop.run_in_executor(None, lambda: context.run(core.plan, request))
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        def give_back(done: Any) -> None:
            if not done.cancelled() and done.exception() is None:
                loop.run_in_executor(None, core.release, done.result())

        future.add_done_callback(give_back)
        raise


def install(
    *,
    warrant: Any = None,
    signing_key: Any = None,
    trusted_roots: Optional[list] = None,
    warrant_chain: Optional[Sequence[Any]] = None,
    budget_store: Union[TokenMeter, BudgetStore, str, None] = None,
    audit_callback: Optional[Callable[[MeterEvent], None]] = None,
    hosts: Sequence[str] = (),
    unmetered_paths: Sequence[str] = (),
    chat_output_param: str = "max_completion_tokens",
) -> TokenMeter:
    """Meter the model calls of every ``httpx`` / ``httpx2`` client in this process.

    Call it once at startup, before or after clients are created. Nothing else
    has to be wired: SDKs and frameworks keep building their own clients.

    Args:
        warrant, signing_key, warrant_chain: The default credentials. A call
            made inside ``warrant_scope()`` / ``key_scope()`` (and
            ``chain_scope()``) uses those instead, so several agents in one
            process can each spend from their own warrant. With neither, a
            model call is refused.
        trusted_roots, budget_store, audit_callback, unmetered_paths,
            chat_output_param: As for :class:`MeteredTransport`.
        hosts: Extra hosts to meter, besides the known providers in
            ``DEFAULT_HOSTS``: a gateway, a self-hosted server
            (``"localhost:1234"``), or ``"*"`` for every host. Requests to any
            other host are not touched.

    Returns the meter, whose ``store`` holds the running totals.

    Not covered: HTTP libraries other than these two. The Google GenAI SDK
    prefers ``aiohttp`` for async calls when it is installed; ``install()``
    switches it to its ``httpx`` path for as long as it is installed.
    """
    import importlib

    global _INSTALLED
    uninstall()
    installed = _Installation(
        warrant=warrant, signing_key=signing_key, warrant_chain=warrant_chain, trusted_roots=trusted_roots,
        budget_store=budget_store, audit_callback=audit_callback, hosts=hosts, unmetered_paths=unmetered_paths,
        chat_output_param=chat_output_param,
    )
    for name in ("httpx", "httpx2"):
        try:
            http = importlib.import_module(name)
        except ImportError:
            continue
        bound = for_library(http)
        own = (bound.MeteredTransport, bound.AsyncMeteredTransport, bound.AmbientTransport, bound.AsyncAmbientTransport)
        for client_class, wrapper in ((http.Client, bound.AmbientTransport), (http.AsyncClient, bound.AsyncAmbientTransport)):
            original = client_class._transport_for_url

            # A transport that serves both interfaces gets a wrapper for each.
            slot = "_tenuo_ambient_async" if client_class is http.AsyncClient else "_tenuo_ambient"

            def choose(self: Any, url: Any, _original: Any = original, _wrapper: Any = wrapper, _own: Any = own,
                       _slot: str = slot) -> Any:
                transport = _original(self, url)
                if _INSTALLED is None or isinstance(transport, _own):
                    return transport  # not installed, or already metered explicitly
                ambient = getattr(transport, _slot, None)
                if ambient is None:
                    ambient = _wrapper(transport)
                    try:
                        setattr(transport, _slot, ambient)
                    except AttributeError:
                        pass
                return ambient

            client_class._transport_for_url = choose
            installed.patched.append((client_class, original))
    try:
        from google.genai import _api_client as genai_client  # type: ignore[import-not-found]

        if getattr(genai_client, "has_aiohttp", False):
            genai_client.has_aiohttp = False  # use its httpx path, which is the one metered here
            installed.restore_genai = True
    except Exception:
        pass
    _INSTALLED = installed
    return installed.meter


def uninstall() -> None:
    """Undo :func:`install`."""
    global _INSTALLED
    installed, _INSTALLED = _INSTALLED, None
    if installed is None:
        return
    for client_class, original in installed.patched:
        client_class._transport_for_url = original
    if installed.restore_genai:
        try:
            from google.genai import _api_client as genai_client  # type: ignore[import-not-found]

            genai_client.has_aiohttp = True
        except Exception:
            pass


def is_budget_error(error: BaseException) -> bool:
    """True when ``error``, or anything it was raised from, is a spent token budget.

    Works on the error types SDKs raise for the local 403 as well as on
    :class:`tenuo.budget.BudgetExceeded` itself.
    """
    seen = set()
    current: Optional[BaseException] = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, BudgetExceeded):
            return True
        if getattr(current, "code", None) == BUDGET_CODE:
            return True
        body = getattr(current, "body", None)
        if body is not None and BUDGET_CODE in json.dumps(body, default=str):
            return True
        headers = getattr(getattr(current, "response", None), "headers", None)
        if headers is not None and headers.get("x-tenuo-denial") == BUDGET_CODE:
            return True
        if BUDGET_CODE in str(getattr(current, "details", "")) or "tenuo: token budget reached" in str(current):
            return True  # SDKs that keep only the error body or its message
        current = current.__cause__ or current.__context__
    return False
