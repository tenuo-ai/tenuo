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
``token_budget_exceeded`` (the budget is spent), ``model_call_denied`` (the
warrant refuses for another reason, such as the model), or, under a lease,
``lease_unavailable`` (no lease could be taken: the issuer is unreachable, or
the trigger or API key is wrong). The response carries
``x-should-retry: false``. Use :func:`is_budget_error` to recognize a spent
budget.

Tenuo Cloud
-----------
When a control plane is connected (``TENUO_CONNECT_TOKEN``, or
``TENUO_CONTROL_PLANE_URL`` + ``TENUO_API_KEY`` + ``TENUO_AUTHORIZER_NAME``),
every refusal and every finished call is also sent there as an authorization
event for the ``llm.chat`` action. Its arguments carry the model, the output
cap and ``llm_usage``: the tokens the call used and the running total and limit
of each warrant it spent from.

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
import os
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
    _is_count,
    usage_counts,
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
LEASE_CODE = "lease_unavailable"


def _lease_refusal(error: Exception) -> Tuple[str, str]:
    """The code and message for a call refused because no lease could be had.

    Only an issuer that says the budget is spent makes it a spent budget. A
    trigger that does not exist, a key it refuses or an issuer it cannot reach
    is a setup or connection problem, and is reported as one.
    """
    if getattr(error, "exhausted", False):
        return BUDGET_CODE, f"tenuo: token budget reached: {error}"
    return LEASE_CODE, f"tenuo: model call refused: no lease could be taken: {error}"

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
        request_id: The provider's id for the request (its ``x-request-id``
            or ``request-id`` response header), when it sent one.
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
    request_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Wire formats
# ---------------------------------------------------------------------------


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _all_finished(state: Dict[str, Any], items: Any, reason_key: str) -> bool:
    """Note which choices of a stream have finished; True once every requested one has.

    ``state['choices']`` is how many the request asked for.
    """
    finished = state.setdefault("finished", set())
    if isinstance(items, list):
        for position, item in enumerate(items):
            if isinstance(item, Mapping) and item.get(reason_key):
                index = item.get("index")
                finished.add(index if isinstance(index, int) and not isinstance(index, bool) else position)
    return len(finished) >= max(1, int(state.get("choices") or 1))


class _Dialect:
    """How one wire format names the output cap and reports usage."""

    name = ""
    output_params: Tuple[str, ...] = ()
    error_shape = "openai"

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """The request as the meter reads it: every field of the body, so a
        warrant can constrain any of them, with the prompt under the names the
        estimate looks for."""
        return body

    _DEPLOYMENT = re.compile(r"/deployments/([^/]+)/")

    def model(self, body: Mapping[str, Any], path: str) -> Optional[str]:
        """The model the request runs on: the deployment in the URL when there is one, else the body's."""
        match = self._DEPLOYMENT.search(path)
        if match:
            return match.group(1)
        value = body.get("model")
        return value if isinstance(value, str) else None

    def also_selected(self, body: Mapping[str, Any], model: Optional[str]) -> List[str]:
        """Every other model the request names: one in the body beside a
        deployment in the URL, and a list of fallbacks. All must be allowed."""
        named = [body.get("model")]
        fallbacks = body.get("models")
        if isinstance(fallbacks, list):
            named.extend(fallbacks)
        out: List[str] = []
        for name in named:
            if isinstance(name, str) and name != model and name not in out:
                out.append(name)
        return out

    def read_cap(self, body: Mapping[str, Any], default: str) -> Tuple[Optional[int], str]:
        """The output cap the caller set, and the field to write the cap to.

        A request that names the cap more than one way asks for the smallest.
        """
        given = [(name, body[name]) for name in self.output_params if _positive_int(body.get(name)) is not None]
        if not given:
            return None, default
        return min(value for _, value in given), given[0][0]

    def write_cap(self, body: Dict[str, Any], param: str, value: int) -> None:
        """Set the cap, on every field of the request that can carry one."""
        body[param] = value
        for name in self.output_params:
            if name in body:
                body[name] = value

    def choices(self, body: Mapping[str, Any]) -> int:
        return 1

    def wants_stream(self, body: Mapping[str, Any], path: str) -> bool:
        return body.get("stream") is True

    def prepare_stream(self, body: Dict[str, Any]) -> bool:
        """Make a streamed request report usage. True if an extra chunk must be hidden."""
        return False

    def uncountable(self, body: Mapping[str, Any]) -> Optional[str]:
        """Why this request's tokens could not be counted, when its response will not report them."""
        return None

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

    def event_usage(self, state: Dict[str, Any], event: Any) -> None:
        if not isinstance(event, Mapping):
            return
        choices = event.get("choices")
        done = _all_finished(state, choices, "finish_reason")
        usage = event.get("usage")
        if usage:
            state["usage"] = usage
            # Some providers send a running count with every chunk. It is the
            # final one in a chunk that carries nothing else, or once every
            # choice the request asked for has finished.
            if not choices or done:
                state["complete"] = True

    def is_hidden_event(self, event: Any) -> bool:
        # The usage-only chunk that include_usage adds: no choices, just usage.
        return isinstance(event, Mapping) and event.get("usage") is not None and not event.get("choices")


class _OpenAICompletions(_OpenAIChat):
    name = "openai.completions"
    output_params = ("max_tokens",)

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

    def uncountable(self, body: Mapping[str, Any]) -> Optional[str]:
        if body.get("background") is True:
            # The response returns before anything is generated; usage comes
            # later, on a request this meter does not settle from.
            return "a background response reports its usage later, where it cannot be counted"
        return None

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
        return {**body, "instructions": body.get("system")}

    @staticmethod
    def _total(usage: Mapping[str, Any]) -> Optional[Dict[str, int]]:
        """Input, output and total from a usage object, or None when it holds no count at all."""
        seen = []

        def read(name: str) -> int:
            value = usage.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                seen.append(value)
                return int(value) if _is_count(value) else 0
            return 0

        # Cached input is reported apart from input_tokens; all of it is input.
        inp = read("input_tokens") + read("cache_creation_input_tokens") + read("cache_read_input_tokens")
        out = read("output_tokens")
        if not seen or not all(_is_count(value) for value in seen):
            return None  # nothing usable was reported: the reservation stands, as for missing usage
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

    def also_selected(self, body: Mapping[str, Any], model: Optional[str]) -> List[str]:
        named = body.get("model")
        if isinstance(named, str) and named.split("/")[-1] != model:
            return [named.split("/")[-1]]
        return []

    # The settings object and its fields are accepted in either spelling.
    _CONFIG_KEYS = ("generationConfig", "generation_config")
    _CAP_NAMES = ("maxOutputTokens", "max_output_tokens")

    def _configs(self, body: Mapping[str, Any]) -> List[Mapping[str, Any]]:
        return [body[key] for key in self._CONFIG_KEYS if isinstance(body.get(key), Mapping)]

    def _config(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """The generation settings, whichever way they were spelled."""
        merged: Dict[str, Any] = {}
        for config in self._configs(body):
            merged.update(config)
        return merged

    def read_cap(self, body: Mapping[str, Any], default: str) -> Tuple[Optional[int], str]:
        configs = self._configs(body)
        given = [config[name] for config in configs for name in self._CAP_NAMES
                 if _positive_int(config.get(name)) is not None]
        snake = any("max_output_tokens" in config for config in configs)
        return (min(given) if given else None), ("max_output_tokens" if snake else "maxOutputTokens")

    def write_cap(self, body: Dict[str, Any], param: str, value: int) -> None:
        # Every settings object, and every spelling of the cap in it.
        keys = [key for key in self._CONFIG_KEYS if key in body] or [self._CONFIG_KEYS[0]]
        for key in keys:
            config = dict(body[key]) if isinstance(body.get(key), Mapping) else {}
            for name in [n for n in self._CAP_NAMES if n in config] or [param]:
                config[name] = value
            body[key] = config

    def choices(self, body: Mapping[str, Any]) -> int:
        counts = [_positive_int(config.get(name)) or 1 for config in self._configs(body)
                  for name in ("candidateCount", "candidate_count")]
        return max(counts, default=1)

    def wants_stream(self, body: Mapping[str, Any], path: str) -> bool:
        return ":streamGenerateContent" in path

    def view(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        # Sampling settings live in generationConfig: they are offered by
        # their own names too, so one constraint reads the same on every format.
        return {
            **body,
            **self._config(body),
            "messages": body.get("contents"),
            "instructions": body.get("systemInstruction") or body.get("system_instruction"),
        }

    @staticmethod
    def _total(meta: Mapping[str, Any]) -> Optional[Dict[str, int]]:
        """Input, output and total from usageMetadata, or None when it holds no count at all."""
        seen = []

        def read(name: str) -> int:
            value = meta.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                seen.append(value)
                return int(value) if _is_count(value) else 0
            return 0

        inp = read("promptTokenCount") + read("toolUsePromptTokenCount")
        out = read("candidatesTokenCount") + read("thoughtsTokenCount")  # thinking is billed as output
        total = max(read("totalTokenCount"), inp + out)  # a total below its own parts is not a total
        if not seen or not all(_is_count(value) for value in seen):
            return None  # nothing usable was reported: the reservation stands, as for missing usage
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
        if _all_finished(state, candidates, "finishReason"):
            state["complete"] = True  # every candidate asked for has finished


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

    def __init__(self, dialect: _Dialect, hide: bool, readable: bool, choices: int = 1) -> None:
        self._dialect = dialect
        self._hide = hide
        self._readable = readable
        self._buffer = b""
        self._state: Dict[str, Any] = {"choices": choices}

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
                max_tokens: Optional[int] = None, request_id: Optional[str] = None) -> None:
    """Hand one event to the audit callback; a callback that raises does not change the outcome."""
    if callback is None:
        return
    event = MeterEvent(
        timestamp=time.time(), decision=decision, tool_name=tool, model=model, reason=reason,
        warrant_id=warrant_id, usage=usage, url=str(request.url.copy_with(query=None)), max_tokens=max_tokens,
        request_id=request_id,
    )
    try:
        callback(event)
    except Exception:
        logger.warning("Audit callback failed", exc_info=True)


def _raised_by(error: BaseException, package: str) -> bool:
    """True when an exception from ``package`` is behind ``error``."""
    seen = set()
    current: Optional[BaseException] = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if (type(current).__module__ or "").split(".")[0] == package:
            return True
        current = current.__cause__ or current.__context__
    return False


_SHARED_METER: Optional[TokenMeter] = None
_SHARED_LOCK = threading.Lock()


def _shared_meter() -> TokenMeter:
    """The meter used when none is given: one in-memory count for the whole process.

    A warrant's budget is one figure however many clients spend from it, so
    clients that were not handed a store still count together.
    """
    global _SHARED_METER
    with _SHARED_LOCK:
        if _SHARED_METER is None:
            _SHARED_METER = TokenMeter()
        return _SHARED_METER


def _is_upgrade(request: Any) -> bool:
    """A request to switch protocols (a websocket session): what follows it is not HTTP."""
    return bool(request.headers.get("upgrade")) and "upgrade" in request.headers.get("connection", "").lower()


_UPGRADE_MESSAGE = ("tenuo: this request opens a streaming session whose tokens cannot be counted, so it is refused "
                    "under a token budget. List the path in unmetered_paths to let it through uncounted.")


def _control_plane() -> Any:
    """The connected control plane, or None."""
    try:
        from tenuo.control_plane import get_or_create

        return get_or_create()
    except Exception:
        logger.debug("no control plane for token usage events", exc_info=True)
        return None


def _send_cloud(control_plane: Any, *, tool: str, warrant_id: str, decision: str, model: Optional[str], reason: str,
                usage: Optional[Dict[str, Any]] = None, max_tokens: Optional[int] = None, authorization: Any = None,
                failed: Optional[str] = None) -> None:
    """Send one model-call decision to the control plane as an authorization event. Never raises."""
    if control_plane is None:
        return
    try:
        import dataclasses

        from tenuo._enforcement import EnforcementResult

        arguments: Dict[str, Any] = {"model": model}
        if max_tokens is not None:
            arguments["max_tokens"] = max_tokens
        if usage is not None:
            arguments["llm_usage"] = usage  # the key that marks a model-call event
        allowed = decision == "ALLOW"
        if isinstance(authorization, EnforcementResult) and authorization.allowed == allowed:
            # The warrant check's own result: an allow keeps its verified chain,
            # and the mark that its runtime receipt has been collected already.
            result = dataclasses.replace(authorization, arguments=arguments)
            if getattr(authorization, "_tenuo_runtime_receipt", False):
                setattr(result, "_tenuo_runtime_receipt", True)
        else:
            result = EnforcementResult(
                allowed=allowed, tool=tool, arguments=arguments, warrant_id=warrant_id,
                denial_reason=None if allowed else reason,
                constraint_violated=None if allowed else failed,
                error_type=None if allowed else "constraint_violation",
            )
        control_plane.emit_for_enforcement(result, chain_result=getattr(result, "chain_result", None))
    except Exception:
        logger.warning("Control plane emission failed for a model call; the usage event was lost", exc_info=True)


def _reads_body(request: Any, unmetered: Tuple[str, ...]) -> bool:
    """Whether planning this request reads its body: only a POST to a model
    endpoint that is not exempt. Anything else, an upload for one, is passed on
    as the stream it is and never held in memory here."""
    if request.method.upper() != "POST":
        return False
    path = request.url.path.rstrip("/")
    if path.endswith(_FREE_SUFFIXES) or path.endswith(unmetered):
        return False
    return _dialect_for(path) is not None


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
    choices: int = 1
    request_id: Optional[str] = None
    done: bool = field(default=False, repr=False)
    # The lease moved on (or is all there is): plan the request again.
    retry: bool = False
    # The lease in hand is all there is for now: plan again without asking for another.
    settle_for_lease: bool = False


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
        lease: Any = None,
    ) -> None:
        from tenuo._enforcement import split_presented_warrant

        if warrant is None or signing_key is None:
            raise ValueError("a metered transport needs a warrant and its holder's signing key")
        self.http = http  # the httpx or httpx2 module this transport belongs to
        self.warrant, chain = split_presented_warrant(warrant, list(warrant_chain) if warrant_chain else None)
        self.chain = chain
        self.signing_key = signing_key
        self.trusted_roots = trusted_roots
        self.meter = TokenMeter.coerce(budget_store) or _shared_meter()
        self.audit_callback = audit_callback
        self.unmetered = tuple(p.rstrip("/") for p in unmetered_paths)
        self.chat_output_param = chat_output_param
        self.warrant_id = str(self.warrant.id)
        self.lease = lease  # a LeasedBudget, when budgets are handed out in leases
        self.control_plane: Any = _control_plane()

    # -- before the request --------------------------------------------------

    def plan(self, request: Any, renew: bool = False) -> _Plan:
        """Decide what to do with ``request``.

        With ``renew``, a call that does not fit in what the current lease has
        left moves to the next lease instead of being cut short or refused: the
        plan then says ``retry`` and the caller plans again.
        """
        path = request.url.path.rstrip("/")
        if request.method.upper() != "POST":
            if _is_upgrade(request) and self.meter.enforce and not path.endswith(self.unmetered):
                return _Plan(request, refusal=self._refuse(request, None, UNMETERED_CODE, _UPGRADE_MESSAGE))
            return _Plan(request)
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

        model = dialect.model(body, path)
        if not monitor:
            for other in dialect.also_selected(body, model):
                if not self.meter.model_allowed(self.warrant, other):
                    return _Plan(request, refusal=self._refuse(
                        request, dialect, DENIED_CODE,
                        f"tenuo: model call refused by the warrant: the request also names model {other!r}, "
                        "which the warrant does not allow", model,
                    ))
            uncountable = dialect.uncountable(body)
            if uncountable is not None:
                return _Plan(request, refusal=self._refuse(
                    request, dialect, UNMETERED_CODE,
                    f"tenuo: this request is refused under a token budget: {uncountable}.", model,
                ))
        requested, param = dialect.read_cap(body, self._default_param(dialect))
        choices = dialect.choices(body)
        streaming = dialect.wants_stream(body, path)
        view = dict(dialect.view(body))
        view["model"] = model
        decided: Dict[str, Any] = {}
        # Parents not given to this meter are taken from chain_scope(), as the
        # warrant check does: the chain that is verified is the chain charged.
        chain = self.chain
        if chain is None:
            from tenuo.decorators import chain_scope

            chain = list(chain_scope() or []) or None

        def authorize(tool: str, args: Dict[str, Any]) -> Any:
            decided["result"] = self._authorize(tool, args, chain)
            return decided["result"]

        # The meter changes the request before it goes out (the output cap,
        # the usage option of a stream). The warrant checks that final form.
        final: Dict[str, Any] = {}

        def as_sent(cap: int) -> Mapping[str, Any]:
            out = dict(body)
            dialect.write_cap(out, param, cap)
            final["hide"] = dialect.prepare_stream(out) if streaming else False
            final["body"] = out
            seen = dict(dialect.view(out))
            seen["model"] = model
            return seen

        try:
            call = self.meter.begin(
                self.warrant, chain, view,
                requested_output=requested, choices=choices, authorize=authorize,
                as_sent=as_sent,
            )
        except BudgetExceeded as e:
            if renew and e.own and self._is_lease():
                moved = self._other_lease(request, dialect, model, used=e.used > 0)
                if moved is not None:
                    return moved
            snapshot: Dict[str, Any] = {"warrant_id": e.warrant_id, "used": e.used}
            if e.limit is not None:
                snapshot["limit"] = e.limit
            if not e.own:
                snapshot["delegated_from"] = True
            reason = self._budget_message(e)
            return _Plan(request, refusal=self._refuse(
                request, dialect, BUDGET_CODE, reason, model, {"budget": [snapshot]},
                authorization=decided.get("result"), failed=self.meter.field))
        except ModelCallDenied as e:
            reason = f"tenuo: model call refused by the warrant: {e}"
            return _Plan(request, refusal=self._refuse(request, dialect, DENIED_CODE, reason, model,
                                                       authorization=e.result))
        call.adapter_state["authorization"] = decided.get("result")
        if renew and call.lowered and self._is_lease() and self._lease_is_short(call):
            call.release()  # nothing is running on the lease, so it can be returned whole
            moved = self._other_lease(request, dialect, model, used=True)
            return moved if moved is not None else _Plan(request, retry=True, settle_for_lease=True)
        charged = [lv.warrant_id for lv in call.levels]
        call.adapter_state["charged"] = charged
        if self.lease is not None and not self.lease.enter(charged):
            # The lease was retired between taking its warrant and here: what
            # it used is being reported, so nothing more may be spent under it.
            call.release()
            call.adapter_state["charged"] = []
            if renew:
                return _Plan(request, retry=True)
            reason = "tenuo: token budget reached: the lease this call would spend from is closed"
            return _Plan(request, refusal=self._refuse(request, dialect, BUDGET_CODE, reason, model,
                                                       failed=self.meter.field))

        if not call.enforced:
            # Only watching: the request goes out exactly as the caller wrote
            # it. Usage is recorded when the response carries it.
            return _Plan(request, call=call, dialect=dialect, choices=choices)
        try:
            if "body" not in final:
                as_sent(call.max_output)  # type: ignore[arg-type]
            hide = final["hide"]
            content = json.dumps(final["body"], separators=(",", ":")).encode()
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
            if self.lease is not None:
                self.lease.exit(charged, None, None)
            raise
        return _Plan(rewritten, call=call, dialect=dialect, hide_usage=hide, choices=choices)

    def _budget_message(self, e: BudgetExceeded) -> str:
        """Say a refusal in the budget's terms when the warrant is a lease.

        "This warrant allows 24 tokens" is true of a lease and useless to the
        person reading it: what they need is how much of the period's budget
        is left and when it resets.
        """
        info = self.lease.describe(e.warrant_id) if self.lease is not None else None
        if not info:
            return str(e)
        period = str(info.get("period") or "")
        whose = {"day": "today's budget", "week": "this week's budget", "month": "this month's budget"}.get(period, "the budget")
        resets = f" It resets at {info['resets_at']}." if info.get("resets_at") else " It does not reset."
        left = max(0, (e.limit or 0) - e.used)
        pool = info.get("pool") if isinstance(info.get("pool"), Mapping) else {}
        if pool.get("remaining"):
            # The period has more, but not in one piece large enough for this call.
            return (f"tenuo: token budget reached: this call needs at least {e.needed:,} tokens and {left:,} are left of the "
                    f"{e.limit or 0:,} this budget hands out at a time. Raise the lease size, or ask for a smaller answer.{resets}")
        return (f"tenuo: token budget reached: {left:,} tokens are left in {whose} and this call needs at least "
                f"{e.needed:,}.{resets}")

    def _is_lease(self) -> bool:
        """This meter's warrant is a lease, the current one or one the process has moved on from."""
        return self.lease is not None and self.lease.knows(self.warrant_id)

    def _lease_is_short(self, call: MeteredCall) -> bool:
        """The lease itself is what cut the call short, and it is not a fresh one."""
        limited = [lv for lv in call.levels if lv.limit is not None]
        if not limited:
            return False
        tight = min(limited, key=lambda lv: (lv.limit or 0) - lv.used)
        return tight.warrant_id == self.warrant_id and tight.used - call.reserved > 0

    def _other_lease(self, request: Any, dialect: Optional[_Dialect], model: Optional[str], used: bool) -> Optional[_Plan]:
        """This lease cannot carry the call: plan it on another one.

        Returns the plan to act on (plan again, or a refusal), or None when
        this lease is all there is for now and the call should be decided on it.
        """
        from tenuo.budget_lease import LeaseUnavailable

        try:
            # A lease another thread has already moved on from needs no renewal:
            # renew() sees that it is not the current one and says so.
            moved = self.lease.renew(self.warrant_id, used=used)
        except LeaseUnavailable as e:
            code, reason = _lease_refusal(e)
            return _Plan(request, refusal=self._refuse(request, dialect, code, reason, model,
                                                       failed=self.meter.field if code == BUDGET_CODE else None))
        return _Plan(request, retry=True) if moved else None

    def _leave_lease(self, plan: _Plan, usage: Optional[Mapping[str, Any]]) -> None:
        if self.lease is None or plan.call is None:
            return
        try:
            self.lease.exit(plan.call.adapter_state.get("charged") or (), plan.call.model, usage)
        except Exception:
            logger.warning("Lease bookkeeping failed", exc_info=True)

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
                model: Optional[str] = None, usage: Optional[Dict[str, Any]] = None, *,
                authorization: Any = None, failed: Optional[str] = None) -> Any:
        """The local 403 for a request, with its one DENY event."""
        self._emit("DENY", model, message, request, usage, authorization=authorization, failed=failed)
        return _refusal(self.http, request, dialect, code, message)

    # -- after the request ---------------------------------------------------

    def failed(self, plan: _Plan, error: BaseException) -> None:
        """The request raised instead of returning a response."""
        if plan.call is None or plan.done:
            return
        h = self.http
        never_sent = isinstance(error, (h.ConnectError, h.ConnectTimeout, h.PoolTimeout,
                                        h.UnsupportedProtocol, h.InvalidURL))
        if not never_sent and isinstance(error, h.LocalProtocolError):
            # HTTP/1.1 checks the request line and headers before it writes
            # anything: a header it will not send (a key with a line break in
            # it, say) means the provider never saw the request.
            never_sent = _raised_by(error, "h11")
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
        self._leave_lease(plan, None)

    def settle(self, plan: _Plan, usage: Any) -> None:
        if plan.call is None or plan.done:
            return
        plan.done = True
        try:
            record = plan.call.settle(usage)
        except Exception:
            # The reservation stays counted, which errs toward the budget.
            logger.warning("Token usage could not be recorded", exc_info=True)
            # The call ran and was billed. The lease and the control plane are
            # told what the provider reported, which can be more than was
            # reserved; the reservation only when there is no usable count.
            try:
                counts = usage_counts(usage)
            except Exception:
                counts = None
            partial: Dict[str, Any] = dict(counts) if counts is not None else {
                "input_tokens": plan.call.input_estimate,
                "output_tokens": plan.call.reserved - plan.call.input_estimate,
                "total_tokens": plan.call.reserved,
                "estimated": True,
            }
            # The running totals could not be confirmed, so none are given.
            partial["unrecorded"] = True
            self._leave_lease(plan, partial)
            self._emit("ALLOW", plan.call.model, "model call metered", plan.request, partial, plan.call.max_output,
                       authorization=plan.call.adapter_state.get("authorization"), request_id=plan.request_id)
            return
        self._leave_lease(plan, record)
        self._emit("ALLOW", plan.call.model, "model call metered", plan.request, record, plan.call.max_output,
                   authorization=plan.call.adapter_state.get("authorization"), request_id=plan.request_id)

    @staticmethod
    def note_response(plan: _Plan, response: Any) -> None:
        """Keep the provider's id for the request, for the usage record."""
        plan.request_id = response.headers.get("x-request-id") or response.headers.get("request-id")

    def usage_from_body(self, plan: _Plan, body: bytes) -> Any:
        try:
            return plan.dialect.response_usage(json.loads(body))  # type: ignore[union-attr]
        except Exception:
            return None

    def tap(self, plan: _Plan, response: Any) -> _StreamTap:
        encoding = response.headers.get("content-encoding", "identity").lower()
        return _StreamTap(plan.dialect, plan.hide_usage,  # type: ignore[arg-type]
                          readable=encoding in ("", "identity"), choices=plan.choices)

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
              usage: Optional[Dict[str, Any]], max_tokens: Optional[int] = None, *,
              authorization: Any = None, failed: Optional[str] = None,
              request_id: Optional[str] = None) -> None:
        self._emit_cloud(decision, model, reason, usage, max_tokens, authorization, failed)
        _send_event(self.audit_callback, decision=decision, tool=self.meter.tool, model=model, reason=reason,
                    warrant_id=self.warrant_id, request=request, usage=usage, max_tokens=max_tokens,
                    request_id=request_id)

    def _emit_cloud(self, decision: str, model: Optional[str], reason: str, usage: Optional[Dict[str, Any]],
                    max_tokens: Optional[int], authorization: Any, failed: Optional[str]) -> None:
        """Send the decision, with its usage, to the control plane when one is connected.

        One event per model call: at the end of an allowed call (so it carries
        what the call used) or at the refusal. Never raises.
        """
        _send_cloud(self.control_plane, tool=self.meter.tool, warrant_id=self.warrant_id, decision=decision,
                    model=model, reason=reason, usage=usage, max_tokens=max_tokens, authorization=authorization,
                    failed=failed)


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

    def send_sync(core: _Core, send: Callable[[Any], Any], request: Any, plan: Optional[_Plan] = None) -> Any:
        """Meter one request sent with ``send``."""
        if plan is None:
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
        core.note_response(plan, response)
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

    async def send_async(core: _Core, send: Callable[[Any], Any], request: Any, plan: Optional[_Plan] = None) -> Any:
        if plan is None:
            if _reads_body(request, core.unmetered):
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
        core.note_response(plan, response)
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
            core, plan, refusal = installed.plan_for(http, request)
            if refusal is not None:
                return refusal
            if core is None:
                return self._inner.handle_request(request)
            return send_sync(core, self._inner.handle_request, request, plan)

        def close(self) -> None:
            self._inner.close()

    class AsyncAmbientTransport(http.AsyncBaseTransport):  # type: ignore[name-defined,misc]
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        async def handle_async_request(self, request: Any) -> Any:
            installed = _INSTALLED
            if installed is None or not installed.covers(request):
                return await self._inner.handle_async_request(request)
            if _reads_body(request, installed.unmetered):
                await request.aread()  # the planner reads the body synchronously
            if installed.lease is not None or installed.meter.store.blocking:
                # Taking or returning a lease is a blocking request to the issuer,
                # and a store that can wait must not be waited on here.
                core, plan, refusal = await _plan_for_off_loop(installed, http, request)
            else:
                core, plan, refusal = installed.plan_for(http, request)
            if refusal is not None:
                return refusal
            if core is None:
                return await self._inner.handle_async_request(request)
            return await send_async(core, self._inner.handle_async_request, request, plan)

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
                 unmetered_paths: Sequence[str], chat_output_param: str, lease: Any = None) -> None:
        self.lease = lease
        self.closed = False  # set by uninstall(): a planner still running takes no new lease
        self.control_plane: Any = None  # looked up when the first refusal without a warrant is reported
        self.unmetered = tuple(p.rstrip("/") for p in unmetered_paths)
        if lease is not None and signing_key is not None and getattr(lease.source, "signing_key", signing_key) is None:
            lease.source.signing_key = signing_key  # returns are signed with the agent's key
        self.warrant, self.signing_key = warrant, signing_key
        self.chain = list(warrant_chain) if warrant_chain else None
        self.meter = TokenMeter.coerce(budget_store) or _shared_meter()
        self.shared: Dict[str, Any] = dict(trusted_roots=trusted_roots, budget_store=self.meter, audit_callback=audit_callback,
                           unmetered_paths=unmetered_paths, chat_output_param=chat_output_param, lease=lease)
        self.hosts = tuple(h.lower() for h in (*DEFAULT_HOSTS, *hosts))
        self.cores: Dict[Any, _Core] = {}
        self.patched: List[Tuple[Any, Any]] = []
        self.restore_genai = False
        self.lock = threading.Lock()

    def covers(self, request: Any) -> bool:
        if "*" in self.hosts:
            return True
        host = (request.url.host or "").lower().rstrip(".")  # "host." is the same host
        with_port = f"{host}:{request.url.port}" if request.url.port else host
        if self._listed(host, with_port):
            return True
        # A request addressed to one host and labelled for another (a Host
        # header over an IP address) is that other host's.
        named = request.headers.get("host", "").lower()
        return bool(named) and self._listed(named.rsplit(":", 1)[0].rstrip("."), named)

    def _listed(self, host: str, with_port: str) -> bool:
        if any(host == h or host.endswith("." + h) or with_port == h for h in self.hosts):
            return True
        # Regional Vertex AI endpoints are named <region>-aiplatform.googleapis.com.
        return _VERTEX_HOST in self.hosts and host.endswith("-" + _VERTEX_HOST)

    def _refused(self, http: Any, request: Any, dialect: Optional[_Dialect], code: str, message: str) -> Any:
        """A refusal made before any warrant is in hand, with its DENY events."""
        model = None
        if dialect is not None:
            try:
                body = json.loads(request.read() or b"{}")
                model = dialect.model(body, request.url.path) if isinstance(body, dict) else None
            except Exception:
                model = None
        _send_event(self.shared["audit_callback"], decision="DENY", tool=self.meter.tool, model=model,
                    reason=message, warrant_id=None, request=request)
        if self.control_plane is None:
            self.control_plane = _control_plane()
        _send_cloud(self.control_plane, tool=self.meter.tool, warrant_id="", decision="DENY", model=model,
                    reason=message, failed=self.meter.field if code == BUDGET_CODE else None)
        return _refusal(http, request, dialect, code, message)

    def core_for(self, http: Any, request: Any) -> Tuple[Optional[_Core], Any]:
        """The meter for the warrant in scope, or a refusal when a model call has none."""
        from tenuo._enforcement import split_presented_warrant
        from tenuo.decorators import chain_scope, get_signing_key_context, get_warrant_context

        if request.method.upper() != "POST":
            path = request.url.path.rstrip("/")
            if _is_upgrade(request) and self.meter.enforce and not path.endswith(self.unmetered):
                return None, self._refused(http, request, None, UNMETERED_CODE, _UPGRADE_MESSAGE)
            return None, None
        warrant = get_warrant_context()
        if warrant is None and self.lease is not None:
            path = request.url.path.rstrip("/")
            if path.endswith(_FREE_SUFFIXES) or path.endswith(self.unmetered):
                return None, None  # counted nowhere, by design: no lease is needed for it
            if _dialect_for(path) is None:
                # As under a plain warrant: a POST the meter cannot count is refused, not let through.
                message = (f"tenuo: {path} is not a model endpoint this meter understands, so it is refused under a "
                           "token budget. List the path in unmetered_paths to let it through uncounted.")
                return None, self._refused(http, request, None, UNMETERED_CODE, message)
            from tenuo.budget_lease import LeaseUnavailable

            try:
                if self.closed:
                    raise LeaseUnavailable("metering was uninstalled while this call was waiting")
                warrant = self.lease.warrant()
            except LeaseUnavailable as e:
                code, reason = _lease_refusal(e)
                return None, self._refused(http, request, _dialect_for(path), code, reason)
        warrant = warrant or self.warrant
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
            return None, self._refused(http, request, dialect, code, message)
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

    def plan_for(self, http: Any, request: Any) -> Tuple[Optional[_Core], Optional[_Plan], Any]:
        """The meter and its plan for one request, moving to the next lease once if this one is short."""
        attempts = 4 if self.lease is not None else 1  # a busy process can see its lease change more than once
        renew = self.lease is not None
        for attempt in range(attempts):
            core, refusal = self.core_for(http, request)
            if core is None:
                return None, None, refusal
            plan = core.plan(request, renew=renew and attempt < attempts - 1)
            if not plan.retry:
                break
            renew = renew and not plan.settle_for_lease
        return core, plan, None


_INSTALLED: Optional[_Installation] = None


def _reset_locks_in_child() -> None:
    """A forked child gets locks of its own: one held by another thread at the fork would never open."""
    global _SHARED_LOCK
    _SHARED_LOCK = threading.Lock()
    installed = _INSTALLED
    if installed is not None:
        installed.lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_locks_in_child)
_VERTEX_HOST = "aiplatform.googleapis.com"


def _warrant_key(warrant: Any) -> str:
    """A cache key for a warrant: its whole signed content, not only its id."""
    encode = getattr(warrant, "to_base64", None)
    if callable(encode):
        try:
            return str(encode())
        except Exception:
            pass
    return str(getattr(warrant, "id", None) or warrant)


async def _off_loop(core: _Core, fn: Callable[..., Any], *args: Any) -> Any:
    """Run a store operation off the asyncio event loop when the store can wait on something.

    A file-backed store can wait on another writer, and ending a call under a
    lease can send that lease back to its issuer. Shielded: a caller that is
    cancelled must not leave the accounting half done.
    """
    if not core.meter.store.blocking and core.lease is None:
        return fn(*args)
    import asyncio
    import contextvars

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return fn(*args)  # another async library: run it where we are
    context = contextvars.copy_context()
    try:
        future = loop.run_in_executor(None, lambda: context.run(fn, *args))
    except RuntimeError:
        return fn(*args)  # the loop's executor is shut down: the accounting still has to happen
    return await asyncio.shield(future)


def _quietly(fn: Callable[..., Any], *args: Any) -> None:
    try:
        fn(*args)
    except Exception:
        logger.warning("A plan abandoned by its caller could not be given back", exc_info=True)


async def _plan_in_worker(make: Callable[[], Any], give_back: Callable[[Any], None]) -> Any:
    """Make a plan off the event loop.

    A plan holds a reservation, and under a lease a place on that lease. When
    its caller is cancelled before it is ready, whichever thread finishes it
    gives it back. That does not go through the loop or its executor, which
    may both be gone by then.
    """
    import asyncio
    import contextvars

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return make()  # another async library: run it where we are
    context = contextvars.copy_context()
    lock = threading.Lock()
    state: Dict[str, Any] = {"abandoned": False, "ready": False, "plan": None}

    def work() -> Any:
        made = context.run(make)
        with lock:
            state["ready"], state["plan"] = True, made
            abandoned = state["abandoned"]
        if abandoned:
            _quietly(give_back, made)
        return made

    try:
        future = loop.run_in_executor(None, work)
    except RuntimeError:
        return make()  # the loop's executor is shut down: plan where we are
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        with lock:
            state["abandoned"] = True
            ready, made = state["ready"], state["plan"]
        if ready:
            # Finished just before the caller left. Given back on a thread of
            # its own: it can mean a request to the issuer.
            threading.Thread(target=_quietly, args=(give_back, made), name="tenuo-plan-release").start()
        raise


async def _plan_off_loop(core: _Core, request: Any) -> _Plan:
    """Plan a request off the event loop; a reservation made for a caller that went away is given back."""
    if not core.meter.store.blocking:
        return core.plan(request)
    return await _plan_in_worker(lambda: core.plan(request), core.release)


async def _plan_for_off_loop(installed: "_Installation", http: Any, request: Any) -> Tuple[Optional[_Core], Optional[_Plan], Any]:
    """Plan a request off the event loop. A plan made for a caller that went away is given back:
    it holds a reservation and a place on a lease."""
    def give_back(made: Tuple[Optional[_Core], Optional[_Plan], Any]) -> None:
        core, plan, _ = made
        if core is not None and plan is not None:
            core.release(plan)

    return await _plan_in_worker(lambda: installed.plan_for(http, request), give_back)


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
    lease: Any = None,
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
        lease: A :class:`tenuo.budget_lease.LeasedBudget`. The default warrant
            is then its current lease, renewed and returned as calls are made;
            ``warrant`` is not needed. ``uninstall()`` returns what it holds.
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
        chat_output_param=chat_output_param, lease=lease,
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
    if installed.lease is not None:
        installed.closed = True
        try:
            installed.lease.close()
        except Exception:
            logger.warning("Leases could not be returned on uninstall", exc_info=True)
    if installed.restore_genai:
        try:
            from google.genai import _api_client as genai_client  # type: ignore[import-not-found]

            genai_client.has_aiohttp = True
        except Exception:
            pass


_TENUO_CODES = (BUDGET_CODE, DENIED_CODE, UNMETERED_CODE, LEASE_CODE)


def _tenuo_code(value: Any, depth: int = 0) -> Optional[str]:
    """The first refusal code of this module found under a ``code`` or ``reason`` key, at any depth."""
    if depth > 6:
        return None
    if isinstance(value, Mapping):
        for key in ("code", "reason"):
            found = value.get(key)
            if isinstance(found, str) and found in _TENUO_CODES:
                return found
        items = list(value.values())
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return None
    for item in items:
        found = _tenuo_code(item, depth + 1)
        if found is not None:
            return found
    return None


def _explicit_code(error: Any) -> Optional[str]:
    """The refusal code an error states outright: its header, its ``code``, or its parsed body."""
    headers = getattr(getattr(error, "response", None), "headers", None)
    if headers is not None:
        found = headers.get("x-tenuo-denial")
        if found in _TENUO_CODES:
            return str(found)
    code = getattr(error, "code", None)
    if isinstance(code, str) and code in _TENUO_CODES:
        return code
    for attr in ("body", "details"):
        found = _tenuo_code(getattr(error, attr, None))
        if found is not None:
            return found
    return None


def is_budget_error(error: BaseException) -> bool:
    """True when ``error``, or anything it was raised from, is a spent token budget.

    Works on the error types SDKs raise for the local 403 as well as on
    :class:`tenuo.budget.BudgetExceeded` itself. A refusal that states another
    code (``lease_unavailable``, ``model_call_denied``) is not a spent budget,
    whatever words its message quotes.
    """
    seen = set()
    current: Optional[BaseException] = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, BudgetExceeded):
            return True
        code = _explicit_code(current)
        if code is not None:
            return code == BUDGET_CODE
        # SDKs that keep only the error text: the refusal is what the message
        # opens with, not something it quotes further on.
        text = str(current)
        opening = text.find("tenuo: ")
        if opening >= 0:
            if text.startswith("tenuo: token budget reached", opening):
                return True
        elif BUDGET_CODE in str(getattr(current, "details", "")):
            return True
        current = current.__cause__ or current.__context__
    return False
