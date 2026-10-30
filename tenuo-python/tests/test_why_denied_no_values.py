"""Denial text never carries the warrant or argument values.

``WhyDenied.suggestion`` flows into exception messages, logs, audit events and
A2A error responses. The pre-filled Explorer link encodes the warrant and the
arguments, so it lives on ``explorer_url`` only.
"""

import base64
import json
from urllib.parse import parse_qs, urlparse

from tenuo_core import Pattern, SigningKey, Warrant

import tenuo.warrant_ext  # noqa: F401  (installs Warrant.why_denied)
from tenuo.warrant_ext import _warrant_why_denied

SECRET = "hunter2-secret-value"


class _ExplodingWarrant:
    tools = ["search"]

    def to_base64(self):
        return "w"

    def is_expired(self):
        return False

    def check_constraints_detailed(self, _tool, args):
        raise ValueError(f"rejected value: {args['query']}")


def _warrant():
    key = SigningKey.generate()
    return Warrant.mint_builder().capability("search", query=Pattern("ok*")).holder(key.public_key).ttl(3600).mint(key)


def _assert_clean(text, warrant):
    assert "?s=" not in text
    assert SECRET not in text
    assert warrant.to_base64() not in text
    assert base64.b64encode(SECRET.encode()).decode()[:12] not in text


def test_tool_not_found_suggestion_has_no_values():
    w = _warrant()
    why = w.why_denied("shell", {"cmd": SECRET})
    assert why.denied
    assert "https://tenuo.ai/explorer/" in why.suggestion
    _assert_clean(why.suggestion, w)


def test_constraint_violation_suggestion_has_no_values():
    w = _warrant()
    why = w.why_denied("search", {"query": SECRET})
    assert why.denied
    _assert_clean(why.suggestion, w)


def test_explorer_url_keeps_prefilled_state():
    w = _warrant()
    why = w.why_denied("search", {"query": SECRET})
    state_b64 = parse_qs(urlparse(why.explorer_url).query)["s"][0]
    state = json.loads(base64.b64decode(state_b64))
    assert state["tool"] == "search"
    assert json.loads(state["args"]) == {"query": SECRET}


def test_explorer_url_escapes_standard_base64_query_characters():
    # This state encodes with a literal '+' in standard base64. It must be
    # percent-escaped or URL query parsers turn it into a space.
    why = _warrant_why_denied(_ExplodingWarrant(), "search", {"query": "0>"})
    assert "%2B" in why.explorer_url
    state_b64 = parse_qs(urlparse(why.explorer_url).query)["s"][0]
    state = json.loads(base64.b64decode(state_b64))
    assert json.loads(state["args"]) == {"query": "0>"}


def test_constraint_error_suggestion_does_not_echo_exception_values():
    warrant = _ExplodingWarrant()
    why = _warrant_why_denied(warrant, "search", {"query": SECRET})
    assert why.denied
    assert "Could not check constraints" in why.suggestion
    _assert_clean(why.suggestion, warrant)


def test_allowed_has_no_explorer_url():
    w = _warrant()
    why = w.why_denied("search", {"query": "ok-1"})
    assert not why.denied
    assert why.explorer_url == ""
