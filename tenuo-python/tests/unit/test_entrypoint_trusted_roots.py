"""Entry points take trusted roots directly, without global configure().

OpenAI's GuardBuilder and AutoGen's module-level guard_tool / guard_tools could
only get trusted roots from tenuo.configure(). They now accept them explicitly,
like guard() and the other builders do.
"""

import json
from unittest.mock import Mock

import pytest

from tenuo import Pattern, SigningKey, Warrant
from tenuo.config import reset_config


@pytest.fixture(autouse=True)
def _no_global_roots():
    reset_config()
    yield
    reset_config()


@pytest.fixture
def keys():
    return SigningKey.generate(), SigningKey.generate()


@pytest.fixture
def warrant(keys):
    issuer_key, agent_key = keys
    return (
        Warrant.mint_builder()
        .capability("search", query=Pattern("ok*"))
        .holder(agent_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


def _response(name: str, args: dict):
    call = Mock()
    call.id = "call_0"
    call.type = "function"
    call.function.name = name
    call.function.arguments = json.dumps(args)
    message = Mock()
    message.tool_calls = [call]
    choice = Mock()
    choice.message = message
    response = Mock()
    response.choices = [choice]
    return response


class TestOpenAIGuardBuilderTrustedRoots:
    def test_with_trusted_roots_authorizes_without_global_config(self, keys, warrant):
        pytest.importorskip("openai")
        from tenuo.openai import GuardBuilder

        issuer_key, agent_key = keys
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = _response("search", {"query": "ok-1"})

        client = (
            GuardBuilder(mock_client)
            .with_warrant(warrant, agent_key)
            .with_trusted_roots([issuer_key.public_key])
            .build()
        )
        response = client.chat.completions.create(model="gpt-4o", messages=[])
        assert [c.function.name for c in response.choices[0].message.tool_calls] == ["search"]

    def test_without_roots_still_fails_closed(self, keys, warrant):
        pytest.importorskip("openai")
        from tenuo.openai import GuardBuilder

        _, agent_key = keys
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = _response("search", {"query": "ok-1"})

        client = GuardBuilder(mock_client).with_warrant(warrant, agent_key).build()
        with pytest.raises(Exception):
            client.chat.completions.create(model="gpt-4o", messages=[])

    def test_builder_records_roots(self, keys):
        pytest.importorskip("openai")
        from tenuo.openai import GuardBuilder

        issuer_key, _ = keys
        client = GuardBuilder(Mock()).with_trusted_roots([issuer_key.public_key]).build()
        assert client._trusted_roots == [issuer_key.public_key]


def _search(query: str) -> str:
    return f"results:{query}"


class TestAutoGenModuleHelpersTrustedRoots:
    def test_guard_tool_accepts_trusted_roots(self, keys, warrant):
        from tenuo.autogen import guard_tool

        issuer_key, agent_key = keys
        guarded = guard_tool(
            _search, warrant.bind(agent_key), tool_name="search", trusted_roots=[issuer_key.public_key]
        )
        assert guarded(query="ok-1") == "results:ok-1"

    def test_guard_tools_accepts_trusted_roots(self, keys, warrant):
        from tenuo.autogen import guard_tools

        issuer_key, agent_key = keys
        (guarded,) = guard_tools(
            [_search],
            warrant.bind(agent_key),
            tool_name_fn=lambda _t: "search",
            trusted_roots=[issuer_key.public_key],
        )
        assert guarded(query="ok-1") == "results:ok-1"

    def test_guard_tool_without_roots_fails_closed(self, keys, warrant):
        from tenuo.autogen import guard_tool

        _, agent_key = keys
        guarded = guard_tool(_search, warrant.bind(agent_key), tool_name="search")
        with pytest.raises(Exception):
            guarded(query="ok-1")

    def test_guard_tool_passes_approval_options_through(self, keys, warrant):
        from tenuo import autogen as ag

        _, agent_key = keys
        handler = object()
        approvals = [object()]
        captured = {}
        original = ag._Guard.__init__

        def spy(self, **kwargs):
            captured.update(kwargs)
            original(self, **kwargs)

        ag._Guard.__init__ = spy
        try:
            ag.guard_tool(
                _search, warrant.bind(agent_key), tool_name="search", approval_handler=handler, approvals=approvals
            )
        finally:
            ag._Guard.__init__ = original
        assert captured["approval_handler"] is handler
        assert captured["approvals"] is approvals
