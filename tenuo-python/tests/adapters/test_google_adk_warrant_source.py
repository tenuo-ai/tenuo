"""Where the ADK guard takes its warrant from, and what the plugin refuses."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytest.importorskip("tenuo_core")

from tenuo import SigningKey, Subpath, Warrant  # noqa: E402
from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.google_adk.guard import GuardBuilder, TenuoGuard  # noqa: E402
from tenuo.google_adk.plugin import TenuoPlugin  # noqa: E402


@pytest.fixture
def setup():
    issuer, agent = SigningKey.generate(), SigningKey.generate()

    def warrant_for(root: str) -> str:
        return (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath(root))
            .holder(agent.public_key)
            .ttl(300)
            .mint(issuer)
            .to_base64()
        )

    tool = MagicMock()
    tool.name = "read_file"
    return SimpleNamespace(
        issuer=issuer,
        agent=agent,
        alice=warrant_for("/data/alice"),
        bob=warrant_for("/data/bob"),
        tool=tool,
    )


def context(user_id: str, state: dict):
    return SimpleNamespace(user_id=user_id, state=state, agent_name="reader")


def read(guard, ctx, tool, path):
    """None when the call is allowed, the denial dict otherwise."""
    return guard.before_tool(tool, {"path": path}, ctx)


def test_resolver_supplies_the_warrant_and_session_state_is_ignored(setup):
    by_user = {"alice": setup.alice}
    guard = TenuoGuard(
        signing_key=setup.agent,
        trusted_roots=[setup.issuer.public_key],
        warrant_key="user_warrant",
        warrant_resolver=lambda ctx: by_user.get(ctx.user_id),
    )

    # Bob's warrant written into Alice's session state does not take effect.
    ctx = context("alice", {"user_warrant": setup.bob})
    assert read(guard, ctx, setup.tool, "/data/alice/notes") is None
    assert read(guard, ctx, setup.tool, "/data/bob/secret") is not None

    # No warrant from the resolver means no warrant, whatever state holds.
    ctx = context("mallory", {"user_warrant": setup.bob})
    assert read(guard, ctx, setup.tool, "/data/bob/secret") is not None


def test_builder_and_plugin_pass_the_resolver_through(setup):
    by_user = {"alice": setup.alice}

    def resolver(ctx):
        return by_user.get(ctx.user_id)

    built = (
        GuardBuilder()
        .with_warrant(None, setup.agent)
        .with_trusted_roots([setup.issuer.public_key])
        .warrant_resolver(resolver)
        .build()
    )
    plugin = TenuoPlugin(
        signing_key=setup.agent,
        trusted_roots=[setup.issuer.public_key],
        warrant_resolver=resolver,
    )
    for guard in (built, plugin._guard):
        ctx = context("alice", {"__tenuo_warrant__": setup.bob})
        assert read(guard, ctx, setup.tool, "/data/alice/notes") is None
        assert read(guard, ctx, setup.tool, "/data/bob/secret") is not None


def test_a_failing_resolver_denies(setup):
    def broken(ctx):
        raise RuntimeError("store unavailable")

    guard = TenuoGuard(
        signing_key=setup.agent,
        trusted_roots=[setup.issuer.public_key],
        warrant_resolver=broken,
    )
    with pytest.raises(ConfigurationError):
        guard._get_warrant_and_chain(context("alice", {}))
    assert read(guard, context("alice", {}), setup.tool, "/data/alice/notes") is not None


@pytest.mark.parametrize("entry", ["guard", "builder", "plugin"])
def test_static_warrant_and_resolver_cannot_be_combined(setup, entry):
    kwargs = dict(warrant=setup.alice, signing_key=setup.agent, warrant_resolver=lambda _: None)
    with pytest.raises(ConfigurationError, match="static warrant or warrant_resolver"):
        if entry == "builder":
            GuardBuilder().with_warrant(setup.alice, setup.agent).warrant_resolver(lambda _: None).build()
        elif entry == "plugin":
            TenuoPlugin(**kwargs)
        else:
            TenuoGuard(**kwargs)


@pytest.mark.parametrize("hook", ["sync", "async", "plugin"])
@pytest.mark.parametrize("local_policy", ["allow", "constraints"])
@pytest.mark.parametrize("failure", ["missing", "raises", "malformed"])
@pytest.mark.parametrize("require_pop", [False, True])
def test_resolver_failure_cannot_fall_back_to_local_rules(setup, hook, local_policy, failure, require_pop):
    def resolver(_):
        if failure == "raises":
            raise RuntimeError("resolver unavailable")
        return None if failure == "missing" else "not a warrant"

    kwargs = dict(warrant_resolver=resolver, require_pop=require_pop)
    if local_policy == "allow":
        kwargs["allow_tools"] = ["read_file"]
    else:
        kwargs["constraints"] = {"read_file": {"path": Subpath("/data")}}
    ctx, args = context("alice", {"__tenuo_warrant__": setup.alice}), {"path": "/data/alice/notes"}
    if hook == "plugin":
        # Plugins share the same guard but expose ADK's keyword-only async hook.
        plugin = TenuoPlugin(warrant_resolver=resolver)
        plugin._guard = TenuoGuard(**kwargs)
        denied = asyncio.run(plugin.before_tool_callback(tool=setup.tool, tool_args=args, tool_context=ctx))
    else:
        guard = TenuoGuard(**kwargs)
        denied = guard.before_tool(setup.tool, args, ctx) if hook == "sync" else asyncio.run(
            guard.async_before_tool(setup.tool, args, ctx)
        )
    assert denied is not None
    assert denied["error"] == "authorization_denied"


def test_resolver_miss_in_builder_does_not_use_an_allow_rule(setup):
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).warrant_resolver(lambda _: None).build()
    assert read(guard, context("alice", {}), setup.tool, "/data/alice/notes") is not None


def test_reading_a_warrant_from_session_state_warns_once(setup, caplog):
    guard = TenuoGuard(
        signing_key=setup.agent,
        trusted_roots=[setup.issuer.public_key],
        warrant_key="user_warrant",
    )
    ctx = context("alice", {"user_warrant": setup.alice})
    with caplog.at_level(logging.WARNING, logger="tenuo.google_adk.guard"):
        assert read(guard, ctx, setup.tool, "/data/alice/notes") is None
        assert read(guard, ctx, setup.tool, "/data/alice/notes") is None
    warnings = [r for r in caplog.records if "session state key" in r.getMessage()]
    assert len(warnings) == 1


def test_plugin_refuses_an_agent_with_a_code_executor(setup):
    def before_agent(plugin, agent):
        callback_context = SimpleNamespace(agent_name="coder", state={})
        return asyncio.run(
            plugin.before_agent_callback(callback_context=callback_context, agent=agent)
        )

    with_executor = SimpleNamespace(name="coder", code_executor=object())
    plain = SimpleNamespace(name="coder", code_executor=None)
    kwargs = dict(signing_key=setup.agent, trusted_roots=[setup.issuer.public_key])

    with pytest.raises(ConfigurationError, match="code_executor"):
        before_agent(TenuoPlugin(**kwargs), with_executor)
    assert before_agent(TenuoPlugin(**kwargs), plain) is None
    assert before_agent(TenuoPlugin(allow_code_execution=True, **kwargs), with_executor) is None
