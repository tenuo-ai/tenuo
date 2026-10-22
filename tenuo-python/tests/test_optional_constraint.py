"""
Optional(inner): an argument that may be omitted (or None) but, when present,
must satisfy ``inner``.

Covers the binding itself, warrant authorization and delegation through the
Rust core, and a real LangChain ``create_agent`` loop with TenuoMiddleware in
which a scripted model calls a tool with and without an optional argument.
"""

from typing import Any, Dict, List, Optional as TypingOptional

import pytest

import tenuo
from tenuo import All, AnyOf, Exact, Not, OptionalArg, Pattern, Range, SigningKey, Warrant, Wildcard
from tenuo import Optional as OptionalC  # alias avoids clashing with typing.Optional here
from tenuo.exceptions import TenuoError


def _mint(key: SigningKey, **constraints: Any) -> Warrant:
    return Warrant.mint_builder().holder(key.public_key).capability("search", **constraints).ttl(600).mint(key)


# ---------------------------------------------------------------------------
# Binding
# ---------------------------------------------------------------------------


class TestBinding:
    def test_optional_arg_alias_and_star_import(self):
        assert OptionalArg is OptionalC is tenuo.Optional
        assert "OptionalArg" in tenuo.__all__
        # `from tenuo import *` must not shadow typing.Optional
        assert "Optional" not in tenuo.__all__

    def test_satisfies_absent_valid_invalid(self):
        c = OptionalC(Range(min=1, max=50))
        assert c.satisfies(None)
        assert c.satisfies(10)
        assert not c.satisfies(500)
        assert c.matches(None)

    def test_inner_and_repr(self):
        c = OptionalC(Pattern("customers:*"))
        assert type(c.inner).__name__ == "Pattern"
        assert repr(c).startswith("Optional(")

    @pytest.mark.parametrize(
        "build",
        [
            lambda: OptionalC(OptionalC(Wildcard())),
            lambda: All([OptionalC(Wildcard())]),
            lambda: AnyOf([Exact("a"), OptionalC(Wildcard())]),
            lambda: Not(OptionalC(Wildcard())),
        ],
    )
    def test_nested_optional_is_rejected(self, build):
        with pytest.raises((TenuoError, ValueError)) as exc:
            build()
        assert "top-level" in str(exc.value) or "cannot wrap" in str(exc.value)

    def test_validate_attenuation(self):
        parent = OptionalC(Range(min=1, max=50))
        parent.validate_attenuation(OptionalC(Range(min=1, max=10)))
        parent.validate_attenuation(Range(min=1, max=10))
        with pytest.raises(Exception):
            parent.validate_attenuation(OptionalC(Range(min=1, max=100)))
        with pytest.raises(Exception):
            Wildcard().validate_attenuation(OptionalC(Wildcard()))


# ---------------------------------------------------------------------------
# Warrants (Rust core enforcement)
# ---------------------------------------------------------------------------


class TestWarrant:
    def test_absent_null_valid_invalid(self):
        key = SigningKey.generate()
        w = _mint(key, query=Wildcard(), limit=OptionalC(Range(min=1, max=50)))
        assert w.allows("search", {"query": "q"})
        assert w.allows("search", {"query": "q", "limit": None})
        assert w.allows("search", {"query": "q", "limit": 10})
        assert not w.allows("search", {"query": "q", "limit": 500})
        # closed world: other unlisted keys are still denied
        assert not w.allows("search", {"query": "q", "page": 2})

    def test_null_rule_for_required_and_unlisted(self):
        key = SigningKey.generate()
        w = _mint(key, operation=Wildcard(), parameters=Wildcard())
        # unlisted None is absent, so it is not an unknown field
        assert w.allows("search", {"operation": "x", "parameters": {}, "human_confirmation": None})
        # required argument sent as None is missing
        assert not w.allows("search", {"operation": "x", "parameters": None})

    def test_core_null_rule_without_python_stripping(self):
        """check_constraints goes straight to the core, with None as JSON null."""
        key = SigningKey.generate()
        w = _mint(key, operation=Wildcard(), limit=OptionalC(Range(max=5)))
        assert w.check_constraints_detailed("search", {"operation": "x", "limit": None, "extra": None}) is None
        failed = w.check_constraints_detailed("search", {"operation": None})
        assert failed is not None and failed[0] == "operation"

    def test_why_denied_treats_absent_optional_as_satisfied(self):
        key = SigningKey.generate()
        w = _mint(key, query=Wildcard(), limit=OptionalC(Range(min=1, max=50)))
        assert not w.why_denied("search", {"query": "q"}).denied
        why = w.why_denied("search", {"query": "q", "limit": 99})
        assert why.denied and why.field == "limit"

    def test_wire_round_trip(self):
        key = SigningKey.generate()
        w = _mint(key, query=Wildcard(), limit=OptionalC(Range(min=1, max=50)))
        decoded = Warrant.from_base64(w.to_base64())
        limit = decoded.capabilities["search"]["limit"]
        assert type(limit).__name__ == "Optional"
        assert decoded.allows("search", {"query": "q"})
        assert not decoded.allows("search", {"query": "q", "limit": 99})

    def _delegate(self, parent: Warrant, key: SigningKey, **constraints: Any) -> Warrant:
        builder = parent.grant_builder()
        builder.capability("search", constraints)
        builder.holder(SigningKey.generate().public_key)
        return builder.grant(key)

    def test_delegation_rules(self):
        key = SigningKey.generate()
        parent = _mint(key, query=Wildcard(), limit=OptionalC(Range(min=1, max=50)))

        # Optional(c) -> Optional(c'), c' narrower
        child = self._delegate(parent, key, query=Wildcard(), limit=OptionalC(Range(min=1, max=10)))
        assert child.allows("search", {"query": "q"})
        assert not child.allows("search", {"query": "q", "limit": 20})

        # Optional(c) -> c' (required)
        required = self._delegate(parent, key, query=Wildcard(), limit=Range(min=1, max=10))
        assert not required.allows("search", {"query": "q"})
        assert required.allows("search", {"query": "q", "limit": 5})

        # widening the inner constraint is rejected
        with pytest.raises(TenuoError):
            self._delegate(parent, key, query=Wildcard(), limit=OptionalC(Range(min=1, max=100)))

        # c -> Optional(c') is rejected (Wildcard included)
        with pytest.raises(TenuoError):
            self._delegate(required, key, query=Wildcard(), limit=OptionalC(Range(min=1, max=10)))
        with pytest.raises(TenuoError):
            self._delegate(parent, key, query=OptionalC(Wildcard()), limit=OptionalC(Range(min=1, max=10)))

        # adding a new optional key to a closed parent is rejected
        with pytest.raises(TenuoError):
            self._delegate(
                parent,
                key,
                query=Wildcard(),
                limit=OptionalC(Range(min=1, max=50)),
                page=OptionalC(Range(min=1, max=5)),
            )

    @pytest.mark.parametrize("gate", [lambda: OptionalC(Wildcard()), lambda: {"exempt": OptionalC(Wildcard())}])
    def test_optional_rejected_in_approval_gates(self, gate):
        key = SigningKey.generate()
        with pytest.raises(Exception, match="(?i)optional"):
            (
                Warrant.mint_builder()
                .holder(key.public_key)
                .capability("search", query=Wildcard())
                .approval_gates({"search": {"query": gate()}})
                .ttl(600)
                .mint(key)
            )


# ---------------------------------------------------------------------------
# Python-side helpers that mirror the core rule
# ---------------------------------------------------------------------------


class TestPythonHelpers:
    def test_scoped_fast_fail_containment(self):
        from tenuo.scoped import _is_constraint_contained as contained

        parent = OptionalC(Range(min=1, max=50))
        assert contained(OptionalC(Range(min=1, max=10)), parent)
        assert contained(Range(min=1, max=10), parent)
        assert not contained(OptionalC(Range(min=1, max=100)), parent)
        assert not contained(OptionalC(Range(min=1, max=10)), Range(min=1, max=50))
        assert not contained(OptionalC(Wildcard()), Wildcard())

    def test_autogen_tier1_check(self):
        from tenuo.autogen import _check_constraints
        from tenuo.exceptions import ConstraintViolation

        constraints = {"query": Wildcard(), "limit": OptionalC(Range(min=1, max=50))}
        _check_constraints("search", constraints, {"query": "q"})
        _check_constraints("search", constraints, {"query": "q", "limit": None})
        _check_constraints("search", constraints, {"query": "q", "limit": 10})
        with pytest.raises(ConstraintViolation):
            _check_constraints("search", constraints, {"query": "q", "limit": 500})
        with pytest.raises(ConstraintViolation):
            _check_constraints("search", constraints, {"limit": 10})
        with pytest.raises(ConstraintViolation):
            _check_constraints("search", constraints, {"query": None})


# ---------------------------------------------------------------------------
# LangChain create_agent + TenuoMiddleware, scripted model
# ---------------------------------------------------------------------------

pytest.importorskip("langchain.agents.middleware", reason="create_agent middleware requires langchain>=1.0")

from langchain.agents import create_agent  # noqa: E402
from langchain.agents.middleware import AgentState  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from tenuo import HolderIdentity, Runtime  # noqa: E402
from tenuo.keys import KeyRegistry  # noqa: E402
from tenuo.langgraph import TenuoMiddleware  # noqa: E402

HOLDER_KEY_ID = "optional-arg-agent"
executed: List[str] = []


@tool
def search(query: str, limit: TypingOptional[int] = None) -> str:
    """Search records, optionally capping the number of results."""
    executed.append(f"search:{query}:{limit}")
    return f"results for {query!r} (limit={limit})"


class _State(AgentState):
    warrant: Any


class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> "_ScriptedModel":
        return self


@pytest.fixture
def agent_env():
    KeyRegistry.reset_instance()
    executed.clear()
    issuer = SigningKey.generate()
    holder = HolderIdentity.generate()
    KeyRegistry.get_instance().register(HOLDER_KEY_ID, holder.signing_key)
    runtime = Runtime(identity=holder, trusted_roots=[issuer.public_key], receipts="collect")
    warrant = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("search", query=Pattern("customers:*"), limit=OptionalC(Range(min=1, max=50)))
        .ttl(600)
        .mint(issuer)
    )
    yield issuer, warrant, runtime
    KeyRegistry.reset_instance()


def _run(args: Dict[str, Any], issuer: SigningKey, warrant: Warrant, runtime: Runtime) -> List[ToolMessage]:
    model = _ScriptedModel(
        messages=iter(
            [
                AIMessage(content="", tool_calls=[{"name": "search", "args": args, "id": "c1", "type": "tool_call"}]),
                AIMessage(content="Done."),
            ]
        )
    )
    agent = create_agent(
        model=model,
        tools=[search],
        state_schema=_State,
        middleware=[TenuoMiddleware(key_id=HOLDER_KEY_ID, trusted_roots=[issuer.public_key])],
    )
    state: Any = {"messages": [HumanMessage("go")], "warrant": str(warrant)}
    with runtime.bind():
        result = agent.invoke(state)
    return [m for m in result["messages"] if isinstance(m, ToolMessage)]


class TestCreateAgentLoop:
    def test_call_without_optional_arg_runs(self, agent_env):
        messages = _run({"query": "customers:acme"}, *agent_env)
        assert [m.status for m in messages] == ["success"]
        assert executed == ["search:customers:acme:None"]

    def test_call_with_null_optional_arg_runs(self, agent_env):
        messages = _run({"query": "customers:acme", "limit": None}, *agent_env)
        assert [m.status for m in messages] == ["success"]
        assert executed == ["search:customers:acme:None"]

    def test_call_with_valid_optional_arg_runs(self, agent_env):
        messages = _run({"query": "customers:acme", "limit": 10}, *agent_env)
        assert [m.status for m in messages] == ["success"]
        assert executed == ["search:customers:acme:10"]

    def test_call_with_invalid_optional_arg_is_denied(self, agent_env):
        messages = _run({"query": "customers:acme", "limit": 500}, *agent_env)
        assert [m.status for m in messages] == ["error"]
        assert executed == []

    def test_required_arg_still_enforced(self, agent_env):
        messages = _run({"query": "payroll:all", "limit": 10}, *agent_env)
        assert [m.status for m in messages] == ["error"]
        assert executed == []
