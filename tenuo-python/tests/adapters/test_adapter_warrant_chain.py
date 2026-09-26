"""
Delegated warrants across the CrewAI, Google ADK, AutoGen, OpenAI, and
LangChain adapters.

A delegated warrant carries only ``parent_hash``, so it verifies only when the
path back to a trusted root is presented with it. Each adapter accepts that
path two ways, both normalized by ``tenuo._enforcement.split_presented_warrant``:

* an explicit ``warrant_chain=`` (parents, root-first, excluding the leaf)
* one token in place of the warrant: an encoded WarrantStack string or a
  root-first list of warrants

Every adapter runs the same matrix with real keys and a root -> mid -> leaf
chain, where the guard trusts only the root key:

    W1  leaf alone is denied
    W2  leaf + warrant_chain is allowed in scope
    W3  WarrantStack string is allowed in scope
    W4  root-first list is allowed in scope
    W5  an argument outside the leaf's narrower constraint is denied with the chain
    W6  a chain whose root is not trusted is denied
    W7  parents that do not link to the leaf are denied
    W8  chain_scope() still works when no warrant_chain is given
    W9  a stack plus an explicit warrant_chain raises ConfigurationError
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

import pytest

from tenuo import Pattern, SigningKey, Warrant, chain_scope, encode_warrant_stack, key_scope, reset_config
from tenuo._enforcement import split_presented_warrant
from tenuo.exceptions import ConfigurationError

IN_SCOPE = "papers/ai-safety"
# Allowed by root and mid, but outside the leaf's narrower pattern.
OUT_OF_LEAF_SCOPE = "papers/biology"


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


@pytest.fixture
def chain() -> Dict[str, Any]:
    """root -> mid -> leaf, each hop narrowing ``search.query``."""
    root_key = SigningKey.generate()
    a_key = SigningKey.generate()
    b_key = SigningKey.generate()
    leaf_key = SigningKey.generate()

    root = Warrant.issue(
        root_key,
        capabilities={"search": {"query": Pattern("*")}},
        ttl_seconds=3600,
        holder=a_key.public_key,
    )
    mid = root.attenuate(
        signing_key=a_key,
        holder=b_key.public_key,
        capabilities={"search": {"query": Pattern("papers/*")}},
        ttl_seconds=1800,
    )
    leaf = mid.attenuate(
        signing_key=b_key,
        holder=leaf_key.public_key,
        capabilities={"search": {"query": Pattern("papers/ai*")}},
        ttl_seconds=600,
    )

    # An unrelated chain whose root no guard trusts.
    rogue_key = SigningKey.generate()
    rogue_root = Warrant.issue(
        rogue_key,
        capabilities={"search": {"query": Pattern("*")}},
        ttl_seconds=3600,
        holder=a_key.public_key,
    )
    rogue_leaf = rogue_root.attenuate(
        signing_key=a_key,
        holder=leaf_key.public_key,
        capabilities={"search": {"query": Pattern("papers/ai*")}},
        ttl_seconds=600,
    )
    return {
        "root_key": root_key,
        "leaf_key": leaf_key,
        "root": root,
        "mid": mid,
        "leaf": leaf,
        "parents": [root, mid],
        "stack": encode_warrant_stack([root, mid, leaf]),
        "rogue_root": rogue_root,
        "rogue_leaf": rogue_leaf,
    }


# =============================================================================
# Shared helper
# =============================================================================


class TestSplitPresentedWarrant:
    def test_plain_warrant_passes_through(self, chain):
        leaf, parents = split_presented_warrant(chain["leaf"])
        assert leaf is chain["leaf"]
        assert parents is None

    def test_explicit_chain_is_returned(self, chain):
        leaf, parents = split_presented_warrant(chain["leaf"], chain["parents"])
        assert leaf is chain["leaf"]
        assert [p.id for p in parents] == [chain["root"].id, chain["mid"].id]

    def test_empty_chain_is_none(self, chain):
        assert split_presented_warrant(chain["leaf"], [])[1] is None

    def test_none_value(self, chain):
        assert split_presented_warrant(None) == (None, None)
        leaf, parents = split_presented_warrant(None, [chain["root"]])
        assert leaf is None and [p.id for p in parents] == [chain["root"].id]

    def test_stack_string(self, chain):
        leaf, parents = split_presented_warrant(chain["stack"])
        assert leaf.id == chain["leaf"].id
        assert [p.id for p in parents] == [chain["root"].id, chain["mid"].id]

    def test_single_warrant_token(self, chain):
        leaf, parents = split_presented_warrant(chain["leaf"].to_base64())
        assert leaf.id == chain["leaf"].id
        assert parents is None

    def test_single_token_with_explicit_chain(self, chain):
        leaf, parents = split_presented_warrant(chain["leaf"].to_base64(), chain["parents"])
        assert leaf.id == chain["leaf"].id
        assert len(parents) == 2

    def test_list_and_tuple(self, chain):
        for value in ([chain["root"], chain["mid"], chain["leaf"]], (chain["root"], chain["mid"], chain["leaf"])):
            leaf, parents = split_presented_warrant(value)
            assert leaf is chain["leaf"]
            assert parents == [chain["root"], chain["mid"]]

    def test_single_element_list(self, chain):
        assert split_presented_warrant([chain["leaf"]]) == (chain["leaf"], None)

    def test_list_entries_may_be_tokens(self, chain):
        leaf, parents = split_presented_warrant([chain["root"].to_base64(), chain["mid"], chain["leaf"].to_base64()])
        assert leaf.id == chain["leaf"].id
        assert [p.id for p in parents] == [chain["root"].id, chain["mid"].id]

    def test_chain_entries_may_be_tokens(self, chain):
        _, parents = split_presented_warrant(chain["leaf"], [chain["root"].to_base64(), chain["mid"]])
        assert [p.id for p in parents] == [chain["root"].id, chain["mid"].id]

    def test_bound_leaf_kept_bound_parent_unwrapped(self, chain):
        bound_leaf = chain["leaf"].bind(chain["leaf_key"])
        bound_root = chain["root"].bind(SigningKey.generate())
        leaf, parents = split_presented_warrant([bound_root, chain["mid"], bound_leaf])
        assert leaf is bound_leaf
        assert parents[0] is chain["root"]

    def test_other_objects_pass_through(self):
        sentinel = object()
        assert split_presented_warrant(sentinel) == (sentinel, None)

    def test_stack_plus_chain_is_ambiguous(self, chain):
        with pytest.raises(ConfigurationError, match="both a multi-warrant stack and an explicit warrant_chain"):
            split_presented_warrant(chain["stack"], [chain["root"]])
        with pytest.raises(ConfigurationError, match="both a multi-warrant stack"):
            split_presented_warrant([chain["mid"], chain["leaf"]], [chain["root"]])

    @pytest.mark.parametrize("bad", ["", "   ", "not-a-warrant", "!!!"])
    def test_bad_token(self, bad):
        with pytest.raises(ConfigurationError):
            split_presented_warrant(bad)

    def test_empty_list(self):
        with pytest.raises(ConfigurationError, match="empty"):
            split_presented_warrant([])

    def test_bad_list_entry(self, chain):
        with pytest.raises(ConfigurationError, match=r"warrant\[0\]"):
            split_presented_warrant([42, chain["leaf"]])

    def test_chain_must_be_a_list(self, chain):
        with pytest.raises(ConfigurationError, match="must be a list"):
            split_presented_warrant(chain["leaf"], chain["stack"])  # type: ignore[arg-type]

    def test_chain_entry_must_be_single_warrant(self, chain):
        with pytest.raises(ConfigurationError, match="3-warrant stack"):
            split_presented_warrant(chain["leaf"], [chain["stack"]])

    def test_bad_chain_entry(self, chain):
        with pytest.raises(ConfigurationError, match=r"warrant_chain\[0\]"):
            split_presented_warrant(chain["leaf"], [object()])


# =============================================================================
# Adapter drivers
# =============================================================================
#
# Each driver builds the adapter's guard from (warrant, warrant_chain, trusted
# roots) and returns a checker: ``check(query, is_async) -> bool`` where True
# means the tool call was allowed. Construction errors propagate so W9 can
# assert on them.

Checker = Callable[[str, bool], bool]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _crewai(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.crewai import GuardBuilder

    guard = (
        GuardBuilder()
        .allow("search", query=Pattern("*"))
        .with_warrant(warrant, key, warrant_chain=warrant_chain)
        .with_trusted_roots(roots)
        .on_denial("raise")
        .build()
    )

    def check(query: str, is_async: bool) -> bool:
        try:
            if is_async:
                result = _run(guard.authorize_async("search", {"query": query}))
            else:
                result = guard.authorize("search", {"query": query})
        except ConfigurationError:
            raise
        except Exception:
            return False
        return result is None

    return check


def _adk(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.google_adk.guard import TenuoGuard

    guard = TenuoGuard(warrant=warrant, signing_key=key, trusted_roots=roots, warrant_chain=warrant_chain)
    tool = SimpleNamespace(name="search")

    def check(query: str, is_async: bool) -> bool:
        if is_async:
            result = _run(guard.async_before_tool(tool, {"query": query}, None))
        else:
            result = guard.before_tool(tool, {"query": query}, None)
        return result is None

    return check


def _autogen(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.autogen import GuardBuilder

    guard = GuardBuilder().with_warrant(warrant, key, warrant_chain=warrant_chain).with_trusted_roots(roots).build()

    def search(query: str) -> str:
        return f"results: {query}"

    async def asearch(query: str) -> str:
        return f"results: {query}"

    guarded = guard.guard_tool(search, tool_name="search")
    aguarded = guard.guard_tool(asearch, tool_name="search")

    def check(query: str, is_async: bool) -> bool:
        try:
            out = _run(aguarded(query=query)) if is_async else guarded(query=query)
        except ConfigurationError:
            raise
        except Exception:
            return False
        return out == f"results: {query}"

    return check


class _FakeCompletions:
    def __init__(self) -> None:
        self.query = ""

    def create(self, *args: Any, **kwargs: Any) -> Any:
        tool_call = SimpleNamespace(
            id="c1",
            type="function",
            function=SimpleNamespace(name="search", arguments=json.dumps({"query": self.query})),
        )
        message = SimpleNamespace(role="assistant", content=None, tool_calls=[tool_call])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _openai(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.openai import TenuoToolGuardrail, guard

    completions = _FakeCompletions()
    client = guard(
        SimpleNamespace(chat=SimpleNamespace(completions=completions)),
        warrant=warrant,
        signing_key=key,
        trusted_roots=roots,
        warrant_chain=warrant_chain,
        on_denial="raise",
    )
    guardrail = TenuoToolGuardrail(warrant=warrant, signing_key=key, trusted_roots=roots, warrant_chain=warrant_chain)

    def check(query: str, is_async: bool) -> bool:
        if is_async:
            out = _run(guardrail(None, None, [{"name": "search", "arguments": json.dumps({"query": query})}]))
            tripped = out.tripwire_triggered if hasattr(out, "tripwire_triggered") else out["tripwire_triggered"]
            return not tripped
        completions.query = query
        try:
            client.chat.completions.create(model="x", messages=[])
        except ConfigurationError:
            raise
        except Exception:
            return False
        return True

    return check


def _langchain(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool as lc_tool

    from tenuo.langchain import TenuoTool

    @lc_tool
    def search(query: str) -> str:
        """Search papers."""
        return f"results: {query}"

    bound = warrant.bind(key) if isinstance(warrant, Warrant) else warrant
    wrapped = TenuoTool(search, bound_warrant=bound, trusted_roots=roots, warrant_chain=warrant_chain)

    def check(query: str, is_async: bool) -> bool:
        # key_scope lets a leaf decoded from a stack token bind at call time.
        with key_scope(key):
            try:
                if is_async:
                    out = _run(wrapped.ainvoke({"query": query}))
                else:
                    out = wrapped.invoke({"query": query})
            except ConfigurationError:
                raise
            except Exception:
                return False
        return out == f"results: {query}"

    return check


ADAPTERS = {
    "crewai": _crewai,
    "google_adk": _adk,
    "autogen": _autogen,
    "openai": _openai,
    "langchain": _langchain,
}


@pytest.fixture(params=sorted(ADAPTERS))
def make(request, chain):
    build = ADAPTERS[request.param]

    def _make(warrant: Any, *, warrant_chain: Optional[List[Any]] = None, roots: Optional[List[Any]] = None) -> Checker:
        return build(
            warrant,
            warrant_chain=warrant_chain,
            key=chain["leaf_key"],
            roots=roots if roots is not None else [chain["root_key"].public_key],
        )

    return _make


@pytest.fixture(params=[False, True], ids=["sync", "async"])
def is_async(request):
    return request.param


class TestAdapterWarrantChain:
    def test_w1_leaf_alone_denied(self, make, chain, is_async):
        assert make(chain["leaf"])(IN_SCOPE, is_async) is False

    def test_w2_explicit_chain_allowed(self, make, chain, is_async):
        assert make(chain["leaf"], warrant_chain=chain["parents"])(IN_SCOPE, is_async) is True

    def test_w3_stack_token_allowed(self, make, chain, is_async):
        assert make(chain["stack"])(IN_SCOPE, is_async) is True

    def test_w4_list_allowed(self, make, chain, is_async):
        assert make([chain["root"], chain["mid"], chain["leaf"]])(IN_SCOPE, is_async) is True

    def test_w5_leaf_constraint_still_applies(self, make, chain, is_async):
        assert make(chain["leaf"], warrant_chain=chain["parents"])(OUT_OF_LEAF_SCOPE, is_async) is False
        assert make(chain["stack"])(OUT_OF_LEAF_SCOPE, is_async) is False

    def test_w6_untrusted_root_denied(self, make, chain, is_async):
        # The genuine chain, but the guard trusts some other key.
        check = make(chain["stack"], roots=[SigningKey.generate().public_key])
        assert check(IN_SCOPE, is_async) is False
        # A well-formed chain rooted at a key the guard does not trust.
        rogue = encode_warrant_stack([chain["rogue_root"], chain["rogue_leaf"]])
        assert make(rogue)(IN_SCOPE, is_async) is False

    def test_w7_unlinked_parents_denied(self, make, chain, is_async):
        # A trusted root that is not the leaf's ancestor.
        assert make(chain["leaf"], warrant_chain=[chain["root"]])(IN_SCOPE, is_async) is False

    def test_w8_chain_scope_fallback(self, make, chain, is_async):
        check = make(chain["leaf"])
        with chain_scope(chain["parents"]):
            assert check(IN_SCOPE, is_async) is True
        assert check(IN_SCOPE, is_async) is False

    def test_w9_stack_plus_chain_rejected(self, make, chain):
        with pytest.raises(ConfigurationError, match="both a multi-warrant stack"):
            make(chain["stack"], warrant_chain=chain["parents"])


# =============================================================================
# Adapter-specific entry points
# =============================================================================


class TestGoogleAdkSessionState:
    """The warrant key in session state may hold a stack string or a list."""

    def _guard(self, chain, **kwargs):
        from tenuo.google_adk.guard import TenuoGuard

        return TenuoGuard(signing_key=chain["leaf_key"], trusted_roots=[chain["root_key"].public_key], **kwargs)

    def _ctx(self, value):
        return SimpleNamespace(state={"__tenuo_warrant__": value})

    def test_leaf_alone_in_state_denied(self, chain):
        result = self._guard(chain).before_tool(
            SimpleNamespace(name="search"), {"query": IN_SCOPE}, self._ctx(chain["leaf"])
        )
        assert result is not None

    @pytest.mark.parametrize("form", ["stack", "list"])
    def test_stack_in_state_allowed(self, chain, form):
        value = chain["stack"] if form == "stack" else [chain["root"], chain["mid"], chain["leaf"]]
        guard = self._guard(chain)
        tool = SimpleNamespace(name="search")
        assert guard.before_tool(tool, {"query": IN_SCOPE}, self._ctx(value)) is None
        assert _run(guard.async_before_tool(tool, {"query": IN_SCOPE}, self._ctx(value))) is None
        assert guard.before_tool(tool, {"query": OUT_OF_LEAF_SCOPE}, self._ctx(value)) is not None

    def test_constructor_chain_is_default_for_state_leaf(self, chain):
        guard = self._guard(chain, warrant_chain=chain["parents"])
        assert guard.before_tool(SimpleNamespace(name="search"), {"query": IN_SCOPE}, self._ctx(chain["leaf"])) is None

    def test_scoped_warrant_around_stack(self, chain):
        from tenuo.google_adk import ScopedWarrant

        guard = self._guard(chain)
        ctx = self._ctx(ScopedWarrant(chain["stack"], "researcher"))
        assert guard.before_tool(SimpleNamespace(name="search"), {"query": IN_SCOPE}, ctx) is None

    def test_malformed_state_token_denied(self, chain):
        guard = self._guard(chain)
        result = guard.before_tool(SimpleNamespace(name="search"), {"query": IN_SCOPE}, self._ctx("not-a-warrant"))
        assert result is not None
        assert "Invalid warrant" in result["message"]

    def test_builder_with_warrant_chain(self, chain):
        from tenuo.google_adk.guard import GuardBuilder

        guard = (
            GuardBuilder()
            .with_warrant(chain["leaf"], chain["leaf_key"], warrant_chain=chain["parents"])
            .with_trusted_roots([chain["root_key"].public_key])
            .build()
        )
        assert guard.before_tool(SimpleNamespace(name="search"), {"query": IN_SCOPE}, None) is None
        with pytest.raises(ConfigurationError):
            GuardBuilder().with_warrant(chain["stack"], chain["leaf_key"], warrant_chain=chain["parents"])

    @pytest.mark.parametrize("use_chain", [False, True])
    def test_plugin_passes_chain(self, chain, use_chain):
        from tenuo.google_adk.plugin import TenuoPlugin

        plugin = TenuoPlugin(
            warrant=chain["leaf"],
            signing_key=chain["leaf_key"],
            trusted_roots=[chain["root_key"].public_key],
            warrant_chain=chain["parents"] if use_chain else None,
        )
        result = _run(
            plugin.before_tool_callback(
                tool=SimpleNamespace(name="search"), tool_args={"query": IN_SCOPE}, tool_context=None
            )
        )
        assert (result is None) is use_chain


class TestAutogenBoundHelpers:
    def test_guard_tool_with_chain_and_list(self, chain):
        from tenuo.autogen import guard_tool
        from tenuo.config import configure

        configure(trusted_roots=[chain["root_key"].public_key])
        bound = chain["leaf"].bind(chain["leaf_key"])

        def search(query: str) -> str:
            return query

        assert guard_tool(search, bound, tool_name="search", warrant_chain=chain["parents"])(query=IN_SCOPE) == IN_SCOPE
        assert guard_tool(search, [chain["root"], chain["mid"], bound], tool_name="search")(query=IN_SCOPE) == IN_SCOPE
        with pytest.raises(Exception):
            guard_tool(search, bound, tool_name="search")(query=IN_SCOPE)

    def test_guard_tool_rejects_unbound_stack(self, chain):
        from tenuo.autogen import guard_tools

        with pytest.raises(ConfigurationError, match="BoundWarrant"):
            guard_tools([], chain["stack"])


class TestOpenAIHelpers:
    def test_verify_tool_call_accepts_chain_and_stack(self, chain):
        from tenuo.openai import WarrantDenied, verify_tool_call

        roots = [chain["root_key"].public_key]
        key = chain["leaf_key"]
        args = {"query": IN_SCOPE}
        verify_tool_call("search", args, None, None, None, chain["leaf"], key, roots, warrant_chain=chain["parents"])
        verify_tool_call("search", args, None, None, None, chain["stack"], key, roots)
        with pytest.raises(WarrantDenied):
            verify_tool_call("search", args, None, None, None, chain["leaf"], key, roots)

    def test_builder_and_tier2_guardrail(self, chain):
        from tenuo.openai import GuardBuilder, create_tier2_guardrail

        client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        guarded = (
            GuardBuilder(client).with_warrant(chain["leaf"], chain["leaf_key"], warrant_chain=chain["parents"]).build()
        )
        assert guarded._warrant is chain["leaf"]
        assert guarded._warrant_chain == chain["parents"]

        guardrail = create_tier2_guardrail(warrant=chain["stack"], signing_key=chain["leaf_key"])
        assert guardrail.warrant.id == chain["leaf"].id
        assert [p.id for p in guardrail.warrant_chain] == [chain["root"].id, chain["mid"].id]


class TestLangChainHelpers:
    def test_guard_splits_stack_once(self, chain):
        pytest.importorskip("langchain_core")
        from langchain_core.tools import tool as lc_tool

        from tenuo.langchain import guard

        @lc_tool
        def search(query: str) -> str:
            """Search papers."""
            return query

        with pytest.raises(ConfigurationError):
            guard([search], chain["stack"], warrant_chain=chain["parents"])

        (wrapped,) = guard([search], chain["leaf"].bind(chain["leaf_key"]), warrant_chain=chain["parents"])
        from tenuo.config import configure

        configure(trusted_roots=[chain["root_key"].public_key])
        assert wrapped.invoke({"query": IN_SCOPE}) == IN_SCOPE

    def test_unbound_stack_without_key_scope(self, chain):
        pytest.importorskip("langchain_core")
        from langchain_core.tools import tool as lc_tool

        from tenuo.langchain import TenuoTool

        @lc_tool
        def search(query: str) -> str:
            """Search papers."""
            return query

        wrapped = TenuoTool(search, bound_warrant=chain["stack"], trusted_roots=[chain["root_key"].public_key])
        with pytest.raises(ConfigurationError, match="unbound warrant"):
            wrapped.invoke({"query": IN_SCOPE})


class TestCrewAIHelpers:
    def test_guarded_step_passes_chain(self, chain):
        from tenuo.config import configure
        from tenuo.crewai import guarded_step

        configure(trusted_roots=[chain["root_key"].public_key])
        seen: Dict[str, Any] = {}

        @guarded_step(
            allow={"search": {"query": Pattern("*")}},
            warrant=chain["leaf"],
            signing_key=chain["leaf_key"],
            warrant_chain=chain["parents"],
        )
        def step():
            from tenuo.crewai import get_active_guard

            guard = get_active_guard()
            seen["result"] = guard.authorize("search", {"query": IN_SCOPE})
            return True

        assert step() is True
        assert seen["result"] is None
