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
    W10 an empty chain raises ConfigurationError (never falls back to Tier 1)

Denials must arrive through each adapter's documented denial channel and name
the expected category (untrusted root, leaf constraint, broken linkage), so an
unrelated crash can never satisfy a negative case.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

import pytest

from tenuo import Pattern, SigningKey, Warrant, chain_scope, encode_warrant_stack, key_scope, reset_config
from tenuo._enforcement import split_presented_warrant
from tenuo.exceptions import AuthorizationDenied, ConfigurationError

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

    @pytest.mark.parametrize("form", ["base64", "str", "pem", "pem_crlf", "wrapped", "surrounding_whitespace"])
    def test_single_warrant_forms_decode_without_from_base64(self, chain, form, monkeypatch):
        """Every single-warrant form Warrant.from_base64 accepts decodes via the stack decoder alone."""
        import tenuo_core

        leaf = chain["leaf"]
        b64 = leaf.to_base64()
        token = {
            "base64": b64,
            "str": str(leaf),
            "pem": leaf.to_pem(),
            "pem_crlf": leaf.to_pem().replace("\n", "\r\n"),
            "wrapped": "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64)),
            "surrounding_whitespace": f"  {b64}\n",
        }[form]
        assert Warrant.from_base64(token).id == leaf.id

        def _no_fallback(*_a, **_k):
            raise AssertionError("Warrant.from_base64 fallback must not be used")

        monkeypatch.setattr(tenuo_core.Warrant, "from_base64", staticmethod(_no_fallback))
        decoded, parents = split_presented_warrant(token)
        assert decoded.id == leaf.id
        assert parents is None

    def test_decode_error_is_preserved(self):
        with pytest.raises(ConfigurationError, match="Failed to decode warrant token: .*Deserialization"):
            split_presented_warrant("not-a-warrant")


class TestWarrantTokenSizeLimit:
    """Input length is bounded before decoding, at the encoded stack ceiling."""

    def test_ceiling_matches_the_rust_stack_limit(self):
        from tenuo import _enforcement as enf

        assert enf._MAX_STACK_SIZE == 256 * 1024
        assert enf._MAX_STACK_B64_CHARS == 349_528  # padded base64 of 256 KiB
        assert enf._MAX_WARRANT_TOKEN_CHARS == 349_528 + 2 * 5_462 + 72

    @pytest.mark.parametrize("where", ["warrant", "list_entry", "warrant_chain_entry"])
    def test_oversized_token_rejected_before_decoding(self, chain, where, monkeypatch):
        import tenuo_core
        from tenuo import _enforcement as enf

        calls = []

        def _spy(*args, **kwargs):
            calls.append(args)
            raise AssertionError("decoder must not be called for oversized input")

        monkeypatch.setattr(tenuo_core, "decode_warrant_stack_base64", _spy)
        # Surrounding whitespace counts: the check runs before strip().
        huge = " " * 10 + "A" * enf._MAX_WARRANT_TOKEN_CHARS
        with pytest.raises(ConfigurationError, match="exceeding the 360524 character limit"):
            if where == "warrant":
                split_presented_warrant(huge)
            elif where == "list_entry":
                split_presented_warrant([huge, chain["leaf"]])
            else:
                split_presented_warrant(chain["leaf"], [huge])
        assert calls == []

    def test_token_at_the_ceiling_reaches_the_decoder(self, monkeypatch):
        import tenuo_core
        from tenuo import _enforcement as enf

        calls = []
        monkeypatch.setattr(tenuo_core, "decode_warrant_stack_base64", lambda s: calls.append(len(s)) or [object()])
        split_presented_warrant("A" * enf._MAX_WARRANT_TOKEN_CHARS)
        assert calls == [enf._MAX_WARRANT_TOKEN_CHARS]

    @pytest.fixture
    def big_chain(self):
        """A valid 3-warrant chain whose encoded stack exceeds the 64 KiB single-warrant limit."""
        from tenuo import MAX_WARRANT_SIZE

        big = "papers/" + "x" * 30_000 + "*"
        keys = [SigningKey.generate() for _ in range(4)]
        warrant = Warrant.issue(
            keys[0], capabilities={"search": {"query": Pattern(big)}}, ttl_seconds=600, holder=keys[1].public_key
        )
        warrants = [warrant]
        for i in (1, 2):
            warrant = warrant.attenuate(
                signing_key=keys[i],
                holder=keys[i + 1].public_key,
                capabilities={"search": {"query": Pattern(big)}},
                ttl_seconds=300,
            )
            warrants.append(warrant)
        stack = encode_warrant_stack(warrants)
        decoded_size = sum(len(w.to_bytes()) for w in warrants)
        assert MAX_WARRANT_SIZE < decoded_size < 256 * 1024
        assert len(stack) > MAX_WARRANT_SIZE
        return {"root_key": keys[0], "leaf_key": keys[3], "warrants": warrants, "stack": stack, "arg": big[:-1] + "ok"}

    @pytest.mark.parametrize("pem", [False, True], ids=["base64", "pem_crlf"])
    def test_stack_larger_than_single_warrant_limit_accepted(self, big_chain, pem):
        from tenuo.openai import verify_tool_call

        token = big_chain["stack"]
        if pem:
            # The encode_pem_stack layout from wire.rs (not exposed to Python):
            # URL-safe unpadded base64 in 64-char lines, here with CRLF endings.
            urlsafe = token.replace("+", "-").replace("/", "_").rstrip("=")
            body = "\r\n".join(urlsafe[i : i + 64] for i in range(0, len(urlsafe), 64))
            token = f"-----BEGIN TENUO WARRANT CHAIN-----\r\n{body}\r\n-----END TENUO WARRANT CHAIN-----\r\n"
        leaf, parents = split_presented_warrant(token)
        assert leaf.id == big_chain["warrants"][-1].id
        assert [p.id for p in parents] == [w.id for w in big_chain["warrants"][:-1]]
        # And it authorizes end to end through an adapter.
        verify_tool_call(
            "search",
            {"query": big_chain["arg"]},
            None,
            None,
            None,
            token,
            big_chain["leaf_key"],
            [big_chain["root_key"].public_key],
        )


# =============================================================================
# Adapter drivers
# =============================================================================
#
# Each driver builds the adapter's guard from (warrant, warrant_chain, trusted
# roots) and returns a checker: ``check(query, is_async) -> Decision``. A
# Decision is "allowed" only when the tool actually ran, and "denied" only when
# the adapter reported an authorization denial through its documented channel
# (a specific exception type or denial result). Anything else, including an
# unrelated crash such as AttributeError, propagates and fails the test.
# Construction errors also propagate so W9 can assert on them.

UNTRUSTED_ROOT = "Root warrant issuer is not trusted"
LEAF_CONSTRAINT = "Constraint 'query' not satisfied"
UNLINKED_CHAIN = "I1 violated"


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    log: str = ""


Checker = Callable[[str, bool], Decision]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _reason(exc: BaseException) -> str:
    return f"{exc} {getattr(exc, 'reason', '') or ''}"


def _crewai(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.crewai import (
        CrewAIConstraintViolation,
        GuardBuilder,
        InsufficientApprovalsDenied,
        InvalidPoP,
        ToolDenied,
        UnlistedArgument,
        WarrantExpired,
        WarrantToolDenied,
    )

    denials = (
        InvalidPoP,
        CrewAIConstraintViolation,
        WarrantToolDenied,
        ToolDenied,
        UnlistedArgument,
        WarrantExpired,
        InsufficientApprovalsDenied,
    )
    guard = (
        GuardBuilder()
        .allow("search", query=Pattern("*"))
        .with_warrant(warrant, key, warrant_chain=warrant_chain)
        .with_trusted_roots(roots)
        .on_denial("raise")
        .build()
    )

    def check(query: str, is_async: bool) -> Decision:
        try:
            if is_async:
                result = _run(guard.authorize_async("search", {"query": query}))
            else:
                result = guard.authorize("search", {"query": query})
        except denials as e:
            return Decision(False, _reason(e))
        assert result is None, f"on_denial='raise' returned {result!r}"
        return Decision(True)

    return check


def _adk(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.google_adk.guard import TenuoGuard

    guard = TenuoGuard(warrant=warrant, signing_key=key, trusted_roots=roots, warrant_chain=warrant_chain)
    tool = SimpleNamespace(name="search")

    def check(query: str, is_async: bool) -> Decision:
        if is_async:
            result = _run(guard.async_before_tool(tool, {"query": query}, None))
        else:
            result = guard.before_tool(tool, {"query": query}, None)
        if result is None:
            return Decision(True)
        # The Tier 2 denial result. "Authorization failed:" is the enforcement
        # branch; other _deny() paths (no warrant, invalid token, a warrant
        # type without bind()) use different prefixes and fail this check.
        assert result["error"] == "authorization_denied", result
        assert result["message"].startswith("Authorization denied: Authorization failed:"), result
        return Decision(False, result["details"])

    return check


def _autogen(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    from tenuo.autogen import GuardBuilder
    from tenuo.exceptions import AuthorizationDenied, ConstraintViolation, ToolNotAuthorized

    guard = GuardBuilder().with_warrant(warrant, key, warrant_chain=warrant_chain).with_trusted_roots(roots).build()

    def search(query: str) -> str:
        return f"results: {query}"

    async def asearch(query: str) -> str:
        return f"results: {query}"

    guarded = guard.guard_tool(search, tool_name="search")
    aguarded = guard.guard_tool(asearch, tool_name="search")

    def check(query: str, is_async: bool) -> Decision:
        try:
            out = _run(aguarded(query=query)) if is_async else guarded(query=query)
        except (AuthorizationDenied, ToolNotAuthorized, ConstraintViolation) as e:
            return Decision(False, _reason(e))
        assert out == f"results: {query}"
        return Decision(True)

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
    from tenuo.openai import OpenAIConstraintViolation, TenuoToolGuardrail, ToolDenied, WarrantDenied, guard

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

    def check(query: str, is_async: bool) -> Decision:
        if is_async:
            # The guardrail converts only its documented denial exceptions into
            # a tripwire; any other exception propagates out of __call__.
            out = _run(guardrail(None, None, [{"name": "search", "arguments": json.dumps({"query": query})}]))
            tripped = out.tripwire_triggered if hasattr(out, "tripwire_triggered") else out["tripwire_triggered"]
            info = out.output_info if hasattr(out, "output_info") else out["output_info"]
            if not tripped:
                return Decision(True)
            assert str(info).startswith("Blocked by Tenuo: search:"), info
            return Decision(False, str(info))
        completions.query = query
        try:
            response = client.chat.completions.create(model="x", messages=[])
        except (WarrantDenied, ToolDenied, OpenAIConstraintViolation) as e:
            return Decision(False, _reason(e))
        assert response.choices[0].message.tool_calls, "allowed call was filtered out"
        return Decision(True)

    return check


def _langchain(warrant: Any, *, warrant_chain: Optional[List[Any]], key: SigningKey, roots: List[Any]) -> Checker:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool as lc_tool

    from tenuo.exceptions import (
        ConstraintViolation,
        ExpiredError,
        InsufficientApprovals,
        SignatureInvalid,
        TenuoError,
        ToolNotAuthorized,
    )
    from tenuo.langchain import TenuoTool

    @lc_tool
    def search(query: str) -> str:
        """Search papers."""
        return f"results: {query}"

    bound = warrant.bind(key) if isinstance(warrant, Warrant) else warrant
    wrapped = TenuoTool(search, bound_warrant=bound, trusted_roots=roots, warrant_chain=warrant_chain)

    def check(query: str, is_async: bool) -> Decision:
        # key_scope lets a leaf decoded from a stack token bind at call time.
        with key_scope(key):
            try:
                if is_async:
                    out = _run(wrapped.ainvoke({"query": query}))
                else:
                    out = wrapped.invoke({"query": query})
            except (ConstraintViolation, ToolNotAuthorized, ExpiredError, SignatureInvalid, InsufficientApprovals) as e:
                # TenuoTool wraps any unexpected exception in a ConstraintViolation;
                # only a Tenuo denial may be the cause, never a crash.
                if e.__cause__ is not None and not isinstance(e.__cause__, TenuoError):
                    raise
                return Decision(False, _reason(e))
        assert out == f"results: {query}"
        return Decision(True)

    return check


ADAPTERS = {
    "crewai": _crewai,
    "google_adk": _adk,
    "autogen": _autogen,
    "openai": _openai,
    "langchain": _langchain,
}

# (adapter, category) pairs whose denial surface does not carry the underlying
# reason: ADK reports a generic "not authorized" for trust and linkage
# failures, and LangChain raises a bare ToolNotAuthorized for a linkage
# failure. Only for these is the category taken from the tenuo.enforcement log
# of that same call. Every other pair must name it in the adapter's own denial.
_REASON_FROM_LOG_OK = {
    ("google_adk", UNTRUSTED_ROOT),
    ("google_adk", UNLINKED_CHAIN),
    ("langchain", UNLINKED_CHAIN),
}


@pytest.fixture(params=sorted(ADAPTERS))
def adapter(request):
    return request.param


@pytest.fixture
def make(adapter, chain, caplog):
    build = ADAPTERS[adapter]

    def _make(warrant: Any, *, warrant_chain: Optional[List[Any]] = None, roots: Optional[List[Any]] = None) -> Checker:
        inner = build(
            warrant,
            warrant_chain=warrant_chain,
            key=chain["leaf_key"],
            roots=roots if roots is not None else [chain["root_key"].public_key],
        )

        def check(query: str, is_async: bool) -> Decision:
            caplog.clear()
            with caplog.at_level(logging.DEBUG, logger="tenuo"):
                decision = inner(query, is_async)
            decision.log = caplog.text
            return decision

        return check

    return _make


@pytest.fixture
def assert_denied(adapter):
    def _assert(decision: Decision, category: str) -> None:
        assert decision.allowed is False, "expected a denial"
        if category in decision.reason:
            return
        assert (adapter, category) in _REASON_FROM_LOG_OK and category in decision.log, (
            f"{adapter}: denial reason {decision.reason!r} does not mention {category!r}"
        )

    return _assert


@pytest.fixture(params=[False, True], ids=["sync", "async"])
def is_async(request):
    return request.param


class TestAdapterWarrantChain:
    def test_w1_leaf_alone_denied(self, make, chain, is_async, assert_denied):
        assert_denied(make(chain["leaf"])(IN_SCOPE, is_async), UNTRUSTED_ROOT)

    def test_w2_explicit_chain_allowed(self, make, chain, is_async):
        assert make(chain["leaf"], warrant_chain=chain["parents"])(IN_SCOPE, is_async).allowed

    def test_w3_stack_token_allowed(self, make, chain, is_async):
        assert make(chain["stack"])(IN_SCOPE, is_async).allowed

    def test_w4_list_allowed(self, make, chain, is_async):
        assert make([chain["root"], chain["mid"], chain["leaf"]])(IN_SCOPE, is_async).allowed

    def test_w5_leaf_constraint_still_applies(self, make, chain, is_async, assert_denied):
        assert_denied(make(chain["leaf"], warrant_chain=chain["parents"])(OUT_OF_LEAF_SCOPE, is_async), LEAF_CONSTRAINT)
        assert_denied(make(chain["stack"])(OUT_OF_LEAF_SCOPE, is_async), LEAF_CONSTRAINT)

    def test_w6_untrusted_root_denied(self, make, chain, is_async, assert_denied):
        # The genuine chain, but the guard trusts some other key.
        check = make(chain["stack"], roots=[SigningKey.generate().public_key])
        assert_denied(check(IN_SCOPE, is_async), UNTRUSTED_ROOT)
        # A well-formed chain rooted at a key the guard does not trust.
        rogue = encode_warrant_stack([chain["rogue_root"], chain["rogue_leaf"]])
        assert_denied(make(rogue)(IN_SCOPE, is_async), UNTRUSTED_ROOT)

    def test_w7_unlinked_parents_denied(self, make, chain, is_async, assert_denied):
        # A trusted root that is not the leaf's ancestor.
        assert_denied(make(chain["leaf"], warrant_chain=[chain["root"]])(IN_SCOPE, is_async), UNLINKED_CHAIN)

    def test_w8_chain_scope_fallback(self, make, chain, is_async, assert_denied):
        check = make(chain["leaf"])
        with chain_scope(chain["parents"]):
            assert check(IN_SCOPE, is_async).allowed
        assert_denied(check(IN_SCOPE, is_async), UNTRUSTED_ROOT)

    def test_w9_stack_plus_chain_rejected(self, make, chain):
        with pytest.raises(ConfigurationError, match="both a multi-warrant stack"):
            make(chain["stack"], warrant_chain=chain["parents"])

    def test_w10_empty_chain_rejected(self, make):
        with pytest.raises(ConfigurationError, match="empty"):
            make([])


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

    @staticmethod
    def _assert_denied(result, message_prefix="Authorization denied: Authorization failed:"):
        assert result is not None, "expected a denial"
        assert result["error"] == "authorization_denied", result
        assert result["message"].startswith(message_prefix), result

    def test_leaf_alone_in_state_denied(self, chain, caplog):
        with caplog.at_level(logging.WARNING, logger="tenuo"):
            result = self._guard(chain).before_tool(
                SimpleNamespace(name="search"), {"query": IN_SCOPE}, self._ctx(chain["leaf"])
            )
        self._assert_denied(result)
        assert UNTRUSTED_ROOT in caplog.text

    @pytest.mark.parametrize("form", ["stack", "list"])
    def test_stack_in_state_allowed(self, chain, form):
        value = chain["stack"] if form == "stack" else [chain["root"], chain["mid"], chain["leaf"]]
        guard = self._guard(chain)
        tool = SimpleNamespace(name="search")
        assert guard.before_tool(tool, {"query": IN_SCOPE}, self._ctx(value)) is None
        assert _run(guard.async_before_tool(tool, {"query": IN_SCOPE}, self._ctx(value))) is None
        denied = guard.before_tool(tool, {"query": OUT_OF_LEAF_SCOPE}, self._ctx(value))
        self._assert_denied(denied)
        assert LEAF_CONSTRAINT in denied["details"]

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
        self._assert_denied(result, "Authorization denied: Invalid warrant:")

    def test_empty_list_in_state_denied(self, chain):
        guard = self._guard(chain)
        result = guard.before_tool(SimpleNamespace(name="search"), {"query": IN_SCOPE}, self._ctx([]))
        self._assert_denied(result, "Authorization denied: Invalid warrant:")

    def test_empty_list_warrant_rejected(self, chain):
        with pytest.raises(ConfigurationError, match="empty"):
            self._guard(chain, warrant=[])

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
        if use_chain:
            assert result is None
        else:
            self._assert_denied(result)


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
        with pytest.raises(AuthorizationDenied) as info:
            guard_tool(search, bound, tool_name="search")(query=IN_SCOPE)
        assert UNTRUSTED_ROOT in (info.value.reason or "")

    def test_guard_tool_rejects_unbound_stack(self, chain):
        from tenuo.autogen import guard_tools

        with pytest.raises(ConfigurationError, match="BoundWarrant"):
            guard_tools([], chain["stack"])

    def test_empty_chain_rejected(self):
        from tenuo.autogen import GuardBuilder, guard_tool, guard_tools

        with pytest.raises(ConfigurationError, match="empty"):
            guard_tools([], [])
        with pytest.raises(ConfigurationError, match="empty"):
            guard_tool(lambda: None, [])
        with pytest.raises(ConfigurationError, match="empty"):
            GuardBuilder().with_warrant([], SigningKey.generate())


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

    def test_empty_chain_rejected(self, chain):
        from tenuo.openai import GuardBuilder, TenuoToolGuardrail, guard, verify_tool_call

        key = chain["leaf_key"]
        client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
        with pytest.raises(ConfigurationError, match="empty"):
            guard(client, warrant=[], signing_key=key)
        with pytest.raises(ConfigurationError, match="empty"):
            GuardBuilder(client).with_warrant([], key)
        with pytest.raises(ConfigurationError, match="empty"):
            TenuoToolGuardrail(warrant=[], signing_key=key)
        with pytest.raises(ConfigurationError, match="empty"):
            verify_tool_call("search", {"query": IN_SCOPE}, None, None, None, [], key)


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

    def test_empty_chain_rejected(self, chain):
        pytest.importorskip("langchain_core")
        from langchain_core.tools import tool as lc_tool

        from tenuo.langchain import TenuoTool, guard

        @lc_tool
        def search(query: str) -> str:
            """Search papers."""
            return query

        # Rejected even when there are no tools to wrap.
        with pytest.raises(ConfigurationError, match="empty"):
            guard([], [])
        with pytest.raises(ConfigurationError, match="empty"):
            guard([search], [])
        with pytest.raises(ConfigurationError, match="empty"):
            TenuoTool(search, bound_warrant=[])


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

    def test_guarded_step_rejects_empty_chain_before_body(self, chain):
        from tenuo.crewai import guarded_step

        ran = []
        with pytest.raises(ConfigurationError, match="empty"):

            @guarded_step(allow={"search": {"query": Pattern("*")}}, warrant=[], signing_key=chain["leaf_key"])
            def step():
                ran.append(True)

        assert ran == []

    def test_guarded_step_rejects_warrant_without_key(self, chain):
        from tenuo.crewai import MissingSigningKey, guarded_step

        with pytest.raises(MissingSigningKey):
            guarded_step(allow={"search": {"query": Pattern("*")}}, warrant=chain["leaf"])

    def test_guarded_step_rejects_chain_without_warrant(self, chain):
        from tenuo.crewai import guarded_step

        with pytest.raises(ConfigurationError, match="without a warrant"):
            guarded_step(allow={"search": {"query": Pattern("*")}}, warrant_chain=chain["parents"])

    def test_builder_rejects_empty_chain(self, chain):
        from tenuo.crewai import CrewAIGuard, GuardBuilder

        with pytest.raises(ConfigurationError, match="empty"):
            GuardBuilder().with_warrant([], chain["leaf_key"])
        with pytest.raises(ConfigurationError, match="empty"):
            CrewAIGuard(
                allowed={},
                warrant=[],
                signing_key=chain["leaf_key"],
                trusted_roots=None,
                on_denial="raise",
                audit_callback=None,
            )
