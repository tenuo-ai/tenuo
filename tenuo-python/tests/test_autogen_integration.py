"""
Tests for Tenuo AutoGen (AgentChat) integration.

Covers:
- Tier 1: GuardBuilder constraints-only enforcement
- Tier 1: Async tool support
- Tier 1: Argument extraction edge cases
- Tier 1: Streaming TOCTOU protection (buffer-verify-emit)
- Tier 2: guard_tool/guard_tools with BoundWarrant (PoP)
- Tier 2: GuardBuilder warrant + PoP enforcement
- protect() zero-config wrapper
- Integration invariants from integration guide
"""

from dataclasses import dataclass
import logging
import time
import pytest
from typing import Any, List, Optional

from tenuo import Pattern, SigningKey, Warrant, Wildcard
from tenuo.autogen import GuardBuilder, guard_tool, guard_tools, protect
from tenuo.exceptions import (
    AuthorizationDenied,
    ConfigurationError,
    ConstraintViolation,
    ExpiredError,
    MissingSigningKey,
    SignatureInvalid,
    ToolNotAuthorized,
)

# =============================================================================
# Mock Tool Helpers
# =============================================================================


def search(query: str, limit: int = 0) -> str:
    """Mock search tool."""
    return f"results:{query}:{limit}"


def read_file(path: str) -> str:
    """Mock file reader tool."""
    return f"contents:{path}"


# =============================================================================
# Mock Streaming Helpers
# =============================================================================


@dataclass
class MockFunction:
    """Mock tool function for streaming."""

    name: str
    arguments: str


@dataclass
class MockToolCallDelta:
    """Mock tool call delta."""

    index: int
    id: Optional[str] = None
    function: Optional[MockFunction] = None


@dataclass
class MockStreamDelta:
    """Mock delta for streaming."""

    tool_calls: Optional[List[Any]] = None
    content: Optional[str] = None


@dataclass
class MockStreamChoice:
    """Mock streaming choice."""

    index: int
    delta: MockStreamDelta
    finish_reason: Optional[str] = None


@dataclass
class MockStreamChunk:
    """Mock streaming chunk."""

    id: str
    choices: List[MockStreamChoice]


# =============================================================================
# Tier 1: GuardBuilder (Constraints-Only)
# =============================================================================


class TestGuardBuilderTier1:
    """Tests for GuardBuilder without warrants (Tier 1)."""

    def test_allows_and_blocks_constraints(self):
        """Allowed tools pass; constraint violations block."""
        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search, tool_name="search")

        assert guarded(query="ok-2") == "results:ok-2:0"
        with pytest.raises(ConstraintViolation):
            guarded(query="nope")

    def test_closed_world_rejects_unknown_args(self):
        """Unlisted args are rejected (closed-world)."""
        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search, tool_name="search")

        with pytest.raises(ConstraintViolation):
            guarded(query="ok", limit=5)

    def test_allow_without_constraints_rejects_args(self):
        """Tool with no constraints rejects all args."""
        guard = GuardBuilder().allow("search").build()
        guarded = guard.guard_tool(search, tool_name="search")

        with pytest.raises(ConstraintViolation):
            guarded(query="ok")

    def test_wildcard_allows_any_value_but_not_unknown_args(self):
        """Wildcard allows any value but still rejects unknown args."""
        guard = GuardBuilder().allow("search", query=Wildcard()).build()
        guarded = guard.guard_tool(search, tool_name="search")

        assert guarded(query="anything") == "results:anything:0"
        with pytest.raises(ConstraintViolation):
            guarded(query="anything", limit=10)

    def test_unlisted_tool_raises(self):
        """Unlisted tool raises ToolNotAuthorized."""
        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(read_file, tool_name="read_file")

        with pytest.raises(ToolNotAuthorized):
            guarded(path="/data/file.txt")

    def test_on_denial_log_allows_execution(self, caplog):
        """on_denial=log allows execution and logs warning."""
        guard = (
            GuardBuilder()
            .allow("search", query=Pattern("ok*"))
            .on_denial("log")
            .build()
        )
        guarded = guard.guard_tool(search, tool_name="search")

        with caplog.at_level(logging.WARNING):
            result = guarded(query="nope")

        assert result == "results:nope:0"
        assert "denied" in caplog.text.lower()

    def test_on_denial_skip_returns_none(self):
        """on_denial=skip returns None and skips tool execution."""
        calls: list[str] = []

        def tracking_tool(query: str) -> str:
            calls.append(query)
            return f"results:{query}"

        guard = (
            GuardBuilder()
            .allow("search", query=Pattern("ok*"))
            .on_denial("skip")
            .build()
        )
        guarded = guard.guard_tool(tracking_tool, tool_name="search")

        assert guarded(query="nope") is None
        assert calls == []


# =============================================================================
# Tier 1: Async Tools
# =============================================================================


class TestAsyncToolsTier1:
    """Async tool support for Tier 1 guardrails."""

    @pytest.mark.asyncio
    async def test_async_tool_allowed(self):
        """Async tools should be awaited and allowed when valid."""
        async def async_search(query: str) -> str:
            return f"async:{query}"

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(async_search, tool_name="search")

        assert await guarded(query="ok") == "async:ok"

    @pytest.mark.asyncio
    async def test_async_tool_denied(self):
        """Async tools should raise on constraint violations."""
        async def async_search(query: str) -> str:
            return f"async:{query}"

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(async_search, tool_name="search")

        with pytest.raises(ConstraintViolation):
            await guarded(query="nope")


# =============================================================================
# Tier 1: Argument Extraction
# =============================================================================


class TestArgumentExtractionTier1:
    """Argument extraction should handle common payload shapes."""

    def test_dict_payload(self):
        """Single dict payload should be used for authorization."""
        def search_payload(payload: dict) -> str:
            return f"payload:{payload['query']}"

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search_payload, tool_name="search")

        assert guarded({"query": "ok"}) == "payload:ok"

    def test_model_dump_payload(self):
        """model_dump() payloads should be supported."""
        class Payload:
            def __init__(self, query: str) -> None:
                self.query = query

            def model_dump(self) -> dict:
                return {"query": self.query}

        def search_payload(payload: Payload) -> str:
            return f"payload:{payload.query}"

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search_payload, tool_name="search")

        assert guarded(Payload("ok")) == "payload:ok"

    def test_dict_fallback_payload(self):
        """__dict__ fallback should be supported for simple objects."""
        @dataclass
        class Payload:
            query: str

        def search_payload(payload: Payload) -> str:
            return f"payload:{payload.query}"

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search_payload, tool_name="search")

        assert guarded(Payload("ok")) == "payload:ok"

    def test_positional_args_bound_by_signature(self):
        """Positional args should be bound to parameter names."""
        guard = GuardBuilder().allow("search", query=Pattern("ok*"), limit=Wildcard()).build()
        guarded = guard.guard_tool(search, tool_name="search")

        assert guarded("ok", 2) == "results:ok:2"

    def test_positional_args_reject_unknowns(self):
        """Unknown positional args should be rejected."""
        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()
        guarded = guard.guard_tool(search, tool_name="search")

        with pytest.raises(ConstraintViolation):
            guarded("ok", 2)


# =============================================================================
# Tier 1: Streaming TOCTOU Protection
# =============================================================================


class TestStreamingTOCTOUProtection:
    """Buffer-verify-emit behavior for streaming tool calls."""

    def test_streaming_buffers_until_complete(self):
        """Tool call chunks must not be emitted before verification."""
        chunks = [
            MockStreamChunk(
                id="chunk_0",
                choices=[
                    MockStreamChoice(
                        index=0,
                        delta=MockStreamDelta(
                            tool_calls=[
                                MockToolCallDelta(
                                    index=0,
                                    id="call_0",
                                    function=MockFunction(name="search", arguments='{"query": "no'),
                                )
                            ]
                        ),
                        finish_reason=None,
                    )
                ],
            ),
            MockStreamChunk(
                id="chunk_1",
                choices=[
                    MockStreamChoice(
                        index=0,
                        delta=MockStreamDelta(
                            tool_calls=[
                                MockToolCallDelta(
                                    index=0, function=MockFunction(name="", arguments='pe"}')
                                )
                            ]
                        ),
                        finish_reason=None,
                    )
                ],
            ),
            MockStreamChunk(
                id="chunk_2",
                choices=[MockStreamChoice(index=0, delta=MockStreamDelta(), finish_reason="tool_calls")],
            ),
        ]

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()

        with pytest.raises(ConstraintViolation):
            list(guard.guard_stream(iter(chunks)))

    def test_streaming_skip_filters_denied_tool_calls(self):
        """Skip mode should filter denied tool calls."""
        chunks = [
            MockStreamChunk(
                id="chunk_0",
                choices=[
                    MockStreamChoice(
                        index=0,
                        delta=MockStreamDelta(content="Let me help..."),
                        finish_reason=None,
                    )
                ],
            ),
            MockStreamChunk(
                id="chunk_1",
                choices=[
                    MockStreamChoice(
                        index=0,
                        delta=MockStreamDelta(
                            tool_calls=[
                                MockToolCallDelta(
                                    index=0, id="call_0", function=MockFunction(name="unauthorized", arguments="{}")
                                )
                            ]
                        ),
                        finish_reason=None,
                    )
                ],
            ),
            MockStreamChunk(
                id="chunk_2",
                choices=[MockStreamChoice(index=0, delta=MockStreamDelta(), finish_reason="tool_calls")],
            ),
        ]

        guard = GuardBuilder().allow("safe_tool", query=Wildcard()).on_denial("skip").build()

        result_chunks = list(guard.guard_stream(iter(chunks)))

        for chunk in result_chunks:
            for choice in chunk.choices:
                delta = choice.delta
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        if tc.function:
                            assert tc.function.name != "unauthorized"

    def test_streaming_emits_allowed_tool_call(self):
        """Allowed tool calls should be emitted after verification."""
        chunks = [
            MockStreamChunk(
                id="chunk_0",
                choices=[
                    MockStreamChoice(
                        index=0,
                        delta=MockStreamDelta(
                            tool_calls=[
                                MockToolCallDelta(
                                    index=0,
                                    id="call_0",
                                    function=MockFunction(name="search", arguments='{"query": "ok"}'),
                                )
                            ]
                        ),
                        finish_reason=None,
                    )
                ],
            ),
            MockStreamChunk(
                id="chunk_1",
                choices=[MockStreamChoice(index=0, delta=MockStreamDelta(), finish_reason="tool_calls")],
            ),
        ]

        guard = GuardBuilder().allow("search", query=Pattern("ok*")).build()

        result_chunks = list(guard.guard_stream(iter(chunks)))
        assert len(result_chunks) == 2


# =============================================================================
# Tier 2: guard_tool / guard_tools (BoundWarrant + PoP)
# =============================================================================


class TestGuardToolTier2:
    """Tests for low-level guard_tool/guard_tools wrappers."""

    def test_guard_tool_allows_when_constraints_match(self):
        """Authorized tool call succeeds when constraints pass."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )
        bound = warrant.bind(key)

        guarded = guard_tool(search, bound, tool_name="search")
        assert guarded(query="ok-1") == "results:ok-1:0"

    def test_guard_tool_denies_when_constraints_fail(self):
        """Constraint violations raise AuthorizationDenied."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )
        bound = warrant.bind(key)

        guarded = guard_tool(search, bound, tool_name="search")
        with pytest.raises(AuthorizationDenied):
            guarded(query="nope")

    def test_guard_tool_denies_when_tool_not_in_warrant(self):
        """Tool not in warrant.tools raises ToolNotAuthorized."""
        key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["search"]).holder(key.public_key).mint(key)
        bound = warrant.bind(key)

        guarded = guard_tool(read_file, bound, tool_name="read_file")
        with pytest.raises(ToolNotAuthorized):
            guarded(path="/data/secret.txt")

    def test_guard_tools_wraps_list_and_dict(self):
        """guard_tools handles list and dict inputs."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )
        bound = warrant.bind(key)

        wrapped_list = guard_tools([search], bound)
        assert wrapped_list[0](query="ok") == "results:ok:0"

        wrapped_dict = guard_tools({"search": search}, bound)
        assert wrapped_dict["search"](query="ok") == "results:ok:0"


# =============================================================================
# Tier 2: Async Tools
# =============================================================================


class TestAsyncToolsTier2:
    """Async tool support for Tier 2 (BoundWarrant + PoP)."""

    @pytest.mark.asyncio
    async def test_async_tool_allows_with_pop(self):
        """Async tools should be awaited and authorized with PoP."""
        async def async_search(query: str) -> str:
            return f"async:{query}"

        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )
        bound = warrant.bind(key)

        guarded = guard_tool(async_search, bound, tool_name="search")
        assert await guarded(query="ok") == "async:ok"

    @pytest.mark.asyncio
    async def test_async_tool_denied_with_pop(self):
        """Async tools should raise on constraint violations."""
        async def async_search(query: str) -> str:
            return f"async:{query}"

        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )
        bound = warrant.bind(key)

        guarded = guard_tool(async_search, bound, tool_name="search")
        with pytest.raises(AuthorizationDenied):
            await guarded(query="nope")


# =============================================================================
# Tier 2: Tool Name Resolution
# =============================================================================


class TestToolNameResolutionTier2:
    """Tool name resolution rules for guard_tool."""

    def test_uses_tool_name_attribute(self):
        """tool.name should be used when tool_name not provided."""
        class NamedTool:
            name = "search"

            def __call__(self, query: str) -> str:
                return f"named:{query}"

        key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["search"]).holder(key.public_key).mint(key)
        bound = warrant.bind(key)

        guarded = guard_tool(NamedTool(), bound)
        assert guarded(query="ok") == "named:ok"

    def test_falls_back_to_class_name(self):
        """Class name should be used when no name or __name__ present."""
        class ClassNameTool:
            def __call__(self, query: str) -> str:
                return f"class:{query}"

        key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["ClassNameTool"]).holder(key.public_key).mint(key)
        bound = warrant.bind(key)

        guarded = guard_tool(ClassNameTool(), bound)
        assert guarded(query="ok") == "class:ok"

    def test_explicit_tool_name_overrides(self):
        """Explicit tool_name should override auto-resolution."""
        class NamedTool:
            name = "internal_name"

            def __call__(self, query: str) -> str:
                return f"override:{query}"

        key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["override"]).holder(key.public_key).mint(key)
        bound = warrant.bind(key)

        guarded = guard_tool(NamedTool(), bound, tool_name="override")
        assert guarded(query="ok") == "override:ok"


# =============================================================================
# Tier 2: GuardBuilder (Warrant + PoP)
# =============================================================================


class TestGuardBuilderTier2:
    """Tests for GuardBuilder with warrants (Tier 2)."""

    def test_tier2_allows_with_pop(self):
        """Authorized tool call succeeds with PoP."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )

        guard = GuardBuilder().with_warrant(warrant, key).build()
        guarded = guard.guard_tool(search, tool_name="search")

        assert guarded(query="ok") == "results:ok:0"

    def test_tier2_blocks_constraint_violation(self):
        """Constraint violations raise AuthorizationDenied in Tier 2."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )

        guard = GuardBuilder().with_warrant(warrant, key).build()
        guarded = guard.guard_tool(search, tool_name="search")

        with pytest.raises(AuthorizationDenied):
            guarded(query="nope")

    def test_tier2_on_denial_log_allows_execution(self, caplog):
        """on_denial=log should allow execution with PoP."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )

        guard = GuardBuilder().with_warrant(warrant, key).on_denial("log").build()
        guarded = guard.guard_tool(search, tool_name="search")

        with caplog.at_level(logging.WARNING):
            result = guarded(query="nope")

        assert result == "results:nope:0"
        assert "denied" in caplog.text.lower()

    def test_tier2_on_denial_skip_returns_none(self):
        """on_denial=skip should skip execution with PoP."""
        calls: list[str] = []

        def tracking_tool(query: str) -> str:
            calls.append(query)
            return f"results:{query}"

        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Pattern("ok*"))
            .holder(key.public_key)
            .mint(key)
        )

        guard = GuardBuilder().with_warrant(warrant, key).on_denial("skip").build()
        guarded = guard.guard_tool(tracking_tool, tool_name="search")

        assert guarded(query="nope") is None
        assert calls == []

    def test_warrant_requires_signing_key(self):
        """Missing signing_key should raise MissingSigningKey."""
        key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["search"]).holder(key.public_key).mint(key)

        with pytest.raises(MissingSigningKey):
            GuardBuilder().with_warrant(warrant, None).build()

    def test_signing_key_must_match_holder(self):
        """Signing key must match warrant holder."""
        key = SigningKey.generate()
        wrong_key = SigningKey.generate()
        warrant = Warrant.mint_builder().tools(["search"]).holder(key.public_key).mint(key)

        with pytest.raises(ConfigurationError):
            GuardBuilder().with_warrant(warrant, wrong_key).build()

    def test_expired_warrant_rejected(self):
        """Expired warrants should be rejected at build time."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("search", query=Wildcard())
            .holder(key.public_key)
            .ttl(1)
            .mint(key)
        )
        time.sleep(2)

        with pytest.raises(ExpiredError):
            GuardBuilder().with_warrant(warrant, key).build()


# =============================================================================
# Zero-config protect()
# =============================================================================


class TestProtect:
    """Tests for protect() convenience wrapper."""

    def test_protect_wraps_list(self):
        """protect() wraps list of tools."""
        guarded_list = protect([search], search=Pattern("ok*"))
        assert guarded_list[0](query="ok") == "results:ok:0"

    def test_protect_wraps_dict(self):
        """protect() wraps dict of tools."""
        guarded_dict = protect({"search": search}, search=Pattern("ok*"))
        assert guarded_dict["search"](query="ok") == "results:ok:0"

# =============================================================================
# Integration Invariants (from integration guide)
# =============================================================================


class TestIntegrationInvariants:
    """Invariant tests required by the integration guide."""

    def test_monotonic_attenuation(self):
        """Attenuation must only narrow authority."""
        root_key = SigningKey.generate()
        child_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("read", path=Wildcard())
            .capability("write", path=Wildcard())
            .holder(root_key.public_key)
            .mint(root_key)
        )

        child = (
            root.grant_builder()
            .capability("read", path=Pattern("/data/*"))
            .holder(child_key.public_key)
            .grant(root_key)
        )

        assert child.allows("read", {"path": "/data/file.txt"})
        assert not child.allows("read", {"path": "/etc/passwd"})
        assert not child.allows("write", {"path": "/data/file.txt"})

    def test_fail_closed_unknown(self):
        """Unknown arguments must be rejected."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("read", path=Pattern("/data/*"))
            .holder(key.public_key)
            .mint(key)
        )

        assert not warrant.allows("read", {"path": "/data/file.txt", "mode": "r"})
        assert warrant.allows("read", {"path": "/data/file.txt"})

    def test_expiry_enforced(self):
        """Expired warrants fail validation."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("read", path=Wildcard())
            .holder(key.public_key)
            .ttl(1)
            .mint(key)
        )
        time.sleep(2)

        bound = warrant.bind(key)
        result = bound.validate("read", {"path": "/data/file.txt"})
        assert not result

    def test_pop_required(self):
        """PoP requires signing key in Tier 2."""
        root_key = SigningKey.generate()
        agent_key = SigningKey.generate()

        warrant = (
            Warrant.mint_builder()
            .capability("read")
            .holder(agent_key.public_key)
            .mint(root_key)
        )

        with pytest.raises(MissingSigningKey):
            GuardBuilder().with_warrant(warrant, None).build()

    def test_tampered_warrant_rejected(self):
        """Tampered warrant should fail signature verification."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("read", path=Wildcard())
            .holder(key.public_key)
            .mint(key)
        )

        token = warrant.to_base64()
        tampered = bytearray(token.encode("utf-8"))
        tampered[10] ^= 0xFF

        with pytest.raises((SignatureInvalid, ValueError)):
            Warrant.from_base64(bytes(tampered).decode("utf-8"))

    def test_chain_validation(self):
        """Delegation chains must be valid from root to leaf."""
        root_key = SigningKey.generate()
        child_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("read", path=Wildcard())
            .holder(root_key.public_key)
            .mint(root_key)
        )

        child = (
            root.grant_builder()
            .capability("read", path=Pattern("/data/*"))
            .holder(child_key.public_key)
            .grant(root_key)
        )

        assert child.depth == 1
        assert child.allows("read", {"path": "/data/file.txt"})
        assert not child.allows("read", {"path": "/etc/passwd"})

