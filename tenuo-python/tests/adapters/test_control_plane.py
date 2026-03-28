"""
Tests for the control plane event streaming integration.

These tests verify:
  1. ControlPlaneClient / emit_for_enforcement Python-side logic (no real HTTP)
  2. MCPVerifier emits events on allow and deny
  3. TenuoMiddleware and TenuoToolNode emit events (LangGraph)
  4. Temporal _emit_allow_event / _emit_denial_event emit events and carry
     warrant_stack on both allow and deny paths
  5. TenuoGuard (Google ADK) emits events for Tier 2 (PoP) and Tier 1 paths

All tests use a mock ControlPlaneClient that captures emitted events in a list
so we can assert on fields without standing up a real control plane server.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from tenuo_core import Authorizer, SigningKey, Warrant

import tenuo.testing  # noqa: F401  — registers test helpers


# ---------------------------------------------------------------------------
# Shared mock
# ---------------------------------------------------------------------------


class MockControlPlane:
    """Drop-in replacement for ControlPlaneClient that records emitted events."""

    def __init__(self):
        self.allow_events: List[Dict[str, Any]] = []
        self.deny_events: List[Dict[str, Any]] = []

    def emit_for_enforcement(
        self,
        result: Any,
        chain_result: Any = None,
        *,
        latency_us: int = 0,
        request_id: Optional[str] = None,
        warrant_stack_override: Optional[str] = None,
    ) -> None:
        entry = {
            "result": result,
            "chain_result": chain_result,
            "latency_us": latency_us,
            "request_id": request_id,
            "warrant_stack_override": warrant_stack_override,
        }
        if getattr(result, "allowed", False):
            self.allow_events.append(entry)
        else:
            self.deny_events.append(entry)

    @property
    def total_events(self) -> int:
        return len(self.allow_events) + len(self.deny_events)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def simple_warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    from tenuo import Pattern

    return Warrant.issue(
        issuer_key,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=agent_key.public_key,
    )


@pytest.fixture
def mock_cp() -> MockControlPlane:
    return MockControlPlane()


# ---------------------------------------------------------------------------
# 1. emit_for_enforcement logic (control_plane.py)
# ---------------------------------------------------------------------------


class TestEmitForEnforcement:
    """Unit tests for ControlPlaneClient.emit_for_enforcement."""

    def _make_cp_wrapper(self, mock):
        """Wrap mock as a ControlPlaneClient that delegates to the mock."""
        from tenuo.control_plane import ControlPlaneClient
        wrapper = object.__new__(ControlPlaneClient)
        wrapper._inner = mock
        return wrapper

    def _make_fake_inner(self):
        """Minimal inner object that captures raw emit_allow / emit_deny calls."""
        @dataclass
        class FakeInner:
            allows: List = field(default_factory=list)
            denies: List = field(default_factory=list)

            def emit_allow(self, *args, **kwargs):
                self.allows.append(args)

            def emit_deny(self, *args, **kwargs):
                self.denies.append(args)

        return FakeInner()

    def test_allow_event_fields(self, simple_warrant, agent_key):
        """emit_for_enforcement with allowed=True calls emit_allow with correct fields."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        result = EnforcementResult(
            allowed=True,
            tool="read_file",
            arguments={"path": "/data/log.txt"},
            warrant_id="wid-123",
        )
        cp.emit_for_enforcement(result, latency_us=500, request_id="req-1")

        assert len(inner.allows) == 1
        args = inner.allows[0]
        assert args[0] == "wid-123"   # warrant_id
        assert args[1] == "read_file"  # tool
        assert args[6] == "req-1"      # request_id
        # arguments should be JSON
        assert json.loads(args[7]) == {"path": "/data/log.txt"}

    def test_deny_event_fields(self):
        """emit_for_enforcement with allowed=False calls emit_deny with reason."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        result = EnforcementResult(
            allowed=False,
            tool="delete",
            arguments={},
            denial_reason="Tool not in warrant",
            constraint_violated="tool_not_allowed",
            warrant_id="wid-456",
        )
        cp.emit_for_enforcement(result, latency_us=100)

        assert len(inner.denies) == 1
        args = inner.denies[0]
        assert args[0] == "wid-456"
        assert args[1] == "delete"
        assert "Tool not in warrant" in args[2]
        assert args[3] == "tool_not_allowed"

    def test_chain_result_overrides_defaults(self):
        """chain_result.leaf_depth and root_issuer are forwarded correctly."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        chain_result = MagicMock()
        chain_result.leaf_depth = 3
        chain_result.root_issuer = b"\xab\xcd" + b"\x00" * 30
        chain_result.warrant_stack_b64 = "base64encodedstack=="

        result = EnforcementResult(
            allowed=True, tool="search", arguments={}, warrant_id="w1",
        )
        cp.emit_for_enforcement(result, chain_result=chain_result)

        args = inner.allows[0]
        assert args[2] == 3            # chain_depth == leaf_depth
        assert args[3] is not None     # root_principal hex string
        assert args[4] == "base64encodedstack=="  # warrant_stack

    def test_warrant_stack_override_used_when_no_chain_result(self):
        """warrant_stack_override is used when chain_result is None."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        result = EnforcementResult(
            allowed=False, tool="op", arguments={}, denial_reason="expired", warrant_id="w2",
        )
        cp.emit_for_enforcement(
            result, warrant_stack_override="fallback-stack-b64"
        )

        args = inner.denies[0]
        assert args[6] == "fallback-stack-b64"  # warrant_stack position in emit_deny

    def test_chain_result_takes_precedence_over_override(self):
        """chain_result.warrant_stack_b64 wins over warrant_stack_override."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        chain_result = MagicMock()
        chain_result.leaf_depth = 1
        chain_result.root_issuer = None
        chain_result.warrant_stack_b64 = "from-chain-result"

        result = EnforcementResult(
            allowed=True, tool="op", arguments={}, warrant_id="w3",
        )
        cp.emit_for_enforcement(
            result, chain_result=chain_result,
            warrant_stack_override="should-be-ignored",
        )

        args = inner.allows[0]
        assert args[4] == "from-chain-result"

    def test_no_error_when_arguments_not_serializable(self):
        """Non-serializable arguments fall back to str() without raising."""
        from tenuo._enforcement import EnforcementResult
        from tenuo.control_plane import ControlPlaneClient

        inner = self._make_fake_inner()
        cp = object.__new__(ControlPlaneClient)
        cp._inner = inner

        class Unserializable:
            pass

        result = EnforcementResult(
            allowed=True, tool="op",
            arguments={"obj": Unserializable()},  # type: ignore
            warrant_id="w4",
        )
        cp.emit_for_enforcement(result)  # must not raise
        assert len(inner.allows) == 1


# ---------------------------------------------------------------------------
# 2. encode_warrant_stack (Rust function — requires rebuilt tenuo_core wheel)
# ---------------------------------------------------------------------------

try:
    from tenuo_core import encode_warrant_stack as _ews  # noqa: F401
    _ENCODE_WARRANT_STACK_AVAILABLE = True
except ImportError:
    _ENCODE_WARRANT_STACK_AVAILABLE = False

needs_encode_warrant_stack = pytest.mark.skipif(
    not _ENCODE_WARRANT_STACK_AVAILABLE,
    reason="encode_warrant_stack not in installed tenuo_core wheel — rebuild required",
)


class TestEncodeWarrantStack:
    @needs_encode_warrant_stack
    def test_single_warrant_roundtrip(self, simple_warrant):
        """encode_warrant_stack → decode_warrant_stack_base64 roundtrip."""
        from tenuo_core import decode_warrant_stack_base64, encode_warrant_stack

        encoded = encode_warrant_stack([simple_warrant])
        assert encoded is not None
        decoded = decode_warrant_stack_base64(encoded)
        assert len(decoded) == 1
        assert decoded[0].id == simple_warrant.id

    @needs_encode_warrant_stack
    def test_empty_list_returns_none(self):
        from tenuo_core import encode_warrant_stack

        result = encode_warrant_stack([])
        assert result is None

    @needs_encode_warrant_stack
    def test_chain_roundtrip(self, issuer_key, agent_key, simple_warrant):
        """encode_warrant_stack works for a 2-warrant chain."""
        from tenuo import Pattern
        from tenuo_core import decode_warrant_stack_base64, encode_warrant_stack

        sub_key = SigningKey.generate()
        child = simple_warrant.attenuate(
            capabilities={"read_file": {"path": Pattern("/data/sub/*")}},
            signing_key=agent_key,
            holder=sub_key.public_key,
        )
        encoded = encode_warrant_stack([simple_warrant, child])
        assert encoded is not None
        decoded = decode_warrant_stack_base64(encoded)
        assert len(decoded) == 2
        assert decoded[0].id == simple_warrant.id
        assert decoded[1].id == child.id


# ---------------------------------------------------------------------------
# 3. MCPVerifier control plane wiring
# ---------------------------------------------------------------------------


class TestMCPVerifierControlPlane:
    def _make_signed_meta(self, warrant: Warrant, agent_key: SigningKey, tool: str, args: dict):
        """Build a _meta dict with warrant + PoP signature."""
        import base64
        import time

        pop = warrant.sign(agent_key, tool, args, int(time.time()))
        return {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(bytes(pop)).decode(),
            }
        }

    def test_emit_allow_on_success(self, authorizer, simple_warrant, agent_key, mock_cp):
        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        meta = self._make_signed_meta(simple_warrant, agent_key, "read_file", {"path": "/data/a.txt"})

        result = verifier.verify("read_file", {"path": "/data/a.txt"}, meta=meta)

        assert result.allowed
        assert mock_cp.total_events == 1
        assert len(mock_cp.allow_events) == 1
        entry = mock_cp.allow_events[0]
        assert entry["result"].allowed is True
        assert entry["result"].tool == "read_file"
        assert entry["latency_us"] > 0

    def test_emit_deny_on_tool_not_authorized(self, authorizer, simple_warrant, agent_key, mock_cp):
        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        meta = self._make_signed_meta(simple_warrant, agent_key, "delete_file", {"path": "/data/a.txt"})

        result = verifier.verify("delete_file", {"path": "/data/a.txt"}, meta=meta)

        assert not result.allowed
        assert mock_cp.total_events == 1
        assert len(mock_cp.deny_events) == 1

    def test_no_emit_on_missing_warrant(self, authorizer, mock_cp):
        """No event is emitted when the warrant is absent — no warrant_id to report."""
        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        result = verifier.verify("read_file", {}, meta=None)

        assert not result.allowed
        # Early return before emit site — no event recorded (warrant_id is unknown)
        assert mock_cp.total_events == 0

    @needs_encode_warrant_stack
    def test_chain_result_attached_on_allow(self, authorizer, simple_warrant, agent_key, mock_cp):
        """chain_result (with warrant_stack_b64) is forwarded to emit_for_enforcement."""
        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        meta = self._make_signed_meta(simple_warrant, agent_key, "read_file", {"path": "/data/b.txt"})

        verifier.verify("read_file", {"path": "/data/b.txt"}, meta=meta)

        entry = mock_cp.allow_events[0]
        chain_result = entry["chain_result"]
        assert chain_result is not None
        assert chain_result.chain_length >= 1
        assert chain_result.warrant_stack_b64 is not None

    def test_no_error_when_control_plane_is_none(self, authorizer, simple_warrant, agent_key):
        """MCPVerifier works normally when no control_plane is provided."""
        from tenuo.mcp.server import MCPVerifier

        verifier = MCPVerifier(authorizer=authorizer)  # no control_plane
        meta = self._make_signed_meta(simple_warrant, agent_key, "read_file", {"path": "/data/c.txt"})
        result = verifier.verify("read_file", {"path": "/data/c.txt"}, meta=meta)
        assert result.allowed


# ---------------------------------------------------------------------------
# 4. LangGraph TenuoMiddleware + TenuoToolNode control plane wiring
# ---------------------------------------------------------------------------


class TestLangGraphControlPlane:
    @pytest.fixture
    def setup(self, issuer_key, agent_key):
        """Return state dict with warrant for LangGraph tests."""
        from tenuo.keys import KeyRegistry

        KeyRegistry.reset_instance()
        registry = KeyRegistry.get_instance()
        registry.register("default", agent_key)

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"search": {}, "read_file": {}},
            holder=agent_key.public_key,
        )
        return {"warrant": warrant, "messages": []}

    def test_middleware_stores_control_plane(self, mock_cp):
        """TenuoMiddleware stores the control_plane parameter correctly."""
        from tenuo.langgraph import TenuoMiddleware, MIDDLEWARE_AVAILABLE

        if not MIDDLEWARE_AVAILABLE:
            pytest.skip("LangChain middleware not available")

        mw = TenuoMiddleware(control_plane=mock_cp)
        assert mw._control_plane is mock_cp

    def test_middleware_control_plane_none_by_default(self):
        from tenuo.langgraph import TenuoMiddleware, MIDDLEWARE_AVAILABLE

        if not MIDDLEWARE_AVAILABLE:
            pytest.skip("LangChain middleware not available")

        mw = TenuoMiddleware()
        assert mw._control_plane is None

    def test_toolnode_emits_allow(self, setup, mock_cp, issuer_key):
        """TenuoToolNode emits allow event for authorized tool call."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not available")

        from typing import Any
        from langchain_core.tools import tool
        from langgraph.graph import StateGraph, END, START

        @tool
        def search(query: str) -> str:
            """Search the web."""
            return f"results for {query}"

        tool_node = TenuoToolNode([search], control_plane=mock_cp, trusted_roots=[issuer_key.public_key])

        state = dict(setup)
        state["messages"] = [
            AIMessage(
                content="",
                tool_calls=[{"id": "t1", "name": "search", "args": {"query": "AI"}}],
            )
        ]

        from tests.adapters.test_langgraph import MockState as _S  # noqa: F401  — reuse existing State

        builder = StateGraph(_S)
        builder.add_node("tools", tool_node)
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()
        graph.invoke(state)

        assert len(mock_cp.allow_events) == 1
        entry = mock_cp.allow_events[0]
        assert entry["result"].tool == "search"
        assert entry["latency_us"] >= 0

    def test_toolnode_emits_deny(self, setup, mock_cp):
        """TenuoToolNode emits deny event for unauthorized tool call."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not available")

        from langchain_core.tools import tool
        from langgraph.graph import StateGraph, END, START
        from tests.adapters.test_langgraph import MockState as _S

        @tool
        def admin_reset() -> str:
            """Reset the admin password."""
            return "reset"

        tool_node = TenuoToolNode([admin_reset], control_plane=mock_cp)

        state = dict(setup)
        state["messages"] = [
            AIMessage(
                content="",
                tool_calls=[{"id": "t2", "name": "admin_reset", "args": {}}],
            )
        ]

        builder = StateGraph(_S)
        builder.add_node("tools", tool_node)
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()
        graph.invoke(state)

        assert len(mock_cp.deny_events) == 1
        assert mock_cp.deny_events[0]["result"].tool == "admin_reset"

    @needs_encode_warrant_stack
    def test_toolnode_warrant_stack_not_none(self, setup, mock_cp, issuer_key):
        """Emitted allow event carries a non-None warrant_stack_override (single-warrant encoding)."""
        from langchain_core.messages import AIMessage
        from tenuo.langgraph import TenuoToolNode, LANGGRAPH_AVAILABLE

        if not LANGGRAPH_AVAILABLE:
            pytest.skip("LangGraph not available")

        from langchain_core.tools import tool
        from langgraph.graph import StateGraph, END, START
        from tests.adapters.test_langgraph import MockState as _S

        @tool
        def read_file(path: str) -> str:
            """Read a file."""
            return "content"

        tool_node = TenuoToolNode([read_file], control_plane=mock_cp, trusted_roots=[issuer_key.public_key])
        state = dict(setup)
        state["messages"] = [
            AIMessage(
                content="",
                tool_calls=[{"id": "t3", "name": "read_file", "args": {"path": "/data/x"}}],
            )
        ]

        builder = StateGraph(_S)
        builder.add_node("tools", tool_node)
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()
        graph.invoke(state)

        entry = mock_cp.allow_events[0]
        assert entry["warrant_stack_override"] is not None


# ---------------------------------------------------------------------------
# 5. Temporal _emit_allow / _emit_denial warrant_stack wiring
# ---------------------------------------------------------------------------


class TestTemporalControlPlane:
    @pytest.fixture
    def interceptor_config(self, mock_cp):
        """Build a minimal TenuoInterceptorConfig with the mock control plane."""
        from tenuo.temporal import TenuoInterceptorConfig
        from tenuo.temporal import EnvKeyResolver

        return TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(),
            control_plane=mock_cp,
        )

    @pytest.fixture
    def interceptor(self, interceptor_config):
        """Build a TenuoActivityInboundInterceptor with the config."""
        from tenuo.temporal import TenuoActivityInboundInterceptor

        # next_interceptor is not called in our tests (we call _emit_* directly)
        return TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(),
            config=interceptor_config,
            version="test",
        )

    @pytest.fixture
    def fake_info(self):
        info = MagicMock()
        info.workflow_id = "wf-1"
        info.workflow_type = "MyWorkflow"
        info.workflow_run_id = "run-1"
        info.activity_type = "my_activity"
        info.activity_id = "act-1"
        info.task_queue = "default"
        return info

    def test_emit_allow_calls_control_plane(
        self, interceptor, fake_info, simple_warrant, mock_cp
    ):
        interceptor._emit_allow_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
        )

        assert len(mock_cp.allow_events) == 1
        entry = mock_cp.allow_events[0]
        assert entry["result"].allowed is True
        assert entry["result"].tool == "my_activity"

    def test_emit_denial_calls_control_plane(
        self, interceptor, fake_info, simple_warrant, mock_cp
    ):
        interceptor._emit_denial_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
            reason="Constraint violated: path out of range",
            constraint="path",
        )

        assert len(mock_cp.deny_events) == 1
        entry = mock_cp.deny_events[0]
        assert entry["result"].allowed is False
        assert "Constraint violated" in entry["result"].denial_reason

    @needs_encode_warrant_stack
    def test_emit_denial_carries_warrant_stack(
        self, interceptor, fake_info, simple_warrant, mock_cp
    ):
        """Denial events carry a warrant_stack_override (single-warrant encoding)."""
        interceptor._emit_denial_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
            reason="expired",
        )

        entry = mock_cp.deny_events[0]
        assert entry["warrant_stack_override"] is not None

    def test_emit_allow_latency_measured(
        self, interceptor, fake_info, simple_warrant, mock_cp
    ):
        """latency_us is calculated when start_ns is provided."""
        import time

        start_ns = time.perf_counter_ns() - 5_000_000  # pretend 5ms elapsed
        interceptor._emit_allow_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
            start_ns=start_ns,
        )

        entry = mock_cp.allow_events[0]
        assert entry["latency_us"] >= 4000  # at least 4ms

    def test_no_emit_when_control_plane_none(
        self, fake_info, simple_warrant
    ):
        """No error when control_plane is not configured."""
        from tenuo.temporal import TenuoActivityInboundInterceptor, TenuoInterceptorConfig, EnvKeyResolver

        config = TenuoInterceptorConfig(key_resolver=EnvKeyResolver())
        interceptor = TenuoActivityInboundInterceptor(
            next_interceptor=MagicMock(), config=config, version="test"
        )
        # Must not raise
        interceptor._emit_allow_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
        )
        interceptor._emit_denial_event(
            info=fake_info,
            warrant=simple_warrant,
            tool="my_activity",
            args={},
            reason="denied",
        )


# ---------------------------------------------------------------------------
# 6. Google ADK TenuoGuard control plane wiring
# ---------------------------------------------------------------------------


class _MockBasePlugin:
    def __init__(self, *args, **kwargs):
        pass


class _MockBaseTool:
    def __init__(self, name: str):
        self.name = name


class _MockToolContext:
    def __init__(self, state=None):
        self.state = state or {}


def _make_adk_sys_modules_patch() -> dict:
    """Return a sys.modules overlay that stubs out google.adk without leaking."""
    mock_google = MagicMock()
    mock_google.adk.plugins.BasePlugin = _MockBasePlugin
    return {
        "google": mock_google,
        "google.adk": mock_google.adk,
        "google.adk.plugins": mock_google.adk.plugins,
        "google.adk.tools": mock_google.adk.tools,
        "google.adk.tools.tool_context": mock_google.adk.tools.tool_context,
        "google.adk.tools.base_tool": mock_google.adk.tools.base_tool,
        "google.adk.agents": mock_google.adk.agents,
        "google.adk.agents.callback_context": mock_google.adk.agents.callback_context,
    }


class TestADKControlPlane:
    """TenuoGuard emits allow/deny events to the control plane."""

    @pytest.fixture(autouse=True)
    def _patch_google_adk(self):
        """Patch google.adk for the duration of each ADK test, then restore.

        Using patch.dict ensures the original sys.modules state is restored after
        every test so other test modules (e.g. crewai tests) are not affected.
        """
        from unittest.mock import patch

        with patch.dict(sys.modules, _make_adk_sys_modules_patch(), clear=False):
            # Re-import guard module so it picks up the patched google.adk
            for mod_name in list(sys.modules):
                if mod_name.startswith("tenuo.google_adk"):
                    del sys.modules[mod_name]
            yield
            # Clean up the re-imported tenuo.google_adk modules after the test
            for mod_name in list(sys.modules):
                if mod_name.startswith("tenuo.google_adk"):
                    del sys.modules[mod_name]

    @pytest.fixture
    def adk_keys(self):
        return SigningKey.generate()

    @pytest.fixture
    def adk_warrant(self, adk_keys):
        from tenuo.constraints import Subpath

        return (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/data"))
            .holder(adk_keys.public_key)
            .ttl(3600)
            .mint(adk_keys)
        )

    def test_guard_stores_control_plane(self, mock_cp):
        """TenuoGuard stores the control_plane reference."""
        from tenuo.google_adk import TenuoGuard

        guard = TenuoGuard(control_plane=mock_cp, require_pop=False)
        assert guard._control_plane is mock_cp

    def test_builder_with_control_plane(self, mock_cp, adk_warrant, adk_keys):
        """GuardBuilder.with_control_plane() passes client through to TenuoGuard."""
        from tenuo.google_adk import GuardBuilder

        guard = (
            GuardBuilder()
            .with_warrant(adk_warrant, adk_keys)
            .with_control_plane(mock_cp)
            .build()
        )
        assert guard._control_plane is mock_cp

    def test_tier2_emits_allow(self, mock_cp, adk_warrant, adk_keys):
        """Tier 2 (PoP) allow path emits a control plane event."""
        from tenuo.google_adk import TenuoGuard

        guard = TenuoGuard(
            warrant=adk_warrant,
            signing_key=adk_keys,
            trusted_roots=[adk_keys.public_key],
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()

        result = guard.before_tool(tool, {"path": "/data/report.pdf"}, ctx)

        assert result is None  # allowed
        assert len(mock_cp.allow_events) == 1
        assert len(mock_cp.deny_events) == 0
        entry = mock_cp.allow_events[0]
        assert entry["result"].tool == "read_file"
        assert entry["latency_us"] >= 0

    def test_tier2_emits_deny_on_constraint_violation(self, mock_cp, adk_warrant, adk_keys):
        """Tier 2 (PoP) deny path emits a control plane event."""
        from tenuo.google_adk import TenuoGuard

        guard = TenuoGuard(
            warrant=adk_warrant,
            signing_key=adk_keys,
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()

        result = guard.before_tool(tool, {"path": "/etc/passwd"}, ctx)

        assert result is not None  # denied
        assert len(mock_cp.deny_events) == 1
        assert len(mock_cp.allow_events) == 0
        assert mock_cp.deny_events[0]["result"].tool == "read_file"

    def test_tier1_emits_allow(self, mock_cp):
        """Tier 1 (guardrails) allow path emits a control plane event."""
        from tenuo.google_adk import TenuoGuard
        from tenuo.constraints import Subpath

        guard = TenuoGuard(
            constraints={"read_file": {"path": Subpath("/data")}},
            require_pop=False,
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()

        result = guard.before_tool(tool, {"path": "/data/report.pdf"}, ctx)

        assert result is None  # allowed
        assert len(mock_cp.allow_events) == 1
        assert mock_cp.allow_events[0]["result"].tool == "read_file"

    def test_tier1_emits_deny_on_constraint_violation(self, mock_cp):
        """Tier 1 (guardrails) deny path emits a control plane event."""
        from tenuo.google_adk import TenuoGuard
        from tenuo.constraints import Subpath

        guard = TenuoGuard(
            constraints={"read_file": {"path": Subpath("/data")}},
            require_pop=False,
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()

        result = guard.before_tool(tool, {"path": "/etc/passwd"}, ctx)

        assert result is not None  # denied
        assert len(mock_cp.deny_events) == 1
        assert mock_cp.deny_events[0]["result"].tool == "read_file"

    def test_tier1_emits_deny_on_unknown_tool(self, mock_cp):
        """Tier 1 deny for a tool not in the allowlist emits an event."""
        from tenuo.google_adk import TenuoGuard
        from tenuo.constraints import Subpath

        guard = TenuoGuard(
            constraints={"read_file": {"path": Subpath("/data")}},
            require_pop=False,
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("delete_database")
        ctx = _MockToolContext()

        guard.before_tool(tool, {}, ctx)

        assert len(mock_cp.deny_events) == 1

    def test_no_emit_when_control_plane_none(self, adk_warrant, adk_keys):
        """No error when control_plane is not set."""
        from tenuo.google_adk import TenuoGuard

        guard = TenuoGuard(warrant=adk_warrant, signing_key=adk_keys)
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()
        # Must not raise
        guard.before_tool(tool, {"path": "/data/ok.pdf"}, ctx)

    @needs_encode_warrant_stack
    def test_tier2_allow_carries_warrant_stack(self, mock_cp, adk_warrant, adk_keys):
        """Tier 2 allow event carries a non-None warrant_stack_override."""
        from tenuo.google_adk import TenuoGuard

        guard = TenuoGuard(
            warrant=adk_warrant,
            signing_key=adk_keys,
            trusted_roots=[adk_keys.public_key],
            control_plane=mock_cp,
        )
        tool = _MockBaseTool("read_file")
        ctx = _MockToolContext()

        guard.before_tool(tool, {"path": "/data/report.pdf"}, ctx)

        entry = mock_cp.allow_events[0]
        assert entry["warrant_stack_override"] is not None
