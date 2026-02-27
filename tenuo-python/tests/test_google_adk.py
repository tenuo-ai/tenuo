"""Tests for Google ADK integration."""

import io
import json

# Mock google.adk classes since they might not be installed
# We need to do this BEFORE importing tenuo.google_adk because plugin.py imports from google.adk
import sys
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

mock_google = MagicMock()
sys.modules["google"] = mock_google
sys.modules["google.adk"] = mock_google.adk
sys.modules["google.adk.plugins"] = mock_google.adk.plugins
sys.modules["google.adk.tools"] = mock_google.adk.tools
sys.modules["google.adk.tools.tool_context"] = mock_google.adk.tools.tool_context
sys.modules["google.adk.tools.base_tool"] = mock_google.adk.tools.base_tool
sys.modules["google.adk.agents"] = mock_google.adk.agents
sys.modules["google.adk.agents.callback_context"] = mock_google.adk.agents.callback_context


class MockBasePlugin:
    """Concrete mock for BasePlugin to avoid MagicMock inheritance issues."""

    def __init__(self, *args, **kwargs):
        pass


# Ensure plugins module is a mock but BasePlugin is our class
mock_google.adk.plugins.BasePlugin = MockBasePlugin
sys.modules["google.adk.plugins"] = mock_google.adk.plugins


class MockBaseTool:
    def __init__(self, name: str):
        self.name = name

    def __call__(self, *args, **kwargs):
        pass


class MockToolContext:
    def __init__(self, state: Optional[Dict[str, Any]] = None):
        self.state = state or {}


# Import the code under test (after mocking google.adk)
from tenuo_core import Pattern, Range, SigningKey, Warrant  # noqa: E402

from tenuo.constraints import Subpath, UrlSafe  # noqa: E402
from tenuo.google_adk import MissingSigningKeyError, TenuoGuard, ToolAuthorizationError  # noqa: E402


@pytest.fixture
def keys():
    return SigningKey.generate()


@pytest.fixture
def warrant(keys):
    """Create a warrant using the current API."""
    return (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/tmp/safe"))
        .capability("web_search", url=UrlSafe(allow_domains=["example.com"]))
        .holder(keys.public_key)
        .ttl(3600)
        .mint(keys)
    )


class TestToolFiltering:
    """Test tool filtering based on warrant grants."""

    def test_filter_tools_basic(self, warrant, keys):
        """Test that unauthorized tools are filtered out."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={
                "read_file_tool": "read_file",
                "search_tool": "web_search",
                "shell_tool": "exec_shell",  # Not in warrant
            },
        )

        tools = [
            MockBaseTool("read_file_tool"),
            MockBaseTool("search_tool"),
            MockBaseTool("shell_tool"),
            MockBaseTool("unknown_tool"),
        ]

        filtered = guard.filter_tools(tools)
        names = [t.name for t in filtered]

        assert "read_file_tool" in names
        assert "search_tool" in names
        assert "shell_tool" not in names
        assert "unknown_tool" not in names
        assert len(filtered) == 2

    def test_filter_tools_no_warrant(self, keys):
        """Test that no warrant returns empty list."""
        guard = TenuoGuard(signing_key=keys)
        tools = [MockBaseTool("read_file_tool")]
        assert guard.filter_tools(tools) == []


class TestTier2Authorization:
    """Test Tier 2 (PoP) authorization."""

    def test_before_tool_allowed_with_pop(self, warrant, keys):
        """Test authorized tool execution with PoP."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        # Valid call with PoP
        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/tmp/safe/doc.txt"},
            tool_context=context,
        )
        assert result is None  # None means allow

    def test_before_tool_denied_constraint(self, warrant, keys):
        """Test execution denied for constraint violation."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        # Invalid path - should be denied
        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/etc/passwd"},
            tool_context=context,
        )

        assert result is not None
        assert result["error"] == "authorization_denied"
        # PoP authorization uses authorize() which checks constraints

    def test_before_tool_denied_skill(self, warrant, keys):
        """Test execution denied for unauthorized skill."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
        )

        tool = MockBaseTool("shell_tool")  # Not in warrant
        context = MockToolContext()

        result = guard.before_tool(
            tool=tool,
            args={"cmd": "ls"},
            tool_context=context,
        )

        assert result is not None
        assert result["error"] == "authorization_denied"

    def test_missing_signing_key_raises(self, warrant):
        """Test that missing signing key raises error with PoP enabled."""
        guard = TenuoGuard(
            warrant=warrant,
            # No signing_key - should raise
            require_pop=True,
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        with pytest.raises(MissingSigningKeyError):
            guard.before_tool(tool, {"path": "/tmp/safe/x"}, context)


class TestTier1Authorization:
    """Test Tier 1 (guardrails-only) authorization."""

    def test_tier1_allowed(self, warrant, keys):
        """Test Tier 1 authorized tool execution (no PoP)."""
        guard = TenuoGuard(
            warrant=warrant,
            require_pop=False,  # Tier 1 mode
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/tmp/safe/doc.txt"},
            tool_context=context,
        )
        assert result is None

    def test_tier1_denied_constraint(self, warrant):
        """Test Tier 1 constraint violation denial."""
        guard = TenuoGuard(
            warrant=warrant,
            require_pop=False,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/etc/passwd"},
            tool_context=context,
        )

        assert result is not None
        assert result["error"] == "authorization_denied"
        assert "violates constraint" in result["message"]


class TestZeroTrust:
    """Test zero-trust argument enforcement."""

    def test_unknown_argument_rejected(self):
        """Test that unknown arguments are rejected in zero-trust mode."""
        # Create a mock warrant with specific constraints
        mock_warrant = MagicMock()
        mock_warrant.tools = ["read_file"]
        mock_warrant.capabilities = {"read_file": {"path": Subpath("/data")}}
        mock_warrant.is_expired = MagicMock(return_value=False)

        guard = TenuoGuard(
            warrant=mock_warrant,
            require_pop=False,
        )

        tool = MockBaseTool("read_file")
        context = MockToolContext()

        # Try to call with extra unknown argument
        result = guard.before_tool(
            tool=tool,
            args={"path": "/data/file.txt", "mode": "rw"},  # "mode" not in constraints
            tool_context=context,
        )

        assert result is not None
        assert result["error"] == "authorization_denied"
        assert "Unknown argument" in result["message"]

    def test_wildcard_allows_unknown_args(self):
        """Test that Wildcard constraint allows any value."""
        from tenuo_core import Wildcard

        mock_warrant = MagicMock()
        mock_warrant.tools = ["api_call"]
        mock_warrant.capabilities = {
            "api_call": {
                "url": UrlSafe(allow_domains=["api.example.com"]),
                "timeout": Wildcard(),  # Allows any value
            }
        }
        mock_warrant.is_expired = MagicMock(return_value=False)

        guard = TenuoGuard(
            warrant=mock_warrant,
            require_pop=False,
        )

        tool = MockBaseTool("api_call")
        context = MockToolContext()

        # Wildcard allows the timeout argument with any value
        result = guard.before_tool(
            tool=tool,
            args={"url": "https://api.example.com/v1", "timeout": 9999},
            tool_context=context,
        )
        assert result is None  # Should be allowed with Wildcard timeout


class TestDynamicWarrants:
    """Test dynamic warrant retrieval from session state."""

    def test_warrant_from_state(self, warrant, keys):
        """Test warrant retrieval from session state."""
        guard = TenuoGuard(
            warrant_key="user_warrant",
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )
        tool = MockBaseTool("read_file_tool")
        context = MockToolContext(state={"user_warrant": warrant})

        # Should succeed with warrant from state
        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/tmp/safe/doc.txt"},
            tool_context=context,
        )
        assert result is None

    def test_missing_warrant(self, keys):
        """Test behavior when no warrant is available."""
        guard = TenuoGuard(
            warrant_key="missing",
            signing_key=keys,
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext(state={})

        result = guard.before_tool(tool, {}, context)

        assert result is not None
        assert "No warrant" in result["message"] or "constraints" in result["message"]


class TestAuditLogging:
    """Test audit logging functionality."""

    def test_audit_logging(self, warrant, keys):
        """Test that actions are logged to audit file."""
        log_file = io.StringIO()
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
            audit_log=log_file,
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        # Action 1: Allowed
        guard.before_tool(tool, {"file_path": "/tmp/safe/a"}, context)

        # Action 2: Completed
        guard.after_tool(tool, {"file_path": "/tmp/safe/a"}, context, "result")

        logs = log_file.getvalue().strip().split("\n")
        assert len(logs) == 2

        log1 = json.loads(logs[0])
        assert log1["event"] == "tool_allowed"
        assert log1["tool"] == "read_file_tool"

        log2 = json.loads(logs[1])
        assert log2["event"] == "tool_completed"


class TestOnDenyRaise:
    """Test exception raising on denial."""

    def test_on_deny_raise(self, warrant, keys):
        """Test that exception is raised with correct details when on_deny='raise'."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            on_deny="raise",
        )

        tool = MockBaseTool("shell_tool")
        context = MockToolContext()

        with pytest.raises(ToolAuthorizationError) as excinfo:
            guard.before_tool(tool, {"cmd": "ls"}, context)

        assert excinfo.value.tool_name == "shell_tool"
        assert excinfo.value.tool_args == {"cmd": "ls"}


class TestArgumentRemapping:
    """Test argument remapping functionality."""

    def test_argument_remapping(self, keys):
        """Test that arguments are remapped correctly for authorization.

        When arg_map maps 'file_path' -> 'path', the guard should:
        1. Remap the incoming args before authorization
        2. Authorize against the warrant's constraint using the remapped key
        3. Allow the call if the remapped value satisfies the constraint
        """
        # Create a real warrant with capability for read_file
        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/tmp/safe"))
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},  # Map file_path -> path
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        # Call with original arg name 'file_path', should be remapped to 'path'
        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/tmp/safe/1.txt"},
            tool_context=context,
        )

        # Should be allowed (None = no denial)
        assert result is None, f"Expected authorization to succeed, got: {result}"

    def test_argument_remapping_denied(self, keys):
        """Test that remapped arguments are properly checked against constraints."""
        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/tmp/safe"))
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        # Call with path outside allowed root - should be denied
        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/etc/passwd"},
            tool_context=context,
        )

        # Should be denied
        assert result is not None, "Expected authorization to fail"
        assert "error" in result or "denied" in str(result).lower()


# --- Plugin Tests ---

from tenuo.google_adk import ScopedWarrant, TenuoPlugin  # noqa: E402


class MockCallbackContext:
    def __init__(self, agent_name: str, state: Dict[str, Any]):
        self.agent_name = agent_name
        self.state = state


class TestScopedWarrant:
    """Test ScopedWarrant for multi-agent safety."""

    def test_scoped_warrant_valid(self, warrant, keys):
        """Test ScopedWarrant allows matching agent."""
        plugin = TenuoPlugin(
            warrant_key="warrant",
            signing_key=keys,
        )

        # Warrant intended for 'researcher'
        scoped = ScopedWarrant(warrant, "researcher")
        state = {"warrant": scoped}

        # Case 1: Matching agent accesses warrant
        ctx_researcher = MockCallbackContext("researcher", state.copy())
        plugin.before_agent_callback(ctx_researcher)
        assert "warrant" in ctx_researcher.state

    def test_scoped_warrant_invalid(self, warrant, keys):
        """Test ScopedWarrant rejects different agent."""
        plugin = TenuoPlugin(
            warrant_key="warrant",
            signing_key=keys,
        )

        # Warrant intended for 'researcher'
        scoped = ScopedWarrant(warrant, "researcher")
        state = {"warrant": scoped}

        # Case 2: Different agent tries to access leaked warrant
        ctx_writer = MockCallbackContext("writer", state.copy())
        plugin.before_agent_callback(ctx_writer)
        assert "warrant" not in ctx_writer.state


class TestPluginExpiryCleanup:
    """Test plugin warrant expiry cleanup."""

    def test_expired_warrant_cleanup(self, keys):
        """Test that expired warrants are removed from state."""
        plugin = TenuoPlugin(
            warrant_key="warrant",
            signing_key=keys,
        )

        # Mock an expired warrant
        mock_warrant = MagicMock()
        mock_warrant.is_expired = MagicMock(return_value=True)

        state = {"warrant": mock_warrant}
        ctx = MockCallbackContext("agent", state)

        plugin.before_agent_callback(ctx)

        assert "warrant" not in state


class TestFailClosedUnknownConstraint:
    """Test fail-closed behavior on unknown constraints."""

    def test_unknown_constraint_fail_closed(self):
        """Test failing closed on unknown constraint types."""
        mock_warrant = MagicMock()

        class UnknownConstraint:
            """A constraint type we don't recognize."""

            pass

        mock_warrant.tools = ["weird_skill"]
        mock_warrant.capabilities = {"weird_skill": {"param": UnknownConstraint()}}
        mock_warrant.is_expired = MagicMock(return_value=False)

        guard = TenuoGuard(
            warrant=mock_warrant,
            require_pop=False,
        )

        result = guard.before_tool(
            MockBaseTool("weird_skill"),
            {"param": "val"},
            MockToolContext(),
        )

        # Should be denied because unknown constraint fails closed
        assert result is not None
        assert "violates constraint" in result["message"]


# =============================================================================
# DX Features Tests
# =============================================================================

from tenuo.google_adk import (  # noqa: E402
    GuardBuilder,
    chain_callbacks,
    explain_denial,
    generate_hints,
    scoped_warrant,
    suggest_skill_mapping,
    visualize_warrant,
)


class TestGuardBuilder:
    """Test GuardBuilder fluent API."""

    def test_builder_basic(self, warrant, keys):
        """Test basic builder usage."""
        guard = (
            GuardBuilder()
            .with_warrant(warrant, keys)
            .map_skill("read_file_tool", "read_file", path="file_path")
            .build()
        )

        assert guard._warrant is warrant
        assert guard._signing_key is keys
        assert guard._skill_map == {"read_file_tool": "read_file"}
        assert guard._arg_map == {"read_file": {"file_path": "path"}}

    def test_builder_tier1(self, warrant):
        """Test Tier 1 mode via builder."""
        guard = GuardBuilder().with_warrant(warrant).tier1().build()

        assert guard._require_pop is False

    def test_builder_dry_run(self, warrant, keys):
        """Test dry run mode via builder."""
        guard = GuardBuilder().with_warrant(warrant, keys).dry_run().build()

        assert guard._dry_run is True

    def test_builder_missing_key_raises(self, warrant):
        """Test that builder raises if PoP required but no key."""
        with pytest.raises(MissingSigningKeyError):
            GuardBuilder().with_warrant(warrant).build()

    def test_builder_on_denial(self, warrant, keys):
        """Test on_denial configuration."""
        guard = GuardBuilder().with_warrant(warrant, keys).on_denial("raise").build()

        assert guard._on_deny == "raise"


class TestDryRunMode:
    """Test dry run functionality."""

    def test_dry_run_logs_but_allows(self, warrant, keys):
        """Test that dry run mode logs denials but doesn't block."""
        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            dry_run=True,
        )

        tool = MockBaseTool("shell_tool")  # Not in warrant
        context = MockToolContext()

        # Should return None (allow) even though it would normally deny
        result = guard.before_tool(tool, {"cmd": "ls"}, context)
        assert result is None  # Allowed through in dry run


class TestHints:
    """Test recovery hints in denials."""

    def test_hints_included_in_denial(self, warrant):
        """Test that hints are included in denial responses."""
        guard = TenuoGuard(
            warrant=warrant,
            require_pop=False,
            include_hints=True,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/etc/passwd"},
            tool_context=context,
        )

        assert result is not None
        assert "hints" in result
        assert len(result["hints"]) > 0

    def test_hints_disabled(self, warrant):
        """Test that hints can be disabled."""
        guard = TenuoGuard(
            warrant=warrant,
            require_pop=False,
            include_hints=False,
            skill_map={"read_file_tool": "read_file"},
            arg_map={"read_file": {"file_path": "path"}},
        )

        tool = MockBaseTool("read_file_tool")
        context = MockToolContext()

        result = guard.before_tool(
            tool=tool,
            args={"file_path": "/etc/passwd"},
            tool_context=context,
        )

        assert result is not None
        assert "hints" not in result


class TestChainCallbacks:
    """Test callback chaining utility."""

    def test_chain_all_pass(self):
        """Test chaining when all callbacks pass."""
        cb1 = MagicMock(return_value=None)
        cb2 = MagicMock(return_value=None)

        chained = chain_callbacks(cb1, cb2)
        result = chained("tool", {}, "ctx")

        assert result is None
        cb1.assert_called_once()
        cb2.assert_called_once()

    def test_chain_first_denies(self):
        """Test chaining short-circuits on first denial."""
        denial = {"error": "denied"}
        cb1 = MagicMock(return_value=denial)
        cb2 = MagicMock(return_value=None)

        chained = chain_callbacks(cb1, cb2)
        result = chained("tool", {}, "ctx")

        assert result == denial
        cb1.assert_called_once()
        cb2.assert_not_called()  # Second callback not called


class TestExplainDenial:
    """Test denial explanation helper."""

    def test_explain_outputs_to_file(self):
        """Test that explain_denial writes to the given file."""
        output = io.StringIO()
        denial = {
            "error": "authorization_denied",
            "message": "Path not allowed",
            "details": "Path must be under /data",
            "hints": ["Try /data/file.txt"],
        }

        explain_denial(denial, file=output, color=False)

        content = output.getvalue()
        assert "Authorization Denied" in content
        assert "Path not allowed" in content
        assert "Suggestions" in content


class TestVisualizeWarrant:
    """Test warrant visualization."""

    def test_visualize_basic(self, warrant):
        """Test basic warrant visualization."""
        output = io.StringIO()
        visualize_warrant(warrant, file=output)

        content = output.getvalue()
        assert "Warrant" in content
        assert "Skills" in content


class TestSuggestSkillMapping:
    """Test skill mapping suggestions."""

    def test_suggest_exact_match(self, warrant):
        """Test that exact matches are suggested."""

        def read_file():
            pass

        def web_search():
            pass

        suggestions = suggest_skill_mapping(
            [read_file, web_search],
            warrant,
            verbose=False,
        )

        assert "read_file" in suggestions
        assert "web_search" in suggestions

    def test_suggest_with_suffix(self, warrant):
        """Test that _tool suffix is stripped for matching."""

        def read_file_tool():
            pass

        suggestions = suggest_skill_mapping(
            [read_file_tool],
            warrant,
            verbose=False,
        )

        assert "read_file_tool" in suggestions
        assert suggestions["read_file_tool"] == "read_file"


class TestScopedWarrantContext:
    """Test scoped warrant context manager."""

    def test_scoped_warrant_cleanup(self, warrant):
        """Test that scoped warrant is cleaned up."""
        state = {}

        with scoped_warrant(state, warrant, key="test_warrant"):
            assert "test_warrant" in state
            assert state["test_warrant"] is warrant

        assert "test_warrant" not in state

    def test_scoped_warrant_with_agent_name(self, warrant):
        """Test scoped warrant with agent binding."""
        from tenuo.google_adk import ScopedWarrant

        state = {}

        with scoped_warrant(state, warrant, key="test", agent_name="researcher"):
            assert "test" in state
            assert isinstance(state["test"], ScopedWarrant)
            assert state["test"].valid_for_agent("researcher")
            assert not state["test"].valid_for_agent("writer")

        assert "test" not in state


class TestGenerateHints:
    """Test hint generation."""

    def test_hints_for_subpath(self):
        """Test hints for Subpath constraint."""
        hints = generate_hints(
            tool_name="read_file",
            args={"path": "/etc/passwd"},
            constraint_param="path",
            constraint=Subpath("/data"),
        )

        assert len(hints) > 0
        assert any("/data" in hint for hint in hints)

    def test_hints_for_urlsafe(self):
        """Test hints for UrlSafe constraint."""
        hints = generate_hints(
            tool_name="fetch",
            args={"url": "http://evil.com"},
            constraint_param="url",
            constraint=UrlSafe(allow_domains=["api.example.com"]),
        )

        assert len(hints) > 0
        assert any("api.example.com" in hint for hint in hints)


# =============================================================================
# Direct Constraints Tests (Tier 1 without warrant)
# =============================================================================


class TestDirectConstraints:
    """Test Tier 1 with direct constraints (no warrant)."""

    def test_allow_with_constraints(self):
        """Test allowing tools with direct constraints."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).allow("search", query=Pattern("*")).build()

        # Allowed: read_file with valid path
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/report.txt"},
            MockToolContext(),
        )
        assert result is None  # Allowed

        # Denied: read_file with invalid path
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/etc/passwd"},
            MockToolContext(),
        )
        assert result is not None
        assert "violates constraint" in result["message"]

    def test_allow_without_constraints(self):
        """Test allowing tools without constraints (allow any args)."""
        guard = (
            GuardBuilder()
            .allow("shell")  # No constraints = allow any args
            .build()
        )

        # Allowed: shell with any args
        result = guard.before_tool(
            MockBaseTool("shell"),
            {"cmd": "rm -rf /"},
            MockToolContext(),
        )
        assert result is None  # Allowed (no constraints)

    def test_ungranted_tool_denied_by_default(self):
        """Test that tools not explicitly granted are denied (Tenuo philosophy)."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # Denied: shell is not in allowlist (explicit grants only)
        result = guard.before_tool(
            MockBaseTool("shell"),
            {"cmd": "ls"},
            MockToolContext(),
        )
        assert result is not None
        assert "not in allowlist" in result["message"]

    def test_filter_tools_with_direct_constraints(self):
        """Test filter_tools works with direct constraints."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).allow("search").build()

        tools = [
            MockBaseTool("read_file"),
            MockBaseTool("search"),
            MockBaseTool("shell"),
            MockBaseTool("unknown"),
        ]

        filtered = guard.filter_tools(tools)

        # Should include only explicitly granted: read_file and search
        # shell and unknown are excluded (not in allowlist)
        assert len(filtered) == 2
        assert any(t.name == "read_file" for t in filtered)
        assert any(t.name == "search" for t in filtered)

    def test_unknown_tool_denied(self):
        """Test that tools not in allowlist are denied."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("shell"),  # Not in allowlist
            {"cmd": "ls"},
            MockToolContext(),
        )
        assert result is not None
        assert "not in allowlist" in result["message"]

    def test_zero_trust_unknown_args(self):
        """Test zero-trust rejects unknown arguments."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt", "unknown_arg": "value"},
            MockToolContext(),
        )
        assert result is not None
        assert "not in constraints" in result["message"]

    def test_multiple_constraints(self):
        """Test tool with multiple parameter constraints."""
        guard = (
            GuardBuilder()
            .allow(
                "fetch_url",
                url=UrlSafe(allow_domains=["api.example.com"]),
                timeout=Range(1, 60),
            )
            .build()
        )

        # Allowed: valid URL and timeout
        result = guard.before_tool(
            MockBaseTool("fetch_url"),
            {"url": "https://api.example.com/v1", "timeout": 30},
            MockToolContext(),
        )
        assert result is None

        # Denied: invalid URL
        result = guard.before_tool(
            MockBaseTool("fetch_url"),
            {"url": "https://evil.com/", "timeout": 30},
            MockToolContext(),
        )
        assert result is not None


class TestBuilderDocumentation:
    """Test that builder usage examples work."""

    def test_tier1_example_from_docstring(self):
        """Test the Tier 1 example from GuardBuilder docstring."""
        guard = (
            GuardBuilder()
            .allow("read_file", path=Subpath("/data"))
            .allow("web_search", url=UrlSafe(allow_domains=["example.com"]))
            .build()
        )

        # Should have correct internal state
        assert guard._require_pop is False  # Auto-set for direct constraints
        assert "read_file" in guard._constraints
        assert "web_search" in guard._constraints
        # Note: "shell" is denied by default (not in allowlist) - no denylist needed


class TestAllowUnknown:
    """Test _allow_unknown opt-out for Zero Trust."""

    def test_allow_unknown_permits_extra_args(self):
        """Test _allow_unknown=True allows unconstrained arguments."""
        guard = (
            GuardBuilder()
            .allow("api_call", url=UrlSafe(allow_domains=["api.example.com"]), _allow_unknown=True)
            .build()
        )

        # Extra args should be allowed with _allow_unknown=True
        result = guard.before_tool(
            MockBaseTool("api_call"),
            {"url": "https://api.example.com/v1", "timeout": 30, "headers": {"X-Custom": "value"}},
            MockToolContext(),
        )
        assert result is None  # Allowed

    def test_without_allow_unknown_rejects_extra_args(self):
        """Test that without _allow_unknown, extra args are rejected (Zero Trust default)."""
        guard = GuardBuilder().allow("api_call", url=UrlSafe(allow_domains=["api.example.com"])).build()

        # Extra args should be rejected (Zero Trust)
        result = guard.before_tool(
            MockBaseTool("api_call"),
            {"url": "https://api.example.com/v1", "timeout": 30},
            MockToolContext(),
        )
        assert result is not None
        assert "not in constraints" in result["message"]


# =============================================================================
# Invariant Tests - Security Properties That Must ALWAYS Hold
# =============================================================================


class TestInvariantExpiryEnforcement:
    """Invariant: Expired warrants MUST be rejected."""

    def test_expired_warrant_denied_in_before_tool(self, keys):
        """Test that expired warrants are rejected in before_tool."""
        mock_warrant = MagicMock()
        mock_warrant.is_expired = MagicMock(return_value=True)
        mock_warrant.tools = ["read_file"]
        mock_warrant.capabilities = {"read_file": {"path": Subpath("/data")}}

        guard = TenuoGuard(warrant=mock_warrant, require_pop=False)

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )

        assert result is not None
        assert "expired" in result["message"].lower()

    def test_expired_warrant_with_valid_args_still_denied(self, keys):
        """Expiry check MUST happen before constraint checks."""
        mock_warrant = MagicMock()
        mock_warrant.is_expired = MagicMock(return_value=True)
        mock_warrant.tools = ["read_file"]
        mock_warrant.capabilities = {"read_file": {}}  # No constraints

        guard = TenuoGuard(warrant=mock_warrant, require_pop=False)

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {},
            MockToolContext(),
        )

        assert result is not None
        assert "expired" in result["message"].lower()


class TestInvariantSubpathTraversal:
    """Invariant: Subpath MUST block all path traversal attacks."""

    def test_dotdot_traversal_blocked(self):
        """../../../etc/passwd MUST be blocked."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/../../../etc/passwd"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_encoded_dotdot_is_literal_string(self):
        """URL-encoded ..%2f is treated as literal characters (not decoded).

        NOTE: Subpath operates on the STRING it receives. URL decoding
        is the responsibility of the HTTP layer BEFORE the value reaches
        the constraint. The literal string "/data/..%2f" does NOT traverse
        because %2f is not a path separator - it's literal characters.

        If the HTTP layer decodes it to "../" THEN Subpath will block it.
        """
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # The literal string "/data/..%2f..%2fetc/passwd" is allowed because
        # %2f is NOT a path separator - it's literal characters
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/..%2f..%2fetc/passwd"},
            MockToolContext(),
        )

        # This is ALLOWED because "%2f" is literal, not "/"
        # The constraint sees: /data/..%2f..%2fetc/passwd (no traversal)
        assert result is None  # Not a security issue - no actual traversal

        # But if it were decoded first, it would be blocked:
        result_decoded = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/../../etc/passwd"},  # Decoded version
            MockToolContext(),
        )
        assert result_decoded is not None
        assert "violates constraint" in result_decoded["message"]

    def test_null_byte_injection_blocked(self):
        """Null byte injection MUST be blocked."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt\x00../etc/passwd"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_absolute_path_outside_root_blocked(self):
        """Absolute paths outside root MUST be blocked."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/etc/passwd"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]


class TestInvariantUrlSafeSSRF:
    """Invariant: UrlSafe MUST block all SSRF attacks."""

    def test_private_ip_blocked(self):
        """Private IPs MUST be blocked."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "http://192.168.1.1/"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_localhost_blocked(self):
        """Localhost MUST be blocked."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "http://localhost/admin"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_decimal_ip_blocked(self):
        """Decimal IP encoding (2130706433 = 127.0.0.1) MUST be blocked."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "http://2130706433/"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_aws_metadata_blocked(self):
        """AWS metadata endpoint MUST be blocked."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "http://169.254.169.254/latest/meta-data/"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_unlisted_domain_blocked(self):
        """Domains not in allowlist MUST be blocked."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "https://evil.com/"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]


class TestInvariantRangeBounds:
    """Invariant: Range MUST enforce numeric bounds strictly."""

    def test_below_min_rejected(self):
        """Values below min MUST be rejected."""
        guard = GuardBuilder().allow("scale", replicas=Range(1, 10)).build()

        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": 0},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_above_max_rejected(self):
        """Values above max MUST be rejected."""
        guard = GuardBuilder().allow("scale", replicas=Range(1, 10)).build()

        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": 100},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_non_numeric_rejected(self):
        """Non-numeric values MUST be rejected."""
        guard = GuardBuilder().allow("scale", replicas=Range(1, 10)).build()

        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": "five"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_boundary_values_allowed(self):
        """Exact boundary values MUST be allowed."""
        guard = GuardBuilder().allow("scale", replicas=Range(1, 10)).build()

        # Min boundary
        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": 1},
            MockToolContext(),
        )
        assert result is None

        # Max boundary
        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": 10},
            MockToolContext(),
        )
        assert result is None


class TestInvariantTypeCoercion:
    """Invariant: Type coercion attacks MUST NOT bypass constraints."""

    def test_string_number_coercion_safe(self):
        """String "5" should be coerced safely for Range."""
        guard = GuardBuilder().allow("scale", replicas=Range(1, 10)).build()

        result = guard.before_tool(
            MockBaseTool("scale"),
            {"replicas": "5"},
            MockToolContext(),
        )
        assert result is None  # Should be allowed (coerces to 5.0)

    def test_array_value_rejected(self):
        """Array values MUST be rejected for scalar constraints."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": ["/data/file.txt", "/etc/passwd"]},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_dict_value_rejected(self):
        """Dict values MUST be rejected for scalar constraints."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": {"file": "/etc/passwd"}},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]


class TestInvariantPoPBypass:
    """Invariant: PoP MUST NOT be bypassable."""

    def test_pop_required_when_configured(self, warrant, keys):
        """When require_pop=True, missing signing_key MUST raise."""
        with pytest.raises(MissingSigningKeyError):
            guard = TenuoGuard(warrant=warrant, require_pop=True)
            guard.before_tool(
                MockBaseTool("read_file"),
                {"path": "/tmp/safe/file.txt"},
                MockToolContext(),
            )

    def test_tier1_explicit_opt_in(self, warrant):
        """Tier 1 MUST be explicitly opted into."""
        # Default is require_pop=True
        guard = TenuoGuard(warrant=warrant)
        assert guard._require_pop is True

    def test_tier2_uses_authorize_not_allows(self, warrant, keys):
        """Tier 2 MUST use authorize() (with PoP), not allows() (debug)."""
        guard = TenuoGuard(warrant=warrant, signing_key=keys, require_pop=True)

        # The warrant.authorize should be called (with signature), not .allows
        # We verify this by checking the code path works
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/tmp/safe/file.txt"},
            MockToolContext(),
        )

        assert result is None  # Should be allowed


class TestInvariantNoImplicitPermissions:
    """Invariant: Nothing is allowed unless explicitly granted."""

    def test_empty_warrant_denies_all(self):
        """Warrant with no capabilities MUST deny all tools."""
        mock_warrant = MagicMock()
        mock_warrant.is_expired = MagicMock(return_value=False)
        mock_warrant.tools = []
        mock_warrant.capabilities = {}
        mock_warrant.grants = []

        guard = TenuoGuard(warrant=mock_warrant, require_pop=False)

        result = guard.before_tool(
            MockBaseTool("anything"),
            {},
            MockToolContext(),
        )

        assert result is not None
        assert "not authorized" in result["message"].lower()

    def test_empty_builder_denies_all(self):
        """Builder with no .allow() MUST deny all tools."""
        guard = GuardBuilder().build()

        result = guard.before_tool(
            MockBaseTool("anything"),
            {},
            MockToolContext(),
        )

        assert result is not None

    def test_partial_capability_doesnt_grant_all(self, keys):
        """Granting one capability MUST NOT grant others."""
        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/data"))
            # Note: NOT granting "shell"
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        guard = TenuoGuard(warrant=warrant, signing_key=keys, require_pop=True)

        # read_file should work
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )
        assert result is None

        # shell should be denied
        result = guard.before_tool(
            MockBaseTool("shell"),
            {"cmd": "ls"},
            MockToolContext(),
        )
        assert result is not None
        assert "not authorized" in result["message"].lower() or "failed" in result["message"].lower()


class TestInvariantAttenuation:
    """Invariant: Constraints can only be narrowed, never expanded."""

    def test_attenuated_warrant_respects_narrower_path(self, keys):
        """Attenuated warrant with narrower path MUST NOT allow parent path."""
        # Parent warrant: /data
        parent_warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/data"))
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        # Child warrant: /data/reports (narrower)
        child_keys = SigningKey.generate()
        child_warrant = (
            parent_warrant.grant_builder()
            .capability("read_file", path=Subpath("/data/reports"))
            .holder(child_keys.public_key)
            .ttl(1800)
            .grant(keys)  # Use .grant() not .mint() for attenuation
        )

        guard = TenuoGuard(warrant=child_warrant, signing_key=child_keys, require_pop=True)

        # Should allow: /data/reports/file.txt
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/reports/file.txt"},
            MockToolContext(),
        )
        assert result is None

        # Should deny: /data/other.txt (outside narrowed scope)
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/other.txt"},
            MockToolContext(),
        )
        assert result is not None

    def test_attenuated_warrant_respects_narrower_domains(self, keys):
        """Attenuated warrant with narrower domains MUST NOT allow parent domains."""
        # Parent warrant: *.example.com
        parent_warrant = (
            Warrant.mint_builder()
            .capability("fetch", url=UrlSafe(allow_domains=["*.example.com"]))
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        # Child warrant: api.example.com only (narrower)
        child_keys = SigningKey.generate()
        child_warrant = (
            parent_warrant.grant_builder()
            .capability("fetch", url=UrlSafe(allow_domains=["api.example.com"]))
            .holder(child_keys.public_key)
            .ttl(1800)
            .grant(keys)  # Use .grant() not .mint() for attenuation
        )

        guard = TenuoGuard(warrant=child_warrant, signing_key=child_keys, require_pop=True)

        # Should allow: api.example.com
        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "https://api.example.com/data"},
            MockToolContext(),
        )
        assert result is None

        # Should deny: other.example.com (outside narrowed scope)
        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "https://other.example.com/data"},
            MockToolContext(),
        )
        assert result is not None

    def test_cannot_escalate_via_builder(self):
        """Direct constraints in builder CANNOT be bypassed by tool args."""
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # Attempt to access outside scope
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/etc/passwd"},
            MockToolContext(),
        )

        assert result is not None
        assert "violates constraint" in result["message"]

    def test_cannot_escalate_to_wildcard(self, keys):
        """Escalating from any constraint TO Wildcard MUST fail (monotonicity)."""
        from tenuo_core import Exact, Wildcard

        # Create parent with Exact constraint
        parent_warrant = Warrant.issue(
            keypair=keys,
            holder=keys.public_key,
            ttl_seconds=3600,
            capabilities={"action": {"type": Exact("read")}},
        )

        # Attempt to escalate to Wildcard - MUST fail
        with pytest.raises(Exception) as exc_info:
            parent_warrant.attenuate(
                signing_key=keys,
                holder=keys.public_key,
                ttl_seconds=3600,
                capabilities={"action": {"type": Wildcard()}},
            )

        # Verify it's a WildcardExpansion error
        assert "Wildcard" in str(exc_info.value)

    def test_wildcard_can_narrow_to_anything(self, keys):
        """Wildcard CAN be narrowed to any constraint (it's the superset)."""
        from tenuo_core import Exact, Wildcard

        # Create parent with Wildcard constraint
        parent_warrant = Warrant.issue(
            keypair=keys,
            holder=keys.public_key,
            ttl_seconds=3600,
            capabilities={"action": {"type": Wildcard()}},
        )

        # Narrowing to Exact should succeed
        child_warrant = parent_warrant.attenuate(
            signing_key=keys,
            holder=keys.public_key,
            ttl_seconds=3600,
            capabilities={"action": {"type": Exact("read")}},
        )

        assert child_warrant is not None
        assert "action" in child_warrant.tools


class TestInvariantWireAuthorization:
    """Invariant: Tier 2 authorization MUST use Rust core for cryptographic validation."""

    def test_tier2_uses_rust_core_validation(self, keys):
        """Tier 2 MUST use Rust core for authorization (via enforce_tool_call).

        This test verifies that authorization goes through the Rust core by checking
        that both valid and invalid calls are correctly handled.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/data"))
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        guard = TenuoGuard(
            warrant=warrant,
            signing_key=keys,
            require_pop=True,
        )

        # Valid call should be allowed
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )
        assert result is None, f"Expected valid call to be allowed, got: {result}"

        # Invalid call (path outside constraint) should be denied
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/etc/passwd"},
            MockToolContext(),
        )
        assert result is not None, "Expected invalid call to be denied"

    def test_tier2_requires_correct_signing_key(self, keys):
        """Tier 2 MUST verify PoP - wrong signing key should fail.

        This verifies that cryptographic verification is happening, not just
        logical checks.
        """
        warrant = (
            Warrant.mint_builder()
            .capability("read_file")
            .holder(keys.public_key)
            .ttl(3600)
            .mint(keys)
        )

        # Use a DIFFERENT key for signing
        wrong_key = SigningKey.generate()

        guard = TenuoGuard(
            warrant=warrant,
            signing_key=wrong_key,  # Wrong key!
            require_pop=True,
        )

        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )

        # Should be denied because PoP signature is invalid
        assert result is not None, "Expected PoP with wrong key to be denied"

    def test_tier1_uses_constraint_methods(self):
        """Tier 1 constraint checks should call constraint methods (Rust bindings)."""
        # Use real Subpath constraint to verify Rust binding is called
        real_constraint = Subpath("/data")

        mock_warrant = MagicMock()
        mock_warrant.is_expired = MagicMock(return_value=False)
        mock_warrant.tools = ["read_file"]
        mock_warrant.capabilities = {"read_file": {"path": real_constraint}}
        mock_warrant.grants = []

        guard = TenuoGuard(warrant=mock_warrant, require_pop=False)

        # This should call Subpath.contains() which is a Rust binding
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )

        # Verify it was allowed (Rust constraint check passed)
        assert result is None

    def test_subpath_uses_rust_contains(self):
        """Subpath.contains() MUST be called (Rust binding)."""
        # Use real Subpath to verify it works
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        # This should call Subpath.contains() which is a Rust binding
        result = guard.before_tool(
            MockBaseTool("read_file"),
            {"path": "/data/file.txt"},
            MockToolContext(),
        )

        assert result is None  # Allowed

    def test_urlsafe_uses_rust_is_safe(self):
        """UrlSafe.is_safe() MUST be called (Rust binding)."""
        guard = GuardBuilder().allow("fetch", url=UrlSafe(allow_domains=["api.example.com"])).build()

        # This should call UrlSafe.is_safe() which is a Rust binding
        result = guard.before_tool(
            MockBaseTool("fetch"),
            {"url": "https://api.example.com/data"},
            MockToolContext(),
        )

        assert result is None  # Allowed
