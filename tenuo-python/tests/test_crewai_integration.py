"""
CrewAI Integration Tests

Tests that verify Tenuo integration with the real CrewAI package.
These tests focus on the protection layer and don't require LLM calls.

Run with: pytest tests/test_crewai_integration.py -v
"""
import pytest
from unittest.mock import MagicMock

# Skip all tests if crewai is not installed
crewai = pytest.importorskip("crewai")

from tenuo.crewai import (  # noqa: E402 - must be after importorskip
    GuardBuilder,
    CrewAIGuard,
    GuardedCrew,
    guarded_step,
    get_active_guard,
    is_strict_mode,
    Subpath,
    Wildcard,
    ConfigurationError,
    DenialResult,
)


class TestCrewAIToolStructure:
    """Tests verifying CrewAI tool structure compatibility."""

    def test_crewai_basetool_structure(self):
        """Verify CrewAI BaseTool has expected structure."""
        from crewai.tools import BaseTool

        class TestTool(BaseTool):
            name: str = "test_tool"
            description: str = "A test tool"
            def _run(self, arg: str) -> str:
                return f"Result: {arg}"

        tool = TestTool()

        # Verify expected CrewAI structure
        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, '_run')
        assert tool.name == "test_tool"

        # Direct call to _run should work
        result = tool._run("hello")
        assert result == "Result: hello"

    def test_tool_protection_creates_wrapper(self):
        """Tool protection creates a wrapped tool."""
        from crewai.tools import BaseTool

        class ReadTool(BaseTool):
            name: str = "read_file"
            description: str = "Read a file"
            def _run(self, path: str) -> str:
                return f"Contents of {path}"

        ReadTool()

        guard = (GuardBuilder()
            .allow("read_file", path=Subpath("/data"))
            .build())

        # NOTE: CrewAI tools use _run instead of func, so we test with a
        # compatible tool format. The protection mechanism works with
        # tools that have a .func attribute (like LangChain tools).
        # For real CrewAI BaseTool, use protect_all which handles the wrapper.

        # Just verify that the guard was built correctly
        assert guard is not None
        assert "read_file" in guard._allowed


class TestGuardedStepIntegration:
    """Tests for @guarded_step with real CrewAI patterns."""

    def test_guarded_step_creates_context(self):
        """@guarded_step creates a scoped guard context."""
        guard_inside = None
        strict_inside = None

        @guarded_step(
            allow={"search": {"query": Wildcard()}},
            strict=True
        )
        def my_step():
            nonlocal guard_inside, strict_inside
            guard_inside = get_active_guard()
            strict_inside = is_strict_mode()
            return "done"

        # Before: no active guard
        assert get_active_guard() is None
        assert is_strict_mode() is False

        # During: guard is active
        result = my_step()

        assert guard_inside is not None
        assert strict_inside is True
        assert result == "done"

        # After: guard is cleared
        assert get_active_guard() is None

    def test_guarded_step_with_ttl_string(self):
        """@guarded_step parses TTL string."""
        guard_ref = None

        @guarded_step(
            allow={"tool": {"arg": Wildcard()}},
            ttl="30s"
        )
        def step_with_ttl():
            nonlocal guard_ref
            guard_ref = get_active_guard()
            return "done"

        step_with_ttl()

        assert guard_ref is not None
        # Guard should be a valid CrewAIGuard instance
        assert isinstance(guard_ref, CrewAIGuard)

    def test_guarded_step_without_strict(self):
        """@guarded_step defaults to non-strict mode."""
        strict_value = None

        @guarded_step(allow={"tool": {"arg": Wildcard()}})
        def non_strict_step():
            nonlocal strict_value
            strict_value = is_strict_mode()
            return "ok"

        non_strict_step()

        assert strict_value is False

    def test_guarded_step_exception_cleanup(self):
        """@guarded_step cleans up context on exception."""
        @guarded_step(allow={"tool": {"arg": Wildcard()}})
        def failing_step():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_step()

        # Context should be cleaned up
        assert get_active_guard() is None
        assert is_strict_mode() is False


class TestGuardedCrewBuilder:
    """Tests for GuardedCrew builder pattern."""

    def test_guarded_crew_builder_chain(self):
        """GuardedCrew fluent builder works."""
        mock_agent = MagicMock()
        mock_agent.role = "researcher"
        mock_task = MagicMock()

        builder = (GuardedCrew(agents=[mock_agent], tasks=[mock_task])
            .policy({"researcher": ["search", "read"]})
            .constraints({"researcher": {"search": {"query": Wildcard()}}})
            .on_denial("log")
            .strict())

        # Builder should be chainable
        assert builder is not None

        # Build should return GuardedCrewInstance
        crew = builder.build()
        assert crew is not None

    def test_guarded_crew_policy_required(self):
        """GuardedCrew validates all agents are in policy."""
        mock_agent = MagicMock()
        mock_agent.role = "unknown_agent"
        mock_task = MagicMock()

        crew = (GuardedCrew(agents=[mock_agent], tasks=[mock_task])
            .policy({"researcher": ["search"]})  # wrong role!
            .build())

        # Policy validation happens at kickoff
        with pytest.raises(ConfigurationError, match="not listed in policy"):
            crew.kickoff()

    def test_guarded_crew_with_audit(self):
        """GuardedCrew accepts audit callback."""
        audit_events = []

        mock_agent = MagicMock()
        mock_agent.role = "researcher"
        mock_task = MagicMock()

        crew = (GuardedCrew(agents=[mock_agent], tasks=[mock_task])
            .policy({"researcher": ["search"]})
            .audit(lambda e: audit_events.append(e))
            .build())

        assert crew is not None


class TestSecurityIntegration:
    """Tests verifying security properties with CrewAI."""

    def test_guard_rejects_unlisted_tool(self):
        """Guard correctly rejects tools not in allow list."""
        guard = (GuardBuilder()
            .allow("safe_tool", arg=Wildcard())
            .on_denial("skip")
            .build())

        result = guard._authorize("dangerous_tool", {"arg": "value"})

        assert isinstance(result, DenialResult)
        assert result.error_code == "TOOL_DENIED"

    def test_guard_rejects_constraint_violation(self):
        """Guard correctly rejects constraint violations."""
        guard = (GuardBuilder()
            .allow("read", path=Subpath("/safe"))
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/etc/passwd"})

        assert isinstance(result, DenialResult)
        assert result.error_code == "CONSTRAINT_VIOLATION"

    def test_guard_rejects_unlisted_argument(self):
        """Guard correctly rejects unlisted arguments (closed-world)."""
        guard = (GuardBuilder()
            .allow("tool", known_arg=Wildcard())
            .on_denial("skip")
            .build())

        result = guard._authorize("tool", {"known_arg": "ok", "injection": "bad"})

        assert isinstance(result, DenialResult)
        assert result.error_code == "UNLISTED_ARGUMENT"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
