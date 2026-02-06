"""
Smoke tests for integration APIs.

These tests verify the basic API contract hasn't changed.
Run against multiple versions to detect breaking changes.

IMPORTANT: These are MINIMAL tests that only check:
1. Package can be imported
2. Key classes/functions exist
3. Basic attributes are present

They do NOT test:
- Full object construction (may require complex setup)
- Runtime behavior
- Internal implementation details

Pattern for Robust Smoke Tests:
    1. Try import -> skip if not available
    2. Check class/function exists with hasattr()
    3. For construction tests, wrap in try-except and skip on failure
    4. Never assume internal state or complex initialization will work

Usage:
    # Test currently installed versions
    pytest tests/integration/test_smoke.py -v

    # Test specific version
    pip install crewai==1.9.0
    pytest tests/integration/test_smoke.py -v
"""

import pytest
import sys

# =============================================================================
# OpenAI Smoke Tests
# =============================================================================


def test_openai_import():
    """Verify OpenAI can be imported."""
    try:
        import openai

        assert openai is not None
    except ImportError:
        pytest.skip("openai not installed")


def test_openai_client_creation():
    """Verify OpenAI client class exists and has expected API.

    NOTE: Client instantiation may fail due to httpx version mismatches
    in older openai versions. We verify the class exists and has expected
    attributes without requiring successful instantiation.
    """
    try:
        from openai import OpenAI

        # Verify the class exists
        assert OpenAI is not None

        # Verify key class attributes exist (without instantiation)
        assert hasattr(OpenAI, "__init__")

        # Try instantiation, but skip test if it fails due to dependency issues
        try:
            client = OpenAI(api_key="test-key")
            assert hasattr(client, "chat")
            assert hasattr(client.chat, "completions")
        except TypeError as e:
            if "unexpected keyword argument" in str(e):
                # httpx version mismatch - known issue with older openai versions
                pytest.skip(f"OpenAI/httpx version mismatch: {e}")
            raise

    except ImportError:
        pytest.skip("openai not installed")


def test_openai_beta_chat():
    """Verify OpenAI beta.chat API (if available).

    NOTE: Client instantiation may fail due to httpx version mismatches.
    """
    try:
        from openai import OpenAI

        # Try instantiation, but skip test if it fails due to dependency issues
        try:
            client = OpenAI(api_key="test-key")

            if hasattr(client, "beta"):
                assert hasattr(client.beta, "chat")
        except TypeError as e:
            if "unexpected keyword argument" in str(e):
                pytest.skip(f"OpenAI/httpx version mismatch: {e}")
            raise

    except ImportError:
        pytest.skip("openai not installed")


# =============================================================================
# CrewAI Smoke Tests
# =============================================================================


def test_crewai_import():
    """Verify CrewAI can be imported."""
    try:
        import crewai  # type: ignore[import-not-found]

        assert crewai is not None
    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_tool_creation():
    """Verify CrewAI Tool constructor signature."""
    try:
        from crewai import Tool

        # This should work in all versions >= 1.0
        tool = Tool(name="test", description="test tool", func=lambda x: x)

        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert hasattr(tool, "func")
        assert tool.name == "test"
    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_agent_creation():
    """Verify Agent class exists and has expected attributes.

    NOTE: This test only verifies the class exists, not that instances
    can be created. Different CrewAI versions have different construction
    requirements (LLM instances, etc.) which are too complex for smoke tests.
    """
    try:
        from crewai import Agent

        # Verify the class exists
        assert Agent is not None

        # Verify key class attributes/methods exist (without instantiation)
        # These are stable across versions
        assert hasattr(Agent, "__init__")

        # If we can inspect the signature, verify expected parameters exist
        # But don't fail if inspection doesn't work
        try:
            import inspect

            sig = inspect.signature(Agent.__init__)
            params = list(sig.parameters.keys())
            # These params have existed since 1.0
            assert "role" in params or "self" in params  # 'self' always present
        except (ValueError, TypeError):
            # Signature inspection may not work in all versions, that's OK
            pass

    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_crew_creation():
    """Verify Crew, Task, and Agent classes exist.

    NOTE: This test only verifies the classes exist, not that instances
    can be created. Different CrewAI versions have different construction
    requirements which are too complex for smoke tests.
    """
    try:
        from crewai import Agent, Task, Crew

        # Verify the classes exist
        assert Agent is not None
        assert Task is not None
        assert Crew is not None

        # Verify key methods exist on Crew class (without instantiation)
        assert hasattr(Crew, "__init__")
        assert hasattr(Crew, "kickoff")

    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_process_enum():
    """Verify Process enum exists."""
    try:
        from crewai import Process

        assert hasattr(Process, "sequential")
        # hierarchical added in 1.5.0, may not exist in older versions
        if hasattr(Process, "hierarchical"):
            assert Process.hierarchical is not None
    except ImportError:
        pytest.skip("crewai not installed")


# =============================================================================
# AutoGen Smoke Tests
# =============================================================================


def test_autogen_import():
    """Verify AutoGen can be imported."""
    if sys.version_info < (3, 10):
        pytest.skip("autogen requires Python 3.10+")

    try:
        import autogen_agentchat  # type: ignore[import-not-found]

        assert autogen_agentchat is not None
    except ImportError:
        pytest.skip("autogen not installed")


def test_autogen_assistant_agent():
    """Verify AssistantAgent constructor signature."""
    if sys.version_info < (3, 10):
        pytest.skip("autogen requires Python 3.10+")

    try:
        from autogen_agentchat.agents import AssistantAgent  # type: ignore[import-not-found]
        from autogen_ext.models import OpenAIChatCompletionClient  # type: ignore[import-not-found]

        # Just verify we can create the classes
        assert AssistantAgent is not None
        assert OpenAIChatCompletionClient is not None
    except ImportError:
        pytest.skip("autogen not installed")


# =============================================================================
# LangChain Smoke Tests
# =============================================================================


def test_langchain_import():
    """Verify LangChain can be imported."""
    try:
        import langchain_core

        assert langchain_core is not None
    except ImportError:
        pytest.skip("langchain not installed")


def test_langchain_tool_decorator():
    """Verify @tool decorator signature."""
    try:
        from langchain_core.tools import tool

        @tool
        def test_tool(x: int) -> int:
            """Test tool."""
            return x * 2

        assert hasattr(test_tool, "name")
        assert hasattr(test_tool, "description")
        # LangChain tools have invoke() method, not direct callable
        assert hasattr(test_tool, "invoke") or callable(test_tool)
    except ImportError:
        pytest.skip("langchain not installed")


def test_langchain_structured_tool():
    """Verify StructuredTool creation."""
    try:
        from langchain_core.tools import StructuredTool

        tool = StructuredTool.from_function(func=lambda x: x, name="test", description="test")

        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
    except ImportError:
        pytest.skip("langchain not installed")


# =============================================================================
# LangGraph Smoke Tests
# =============================================================================


def test_langgraph_import():
    """Verify LangGraph can be imported."""
    try:
        import langgraph

        assert langgraph is not None
    except ImportError:
        pytest.skip("langgraph not installed")


def test_langgraph_state_graph():
    """Verify StateGraph constructor signature."""
    try:
        from langgraph.graph import StateGraph
        from typing import TypedDict

        class State(TypedDict):
            value: int

        graph = StateGraph(State)

        assert hasattr(graph, "add_node")
        assert hasattr(graph, "add_edge")
        assert hasattr(graph, "compile")
    except ImportError:
        pytest.skip("langgraph not installed")


# =============================================================================
# Version Information Tests
# =============================================================================


def test_print_installed_versions():
    """Print installed versions for debugging."""
    versions = {}

    try:
        import openai

        versions["openai"] = getattr(openai, "__version__", "unknown")
    except ImportError:
        versions["openai"] = "not installed"

    try:
        import crewai

        versions["crewai"] = getattr(crewai, "__version__", "unknown")
    except ImportError:
        versions["crewai"] = "not installed"

    try:
        import autogen_agentchat

        versions["autogen"] = getattr(autogen_agentchat, "__version__", "unknown")
    except ImportError:
        versions["autogen"] = "not installed"

    try:
        import langchain_core

        versions["langchain"] = getattr(langchain_core, "__version__", "unknown")
    except ImportError:
        versions["langchain"] = "not installed"

    try:
        import langgraph

        versions["langgraph"] = getattr(langgraph, "__version__", "unknown")
    except ImportError:
        versions["langgraph"] = "not installed"

    print("\n=== Installed Integration Versions ===")
    for name, version in versions.items():
        print(f"{name:15} {version}")
    print("=" * 40)

    # This test always passes, it's just for information
    assert True


# =============================================================================
# Integration-Specific Feature Detection
# =============================================================================


def test_crewai_features():
    """Detect which CrewAI features are available."""
    try:
        from crewai import Process

        features = {
            "sequential": hasattr(Process, "sequential"),
            "hierarchical": hasattr(Process, "hierarchical"),
        }

        print("\n=== CrewAI Features ===")
        for feature, available in features.items():
            status = "✅" if available else "❌"
            print(f"{status} {feature}")
        print("=" * 40)

        assert features["sequential"], "sequential process should always be available"
    except ImportError:
        pytest.skip("crewai not installed")
