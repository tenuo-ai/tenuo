"""
Smoke tests for integration APIs.

These tests verify the basic API contract hasn't changed.
Run against multiple versions to detect breaking changes.

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
    """Verify OpenAI client constructor signature."""
    try:
        from openai import OpenAI

        # This should work in all versions >= 1.0
        client = OpenAI(api_key="test-key")

        assert hasattr(client, 'chat')
        assert hasattr(client.chat, 'completions')
    except ImportError:
        pytest.skip("openai not installed")


def test_openai_beta_chat():
    """Verify OpenAI beta.chat API (if available)."""
    try:
        from openai import OpenAI

        client = OpenAI(api_key="test-key")

        if hasattr(client, 'beta'):
            assert hasattr(client.beta, 'chat')
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
        tool = Tool(
            name="test",
            description="test tool",
            func=lambda x: x
        )

        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
        assert hasattr(tool, 'func')
        assert tool.name == "test"
    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_agent_creation():
    """Verify Agent constructor signature."""
    try:
        from crewai import Agent

        # Use a fake model string - Agent validates it's non-empty but
        # won't actually call the LLM during construction
        agent = Agent(
            role="test",
            goal="test goal",
            backstory="test backstory",
            tools=[],
            llm="gpt-4o-mini",
            allow_delegation=False,
            verbose=False
        )

        assert hasattr(agent, 'role')
        assert hasattr(agent, 'goal')
        assert hasattr(agent, 'tools')
    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_crew_creation():
    """Verify Crew constructor signature."""
    try:
        from crewai import Agent, Task, Crew

        # Use a fake model string - Agent validates it's non-empty but
        # won't actually call the LLM during construction
        agent = Agent(
            role="test",
            goal="test goal",
            backstory="test backstory",
            tools=[],
            llm="gpt-4o-mini",
            allow_delegation=False,
            verbose=False
        )
        task = Task(description="test task", expected_output="test output", agent=agent)
        crew = Crew(agents=[agent], tasks=[task])

        assert hasattr(crew, 'agents')
        assert hasattr(crew, 'tasks')
        assert hasattr(crew, 'kickoff')
    except ImportError:
        pytest.skip("crewai not installed")


def test_crewai_process_enum():
    """Verify Process enum exists."""
    try:
        from crewai import Process

        assert hasattr(Process, 'sequential')
        # hierarchical added in 1.5.0, may not exist in older versions
        if hasattr(Process, 'hierarchical'):
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

        assert hasattr(test_tool, 'name')
        assert hasattr(test_tool, 'description')
        # LangChain tools have invoke() method, not direct callable
        assert hasattr(test_tool, 'invoke') or callable(test_tool)
    except ImportError:
        pytest.skip("langchain not installed")


def test_langchain_structured_tool():
    """Verify StructuredTool creation."""
    try:
        from langchain_core.tools import StructuredTool

        tool = StructuredTool.from_function(
            func=lambda x: x,
            name="test",
            description="test"
        )

        assert hasattr(tool, 'name')
        assert hasattr(tool, 'description')
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

        assert hasattr(graph, 'add_node')
        assert hasattr(graph, 'add_edge')
        assert hasattr(graph, 'compile')
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
        versions['openai'] = getattr(openai, '__version__', 'unknown')
    except ImportError:
        versions['openai'] = 'not installed'

    try:
        import crewai
        versions['crewai'] = getattr(crewai, '__version__', 'unknown')
    except ImportError:
        versions['crewai'] = 'not installed'

    try:
        import autogen_agentchat
        versions['autogen'] = getattr(autogen_agentchat, '__version__', 'unknown')
    except ImportError:
        versions['autogen'] = 'not installed'

    try:
        import langchain_core
        versions['langchain'] = getattr(langchain_core, '__version__', 'unknown')
    except ImportError:
        versions['langchain'] = 'not installed'

    try:
        import langgraph
        versions['langgraph'] = getattr(langgraph, '__version__', 'unknown')
    except ImportError:
        versions['langgraph'] = 'not installed'

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
            'sequential': hasattr(Process, 'sequential'),
            'hierarchical': hasattr(Process, 'hierarchical'),
        }

        print("\n=== CrewAI Features ===")
        for feature, available in features.items():
            status = "✅" if available else "❌"
            print(f"{status} {feature}")
        print("=" * 40)

        assert features['sequential'], "sequential process should always be available"
    except ImportError:
        pytest.skip("crewai not installed")
