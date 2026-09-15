"""Tests for the local ``@tenuo_node`` LangGraph delegation example."""

import importlib.util
from pathlib import Path

import pytest


pytest.importorskip("langgraph.graph", reason="LangGraph is required for this example")
pytest.importorskip("tenuo_core", reason="Tenuo's compiled core is required for this example")

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "langchain" / "langgraph_tenuo_node.py"


@pytest.fixture
def example():
    spec = importlib.util.spec_from_file_location("langgraph_tenuo_node_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_delegation_allows_research_and_never_runs_publish(example):
    result = example.run_demo()

    assert result["planner_checked_research"] is True
    assert result["research_result"] == f"Research notes for: {example.RESEARCH_TOPIC}"
    assert result["denied_action_body_ran"] is False
    assert result["warrant"].allows("research", {"topic": example.RESEARCH_TOPIC})
    assert not result["warrant"].allows("publish", {"destination": "public"})
