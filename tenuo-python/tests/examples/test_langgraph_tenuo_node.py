"""Tests for the local ``@tenuo_node`` LangGraph delegation example."""

import importlib.util
import sys
from pathlib import Path

import pytest


pytest.importorskip("langgraph.graph", reason="LangGraph is required for this example")
pytest.importorskip("tenuo_core", reason="Tenuo's compiled core is required for this example")

from tenuo import SigningKey, Warrant, enforce_tool_call  # noqa: E402
from tenuo.keys import KeyRegistry  # noqa: E402

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "langchain" / "langgraph_tenuo_node.py"
MODULE_NAME = "langgraph_tenuo_node_example"


@pytest.fixture
def example():
    KeyRegistry.reset_instance()
    spec = importlib.util.spec_from_file_location(MODULE_NAME, EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # StateGraph resolves the TypedDict's annotations via sys.modules, so the
    # module must be registered before it executes (fails on 3.9 otherwise).
    sys.modules[MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(MODULE_NAME, None)
        KeyRegistry.reset_instance()


def test_delegation_allows_research_and_never_runs_publish(example):
    result = example.run_demo()

    assert result["planner_checked_research"] is True
    assert result["research_result"] == f"Research notes for: {example.RESEARCH_TOPIC}"
    # The denied tool's body never executed: only research ran.
    assert result["executed_tools"] == ["research"]
    assert "publish" in result["publish_denial"]


def test_worker_warrant_is_narrowed_to_research(example):
    result = example.run_demo()

    child = result["warrant"]
    (root,) = result["warrant_chain"]
    assert child.depth == root.depth + 1
    assert child.allows("research", {"topic": example.RESEARCH_TOPIC})
    assert not child.allows("publish", {"destination": "public"})
    assert root.allows("publish", {"destination": "public"})


def test_worker_cannot_expand_its_own_scope(example):
    """Re-delegating with a broader tool list cannot recover ``publish`` (I4)."""
    result = example.run_demo()

    child = result["warrant"]
    worker_key = KeyRegistry.get_instance().get(example.WORKER_KEY_ID)
    sub_key = SigningKey.generate()
    grandchild = child.bind(worker_key).grant(
        to=sub_key.public_key,
        allow=["research", "publish"],
        ttl=30,
    )

    assert "publish" not in grandchild.tools
    denied = enforce_tool_call(
        "publish",
        {"destination": "public"},
        grandchild.bind(sub_key),
        trusted_roots=[result["warrant_chain"][0].issuer],
        warrant_chain=[*result["warrant_chain"], child],
    )
    assert not denied.allowed


def test_planner_key_comes_from_langgraph_config(example):
    """With no 'default' key registered, the run only works if config is honored."""
    with pytest.raises(KeyError):
        KeyRegistry.get_instance().get("default")
    assert isinstance(example.run_demo()["warrant"], Warrant)
