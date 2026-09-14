"""
Tests for examples/langchain/create_agent_middleware.py.

Runs the example's own agent with a scripted fake model: an authorized tool
call executes, and tool calls outside the warrant are denied without running.
"""

import importlib.util
from pathlib import Path

import pytest

from tenuo.keys import KeyRegistry

pytest.importorskip("langchain.agents.middleware", reason="create_agent middleware requires langchain>=1.0")

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "langchain" / "create_agent_middleware.py"


@pytest.fixture
def example():
    KeyRegistry.reset_instance()
    spec = importlib.util.spec_from_file_location("create_agent_middleware_example", EXAMPLE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.executed.clear()
    yield module
    KeyRegistry.reset_instance()


@pytest.fixture
def keys_and_warrant(example):
    return example.setup_keys_and_warrant()


def test_authorized_search_runs(example, keys_and_warrant):
    issuer_key, warrant = keys_and_warrant

    messages = example.run("search", {"query": "customers:acme"}, issuer_key, warrant)

    assert [m.status for m in messages] == ["success"]
    assert "3 records match" in messages[0].content
    assert example.executed == ["search:customers:acme"]


def test_tool_not_in_warrant_is_denied_and_never_runs(example, keys_and_warrant):
    issuer_key, warrant = keys_and_warrant

    messages = example.run("delete_record", {"record_id": "42"}, issuer_key, warrant)

    assert [m.status for m in messages] == ["error"]
    assert "Authorization denied" in messages[0].content
    assert example.executed == []


def test_search_outside_its_constraint_is_denied_and_never_runs(example, keys_and_warrant):
    issuer_key, warrant = keys_and_warrant

    messages = example.run("search", {"query": "payroll:all"}, issuer_key, warrant)

    assert [m.status for m in messages] == ["error"]
    assert example.executed == []


def test_warrant_from_an_untrusted_issuer_is_denied(example, keys_and_warrant):
    _, warrant = keys_and_warrant
    other_issuer = example.SigningKey.generate()

    messages = example.run("search", {"query": "customers:acme"}, other_issuer, warrant)

    assert [m.status for m in messages] == ["error"]
    assert example.executed == []


def test_main_runs_end_to_end(example, capsys):
    example.main()

    out = capsys.readouterr().out
    assert "success: 3 records match 'customers:acme'" in out
    assert "error: Authorization denied" in out
    assert "Tool bodies that ran: ['search:customers:acme']" in out
