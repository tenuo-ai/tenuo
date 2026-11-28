"""The Send workers execute concurrently and cannot borrow one another's tools."""

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from langchain_core.messages import ToolMessage
from tenuo.langgraph import WRAP_TOOL_CALL_SUPPORTED


EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "langchain" / "langgraph_parallel_workers.py"


def load_example():
    spec = importlib.util.spec_from_file_location("langgraph_parallel_workers", EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(not WRAP_TOOL_CALL_SUPPORTED, reason="langgraph-prebuilt >= 1.0.2 required for TenuoToolNode")
async def test_parallel_workers_enforce_separate_warrants():
    example = load_example()
    arrived = []
    both_arrived = asyncio.Event()

    async def synchronize():
        arrived.append(1)
        if len(arrived) == 2:
            both_arrived.set()
        await both_arrived.wait()

    graph, root, executed = example.build_graph(on_execute=synchronize)
    result = await asyncio.wait_for(
        graph.ainvoke({"messages": [], "warrant": root, "warrant_chain": [], "dispatches": []}),
        timeout=5,
    )

    messages = {message.tool_call_id: message for message in result["messages"] if isinstance(message, ToolMessage)}
    assert set(messages) == {"research-search", "research-write", "writer-write", "writer-search"}
    dispatches = result["dispatches"]
    assert {item["worker"] for item in dispatches} == {"researcher", "writer"}
    assert dispatches[0]["warrant"] != dispatches[1]["warrant"]
    assert messages["research-search"].status == "success"
    assert messages["writer-write"].status == "success"
    assert messages["research-write"].status == "error"
    assert messages["writer-search"].status == "error"
    assert sorted(executed) == ["search", "write_report"]
    assert len(arrived) == 2
