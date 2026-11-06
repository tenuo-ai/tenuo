"""Exercise a native handoff and the specialist's narrower tool authority."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("agents")

from agents import Runner, set_tracing_disabled  # noqa: E402


EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "openai" / "handoff.py"


@pytest.mark.asyncio
async def test_handoff_runs_allowed_tools_and_blocks_ungranted_tool():
    set_tracing_disabled(True)
    spec = importlib.util.spec_from_file_location("openai_handoff", EXAMPLE)
    assert spec is not None and spec.loader is not None
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)

    model = example.ScriptedModel(
        [
            [example._call("transfer_to_refund_specialist", {}, "h1")],
            [example._call("lookup_order", {}, "c1")],
            [example._call("issue_refund", {"amount": 50}, "c2")],
            [example._call("delete_all_orders", {}, "c3")],
            [example._text("done")],
        ]
    )
    executed = []
    triage, parent, child, guardrail = example.build_agents(model, executed)
    assert "delete_all_orders" in parent.tools
    assert "delete_all_orders" not in child.tools
    preview = await guardrail(None, None, [{"function": {"name": "delete_all_orders", "arguments": "{}"}}])
    assert preview.tripwire_triggered
    over_limit = await guardrail(
        None,
        None,
        [{"function": {"name": "issue_refund", "arguments": '{"amount": 101}'}}],
    )
    assert over_limit.tripwire_triggered

    result = await Runner.run(triage, "Check the order and refund 50 cents")

    assert result.last_agent.name == "refund_specialist"
    assert executed == ["lookup_order", "issue_refund"]
    outputs = [
        str(item.get("output"))
        for turn in model.inputs
        for item in turn
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    ]
    assert any("blocked by Tenuo" in output for output in outputs)
