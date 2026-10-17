import pytest
import agent_app

@pytest.mark.asyncio
async def test_refund():
    agent_app.effects.clear()
    await agent_app.run_agent([{"order_id": "123", "amount_cents": 20000}])
    assert agent_app.effects == [("123", 20000)]

@pytest.mark.asyncio
async def test_no_tool_call():
    agent_app.effects.clear()
    await agent_app.run_agent([])
    assert agent_app.effects == []
