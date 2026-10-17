import pytest
import agent_app

@pytest.mark.asyncio
async def test_retry():
    agent_app.attempts.clear(); agent_app.effects.clear()
    result, _ = await agent_app.run_refund("123",20000,retry_once=True)
    assert result == "refunded"
    assert agent_app.attempts == [1,2]
    assert agent_app.effects == [("123",20000)]

@pytest.mark.asyncio
async def test_resume():
    agent_app.attempts.clear(); agent_app.effects.clear()
    result, _ = await agent_app.run_refund("123",20000,pause=True)
    assert result == "refunded"
    assert agent_app.effects == [("123",20000)]
