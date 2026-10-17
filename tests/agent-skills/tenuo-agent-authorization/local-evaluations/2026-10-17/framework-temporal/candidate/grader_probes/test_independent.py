import pytest
import agent_app as a
from dev_authority import authorize_refund
from temporalio.worker import Replayer

@pytest.mark.asyncio
async def test_independent_live_denial_and_replay():
    a.effects.clear(); a.attempts.clear()
    with pytest.raises(Exception):
        await a.run_refund("123",200,retry_once=True,pause=True,authority=None)
    assert a.effects == [] and a.attempts == []
    proof=authorize_refund("123",200)
    with pytest.raises(Exception):
        await a.run_refund("123",201,authority=proof)
    assert a.effects == [] and a.attempts == []
    result, history=await a.run_refund("123",200,retry_once=True,pause=True)
    assert result == "refunded"
    assert a.effects == [("123",200)] and a.attempts == [1,2]
    before=list(a.effects)
    await Replayer(workflows=[a.RefundWorkflow]).replay_workflow(history)
    assert a.effects == before
