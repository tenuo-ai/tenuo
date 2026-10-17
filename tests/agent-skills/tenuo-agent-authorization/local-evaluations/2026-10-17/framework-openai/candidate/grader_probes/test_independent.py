import pytest
import agent_app as a
from tenuo import SigningKey, Warrant, Exact, Range
from refund_service import RefundService, RefundDenied

@pytest.mark.asyncio
async def test_independent_framework_narrower_than_host_policy():
    a.effects.clear()
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    root = Warrant.mint(keypair=issuer, capabilities={"refund_order": {"order_id": Exact("123"), "amount_cents": Range(min=1,max=10000)}}, holder=holder.public_key, ttl_seconds=120)
    leaf = root.grant_builder().capability("refund_order", {"order_id": Exact("123"), "amount_cents": Range(min=1,max=10000)}).holder(holder.public_key).ttl(60).terminal().grant(holder)
    session = a.RefundSession(RefundService([issuer.public_key],a.effects),(root.to_base64(),leaf.to_base64()),holder)
    with pytest.raises(Exception, match="Constraint.*amount_cents"):
        await a.run_agent([{"order_id":"123","amount_cents":10001}],session=session)
    assert a.effects == []
    await a.run_agent([{"order_id":"123","amount_cents":9999}],session=session)
    assert a.effects == [("123",9999)]

@pytest.mark.asyncio
async def test_independent_real_dispatch_denial_then_allow():
    a.effects.clear()
    for args in [{"order_id":"124","amount_cents":200}, {"order_id":"123","amount_cents":50001}, {"order_id":"123","amount_cents":True}]:
        with pytest.raises(Exception):
            await a.run_agent([args])
        assert a.effects == []
    await a.run_agent([{"order_id":"123","amount_cents":49999}])
    assert a.effects == [("123",49999)]
