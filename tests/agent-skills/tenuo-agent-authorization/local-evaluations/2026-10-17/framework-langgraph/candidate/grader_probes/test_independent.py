import time
import pytest
import agent_app as a
from tenuo import SigningKey, Warrant, Exact, Range
from langchain_core.messages import AIMessage

def test_independent_compiled_dispatch_public_transport():
    a.effects.clear()
    issuer, delegator, holder = [SigningKey.generate() for _ in range(3)]
    scope={"order_id":Exact("123"),"amount_cents":Range(min=1,max=10000)}
    root=Warrant.mint_builder().holder(delegator.public_key).capability("refund_order",**scope).ttl(120).mint(issuer)
    leaf=root.grant_builder().capability("refund_order", **scope).holder(holder.public_key).ttl(60).terminal().grant(delegator)
    graph=a.make_graph([issuer.public_key])
    def invoke(amount,chain,key=holder,signed_amount=None):
        args={"order_id":"123","amount_cents":amount}
        signed={**args,"amount_cents":amount if signed_amount is None else signed_amount}
        presentation={"chain":[w.to_base64() for w in chain],"signature":leaf.sign(key,"refund_order",signed,int(time.time()))}
        state={"messages":[AIMessage(content="",tool_calls=[{"name":"refund_order","args":args,"id":"grader"}])],"warrant":leaf,"warrant_chain":[root]}
        try:
            graph.invoke(state,config={"configurable":{"refund_presentation":presentation}})
        except Exception:
            pass
    for amount,chain,key,signed in [(10001,[root,leaf],holder,None),(5000,[leaf],holder,None),(5000,[root,leaf],SigningKey.generate(),None),(5000,[root,leaf],holder,4000)]:
        invoke(amount,chain,key,signed)
        assert a.effects == []
    invoke(9999,[root,leaf])
    assert a.effects == [("123",9999)]

def test_independent_original_bypass_retired():
    a.effects.clear()
    with pytest.raises(PermissionError):
        a.refund_order.func("123",200)
    with pytest.raises(PermissionError):
        a.refund_order.invoke({"order_id":"123","amount_cents":200})
    assert a.effects == []
