"""Denials exercise the receiving handler and real Temporal dispatch."""
import asyncio
import base64
import pytest
from temporalio.exceptions import ApplicationError
from temporalio.client import WorkflowFailureError
from tenuo import Exact, Range, SigningKey, Warrant
import agent_app
import dev_authority as caller


@pytest.fixture(autouse=True)
def reset_effects():
    agent_app.effects.clear()
    agent_app.attempts.clear()


def mint(*, issuer=None, holder=None, capability="refund_order", ttl=60):
    return (Warrant.mint_builder().holder((holder or caller._holder).public_key)
            .capability(capability, order_id=Exact("123"), amount_cents=Range(min=1,max=50000))
            .ttl(ttl).mint(issuer or caller._issuer))


async def denied(order, cents, authority, reason):
    # This is the original module and callable, not a new wrapper alias.
    with pytest.raises(ApplicationError) as caught:
        await agent_app.refund_order(order, cents, {"trace_id":"direct", "retry_once":False}, authority)
    assert caught.value.type == "RefundAuthorizationDenied"
    assert caught.value.non_retryable
    assert reason.lower() in str(caught.value.details).lower()
    assert agent_app.effects == []
    assert agent_app.attempts == []


@pytest.mark.asyncio
async def test_original_direct_route_missing_authority():
    with pytest.raises(ApplicationError, match="authorization denied"):
        await agent_app.refund_order("123", 20000, {})
    assert agent_app.effects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("order,cents", [("124",20000),("123",50001),("123",490000),("123",0),("123",-1),("123",2**60)])
async def test_local_ceiling(order,cents):
    await denied(order,cents,caller.authorize_refund(order,cents),"ceiling")


@pytest.mark.asyncio
@pytest.mark.parametrize("order,cents", [(123,20000),("123",True),("123",20000.0),("123","20000")])
async def test_lossless_types(order,cents):
    # No proof is needed to establish rejection of an invalid effect type.
    await denied(order,cents,None,"integer")


@pytest.mark.asyncio
async def test_missing_malformed_and_bad_proof():
    await denied("123",20000,None,"missing")
    await denied("123",20000,{"chain":["garbage"],"proof":"00"},"deserialization")
    p=caller.authorize_refund("123",20000)
    p["proof"]="00"*64
    await denied("123",20000,p,"signature")


@pytest.mark.asyncio
async def test_untrusted_issuer():
    w=mint(issuer=SigningKey.generate())
    await denied("123",20000,caller.presentation(w,"123",20000),"trust")


@pytest.mark.asyncio
async def test_wrong_holder():
    w=mint()
    await denied("123",20000,caller.presentation(w,"123",20000,holder=SigningKey.generate()),"signature")


@pytest.mark.asyncio
async def test_wrong_capability():
    w=mint(capability="cancel_order")
    await denied("123",20000,caller.presentation(w,"123",20000),"refund_order")


@pytest.mark.asyncio
async def test_proof_binds_final_arguments():
    await denied("123",20001,caller.authorize_refund("123",20000),"signature")


@pytest.mark.asyncio
async def test_expired():
    w=mint(ttl=1)
    p=caller.presentation(w,"123",20000)
    await asyncio.sleep(1.2)
    await denied("123",20000,p,"expired")


@pytest.mark.asyncio
async def test_temporal_maximum_and_public_history():
    result,history=await agent_app.run_refund("123",50000,pause=True,retry_once=True)
    assert result == "refunded"
    assert agent_app.effects == [("123",50000)]
    assert agent_app.attempts == [1,2]
    payloads = history.events[0].workflow_execution_started_event_attributes.input.payloads
    encoded = "\n".join(p.data.decode() for p in payloads)
    assert "chain" in encoded and "proof" in encoded
    # Public presentations only; these exact private values never enter history.
    assert base64.b64encode(bytes(caller._holder.secret_key_bytes())).decode() not in encoded
    assert base64.b64encode(bytes(caller._issuer.secret_key_bytes())).decode() not in encoded


@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["missing","out_of_scope","proof_tamper"])
async def test_temporal_denials(mode):
    cents=50001 if mode=="out_of_scope" else 20000
    p=caller.authorize_refund("123",cents)
    if mode=="missing": p=None
    if mode=="proof_tamper": p["proof"]="00"*64
    with pytest.raises(WorkflowFailureError) as caught:
        await agent_app.run_refund("123",cents,authority=p,retry_once=True,pause=True)
    error=caught.value.cause.cause
    assert error.type == "RefundAuthorizationDenied"
    assert error.non_retryable
    assert agent_app.effects == []
    assert agent_app.attempts == []


@pytest.mark.asyncio
async def test_narrow_delegation_root_only_and_missing_parent():
    parent=caller.issue_refund_authority()
    child_holder=SigningKey.generate()
    builder=parent.attenuate_builder()
    builder.with_capability("refund_order",{"order_id":Exact("123"),"amount_cents":Range(min=1,max=10000)})
    builder.with_holder(child_holder.public_key)
    builder.with_ttl(30)
    builder.terminal()
    child=builder.delegate(caller._holder)
    assert child.is_terminal()
    p=caller.presentation(child,"123",10000,holder=child_holder,parents=[parent])
    result,_=await agent_app.run_refund("123",10000,authority=p)
    assert result == "refunded" and agent_app.effects == [("123",10000)]
    agent_app.effects.clear(); agent_app.attempts.clear()
    await denied("123",10000,caller.presentation(child,"123",10000,holder=child_holder),"not trusted")
    await denied("123",10001,caller.presentation(child,"123",10001,holder=child_holder,parents=[parent]),"constraint")


@pytest.mark.asyncio
async def test_widened_delegation():
    parent=caller.issue_refund_authority()
    with pytest.raises(Exception,match="Monotonicity violation"):
        parent.attenuate({"refund_order":{"order_id":Exact("123"),"amount_cents":Range(min=1,max=50001)}},caller._holder)
    # Also send a separately minted holder-signed leaf to the receiver
    # as if it belonged to this parent. It must not become a valid chain.
    forged=mint(issuer=caller._holder)
    await denied("123",20000,caller.presentation(forged,"123",20000,parents=[parent]),"parent_hash")
