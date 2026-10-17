import asyncio
import time
from dataclasses import replace

import pytest
from agents import Runner
from agents.exceptions import UserError
from agents.tool_context import ToolContext
from tenuo import Exact, Range, SigningKey, Warrant

import agent_app
from refund_service import Presentation, RefundDenied, RefundService

def tool_context(context):
    return ToolContext(context=context, tool_name="refund_order", tool_call_id="direct",
                       tool_arguments='{"order_id":"123","amount_cents":20000}')


ARGS = {"order_id": "123", "amount_cents": 20000}


@pytest.fixture(autouse=True)
def reset_effects():
    agent_app.effects.clear()


def authority(*, tool="refund_order", ceiling=50000, ttl=240, root=None):
    issuer, holder = root or SigningKey.generate(), SigningKey.generate()
    scope = {"order_id": Exact("123"), "amount_cents": Range(min=1, max=ceiling)}
    parent = Warrant.mint(keypair=issuer, capabilities={tool: scope},
                          holder=holder.public_key, ttl_seconds=300)
    leaf = (parent.grant_builder().capability(tool, scope).holder(holder.public_key)
            .ttl(ttl).terminal().grant(holder))
    return issuer, holder, parent, leaf


def presentation(holder, parent, leaf, args=ARGS):
    return Presentation((parent.to_base64(), leaf.to_base64()),
                        leaf.sign(holder, "refund_order", args, int(time.time())))


@pytest.mark.asyncio
@pytest.mark.parametrize("amount", [1, 20000, 50000])
async def test_dispatch_allowed(amount):
    await agent_app.run_agent([{**ARGS, "amount_cents": amount}])
    assert agent_app.effects == [("123", amount)]


@pytest.mark.asyncio
@pytest.mark.parametrize("args", [
    {**ARGS, "order_id": "124"}, {**ARGS, "amount_cents": 50001},
    {**ARGS, "amount_cents": 490000}, {**ARGS, "amount_cents": 0},
    {**ARGS, "amount_cents": -1}, {**ARGS, "amount_cents": 20000.5},
    {**ARGS, "amount_cents": True}, {**ARGS, "amount_cents": "20000"},
    {**ARGS, "amount_cents": 2**60}, {**ARGS, "order_id": 123},
])
async def test_dispatch_denies(args):
    with pytest.raises(Exception, match="outside refund policy|Invalid JSON input|invalid argument types"):
        await agent_app.run_agent([args])
    assert agent_app.effects == []


@pytest.mark.asyncio
async def test_original_tool_route_without_context_denies():
    # Original module and FunctionTool method, bypassing make_agent/Runner.
    with pytest.raises(RefundDenied, match="missing session authority"):
        await agent_app.refund_order.on_invoke_tool(
            tool_context(None), '{"order_id":"123","amount_cents":20000}')
    assert agent_app.effects == []


def test_unwrapped_original_handler_still_checks_service():
    issuer, holder, parent, leaf = authority(ceiling=10000)
    session = agent_app.RefundSession(RefundService([issuer.public_key], agent_app.effects),
                                    (parent.to_base64(), leaf.to_base64()), holder)
    # SDK explicitly exposes the raw original callable; skip all tool hooks.
    with pytest.raises(RefundDenied, match="[Cc]onstraint"):
        agent_app.refund_order.__wrapped__(tool_context(session), "123", 20000)
    assert agent_app.effects == []


@pytest.mark.parametrize("kind,reason", [
    ("missing", "missing authority"), ("malformed", "authority rejected"),
    ("wrong_holder", "[Ss]ignature|PoP|[Pp]roof"), ("untrusted", "trust"),
    ("wrong_capability", "tool|capability|authorized"),
    ("constraint", "constraint"), ("changed_args", "[Ss]ignature|PoP|[Pp]roof"),
    ("missing_chain", "trust|chain|parent"), ("tampered", "authority rejected"),
])
def test_receiver_denials(kind, reason):
    issuer, holder, parent, leaf = authority(
        tool="cancel_order" if kind == "wrong_capability" else "refund_order",
        ceiling=10000 if kind == "constraint" else 50000)
    roots = [SigningKey.generate().public_key] if kind == "untrusted" else [issuer.public_key]
    service = RefundService(roots, agent_app.effects)
    proof_holder = SigningKey.generate() if kind == "wrong_holder" else holder
    p = presentation(proof_holder, parent, leaf)
    args = ARGS.copy()
    if kind == "missing":
        p = None
    elif kind == "malformed":
        p = Presentation(("invalid",), b"")
    elif kind == "changed_args":
        args["amount_cents"] = 20001
    elif kind == "missing_chain":
        p = replace(p, chain=(leaf.to_base64(),))
    elif kind == "tampered":
        raw = bytearray(leaf.to_bytes())
        raw[-1] ^= 1
        import base64
        p = replace(p, chain=(parent.to_base64(), base64.b64encode(raw).decode()))
    with pytest.raises(RefundDenied, match=reason):
        service.refund_order(**args, presentation=p)
    assert agent_app.effects == []


@pytest.mark.parametrize("value", [0, -1, 50001, 490000, 2**60, True, 1.5, "20000"])
def test_receiver_amount_domain(value):
    session = agent_app.development_session()
    with pytest.raises(RefundDenied, match="argument types|outside refund policy"):
        session.service.refund_order("123", value, session.present(ARGS))
    assert agent_app.effects == []


def test_receiver_narrow_child_positive_then_widening_rejected():
    issuer, holder, parent, leaf = authority(ceiling=10000)
    args = {**ARGS, "amount_cents": 10000}
    service = RefundService([issuer.public_key], agent_app.effects)
    service.refund_order(**args, presentation=presentation(holder, parent, leaf, args))
    assert agent_app.effects == [("123", 10000)]
    agent_app.effects.clear()
    # Same working holder and envelope; only maximum is widened.
    with pytest.raises(Exception, match="[Mm]onotonic|[Aa]ttenuation|[Cc]onstraint|widen|exceed"):
        parent.grant_builder().capability("refund_order", order_id=Exact("123"),
            amount_cents=Range(min=1, max=50000)).ttl(100).terminal().grant(holder)
    assert agent_app.effects == []


@pytest.mark.asyncio
async def test_expired_receiver():
    issuer, holder, parent, leaf = authority(ttl=1)
    await asyncio.sleep(1.2)
    service = RefundService([issuer.public_key], agent_app.effects)
    with pytest.raises(RefundDenied, match="[Ee]xpir"):
        service.refund_order(**ARGS, presentation=presentation(holder, parent, leaf))
    assert agent_app.effects == []


@pytest.mark.asyncio
async def test_dispatch_uses_warrant_constraints():
    issuer, holder, parent, leaf = authority(ceiling=10000)
    session = agent_app.RefundSession(RefundService([issuer.public_key], agent_app.effects),
                                    (parent.to_base64(), leaf.to_base64()), holder)
    with pytest.raises(UserError, match="[Cc]onstraint"):
        await agent_app.run_agent([ARGS], session=session)
    assert agent_app.effects == []


@pytest.mark.asyncio
async def test_runner_without_authority():
    with pytest.raises(UserError, match="missing session authority"):
        await Runner.run(agent_app.make_agent([ARGS]), "refund", context=None)
    assert agent_app.effects == []
