import time
import pytest
from langchain_core.messages import AIMessage
from tenuo import Exact, Range, SigningKey, Warrant
from tenuo.keys import KeyRegistry
import agent_app as app


@pytest.fixture(autouse=True)
def reset():
    KeyRegistry.reset_instance()
    app.effects.clear()


def dispatch(graph, chain=None, signer=None, order="123", cents=20000, signature=None, tool="refund_order", extra=None):
    args = {"order_id": order, "amount_cents": cents, **(extra or {})}
    presentation = None
    if chain is not None:
        if signature is None:
            signature = chain[-1].sign(signer, tool, args, int(time.time()))
        presentation = {"chain": [w.to_base64() for w in chain], "signature": signature}
    state = {"messages": [AIMessage(content="", tool_calls=[{"name": tool, "args": args, "id": "test"}])], "warrant": None, "warrant_chain": []}
    return graph.invoke(state, config={"configurable": {"refund_presentation": presentation}})["messages"][-1]


def root_warrant(issuer, holder, capability="refund_order", maximum=50000, ttl=120):
    return Warrant.mint_builder().holder(holder.public_key).capability(capability, order_id=Exact("123"), amount_cents=Range(min=1, max=maximum)).ttl(ttl).mint(issuer)


def denied(message, reason):
    assert message.status == "error"
    assert reason.lower() in message.content.lower()
    assert app.effects == []


def test_delegated_task_and_demo(capsys):
    issuer, root, child = app.task_authority()
    graph = app.make_graph([issuer.public_key])
    result = app.run_refund(graph, child, [root], "123", 20000)
    assert result["messages"][-1].content == "refunded"
    assert app.effects == [("123", 20000)]
    print("Task warrant: refund(order=123, amount<=500 USD)")
    print("Allowed: refund(order=123, amount=200 USD) -> effects=1")
    app.effects.clear()
    result = app.run_refund(graph, child, [root], "123", 490000)
    denied(result["messages"][-1], "ceiling")
    print("Denied: refund(order=123, amount=4900 USD) -> effects=0")


def test_direct_tool_and_underlying_callable():
    with pytest.raises(PermissionError, match="Direct refund route disabled"):
        app.refund_order.invoke({"order_id": "123", "amount_cents": 20000})
    with pytest.raises(PermissionError, match="Direct refund route disabled"):
        app.refund_order.func("123", 20000)
    assert app.effects == []


@pytest.mark.parametrize("cents", [1, 50000])
def test_allowed_edges(cents):
    issuer, root, child = app.task_authority()
    result = app.run_refund(app.make_graph([issuer.public_key]), child, [root], "123", cents)
    assert result["messages"][-1].content == "refunded"
    assert app.effects == [("123", cents)]


@pytest.mark.parametrize("order,cents", [("124", 20000), ("123", 50001), ("123", 0), ("123", -1), ("123", 2**60)])
def test_local_ceiling(order, cents):
    issuer, root, child = app.task_authority()
    denied(app.run_refund(app.make_graph([issuer.public_key]), child, [root], order, cents)["messages"][-1], "ceiling")


@pytest.mark.parametrize("cents", [True, 1.5, "20000"])
def test_no_lossy_coercion(cents):
    issuer, _, _ = app.task_authority()
    denied(dispatch(app.make_graph([issuer.public_key]), cents=cents), "valid integer")


def test_missing_and_malformed():
    issuer, _, _ = app.task_authority()
    graph = app.make_graph([issuer.public_key])
    denied(dispatch(graph), "Missing public authorization")
    state = {"messages": [AIMessage(content="", tool_calls=[{"name": "refund_order", "args": {"order_id":"123", "amount_cents":20000}, "id":"x"}])]}
    message = graph.invoke(state, config={"configurable": {"refund_presentation": {"chain":["invalid"], "signature": bytes(64)}}})["messages"][-1]
    denied(message, "Authorization denied")


def test_untrusted_wrong_holder_missing_chain():
    issuer, root, child = app.task_authority()
    worker = KeyRegistry.get_instance().get("refund-worker")
    denied(dispatch(app.make_graph([SigningKey.generate().public_key]), [root, child], worker), "trust")
    graph = app.make_graph([issuer.public_key])
    denied(dispatch(graph, [root, child], SigningKey.generate()), "signature")
    denied(dispatch(graph, [child], worker), "trust")


def test_wrong_capability_and_narrower_amount():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    graph = app.make_graph([issuer.public_key])
    wrong = root_warrant(issuer, holder, capability="cancel_order")
    denied(dispatch(graph, [wrong], holder), "refund_order")
    narrow = root_warrant(issuer, holder, maximum=10000)
    denied(dispatch(graph, [narrow], holder), "amount_cents")


def test_proof_binds_final_arguments():
    issuer, root, child = app.task_authority()
    worker = KeyRegistry.get_instance().get("refund-worker")
    proof = child.sign(worker, "refund_order", {"order_id":"123", "amount_cents":10000}, int(time.time()))
    denied(dispatch(app.make_graph([issuer.public_key]), [root, child], signature=proof), "signature")


def test_unknown_args_fail_before_effect():
    issuer, root, child = app.task_authority()
    worker = KeyRegistry.get_instance().get("refund-worker")
    # Even if the framework ignores the unknown field, it changes signed args;
    # proof verification must reject that call before the effect.
    denied(dispatch(app.make_graph([issuer.public_key]), [root, child], worker, extra={"currency":"EUR"}), "signature")


def test_expired_at_receiving_boundary():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = root_warrant(issuer, holder, ttl=1)
    graph = app.make_graph([issuer.public_key])
    time.sleep(1.1)
    denied(dispatch(graph, [warrant], holder), "expir")


def test_valid_narrow_child_then_widening_rejected():
    issuer, parent, worker = [SigningKey.generate() for _ in range(3)]
    root = root_warrant(issuer, parent)
    child = root.grant_builder().holder(worker.public_key).capability("refund_order", order_id=Exact("123"), amount_cents=Range(min=1, max=20000)).ttl(60).terminal().grant(parent)
    assert dispatch(app.make_graph([issuer.public_key]), [root, child], worker).content == "refunded"
    assert app.effects == [("123", 20000)]
    app.effects.clear()
    with pytest.raises(Exception, match="(?i)(attenuat|constraint|widen|range)"):
        root.grant_builder().holder(worker.public_key).capability("refund_order", order_id=Exact("123"), amount_cents=Range(min=1, max=50001)).ttl(60).grant(parent)
    assert app.effects == []
