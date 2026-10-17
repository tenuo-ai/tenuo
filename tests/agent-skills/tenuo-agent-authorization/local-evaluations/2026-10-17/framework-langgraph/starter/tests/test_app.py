import agent_app
from tenuo.keys import KeyRegistry

def test_delegated_task():
    KeyRegistry.reset_instance(); agent_app.effects.clear()
    issuer, root, child = agent_app.task_authority()
    graph = agent_app.make_graph([issuer.public_key])
    agent_app.run_refund(graph, child, [root], "123", 20000)
    assert agent_app.effects == [("123", 20000)]

def test_direct_tool():
    agent_app.effects.clear()
    agent_app.refund_order.invoke({"order_id":"123", "amount_cents":20000})
    assert agent_app.effects == [("123", 20000)]
