"""Local files mediate real LangChain dispatch, including the async path."""

import json

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool

from tenuo import WarrantTemplate
from tenuo.approval import ApprovalRequired
from tenuo.langchain import TenuoTool
from tenuo.local_cli.approvals import sign_response
from tenuo.local_cli.files import load_yaml, publish, update_revocations, write_yaml
from tenuo.local_cli.warrants import encode_chain
from tenuo.local_cli.workspace import Workspace


@pytest.fixture
def local(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    data = {"version": 2, "ttl": "30m", "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}}}
    warrant = WarrantTemplate(data).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    return workspace, path, data


def test_a11_allowed_and_denied_arguments_never_reach_handler(local):
    workspace, path, _ = local
    calls = []

    @tool
    def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append((order_id, amount_cents))
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)
    assert protected.invoke({"order_id": "A-1001", "amount_cents": 5000}) == "refunded"
    for args in ({"order_id": "OTHER", "amount_cents": 5000}, {"order_id": "A-1001", "amount_cents": 12001}):
        with pytest.raises(Exception):
            protected.invoke(args)
    assert calls == [("A-1001", 5000)]
    records = [json.loads(line) for line in (workspace.path / "receipts.jsonl").read_text().splitlines()]
    assert len(records) == 3 and all(record["receipt"] for record in records)


def test_a12_reload_revocation_missing_files_and_rollback_fail_closed(local):
    workspace, path, _ = local
    calls = []

    @tool
    def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append(order_id)
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)
    args = {"order_id": "A-1001", "amount_cents": 5000}
    assert protected.invoke(args) == "refunded"
    old = (workspace.path / "revocations.srl").read_bytes()
    from tenuo.local_cli.warrants import load_chain

    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [load_chain(path)[-1].id])
    with pytest.raises(Exception):
        protected.invoke(args)
    (workspace.path / "revocations.srl").write_bytes(old)
    with pytest.raises(Exception):
        protected.invoke(args)
    (workspace.path / "revocations.srl").unlink()
    with pytest.raises(FileNotFoundError):
        protected.invoke(args)
    assert calls == ["A-1001"]


def test_a13_portable_approval_wait_retry_and_scope_are_real(local):
    workspace, path, data = local
    data["approvals"] = {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"refund": "always"}}
    warrant = WarrantTemplate(data).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    publish(path, (encode_chain([warrant]) + "\n").encode(), replace=True)
    calls = []

    @tool
    def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append(order_id)
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)
    args = {"order_id": "A-1001", "amount_cents": 6000}
    with pytest.raises(ApprovalRequired, match="approval show"):
        protected.invoke(args)
    assert calls == []
    request_path = next((workspace.path / "requests").glob("*.yaml"))
    request = load_yaml(request_path)
    response = sign_response(request, workspace.authorizer(), workspace.signing_key("approver"))
    write_yaml(workspace.path / "approvals" / request_path.name, response)
    assert protected.invoke(args) == "refunded"
    assert calls == ["A-1001"]


@pytest.mark.asyncio
async def test_async_local_tool_dispatch(local):
    workspace, path, _ = local
    calls = []

    @tool
    async def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append(order_id)
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)
    assert await protected.ainvoke({"order_id": "A-1001", "amount_cents": 5000}) == "refunded"
    with pytest.raises(Exception):
        await protected.ainvoke({"order_id": "OTHER", "amount_cents": 5000})
    assert calls == ["A-1001"]


def test_a14_langgraph_toolnode_uses_the_same_file_enforcement(local):
    pytest.importorskip("langgraph")
    from typing import TypedDict
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import ToolNode

    workspace, path, _ = local
    calls = []

    @tool
    def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append(order_id)
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)

    class State(TypedDict):
        messages: list

    builder = StateGraph(State)
    builder.add_node("tools", ToolNode([protected], handle_tool_errors=True))
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    graph = builder.compile()
    for order in ("A-1001", "OTHER"):
        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {"name": "refund", "args": {"order_id": order, "amount_cents": 5000}, "id": "call-1"}
                        ],
                    )
                ]
            }
        )
        assert result["messages"][-1].status == ("success" if order == "A-1001" else "error")
    assert calls == ["A-1001"]
