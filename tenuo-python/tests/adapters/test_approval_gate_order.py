"""A call the warrant does not grant is denied before any approval is requested.

The warrant allows paying one payee up to 5000 and gates amounts over 1000
behind an approval. A call to another payee, or over 5000, must be denied
without the approval handler ever running, in every adapter.
"""

import asyncio
from typing import Any, Dict, List

import pytest

from tenuo import Exact, Range, SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async, verify_inbound_call
from tenuo.approval import sign_approval

ISSUER, AGENT, APPROVER = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()

WARRANT = (
    Warrant.mint_builder()
    .capability("issue_payout", payee=Exact("ACCT-CLAIMANT"), amount=Range(0, 5000))
    .approval_gates({"issue_payout": {"amount": {"exempt": Range(0, 1000)}}})
    .required_approvers([APPROVER.public_key])
    .min_approvals(1)
    .holder(AGENT.public_key)
    .ttl(3600)
    .mint(ISSUER)
)
BOUND = WARRANT.bind(AGENT, trusted_roots=[ISSUER.public_key])
ROOTS = [ISSUER.public_key]

OUT_OF_BOUNDS = [
    pytest.param({"payee": "ACCT-ATTACKER", "amount": 48000}, id="wrong-payee-and-over-limit"),
    pytest.param({"payee": "ACCT-ATTACKER", "amount": 2500}, id="wrong-payee"),
    pytest.param({"payee": "ACCT-CLAIMANT", "amount": 9000}, id="over-limit"),
]
GATED_IN_BOUNDS = {"payee": "ACCT-CLAIMANT", "amount": 2500}


class RecordingHandler:
    """Approval handler that records every request and signs it."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []

    def __call__(self, request: Any) -> Any:
        self.requests.append(dict(request.arguments))
        return sign_approval(request, APPROVER)


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_enforce_denies_without_asking(args):
    handler = RecordingHandler()
    result = enforce_tool_call("issue_payout", args, BOUND, trusted_roots=ROOTS, approval_handler=handler)
    assert not result.allowed
    assert result.error_type == "constraint_violation"
    assert handler.requests == []


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_enforce_async_denies_without_asking(args):
    handler = RecordingHandler()
    result = asyncio.run(
        enforce_tool_call_async("issue_payout", args, BOUND, trusted_roots=ROOTS, approval_handler=handler)
    )
    assert not result.allowed
    assert result.error_type == "constraint_violation"
    assert handler.requests == []


def test_denial_names_the_argument():
    result = enforce_tool_call("issue_payout", {"payee": "ACCT-ATTACKER", "amount": 2500}, BOUND,
                               trusted_roots=ROOTS, approval_handler=RecordingHandler())
    assert not result.allowed
    assert result.constraint_violated == "payee"
    assert "payee" in (result.denial_reason or "")


def test_ungranted_tool_with_gate_denied_without_asking():
    warrant = (
        Warrant.mint_builder()
        .capability("read_file")
        .approval_gates({"delete_file": None})
        .required_approvers([APPROVER.public_key])
        .min_approvals(1)
        .holder(AGENT.public_key)
        .ttl(3600)
        .mint(ISSUER)
    )
    handler = RecordingHandler()
    result = enforce_tool_call("delete_file", {}, warrant.bind(AGENT, trusted_roots=ROOTS),
                               trusted_roots=ROOTS, approval_handler=handler)
    assert not result.allowed
    assert handler.requests == []


def test_gated_call_in_bounds_still_asks_and_is_allowed():
    handler = RecordingHandler()
    result = enforce_tool_call("issue_payout", GATED_IN_BOUNDS, BOUND, trusted_roots=ROOTS, approval_handler=handler)
    assert result.allowed
    assert handler.requests == [GATED_IN_BOUNDS]


def test_exempt_call_does_not_ask():
    handler = RecordingHandler()
    result = enforce_tool_call("issue_payout", {"payee": "ACCT-CLAIMANT", "amount": 600}, BOUND,
                               trusted_roots=ROOTS, approval_handler=handler)
    assert result.allowed
    assert handler.requests == []


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_approval_cannot_authorize_out_of_bounds_call(args):
    """Even a valid signature over the exact out-of-bounds call does not allow it."""
    captured: List[Any] = []

    def capture(request: Any) -> Any:
        captured.append(request)
        return sign_approval(request, APPROVER)

    from tenuo._enforcement import _collect_approvals_for_approval_gate

    signed = _collect_approvals_for_approval_gate(
        "issue_payout", args, BOUND, [APPROVER.public_key], 1, capture, None,
    )
    result = enforce_tool_call("issue_payout", args, BOUND, trusted_roots=ROOTS, approvals=signed)
    assert not result.allowed


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_inbound_verify_denies_without_asking(args):
    """Receiving side (Temporal, MCP server, FastAPI, A2A) uses verify_inbound_call."""
    import time

    from tenuo_core import Authorizer

    handler = RecordingHandler()
    pop = bytes(WARRANT.sign(AGENT, "issue_payout", args, int(time.time())))
    result = verify_inbound_call(
        tool_name="issue_payout", tool_args=args, warrant=WARRANT, pop_signature=pop,
        authorizer=Authorizer(trusted_roots=ROOTS), approval_handler=handler,
    )
    assert not result.allowed
    assert handler.requests == []


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_langchain_guard_denies_without_asking(args):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    from tenuo.langchain import guard

    @tool
    def issue_payout(payee: str, amount: float) -> str:
        """Pay."""
        return "PAID"

    handler = RecordingHandler()
    [guarded] = guard([issue_payout], BOUND, approval_handler=handler)
    try:
        out = guarded.invoke(args)
    except Exception as e:  # denial surfaces as an exception in this adapter
        out = e
    assert out != "PAID"
    assert handler.requests == []


@pytest.mark.parametrize("args", OUT_OF_BOUNDS)
def test_langgraph_middleware_denies_without_asking(args):
    langgraph = pytest.importorskip("tenuo.langgraph")
    if not langgraph.MIDDLEWARE_AVAILABLE:
        pytest.skip("langchain>=1.0 middleware not installed")
    from langchain_core.messages import ToolMessage

    from tenuo.keys import KeyRegistry

    KeyRegistry.get_instance().register("approval-order-test", AGENT)

    class Request:
        tool_call = {"name": "issue_payout", "args": args, "id": "call_1"}
        state = {"warrant": WARRANT}
        runtime = None

    handler = RecordingHandler()
    middleware = langgraph.TenuoMiddleware(key_id="approval-order-test", trusted_roots=ROOTS,
                                           approval_handler=handler)

    async def run_tool(request: Any) -> Any:
        return ToolMessage("PAID", tool_call_id="call_1")

    out = asyncio.run(middleware.awrap_tool_call(Request(), run_tool))
    assert getattr(out, "content", "") != "PAID"
    assert getattr(out, "status", "") == "error"
    assert handler.requests == []
