"""The A2A server records a warrant's jti only once the call is authorized.

Recording it before PoP and the approval gate let a denied attempt consume
it: the approval-required response burned the warrant the approved retry
needed, and a caller without the holder key could burn a copied warrant.
These tests run a real server over HTTP and record which skills executed.
"""

import base64
import contextlib
import json
import os
import socket
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

httpx = pytest.importorskip("httpx")
uvicorn = pytest.importorskip("uvicorn")

from tenuo import Pattern, Range, SigningKey, Warrant, compute_request_hash  # noqa: E402
from tenuo.a2a import A2AClient, A2AServer  # noqa: E402
from tenuo.a2a.errors import A2AError  # noqa: E402
from tenuo.approval import ApprovalRequest, sign_approval  # noqa: E402

ROOT = SigningKey.generate()
HOLDER = SigningKey.generate()
THIEF = SigningKey.generate()
APPROVER = SigningKey.generate()
SERVER_KEY = SigningKey.generate()


@contextlib.contextmanager
def _serve(*, require_pop: bool = True) -> Iterator[Tuple[str, List[Any]]]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    ran: List[Any] = []
    server = A2AServer(
        name="W",
        url=url,
        public_key=SERVER_KEY.public_key,
        trusted_issuers=[ROOT.public_key],
        require_audience=False,
        require_pop=require_pop,
        check_replay=True,
        audit_log=open(os.devnull, "w"),
    )

    @server.skill("transfer")
    async def transfer(amount: int, to: str) -> str:
        ran.append(("transfer", amount, to))
        return "sent"

    @server.skill("other")
    async def other() -> str:
        ran.append(("other",))
        return "other"

    uv = uvicorn.Server(uvicorn.Config(server.app, log_level="error"))
    thread = threading.Thread(target=uv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not uv.started and time.time() < deadline:
        time.sleep(0.02)
    try:
        yield url, ran
    finally:
        uv.should_exit = True
        thread.join(5)
        sock.close()


def _warrant(gated: bool = False) -> Any:
    builder = Warrant.mint_builder().capability("transfer", amount=Range(0, 10000), to=Pattern("*"))
    if gated:
        builder = (
            builder.approval_gates({"transfer": {"args": None, "message": "confirm"}})
            .required_approvers([APPROVER.public_key])
            .min_approvals(1)
        )
    return builder.holder(HOLDER.public_key).ttl(300).mint(ROOT)


def _approval(warrant: Any, args: Dict[str, Any]) -> Any:
    request_hash = compute_request_hash(warrant.id, "transfer", args, HOLDER.public_key)
    return sign_approval(
        ApprovalRequest(
            tool="transfer",
            arguments=args,
            warrant_id=warrant.id,
            request_hash=bytes(request_hash),
            holder_key=HOLDER.public_key,
        ),
        APPROVER,
    )


async def _post(url: str, warrant: Any, args: Dict[str, Any], approvals: Optional[List[Any]] = None) -> Dict[str, Any]:
    """Raw JSON-RPC call (A2AClient has no approvals parameter)."""
    pop = warrant.sign(HOLDER, "transfer", args, int(time.time()))
    headers = {"X-Tenuo-Warrant": warrant.to_base64(), "X-Tenuo-PoP": base64.urlsafe_b64encode(bytes(pop)).decode()}
    if approvals:
        encoded = [base64.b64encode(a.to_bytes()).decode() for a in approvals]
        headers["X-Tenuo-Approvals"] = base64.b64encode(json.dumps(encoded).encode()).decode()
    body = {"jsonrpc": "2.0", "id": 1, "method": "task/send", "params": {"task": {"skill": "transfer", "arguments": args}}}
    async with httpx.AsyncClient() as client:
        return (await client.post(url + "/a2a", json=body, headers=headers)).json()


@pytest.mark.asyncio
async def test_approval_required_response_does_not_consume_jti() -> None:
    args = {"amount": 5000, "to": "acme"}
    with _serve() as (url, ran):
        warrant = _warrant(gated=True)
        first = await _post(url, warrant, args)
        assert first["error"]["message"] == "approval_required"
        assert ran == []

        retry = await _post(url, warrant, args, [_approval(warrant, args)])
        assert retry.get("result", {}).get("output") == "sent", retry
        assert ran == [("transfer", 5000, "acme")]

        replay = await _post(url, warrant, args, [_approval(warrant, args)])
        assert replay["error"]["message"] == "replay_detected"
        assert len(ran) == 1


@pytest.mark.asyncio
async def test_bad_pop_from_another_key_does_not_burn_warrant() -> None:
    args = {"amount": 10, "to": "acme"}
    with _serve() as (url, ran):
        warrant = _warrant()
        client = A2AClient(url)
        try:
            with pytest.raises(A2AError) as stolen:
                await client.send_task("go", warrant, skill="transfer", arguments=args, signing_key=THIEF)
            assert "replay" not in str(stolen.value).lower()
            assert ran == []

            result = await client.send_task("go", warrant, skill="transfer", arguments=args, signing_key=HOLDER)
            assert result.output == "sent"
            assert ran == [("transfer", 10, "acme")]

            with pytest.raises(A2AError, match="replay"):
                await client.send_task("go", warrant, skill="transfer", arguments=args, signing_key=HOLDER)
            assert len(ran) == 1
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_constraint_denial_does_not_burn_warrant() -> None:
    with _serve() as (url, ran):
        warrant = _warrant()
        denied = await _post(url, warrant, {"amount": 999999, "to": "acme"})
        assert "error" in denied and denied["error"]["message"] != "replay_detected"
        assert ran == []
        allowed = await _post(url, warrant, {"amount": 5, "to": "acme"})
        assert allowed.get("result", {}).get("output") == "sent", allowed
        assert ran == [("transfer", 5, "acme")]


@pytest.mark.asyncio
async def test_without_pop_ungranted_skill_does_not_burn_warrant() -> None:
    with _serve(require_pop=False) as (url, ran):
        warrant = _warrant()
        client = A2AClient(url)
        try:
            with pytest.raises(A2AError) as denied:
                await client.send_task("go", warrant, skill="other", arguments={})
            assert "replay" not in str(denied.value).lower()
            assert ran == []
            result = await client.send_task("go", warrant, skill="transfer", arguments={"amount": 1, "to": "x"})
            assert result.output == "sent"
            with pytest.raises(A2AError, match="replay"):
                await client.send_task("go", warrant, skill="transfer", arguments={"amount": 1, "to": "x"})
            assert ran == [("transfer", 1, "x")]
        finally:
            await client.close()
