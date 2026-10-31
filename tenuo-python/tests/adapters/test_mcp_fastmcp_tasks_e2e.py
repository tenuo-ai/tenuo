"""
End-to-end: :class:`TenuoMiddleware` binds SEP-2663 tasks to the creating
warrant and guards ``tasks/get``/``tasks/update``/``tasks/cancel``.

Runs over FastMCP's in-memory transport. Requires FastMCP 4 with the
``fastmcp-tasks`` package (``pip install "fastmcp[tasks]"``); skipped otherwise.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional

import pytest
from tenuo_core import Authorizer, SigningKey, Warrant, sign_meta

from tenuo import Pattern
from tenuo.meta import argument_json
from tenuo.mcp.server import MCPVerifier
from tenuo.mcp.tasks import sign_task_request

pytest.importorskip("fastmcp")
pytest.importorskip("fastmcp_tasks")

from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp_tasks import TasksExtension  # noqa: E402
from fastmcp_tasks.client import call_tool_task  # noqa: E402
from fastmcp_tasks.client_models import (  # noqa: E402
    CancelTaskRequest,
    CancelTaskRequestParams,
    ClientGetTaskResult,
    GetTaskRequest,
    GetTaskRequestParams,
)
from mcp.shared.exceptions import MCPError  # noqa: E402
from mcp_types import Result  # noqa: E402

from tenuo.mcp.fastmcp_middleware import TenuoMiddleware  # noqa: E402

pytestmark = pytest.mark.asyncio


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    return Warrant.issue(
        issuer_key,
        capabilities={"crunch": {"dataset": Pattern("d*")}},
        holder=agent_key.public_key,
        ttl_seconds=600,
    )


def _server(issuer_key: SigningKey, *, require_warrant: bool = True) -> tuple[FastMCP, TenuoMiddleware]:
    verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=[issuer_key.public_key]),
        require_warrant=require_warrant,
    )
    middleware = TenuoMiddleware(verifier)
    mcp = FastMCP("tasks-test", middleware=[middleware])
    mcp.add_extension(TasksExtension())

    @mcp.tool(task=True)
    async def crunch(dataset: str) -> str:
        await asyncio.sleep(0.05)
        return f"crunched {dataset}"

    return mcp, middleware


def _call_meta(warrant: Warrant, key: SigningKey, args: Dict[str, Any]) -> Dict[str, Any]:
    return {"tenuo": sign_meta([warrant], key, "crunch", argument_json(args), int(time.time()), None)}


async def _get(client: Client, task_id: str, tenuo: Optional[Dict[str, Any]] = None) -> ClientGetTaskResult:
    meta = {"tenuo": tenuo} if tenuo is not None else None
    return await client.session.send_request(
        GetTaskRequest(params=GetTaskRequestParams(task_id=task_id, meta=meta)),
        ClientGetTaskResult,
    )


async def _get_until_done(client: Client, task_id: str, warrant: Warrant, key: SigningKey) -> ClientGetTaskResult:
    for _ in range(50):
        status = await _get(client, task_id, sign_task_request([warrant], key, "tasks/get", {"taskId": task_id}))
        if status.status in ("completed", "failed", "cancelled"):
            return status
        await asyncio.sleep(1.0)  # one PoP per second: the timestamp is the nonce
    raise AssertionError("task did not finish")


async def test_task_is_bound_and_creator_can_poll(issuer_key, agent_key, warrant) -> None:
    mcp, middleware = _server(issuer_key)
    args = {"dataset": "d1"}
    async with Client(mcp) as client:
        task = await call_tool_task(client, "crunch", args, meta=_call_meta(warrant, agent_key, args))
        binding = middleware._task_bindings.get(task.task_id)
        assert binding is not None and binding.warrant_id == warrant.id

        final = await _get_until_done(client, task.task_id, warrant, agent_key)
        assert final.status == "completed"


async def test_unsigned_task_request_is_denied(issuer_key, agent_key, warrant) -> None:
    mcp, _ = _server(issuer_key)
    args = {"dataset": "d1"}
    async with Client(mcp) as client:
        task = await call_tool_task(client, "crunch", args, meta=_call_meta(warrant, agent_key, args))
        with pytest.raises(MCPError) as exc:
            await _get(client, task.task_id)
        assert exc.value.error.code == -32001


async def test_other_holder_is_denied(issuer_key, agent_key, warrant) -> None:
    mcp, _ = _server(issuer_key)
    args = {"dataset": "d1"}
    other_key = SigningKey.generate()
    other = Warrant.issue(issuer_key, capabilities={"crunch": {}}, holder=other_key.public_key)
    async with Client(mcp) as client:
        task = await call_tool_task(client, "crunch", args, meta=_call_meta(warrant, agent_key, args))
        with pytest.raises(MCPError, match="not accessible"):
            await _get(client, task.task_id, sign_task_request([other], other_key, "tasks/get", {"taskId": task.task_id}))


async def test_cancel_requires_its_own_pop(issuer_key, agent_key, warrant) -> None:
    mcp, _ = _server(issuer_key)
    args = {"dataset": "d1"}
    async with Client(mcp) as client:
        task = await call_tool_task(client, "crunch", args, meta=_call_meta(warrant, agent_key, args))
        get_pop = sign_task_request([warrant], agent_key, "tasks/get", {"taskId": task.task_id})
        cancel = CancelTaskRequest(params=CancelTaskRequestParams(task_id=task.task_id, meta={"tenuo": get_pop}))
        with pytest.raises(MCPError, match="PoP"):
            await client.session.send_request(cancel, Result)

        cancel_pop = sign_task_request([warrant], agent_key, "tasks/cancel", {"taskId": task.task_id})
        cancel = CancelTaskRequest(params=CancelTaskRequestParams(task_id=task.task_id, meta={"tenuo": cancel_pop}))
        await client.session.send_request(cancel, Result)


async def test_denied_call_creates_no_binding(issuer_key, agent_key, warrant) -> None:
    mcp, middleware = _server(issuer_key)
    args = {"dataset": "x-not-allowed"}
    async with Client(mcp) as client:
        with pytest.raises(Exception):
            await call_tool_task(client, "crunch", args, meta=_call_meta(warrant, agent_key, args))
    assert len(middleware._task_bindings) == 0


async def test_unbound_task_passes_during_rollout(issuer_key) -> None:
    """require_warrant=False: a task created without a warrant stays reachable without one."""
    mcp, middleware = _server(issuer_key, require_warrant=False)
    async with Client(mcp) as client:
        task = await call_tool_task(client, "crunch", {"dataset": "d1"})
        assert len(middleware._task_bindings) == 0
        status = await _get(client, task.task_id)
        assert status.task_id == task.task_id
