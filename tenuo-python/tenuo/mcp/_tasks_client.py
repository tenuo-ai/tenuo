"""
Client half of MCP Tasks (SEP-2663) for :class:`~tenuo.mcp.client.SecureMCPClient`.

Requires the MCP SDK 2.x (2026-07-28 protocol). The session advertises the
``io.modelcontextprotocol/tasks`` extension and claims ``resultType: "task"``
so a tasked ``tools/call`` comes back as a :class:`CreateTaskResult`. A
:class:`TenuoTask` then drives ``tasks/get``/``tasks/update``/``tasks/cancel``,
signing each request with the warrant chain and key that created the task,
which is what a :class:`~tenuo.mcp.TenuoMiddleware` server requires.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar, Dict, List, Literal, Optional

import mcp_types
from mcp.client.extension import ClaimContext, ResultClaim
from mcp_types import RequestParams, Result
from pydantic import ConfigDict, Field

from .tasks import sign_task_request

__all__ = [
    "TASKS_EXTENSION_ID",
    "CreateTaskResult",
    "GetTaskResult",
    "TenuoTask",
    "TaskInputRequired",
    "task_session_options",
]

TASKS_EXTENSION_ID = "io.modelcontextprotocol/tasks"

_TERMINAL = frozenset({"completed", "failed", "cancelled"})
# PoP timestamps have one-second resolution and identical proofs are
# replays, so never sign two task requests within the same second.
_MIN_POLL_SECONDS = 1.0


class _TaskFields(Result):
    model_config = ConfigDict(populate_by_name=True)

    task_id: str = Field(alias="taskId")
    status: Literal["working", "input_required", "completed", "failed", "cancelled"]
    status_message: Optional[str] = Field(default=None, alias="statusMessage")
    ttl_ms: Optional[int] = Field(default=None, alias="ttlMs")
    poll_interval_ms: Optional[int] = Field(default=None, alias="pollIntervalMs")


class CreateTaskResult(_TaskFields):
    """A ``tools/call`` the server chose to run as a task."""

    result_type: Literal["task"] = Field(alias="resultType")


class GetTaskResult(_TaskFields):
    """A ``tasks/get`` response. One of ``result``/``error``/``input_requests``
    is set to match ``status``."""

    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None
    input_requests: Optional[Dict[str, Any]] = Field(default=None, alias="inputRequests")


class _TaskIdParams(RequestParams):
    model_config = ConfigDict(populate_by_name=True)

    task_id: str = Field(serialization_alias="taskId")


class _UpdateParams(_TaskIdParams):
    input_responses: Dict[str, Any] = Field(serialization_alias="inputResponses")


class _GetTaskRequest(mcp_types.Request[_TaskIdParams, Literal["tasks/get"]]):
    name_param: ClassVar[Optional[str]] = "taskId"
    method: Literal["tasks/get"] = "tasks/get"
    params: _TaskIdParams


class _UpdateTaskRequest(mcp_types.Request[_UpdateParams, Literal["tasks/update"]]):
    name_param: ClassVar[Optional[str]] = "taskId"
    method: Literal["tasks/update"] = "tasks/update"
    params: _UpdateParams


class _CancelTaskRequest(mcp_types.Request[_TaskIdParams, Literal["tasks/cancel"]]):
    name_param: ClassVar[Optional[str]] = "taskId"
    method: Literal["tasks/cancel"] = "tasks/cancel"
    params: _TaskIdParams


async def _not_resolved_by_session(result: CreateTaskResult, ctx: ClaimContext) -> Any:
    raise RuntimeError("SecureMCPClient drives tasks itself")


def task_session_options() -> Dict[str, Any]:
    """``ClientSession`` keyword arguments that opt the session in to tasks."""
    return {
        "extensions": {TASKS_EXTENSION_ID: {}},
        "result_claims": {
            TASKS_EXTENSION_ID: [
                ResultClaim(
                    result_type="task",
                    model=CreateTaskResult,
                    resolve=_not_resolved_by_session,
                )
            ]
        },
    }


class TaskInputRequired(Exception):
    """The task paused for input. Answer with :meth:`TenuoTask.update`."""

    def __init__(self, task: "TenuoTask", status: GetTaskResult) -> None:
        self.task = task
        self.status = status
        super().__init__(
            f"Task {status.task_id} needs input "
            f"({', '.join(sorted(status.input_requests or {}))}); "
            "answer it with TenuoTask.update(...)"
        )


class TenuoTask:
    """Handle on a task created by :meth:`SecureMCPClient.call_tool_task`.

    Every request is signed with the warrant chain and key that created the
    task, captured at creation, so later changes to the active warrant scope
    do not affect it.
    """

    def __init__(
        self,
        session: Any,
        tool_name: str,
        created: CreateTaskResult,
        *,
        chain: Optional[List[Any]],
        key: Any,
        timeout: float = 30.0,
    ) -> None:
        self._session = session
        self.tool_name = tool_name
        self.created = created
        self._chain = chain
        self._key = key
        self._timeout = timeout
        self._last_signed = 0.0

    @property
    def task_id(self) -> str:
        return self.created.task_id

    async def _signed_meta(self, method: str, params: Dict[str, Any]) -> Any:
        """The request `_meta` with `tenuo` set, or None without a signer."""
        if not self._chain or self._key is None:
            return None
        wait = self._last_signed + _MIN_POLL_SECONDS - time.time()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_signed = time.time()
        return {"tenuo": sign_task_request(self._chain, self._key, method, params)}

    async def status(self) -> GetTaskResult:
        """Send a signed ``tasks/get``."""
        meta = await self._signed_meta("tasks/get", {"taskId": self.task_id})
        request = _GetTaskRequest(params=_TaskIdParams(task_id=self.task_id, _meta=meta))
        return await asyncio.wait_for(
            self._session.send_request(request, GetTaskResult), timeout=self._timeout
        )

    async def update(self, input_responses: Dict[str, Any]) -> None:
        """Send a signed ``tasks/update`` answering the task's ``inputRequests``."""
        body = {"taskId": self.task_id, "inputResponses": input_responses}
        meta = await self._signed_meta("tasks/update", body)
        request = _UpdateTaskRequest(
            params=_UpdateParams(task_id=self.task_id, input_responses=input_responses, _meta=meta)
        )
        await asyncio.wait_for(
            self._session.send_request(request, mcp_types.Result), timeout=self._timeout
        )

    async def cancel(self) -> None:
        """Send a signed ``tasks/cancel``. Cancellation is cooperative."""
        meta = await self._signed_meta("tasks/cancel", {"taskId": self.task_id})
        request = _CancelTaskRequest(params=_TaskIdParams(task_id=self.task_id, _meta=meta))
        await asyncio.wait_for(
            self._session.send_request(request, mcp_types.Result), timeout=self._timeout
        )

    async def wait(self, timeout: Optional[float] = None) -> GetTaskResult:
        """Poll until the task is terminal.

        Raises :class:`TaskInputRequired` when the task pauses for input and
        ``asyncio.TimeoutError`` after *timeout* seconds.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        interval = (self.created.poll_interval_ms or 1000) / 1000
        while True:
            current = await self.status()
            if current.status in _TERMINAL:
                return current
            if current.status == "input_required":
                raise TaskInputRequired(self, current)
            if current.poll_interval_ms:
                interval = current.poll_interval_ms / 1000
            delay = max(interval, _MIN_POLL_SECONDS)
            if deadline is not None and time.monotonic() + delay > deadline:
                raise asyncio.TimeoutError(f"Task {self.task_id} did not finish within {timeout}s")
            await asyncio.sleep(delay)

    async def result(self, timeout: Optional[float] = None) -> mcp_types.CallToolResult:
        """Wait for the task and return the tool's ``CallToolResult``.

        A failed or cancelled task becomes an error result, so the caller's
        ordinary ``isError`` handling applies.
        """
        final = await self.wait(timeout)
        if final.status == "completed":
            return mcp_types.CallToolResult.model_validate(final.result or {"content": []})
        if final.status == "failed":
            message = (final.error or {}).get("message") or final.status_message or "Task failed"
        else:
            message = final.status_message or f"Task {final.task_id} was cancelled"
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=str(message))],
            is_error=True,
        )
