"""
Live tests for ``TenuoPluginConfig.unchecked_args``.

Some frameworks pass every activity an extra argument of their own (here a
pydantic context object) and dispatch activities by name. Without
``unchecked_args`` that argument can't be signed and the call fails closed.
With it, the argument is left out of PoP and the warrant check, while every
other argument is still enforced, and a request that relabels arguments to
hide one behind the unchecked name is denied.
"""

import uuid
from datetime import timedelta
from typing import Any, Optional

import pytest

pytest.importorskip("temporalio")

from pydantic import BaseModel  # noqa: E402
from temporalio import activity, workflow  # noqa: E402
from temporalio.api.common.v1 import Payload  # noqa: E402
from temporalio.client import Client, WorkflowFailureError  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.contrib.pydantic import pydantic_data_converter  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import (  # noqa: E402
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
    Worker,
)
from temporalio.worker.workflow_sandbox import (  # noqa: E402
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)
from tenuo import Exact, Range, SigningKey, Warrant  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    TemporalAuditEvent,
    TenuoClientInterceptor,
    TenuoPluginConfig,
    TenuoWorkerInterceptor,
    tenuo_headers,
)
from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER  # noqa: E402


class RoutingContext(BaseModel):
    """Plumbing a framework adds to every call: where to publish events."""

    turn_id: str
    tool_id: str


RECEIVED: list = []


@activity.defn(name="refund")
async def refund(order_id: str, amount: int, ctx: RoutingContext) -> str:
    RECEIVED.append(ctx)
    return f"refunded:{order_id}:{amount}"


@workflow.defn
class RefundByNameWorkflow:
    """Dispatches by activity NAME, with the context as the trailing argument."""

    @workflow.run
    async def run(self, order_id: str, amount: int) -> str:
        return await workflow.execute_activity(
            "refund",
            args=[order_id, amount, RoutingContext(turn_id="t1", tool_id="call-1")],
            result_type=str,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


class _RelabelArgKeys(Interceptor):
    """Rewrites x-tenuo-arg-keys before Tenuo sees it, as a tampered request would."""

    def __init__(self, keys: str) -> None:
        self._keys = keys

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        keys = self._keys

        class _Inbound(ActivityInboundInterceptor):
            async def execute_activity(self, input: ExecuteActivityInput) -> Any:
                input.headers = {
                    **input.headers,
                    TENUO_ARG_KEYS_HEADER: Payload(data=keys.encode("utf-8")),
                }
                return await self.next.execute_activity(input)

        return _Inbound(next)


ROOT = SigningKey.generate()
HOLDER = SigningKey.generate()


class _Keys:
    def resolve_sync(self, key_id: str):
        return HOLDER

    async def resolve(self, key_id: str):
        return HOLDER


def _warrant() -> Warrant:
    return (
        Warrant.mint_builder()
        .holder(HOLDER.public_key)
        .capability("refund", order_id=Exact("A-1"), amount=Range(1, 100))
        .ttl(600)
        .mint(ROOT)
    )


async def _run(
    env: WorkflowEnvironment,
    order_id: str,
    amount: int,
    *,
    unchecked: Optional[set] = None,
    relabel: Optional[str] = None,
):
    task_queue = f"unchecked-{uuid.uuid4().hex[:8]}"
    workflow_id = f"unchecked-{uuid.uuid4().hex[:8]}"
    client_interceptor = TenuoClientInterceptor()
    client_interceptor.set_headers_for_workflow(workflow_id, tenuo_headers(_warrant(), "agent"))
    events: list[TemporalAuditEvent] = []
    cfg = TenuoPluginConfig(
        key_resolver=_Keys(),
        trusted_roots=[ROOT.public_key],
        on_denial="raise",
        audit_callback=events.append,
        activity_fns=[refund],
        unchecked_args=unchecked or frozenset(),
    )
    interceptors: list = [TenuoWorkerInterceptor(cfg, task_queue=task_queue)]
    if relabel is not None:
        interceptors.insert(0, _RelabelArgKeys(relabel))  # runs before Tenuo's
    client = await Client.connect(
        env.client.service_client.config.target_host,
        interceptors=[client_interceptor],  # type: ignore[list-item]
        data_converter=pydantic_data_converter,
    )
    async with Worker(
        client,
        task_queue=task_queue,
        workflows=[RefundByNameWorkflow],
        activities=[refund],
        interceptors=interceptors,
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                "tenuo", "tenuo_core", "pydantic"
            )
        ),
    ):
        result = await client.execute_workflow(
            RefundByNameWorkflow.run,
            args=[order_id, amount],
            id=workflow_id,
            task_queue=task_queue,
            execution_timeout=timedelta(seconds=60),
        )
    return result, events


def _cause_text(exc: BaseException) -> str:
    parts, cur = [], exc
    while cur is not None:
        parts.append(str(cur))
        cur = cur.__cause__
    return " <- ".join(parts)


@pytest.mark.temporal_live
class TestUncheckedArgsLive:
    @pytest.mark.asyncio
    async def test_without_it_a_context_argument_fails_closed(self):
        async with await WorkflowEnvironment.start_local() as env:
            with pytest.raises(WorkflowFailureError) as exc:
                await _run(env, "A-1", 40)
        assert "ctx" in _cause_text(exc.value)

    @pytest.mark.asyncio
    async def test_the_context_argument_is_left_out_and_the_rest_is_checked(self):
        RECEIVED.clear()
        async with await WorkflowEnvironment.start_local() as env:
            result, events = await _run(env, "A-1", 40, unchecked={"ctx"})
        assert result == "refunded:A-1:40"
        # The activity still gets its context, unchanged.
        assert RECEIVED == [RoutingContext(turn_id="t1", tool_id="call-1")]
        assert [e.decision for e in events] == ["ALLOW"]

    @pytest.mark.asyncio
    async def test_the_other_arguments_are_still_enforced(self):
        RECEIVED.clear()
        async with await WorkflowEnvironment.start_local() as env:
            with pytest.raises(WorkflowFailureError) as exc:
                await _run(env, "B-2", 40, unchecked={"ctx"})
        assert "order_id" in _cause_text(exc.value)
        assert RECEIVED == []

    @pytest.mark.asyncio
    async def test_relabelling_an_argument_as_unchecked_is_denied(self):
        # Swap the names so the real order_id would be dropped as "ctx" and the
        # context object checked as order_id. The worker names arguments from
        # the activity's signature, so the mismatch is caught before any check.
        RECEIVED.clear()
        async with await WorkflowEnvironment.start_local() as env:
            with pytest.raises(WorkflowFailureError) as exc:
                await _run(env, "A-1", 40, unchecked={"ctx"}, relabel="ctx,amount,order_id")
        assert "don't match the activity's signature" in _cause_text(exc.value)
        assert RECEIVED == []


class TestUncheckedArgsConfig:
    def _cfg(self, unchecked):
        return TenuoPluginConfig(
            key_resolver=_Keys(), trusted_roots=[ROOT.public_key], unchecked_args=unchecked
        )

    def test_defaults_to_nothing_unchecked(self):
        cfg = TenuoPluginConfig(key_resolver=_Keys(), trusted_roots=[ROOT.public_key])
        assert cfg.unchecked_args == frozenset()

    def test_takes_any_collection_of_names(self):
        assert self._cfg(["ctx", "ctx"]).unchecked_args == frozenset({"ctx"})

    def test_rejects_a_bare_string(self):
        # A bare string would otherwise become its characters: {"c", "t", "x"}.
        with pytest.raises(ValueError, match="not a string"):
            self._cfg("ctx")

    def test_rejects_empty_names(self):
        with pytest.raises(ValueError, match="non-empty"):
            self._cfg({""})
