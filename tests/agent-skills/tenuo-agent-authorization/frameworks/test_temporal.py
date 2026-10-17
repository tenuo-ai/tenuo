"""Live workflow -> activity dispatch, durable effects, retry/resume and replay.

Requires a Temporal test-server binary (SDK downloads it when not cached).
No mock activity interceptor or direct Authorizer call substitutes for dispatch.
"""

import uuid
from datetime import timedelta

import pytest
from temporalio import activity, workflow
from temporalio.client import Client, WorkflowFailureError
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

with workflow.unsafe.imports_passed_through():
    from tenuo import Range, SigningKey, Warrant
    from tenuo.temporal import (
        KeyResolver,
        TenuoClientInterceptor,
        TenuoPluginConfig,
        TenuoWorkerInterceptor,
        tenuo_execute_activity,
        tenuo_headers,
    )
    from tenuo_core import encode_warrant_stack


# The handler's attempt journal is distinct from its effect journal.
ATTEMPTS = []
EFFECTS = []


@activity.defn
async def refund(amount: int, retry: bool) -> str:
    ATTEMPTS.append(activity.info().attempt)
    if retry and activity.info().attempt == 1:
        raise ApplicationError("transient before effect")
    EFFECTS.append(amount)
    return "refunded"


@activity.defn
async def refund_with_context(amount: int, tool_ctx: dict) -> str:
    ATTEMPTS.append(activity.info().attempt)
    EFFECTS.append(amount)
    return "refunded"


@workflow.defn
class RefundWorkflow:
    def __init__(self):
        self.released = False

    @workflow.signal
    def release(self):
        self.released = True

    @workflow.run
    async def run(self, amount: int, retry: bool, pause: bool, injected: bool) -> str:
        if pause:
            await workflow.wait_condition(lambda: self.released)
        fn = refund_with_context if injected else refund
        args = [amount, {"tenant": "other"}] if injected else [amount, retry]
        return await tenuo_execute_activity(
            fn,
            args=args,
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(
                maximum_attempts=2, initial_interval=timedelta(milliseconds=10)
            ),
        )


class Keys(KeyResolver):
    def __init__(self, holder):
        self.holder = holder

    def resolve_sync(self, key_id):
        assert key_id == "holder"
        return self.holder

    async def resolve(self, key_id):
        return self.resolve_sync(key_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "allow",
        "deny",
        "delegated",
        "missing-chain",
        "retry",
        "resume-replay",
        "injected-argument",
    ],
)
async def test_workflow_effect(case):
    from tenuo import Wildcard

    ATTEMPTS.clear()
    EFFECTS.clear()
    issuer, holder, worker = [SigningKey.generate() for _ in range(3)]
    root = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=500), retry=Wildcard())
        .capability("refund_with_context", amount=Range(max=500))
        .ttl(300)
        .mint(issuer)
    )
    leaf = root
    if case in ("delegated", "missing-chain"):
        leaf = (
            root.grant_builder()
            .holder(worker.public_key)
            .capability("refund", amount=Range(max=300), retry=Wildcard())
            .ttl(120)
            .grant(holder)
        )
        holder = worker
    headers = tenuo_headers(leaf, "holder")
    if case == "delegated":
        # Existing main wire format includes the leaf; the new helper argument
        # in #836/#844 is intentionally NOT borrowed into this source lane.
        headers["x-tenuo-warrant-chain"] = encode_warrant_stack([root, leaf]).encode()
    events = []
    config = TenuoPluginConfig(
        audit_callback=events.append,
        key_resolver=Keys(holder),
        trusted_roots=[issuer.public_key],
        on_denial="raise",
        activity_fns=[refund, refund_with_context],
    )
    interceptor = TenuoWorkerInterceptor(config)
    runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo", "tenuo_core"
        )
    )
    wf_id = "skill-" + uuid.uuid4().hex
    queue = "queue-" + uuid.uuid4().hex
    client_interceptor = TenuoClientInterceptor()
    client_interceptor.set_headers_for_workflow(wf_id, headers)
    allowed = case in ("allow", "delegated", "retry", "resume-replay")
    async with await WorkflowEnvironment.start_local() as env:
        client = await Client.connect(
            env.client.service_client.config.target_host,
            interceptors=[client_interceptor],
        )
        async with Worker(
            client,
            task_queue=queue,
            workflows=[RefundWorkflow],
            activities=[refund, refund_with_context],
            interceptors=[interceptor],
            workflow_runner=runner,
        ):
            handle = await client.start_workflow(
                RefundWorkflow.run,
                args=[
                    4900 if case == "deny" else 200,
                    case == "retry",
                    case == "resume-replay",
                    case == "injected-argument",
                ],
                id=wf_id,
                task_queue=queue,
                execution_timeout=timedelta(seconds=30),
            )
            if case == "resume-replay":
                await handle.signal(RefundWorkflow.release)
            if allowed:
                assert await handle.result() == "refunded"
            else:
                with pytest.raises(WorkflowFailureError) as exc:
                    await handle.result()
                # Exclude timeout/setup failures from denial evidence.
                causes = []
                cause = exc.value
                while cause:
                    causes.append(str(cause))
                    cause = cause.__cause__
                assert any(
                    word in " ".join(causes).lower()
                    for word in (
                        "constraint",
                        "trusted",
                        "chain",
                        "pre-validation",
                        "prevalidation",
                        "not allowed",
                        "not authorized",
                    )
                )
            history = await handle.fetch_history()
    if case in ("deny", "missing-chain"):
        assert any(
            event.decision == "DENY" and event.activity_name == "refund"
            for event in events
        )
    if case == "injected-argument":
        assert events == []  # outbound structural prevalidation, not a receiver proof
    assert EFFECTS == ([200] if allowed else [])
    assert ATTEMPTS == ([1, 2] if case == "retry" else [1] if allowed else [])
    if case == "resume-replay":
        before = list(EFFECTS)
        replay = await Replayer(
            workflows=[RefundWorkflow],
            interceptors=[TenuoWorkerInterceptor(config)],
            workflow_runner=runner,
        ).replay_workflow(history, raise_on_replay_failure=False)
        assert replay.replay_failure is None
        assert EFFECTS == before  # Replayer reuses activity history, not effects.
