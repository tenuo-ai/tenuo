"""Workflow refund agent. All amounts are integer USD cents."""
import uuid
from datetime import timedelta
import pytest
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from temporalio.exceptions import ApplicationError

attempts = []
effects = []

@activity.defn
async def refund_order(order_id: str, amount_cents: int, framework_ctx: dict) -> str:
    """Refund cents. framework_ctx carries tracing and retry-test controls."""
    attempts.append(activity.info().attempt)
    if framework_ctx.get("retry_once") and activity.info().attempt == 1:
        raise ApplicationError("transient failure before refund")
    effects.append((order_id, amount_cents))
    return "refunded"

@workflow.defn
class RefundWorkflow:
    def __init__(self):
        self.ready = False
    @workflow.signal
    def resume(self):
        self.ready = True
    @workflow.run
    async def run(self, order_id: str, amount_cents: int, retry_once: bool, pause: bool):
        if pause:
            await workflow.wait_condition(lambda: self.ready)
        return await workflow.execute_activity(refund_order, args=[order_id, amount_cents, {"trace_id":"demo", "retry_once":retry_once}], start_to_close_timeout=timedelta(seconds=10), retry_policy=RetryPolicy(maximum_attempts=2, initial_interval=timedelta(milliseconds=10)))

async def run_refund(order_id, amount_cents, *, retry_once=False, pause=False):
    async with await WorkflowEnvironment.start_local() as env:
        queue = "refund-" + uuid.uuid4().hex
        async with Worker(env.client, task_queue=queue, workflows=[RefundWorkflow], activities=[refund_order]):
            handle = await env.client.start_workflow(RefundWorkflow.run, args=[order_id, amount_cents,retry_once,pause], id="wf-"+uuid.uuid4().hex, task_queue=queue, execution_timeout=timedelta(seconds=30))
            if pause:
                await handle.signal(RefundWorkflow.resume)
            result = await handle.result()
            history = await handle.fetch_history()
        return result, history
