"""Workflow refund agent. All amounts are integer USD cents; effects are fake."""
import uuid
from datetime import timedelta
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from dev_authority import TRUSTED_ROOT, authorize_refund
    from refund_security import RefundVerifier

attempts = []
effects = []
# Local demonstration root provisioned independently of request arguments.
_verifier = RefundVerifier([TRUSTED_ROOT])


@activity.defn
async def refund_order(order_id: str, amount_cents: int, framework_ctx: dict,
                       authority: dict | None = None) -> str:
    """The original callable now verifies even when invoked outside Temporal."""
    args = _verifier.verify(order_id, amount_cents, authority)
    attempts.append(activity.info().attempt)
    if framework_ctx.get("retry_once") and activity.info().attempt == 1:
        raise ApplicationError("transient failure before refund")
    effects.append((args["order_id"], args["amount_cents"]))
    return "refunded"


@workflow.defn
class RefundWorkflow:
    def __init__(self):
        self.ready = False

    @workflow.signal
    def resume(self):
        self.ready = True

    @workflow.run
    async def run(self, order_id: str, amount_cents: int, retry_once: bool,
                  pause: bool, authority: dict | None = None):
        if pause:
            await workflow.wait_condition(lambda: self.ready)
        return await workflow.execute_activity(
            refund_order,
            args=[order_id, amount_cents, {"trace_id": "demo", "retry_once": retry_once}, authority],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=2, initial_interval=timedelta(milliseconds=10)))


_AUTO_AUTHORITY = object()


async def run_refund(order_id, amount_cents, *, retry_once=False, pause=False,
                     authority=_AUTO_AUTHORITY):
    # This is the local caller's issuance path, never a verifier fallback.
    # Issue after starting the server so startup does not consume the short TTL.
    async with await WorkflowEnvironment.start_local() as env:
        if authority is _AUTO_AUTHORITY:
            authority = authorize_refund(order_id, amount_cents)
        queue = "refund-" + uuid.uuid4().hex
        async with Worker(env.client, task_queue=queue, workflows=[RefundWorkflow], activities=[refund_order]):
            handle = await env.client.start_workflow(
                RefundWorkflow.run, args=[order_id, amount_cents, retry_once, pause, authority],
                id="wf-" + uuid.uuid4().hex, task_queue=queue,
                execution_timeout=timedelta(seconds=30))
            if pause:
                await handle.signal(RefundWorkflow.resume)
            result = await handle.result()
            history = await handle.fetch_history()
        return result, history
