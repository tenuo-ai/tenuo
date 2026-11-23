# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2", "temporalio==1.34.0"]
# ///
"""Generic activity/service enforcement; starts a disposable Temporal server."""
import asyncio
import logging
import uuid
from datetime import timedelta
from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from common import Task, PaymentService, demonstrate, TransportedConstraintDenial
    from tenuo.exceptions import ConstraintViolation

service = None


@activity.defn
async def pay_invoice(args: dict, chain: list[str], proof: bytes):
    if service is None:
        raise RuntimeError("Activity service is not configured")
    try:
        return service.pay_invoice(args, chain, proof)
    except ConstraintViolation as exc:
        raise ApplicationError(str(exc), type="TaskAuthorityDenied", non_retryable=True) from exc


@workflow.defn
class InvoiceWorkflow:
    @workflow.run
    async def run(self, args: dict, chain: list[str], proof: bytes):
        # Only public warrant bytes and a call proof cross workflow history.
        return await workflow.execute_activity(pay_invoice, args=[args, chain, proof],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1))


class ExpectedDenialFilter(logging.Filter):
    def filter(self, record):
        error = record.exc_info[1] if record.exc_info else None
        return not (isinstance(error, ApplicationError) and error.type == "TaskAuthorityDenied")


async def main():
    global service
    logging.getLogger("temporalio.activity").addFilter(ExpectedDenialFilter())
    # First use can download Temporal’s CLI/server; no model key or account.
    async with await WorkflowEnvironment.start_local() as env:
        task = Task()  # Issue after startup, so download time cannot exhaust TTL.
        service = PaymentService(task.root)
        queue = "invoice-" + uuid.uuid4().hex
        async with Worker(env.client, task_queue=queue, workflows=[InvoiceWorkflow], activities=[pay_invoice]):
            async def dispatch(args):
                try:
                    await env.client.execute_workflow(InvoiceWorkflow.run,
                        args=[args, list(task.chain), task.proof(args)],
                        id=uuid.uuid4().hex, task_queue=queue,
                        execution_timeout=timedelta(seconds=20))
                except Exception as exc:
                    # Surface the actual activity denial, not just wrapper text.
                    cause = exc
                    while (getattr(cause, "cause", None) is not None
                           and not (isinstance(cause, ApplicationError) and cause.type == "TaskAuthorityDenied")):
                        cause = cause.cause
                    if isinstance(cause, ApplicationError) and cause.type == "TaskAuthorityDenied":
                        raise TransportedConstraintDenial(str(cause)) from exc
                    raise
            await demonstrate(dispatch, lambda: service.effect_count)


if __name__ == "__main__":
    asyncio.run(main())
