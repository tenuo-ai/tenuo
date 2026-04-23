import pytest
from datetime import timedelta

try:
    from temporalio import workflow, activity
    from temporalio.worker import Replayer, Worker
    from temporalio.testing import WorkflowEnvironment
    from temporalio.client import Client
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner,
        SandboxRestrictions,
    )
except ImportError:
    pytest.skip("temporalio not installed", allow_module_level=True)

from tenuo.temporal import (
    AuthorizedWorkflow,
    KeyResolver,
    TenuoClientInterceptor,
    TenuoWorkerInterceptor,
    TenuoPluginConfig,
    tenuo_headers,
)
from tenuo.temporal.exceptions import KeyResolutionError
from tenuo import Warrant
from tenuo_core import SigningKey

KEY_ID = "replay-test-key"
# Temporal activity type defaults to the Python function name.
TOOL = "write_db_activity"


class DictKeyResolver(KeyResolver):
    """Pre-loaded keys (same pattern as test_temporal_live — no os.environ in sandbox)."""

    def __init__(self, keys: dict):
        self.keys = keys

    async def resolve(self, key_id: str):
        return self.resolve_sync(key_id)

    def resolve_sync(self, key_id: str):
        if key_id not in self.keys:
            raise KeyResolutionError(key_id=key_id)
        return self.keys[key_id]


@activity.defn
async def write_db_activity(data: str) -> str:
    return f"Wrote: {data}"


@workflow.defn
class ReplayTestWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, data: str) -> str:
        # On replay, this should NOT execute the activity again — history supplies the result.
        return await self.execute_authorized_activity(
            write_db_activity,
            args=[data],
            start_to_close_timeout=timedelta(minutes=1),
        )


def _tenuo_sandbox_runner() -> SandboxedWorkflowRunner:
    """Same sandbox + passthrough as production examples and test_temporal_live."""
    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo",
            "tenuo_core",
        )
    )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_safety():
    """TenuoWorkerInterceptor + AuthorizedWorkflow stay deterministic under Temporal Replayer."""
    signing_key = SigningKey.generate()
    config = TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: signing_key}),
        dry_run=False,
        trusted_roots=[signing_key.public_key],
        activity_fns=[write_db_activity],
    )

    warrant = (
        Warrant.mint_builder()
        .holder(signing_key.public_key)
        .capability(TOOL)
        .ttl(3600)
        .mint(signing_key)
    )

    async with await WorkflowEnvironment.start_local() as env:
        client = env.client

        client_interceptor = TenuoClientInterceptor()
        client_with_interceptor = Client(
            client.service_client,
            namespace=client.namespace,
            data_converter=client.data_converter,
            interceptors=[client_interceptor],
        )

        async with Worker(
            client_with_interceptor,
            task_queue="replay-task-queue",
            workflows=[ReplayTestWorkflow],
            activities=[write_db_activity],
            interceptors=[TenuoWorkerInterceptor(config)],
            workflow_runner=_tenuo_sandbox_runner(),
        ):
            client_interceptor.set_headers_for_workflow(
                "replay-wf-1",
                tenuo_headers(warrant, KEY_ID),
            )
            result = await client_with_interceptor.execute_workflow(
                ReplayTestWorkflow.run,
                "test-data-123",
                id="replay-wf-1",
                task_queue="replay-task-queue",
            )
            assert result == "Wrote: test-data-123"

            wf_handle = client_with_interceptor.get_workflow_handle("replay-wf-1")
            history = await wf_handle.fetch_history()

    replayer = Replayer(
        workflows=[ReplayTestWorkflow],
        interceptors=[TenuoWorkerInterceptor(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is None, (
        f"Workflow replay failed: {replay_results.replay_failure}"
    )
