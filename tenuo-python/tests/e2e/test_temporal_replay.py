import pytest
from datetime import timedelta

try:
    from temporalio import workflow, activity
    from temporalio.worker import Replayer, Worker
    from temporalio.testing import WorkflowEnvironment
    from temporalio.client import Client, WorkflowHistory
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
    TenuoPlugin,
    TenuoPluginConfig,
    tenuo_headers,
)
from tenuo.temporal._constants import TENUO_POP_HEADER
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


# ---------------------------------------------------------------------------
# Helpers for the tampering / rotated-root tests
# ---------------------------------------------------------------------------


async def _record_successful_run(
    signing_key: SigningKey, config: TenuoPluginConfig
) -> WorkflowHistory:
    """Run the workflow end-to-end and return the recorded history."""
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
            interceptors=[TenuoPlugin(config)],
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
            return await client_with_interceptor.get_workflow_handle(
                "replay-wf-1"
            ).fetch_history()


def _flip_pop_byte_in_history(history: WorkflowHistory) -> WorkflowHistory:
    """Return a new history where the PoP payload on the first activity-schedule
    event has one byte flipped. Raises if no PoP header is found (keeps the test
    honest — if the recording didn't carry a PoP, the scenario is meaningless).
    """
    tampered_any = False
    for event in history.events:
        attrs = event.activity_task_scheduled_event_attributes
        if attrs is None or not attrs.ByteSize():
            continue
        header = attrs.header
        if header is None:
            continue
        field = header.fields.get(TENUO_POP_HEADER)
        if field is None or not field.data:
            continue
        mutated = bytearray(field.data)
        mutated[0] ^= 0x01
        field.data = bytes(mutated)
        tampered_any = True
        break

    if not tampered_any:
        raise AssertionError(
            "No activity-task-scheduled event with a PoP header found in the "
            "captured history; cannot tamper a non-existent field."
        )
    return history


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_safety():
    """TenuoPlugin + AuthorizedWorkflow stay deterministic under Temporal Replayer."""
    signing_key = SigningKey.generate()
    config = TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: signing_key}),
        dry_run=False,
        trusted_roots=[signing_key.public_key],
        activity_fns=[write_db_activity],
    )

    history = await _record_successful_run(signing_key, config)

    replayer = Replayer(
        workflows=[ReplayTestWorkflow],
        interceptors=[TenuoPlugin(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is None, (
        f"Workflow replay failed: {replay_results.replay_failure}"
    )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_replay_fails_on_tampered_pop_header():
    """Proves the verification path runs during replay.

    Record a successful run, flip a byte in the PoP header embedded in the
    recorded history, then replay. The plugin re-verifies each activity's PoP
    on replay, so a single mutated byte must turn into a replay failure. If
    this test ever passes through with ``replay_failure is None``, the plugin
    is no longer verifying during replay.
    """
    signing_key = SigningKey.generate()
    config = TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: signing_key}),
        dry_run=False,
        trusted_roots=[signing_key.public_key],
        activity_fns=[write_db_activity],
    )

    history = await _record_successful_run(signing_key, config)
    tampered_history = _flip_pop_byte_in_history(history)

    replayer = Replayer(
        workflows=[ReplayTestWorkflow],
        interceptors=[TenuoPlugin(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        tampered_history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is not None, (
        "Replay succeeded despite a tampered PoP payload — the plugin is not "
        "verifying activity PoP signatures during replay."
    )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_replay_fails_when_trusted_root_removed():
    """Replay must fail when the recorded warrant's issuer is no longer trusted.

    Records a run signed by ``original_key`` and trusted by ``[original_key]``,
    then replays with a config trusting only a different key. The plugin must
    reject the history during replay rather than silently accepting stored
    state.
    """
    original_key = SigningKey.generate()
    recording_config = TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: original_key}),
        dry_run=False,
        trusted_roots=[original_key.public_key],
        activity_fns=[write_db_activity],
    )

    history = await _record_successful_run(original_key, recording_config)

    rotated_key = SigningKey.generate()
    replay_config = TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: original_key}),
        dry_run=False,
        # Only the rotated root is trusted; the recorded warrant's issuer is not.
        trusted_roots=[rotated_key.public_key],
        activity_fns=[write_db_activity],
    )

    replayer = Replayer(
        workflows=[ReplayTestWorkflow],
        interceptors=[TenuoPlugin(replay_config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is not None, (
        "Replay succeeded even though the recorded warrant's issuer was "
        "removed from the trusted root set — the plugin is not re-checking "
        "trust during replay."
    )
