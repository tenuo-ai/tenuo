"""Record-and-replay tests for the Tenuo Temporal integration.

These tests exercise the full live worker -> history -> Replayer cycle and
assert that workflow decisions (success AND failure) reproduce deterministically
on replay, across realistic configuration drift (trusted-root rotation, clock
boundary crossings).

Each test records a history against a real in-process Temporal server, then
replays that history in a separate ``Replayer`` instance. ``replay_failure``
being ``None`` is the load-bearing assertion: Temporal flags any non-determinism
(command sequence drift, new activity dispatches, timestamp misuse) as a replay
failure, so this is the workflow-level determinism guarantee.

Activity bodies are **not** re-executed on replay — their recorded results are
fed back to the workflow. That means these tests prove workflow-side
determinism (outbound interceptor PoP computation, command sequencing,
`workflow.now()` discipline) but do NOT exercise the activity-inbound
authorization path during replay. Activity-inbound verification happens once,
at record time; see ``test_temporal_live.py`` for that coverage.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

try:
    from temporalio import activity, workflow
    from temporalio.client import Client, WorkflowFailureError
    from temporalio.common import RetryPolicy
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Replayer, Worker
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner,
        SandboxRestrictions,
    )
except ImportError:
    pytest.skip("temporalio not installed", allow_module_level=True)

from tenuo import Subpath, Warrant
from tenuo.temporal import (
    AuthorizedWorkflow,
    KeyResolver,
    TenuoClientInterceptor,
    TenuoPluginConfig,
    TenuoWorkerInterceptor,
    tenuo_headers,
)
from tenuo.temporal.exceptions import KeyResolutionError
from tenuo_core import SigningKey

KEY_ID = "replay-test-key"
TOOL = "write_db_activity"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class DictKeyResolver(KeyResolver):
    """Pre-loaded keys: avoids os.environ access inside the workflow sandbox."""

    def __init__(self, keys: dict):
        self.keys = keys

    async def resolve(self, key_id: str):
        return self.resolve_sync(key_id)

    def resolve_sync(self, key_id: str):
        if key_id not in self.keys:
            raise KeyResolutionError(key_id=key_id)
        return self.keys[key_id]


def _tenuo_sandbox_runner() -> SandboxedWorkflowRunner:
    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo",
            "tenuo_core",
        )
    )


def _build_config(
    signing_key: SigningKey,
    *,
    trusted_roots: list,
    activity_fns: list,
) -> TenuoPluginConfig:
    return TenuoPluginConfig(
        key_resolver=DictKeyResolver({KEY_ID: signing_key}),
        dry_run=False,
        trusted_roots=trusted_roots,
        activity_fns=activity_fns,
    )


async def _record_and_fetch_history(
    *,
    env: WorkflowEnvironment,
    config: TenuoPluginConfig,
    workflow_cls,
    activities: list,
    task_queue: str,
    workflow_id: str,
    warrant: Warrant,
    arg,
    expect_failure: bool = False,
):
    """Run a workflow end-to-end and return its recorded history.

    Returns the ``WorkflowHistory`` suitable for replay. If
    ``expect_failure`` is True, the workflow is expected to raise
    ``WorkflowFailureError`` during ``execute_workflow``; this is caught so the
    test can still fetch the recorded (failed) history.
    """
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
        task_queue=task_queue,
        workflows=[workflow_cls],
        activities=activities,
        interceptors=[TenuoWorkerInterceptor(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    ):
        client_interceptor.set_headers_for_workflow(
            workflow_id,
            tenuo_headers(warrant, KEY_ID),
        )
        try:
            await client_with_interceptor.execute_workflow(
                workflow_cls.run,
                arg,
                id=workflow_id,
                task_queue=task_queue,
            )
        except WorkflowFailureError:
            if not expect_failure:
                raise

        handle = client_with_interceptor.get_workflow_handle(workflow_id)
        return await handle.fetch_history()


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------


@activity.defn
async def write_db_activity(data: str) -> str:
    return f"Wrote: {data}"


@activity.defn
async def list_directory(path: str) -> list[str]:
    # Stub: tests exercise the authorization path, not filesystem access.
    return [f"{path}/stub.txt"]


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------


@workflow.defn
class ReplayTestWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, data: str) -> str:
        return await self.execute_authorized_activity(
            write_db_activity,
            args=[data],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


@workflow.defn
class DeniedReplayWorkflow(AuthorizedWorkflow):
    """Attempts an activity whose arguments violate the warrant's Subpath constraint."""

    @workflow.run
    async def run(self, path: str) -> list[str]:
        return await self.execute_authorized_activity(
            list_directory,
            args=[path],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


@workflow.defn
class ClockBoundaryWorkflow(AuthorizedWorkflow):
    """Two activity dispatches separated by a sleep that crosses the PoP window.

    PoP windows are 30-second buckets ``(unix_now // 30) * 30``. A sleep longer
    than 30s guarantees the two dispatches land in different buckets, so the
    replayed outbound interceptor has to reproduce distinct bucket timestamps
    from ``workflow.now()`` — not from wall-clock ``time.time()``.
    """

    @workflow.run
    async def run(self, data: str) -> str:
        r1 = await self.execute_authorized_activity(
            write_db_activity,
            args=[f"{data}-1"],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        # 35s > 30s PoP bucket width, so the next activity dispatch
        # falls in a later bucket.
        await workflow.sleep(timedelta(seconds=35))
        r2 = await self.execute_authorized_activity(
            write_db_activity,
            args=[f"{data}-2"],
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        return f"{r1}|{r2}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_safety():
    """Happy-path replay: an authorized workflow replays without replay_failure."""
    signing_key = SigningKey.generate()
    config = _build_config(
        signing_key,
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
        history = await _record_and_fetch_history(
            env=env,
            config=config,
            workflow_cls=ReplayTestWorkflow,
            activities=[write_db_activity],
            task_queue=f"replay-happy-{uuid.uuid4().hex[:8]}",
            workflow_id=f"replay-happy-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            arg="test-data-123",
        )

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


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_denied_workflow():
    """Denied-workflow replay: a workflow that failed authorization at record
    time must reach the *same* failure deterministically on replay.

    Regression guard: if denial branches ever read wall-clock state or
    non-deterministic context, the original execution would complete but
    replay would crash with a mismatched command sequence.
    """
    signing_key = SigningKey.generate()
    config = _build_config(
        signing_key,
        trusted_roots=[signing_key.public_key],
        activity_fns=[list_directory],
    )
    # Warrant permits list_directory only under /allowed; we'll dispatch against /forbidden.
    warrant = (
        Warrant.mint_builder()
        .holder(signing_key.public_key)
        .capability("list_directory", path=Subpath("/allowed"))
        .ttl(3600)
        .mint(signing_key)
    )

    async with await WorkflowEnvironment.start_local() as env:
        history = await _record_and_fetch_history(
            env=env,
            config=config,
            workflow_cls=DeniedReplayWorkflow,
            activities=[list_directory],
            task_queue=f"replay-denied-{uuid.uuid4().hex[:8]}",
            workflow_id=f"replay-denied-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            arg="/forbidden",
            expect_failure=True,
        )

    replayer = Replayer(
        workflows=[DeniedReplayWorkflow],
        interceptors=[TenuoWorkerInterceptor(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is None, (
        f"Denied workflow did not replay deterministically: "
        f"{replay_results.replay_failure}"
    )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_trusted_root_rotation():
    """Rotation replay: replay with an extended trusted-root set (overlap
    with the recording root) must still complete cleanly.

    Simulates the operational scenario where a new trusted root is provisioned
    between workflow record and replay (e.g. worker redeploys with a rotated
    provider). The original root remains in the set, so previously-issued
    warrants remain verifiable; the new root is additive.
    """
    original_key = SigningKey.generate()
    rotated_key = SigningKey.generate()

    record_config = _build_config(
        original_key,
        trusted_roots=[original_key.public_key],
        activity_fns=[write_db_activity],
    )
    # Rotated config: both roots are trusted (overlap).
    replay_config = _build_config(
        original_key,
        trusted_roots=[original_key.public_key, rotated_key.public_key],
        activity_fns=[write_db_activity],
    )

    warrant = (
        Warrant.mint_builder()
        .holder(original_key.public_key)
        .capability(TOOL)
        .ttl(3600)
        .mint(original_key)
    )

    async with await WorkflowEnvironment.start_local() as env:
        history = await _record_and_fetch_history(
            env=env,
            config=record_config,
            workflow_cls=ReplayTestWorkflow,
            activities=[write_db_activity],
            task_queue=f"replay-rot-{uuid.uuid4().hex[:8]}",
            workflow_id=f"replay-rot-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            arg="rotation-data",
        )

    replayer = Replayer(
        workflows=[ReplayTestWorkflow],
        interceptors=[TenuoWorkerInterceptor(replay_config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is None, (
        f"Replay under rotated trusted-root set failed: "
        f"{replay_results.replay_failure}"
    )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_tenuo_plugin_replay_clock_boundary_crossing():
    """Clock-boundary replay: a workflow whose activity dispatches straddle a
    30-second PoP window boundary must replay deterministically.

    Uses a time-skipping test server so the in-workflow ``workflow.sleep(35s)``
    advances virtual time without burning real seconds. ``workflow.now()`` is
    replay-deterministic, so both dispatches land in the same PoP buckets on
    replay as on record — regression guard against any accidental
    ``time.time()``/``datetime.now()`` leak into the PoP path.
    """
    signing_key = SigningKey.generate()
    config = _build_config(
        signing_key,
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

    async with await WorkflowEnvironment.start_time_skipping() as env:
        history = await _record_and_fetch_history(
            env=env,
            config=config,
            workflow_cls=ClockBoundaryWorkflow,
            activities=[write_db_activity],
            task_queue=f"replay-clock-{uuid.uuid4().hex[:8]}",
            workflow_id=f"replay-clock-{uuid.uuid4().hex[:8]}",
            warrant=warrant,
            arg="clock-data",
        )

    replayer = Replayer(
        workflows=[ClockBoundaryWorkflow],
        interceptors=[TenuoWorkerInterceptor(config)],
        workflow_runner=_tenuo_sandbox_runner(),
    )
    replay_results = await replayer.replay_workflow(
        history,
        raise_on_replay_failure=False,
    )

    assert replay_results.replay_failure is None, (
        f"Clock-boundary workflow did not replay deterministically: "
        f"{replay_results.replay_failure}"
    )
