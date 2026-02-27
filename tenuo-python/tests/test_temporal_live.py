"""
Live Temporal integration tests — runs a real in-process Temporal server.

Unlike test_temporal_e2e.py (which mocks Temporal), these tests exercise
the full serialization pipeline: Payload encoding, header propagation
through the server, sandbox passthrough, interceptor dispatch, and PoP
verification.  Any mismatch between what the client sends and what the
worker receives will surface here.

Requires: temporalio (the SDK downloads a test server binary on first run).

These tests are slower (~2-5s each) but catch the class of bugs that
unit tests with mocks fundamentally cannot:
  - Payload vs bytes encoding mismatches
  - Header propagation across client -> server -> worker boundary
  - Workflow sandbox import/passthrough issues
  - Activity dispatch to interceptors with real Temporal scheduling
  - asyncio.gather parallel PoP under real event loop scheduling
"""

import asyncio
import uuid
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("temporalio")

from temporalio import activity, workflow  # noqa: E402
from temporalio.client import Client, WorkflowFailureError  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402
from temporalio.worker.workflow_sandbox import (  # noqa: E402
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)
from tenuo_core import Pattern, Subpath  # noqa: E402

from tenuo import SigningKey, Warrant  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    AuthorizedWorkflow,
    KeyResolver,
    TemporalAuditEvent,
    TenuoClientInterceptor,
    TenuoInterceptor,
    TenuoInterceptorConfig,
    tenuo_execute_activity,
    tenuo_headers,
)

# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def echo(message: str) -> str:
    return f"echo:{message}"


@activity.defn
async def read_file(path: str) -> str:
    return Path(path).read_text()


@activity.defn
async def list_directory(path: str) -> list[str]:
    return sorted(str(p) for p in Path(path).iterdir())


# ---------------------------------------------------------------------------
# Workflows
# ---------------------------------------------------------------------------

@workflow.defn
class SequentialWorkflow:
    @workflow.run
    async def run(self, data_dir: str) -> str:
        files = await tenuo_execute_activity(
            list_directory,
            args=[data_dir],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        count = 0
        for f in files:
            if f.endswith(".txt"):
                await tenuo_execute_activity(
                    read_file,
                    args=[f],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
                count += 1
        return f"read:{count}"


@workflow.defn
class ParallelWorkflow:
    @workflow.run
    async def run(self, data_dir: str) -> str:
        no_retry = RetryPolicy(maximum_attempts=1)
        timeout = timedelta(seconds=10)

        contents = await asyncio.gather(
            tenuo_execute_activity(
                read_file, args=[f"{data_dir}/a.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
            tenuo_execute_activity(
                read_file, args=[f"{data_dir}/b.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
            tenuo_execute_activity(
                read_file, args=[f"{data_dir}/c.txt"],
                start_to_close_timeout=timeout, retry_policy=no_retry,
            ),
        )
        return f"parallel:{len(contents)}"


@workflow.defn
class AuthorizedFileWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, msg: str) -> str:
        result = await self.execute_authorized_activity(
            echo,
            args=[msg],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
        return result


@workflow.defn
class UnauthorizedPathWorkflow:
    @workflow.run
    async def run(self, path: str) -> str:
        return await tenuo_execute_activity(
            list_directory,
            args=[path],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def keys():
    control = SigningKey.generate()
    agent = SigningKey.generate()
    return control, agent


@pytest.fixture
def demo_dir(tmp_path):
    d = tmp_path / "tenuo_live"
    d.mkdir()
    (d / "a.txt").write_text("alpha")
    (d / "b.txt").write_text("bravo")
    (d / "c.txt").write_text("charlie")
    return d


@pytest.fixture
def warrant(keys, demo_dir):
    control, agent = keys
    return (
        Warrant.mint_builder()
        .holder(agent.public_key)
        .capability("echo", message=Pattern("*"))
        .capability("read_file", path=Subpath(str(demo_dir)))
        .capability("list_directory", path=Subpath(str(demo_dir)))
        .ttl(3600)
        .mint(control)
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class DictKeyResolver(KeyResolver):
    """Dictionary-based key resolver for tests (no sandbox restrictions)."""

    def __init__(self, keys: dict):
        """Initialize with pre-loaded keys."""
        self.keys = keys

    async def resolve(self, key_id: str):
        """Resolve key asynchronously."""
        return self.resolve_sync(key_id)

    def resolve_sync(self, key_id: str):
        """Resolve key synchronously without accessing os.environ."""
        if key_id not in self.keys:
            raise ValueError(f"Key {key_id} not found")
        return self.keys[key_id]


async def _run_workflow(
    env: WorkflowEnvironment,
    keys,
    warrant,
    wf_class,
    arg,
    *,
    send_headers: bool = True,
):
    """Start a worker + run a single workflow, return the result."""
    control, agent = keys
    task_queue = f"test-{uuid.uuid4().hex[:8]}"

    # Pre-load keys to avoid sandbox restrictions on os.environ
    key_dict = {"agent1": agent}

    client_interceptor = TenuoClientInterceptor()
    if send_headers:
        client_interceptor.set_headers(
            tenuo_headers(warrant, "agent1")
        )

    events: list[TemporalAuditEvent] = []

    interceptor = TenuoInterceptor(
        TenuoInterceptorConfig(
            key_resolver=DictKeyResolver(key_dict),
            on_denial="raise",
            trusted_roots=[control.public_key],
            audit_callback=events.append,
        )
    )

    sandbox_runner = SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(
            "tenuo",
            "tenuo_core",
        )
    )

    raw_client = await Client.connect(
        env.client.service_client.config.target_host,
        interceptors=[client_interceptor],  # type: ignore[list-item]
    )

    worker = Worker(
        raw_client,
        task_queue=task_queue,
        workflows=[wf_class],
        activities=[echo, read_file, list_directory],
        interceptors=[interceptor],  # type: ignore[list-item]
        workflow_runner=sandbox_runner,
    )

    async with worker:
        result = await raw_client.execute_workflow(
            wf_class.run,
            args=[arg],
            id=f"live-{uuid.uuid4().hex[:8]}",
            task_queue=task_queue,
            execution_timeout=timedelta(seconds=120),
        )

    return result, events


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.temporal_live
class TestLiveSequential:
    @pytest.mark.asyncio
    async def test_sequential_activities(self, keys, warrant, demo_dir):
        async with await WorkflowEnvironment.start_local() as env:
            result, events = await _run_workflow(
                env, keys, warrant, SequentialWorkflow, str(demo_dir),
            )
        assert result == "read:3"
        allow_events = [e for e in events if e.decision == "ALLOW"]
        assert len(allow_events) >= 4  # 1 list + 3 reads


@pytest.mark.temporal_live
class TestLiveParallel:
    @pytest.mark.asyncio
    async def test_parallel_gather(self, keys, warrant, demo_dir):
        async with await WorkflowEnvironment.start_local() as env:
            result, events = await _run_workflow(
                env, keys, warrant, ParallelWorkflow, str(demo_dir),
            )
        assert result == "parallel:3"
        allow_events = [e for e in events if e.decision == "ALLOW"]
        assert len(allow_events) == 3


@pytest.mark.temporal_live
class TestLiveAuthorizedWorkflow:
    @pytest.mark.asyncio
    async def test_authorized_workflow_happy_path(self, keys, warrant, demo_dir):
        async with await WorkflowEnvironment.start_local() as env:
            result, events = await _run_workflow(
                env, keys, warrant, AuthorizedFileWorkflow, "hello",
            )
        assert result == "echo:hello"

    @pytest.mark.asyncio
    async def test_authorized_workflow_missing_headers(self, keys, warrant, demo_dir):
        async with await WorkflowEnvironment.start_local() as env:
            with pytest.raises(WorkflowFailureError):
                await _run_workflow(
                    env, keys, warrant, AuthorizedFileWorkflow, "hello",
                    send_headers=False,
                )


@pytest.mark.temporal_live
class TestLiveDenial:
    @pytest.mark.asyncio
    async def test_out_of_scope_denied(self, keys, warrant, demo_dir):
        async with await WorkflowEnvironment.start_local() as env:
            with pytest.raises(WorkflowFailureError):
                await _run_workflow(
                    env, keys, warrant, UnauthorizedPathWorkflow, "/etc",
                )
