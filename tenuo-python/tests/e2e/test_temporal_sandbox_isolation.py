"""Live Temporal tests for process-wide state shared between workers.

* A plain (non-Tenuo) worker whose workflow module imports ``tenuo`` makes
  Temporal's sandbox re-import ``tenuo``. That copy must not replace the
  extension methods the host installed on the shared ``tenuo_core`` classes,
  or later Tenuo-protected activities in the same process are denied.
* ``Replayer`` with ``EnvKeyResolver`` must preload keys the same way a
  ``Worker`` does, or replay reports a false nondeterminism error.
"""

from __future__ import annotations

import base64
import sys
import uuid
from datetime import timedelta

import pytest

pytest.importorskip("temporalio")

from temporalio import activity, workflow  # noqa: E402
from temporalio.client import Client  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Replayer, Worker  # noqa: E402
from temporalio.worker.workflow_sandbox import (  # noqa: E402
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

import tenuo  # noqa: E402
from tenuo import BoundWarrant, Pattern, SigningKey, Warrant  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    AuthorizedWorkflow,
    EnvKeyResolver,
    TenuoPluginConfig,
    execute_workflow_authorized,
)
from tenuo.temporal_plugin import TenuoTemporalPlugin  # noqa: E402

pytestmark = pytest.mark.temporal_live

KEY_ID = "sandbox-isolation-agent"


@activity.defn
async def sandbox_echo(message: str) -> str:
    return f"echo:{message}"


@workflow.defn
class PlainWorkflow:
    """Unprotected workflow; reports which BoundWarrant class it sees."""

    @workflow.run
    async def run(self) -> int:
        return id(BoundWarrant)


@workflow.defn
class EchoWorkflow(AuthorizedWorkflow):
    @workflow.run
    async def run(self, message: str) -> str:
        return await self.execute_authorized_activity(
            sandbox_echo,
            args=[message],
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


def _plain_runner() -> SandboxedWorkflowRunner:
    """Default sandbox, but without the Tenuo plugin's ``tenuo`` passthrough.

    Third-party modules are passed through so optional dependencies that
    ``tenuo`` imports do not trip sandbox restrictions; ``tenuo`` itself is
    re-imported inside the sandbox, as it is for any worker without the plugin.
    """
    own = {"tenuo", "tenuo_core", __name__.split(".")[0]}
    passthrough = sorted({name.split(".")[0] for name in list(sys.modules)} - own)
    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules(*passthrough)
    )


@pytest.fixture
def keys(monkeypatch):
    control = SigningKey.generate()
    agent = SigningKey.generate()
    monkeypatch.setenv(f"TENUO_KEY_{KEY_ID}", base64.b64encode(agent.secret_key_bytes()).decode())
    return control, agent


def _warrant(control: SigningKey, agent: SigningKey) -> Warrant:
    return (
        Warrant.mint_builder()
        .holder(agent.public_key)
        .capability("sandbox_echo", message=Pattern("*"))
        .ttl(300)
        .mint(control)
    )


def _plugin(control: SigningKey) -> TenuoTemporalPlugin:
    return TenuoTemporalPlugin(
        TenuoPluginConfig(
            key_resolver=EnvKeyResolver(warn_in_production=False),
            trusted_roots=[control.public_key],
            activity_fns=[sandbox_echo],
        )
    )


async def _run_tenuo_echo(target: str, control: SigningKey, agent: SigningKey) -> tuple[Client, str, str]:
    client = await Client.connect(target, plugins=[_plugin(control)])
    task_queue = f"tenuo-{uuid.uuid4().hex[:8]}"
    workflow_id = f"echo-{uuid.uuid4().hex[:8]}"
    async with Worker(client, task_queue=task_queue, workflows=[EchoWorkflow], activities=[sandbox_echo]):
        result = await execute_workflow_authorized(
            client=client,
            workflow_run_fn=EchoWorkflow.run,
            workflow_id=workflow_id,
            warrant=_warrant(control, agent),
            key_id=KEY_ID,
            args=["hi"],
            task_queue=task_queue,
            execution_timeout=timedelta(seconds=30),
        )
    return client, workflow_id, result


@pytest.mark.asyncio
async def test_plain_worker_does_not_break_later_tenuo_worker(keys):
    control, agent = keys
    async with await WorkflowEnvironment.start_local() as env:
        target = env.client.service_client.config.target_host

        plain_client = await Client.connect(target)
        task_queue = f"plain-{uuid.uuid4().hex[:8]}"
        async with Worker(
            plain_client,
            task_queue=task_queue,
            workflows=[PlainWorkflow],
            workflow_runner=_plain_runner(),
        ):
            sandbox_cls_id = await plain_client.execute_workflow(
                PlainWorkflow.run, id=f"plain-{uuid.uuid4().hex[:8]}", task_queue=task_queue
            )
        # The plain worker really did run a separate copy of tenuo.
        assert sandbox_cls_id != id(BoundWarrant)

        # The host's extension methods are still the host's.
        assert type(_warrant(control, agent).bind(agent)) is tenuo.BoundWarrant

        _, _, result = await _run_tenuo_echo(target, control, agent)
        assert result == "echo:hi"


@pytest.mark.asyncio
async def test_replayer_preloads_env_keys(keys):
    control, agent = keys
    async with await WorkflowEnvironment.start_local() as env:
        target = env.client.service_client.config.target_host
        client, workflow_id, result = await _run_tenuo_echo(target, control, agent)
        assert result == "echo:hi"
        history = await client.get_workflow_handle(workflow_id).fetch_history()

    replay = await Replayer(workflows=[EchoWorkflow], plugins=[_plugin(control)]).replay_workflow(
        history, raise_on_replay_failure=False
    )
    assert replay.replay_failure is None, replay.replay_failure
