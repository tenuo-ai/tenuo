"""Pydantic activity arguments on a real Temporal server: signed by PoP like any
other argument, so a framework's context object needs no exclusion from it."""

import uuid
from datetime import timedelta
from typing import Any, List

import pytest

pytest.importorskip("temporalio")
pydantic = pytest.importorskip("pydantic")

from temporalio import activity, workflow  # noqa: E402
from temporalio.client import Client, WorkflowFailureError  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.contrib.pydantic import pydantic_data_converter  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import UnsandboxedWorkflowRunner, Worker  # noqa: E402

from tenuo import Pattern, SigningKey, Warrant  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    KeyResolver,
    TenuoClientInterceptor,
    TenuoPluginConfig,
    TenuoWorkerInterceptor,
    framework_args,
    tenuo_execute_activity,
    tenuo_headers,
)


class Route(pydantic.BaseModel):
    topic: str
    partition: int


class ToolContext(pydantic.BaseModel):
    """What a framework passes every activity: where to publish events."""

    run_id: str
    route: Route


SEEN: List[Any] = []


@activity.defn
async def search(query: str, tool_ctx: ToolContext) -> str:
    SEEN.append((query, tool_ctx))
    return f"results for {query}"


@workflow.defn
class SearchWorkflow:
    @workflow.run
    async def run(self, query: str) -> str:
        ctx = ToolContext(run_id=workflow.info().run_id, route=Route(topic="events", partition=3))
        return await tenuo_execute_activity(
            search, args=[query, ctx],
            start_to_close_timeout=timedelta(seconds=10), retry_policy=RetryPolicy(maximum_attempts=1),
        )


class Keys(KeyResolver):
    def __init__(self, keys):
        self.keys = keys

    async def resolve(self, key_id):
        return self.keys[key_id]

    def resolve_sync(self, key_id):
        return self.keys[key_id]


async def run(env, control, agent, warrant, query):
    queue, workflow_id = f"pyd-{uuid.uuid4().hex[:8]}", f"pyd-{uuid.uuid4().hex[:8]}"
    client_interceptor = TenuoClientInterceptor()
    client_interceptor.set_headers_for_workflow(workflow_id, tenuo_headers(warrant, "agent1"))
    config = TenuoPluginConfig(key_resolver=Keys({"agent1": agent}), on_denial="raise",
                               trusted_roots=[control.public_key])
    client = await Client.connect(env.client.service_client.config.target_host,
                                  interceptors=[client_interceptor], data_converter=pydantic_data_converter)
    async with Worker(client, task_queue=queue, workflows=[SearchWorkflow], activities=[search],
                      interceptors=[TenuoWorkerInterceptor(config, task_queue=queue)],
                      workflow_runner=UnsandboxedWorkflowRunner()):
        return await client.execute_workflow(SearchWorkflow.run, query, id=workflow_id, task_queue=queue,
                                             execution_timeout=timedelta(seconds=60))


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_pydantic_context_argument_is_signed_and_checked():
    control, agent = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(agent.public_key)
               .capability("search", query=Pattern("docs:*"), **framework_args("tool_ctx"))
               .ttl(3600).mint(control))
    # The context only names its route as an any-value argument; nothing else changes.
    without_ctx = (Warrant.mint_builder().holder(agent.public_key)
                   .capability("search", query=Pattern("docs:*")).ttl(3600).mint(control))
    async with await WorkflowEnvironment.start_local() as env:
        SEEN.clear()
        assert await run(env, control, agent, warrant, "docs:retry") == "results for docs:retry"
        assert SEEN[0][1].route == Route(topic="events", partition=3)
        with pytest.raises(WorkflowFailureError):
            await run(env, control, agent, warrant, "payroll:2026")
        # Closed world: a warrant that doesn't declare the framework argument refuses it.
        with pytest.raises(WorkflowFailureError):
            await run(env, control, agent, without_ctx, "docs:retry")
    assert len(SEEN) == 1


from dataclasses import dataclass  # noqa: E402


@dataclass
class Spec:
    topic: str
    limit: int


@activity.defn
async def configure(spec: Spec, labels: dict) -> str:
    SEEN.append((spec, labels))
    return "configured"


@workflow.defn
class ConfigureWorkflow:
    @workflow.run
    async def run(self, topic: str) -> str:
        return await tenuo_execute_activity(
            configure, args=[Spec(topic=topic, limit=5), {"team": "billing"}],
            start_to_close_timeout=timedelta(seconds=10), retry_policy=RetryPolicy(maximum_attempts=1),
        )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_dataclass_and_dict_arguments_are_checked_as_signed():
    control, agent = SigningKey.generate(), SigningKey.generate()
    warrant = (Warrant.mint_builder().holder(agent.public_key)
               .capability("configure", **framework_args("spec", "labels")).ttl(3600).mint(control))
    queue, workflow_id = f"pyd-{uuid.uuid4().hex[:8]}", f"pyd-{uuid.uuid4().hex[:8]}"
    client_interceptor = TenuoClientInterceptor()
    client_interceptor.set_headers_for_workflow(workflow_id, tenuo_headers(warrant, "agent1"))
    config = TenuoPluginConfig(key_resolver=Keys({"agent1": agent}), on_denial="raise",
                               trusted_roots=[control.public_key])
    async with await WorkflowEnvironment.start_local() as env:
        client = await Client.connect(env.client.service_client.config.target_host,
                                      interceptors=[client_interceptor])
        async with Worker(client, task_queue=queue, workflows=[ConfigureWorkflow], activities=[configure],
                          interceptors=[TenuoWorkerInterceptor(config, task_queue=queue)],
                          workflow_runner=UnsandboxedWorkflowRunner()):
            assert await client.execute_workflow(ConfigureWorkflow.run, "events", id=workflow_id, task_queue=queue,
                                                 execution_timeout=timedelta(seconds=60)) == "configured"
