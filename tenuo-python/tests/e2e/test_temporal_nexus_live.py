"""Live Temporal Nexus authorization smoke tests.

These tests exercise the real Temporal Nexus header boundary. They are kept
small because local Nexus endpoint support depends on the Temporal test server
version bundled by the Python SDK.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("temporalio")
pytest.importorskip("nexusrpc")

import nexusrpc  # noqa: E402
from google.protobuf.duration_pb2 import Duration  # noqa: E402
from nexusrpc import handler as nexus_handler  # noqa: E402
from temporalio import workflow  # noqa: E402
from temporalio.api.common.v1 import message_pb2 as common_pb2  # noqa: E402
from temporalio.api.nexus.v1 import message_pb2 as nexus_pb2  # noqa: E402
from temporalio.api.operatorservice.v1 import (  # noqa: E402
    request_response_pb2 as operator_pb2,
)
from temporalio.api.workflowservice.v1 import (  # noqa: E402
    request_response_pb2 as workflow_service_pb2,
)
from temporalio.client import Client, WorkflowFailureError  # noqa: E402
from temporalio.common import RetryPolicy  # noqa: E402
from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Worker  # noqa: E402
from temporalio.worker.workflow_sandbox import (  # noqa: E402
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

import tenuo  # noqa: F401, E402 - installs Warrant.mint_builder()
from tenuo_core import Exact, Range, SigningKey, Warrant  # noqa: E402

from tenuo.temporal import (  # noqa: E402
    KeyResolver,
    TenuoClientInterceptor,
    TenuoPluginConfig,
    TenuoWorkerInterceptor,
    nexus_tool_name,
    tenuo_execute_nexus_operation,
    tenuo_headers,
    tenuo_nexus_operation,
)


@dataclass
class RefundInput:
    order_id: str
    amount_cents: int


@dataclass
class RefundOutput:
    status: str


@nexusrpc.service
class BillingService:
    refund: nexusrpc.Operation[RefundInput, RefundOutput]


@workflow.defn
class NexusCallerWorkflow:
    @workflow.run
    async def run(self, endpoint: str, order_id: str, amount_cents: int) -> str:
        nexus_client = workflow.create_nexus_client(
            service=BillingService,
            endpoint=endpoint,
        )
        result = await tenuo_execute_nexus_operation(
            nexus_client,
            BillingService.refund,
            RefundInput(order_id=order_id, amount_cents=amount_cents),
            schedule_to_close_timeout=timedelta(seconds=10),
        )
        return result.status


class DictKeyResolver(KeyResolver):
    def __init__(self, keys: dict[str, Any]) -> None:
        self.keys = keys

    async def resolve(self, key_id: str) -> Any:
        return self.resolve_sync(key_id)

    def resolve_sync(self, key_id: str) -> Any:
        return self.keys[key_id]


async def _register_namespace(client: Client, namespace: str) -> None:
    retention = Duration()
    retention.FromTimedelta(timedelta(days=1))
    try:
        await client.workflow_service.register_namespace(
            workflow_service_pb2.RegisterNamespaceRequest(
                namespace=namespace,
                workflow_execution_retention_period=retention,
            )
        )
    except Exception as exc:
        message = str(exc)
        if "already exists" in message.lower():
            return
        raise


async def _create_nexus_endpoint(
    client: Client,
    *,
    endpoint_name: str,
    handler_namespace: str,
    handler_task_queue: str,
) -> tuple[str, int]:
    description = common_pb2.Payload(
        metadata={"encoding": b"json/plain"},
        data=b'"Tenuo Nexus live authorization smoke test"',
    )
    response = await client.operator_service.create_nexus_endpoint(
        operator_pb2.CreateNexusEndpointRequest(
            spec=nexus_pb2.EndpointSpec(
                name=endpoint_name,
                description=description,
                target=nexus_pb2.EndpointTarget(
                    worker=nexus_pb2.EndpointTarget.Worker(
                        namespace=handler_namespace,
                        task_queue=handler_task_queue,
                    )
                ),
            )
        )
    )
    return response.endpoint.id, response.endpoint.version


async def _delete_nexus_endpoint(client: Client, endpoint_id: str, version: int) -> None:
    await client.operator_service.delete_nexus_endpoint(
        operator_pb2.DeleteNexusEndpointRequest(id=endpoint_id, version=version)
    )


def _nexus_supported_or_skip(exc: Exception) -> None:
    message = str(exc).lower()
    if (
        "unimplemented" in message
        or "unknown service" in message
        or "nexus" in message and "disabled" in message
    ):
        pytest.skip(f"Local Temporal test server does not support Nexus setup: {exc}")
    raise exc


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_live_cross_namespace_nexus_operation_authorizes_headers() -> None:
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()

    suffix = uuid.uuid4().hex[:10]
    caller_namespace = f"tenuo-caller-{suffix}"
    handler_namespace = f"tenuo-handler-{suffix}"
    caller_task_queue = f"tenuo-caller-tq-{suffix}"
    handler_task_queue = f"tenuo-handler-tq-{suffix}"
    endpoint_name = f"tenuo-nexus-{suffix}"
    allowed_workflow_id = f"tenuo-nexus-allow-{suffix}"
    denied_workflow_id = f"tenuo-nexus-deny-{suffix}"

    async with await WorkflowEnvironment.start_local() as env:
        try:
            await _register_namespace(env.client, caller_namespace)
            await _register_namespace(env.client, handler_namespace)
            endpoint_id, endpoint_version = await _create_nexus_endpoint(
                env.client,
                endpoint_name=endpoint_name,
                handler_namespace=handler_namespace,
                handler_task_queue=handler_task_queue,
            )
        except Exception as exc:
            _nexus_supported_or_skip(exc)

        try:
            target = env.client.service_client.config.target_host
            caller_headers = TenuoClientInterceptor()
            caller_client = await Client.connect(
                target,
                namespace=caller_namespace,
                interceptors=[caller_headers],  # type: ignore[list-item]
            )
            handler_client = await Client.connect(target, namespace=handler_namespace)

            warrant = (
                Warrant.mint_builder()
                .holder(agent_key.public_key)
                .capability(
                    nexus_tool_name(
                        endpoint_name,
                        "refund",
                        service="BillingService",
                    ),
                    order_id=Exact("ord_123"),
                    amount_cents=Range(0, 5000),
                )
                .ttl(3600)
                .mint(control_key)
            )
            caller_headers.set_headers_for_workflow(
                allowed_workflow_id,
                tenuo_headers(warrant, "agent1"),
            )
            caller_headers.set_headers_for_workflow(
                denied_workflow_id,
                tenuo_headers(warrant, "agent1"),
            )
            config = TenuoPluginConfig(
                key_resolver=DictKeyResolver({"agent1": agent_key}),
                trusted_roots=[control_key.public_key],
            )

            @nexus_handler.service_handler(service=BillingService)
            class BillingServiceHandler:
                @nexus_handler.sync_operation
                @tenuo_nexus_operation(config, endpoint=endpoint_name)
                async def refund(
                    self,
                    ctx: nexus_handler.StartOperationContext,
                    input: RefundInput,
                ) -> RefundOutput:
                    return RefundOutput(status=f"refunded:{input.order_id}")

            sandbox_runner = SandboxedWorkflowRunner(
                restrictions=SandboxRestrictions.default.with_passthrough_modules(
                    "tenuo",
                    "tenuo_core",
                )
            )
            caller_interceptor = TenuoWorkerInterceptor(
                config,
                task_queue=caller_task_queue,
            )

            async with Worker(
                handler_client,
                task_queue=handler_task_queue,
                nexus_service_handlers=[BillingServiceHandler()],
            ), Worker(
                caller_client,
                task_queue=caller_task_queue,
                workflows=[NexusCallerWorkflow],
                interceptors=[caller_interceptor],
                workflow_runner=sandbox_runner,
            ):
                result = await caller_client.execute_workflow(
                    NexusCallerWorkflow.run,
                    args=[endpoint_name, "ord_123", 2500],
                    id=allowed_workflow_id,
                    task_queue=caller_task_queue,
                    execution_timeout=timedelta(seconds=20),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )
                with pytest.raises(WorkflowFailureError):
                    await caller_client.execute_workflow(
                        NexusCallerWorkflow.run,
                        args=[endpoint_name, "ord_123", 7000],
                        id=denied_workflow_id,
                        task_queue=caller_task_queue,
                        execution_timeout=timedelta(seconds=20),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )

            assert result == "refunded:ord_123"
        finally:
            try:
                await _delete_nexus_endpoint(env.client, endpoint_id, endpoint_version)
            except Exception:
                pass
