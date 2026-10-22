"""Shared CLI files on real Temporal activity ingress; no LLM or Cloud."""

import shutil
import uuid
from datetime import timedelta

import pytest

pytest.importorskip("temporalio")

from temporalio import activity, workflow
from temporalio.client import Client, WorkflowFailureError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli.files import DocumentError, update_revocations
from tenuo.local_cli.workspace import Workspace
from tenuo.temporal import TenuoPluginConfig, TenuoTemporalPlugin, start_workflow_authorized, tenuo_execute_activity
from tenuo.temporal._constants import TENUO_CHAIN_HEADER
from tenuo.temporal._headers import tenuo_headers
from tenuo_core import decode_warrant_stack_base64

CALLS = []


@activity.defn(name="get_order")
async def local_lookup(order_id: str) -> str:
    CALLS.append(order_id)
    return "order ready"


@workflow.defn
class LocalLookupWorkflow:
    @workflow.run
    async def run(self, order_id: str) -> str:
        return await tenuo_execute_activity(local_lookup, args=[order_id], start_to_close_timeout=timedelta(seconds=10))


def test_local_temporal_config_requires_enforcement_and_no_issuer(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    (workspace.path / "keys/issuer.key").unlink()
    config = TenuoPluginConfig.local(workspace.path)
    assert config.require_warrant and not config.dry_run
    assert bytes(config.signing_key.public_key.to_bytes()) == bytes(workspace.public_key("agent").to_bytes())
    with pytest.raises(DocumentError):
        TenuoPluginConfig.local(workspace.path, require_warrant=False)
    (workspace.path / "keys/agent.key").unlink()
    verifier = TenuoPluginConfig.local(workspace.path, key=None)
    assert verifier.signing_key is None


def test_temporal_headers_preserve_entire_stack():
    root_key, holder = SigningKey.generate(), SigningKey.generate()
    root = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "any"}}}).mint(
        root_key, holder.public_key
    )
    child = (
        root.grant_builder()
        .capability("get_order", **root.capabilities["get_order"])
        .holder(holder.public_key)
        .ttl(600)
        .grant(holder)
    )
    headers = tenuo_headers([root, child], "agent")
    decoded = decode_warrant_stack_base64(headers[TENUO_CHAIN_HEADER].decode())
    assert [w.id for w in decoded] == [root.id, child.id]


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_a17_temporal_local_files_allow_deny_and_reload_revocation(tmp_path):
    binary = shutil.which("temporal")
    if binary is None:
        pytest.skip("install the Temporal CLI to run the local server test")
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent")
    )
    config = TenuoPluginConfig.local(workspace.path, activity_fns=[local_lookup])
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=binary)
    try:
        client = await Client.connect(
            env.client.service_client.config.target_host, plugins=[TenuoTemporalPlugin(config)]
        )
        queue = "local-cli-" + uuid.uuid4().hex
        async with Worker(
            client,
            task_queue=queue,
            workflows=[LocalLookupWorkflow],
            activities=[local_lookup],
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):

            async def start(order_id):
                handle = await start_workflow_authorized(
                    client=client,
                    workflow_run_fn=LocalLookupWorkflow.run,
                    workflow_id="local-cli-" + uuid.uuid4().hex,
                    warrant=[warrant],
                    key_id="agent",
                    args=[order_id],
                    task_queue=queue,
                    execution_timeout=timedelta(seconds=30),
                )
                return await handle.result()

            before = len(CALLS)
            assert await start("A-1001") == "order ready"
            with pytest.raises(WorkflowFailureError):
                await start("OTHER")
            update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
            with pytest.raises(WorkflowFailureError):
                await start("A-1001")
            (workspace.path / "revocations.srl").unlink()
            with pytest.raises(WorkflowFailureError):
                await start("A-1001")
            assert CALLS[before:] == ["A-1001"]
            assert (workspace.path / "receipts.jsonl").read_text().strip()
    finally:
        await env.shutdown()


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_temporal_local_observe_runs_and_records_then_refuses_a_mode_change(tmp_path):
    import json

    binary = shutil.which("temporal")
    if binary is None:
        pytest.skip("install the Temporal CLI to run the local server test")
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    warrant = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent")
    )
    config = TenuoPluginConfig.local(workspace.path, activity_fns=[local_lookup])
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=binary)
    try:
        client = await Client.connect(
            env.client.service_client.config.target_host, plugins=[TenuoTemporalPlugin(config)]
        )
        queue = "local-cli-" + uuid.uuid4().hex
        async with Worker(
            client,
            task_queue=queue,
            workflows=[LocalLookupWorkflow],
            activities=[local_lookup],
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):

            async def start(order_id):
                handle = await start_workflow_authorized(
                    client=client,
                    workflow_run_fn=LocalLookupWorkflow.run,
                    workflow_id="local-cli-" + uuid.uuid4().hex,
                    warrant=[warrant],
                    key_id="agent",
                    args=[order_id],
                    task_queue=queue,
                    execution_timeout=timedelta(seconds=30),
                )
                return await handle.result()

            before = len(CALLS)
            assert await start("A-1001") == "order ready"
            assert await start("OTHER") == "order ready"
            assert CALLS[before:] == ["A-1001", "OTHER"]
            lines = [json.loads(line) for line in (workspace.path / "observations.jsonl").read_text().splitlines()]
            assert [(line["tool"], line["decision"]) for line in lines] == [("get_order", "allow"), ("get_order", "deny")]
            assert lines[1]["args"] == {"order_id": "OTHER"}
            assert not (workspace.path / "receipts.jsonl").read_text().strip()
            workspace.set_mode("enforce")
            with pytest.raises(WorkflowFailureError):
                await start("A-1001")
            assert CALLS[before:] == ["A-1001", "OTHER"]
    finally:
        await env.shutdown()


REFUNDS = []


@activity.defn(name="refund")
async def local_refund(order_id: str, amount_cents: int) -> str:
    REFUNDS.append((order_id, amount_cents))
    return "refunded"


@workflow.defn
class LocalRefundWorkflow:
    @workflow.run
    async def run(self, order_id: str, amount_cents: int) -> str:
        return await tenuo_execute_activity(
            local_refund, args=[order_id, amount_cents], start_to_close_timeout=timedelta(seconds=10)
        )


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_temporal_gated_activity_waits_for_file_approval(tmp_path):
    import asyncio

    from tenuo.local import file_approval_handler
    from tenuo.local_cli import main

    binary = shutil.which("temporal")
    if binary is None:
        pytest.skip("install the Temporal CLI to run the local server test")
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate(
        {
            "version": 2,
            "ttl": "30m",
            "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}},
            "approvals": {
                "keys": [str(workspace.path / "keys/approver.pub")],
                "required": {"refund": {"unless": {"amount_cents": "1..5000"}}},
            },
        }
    ).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    config = TenuoPluginConfig.local(
        workspace.path, activity_fns=[local_refund], approval_handler=file_approval_handler(workspace.path)
    )
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=binary)
    try:
        client = await Client.connect(
            env.client.service_client.config.target_host, plugins=[TenuoTemporalPlugin(config)]
        )
        queue = "local-cli-" + uuid.uuid4().hex
        async with Worker(
            client,
            task_queue=queue,
            workflows=[LocalRefundWorkflow],
            activities=[local_refund],
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):
            handle = await start_workflow_authorized(
                client=client,
                workflow_run_fn=LocalRefundWorkflow.run,
                workflow_id="local-cli-" + uuid.uuid4().hex,
                warrant=[warrant],
                key_id="agent",
                args=["A-1001", 6000],
                task_queue=queue,
                execution_timeout=timedelta(seconds=60),
            )
            requests = workspace.path / "requests"
            for _ in range(100):
                if list(requests.glob("*.yaml")):
                    break
                await asyncio.sleep(0.2)
            (request,) = requests.glob("*.yaml")
            assert REFUNDS == []
            home = ["--home", str(workspace.path)]
            assert main([*home, "approval", "approve", "--file", str(request), "--yes"]) == 0
            assert await handle.result() == "refunded"
            assert REFUNDS == [("A-1001", 6000)]
    finally:
        await env.shutdown()


@pytest.mark.temporal_live
@pytest.mark.asyncio
async def test_temporal_observe_records_extra_arguments_and_unwarranted_runs(tmp_path):
    """In observe, an argument the warrant doesn't name and a workflow started
    without a warrant both run and are recorded, rather than blocked early."""
    import json

    binary = shutil.which("temporal")
    if binary is None:
        pytest.skip("install the Temporal CLI to run the local server test")
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    warrant = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"refund": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent")
    )
    config = TenuoPluginConfig.local(workspace.path, activity_fns=[local_refund])
    env = await WorkflowEnvironment.start_local(dev_server_existing_path=binary)
    try:
        client = await Client.connect(
            env.client.service_client.config.target_host, plugins=[TenuoTemporalPlugin(config)]
        )
        queue = "local-cli-" + uuid.uuid4().hex
        async with Worker(
            client,
            task_queue=queue,
            workflows=[LocalRefundWorkflow],
            activities=[local_refund],
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):
            before = len(REFUNDS)
            authorized = await start_workflow_authorized(
                client=client,
                workflow_run_fn=LocalRefundWorkflow.run,
                workflow_id="local-cli-" + uuid.uuid4().hex,
                warrant=[warrant],
                key_id="agent",
                args=["A-1001", 500],  # amount_cents isn't in the warrant
                task_queue=queue,
                execution_timeout=timedelta(seconds=30),
            )
            assert await authorized.result() == "refunded"
            plain = await client.start_workflow(
                LocalRefundWorkflow.run, args=["A-2002", 700], id="local-cli-" + uuid.uuid4().hex,
                task_queue=queue, execution_timeout=timedelta(seconds=30),
            )
            assert await plain.result() == "refunded"
            assert REFUNDS[before:] == [("A-1001", 500), ("A-2002", 700)]
            lines = [json.loads(line) for line in (workspace.path / "observations.jsonl").read_text().splitlines()]
            assert [(line["tool"], line["decision"], line["reason"]) for line in lines] == [
                ("refund", "deny", lines[0]["reason"]),
                ("refund", None, "no_warrant"),
            ]
            assert lines[0]["args"] == {"order_id": "A-1001", "amount_cents": 500}
            assert lines[1]["args"] == {"order_id": "A-2002", "amount_cents": 700}
    finally:
        await env.shutdown()
