"""Tests for Tenuo's Temporal Nexus authorization helpers."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("temporalio")
pytest.importorskip("nexusrpc")

import nexusrpc  # noqa: E402
import tenuo  # noqa: F401, E402 - installs Warrant.mint_builder()
from tenuo_core import Exact, Range, SigningKey, Warrant  # noqa: E402

from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._workflow import current_key_id  # noqa: E402
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._nexus import (  # noqa: E402
    TenuoNexusWorkflowEnvelope,
    nexus_input_args,
    nexus_tool_name,
    tenuo_bootstrap_nexus_workflow,
    tenuo_create_nexus_workflow_envelope,
    tenuo_execute_nexus_operation,
    tenuo_forward_nexus_authority,
    tenuo_nexus_headers,
    tenuo_nexus_operation,
    verify_nexus_operation,
)
from tenuo.temporal._state import (  # noqa: E402
    _store_lock,
    _workflow_config_store,
    _workflow_headers_store,
)
from tenuo.temporal.exceptions import TenuoContextError  # noqa: E402


@dataclass
class RefundInput:
    order_id: str
    amount_cents: int


class StaticResolver:
    def __init__(self, key: Any) -> None:
        self.key = key

    async def resolve(self, key_id: str) -> Any:
        return self.key

    def resolve_sync(self, key_id: str) -> Any:
        return self.key


class FakeNexusClient:
    endpoint = "billing-prod"
    service_name = "BillingService"

    def __init__(self) -> None:
        self.execute_call: tuple[Any, Any, dict[str, Any]] | None = None

    async def execute_operation(self, operation: Any, input: Any, **kwargs: Any) -> str:
        self.execute_call = (operation, input, kwargs)
        return "accepted"


@pytest.fixture(autouse=True)
def clean_workflow_stores() -> None:
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()
    yield
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()


@pytest.fixture
def nexus_keys() -> tuple[Any, Any]:
    return SigningKey.generate(), SigningKey.generate()


@pytest.fixture
def nexus_warrant(nexus_keys: tuple[Any, Any]) -> Any:
    root_key, agent_key = nexus_keys
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability(
            nexus_tool_name(
                "billing-prod",
                "refund",
                service="BillingService",
            ),
            order_id=Exact("ord_123"),
            amount_cents=Range(0, 5000),
        )
        .ttl(3600)
        .mint(root_key)
    )


def test_nexus_input_args_exposes_dataclass_fields() -> None:
    assert nexus_input_args(RefundInput("ord_123", 2500)) == {
        "order_id": "ord_123",
        "amount_cents": 2500,
    }


def test_tenuo_nexus_headers_round_trip_verifies_cross_namespace_operation(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    headers = tenuo_nexus_headers(
        nexus_warrant,
        "agent-key",
        agent_key,
        endpoint="billing-prod",
        service="BillingService",
        operation="refund",
        input=input,
    )
    ctx = SimpleNamespace(
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    verified = verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    assert verified.to_bytes() == nexus_warrant.to_bytes()


def test_verify_nexus_operation_rejects_wrong_operation_binding(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    headers = tenuo_nexus_headers(
        nexus_warrant,
        "agent-key",
        agent_key,
        endpoint="billing-prod",
        service="BillingService",
        operation="refund",
        input=input,
    )
    ctx = SimpleNamespace(
        service="BillingService",
        operation="capture",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="Nexus operation authorization failed"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_rejects_input_constraint_mismatch(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    signed_input = RefundInput("ord_123", 2500)
    headers = tenuo_nexus_headers(
        nexus_warrant,
        "agent-key",
        agent_key,
        endpoint="billing-prod",
        service="BillingService",
        operation="refund",
        input=signed_input,
    )
    ctx = SimpleNamespace(
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="Nexus operation authorization failed"):
        verify_nexus_operation(ctx, RefundInput("ord_999", 2500), config, endpoint="billing-prod")


async def test_tenuo_execute_nexus_operation_merges_headers_and_calls_client(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    run_key = "run-nexus-001"
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    with _store_lock:
        _workflow_headers_store[run_key] = tenuo_headers(nexus_warrant, "agent-key")
        _workflow_config_store[run_key] = config
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)

    client = FakeNexusClient()
    input = RefundInput("ord_123", 2500)
    try:
        result = await tenuo_execute_nexus_operation(
            client,
            "refund",
            input,
            headers={"x-request-id": "req-123"},
            summary="refund order",
        )
    finally:
        with _store_lock:
            _workflow_headers_store.pop(run_key, None)
            _workflow_config_store.pop(run_key, None)

    assert result == "accepted"
    assert client.execute_call is not None
    operation, called_input, kwargs = client.execute_call
    assert operation == "refund"
    assert called_input == input
    assert kwargs["summary"] == "refund order"
    assert kwargs["headers"]["x-request-id"] == "req-123"

    ctx = SimpleNamespace(
        service="BillingService",
        operation="refund",
        headers=kwargs["headers"],
    )
    verified = verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    assert verified.to_bytes() == nexus_warrant.to_bytes()


async def test_tenuo_nexus_operation_decorator_maps_denial_to_handler_error(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    class Handler:
        called = False

        @tenuo_nexus_operation(config, endpoint="billing-prod")
        async def refund(self, ctx: Any, input: RefundInput) -> str:
            self.called = True
            return "ok"

    handler = Handler()
    ctx = SimpleNamespace(
        service="BillingService",
        operation="refund",
        headers={},
    )

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await handler.refund(ctx, RefundInput("ord_123", 2500))

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert handler.called is False


def test_forward_nexus_authority_creates_bootstrap_envelope(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        service="BillingService",
        operation="refund",
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
        ),
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    envelope = tenuo_forward_nexus_authority(
        ctx,
        input,
        config,
        endpoint="billing-prod",
        workflow_id="refund-wf-001",
        workflow_type="RefundWorkflow",
    )

    assert isinstance(envelope, TenuoNexusWorkflowEnvelope)
    assert envelope.mode == "forwarded"
    assert envelope.source_operation == "refund"
    assert envelope.target_workflow_id == "refund-wf-001"


def test_create_nexus_workflow_envelope_supports_handler_minted_authority(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, handler_key = nexus_keys
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )

    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-key",
        workflow_id="refund-wf-002",
        workflow_type="RefundWorkflow",
        source_endpoint="billing-prod",
        source_service="BillingService",
        source_operation="refund",
    )

    assert envelope.mode == "minted"
    assert envelope.source_endpoint == "billing-prod"
    assert envelope.target_workflow_id == "refund-wf-002"


def test_bootstrap_nexus_workflow_installs_envelope_headers(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, handler_key = nexus_keys
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-key",
        workflow_id="refund-wf-003",
        workflow_type="RefundWorkflow",
    )
    run_key = "run-nexus-bootstrap"
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-003",
            workflow_type="RefundWorkflow",
            run_id=run_key,
        ),
    )
    with _store_lock:
        _workflow_config_store[run_key] = TenuoPluginConfig(
            key_resolver=StaticResolver(handler_key),
            trusted_roots=[root_key.public_key],
        )

    tenuo_bootstrap_nexus_workflow(envelope)

    with _store_lock:
        raw_headers = dict(_workflow_headers_store[run_key])
    assert raw_headers
    assert raw_headers["x-tenuo-key-id"] == b"handler-key"
    assert current_key_id() == "handler-key"


def test_bootstrap_nexus_workflow_rejects_wrong_workflow_id(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, handler_key = nexus_keys
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-key",
        workflow_id="refund-wf-expected",
    )
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-actual",
            workflow_type="RefundWorkflow",
            run_id="run-nexus-bootstrap-mismatch",
        ),
    )

    with pytest.raises(TenuoContextError, match="target_workflow_id mismatch"):
        tenuo_bootstrap_nexus_workflow(envelope)


def test_bootstrap_nexus_workflow_requires_worker_config(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, handler_key = nexus_keys
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-key",
        workflow_id="refund-wf-no-config",
    )
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-no-config",
            workflow_type="RefundWorkflow",
            run_id="run-nexus-no-config",
        ),
    )

    with pytest.raises(TenuoContextError, match="requires TenuoWorkerInterceptor"):
        tenuo_bootstrap_nexus_workflow(envelope)
