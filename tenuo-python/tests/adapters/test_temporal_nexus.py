"""Tests for Tenuo's Temporal Nexus authorization helpers."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable, Optional, Tuple

import pytest

pytest.importorskip("temporalio")
pytest.importorskip("nexusrpc")

import nexusrpc  # noqa: E402
import tenuo  # noqa: F401, E402 - installs Warrant.mint_builder()
from tenuo.approval import ApprovalRequest, sign_approval  # noqa: E402
from tenuo_core import Exact, Range, SigningKey, Warrant, py_compute_request_hash  # noqa: E402

from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._client import TenuoClientInterceptor  # noqa: E402
from tenuo.temporal._interceptors import (  # noqa: E402
    TenuoNexusOperationInboundInterceptor,
    TenuoWorkerInterceptor,
)
from tenuo.temporal._constants import (  # noqa: E402
    TENUO_ARG_KEYS_HEADER,
    TENUO_KEY_ID_HEADER,
)
from tenuo.temporal._dedup import _default_pop_dedup_store, _pop_dedup_cache  # noqa: E402
from tenuo.temporal._workflow import current_key_id  # noqa: E402
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._nexus import (  # noqa: E402
    TENUO_NEXUS_TOOL_HEADER,
    TenuoNexusWorkflowEnvelope,
    nexus_input_args,
    nexus_tool_name,
    tenuo_bootstrap_nexus_workflow,
    tenuo_create_nexus_workflow_envelope,
    tenuo_execute_nexus_operation,
    tenuo_forward_nexus_authority,
    tenuo_nexus_execute_update,
    tenuo_nexus_headers,
    tenuo_nexus_operation,
    tenuo_nexus_query_workflow,
    tenuo_nexus_signal_workflow,
    tenuo_nexus_start_update,
    tenuo_start_nexus_workflow,
    verify_nexus_operation,
)
from tenuo.temporal._state import (  # noqa: E402
    _store_lock,
    _workflow_config_store,
    _workflow_headers_store,
)
from tenuo.temporal.exceptions import (  # noqa: E402
    ChainValidationError,
    PopVerificationError,
    TemporalConstraintViolation,
    TenuoContextError,
)
from tenuo.exceptions import (  # noqa: E402
    ApprovalGateTriggered,
    ConstraintViolation,
    SignatureInvalid,
)


@dataclass
class RefundInput:
    order_id: str
    amount_cents: int


@dataclass
class RouterInput:
    workflow_id: str
    action: str
    value: str


class StaticResolver:
    def __init__(self, key: Any) -> None:
        self.key = key

    async def resolve(self, key_id: str) -> Any:
        return self.key

    def resolve_sync(self, key_id: str) -> Any:
        return self.key


class RecordingControlPlane:
    def __init__(self) -> None:
        self.allow_events: list[dict[str, Any]] = []
        self.deny_events: list[dict[str, Any]] = []

    def emit_for_enforcement(
        self,
        result: Any,
        chain_result: Any = None,
        *,
        latency_us: int = 0,
        request_id: Optional[str] = None,
        warrant_stack_override: Optional[str] = None,
    ) -> None:
        event = {
            "result": result,
            "chain_result": chain_result,
            "latency_us": latency_us,
            "request_id": request_id,
            "warrant_stack_override": warrant_stack_override,
        }
        if result.allowed:
            self.allow_events.append(event)
        else:
            self.deny_events.append(event)


class FailingControlPlane:
    def emit_for_enforcement(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("control plane unavailable")


class FakeNexusClient:
    endpoint = "billing-prod"
    service_name = "BillingService"

    def __init__(self) -> None:
        self.execute_call: Optional[Tuple[Any, Any, dict[str, Any]]] = None

    async def execute_operation(self, operation: Any, input: Any, **kwargs: Any) -> str:
        self.execute_call = (operation, input, kwargs)
        return "accepted"


class FakeNexusWorkflowRunContext:
    def __init__(
        self,
        *,
        headers: dict[str, str],
        request_id: str = "req-default",
        service: str = "BillingService",
        operation: str = "refund",
        fail_start: bool = False,
        on_start: Optional[Callable[[], None]] = None,
        consume_interceptor: Any = None,
    ) -> None:
        self.request_id = request_id
        self.service = service
        self.operation = operation
        self.headers = headers
        self.fail_start = fail_start
        self.on_start = on_start
        self.consume_interceptor = consume_interceptor
        self.start_calls: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    async def start_workflow(self, workflow_run_fn: Any, *args: Any, **kwargs: Any) -> str:
        self.start_calls.append((workflow_run_fn, args, kwargs))
        if self.on_start is not None:
            self.on_start()
        if self.fail_start:
            raise RuntimeError("start failed")
        workflow_id = kwargs.get("id")
        if self.consume_interceptor is not None and workflow_id:
            self.consume_interceptor.discard_headers_for_workflow(workflow_id)
        return "workflow-handle"


class FakeWorkflowHandle:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, Any, dict[str, Any]]] = []

    async def signal(self, signal: Any, arg: Any = None, **kwargs: Any) -> None:
        self.calls.append(("signal", signal, arg, kwargs))

    async def query(self, query: Any, arg: Any = None, **kwargs: Any) -> str:
        self.calls.append(("query", query, arg, kwargs))
        return "query-result"

    async def execute_update(self, update: Any, arg: Any = None, **kwargs: Any) -> str:
        self.calls.append(("execute_update", update, arg, kwargs))
        return "update-result"

    async def start_update(self, update: Any, arg: Any = None, **kwargs: Any) -> str:
        self.calls.append(("start_update", update, arg, kwargs))
        return "update-handle"


@pytest.fixture(autouse=True)
def clean_workflow_stores() -> None:
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()
        _pop_dedup_cache.clear()
        _default_pop_dedup_store._owner_cache.clear()
    yield
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()
        _pop_dedup_cache.clear()
        _default_pop_dedup_store._owner_cache.clear()


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


def _router_warrant(root_key: Any, agent_key: Any) -> Any:
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability(
            nexus_tool_name(
                "billing-prod",
                "route_signal",
                service="BillingService",
            ),
            workflow_id=Exact("refund-wf-001"),
            action=Exact("approve"),
            value=Exact("yes"),
        )
        .ttl(3600)
        .mint(root_key)
    )


def _router_ctx_and_config(
    root_key: Any,
    agent_key: Any,
    input: RouterInput,
) -> tuple[Any, Any]:
    warrant = _router_warrant(root_key, agent_key)
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="route_signal",
        headers=tenuo_nexus_headers(
            warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="route_signal",
            input=input,
        ),
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    return ctx, config


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
        request_id="req-default",
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


def test_verify_nexus_operation_emits_control_plane_allow(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    control_plane = RecordingControlPlane()
    ctx = SimpleNamespace(
        request_id="req-control-plane-allow",
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
        control_plane=control_plane,
    )

    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")

    assert len(control_plane.allow_events) == 1
    entry = control_plane.allow_events[0]
    assert entry["request_id"] == "req-control-plane-allow"
    assert entry["chain_result"] is not None
    assert entry["result"].allowed is True
    assert entry["result"].tool == nexus_tool_name(
        "billing-prod", "refund", service="BillingService"
    )
    assert entry["result"].arguments == {
        "order_id": "[REDACTED]",
        "amount_cents": "[REDACTED]",
    }


def test_verify_nexus_operation_control_plane_failure_does_not_deny_allow(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-control-plane-fails-open-for-authz",
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
        control_plane=FailingControlPlane(),
    )

    verified = verify_nexus_operation(ctx, input, config, endpoint="billing-prod")

    assert verified.to_bytes() == nexus_warrant.to_bytes()


def test_verify_nexus_operation_emits_control_plane_deny_before_reraising(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    bad_input = RefundInput("ord_999", 2500)
    control_plane = RecordingControlPlane()
    ctx = SimpleNamespace(
        request_id="req-control-plane-deny",
        service="BillingService",
        operation="refund",
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=bad_input,
        ),
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
        control_plane=control_plane,
    )

    with pytest.raises(ConstraintViolation):
        verify_nexus_operation(ctx, bad_input, config, endpoint="billing-prod")

    assert len(control_plane.deny_events) == 1
    entry = control_plane.deny_events[0]
    assert entry["request_id"] == "req-control-plane-deny"
    assert entry["warrant_stack_override"] is not None
    assert entry["result"].allowed is False
    assert entry["result"].error_type == "constraint_violation"
    assert entry["result"].arguments == {
        "order_id": "[REDACTED]",
        "amount_cents": "[REDACTED]",
    }


def test_verify_nexus_operation_rejects_missing_endpoint(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
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

    with pytest.raises(TenuoContextError, match="requires endpoint"):
        verify_nexus_operation(ctx, input, config)


def test_verify_nexus_operation_rejects_context_endpoint_mismatch(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
        endpoint="billing-staging",
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

    with pytest.raises(TenuoContextError, match="endpoint mismatch"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_emits_control_plane_deny_on_endpoint_mismatch(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    control_plane = RecordingControlPlane()
    ctx = SimpleNamespace(
        request_id="req-endpoint-mismatch",
        endpoint="billing-staging",
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
        control_plane=control_plane,
    )

    with pytest.raises(TenuoContextError, match="endpoint mismatch"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")

    assert len(control_plane.deny_events) == 1
    entry = control_plane.deny_events[0]
    assert entry["request_id"] == "req-endpoint-mismatch"
    assert entry["result"].allowed is False
    assert entry["result"].error_type == "constraint_violation"
    assert "endpoint mismatch" in entry["result"].constraint_violated


def test_verify_nexus_operation_rejects_nexus_info_endpoint_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
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
    monkeypatch.setattr(
        "temporalio.nexus.info",
        lambda: SimpleNamespace(endpoint="billing-staging"),
    )

    with pytest.raises(TenuoContextError, match="endpoint mismatch"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_rejects_missing_warrant(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers={},
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TemporalConstraintViolation, match="No warrant"):
        verify_nexus_operation(
            ctx,
            RefundInput("ord_123", 2500),
            config,
            endpoint="billing-prod",
        )


def test_verify_nexus_operation_rejects_missing_pop(
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
    headers.pop("x-tenuo-pop")
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(PopVerificationError, match="Missing PoP"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_allows_repeat_calls_by_default(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
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

    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    redelivery_ctx = SimpleNamespace(
        request_id="req-redelivery-default",
        service="BillingService",
        operation="refund",
        headers=ctx.headers,
    )
    verify_nexus_operation(redelivery_ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_strict_replay_scoped_by_request_id(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-original",
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
        nexus_pop_replay_protection=True,
    )

    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")

    replay_ctx = SimpleNamespace(
        request_id="req-replay",
        service="BillingService",
        operation="refund",
        headers=ctx.headers,
    )
    with pytest.raises(PopVerificationError, match="replay detected"):
        verify_nexus_operation(replay_ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_strict_replay_rejects_namespace_or_task_queue_drift(
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
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
        nexus_pop_replay_protection=True,
    )
    original = SimpleNamespace(
        request_id="req-bound",
        namespace="billing-prod-ns",
        task_queue="billing-tq",
        service="BillingService",
        operation="refund",
        headers=headers,
    )

    verify_nexus_operation(original, input, config, endpoint="billing-prod")
    verify_nexus_operation(original, input, config, endpoint="billing-prod")

    other_namespace = SimpleNamespace(
        request_id="req-bound",
        namespace="billing-staging-ns",
        task_queue="billing-tq",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    with pytest.raises(PopVerificationError, match="replay detected"):
        verify_nexus_operation(other_namespace, input, config, endpoint="billing-prod")

    other_queue = SimpleNamespace(
        request_id="req-bound",
        namespace="billing-prod-ns",
        task_queue="billing-tq-canary",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    with pytest.raises(PopVerificationError, match="replay detected"):
        verify_nexus_operation(other_queue, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_strict_replay_uses_nexus_info_namespace(
    monkeypatch: pytest.MonkeyPatch,
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
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
        nexus_pop_replay_protection=True,
    )
    reported = SimpleNamespace(namespace="billing-prod-ns")
    monkeypatch.setattr(
        "temporalio.nexus.info",
        lambda: SimpleNamespace(namespace=reported.namespace),
    )
    ctx = SimpleNamespace(
        request_id="req-bound",
        task_queue="billing-tq",
        service="BillingService",
        operation="refund",
        headers=headers,
    )

    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    reported.namespace = "billing-staging-ns"

    with pytest.raises(PopVerificationError, match="replay detected"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_execute_nexus_operation_rejects_reserved_header_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    run_key = "run-nexus-reserved-header"
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    with _store_lock:
        _workflow_headers_store[run_key] = tenuo_headers(nexus_warrant, "agent-key")
        _workflow_config_store[run_key] = config
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)

    with pytest.raises(TenuoContextError, match="reserved Tenuo header"):
        awaitable = tenuo_execute_nexus_operation(
            FakeNexusClient(),
            "refund",
            RefundInput("ord_123", 2500),
            headers={"X-Tenuo-Warrant": "forged"},
        )
        import asyncio

        asyncio.run(awaitable)


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
        request_id="req-default",
        service="BillingService",
        operation="capture",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="tool binding mismatch"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_rejects_missing_tool_binding_header(
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
    del headers[TENUO_NEXUS_TOOL_HEADER]
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="missing x-tenuo-tool-name"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_rejects_missing_arg_key_binding_header(
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
    del headers[TENUO_ARG_KEYS_HEADER]
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="missing x-tenuo-arg-keys"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_requires_operation_name(
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
        request_id="req-default",
        service="BillingService",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="requires operation="):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_accepts_arg_key_order_drift(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    signed_input = {"amount_cents": 2500, "order_id": "ord_123"}
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
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    verify_nexus_operation(ctx, RefundInput("ord_123", 2500), config, endpoint="billing-prod")


def test_verify_nexus_operation_rejects_arg_key_binding_mismatch(
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
    headers[TENUO_ARG_KEYS_HEADER] = base64.b64encode(
        b"order_id,total_cents"
    ).decode("ascii")
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(TenuoContextError, match="argument binding mismatch"):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_tenuo_nexus_headers_send_binding_diagnostics(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    _root_key, agent_key = nexus_keys
    headers = tenuo_nexus_headers(
        nexus_warrant,
        "agent-key",
        agent_key,
        endpoint="billing-prod",
        service="BillingService",
        operation="refund",
        input=RefundInput("ord_123", 2500),
    )

    assert base64.b64decode(headers[TENUO_NEXUS_TOOL_HEADER]).decode() == (
        "nexus:billing-prod:BillingService:refund"
    )
    assert base64.b64decode(headers[TENUO_ARG_KEYS_HEADER]).decode() == (
        "order_id,amount_cents"
    )


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
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=headers,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    with pytest.raises(SignatureInvalid):
        verify_nexus_operation(ctx, RefundInput("ord_999", 2500), config, endpoint="billing-prod")


def test_verify_nexus_operation_approval_gate_requires_approval(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    tool_name = nexus_tool_name("billing-prod", "refund", service="BillingService")
    warrant = Warrant.issue(
        keypair=root_key,
        capabilities={
            tool_name: {
                "order_id": Exact("ord_123"),
                "amount_cents": Range(0, 5000),
            }
        },
        ttl_seconds=3600,
        holder=agent_key.public_key,
        required_approvers=[root_key.public_key],
        min_approvals=1,
        approval_gates={tool_name: None},
    )
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=tenuo_nexus_headers(
            warrant,
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

    with pytest.raises(ApprovalGateTriggered):
        verify_nexus_operation(ctx, input, config, endpoint="billing-prod")


def test_verify_nexus_operation_accepts_pre_supplied_approvals(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    tool_name = nexus_tool_name("billing-prod", "refund", service="BillingService")
    args = nexus_input_args(input)
    warrant = Warrant.issue(
        keypair=root_key,
        capabilities={
            tool_name: {
                "order_id": Exact("ord_123"),
                "amount_cents": Range(0, 5000),
            }
        },
        ttl_seconds=3600,
        holder=agent_key.public_key,
        required_approvers=[root_key.public_key],
        min_approvals=1,
        approval_gates={tool_name: None},
    )
    request_hash = py_compute_request_hash(
        warrant.id,
        tool_name,
        args,
        agent_key.public_key,
    )
    approval = sign_approval(
        ApprovalRequest(
            tool=tool_name,
            arguments=args,
            warrant_id=warrant.id,
            request_hash=request_hash,
        ),
        root_key,
    )
    ctx = SimpleNamespace(
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers=tenuo_nexus_headers(
            warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
            approvals=[approval],
        ),
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )

    verified = verify_nexus_operation(ctx, input, config, endpoint="billing-prod")
    assert verified.to_bytes() == warrant.to_bytes()


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
        request_id="req-default",
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
        request_id="req-default",
        service="BillingService",
        operation="refund",
        headers={},
    )

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await handler.refund(ctx, RefundInput("ord_123", 2500))

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert handler.called is False


async def test_tenuo_nexus_operation_wraps_plain_function_handlers(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    ctx = SimpleNamespace(
        request_id="req-default",
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

    @tenuo_nexus_operation(config, endpoint="billing-prod")
    async def refund(ctx: Any, input: RefundInput) -> str:
        return f"{ctx.operation}:{input.order_id}"

    assert await refund(ctx, input) == "refund:ord_123"


async def test_nexus_signal_workflow_verifies_before_signaling(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    input = RouterInput("refund-wf-001", "approve", "yes")
    ctx, config = _router_ctx_and_config(root_key, agent_key, input)
    handle = FakeWorkflowHandle()

    await tenuo_nexus_signal_workflow(
        ctx,
        input,
        config,
        handle,
        "approve",
        "yes",
        endpoint="billing-prod",
        rpc_metadata={"x-request-id": "req-123"},
    )

    assert handle.calls == [
        (
            "signal",
            "approve",
            "yes",
            {"args": (), "rpc_metadata": {"x-request-id": "req-123"}},
        )
    ]


async def test_nexus_signal_workflow_denial_does_not_signal(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    signed_input = RouterInput("refund-wf-001", "approve", "yes")
    ctx, config = _router_ctx_and_config(root_key, agent_key, signed_input)
    handle = FakeWorkflowHandle()

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await tenuo_nexus_signal_workflow(
            ctx,
            RouterInput("refund-wf-999", "approve", "yes"),
            config,
            handle,
            "approve",
            "yes",
            endpoint="billing-prod",
        )

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert handle.calls == []


async def test_nexus_query_and_update_helpers_preserve_sdk_kwargs(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    input = RouterInput("refund-wf-001", "approve", "yes")
    ctx, config = _router_ctx_and_config(root_key, agent_key, input)
    handle = FakeWorkflowHandle()

    query_result = await tenuo_nexus_query_workflow(
        ctx,
        input,
        config,
        handle,
        "status",
        endpoint="billing-prod",
        result_type=str,
    )
    ctx, config = _router_ctx_and_config(root_key, agent_key, input)
    update_result = await tenuo_nexus_execute_update(
        ctx,
        input,
        config,
        handle,
        "approve",
        "yes",
        endpoint="billing-prod",
        id="update-001",
        result_type=str,
    )
    ctx, config = _router_ctx_and_config(root_key, agent_key, input)
    update_handle = await tenuo_nexus_start_update(
        ctx,
        input,
        config,
        handle,
        "approve",
        "yes",
        endpoint="billing-prod",
        wait_for_stage=object(),
    )

    assert query_result == "query-result"
    assert update_result == "update-result"
    assert update_handle == "update-handle"
    assert handle.calls[0] == (
        "query",
        "status",
        None,
        {"args": (), "result_type": str, "rpc_metadata": {}},
    )
    assert handle.calls[1] == (
        "execute_update",
        "approve",
        "yes",
        {"args": (), "id": "update-001", "result_type": str, "rpc_metadata": {}},
    )
    assert handle.calls[2][0:3] == ("start_update", "approve", "yes")
    assert "wait_for_stage" in handle.calls[2][3]


async def test_nexus_query_workflow_denial_raises_nexus_unauthorized(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    signed_input = RouterInput("refund-wf-001", "approve", "yes")
    ctx, config = _router_ctx_and_config(root_key, agent_key, signed_input)
    handle = FakeWorkflowHandle()

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await tenuo_nexus_query_workflow(
            ctx,
            RouterInput("refund-wf-999", "approve", "yes"),
            config,
            handle,
            "status",
            endpoint="billing-prod",
        )

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert handle.calls == []


async def test_nexus_execute_update_denial_raises_nexus_unauthorized(
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, agent_key = nexus_keys
    signed_input = RouterInput("refund-wf-001", "approve", "yes")
    ctx, config = _router_ctx_and_config(root_key, agent_key, signed_input)
    handle = FakeWorkflowHandle()

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await tenuo_nexus_execute_update(
            ctx,
            RouterInput("refund-wf-999", "approve", "yes"),
            config,
            handle,
            "approve",
            "yes",
            endpoint="billing-prod",
        )

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert handle.calls == []


def test_forward_nexus_authority_creates_bootstrap_envelope(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
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


def test_forward_nexus_authority_requires_workflow_id(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-default",
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

    with pytest.raises(TenuoContextError, match="requires workflow_id"):
        tenuo_forward_nexus_authority(ctx, input, config, endpoint="billing-prod")


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


def test_create_nexus_workflow_envelope_requires_workflow_id(
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

    with pytest.raises(TenuoContextError, match="requires workflow_id"):
        tenuo_create_nexus_workflow_envelope(workflow_warrant, "handler-key")


async def test_start_nexus_workflow_binds_headers_and_starts_backing_workflow(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    handler_key = SigningKey.generate()
    input = RefundInput("ord_123", 2500)
    ctx = FakeNexusWorkflowRunContext(
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
        )
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("RefundWorkflow", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    client_interceptor = TenuoClientInterceptor()
    ctx.consume_interceptor = client_interceptor

    result = await tenuo_start_nexus_workflow(
        ctx,
        input,
        config,
        client_interceptor,
        "RefundWorkflow.run",
        RouterInput("refund-wf-ambient", "refund", "ord_123"),
        workflow_id="refund-wf-ambient",
        workflow_warrant=workflow_warrant,
        workflow_key_id="handler-key",
        endpoint="billing-prod",
    )

    assert result == "workflow-handle"
    assert ctx.start_calls == [
        (
            "RefundWorkflow.run",
            (RouterInput("refund-wf-ambient", "refund", "ord_123"),),
            {"id": "refund-wf-ambient"},
        )
    ]
    assert "refund-wf-ambient" not in client_interceptor._headers_by_workflow_id


async def test_start_nexus_workflow_does_not_start_when_nexus_verification_fails(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    handler_key = SigningKey.generate()
    signed_input = RefundInput("ord_123", 2500)
    ctx = FakeNexusWorkflowRunContext(
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=signed_input,
        )
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("RefundWorkflow", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    client_interceptor = TenuoClientInterceptor()

    with pytest.raises(nexusrpc.HandlerError) as exc:
        await tenuo_start_nexus_workflow(
            ctx,
            RefundInput("ord_999", 2500),
            config,
            client_interceptor,
            "RefundWorkflow.run",
            workflow_id="refund-wf-denied",
            workflow_warrant=workflow_warrant,
            workflow_key_id="handler-key",
            endpoint="billing-prod",
        )

    assert exc.value.type == nexusrpc.HandlerErrorType.UNAUTHORIZED
    assert ctx.start_calls == []
    assert "refund-wf-denied" not in client_interceptor._headers_by_workflow_id


async def test_start_nexus_workflow_discards_pending_headers_when_start_fails(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    handler_key = SigningKey.generate()
    input = RefundInput("ord_123", 2500)
    ctx = FakeNexusWorkflowRunContext(
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
        ),
        fail_start=True,
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("RefundWorkflow", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    client_interceptor = TenuoClientInterceptor()

    with pytest.raises(RuntimeError, match="start failed"):
        await tenuo_start_nexus_workflow(
            ctx,
            input,
            config,
            client_interceptor,
            "RefundWorkflow.run",
            workflow_id="refund-wf-failed-start",
            workflow_warrant=workflow_warrant,
            workflow_key_id="handler-key",
            endpoint="billing-prod",
        )

    assert "refund-wf-failed-start" not in client_interceptor._headers_by_workflow_id


async def test_start_nexus_workflow_does_not_discard_newer_rebound_headers(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    handler_key = SigningKey.generate()
    input = RefundInput("ord_123", 2500)
    client_interceptor = TenuoClientInterceptor()
    newer_headers = {TENUO_KEY_ID_HEADER: b"newer-handler-key"}
    ctx = FakeNexusWorkflowRunContext(
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
        ),
        fail_start=True,
        on_start=lambda: client_interceptor.set_headers_for_workflow(
            "refund-wf-rebound",
            newer_headers,
        ),
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("RefundWorkflow", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )

    with pytest.raises(RuntimeError, match="start failed"):
        await tenuo_start_nexus_workflow(
            ctx,
            input,
            config,
            client_interceptor,
            "RefundWorkflow.run",
            workflow_id="refund-wf-rebound",
            workflow_warrant=workflow_warrant,
            workflow_key_id="handler-key",
            endpoint="billing-prod",
        )

    rebound_headers = client_interceptor._headers_by_workflow_id["refund-wf-rebound"][0]
    assert rebound_headers == newer_headers


async def test_start_nexus_workflow_rejects_unconsumed_pending_headers(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    handler_key = SigningKey.generate()
    input = RefundInput("ord_123", 2500)
    ctx = FakeNexusWorkflowRunContext(
        headers=tenuo_nexus_headers(
            nexus_warrant,
            "agent-key",
            agent_key,
            endpoint="billing-prod",
            service="BillingService",
            operation="refund",
            input=input,
        )
    )
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
    )
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("RefundWorkflow", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    client_interceptor = TenuoClientInterceptor()

    with pytest.raises(TenuoContextError, match="did not consume pending headers"):
        await tenuo_start_nexus_workflow(
            ctx,
            input,
            config,
            client_interceptor,
            "RefundWorkflow.run",
            workflow_id="refund-wf-wrong-interceptor",
            workflow_warrant=workflow_warrant,
            workflow_key_id="handler-key",
            endpoint="billing-prod",
        )

    assert "refund-wf-wrong-interceptor" not in client_interceptor._headers_by_workflow_id


def test_worker_interceptor_wires_control_plane_on_shared_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()
    monkeypatch.setattr("tenuo.control_plane.get_or_create", lambda: sentinel)
    root_key = SigningKey.generate()
    config = TenuoPluginConfig(
        signing_key=root_key,
        trusted_roots=[root_key.public_key],
    )
    assert config.control_plane is None

    interceptor = TenuoWorkerInterceptor(config)

    assert interceptor._config is config
    assert config.control_plane is sentinel


def test_verify_nexus_operation_emits_audit_callback_on_allow_and_deny(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    events: list[Any] = []
    input = RefundInput("ord_123", 2500)
    allow_ctx = SimpleNamespace(
        request_id="req-audit-allow",
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
    allow_config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
        audit_callback=events.append,
    )

    verify_nexus_operation(allow_ctx, input, allow_config, endpoint="billing-prod")

    deny_ctx = SimpleNamespace(
        request_id="req-audit-deny",
        service="BillingService",
        operation="refund",
        headers=allow_ctx.headers,
    )
    deny_config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[root_key.public_key],
        audit_callback=events.append,
    )
    with pytest.raises(SignatureInvalid):
        verify_nexus_operation(
            deny_ctx,
            RefundInput("ord_999", 2500),
            deny_config,
            endpoint="billing-prod",
        )

    assert [event.decision for event in events] == ["ALLOW", "DENY"]
    assert events[0].workflow_type == "nexus"
    assert events[0].tool == "nexus:billing-prod:BillingService:refund"


async def test_verify_nexus_operation_skips_duplicate_emit_inside_inbound_interceptor(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    control_plane = RecordingControlPlane()
    events: list[Any] = []
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-dedup-verify",
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
        control_plane=control_plane,
        audit_callback=events.append,
        nexus_endpoint="billing-prod",
    )
    seen: list[Any] = []

    class _Next:
        async def execute_nexus_operation_start(self, inbound_input: Any) -> Any:
            seen.append(
                verify_nexus_operation(
                    inbound_input.ctx,
                    inbound_input.input,
                    config,
                    endpoint="billing-prod",
                )
            )
            return "ok"

    inbound = TenuoNexusOperationInboundInterceptor(_Next(), config)
    await inbound.execute_nexus_operation_start(SimpleNamespace(ctx=ctx, input=input))

    assert seen[0].to_bytes() == nexus_warrant.to_bytes()
    assert len(control_plane.allow_events) == 1
    assert len(events) == 1


async def test_inbound_interceptor_cache_still_checks_explicit_binding(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-cache-binding",
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
        nexus_endpoint="billing-prod",
    )

    class _Next:
        async def execute_nexus_operation_start(self, inbound_input: Any) -> Any:
            verify_nexus_operation(
                inbound_input.ctx,
                inbound_input.input,
                config,
                endpoint="billing-prod",
                operation="capture",
            )

    inbound = TenuoNexusOperationInboundInterceptor(_Next(), config)

    with pytest.raises(TenuoContextError, match="tool binding mismatch"):
        await inbound.execute_nexus_operation_start(SimpleNamespace(ctx=ctx, input=input))


async def test_nexus_inbound_interceptor_verifies_before_handler(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    root_key, agent_key = nexus_keys
    input = RefundInput("ord_123", 2500)
    ctx = SimpleNamespace(
        request_id="req-inbound-interceptor",
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
        nexus_endpoint="billing-prod",
    )
    started: list[Any] = []

    class _Next:
        async def execute_nexus_operation_start(self, inbound_input: Any) -> str:
            started.append(inbound_input)
            return "ok"

    inbound = TenuoNexusOperationInboundInterceptor(_Next(), config)
    result = await inbound.execute_nexus_operation_start(
        SimpleNamespace(ctx=ctx, input=input)
    )

    assert result == "ok"
    assert len(started) == 1


async def test_nexus_inbound_interceptor_requires_endpoint(
    nexus_keys: tuple[Any, Any],
    nexus_warrant: Any,
) -> None:
    _root_key, agent_key = nexus_keys
    config = TenuoPluginConfig(
        key_resolver=StaticResolver(agent_key),
        trusted_roots=[nexus_keys[0].public_key],
    )
    inbound = TenuoNexusOperationInboundInterceptor(SimpleNamespace(), config)

    with pytest.raises(TenuoContextError, match="nexus_endpoint is required"):
        await inbound.execute_nexus_operation_start(
            SimpleNamespace(
                ctx=SimpleNamespace(request_id="req-missing-endpoint"),
                input=RefundInput("ord_123", 2500),
            )
        )


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


def test_bootstrap_nexus_workflow_rejects_malformed_base64_header(
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
        workflow_id="refund-wf-malformed",
    )
    envelope.headers["x-tenuo-warrant"] = "not valid base64!!!"
    run_key = "run-nexus-malformed"
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-malformed",
            workflow_type="RefundWorkflow",
            run_id=run_key,
        ),
    )

    with pytest.raises(ChainValidationError, match="Failed to decode"):
        tenuo_bootstrap_nexus_workflow(envelope)


def test_bootstrap_nexus_workflow_rejects_untrusted_envelope_root(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
) -> None:
    untrusted_root, handler_key = nexus_keys
    trusted_root = SigningKey.generate()
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(untrusted_root)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "handler-key",
        workflow_id="refund-wf-untrusted-root",
    )
    run_key = "run-nexus-untrusted-root"
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-untrusted-root",
            workflow_type="RefundWorkflow",
            run_id=run_key,
        ),
    )
    with _store_lock:
        _workflow_config_store[run_key] = TenuoPluginConfig(
            key_resolver=StaticResolver(handler_key),
            trusted_roots=[trusted_root.public_key],
        )

    with pytest.raises(TenuoContextError, match="authorization failed"):
        tenuo_bootstrap_nexus_workflow(envelope)


def test_bootstrap_nexus_workflow_rejects_key_id_holder_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    nexus_keys: tuple[Any, Any],
) -> None:
    root_key, handler_key = nexus_keys
    wrong_key = SigningKey.generate()
    workflow_warrant = (
        Warrant.mint_builder()
        .holder(handler_key.public_key)
        .capability("record_refund", order_id=Exact("ord_123"))
        .ttl(3600)
        .mint(root_key)
    )
    envelope = tenuo_create_nexus_workflow_envelope(
        workflow_warrant,
        "wrong-key",
        workflow_id="refund-wf-holder-mismatch",
    )
    run_key = "run-nexus-holder-mismatch"
    monkeypatch.setattr("tenuo.temporal._nexus._current_run_key", lambda: run_key)
    monkeypatch.setattr(
        "temporalio.workflow.info",
        lambda: SimpleNamespace(
            workflow_id="refund-wf-holder-mismatch",
            workflow_type="RefundWorkflow",
            run_id=run_key,
        ),
    )
    with _store_lock:
        _workflow_config_store[run_key] = TenuoPluginConfig(
            key_resolver=StaticResolver(wrong_key),
            trusted_roots=[root_key.public_key],
        )

    with pytest.raises(TenuoContextError, match="does not resolve"):
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
