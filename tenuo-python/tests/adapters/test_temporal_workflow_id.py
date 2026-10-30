"""Optional workflow-scope constraints filled from Temporal.

A warrant can limit a capability to one workflow (``Exact``) or a family of
workflows (``Pattern``). The outbound interceptor signs the running workflow's
namespace and ID and the Activity interceptor verifies both from Temporal's own
info. Capabilities must name both reserved fields or neither.
"""

import asyncio
import datetime
from dataclasses import dataclass
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from temporalio.exceptions import ApplicationError  # noqa: E402

from tenuo import Exact, Pattern, Range, SigningKey, Warrant  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    TenuoPluginConfig,
    TenuoWorkerInterceptor,
    tenuo_headers,
)
from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER  # noqa: E402
from tenuo.temporal._dedup import _pop_dedup_cache  # noqa: E402
from tenuo.temporal._interceptors import _TenuoWorkflowOutboundInterceptor  # noqa: E402
from tenuo.temporal._state import _workflow_headers_store  # noqa: E402


@dataclass
class StartActivity:
    activity: str = "issue_refund"
    fn: Any = None
    args: tuple = ()
    headers: Optional[Dict[str, Any]] = None


@dataclass
class WorkflowInfo:
    workflow_id: str
    namespace: str = "payments-prod"
    run_id: str = "run-1"


@dataclass
class ActivityInfo:
    workflow_id: str
    workflow_namespace: Optional[str] = "payments-prod"
    activity_type: str = "issue_refund"
    activity_id: str = "1"
    workflow_type: str = "RefundWorkflow"
    workflow_run_id: str = "run-1"
    task_queue: str = "q"
    is_local: bool = False
    attempt: int = 1


@dataclass
class ExecuteActivity:
    fn: Any
    args: tuple
    headers: Dict[str, Any]


def issue_refund(order_id: str, amount: int) -> str:
    return f"refunded {amount}"


def refund_with_reserved_name(order_id: str, _workflow_id: str) -> str:
    return "never"


def refund_with_reserved_namespace(order_id: str, _workflow_namespace: str) -> str:
    return "never"


@pytest.fixture(autouse=True)
def clean_stores():
    _workflow_headers_store.clear()
    _pop_dedup_cache.clear()
    yield
    _workflow_headers_store.clear()
    _pop_dedup_cache.clear()


class Setup:
    def __init__(self, workflow_scope=None, namespace_scope=None):
        self.issuer, self.holder = SigningKey.generate(), SigningKey.generate()
        fields = {"order_id": Exact("order-123"), "amount": Range(min=0, max=100)}
        if workflow_scope is not None:
            fields["_workflow_namespace"] = namespace_scope or Exact("payments-prod")
            fields["_workflow_id"] = workflow_scope
        self.warrant = (
            Warrant.mint_builder()
            .holder(self.holder.public_key)
            .capability("issue_refund", **fields)
            .ttl(600)
            .mint(self.issuer)
        )
        resolver = MagicMock()
        resolver.resolve_sync = MagicMock(return_value=self.holder)
        self.config = TenuoPluginConfig(key_resolver=resolver, trusted_roots=[self.issuer.public_key])

    def schedule(
        self,
        workflow_id,
        fn=issue_refund,
        args=("order-123", 25),
        namespace="payments-prod",
    ):
        """Run the outbound interceptor in workflow ``workflow_id``; return its headers."""
        _workflow_headers_store["run-1"] = tenuo_headers(self.warrant, "holder")
        captured = {}

        class Next:
            def start_activity(self, input):
                captured["headers"] = dict(input.headers or {})
                return MagicMock()

        outbound = _TenuoWorkflowOutboundInterceptor(Next(), config=self.config)
        with (
            patch(
                "temporalio.workflow.info",
                return_value=WorkflowInfo(workflow_id, namespace),
            ),
            patch(
                "temporalio.workflow.now",
                return_value=datetime.datetime.now(datetime.timezone.utc),
            ),
        ):
            outbound.start_activity(StartActivity(fn=fn, args=args))
        return captured["headers"]

    def execute(
        self,
        headers,
        workflow_id,
        fn=issue_refund,
        args=("order-123", 25),
        namespace="payments-prod",
    ):
        """Run the Activity interceptor in workflow ``workflow_id``; return the body mock."""
        body = MagicMock()
        body.execute_activity = AsyncMock(return_value="refunded 25")
        body.init = MagicMock()
        inbound = TenuoWorkerInterceptor(self.config).intercept_activity(body)
        loop = asyncio.new_event_loop()
        try:
            with patch(
                "temporalio.activity.info",
                return_value=ActivityInfo(workflow_id, namespace),
            ):
                loop.run_until_complete(inbound.execute_activity(ExecuteActivity(fn, args, headers)))
        finally:
            loop.close()
        return body


def test_exact_workflow_is_allowed_and_the_body_gets_its_own_arguments():
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("refund-order-123")
    assert headers[TENUO_ARG_KEYS_HEADER].data == b"order_id,amount"
    body = s.execute(headers, "refund-order-123")
    body.execute_activity.assert_called_once()
    assert body.execute_activity.call_args.args[0].args == ("order-123", 25)


def test_another_workflow_is_denied_before_the_body():
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("refund-order-123")
    with pytest.raises(ApplicationError) as error:
        s.execute(headers, "some-other-workflow")
    assert error.value.non_retryable
    # Nothing ran: the workflow ID is checked like any other constrained argument.


def test_same_workflow_id_in_another_namespace_is_denied():
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("refund-order-123", namespace="another-tenant")
    with pytest.raises(ApplicationError) as error:
        s.execute(headers, "refund-order-123", namespace="another-tenant")
    assert error.value.non_retryable


def test_headers_that_reach_another_workflow_are_denied():
    # Signing checks argument names, not values; the Activity Worker denies it.
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("some-other-workflow")
    with pytest.raises(ApplicationError) as error:
        s.execute(headers, "some-other-workflow")
    assert error.value.non_retryable


def test_a_wildcard_capability_can_constrain_it():
    s = Setup()
    s.warrant = (
        Warrant.mint_builder()
        .holder(s.holder.public_key)
        .capability(
            "*",
            order_id=Exact("order-123"),
            amount=Range(min=0, max=100),
            _workflow_namespace=Exact("payments-prod"),
            _workflow_id=Exact("refund-order-123"),
        )
        .ttl(600)
        .mint(s.issuer)
    )
    s.execute(s.schedule("refund-order-123"), "refund-order-123")
    _pop_dedup_cache.clear()
    with pytest.raises(ApplicationError):
        s.execute(s.schedule("other"), "other")


def test_a_pattern_admits_child_and_scheduled_workflow_ids():
    s = Setup(Pattern("refund-order-123*"))
    for workflow_id in ("refund-order-123", "refund-order-123/repair-2"):
        _pop_dedup_cache.clear()
        body = s.execute(s.schedule(workflow_id), workflow_id)
        body.execute_activity.assert_called_once()


def test_a_child_warrant_can_narrow_to_one_workflow_but_not_widen():
    s = Setup(Pattern("refund-order-123*"))
    child = s.warrant.attenuate(
        {
            "issue_refund": {
                "order_id": Exact("order-123"),
                "amount": Range(min=0, max=100),
                "_workflow_namespace": Exact("payments-prod"),
                "_workflow_id": Exact("refund-order-123/repair-2"),
            }
        },
        s.holder,
    )
    assert repr(child.capabilities["issue_refund"]["_workflow_id"]) == repr(Exact("refund-order-123/repair-2"))
    with pytest.raises(Exception):
        s.warrant.attenuate(
            {
                "issue_refund": {
                    "order_id": Exact("order-123"),
                    "amount": Range(min=0, max=100),
                    "_workflow_namespace": Exact("payments-prod"),
                    "_workflow_id": Pattern("*"),
                }
            },
            s.holder,
        )


def test_capabilities_without_it_are_unchanged():
    s = Setup()
    headers = s.schedule("any-workflow")
    assert headers[TENUO_ARG_KEYS_HEADER].data == b"order_id,amount"
    body = s.execute(headers, "a-different-workflow")
    body.execute_activity.assert_called_once()


@pytest.mark.parametrize(
    ("fn", "reserved_value"),
    [
        (refund_with_reserved_name, "refund-order-123"),
        (refund_with_reserved_namespace, "payments-prod"),
    ],
)
def test_an_activity_argument_cannot_supply_a_reserved_name(fn, reserved_value):
    # Reserved names are rejected even when workflow scoping is not enabled.
    s = Setup()
    with pytest.raises(ApplicationError, match="reserved"):
        s.schedule(
            "refund-order-123",
            fn=fn,
            args=("order-123", reserved_value),
        )


def test_header_alias_cannot_hide_a_reserved_worker_parameter():
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("refund-order-123", fn=issue_refund)

    with pytest.raises(ApplicationError, match="reserved"):
        s.execute(
            headers,
            "refund-order-123",
            fn=refund_with_reserved_name,
            args=("order-123", 25),
        )


def test_positional_fallback_cannot_hide_a_reserved_worker_parameter():
    s = Setup()
    s.warrant = (
        Warrant.mint_builder()
        .holder(s.holder.public_key)
        .capability(
            "issue_refund",
            arg0=Exact("order-123"),
            arg1=Range(min=0, max=100),
            _workflow_namespace=Exact("payments-prod"),
            _workflow_id=Exact("refund-order-123"),
        )
        .ttl(600)
        .mint(s.issuer)
    )
    headers = s.schedule("refund-order-123", fn=None)

    with pytest.raises(ApplicationError, match="reserved"):
        s.execute(
            headers,
            "refund-order-123",
            fn=refund_with_reserved_namespace,
            args=("order-123", 25),
        )


@pytest.mark.parametrize("field", ["_workflow_namespace", "_workflow_id"])
def test_partial_workflow_scope_fails_closed(field):
    s = Setup()
    constraints = {
        "order_id": Exact("order-123"),
        "amount": Range(min=0, max=100),
        field: Exact("payments-prod" if field == "_workflow_namespace" else "refund-order-123"),
    }
    s.warrant = (
        Warrant.mint_builder()
        .holder(s.holder.public_key)
        .capability("issue_refund", **constraints)
        .ttl(600)
        .mint(s.issuer)
    )

    with pytest.raises(ApplicationError, match="must constrain both"):
        s.schedule("refund-order-123")


def test_missing_temporal_workflow_identity_fails_closed():
    s = Setup(Exact("refund-order-123"))
    headers = s.schedule("refund-order-123")
    with pytest.raises(ApplicationError, match="complete workflow identity"):
        s.execute(headers, "refund-order-123", namespace=None)
