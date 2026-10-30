"""PoP failures reach the wire as POP_VERIFICATION_FAILED.

A malformed or replayed PoP already did; a missing PoP or one signed by the
wrong key surfaced as CONSTRAINT_VIOLATED. Trust failures keep their code.
"""

import asyncio
import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from temporalio.exceptions import ApplicationError  # noqa: E402

from tenuo import SigningKey, Warrant  # noqa: E402
from tenuo.temporal._config import TenuoPluginConfig  # noqa: E402
from tenuo.temporal._constants import TENUO_POP_HEADER  # noqa: E402
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._interceptors import TenuoWorkerInterceptor  # noqa: E402
from tenuo.temporal._resolvers import EnvKeyResolver  # noqa: E402


class _Payload:
    def __init__(self, data):
        self.data = data


def _run(pop_signer, trusted_root=None):
    root, agent = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().holder(agent.public_key).capability("deploy").ttl(3600).mint(root)
    cfg = TenuoPluginConfig(key_resolver=EnvKeyResolver(), trusted_roots=[(trusted_root or root).public_key])
    headers = {
        k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
        for k, v in tenuo_headers(warrant, "agent1").items()
        if k.startswith("x-tenuo-")
    }
    if pop_signer is not None:
        signer = agent if pop_signer == "holder" else SigningKey.generate()
        headers[TENUO_POP_HEADER] = base64.b64encode(bytes(warrant.sign(signer, "deploy", {}, int(time.time()))))

    info = MagicMock(
        activity_type="deploy",
        activity_id="1",
        workflow_id="wf-pop",
        workflow_run_id="run-1",
        workflow_type="W",
        task_queue="q",
        attempt=1,
        is_local=False,
    )
    inp = MagicMock(fn=lambda: None, args=(), headers={k: _Payload(v) for k, v in headers.items()})
    ai = TenuoWorkerInterceptor(cfg).intercept_activity(
        MagicMock(execute_activity=AsyncMock(return_value="ok"), init=MagicMock())
    )
    loop = asyncio.new_event_loop()
    try:
        with patch("temporalio.activity.info", return_value=info):
            with pytest.raises(ApplicationError) as excinfo:
                loop.run_until_complete(ai.execute_activity(inp))
    finally:
        loop.close()
    assert excinfo.value.non_retryable is True
    return excinfo.value.type


def test_missing_pop_is_pop_verification_failed():
    assert _run(pop_signer=None) == "POP_VERIFICATION_FAILED"


def test_wrong_key_pop_is_pop_verification_failed():
    assert _run(pop_signer="other") == "POP_VERIFICATION_FAILED"


def test_untrusted_issuer_keeps_its_code():
    assert _run(pop_signer="holder", trusted_root=SigningKey.generate()) == "CONSTRAINT_VIOLATED"


def _gated_inputs(pop_kind):
    """A warrant whose ``deploy`` call is in scope but approval-gated."""
    root, agent, approver = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(agent.public_key)
        .capability("deploy")
        .required_approvers([approver.public_key])
        .min_approvals(1)
        .approval_gates({"deploy": None})
        .ttl(3600)
        .mint(root)
    )
    headers = {
        k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
        for k, v in tenuo_headers(warrant, "agent1").items()
        if k.startswith("x-tenuo-")
    }
    if pop_kind != "missing":
        signer = agent if pop_kind == "valid" else SigningKey.generate()
        headers[TENUO_POP_HEADER] = base64.b64encode(
            bytes(warrant.sign(signer, "deploy", {}, int(time.time())))
        )
    info = MagicMock(
        activity_type="deploy",
        activity_id="1",
        workflow_id="wf-pop-gate",
        workflow_run_id="run-1",
        workflow_type="W",
        task_queue="q",
        attempt=1,
        is_local=False,
    )
    inp = MagicMock(fn=lambda: None, args=(), headers={k: _Payload(v) for k, v in headers.items()})
    return root, info, inp


@pytest.mark.parametrize("pop_kind", ["missing", "invalid", "valid"])
def test_only_valid_pop_reaches_approval_handler(pop_kind):
    """A copied warrant with no PoP or an invalid PoP never reaches the approver."""
    root, info, inp = _gated_inputs(pop_kind)
    # Returning None leaves the gate unsatisfied, so even the valid-PoP case is
    # denied; it only shows the handler is reachable after PoP authentication.
    handler = MagicMock(return_value=None)
    cfg = TenuoPluginConfig(
        key_resolver=EnvKeyResolver(),
        trusted_roots=[root.public_key],
        approval_handler=handler,
    )
    ai = TenuoWorkerInterceptor(cfg).intercept_activity(
        MagicMock(execute_activity=AsyncMock(return_value="ok"), init=MagicMock())
    )
    loop = asyncio.new_event_loop()
    try:
        with patch("temporalio.activity.info", return_value=info):
            with pytest.raises(ApplicationError) as excinfo:
                loop.run_until_complete(ai.execute_activity(inp))
    finally:
        loop.close()

    if pop_kind == "valid":
        handler.assert_called_once()
    else:
        handler.assert_not_called()
        assert excinfo.value.type == "POP_VERIFICATION_FAILED"
        assert excinfo.value.non_retryable is True
