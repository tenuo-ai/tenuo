"""End-to-end tests for the Temporal Agent Harness support surfaces.

Covers, without a running Temporal server (mirrors the technique in
``tests/e2e/test_temporal_e2e.py``: real Tenuo objects, fake Temporal
input/info dataclasses):

  - ``TenuoPluginConfig.unwarranted_activities`` — internal-activity
    allowlist, construction-time rejection of over-broad patterns (bare
    ``"*"`` and anything MCP-call-tool-shaped), and that a presented warrant
    is still verified normally even for an allowlisted activity.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("temporalio")

from temporalio.exceptions import ApplicationError  # noqa: E402

from tenuo import SigningKey, Warrant  # noqa: E402
from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.temporal import EnvKeyResolver, TenuoPluginConfig, TenuoWorkerInterceptor  # noqa: E402
from tenuo.temporal._activity_patterns import validate_unwarranted_activities  # noqa: E402
from tenuo.temporal._constants import TENUO_ARG_KEYS_HEADER, TENUO_POP_HEADER  # noqa: E402
from tenuo.temporal._dedup import _pop_dedup_cache  # noqa: E402
from tenuo.temporal._headers import tenuo_headers  # noqa: E402
from tenuo.temporal._interceptors import _TenuoWorkflowOutboundInterceptor  # noqa: E402
from tenuo.temporal._state import _store_lock, _workflow_headers_store  # noqa: E402

_TEMPORAL_TRUST_ROOTS = [SigningKey.generate().public_key]


@pytest.fixture(autouse=True)
def clean_stores():
    _workflow_headers_store.clear()
    _pop_dedup_cache.clear()
    yield
    _workflow_headers_store.clear()
    _pop_dedup_cache.clear()


# -- Fake Temporal plumbing (mirrors tests/e2e/test_temporal_e2e.py) --------

@dataclass
class FakeActivityInfo:
    activity_type: str = "do_thing"
    activity_id: str = "1"
    workflow_id: str = "wf-test-001"
    workflow_type: str = "TestWorkflow"
    workflow_run_id: str = "run-001"
    task_queue: str = "test-queue"
    is_local: bool = False
    attempt: int = 1


@dataclass
class FakePayload:
    data: bytes = b""


@dataclass
class FakeExecuteActivityInput:
    fn: Any = None
    args: tuple = ()
    headers: Optional[Dict[str, Any]] = None


@dataclass
class FakeStartActivityInput:
    activity: str
    fn: Any = None
    args: tuple = ()
    headers: Dict[str, Any] = field(default_factory=dict)
    summary: Optional[str] = None


def _run(coro):
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _assert_non_retryable(exc_info, *, match: Optional[str] = None):
    exc = exc_info.value
    assert isinstance(exc, ApplicationError)
    assert exc.non_retryable
    if match:
        assert match.lower() in str(exc).lower(), f"{match!r} not in {str(exc)!r}"


def _make_activity_headers_dict(hdict, warrant, signer, tool, args_dict):
    """Build FakePayload headers for an activity, simulating outbound injection."""
    pop = warrant.sign(signer, tool, args_dict, int(time.time()))
    raw = {}
    for k, v in hdict.items():
        raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
        if k.startswith("x-tenuo-"):
            raw[k] = raw_v
    raw[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))
    raw[TENUO_ARG_KEYS_HEADER] = ",".join(args_dict.keys()).encode("utf-8")
    return {k: FakePayload(data=v) for k, v in raw.items()}


def _outbound_for(config: TenuoPluginConfig):
    """A bare ``_TenuoWorkflowOutboundInterceptor`` wrapping a passthrough next."""
    nxt = MagicMock()
    nxt.start_activity.side_effect = lambda value: value
    return _TenuoWorkflowOutboundInterceptor(nxt, config)


def _sign_via_outbound(config, workflow_headers, run_key, activity_type, activity_fn, args):
    """Drive real outbound ``start_activity`` PoP injection, return resulting Payload headers."""
    import datetime as _dt

    from temporalio import workflow

    with _store_lock:
        _workflow_headers_store[run_key] = workflow_headers
    try:
        outbound = _outbound_for(config)
        info = MagicMock(run_id=run_key, workflow_id=run_key)
        with (
            patch.object(workflow, "info", return_value=info),
            patch.object(workflow, "now", return_value=_dt.datetime.now(_dt.timezone.utc)),
        ):
            inp = FakeStartActivityInput(activity=activity_type, fn=activity_fn, args=tuple(args))
            result = outbound.start_activity(inp)
        return result
    finally:
        with _store_lock:
            _workflow_headers_store.pop(run_key, None)


# =============================================================================
# unwarranted_activities
# =============================================================================


class TestUnwarrantedActivitiesConfig:
    def test_bare_wildcard_rejected(self):
        with pytest.raises(ConfigurationError):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                unwarranted_activities=["*"],
            )

    @pytest.mark.parametrize(
        "pattern",
        ["*-call-tool-v2", "*call-tool-v2", "call-tool-v2", "*-stateful-call-tool-v2"],
    )
    def test_mcp_shaped_pattern_rejected(self, pattern):
        with pytest.raises(ConfigurationError):
            TenuoPluginConfig(
                key_resolver=EnvKeyResolver(),
                trusted_roots=_TEMPORAL_TRUST_ROOTS,
                unwarranted_activities=[pattern],
            )

    def test_narrow_pattern_accepted(self):
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=_TEMPORAL_TRUST_ROOTS,
            unwarranted_activities=["invoke_model_activity", "*-list-tools"],
        )
        assert cfg.unwarranted_activities == ("invoke_model_activity", "*-list-tools")

    def test_validate_unwarranted_activities_helper_matches_anchored_only(self):
        # A pattern that looks dangerous as a substring must not match unless
        # it's the whole name.
        validate_unwarranted_activities(["call-tool"])  # does not match "-call-tool-v2" shapes
        with pytest.raises(ConfigurationError):
            validate_unwarranted_activities(["*call-tool*"])


class TestUnwarrantedActivitiesOutbound:
    def test_matching_activity_dispatches_without_headers(self):
        control = SigningKey.generate()
        agent = SigningKey.generate()
        warrant = Warrant.issue(
            control, capabilities={"read_file": {}}, ttl_seconds=3600,
            holder=agent.public_key,
        )
        headers = tenuo_headers(warrant, "agent1")
        resolver = MagicMock()
        resolver.resolve_sync.return_value = agent
        config = TenuoPluginConfig(
            key_resolver=resolver, trusted_roots=[control.public_key],
            unwarranted_activities=["invoke_model_activity"],
        )
        result = _sign_via_outbound(
            config, headers, "wf-unwarranted-out", "invoke_model_activity", None, (),
        )
        assert not result.headers, "no Tenuo headers should be attached"


class TestUnwarrantedActivitiesInbound:
    def _make(self, control_key, patterns):
        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
            unwarranted_activities=patterns,
        )
        ti = TenuoWorkerInterceptor(cfg)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        return ti.intercept_activity(nxt), nxt

    def test_allowlisted_activity_with_no_warrant_is_allowed(self):
        control = SigningKey.generate()
        ai, nxt = self._make(control, ["invoke_model_activity"])
        info = FakeActivityInfo(activity_type="invoke_model_activity")
        inp = FakeExecuteActivityInput(fn=lambda: None, args=())
        with patch("temporalio.activity.info", return_value=info):
            result = _run(ai.execute_activity(inp))
        assert result == "ok"

    def test_non_allowlisted_activity_with_no_warrant_still_denied(self):
        control = SigningKey.generate()
        ai, nxt = self._make(control, ["invoke_model_activity"])
        info = FakeActivityInfo(activity_type="read_file")
        inp = FakeExecuteActivityInput(fn=lambda: None, args=())
        with patch("temporalio.activity.info", return_value=info):
            with pytest.raises(ApplicationError) as exc_info:
                _run(ai.execute_activity(inp))
            _assert_non_retryable(exc_info, match="No warrant")

    def test_allowlisted_activity_with_authorizing_warrant_is_verified_and_allowed(self):
        """A warrant IS presented for an allowlisted activity: normal verification runs."""
        control = SigningKey.generate()
        agent = SigningKey.generate()
        warrant = Warrant.issue(
            control, capabilities={"invoke_model_activity": {}}, ttl_seconds=3600,
            holder=agent.public_key,
        )
        act_headers = _make_activity_headers_dict(
            tenuo_headers(warrant, "agent1"), warrant, agent, "invoke_model_activity", {},
        )
        ai, nxt = self._make(control, ["invoke_model_activity"])
        info = FakeActivityInfo(activity_type="invoke_model_activity")
        inp = FakeExecuteActivityInput(fn=lambda: None, args=(), headers=act_headers)
        with patch("temporalio.activity.info", return_value=info):
            result = _run(ai.execute_activity(inp))
        assert result == "ok"

    def test_allowlisted_activity_with_non_authorizing_warrant_is_still_denied(self):
        """The allowlist is not a bypass for a bad/insufficient warrant."""
        control = SigningKey.generate()
        agent = SigningKey.generate()
        warrant = Warrant.issue(
            control, capabilities={"some_other_tool": {}}, ttl_seconds=3600,
            holder=agent.public_key,
        )
        act_headers = _make_activity_headers_dict(
            tenuo_headers(warrant, "agent1"), warrant, agent, "invoke_model_activity", {},
        )
        ai, nxt = self._make(control, ["invoke_model_activity"])
        info = FakeActivityInfo(activity_type="invoke_model_activity")
        inp = FakeExecuteActivityInput(fn=lambda: None, args=(), headers=act_headers)
        with patch("temporalio.activity.info", return_value=info):
            with pytest.raises(ApplicationError) as exc_info:
                _run(ai.execute_activity(inp))
            _assert_non_retryable(exc_info)
        nxt.execute_activity.assert_not_called()
