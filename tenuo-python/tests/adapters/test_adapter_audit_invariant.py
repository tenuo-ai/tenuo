"""
Cross-adapter invariant: audit callbacks never crash the caller, and
their failures always reach the operator with a traceback.

Every Tenuo adapter (Temporal, OpenAI, CrewAI, …) exposes an
``audit_callback`` hook. These hooks are user code — it is
*compliance-critical* that:

1. A raising audit callback does **not** propagate the exception to the
   caller. A crashed adapter turns audit into an availability risk.
2. The failure **is** logged with a traceback (``exc_info=True``) so the
   on-call engineer can diagnose the user-supplied callback.

Deep-review round 4 turned up this exact drift on the Temporal adapter
(``logger.warning(f"...: {e}")`` without ``exc_info=True``). The audit
path in OpenAI + CrewAI had the same footgun for months. These tests
force the invariant across every adapter, forever.

Adding a new adapter with an ``audit_callback``? Add a test here.
Use the :func:`raising_audit_callback` fixture and
:func:`assert_audit_failure_logged_with_traceback` helper from
``tests/conftest.py``.
"""

from __future__ import annotations

import logging

import pytest

from tests.conftest import assert_audit_failure_logged_with_traceback


# ── Temporal adapter ────────────────────────────────────────────────────


pytest.importorskip("temporalio")


class TestTemporalAuditSinkInvariant:
    """``TenuoActivityInboundInterceptor._emit_allow_event`` and
    ``_emit_denial_event`` must swallow callback failures and log with
    ``exc_info``.
    """

    def test_raising_audit_callback_does_not_crash_allow_path(
        self, raising_audit_callback, caplog
    ) -> None:
        import asyncio
        import base64
        import time as _time
        from unittest.mock import AsyncMock, MagicMock, patch

        from tenuo import SigningKey, Warrant
        from tenuo.temporal._config import TenuoPluginConfig
        from tenuo.temporal._constants import TENUO_POP_HEADER
        from tenuo.temporal._headers import tenuo_headers
        from tenuo.temporal._interceptors import TenuoWorkerInterceptor
        from tenuo.temporal._resolvers import EnvKeyResolver

        control_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("noop")
            .ttl(3600)
            .mint(control_key)
        )
        pop = warrant.sign(agent_key, "noop", {}, int(_time.time()))

        cfg = TenuoPluginConfig(
            key_resolver=EnvKeyResolver(),
            trusted_roots=[control_key.public_key],
            audit_callback=raising_audit_callback,
            audit_allow=True,
            audit_deny=True,
        )
        plugin = TenuoWorkerInterceptor(cfg)

        h = tenuo_headers(warrant, "agent1")
        act_headers = {
            k: (v if isinstance(v, bytes) else str(v).encode("utf-8"))
            for k, v in h.items() if k.startswith("x-tenuo-")
        }
        act_headers[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        class FakePayload:
            def __init__(self, data):
                self.data = data

        info = MagicMock()
        info.activity_type = "noop"
        info.activity_id = "1"
        info.workflow_id = "wf"
        info.workflow_run_id = "run"
        info.workflow_type = "W"
        info.task_queue = "q"
        info.attempt = 1
        info.is_local = False

        inp = MagicMock()
        inp.fn = None
        inp.args = ()
        inp.headers = {k: FakePayload(data=v) for k, v in act_headers.items()}

        ai = plugin.intercept_activity(MagicMock(
            execute_activity=AsyncMock(return_value="ok"),
            init=MagicMock(),
        ))

        with caplog.at_level(logging.ERROR, logger="tenuo.temporal"):
            loop = asyncio.new_event_loop()
            try:
                with patch("temporalio.activity.info", return_value=info):
                    result = loop.run_until_complete(ai.execute_activity(inp))
            finally:
                loop.close()

        assert result == "ok"
        assert raising_audit_callback.events, (
            "Temporal adapter did not invoke audit_callback — regression"
        )
        assert_audit_failure_logged_with_traceback(caplog)


# ── OpenAI adapter ──────────────────────────────────────────────────────


class TestOpenAIAuditSinkInvariant:
    """``GuardedClient`` must swallow audit callback failures and log
    with ``exc_info``.
    """

    def test_raising_audit_callback_does_not_crash_guarded_client(
        self, raising_audit_callback, caplog
    ) -> None:
        from tenuo.openai import Pattern, guard

        from tests.adapters.test_openai_adapter import make_mock_client, make_response

        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)

        client = guard(
            mock_client,
            constraints={"read_file": {"path": Pattern("/data/*")}},
            audit_callback=raising_audit_callback,
        )

        with caplog.at_level(logging.WARNING, logger="tenuo.openai"):
            result = client.chat.completions.create(model="gpt-4o", messages=[])

        assert result is not None, (
            "OpenAI guard re-raised audit callback error — audit must not "
            "turn into an availability risk"
        )
        assert raising_audit_callback.events, (
            "OpenAI adapter did not invoke audit_callback — regression"
        )
        assert_audit_failure_logged_with_traceback(caplog)


# ── CrewAI adapter ──────────────────────────────────────────────────────


class TestCrewAIAuditSinkInvariant:
    """``CrewAIGuard._audit`` must swallow audit callback failures and
    log with ``exc_info``.
    """

    def test_raising_audit_callback_does_not_crash_authorize(
        self, raising_audit_callback, caplog
    ) -> None:
        from tenuo.crewai import GuardBuilder, Wildcard

        crew_guard = (
            GuardBuilder()
            .allow("read", path=Wildcard())
            .audit(raising_audit_callback)
            .build()
        )

        with caplog.at_level(logging.ERROR, logger="tenuo.crewai"):
            # On the ALLOW path ``_authorize`` calls the audit callback
            # and must not propagate the raise.
            crew_guard._authorize("read", {"path": "/data/file.txt"})

        assert raising_audit_callback.events, (
            "CrewAI adapter did not invoke audit_callback — regression"
        )
        assert_audit_failure_logged_with_traceback(caplog)
