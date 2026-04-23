"""
Shared pytest configuration and invariant fixtures for the test suite.

The fixtures in this module express *cross-adapter* contracts that every
Tenuo integration (Temporal, OpenAI, CrewAI, …) must honor. They are the
runtime enforcement of the invariants called out in design review:

* :func:`raising_audit_callback` + :func:`assert_audit_failure_logged_with_traceback`
  — every audit emission path must swallow exceptions from user-supplied
  callbacks **and** log the failure with a traceback (``exc_info=True``).
  A silent swallow turns compliance-critical DENY events into ghosts;
  crashing the caller turns audit into an availability risk.

Keep new adapters honest by reusing these fixtures in at least one test
per adapter (see ``test_adapter_audit_invariant.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, List

import pytest

_TEMPORAL_E2E_FILES = frozenset({"test_temporal_live.py", "test_temporal_replay.py"})


def pytest_collection_modifyitems(config, items):
    pass


# ── Cross-adapter audit-sink invariant helpers ──────────────────────────


@dataclass
class _AuditSinkSpy:
    """Recording audit callback that optionally raises.

    Exposes the list of events the adapter tried to emit *before* the raise,
    so tests can assert "callback was actually invoked" (catching the
    regression where ``if self._audit_callback: ...`` was accidentally
    dropped) in addition to "the raise was swallowed".
    """

    events: List[Any] = field(default_factory=list)
    _should_raise: bool = True
    _message: str = "audit sink exploded"

    def __call__(self, event: Any) -> None:
        self.events.append(event)
        if self._should_raise:
            raise RuntimeError(self._message)

    def stop_raising(self) -> None:
        self._should_raise = False


@pytest.fixture
def raising_audit_callback() -> _AuditSinkSpy:
    """Audit callback that raises ``RuntimeError`` on every invocation.

    Use together with :func:`assert_audit_failure_logged_with_traceback`
    (and ``caplog.at_level(logging.WARNING, ...)``) to assert the
    swallows-and-logs-traceback contract.
    """
    return _AuditSinkSpy()


def assert_audit_failure_logged_with_traceback(
    caplog: pytest.LogCaptureFixture,
    *,
    message_substring: str = "Audit callback failed",
) -> None:
    """Assert at least one log record matches *message_substring* and carries
    a traceback (``exc_info`` is set).

    The traceback check is the load-bearing part: a one-line warning like
    ``Audit callback failed: foo`` is not enough for on-call to diagnose a
    misconfigured sink — the stack is what points at the user's bug.
    """
    matches = [
        r for r in caplog.records
        if message_substring in r.getMessage()
    ]
    assert matches, (
        f"no log record matched {message_substring!r}; the audit sink path "
        f"must log (not silently swallow) callback failures. caplog contents:"
        f"\n  " + "\n  ".join(r.getMessage() for r in caplog.records)
    )
    assert any(r.exc_info is not None for r in matches), (
        f"log record matched {message_substring!r} but did not carry "
        f"exc_info — operators cannot diagnose the audit sink bug without "
        f"a traceback. Use logger.<level>(..., exc_info=True)."
    )


@pytest.fixture
def assert_audit_callback_invariant() -> Callable[
    [Callable[[Callable[[Any], None]], Any], pytest.LogCaptureFixture], None
]:
    """Return a helper ``run(invoke, caplog)`` that asserts:

    1. ``invoke(raising_callback)`` completes without the adapter
       re-raising the callback's error (audit never crashes the caller).
    2. At least one log record with ``exc_info`` documents the failure.

    Adapter-agnostic: pass a closure that drives your adapter through one
    full decision with the supplied audit callback.
    """

    def run(
        invoke: Callable[[Callable[[Any], None]], Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging as _logging

        spy = _AuditSinkSpy()
        with caplog.at_level(_logging.WARNING):
            try:
                invoke(spy)
            except RuntimeError as e:  # pragma: no cover — would be a bug
                if str(e) == spy._message:
                    pytest.fail(
                        "adapter re-raised the audit callback error; audit "
                        "sinks must never crash the caller. See "
                        "tests/conftest.py::raising_audit_callback."
                    )
                raise
        assert spy.events, (
            "audit callback was never invoked — adapter dropped the event "
            "entirely (regression: audit path guarded by a stale flag?)"
        )
        assert_audit_failure_logged_with_traceback(caplog)

    return run
