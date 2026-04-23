"""
Boundary-contract tests: Tenuo exceptions → Temporal wire.

These tests express a single, permanent invariant:

    When a Tenuo exception reaches the Temporal hook boundary
    (``execute_activity`` / ``handle_signal`` / ``handle_update_handler``),
    it becomes ``ApplicationError`` with:

      * ``non_retryable=True``              (auth failures never retry)
      * ``type == exc.error_code``          (stable wire code, not class name)
      * ``__cause__ is exc``                (original traceback preserved)

This file is the runtime enforcement of that contract. Deep-review round 4
turned up *three* separate bugs where one of those legs regressed
(``ApprovalGateTriggered`` collapsed into ``CONSTRAINT_VIOLATED``;
``ConfigurationError`` reached the wire as retryable; generic
``Exception`` was retryable). The sweep below covers every concrete
Tenuo exception with an ``error_code`` so future drift is caught at
commit time instead of in production.

Adding a new Tenuo exception? No code change needed here — the sweep
picks it up automatically from ``inspect.getmembers``.
"""

from __future__ import annotations

import inspect
from typing import List, Type

import pytest

pytest.importorskip("temporalio")

from temporalio.exceptions import ApplicationError  # noqa: E402

from tenuo import exceptions as _tenuo_exc_mod  # noqa: E402
from tenuo.temporal import exceptions as _tenuo_temporal_exc_mod  # noqa: E402
from tenuo.temporal._interceptors import (  # noqa: E402
    TenuoActivityInboundInterceptor,
    _error_type_for_wire,
    _raise_non_retryable,
)
from tenuo.temporal._workflow import _fail_workflow_non_retryable  # noqa: E402


# ── Exception discovery ─────────────────────────────────────────────────


def _discoverable_exception_classes() -> List[Type[BaseException]]:
    """Every exception class the sweep tests should cover.

    Rules:
      * Must be a subclass of ``BaseException``.
      * Must declare an ``error_code`` (the wire contract we're testing).
      * Must be constructible with zero positional arguments *or* via
        the ``_instantiate`` helper below.
    """
    seen: set[type] = set()
    out: list[Type[BaseException]] = []
    for module in (_tenuo_exc_mod, _tenuo_temporal_exc_mod):
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, BaseException):
                continue
            if obj in seen:
                continue
            code = getattr(obj, "error_code", None)
            if not isinstance(code, str) or not code:
                continue
            seen.add(obj)
            out.append(obj)
    return out


def _instantiate(cls: Type[BaseException]) -> BaseException:
    """Best-effort constructor for sweep tests.

    Tenuo exceptions are a mix of:
      * plain ``Exception`` subclasses (take ``*args, **kwargs``)
      * frozen ``@dataclass`` exceptions with required fields
      * ``@dataclass(init=False)`` exceptions with custom ``__init__``

    We try a menu of known constructor shapes and fall back to
    ``object.__new__`` + in-place attribute assignment when the
    signature doesn't match any of them. This is only used for the
    wire-contract sweep — we don't care whether the exception is a
    "realistic" instance, only whether it round-trips ``error_code``.
    """
    from datetime import datetime, timezone

    attempts: list[tuple[tuple, dict]] = [
        (("sweep-boundary-contract",), {}),
        ((), {}),
        (("sweep",), {"activity_name": "sweep_activity"}),
        (
            (),
            {"tool": "sweep", "arguments": {}, "constraint": "x", "warrant_id": "w"},
        ),
        (
            (),
            {"warrant_id": "w", "expired_at": datetime(2030, 1, 1, tzinfo=timezone.utc)},
        ),
        ((), {"reason": "sweep", "depth": 0}),
        ((), {"key_id": "k"}),
        (("sweep",), {"activity_name": "x"}),
        (("sweep",), {"size": 1, "max_size": 2}),
    ]
    last_exc: BaseException | None = None
    for args, kwargs in attempts:
        try:
            return cls(*args, **kwargs)  # type: ignore[call-arg]
        except TypeError as e:
            last_exc = e
            continue
    # Final fallback: bypass __init__, then seed the attributes
    # ``TenuoError.__str__`` / ``repr`` reach for. We don't care about a
    # "realistic" payload — only about whether the exception round-trips
    # ``error_code`` through ``_error_type_for_wire`` / ``_wrap_as_non_retryable``.
    try:
        inst = cls.__new__(cls)  # type: ignore[call-arg]
        BaseException.__init__(inst, "sweep-fallback")
        for attr, default in (
            ("message", "sweep-fallback"),
            ("details", {}),
            ("hint", None),
        ):
            if not hasattr(inst, attr):
                try:
                    setattr(inst, attr, default)
                except AttributeError:
                    pass  # frozen dataclass — let str() surface the bug
        return inst
    except Exception:  # pragma: no cover — defensive
        raise AssertionError(
            f"Cannot instantiate {cls.__name__} for sweep; update "
            f"_instantiate() in tests/adapters/test_boundary_contract.py. "
            f"Last constructor error: {last_exc}"
        )


_EXCEPTION_CLASSES = _discoverable_exception_classes()


# ── Unit sweep: wire mapping is stable and correct ─────────────────────


class TestExceptionToWireCodeMapping:
    """Every Tenuo exception with ``error_code`` must map to that code at
    the Temporal wire boundary (``ApplicationError.type``).
    """

    @pytest.mark.parametrize(
        "exc_cls",
        _EXCEPTION_CLASSES,
        ids=[c.__name__ for c in _EXCEPTION_CLASSES],
    )
    def test_error_type_for_wire_returns_error_code(
        self, exc_cls: Type[BaseException]
    ) -> None:
        exc = _instantiate(exc_cls)
        expected = exc_cls.error_code  # type: ignore[attr-defined]
        actual = _error_type_for_wire(exc)
        assert actual == expected, (
            f"{exc_cls.__name__} mapped to {actual!r} but its contract "
            f"is error_code={expected!r}. If you intentionally changed "
            f"the wire code, update the class attribute and any client "
            f"code that branches on the old value."
        )

    def test_unknown_exception_falls_back_to_class_name(self) -> None:
        """A non-Tenuo exception (no ``error_code``) still produces a
        stable, branchable wire type (its class name).
        """
        assert _error_type_for_wire(ValueError("x")) == "ValueError"
        assert _error_type_for_wire(KeyError("x")) == "KeyError"

    @pytest.mark.parametrize(
        "exc_cls",
        _EXCEPTION_CLASSES,
        ids=[c.__name__ for c in _EXCEPTION_CLASSES],
    )
    def test_wrap_as_non_retryable_preserves_error_code_and_non_retryable(
        self, exc_cls: Type[BaseException]
    ) -> None:
        """``TenuoActivityInboundInterceptor._wrap_as_non_retryable`` is
        the single path every auth denial funnels through before raising.
        Its output must be a non-retryable ``ApplicationError`` tagged
        with the Tenuo ``error_code``. If this test fails, denials are
        either retryable (activity loops on a broken auth config) or
        carry a class-name type (client branching breaks).
        """
        if not issubclass(exc_cls, Exception):
            pytest.skip(
                f"{exc_cls.__name__} is not an ``Exception`` subclass; "
                f"``_wrap_as_non_retryable`` takes ``Exception``."
            )
        exc = _instantiate(exc_cls)
        wrapped = TenuoActivityInboundInterceptor._wrap_as_non_retryable(exc)
        assert isinstance(wrapped, ApplicationError), (
            f"{exc_cls.__name__} did not wrap to ApplicationError — "
            f"fail-closed is broken"
        )
        assert wrapped.non_retryable is True, (
            f"{exc_cls.__name__} wrapped as *retryable*. Temporal will "
            f"loop the failing activity until the retry policy gives up, "
            f"re-running the same broken auth path every attempt."
        )
        assert wrapped.type == exc_cls.error_code, (  # type: ignore[attr-defined]
            f"{exc_cls.__name__} wrapped with type={wrapped.type!r} but "
            f"error_code={exc_cls.error_code!r}"  # type: ignore[attr-defined]
        )

    @pytest.mark.parametrize(
        "exc_cls",
        _EXCEPTION_CLASSES,
        ids=[c.__name__ for c in _EXCEPTION_CLASSES],
    )
    def test_fail_workflow_non_retryable_preserves_error_code_and_non_retryable(
        self, exc_cls: Type[BaseException]
    ) -> None:
        """``_fail_workflow_non_retryable`` is the workflow-context twin of
        ``_wrap_as_non_retryable``: used by ``execute_child_workflow_authorized``,
        ``workflow_grant``, ``delegate_warrant``, etc. It must obey the same
        three-leg contract.

        Regression test — before this sweep covered it, the helper was
        emitting ``type=type(exc).__name__`` (Python class name) instead of
        the Tenuo ``error_code``, so workflow-context denials surfaced as
        ``type="TemporalConstraintViolation"`` while the identical violation
        in activity context surfaced as ``type="CONSTRAINT_VIOLATED"``.
        Clients branching on ``ApplicationError.type`` broke silently.
        """
        if not issubclass(exc_cls, Exception):
            pytest.skip(
                f"{exc_cls.__name__} is not an ``Exception`` subclass; "
                f"``_fail_workflow_non_retryable`` takes ``Exception``."
            )
        exc = _instantiate(exc_cls)
        wrapped = _fail_workflow_non_retryable(exc)
        assert isinstance(wrapped, ApplicationError), (
            f"{exc_cls.__name__} did not wrap to ApplicationError in "
            f"workflow context — fail-closed is broken"
        )
        assert wrapped.non_retryable is True, (
            f"{exc_cls.__name__} wrapped as *retryable* in workflow "
            f"context. Temporal will retry the workflow task forever."
        )
        assert wrapped.type == exc_cls.error_code, (  # type: ignore[attr-defined]
            f"{exc_cls.__name__} wrapped with type={wrapped.type!r} but "
            f"error_code={exc_cls.error_code!r}. Workflow-context denials "
            f"must expose the same wire code as activity-context denials."  # type: ignore[attr-defined]
        )
        assert wrapped.__cause__ is exc, (
            f"{exc_cls.__name__}: __cause__ was not preserved; Temporal's "
            f"traceback will point at the wrapper, not at the Tenuo "
            f"exception that actually rejected the action."
        )


# ── Cause preservation ──────────────────────────────────────────────────


class TestCausePreservation:
    """``_raise_non_retryable`` must preserve the original exception as
    ``__cause__`` so the traceback at the Temporal activity boundary
    points back at the Tenuo code that rejected the action, not just the
    wrapper. Bare ``raise ApplicationError(...)`` would drop the chain.
    """

    def test_raise_non_retryable_sets_cause(self) -> None:
        from tenuo.temporal.exceptions import PopVerificationError

        original = PopVerificationError(
            reason="malformed base64", activity_name="deploy",
        )
        try:
            _raise_non_retryable(original)
        except ApplicationError as app:
            assert app.__cause__ is original, (
                "ApplicationError.__cause__ must be the original Tenuo "
                "exception — otherwise Temporal's traceback points at the "
                "wrapper and the real denial reason is invisible in logs."
            )
            assert app.non_retryable is True
            assert app.type == PopVerificationError.error_code
        else:  # pragma: no cover — the helper always raises
            pytest.fail("_raise_non_retryable must raise")

    def test_raise_non_retryable_uses_class_name_for_non_tenuo(self) -> None:
        """Non-Tenuo exceptions without ``error_code`` still round-trip
        the class name on the wire so unknown errors remain branchable.
        """
        original = ValueError("plain error")
        try:
            _raise_non_retryable(original)
        except ApplicationError as app:
            assert app.type == "ValueError"
            assert app.__cause__ is original
        else:  # pragma: no cover
            pytest.fail("_raise_non_retryable must raise")


# ── Drift guard: adding a new exception without error_code is flagged ──


class TestNewExceptionsDeclareErrorCode:
    """New Tenuo exception classes must declare ``error_code``; otherwise
    the sweep above won't cover them and downstream consumers can't
    branch on the wire. This is a soft check — it skips exceptions
    flagged as intentionally untyped in ``_NO_ERROR_CODE_OK``.
    """

    # Exceptions that are deliberately not wire-exposed (abstract bases,
    # helpers). Keep this set tiny; if you're adding a new entry, ask
    # whether the exception should instead be wire-exposed.
    _NO_ERROR_CODE_OK = frozenset({
        "TenuoError",
        "TenuoTemporalError",
        "TenuoArgNormalizationError",
    })

    def test_every_public_exception_either_declares_error_code_or_is_exempt(self) -> None:
        missing: list[str] = []
        for module in (_tenuo_exc_mod, _tenuo_temporal_exc_mod):
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if not issubclass(obj, BaseException):
                    continue
                if obj.__module__ != module.__name__:
                    # re-exported (e.g. ``ApprovalGateTriggered`` in temporal.exceptions)
                    continue
                if name.startswith("_"):
                    continue
                code = getattr(obj, "error_code", None)
                if not isinstance(code, str) or not code:
                    if name not in self._NO_ERROR_CODE_OK:
                        missing.append(f"{module.__name__}.{name}")
        assert not missing, (
            "New Tenuo exception classes must declare ``error_code`` so "
            "they round-trip across the Temporal wire (and stay stable "
            "for client-side branching). If the class is an abstract "
            "base, add it to ``_NO_ERROR_CODE_OK``. Missing: " + ", ".join(missing)
        )
