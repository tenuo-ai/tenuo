"""
Boundary-contract tests: Tenuo exceptions → Temporal wire.

These tests express a single, permanent invariant:

    When a Tenuo exception reaches the Temporal hook boundary
    (``execute_activity`` / workflow context / ``AuthorizedWorkflow.__init__``
    / signal / update handler), it becomes ``ApplicationError`` with:

      * ``non_retryable=True``              (auth failures never retry)
      * ``type == exc.error_code``          (stable wire code, not class name)
      * ``__cause__ is exc``                (original traceback preserved)

Enforcement strategy (after deep-review round 4+5):

  1. *Data* sweep — ``TestBuilderContract`` parametrises every
     Tenuo exception class through the single builder
     (``_build_non_retryable_application_error``) and asserts all
     three legs.

  2. *Structural* guard — ``TestNoRawApplicationErrorInTemporalPackage``
     AST-scans ``tenuo/temporal/**/*.py`` and asserts that every
     ``ApplicationError(...)`` constructor call lives inside the
     builder. This is what actually prevents the "new wrapper forgets
     to delegate" class of regression that motivated this file: the
     data sweep can only cover wrappers it knows about; the AST
     guard fires regardless of whether the new wrapper was ever
     registered anywhere.

  3. Thin per-wrapper smoke tests (``TestWrappersDelegateToBuilder``)
     catch outright call-site breakage (e.g. wrapper stops being
     called at all). These are *not* parametrised — the builder
     sweep does that work.

Adding a new Tenuo exception? No code change needed — the sweep picks
it up from ``inspect.getmembers``. Adding a new wrapper? Route it
through the builder; the AST guard will fail otherwise.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
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
from tenuo.temporal.exceptions import (  # noqa: E402
    _build_non_retryable_application_error,
)


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


# ── Data sweep: every exception round-trips the contract via the builder ──


class TestExceptionToWireCodeMapping:
    """``_error_type_for_wire`` is the pure mapping from exception → wire
    type; the builder composes it with ``non_retryable=True`` and
    ``__cause__``. Test both.
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


class TestBuilderContract:
    """Single authoritative sweep of the three-leg wire contract, run
    against the one construction site all wrappers delegate to. Every
    ``ApplicationError`` that reaches the Temporal wire in this package
    flows through here (enforced structurally by
    :class:`TestNoRawApplicationErrorInTemporalPackage`).
    """

    @pytest.mark.parametrize(
        "exc_cls",
        _EXCEPTION_CLASSES,
        ids=[c.__name__ for c in _EXCEPTION_CLASSES],
    )
    def test_builder_emits_contract_compliant_application_error(
        self, exc_cls: Type[BaseException]
    ) -> None:
        """Builder output must: be ``ApplicationError``, be
        ``non_retryable=True``, carry ``type == error_code``, and
        preserve ``__cause__``.

        Regression history:
          * ``ApprovalGateTriggered`` was collapsed into
            ``CONSTRAINT_VIOLATED`` (different semantics).
          * ``ConfigurationError`` reached the wire as retryable.
          * Workflow-context wrapper emitted the Python class name
            (e.g. ``"TemporalConstraintViolation"``) while the
            activity-context wrapper emitted ``"CONSTRAINT_VIOLATED"``
            — same violation, different wire code, silent client
            breakage.
        """
        if not issubclass(exc_cls, Exception):
            pytest.skip(
                f"{exc_cls.__name__} is not an ``Exception`` subclass; "
                f"builder signature takes ``BaseException`` but the "
                f"wrappers that use it take ``Exception``."
            )
        exc = _instantiate(exc_cls)
        app = _build_non_retryable_application_error(exc)

        assert isinstance(app, ApplicationError), (
            f"{exc_cls.__name__} did not wrap to ApplicationError — "
            f"fail-closed is broken"
        )
        assert app.non_retryable is True, (
            f"{exc_cls.__name__} wrapped as *retryable*. Temporal will "
            f"loop the failing activity/workflow task until the retry "
            f"policy gives up, re-running the same broken auth path "
            f"every attempt."
        )
        assert app.type == exc_cls.error_code, (  # type: ignore[attr-defined]
            f"{exc_cls.__name__} wrapped with type={app.type!r} but "
            f"error_code={exc_cls.error_code!r}"  # type: ignore[attr-defined]
        )
        assert app.__cause__ is exc, (
            f"{exc_cls.__name__}: __cause__ was not preserved; Temporal's "
            f"traceback will point at the wrapper, not at the Tenuo "
            f"exception that actually rejected the action."
        )


# ── Wrapper smoke tests: each call site actually reaches the builder ─────


class TestWrappersDelegateToBuilder:
    """Smoke-test each wrapper call site with a single representative
    exception. The *data* sweep (builder contract) + *structural* sweep
    (AST guard) together prove that every wrapper goes through the
    builder for every exception class. These thin tests are belt-and-
    suspenders: they catch "wrapper stops being called at all" or
    "wrapper raises its own unrelated error" regressions that neither
    the data nor structural sweep would notice.
    """

    def _representative_exception(self) -> BaseException:
        from tenuo.temporal.exceptions import PopVerificationError

        return PopVerificationError(
            reason="smoke-test", activity_name="sweep",
        )

    def test_raise_non_retryable_delegates(self) -> None:
        original = self._representative_exception()
        try:
            _raise_non_retryable(original)
        except ApplicationError as app:
            assert app.non_retryable is True
            assert app.type == type(original).error_code  # type: ignore[attr-defined]
            assert app.__cause__ is original
        else:  # pragma: no cover — helper always raises
            pytest.fail("_raise_non_retryable must raise")

    def test_wrap_as_non_retryable_delegates(self) -> None:
        original = self._representative_exception()
        wrapped = TenuoActivityInboundInterceptor._wrap_as_non_retryable(original)
        assert isinstance(wrapped, ApplicationError)
        assert wrapped.non_retryable is True
        assert wrapped.type == type(original).error_code  # type: ignore[attr-defined]
        assert wrapped.__cause__ is original

    def test_fail_workflow_non_retryable_delegates(self) -> None:
        original = self._representative_exception()
        wrapped = _fail_workflow_non_retryable(original)
        assert isinstance(wrapped, ApplicationError)
        assert wrapped.non_retryable is True
        assert wrapped.type == type(original).error_code  # type: ignore[attr-defined]
        assert wrapped.__cause__ is original


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


# ── Structural guard: no raw ApplicationError() outside the builder ──────


class TestNoRawApplicationErrorInTemporalPackage:
    """AST-scan ``tenuo/temporal/**/*.py`` and fail if any
    ``ApplicationError(...)`` constructor call lives outside
    ``_build_non_retryable_application_error``.

    This is the *structural* half of the wire-contract enforcement.
    The data sweep (``TestBuilderContract``) only covers what it can
    enumerate — the builder — so a new wrapper that constructs
    ``ApplicationError`` directly would bypass it silently (exactly
    how ``_fail_workflow_non_retryable`` and
    ``AuthorizedWorkflow.__init__`` historically drifted from the
    contract). Adding this guard means:

      * Every existing and future wrapper must funnel through the
        builder (enforced at test time by this scan).
      * The builder is then the *only* thing the data sweep has to
        cover — one construction site, one test, impossible to
        skip-list a new wrapper into a quiet regression.

    If this test fails because you legitimately need a new construction
    site: ask yourself whether the new call site preserves all three
    legs of the contract (``non_retryable=True``, stable
    ``error_code``, ``__cause__`` preserved). If yes, route it through
    the builder. If no, you're weakening the wire contract — don't.
    """

    _BUILDER_NAME = "_build_non_retryable_application_error"

    def _temporal_package_py_files(self) -> list[Path]:
        """Every .py file in the ``tenuo/temporal`` package tree."""
        from tenuo import temporal as _tenuo_temporal_pkg

        package_root = Path(_tenuo_temporal_pkg.__file__).resolve().parent
        return sorted(package_root.rglob("*.py"))

    def test_only_builder_constructs_application_error(self) -> None:
        violations: list[str] = []
        saw_any_py_file = False

        for py_path in self._temporal_package_py_files():
            saw_any_py_file = True
            source = py_path.read_text()
            try:
                tree = ast.parse(source, filename=str(py_path))
            except SyntaxError as e:  # pragma: no cover — defensive
                pytest.fail(f"Cannot parse {py_path}: {e}")

            # Build a map from each Call node to the FunctionDef /
            # AsyncFunctionDef that encloses it (or None if it's at
            # module scope). We walk top-down and pass the enclosing
            # function name down manually because ``ast`` doesn't
            # expose parent pointers.
            def _scan(node: ast.AST, enclosing_func: str | None) -> None:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    enclosing_func = node.name
                if isinstance(node, ast.Call) and _is_application_error_call(node.func):
                    if enclosing_func != self._BUILDER_NAME:
                        rel = py_path.relative_to(py_path.parents[2])
                        violations.append(
                            f"{rel}:{node.lineno}: ApplicationError(...) "
                            f"constructed inside "
                            f"{enclosing_func or '<module>'}() — must go "
                            f"through {self._BUILDER_NAME}() so the "
                            f"three-leg wire contract "
                            f"(non_retryable + error_code + __cause__) "
                            f"is enforced by construction."
                        )
                for child in ast.iter_child_nodes(node):
                    _scan(child, enclosing_func)

            _scan(tree, None)

        assert saw_any_py_file, (
            "AST scan found no .py files under tenuo/temporal — fixture "
            "is broken, not a real pass."
        )
        assert not violations, (
            "Direct ApplicationError(...) constructions detected in "
            "tenuo/temporal. Route them through "
            f"{self._BUILDER_NAME}() in tenuo/temporal/exceptions.py:\n\n"
            + "\n".join(violations)
        )


def _is_application_error_call(func: ast.AST) -> bool:
    """True if the call target is ``ApplicationError`` — either the
    bare name (``ApplicationError(...)``) or an attribute
    (``temporalio.exceptions.ApplicationError(...)``).
    """
    if isinstance(func, ast.Name):
        return func.id == "ApplicationError"
    if isinstance(func, ast.Attribute):
        return func.attr == "ApplicationError"
    return False


# ── Drift guard: adding a new exception without error_code is flagged ──


class TestNewExceptionsDeclareErrorCode:
    """New Tenuo exception classes must declare ``error_code``; otherwise
    the sweep above won't cover them and downstream consumers can't
    branch on the wire. This is a soft check — it skips exceptions
    flagged as intentionally untyped in ``_NO_ERROR_CODE_OK``.
    """

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
