"""Exception classes for the Tenuo-Temporal integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict

from tenuo.exceptions import ApprovalGateTriggered  # noqa: F401 — re-exported

if TYPE_CHECKING:
    from temporalio.exceptions import ApplicationError


def _error_type_for_wire(exc: BaseException) -> str:
    """Return the preferred ``ApplicationError.type`` string for *exc*.

    Prefers the Tenuo ``error_code`` (e.g. ``POP_VERIFICATION_FAILED``) when
    present; this is the documented wire contract — downstream consumers that
    want to branch on "why was this denied?" can read the code off
    ``ApplicationError.type`` without string-matching the message. Falls back
    to the Python class name for exceptions that don't carry an
    ``error_code`` attribute.

    Defined here (not in ``_interceptors.py``) so the workflow-context wrapper
    (``_workflow._fail_workflow_non_retryable``) and the activity/interceptor
    wrappers share a single implementation. ``_interceptors`` re-exports the
    name under its original path for test back-compat.
    """
    code = getattr(exc, "error_code", None)
    if isinstance(code, str) and code:
        return code
    return type(exc).__name__


def _build_non_retryable_application_error(exc: BaseException) -> "ApplicationError":
    """Return a non-retryable :class:`ApplicationError` encoding *exc* per
    the Tenuo-Temporal boundary contract.

    The *single* construction site for every non-retryable auth failure that
    crosses the Temporal wire — activity-inbound, workflow-inbound,
    workflow-context helpers, ``AuthorizedWorkflow.__init__``. Three legs
    are always set:

    1. ``non_retryable=True`` — auth denials never retry (the warrant,
       constraints, and key resolver state don't change between attempts).
    2. ``type`` = :func:`_error_type_for_wire` — the stable Tenuo
       ``error_code`` (``POP_VERIFICATION_FAILED``, ``CONSTRAINT_VIOLATED``,
       …) so clients can branch on ``ApplicationError.type`` without caring
       whether the denial fired in activity or workflow context.
    3. ``__cause__ is exc`` — Temporal's traceback points back at the
       Tenuo exception that rejected the action, not at this wrapper.

    Having one constructor means the wire contract is enforced **by
    construction** rather than re-checked at every call site. A test in
    ``tests/adapters/test_boundary_contract.py`` AST-scans
    ``tenuo/temporal/**/*.py`` to make sure no new code constructs
    ``ApplicationError(...)`` directly (which would bypass this helper
    and risk regressing the contract).

    Callers that need ``raise ... from exc`` semantics should still use
    ``from`` at the raise site; the function sets ``__cause__``
    unconditionally, and ``raise X from exc`` just re-binds it to the
    same value.
    """
    from temporalio.exceptions import ApplicationError  # type: ignore[import-not-found]

    app_error = ApplicationError(
        str(exc),
        type=_error_type_for_wire(exc),
        non_retryable=True,
    )
    app_error.__cause__ = exc
    return app_error


class TenuoTemporalError(Exception):
    """Base exception for tenuo.temporal module."""


class TenuoContextError(TenuoTemporalError):
    """Raised when Tenuo context is missing or invalid."""

    error_code = "CONTEXT_MISSING"


class LocalActivityError(TenuoTemporalError):
    """Raised when a protected activity is used as local activity."""

    error_code = "LOCAL_ACTIVITY_BLOCKED"

    def __init__(self, activity_name: str) -> None:
        self.activity_name = activity_name
        super().__init__(
            f"Activity '{activity_name}' cannot be used as local activity. "
            "Protected activities must be executed as regular activities for "
            "authorization enforcement. Mark with @unprotected to allow local execution."
        )


class TenuoArgNormalizationError(TypeError):
    """Raised when an activity argument cannot be normalized for PoP signing.

    The Tenuo Temporal interceptor automatically normalizes dataclasses, dicts,
    lists, tuples, bytes, and None before PoP signing. If an argument type is
    not normalizable (e.g. set, datetime, Enum, custom class without
    ``__dataclass_fields__``), this error is raised at activity dispatch time
    (non-retryable).

    Fix by converting the argument to a dataclass, a dict, or a primitive, or
    by lifting the relevant field to a top-level primitive argument with a real
    constraint (e.g. ``Subpath``, ``AnyOf``).

    See: docs/temporal.md — "Structured state in activity arguments".
    """

    error_code = "ARG_NORMALIZATION_FAILED"


class TenuoPreValidationError(TenuoContextError):
    """Raised when an activity's args don't match the warrant before PoP signing.

    This is a diagnostic accelerator: it enumerates *all* unknown and missing
    fields in one error rather than surfacing them one-at-a-time from core.
    The authoritative check still runs in Rust — this error fires first so the
    developer can fix all field mismatches at once.

    Inherits from TenuoContextError so it is raised as non-retryable by the
    outbound interceptor's error handler (same path as other PoP signing failures).

    Contains the substring ``"unknown field not allowed (zero-trust mode)"``
    when unknown fields are present, for compatibility with any callers that
    substring-match on the core error format.
    """

    error_code = "PRE_VALIDATION_FAILED"


@dataclass
class PopVerificationError(TenuoTemporalError):
    """Raised when Proof-of-Possession verification fails.

    Attributes:
        reason: Why PoP verification failed
        activity_name: The activity that failed PoP
        error_code: Wire format error code
    """

    reason: str
    activity_name: str
    error_code: str = field(default="POP_VERIFICATION_FAILED", init=False)

    def __str__(self) -> str:
        return f"PoP verification failed for '{self.activity_name}': {self.reason}"


@dataclass
class TemporalConstraintViolation(TenuoTemporalError):
    """Raised when an activity violates warrant constraints.

    Attributes:
        tool: The tool/activity that was denied
        arguments: The arguments that were checked
        constraint: The constraint that was violated
        warrant_id: The warrant that denied the action
        error_code: Wire format error code
    """

    tool: str
    arguments: Dict[str, Any]
    constraint: str
    warrant_id: str
    error_code: str = field(default="CONSTRAINT_VIOLATED", init=False)

    def __str__(self) -> str:
        return f"Activity '{self.tool}' denied: {self.constraint} (warrant: {self.warrant_id})"


@dataclass
class WarrantExpired(TenuoTemporalError):
    """Raised when the warrant has expired.

    Attributes:
        warrant_id: The expired warrant
        expired_at: When the warrant expired
        error_code: Wire format error code
    """

    warrant_id: str
    expired_at: datetime
    error_code: str = field(default="WARRANT_EXPIRED", init=False)

    def __str__(self) -> str:
        return f"Warrant '{self.warrant_id}' expired at {self.expired_at}"


@dataclass
class ChainValidationError(TenuoTemporalError):
    """Raised when warrant chain validation fails.

    Attributes:
        reason: Description of the validation failure
        depth: The depth at which validation failed
        error_code: Wire format error code
    """

    reason: str
    depth: int
    error_code: str = field(default="CHAIN_INVALID", init=False)

    def __str__(self) -> str:
        return f"Warrant chain invalid at depth {self.depth}: {self.reason}"


@dataclass
class KeyResolutionError(TenuoTemporalError):
    """Raised when a signing key cannot be resolved.

    Attributes:
        key_id: The key ID that could not be resolved
        error_code: Wire format error code
    """

    key_id: str
    error_code: str = field(default="KEY_NOT_FOUND", init=False)

    def __str__(self) -> str:
        return f"Cannot resolve key: {self.key_id}"
