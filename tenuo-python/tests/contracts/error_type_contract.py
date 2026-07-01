"""Canonical enforcement error_type → integration signal contract.

Each row defines how a single ``EnforcementResult.error_type`` must surface
to callers through adapter-specific mapping surfaces.  Parametric tests in
``test_integration_error_contract.py`` assert production code matches this
table so integrations cannot silently drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Optional, Type

from tenuo._enforcement import EnforcementResult

# Every value ``enforce_tool_call`` may assign to ``EnforcementResult.error_type``.
# Property tests import this set — add new error types here first.
CANONICAL_ERROR_TYPES: FrozenSet[Optional[str]] = frozenset(
    {
        None,
        "tool_not_allowed",
        "policy_violation",
        "authorization_failed",
        "expired",
        "constraint_violation",
        "tenuo_error",
        "internal_error",
        "invalid_pop",
        "approval_gate_misconfigured",
        "insufficient_approvals",
        "revoked",
    }
)


def make_denial(
    error_type: str,
    *,
    tool: str = "transfer",
    arguments: Optional[Dict[str, Any]] = None,
    denial_reason: Optional[str] = None,
    constraint_violated: Optional[str] = None,
    approval_metadata: Optional[Dict[str, Any]] = None,
) -> EnforcementResult:
    """Build a synthetic denied ``EnforcementResult`` for contract tests."""
    return EnforcementResult(
        allowed=False,
        tool=tool,
        arguments=arguments if arguments is not None else {"amount": 100},
        denial_reason=denial_reason or f"test denial ({error_type})",
        constraint_violated=constraint_violated,
        error_type=error_type,
        approval_metadata=approval_metadata,
    )


@dataclass(frozen=True)
class IntegrationExpectation:
    """Expected caller-visible signal for one adapter."""

    raises: Optional[Type[Exception]] = None
    http_status: Optional[int] = None
    http_error: Optional[str] = None
    jsonrpc_code: Optional[int] = None
    wire_type: Optional[str] = None
    tenuo_wire_code: Optional[int] = None
    got_need_in_payload: bool = False
    returns_tool_message: bool = False


@dataclass(frozen=True)
class ErrorTypeContract:
    """One row of the cross-integration error contract."""

    error_type: str
    core_exception: Type[Exception]
    result_factory: Callable[[], EnforcementResult]
    integrations: Dict[str, IntegrationExpectation] = field(default_factory=dict)


def _rows() -> list[ErrorTypeContract]:
    return [
        ErrorTypeContract(
            error_type="insufficient_approvals",
            core_exception=_exc("InsufficientApprovals"),
            result_factory=lambda: make_denial(
                "insufficient_approvals",
                approval_metadata={"got": 1, "need": 2},
            ),
            integrations={
                "core": IntegrationExpectation(raises=_exc("InsufficientApprovals")),
                "openai": IntegrationExpectation(raises=_exc("InsufficientApprovals")),
                "crewai": IntegrationExpectation(raises=_exc("InsufficientApprovalsDenied", "crewai")),
                "langgraph": IntegrationExpectation(raises=_exc("InsufficientApprovals")),
                "fastapi": IntegrationExpectation(
                    http_status=409,
                    http_error="insufficient_approvals",
                    got_need_in_payload=True,
                ),
                "mcp": IntegrationExpectation(
                    jsonrpc_code=-32002,
                    got_need_in_payload=True,
                ),
                "a2a": IntegrationExpectation(
                    raises=_exc("InsufficientApprovalsError", "a2a"),
                    tenuo_wire_code=1700,
                    got_need_in_payload=True,
                ),
                "temporal": IntegrationExpectation(wire_type="insufficient_approvals"),
            },
        ),
        ErrorTypeContract(
            error_type="expired",
            core_exception=_exc("ExpiredError"),
            result_factory=lambda: make_denial("expired", denial_reason="Warrant expired"),
            integrations={
                "core": IntegrationExpectation(raises=_exc("ExpiredError")),
                "openai": IntegrationExpectation(raises=_exc("WarrantDenied", "openai")),
                "crewai": IntegrationExpectation(raises=_exc("WarrantExpired", "crewai")),
                "langgraph": IntegrationExpectation(returns_tool_message=True),
                "fastapi": IntegrationExpectation(http_status=401, http_error="warrant_expired"),
                "temporal": IntegrationExpectation(wire_type="expired"),
            },
        ),
        ErrorTypeContract(
            error_type="tool_not_allowed",
            core_exception=_exc("ToolNotAuthorized"),
            result_factory=lambda: make_denial(
                "constraint_violation",
                constraint_violated="tool",
                denial_reason="warrant does not authorize tool 'read_file'",
                tool="read_file",
            ),
            integrations={
                "core": IntegrationExpectation(raises=_exc("ToolNotAuthorized")),
                "openai": IntegrationExpectation(raises=_exc("WarrantDenied", "openai")),
                "crewai": IntegrationExpectation(raises=_exc("WarrantToolDenied", "crewai")),
                "langgraph": IntegrationExpectation(returns_tool_message=True),
                "fastapi": IntegrationExpectation(http_status=403, http_error="authorization_denied"),
                "mcp": IntegrationExpectation(jsonrpc_code=-32001),
                "temporal": IntegrationExpectation(wire_type="tool_not_authorized"),
            },
        ),
        ErrorTypeContract(
            error_type="constraint_violation",
            core_exception=_exc("ConstraintViolation"),
            result_factory=lambda: make_denial(
                "constraint_violation",
                constraint_violated="amount",
            ),
            integrations={
                "core": IntegrationExpectation(raises=_exc("ConstraintViolation")),
                "openai": IntegrationExpectation(raises=_exc("WarrantDenied", "openai")),
                "crewai": IntegrationExpectation(
                    raises=_exc("CrewAIConstraintViolation", "crewai")
                ),
                "langgraph": IntegrationExpectation(returns_tool_message=True),
                "fastapi": IntegrationExpectation(http_status=403, http_error="authorization_denied"),
                "temporal": IntegrationExpectation(wire_type="constraint_violation"),
            },
        ),
        ErrorTypeContract(
            error_type="invalid_pop",
            core_exception=_exc("SignatureInvalid"),
            result_factory=lambda: make_denial("invalid_pop", denial_reason="bad signature"),
            integrations={
                "core": IntegrationExpectation(raises=_exc("SignatureInvalid")),
                "openai": IntegrationExpectation(raises=_exc("WarrantDenied", "openai")),
                "crewai": IntegrationExpectation(raises=_exc("InvalidPoP", "crewai")),
                "langgraph": IntegrationExpectation(returns_tool_message=True),
                "fastapi": IntegrationExpectation(http_status=403, http_error="authorization_denied"),
                "temporal": IntegrationExpectation(wire_type="signature_invalid"),
            },
        ),
    ]


def _exc(name: str, module: str = "tenuo.exceptions") -> Type[Exception]:
    if module == "tenuo.exceptions":
        from tenuo import exceptions as mod
    elif module == "crewai":
        from tenuo import crewai as mod
    elif module == "openai":
        from tenuo import openai as mod
    elif module == "a2a":
        from tenuo.a2a import errors as mod
    else:
        raise ValueError(f"unknown module {module!r}")
    return getattr(mod, name)


CONTRACT_ROWS: list[ErrorTypeContract] = _rows()

INTEGRATION_SURFACES = frozenset(
    {
        "core",
        "openai",
        "crewai",
        "langgraph",
        "fastapi",
        "mcp",
        "a2a",
        "temporal",
    }
)

# Modules that must catch auth-family exceptions explicitly (not generic fallthrough).
AUTH_CATCH_GUARD_MODULES: Dict[str, tuple[str, ...]] = {
    "tenuo.temporal._interceptors": (
        "InsufficientApprovals",
        "ApprovalGateTriggered",
        "ToolNotAuthorized",
        "ConstraintViolation",
    ),
    "tenuo.mcp.server": (
        "InsufficientApprovals",
        "ApprovalGateTriggered",
        "InvalidApproval",
        "ApprovalExpired",
    ),
    "tenuo.fastapi": (
        "InsufficientApprovals",
        "ApprovalRequired",
        "ApprovalGateTriggered",
    ),
}
