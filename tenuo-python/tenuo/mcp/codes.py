"""Stable denial codes for MCP brokers and job summaries.

JSON-RPC still uses ``-32001`` / ``-32002``. These codes travel beside it
(``MCPVerificationResult.error_code`` and ``error.data.code``) so a broker
can map a refusal without parsing prose.

Receipt payload key 10 stays kebab-case (``constraint-violation``). These
``TENUO_*`` codes are the wire-facing names for the same categories.
"""

from __future__ import annotations

from typing import Optional, Tuple

TENUO_TOOL_NOT_AUTHORIZED = "TENUO_TOOL_NOT_AUTHORIZED"
TENUO_CONSTRAINT_VIOLATION = "TENUO_CONSTRAINT_VIOLATION"
TENUO_INVALID_POP = "TENUO_INVALID_POP"
TENUO_REVOKED = "TENUO_REVOKED"
TENUO_WARRANT_EXPIRED = "TENUO_WARRANT_EXPIRED"
TENUO_UNTRUSTED_ROOT = "TENUO_UNTRUSTED_ROOT"
TENUO_APPROVAL_REQUIRED = "TENUO_APPROVAL_REQUIRED"

# error_type (EnforcementResult / receipts) → TENUO_*
_CODE_BY_ERROR_TYPE = {
    "tool_not_allowed": TENUO_TOOL_NOT_AUTHORIZED,
    "constraint_violation": TENUO_CONSTRAINT_VIOLATION,
    "policy_violation": TENUO_CONSTRAINT_VIOLATION,
    "invalid_pop": TENUO_INVALID_POP,
    "revoked": TENUO_REVOKED,
    "expired": TENUO_WARRANT_EXPIRED,
    "untrusted_issuer": TENUO_UNTRUSTED_ROOT,
    "insufficient_approvals": TENUO_APPROVAL_REQUIRED,
    "approval_required": TENUO_APPROVAL_REQUIRED,
    "approval_gate_misconfigured": TENUO_APPROVAL_REQUIRED,
}


def code_for_error_type(error_type: Optional[str]) -> Optional[str]:
    """Map an ``EnforcementResult.error_type`` to a ``TENUO_*`` code."""
    if not error_type:
        return None
    return _CODE_BY_ERROR_TYPE.get(error_type)


def error_type_and_code(exc: BaseException) -> Tuple[str, str]:
    """Classify a verification exception for receipts and the broker."""
    from ..exceptions import (
        ApprovalExpired,
        ApprovalGateTriggered,
        ConstraintViolation,
        ExpiredError,
        InsufficientApprovals,
        InvalidApproval,
        MissingSignature,
        RevokedError,
        SignatureInvalid,
        SignatureMismatch,
        ToolMismatch,
        ToolNotAuthorized,
        UntrustedRoot,
    )

    if isinstance(exc, (ToolNotAuthorized, ToolMismatch)):
        return "tool_not_allowed", TENUO_TOOL_NOT_AUTHORIZED
    if isinstance(exc, ConstraintViolation):
        return "constraint_violation", TENUO_CONSTRAINT_VIOLATION
    if isinstance(exc, (MissingSignature, SignatureInvalid, SignatureMismatch)):
        return "invalid_pop", TENUO_INVALID_POP
    if isinstance(exc, RevokedError):
        return "revoked", TENUO_REVOKED
    if isinstance(exc, ExpiredError):
        return "expired", TENUO_WARRANT_EXPIRED
    if isinstance(exc, UntrustedRoot):
        return "untrusted_issuer", TENUO_UNTRUSTED_ROOT
    if isinstance(exc, InsufficientApprovals):
        return "insufficient_approvals", TENUO_APPROVAL_REQUIRED
    if isinstance(exc, ApprovalGateTriggered):
        return "approval_required", TENUO_APPROVAL_REQUIRED
    if isinstance(exc, (InvalidApproval, ApprovalExpired)):
        return "invalid_pop", TENUO_INVALID_POP
    return "authorization_failed", TENUO_TOOL_NOT_AUTHORIZED
