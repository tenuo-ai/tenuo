"""
A2A Adapter - Error definitions.

JSON-RPC error codes and exception classes for A2A protocol.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__all__ = [
    # Error codes
    "A2AErrorCode",
    "ERROR_MESSAGES",
    # Base error
    "A2AError",
    # Warrant validation errors
    "MissingWarrantError",
    "InvalidSignatureError",
    "UntrustedIssuerError",
    "WarrantExpiredError",
    "AudienceMismatchError",
    "ReplayDetectedError",
    # PoP errors
    "PopRequiredError",
    "PopVerificationError",
    # Authorization errors
    "SkillNotGrantedError",
    "SkillNotFoundError",
    "ConstraintViolationError",
    "UnknownConstraintError",
    "RevokedError",
    # Chain errors
    "ChainReason",
    "ChainInvalidError",
    "ChainMissingError",
    "ChainValidationError",
    # Client errors
    "KeyMismatchError",
    "MissingSigningKeyError",
    # Configuration errors
    "ConstraintBindingError",
]


# =============================================================================
# JSON-RPC Error Codes (A2A-specific)
# =============================================================================


class A2AErrorCode:
    """JSON-RPC error codes for A2A protocol errors."""

    # Standard JSON-RPC errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # A2A Tenuo-specific errors (-32001 to -32099)
    MISSING_WARRANT = -32001
    INVALID_SIGNATURE = -32002
    UNTRUSTED_ISSUER = -32003
    EXPIRED = -32004
    AUDIENCE_MISMATCH = -32005
    REPLAY_DETECTED = -32006
    SKILL_NOT_GRANTED = -32007
    CONSTRAINT_VIOLATION = -32008
    REVOKED = -32009
    CHAIN_INVALID = -32010
    CHAIN_MISSING = -32011
    KEY_MISMATCH = -32012
    SKILL_NOT_FOUND = -32013  # Skill doesn't exist on server (vs not granted in warrant)
    UNKNOWN_CONSTRAINT = -32014  # Constraint type not recognized
    POP_REQUIRED = -32015  # Proof-of-Possession required but not provided
    POP_FAILED = -32016  # Proof-of-Possession verification failed


# Code to name mapping
ERROR_MESSAGES = {
    A2AErrorCode.MISSING_WARRANT: "missing_warrant",
    A2AErrorCode.INVALID_SIGNATURE: "invalid_signature",
    A2AErrorCode.UNTRUSTED_ISSUER: "untrusted_issuer",
    A2AErrorCode.EXPIRED: "expired",
    A2AErrorCode.AUDIENCE_MISMATCH: "audience_mismatch",
    A2AErrorCode.REPLAY_DETECTED: "replay_detected",
    A2AErrorCode.SKILL_NOT_GRANTED: "skill_not_granted",
    A2AErrorCode.CONSTRAINT_VIOLATION: "constraint_violation",
    A2AErrorCode.REVOKED: "revoked",
    A2AErrorCode.CHAIN_INVALID: "chain_invalid",
    A2AErrorCode.CHAIN_MISSING: "chain_missing",
    A2AErrorCode.KEY_MISMATCH: "key_mismatch",
    A2AErrorCode.SKILL_NOT_FOUND: "skill_not_found",
    A2AErrorCode.UNKNOWN_CONSTRAINT: "unknown_constraint",
    A2AErrorCode.POP_REQUIRED: "pop_required",
    A2AErrorCode.POP_FAILED: "pop_failed",
}


# =============================================================================
# Base Exception
# =============================================================================


class A2AError(Exception):
    """Base exception for A2A errors."""

    code: int = A2AErrorCode.INTERNAL_ERROR

    def __init__(self, message: str, data: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.data = data or {}

    def to_jsonrpc_error(self) -> Dict[str, Any]:
        """Convert to JSON-RPC error response."""
        error = {
            "code": self.code,
            "message": ERROR_MESSAGES.get(self.code, str(self.message)),
        }
        if self.data:
            error["data"] = self.data
        return error


# =============================================================================
# Warrant Validation Errors
# =============================================================================


class MissingWarrantError(A2AError):
    """Warrant required but not provided."""

    code = A2AErrorCode.MISSING_WARRANT


class InvalidSignatureError(A2AError):
    """Warrant signature verification failed."""

    code = A2AErrorCode.INVALID_SIGNATURE


class UntrustedIssuerError(A2AError):
    """Warrant issuer not in trusted_issuers list."""

    code = A2AErrorCode.UNTRUSTED_ISSUER

    def __init__(self, issuer: str, message: str = "Issuer not trusted", *, reason: str = ""):
        super().__init__(reason if reason else message, {"issuer": issuer, "reason": reason if reason else message})


class WarrantExpiredError(A2AError):
    """Warrant has expired."""

    code = A2AErrorCode.EXPIRED

    def __init__(self, message: str = "Warrant expired", mid_stream: bool = False):
        super().__init__(message, {"mid_stream": mid_stream})


class AudienceMismatchError(A2AError):
    """Warrant audience doesn't match server URL."""

    code = A2AErrorCode.AUDIENCE_MISMATCH

    def __init__(self, expected: str, actual: str):
        super().__init__(
            f"Audience mismatch: expected {expected}, got {actual}", {"expected": expected, "actual": actual}
        )


class ReplayDetectedError(A2AError):
    """Warrant jti has already been used."""

    code = A2AErrorCode.REPLAY_DETECTED

    def __init__(self, jti: str):
        super().__init__(f"Warrant {jti} already used", {"jti": jti})


# =============================================================================
# Authorization Errors
# =============================================================================


class SkillNotGrantedError(A2AError):
    """Requested skill not granted in warrant.

    Note: The list of granted skills is intentionally NOT included in the
    error response to prevent capability enumeration attacks.
    """

    code = A2AErrorCode.SKILL_NOT_GRANTED

    def __init__(self, skill: str, granted_skills: list[str]):
        # SECURITY: Don't expose granted_skills in error response to prevent enumeration
        super().__init__(f"Skill '{skill}' not granted in warrant", {"skill": skill})
        # Store internally for logging/debugging but not in wire format
        self._granted_skills = granted_skills


class SkillNotFoundError(A2AError):
    """Skill doesn't exist on this server (different from not granted in warrant).

    Note: The list of available skills is intentionally NOT included in the
    error response to prevent capability enumeration attacks. Use the agent
    card discovery endpoint for legitimate capability discovery.
    """

    code = A2AErrorCode.SKILL_NOT_FOUND

    def __init__(self, skill: str, available_skills: list[str]):
        # SECURITY: Don't expose available_skills in error response to prevent enumeration
        super().__init__(f"Skill '{skill}' not found on this server", {"skill": skill})
        # Store internally for logging/debugging but not in wire format
        self._available_skills = available_skills


class ConstraintViolationError(A2AError):
    """Argument failed constraint check.

    Note: The actual value that violated the constraint is intentionally NOT
    included in the error response to prevent information leakage. The value
    is stored internally for server-side logging.
    """

    code = A2AErrorCode.CONSTRAINT_VIOLATION

    def __init__(self, param: str, constraint_type: str, value: Any, reason: str = ""):
        # SECURITY: Don't expose actual value in error response - could leak
        # attempted attack payloads (path traversal, SSRF targets, etc.)
        super().__init__(
            f"Constraint violation on '{param}': {reason}",
            {
                "param": param,
                "constraint_type": constraint_type,
                "reason": reason,
            },
        )
        # Store internally for server-side logging/debugging
        self._value = value


class UnknownConstraintError(A2AError):
    """Constraint type is not recognized - fail closed for security."""

    code = A2AErrorCode.UNKNOWN_CONSTRAINT

    def __init__(self, constraint_type: str, param: str):
        super().__init__(
            f"Unknown constraint type '{constraint_type}' on '{param}' - denied for security",
            {"constraint_type": constraint_type, "param": param},
        )


class RevokedError(A2AError):
    """
    Warrant or issuer has been revoked.

    NOTE: Reserved for future use. Revocation checking is not currently
    implemented in A2A - requires integration with revocation service.
    Error code -32009 is reserved for this purpose.
    """

    code = A2AErrorCode.REVOKED


# =============================================================================
# Chain Validation Errors
# =============================================================================


class ChainReason:
    """Reasons for chain validation failure."""

    ISSUER_MISMATCH = "issuer_mismatch"
    NOT_ATTENUATED = "not_attenuated"
    UNTRUSTED_ROOT = "untrusted_root"
    MAX_DEPTH_EXCEEDED = "max_depth_exceeded"
    PARENT_EXPIRED = "parent_expired"
    SIGNATURE_INVALID = "signature_invalid"


class ChainInvalidError(A2AError):
    """Delegation chain validation failed."""

    code = A2AErrorCode.CHAIN_INVALID

    def __init__(
        self,
        reason: str,
        depth: int = 0,
        expected_issuer: Optional[str] = None,
        actual_issuer: Optional[str] = None,
        warrant_jti: Optional[str] = None,
    ):
        data = {"reason": reason, "depth": depth}
        if expected_issuer:
            data["expected_issuer"] = expected_issuer
        if actual_issuer:
            data["actual_issuer"] = actual_issuer
        if warrant_jti:
            data["warrant_jti"] = warrant_jti
        super().__init__(f"Chain validation failed: {reason}", data)


class ChainMissingError(A2AError):
    """Chain header required but not provided."""

    code = A2AErrorCode.CHAIN_MISSING


class ChainValidationError(A2AError):
    """
    Generic chain validation error.

    Used when the delegation chain fails validation for reasons like:
    - Empty chain
    - Depth exceeded
    - Linkage broken
    - Warrant parse failure
    """

    code = A2AErrorCode.CHAIN_INVALID

    def __init__(self, message: str, depth: int = 0):
        super().__init__(message, {"reason": message, "depth": depth})


# =============================================================================
# Client Errors
# =============================================================================


class KeyMismatchError(A2AError):
    """Agent public key doesn't match pinned key."""

    code = A2AErrorCode.KEY_MISMATCH

    def __init__(self, expected: str, actual: str):
        super().__init__(
            f"Key mismatch: expected {expected[:20]}..., got {actual[:20]}...", {"expected": expected, "actual": actual}
        )


# =============================================================================
# Server Configuration Errors
# =============================================================================


class ConstraintBindingError(Exception):
    """
    Constraint key doesn't match any function parameter.

    Raised at server startup to catch configuration errors.
    """

    def __init__(self, skill: str, constraint_key: str, available_params: list[str]):
        self.skill = skill
        self.constraint_key = constraint_key
        self.available_params = available_params
        super().__init__(
            f"Constraint '{constraint_key}' does not match any parameter of skill "
            f"'{skill}'. Available: {available_params}"
        )


# =============================================================================
# Proof-of-Possession Errors
# =============================================================================


class PopRequiredError(A2AError):
    """Proof-of-Possession signature required but not provided."""

    code = A2AErrorCode.POP_REQUIRED

    def __init__(self, message: str = "Proof-of-Possession required"):
        super().__init__(message, {"reason": "pop_header_missing"})


class PopVerificationError(A2AError):
    """Proof-of-Possession signature verification failed."""

    code = A2AErrorCode.POP_FAILED

    def __init__(self, reason: str = "signature verification failed"):
        super().__init__(
            f"Proof-of-Possession failed: {reason}",
            {"reason": reason},
        )


class MissingSigningKeyError(A2AError):
    """Signing key required for PoP but not provided.

    Client-side error when agent requires PoP but no signing_key was provided.
    """

    code = A2AErrorCode.POP_REQUIRED

    def __init__(self):
        super().__init__(
            "Signing key required for Proof-of-Possession. "
            "The agent requires PoP authentication. "
            "Pass signing_key parameter to send_task().",
            {"reason": "signing_key_missing"},
        )
