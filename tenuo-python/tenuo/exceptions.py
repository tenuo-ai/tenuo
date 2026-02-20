"""
Pythonic exceptions for Tenuo operations.

These exceptions map 1:1 to Rust Error variants in tenuo-core/src/error.rs.
Keep these in sync! Run test_error_mapping.py to verify.

Error Hierarchy:
    TenuoError (base)
    ├── CryptoError (signature & cryptographic)
    │   ├── SignatureInvalid
    │   ├── MissingSignature
    │   └── InvalidSignature (alias)
    ├── ScopeViolation (authorization scope exceeded)
    │   ├── ToolNotAuthorized
    │   ├── ToolMismatch
    │   ├── ConstraintViolation
    │   ├── ExpiredError
    │   └── Unauthorized
    ├── MonotonicityError (attenuation violations)
    │   ├── IncompatibleConstraintTypes
    │   ├── WildcardExpansion
    │   ├── EmptyResultSet
    │   ├── ExclusionRemoved
    │   ├── ValueNotInParentSet
    │   ├── RangeExpanded
    │   ├── PatternExpanded
    │   ├── RequiredValueRemoved
    │   └── ExactValueMismatch
    ├── ClearanceViolation (clearance level issues)
    │   └── ClearanceLevelExceeded
    ├── IssuanceError (issuer warrant operations)
    │   ├── UnauthorizedToolIssuance
    │   ├── SelfIssuanceProhibited
    │   ├── IssueDepthExceeded
    │   ├── InvalidWarrantType
    │   └── IssuerChainTooLong
    ├── PopError (Proof-of-Possession failures)
    │   ├── MissingSigningKey
    │   ├── SignatureMismatch
    │   └── PopExpired
    ├── ChainError (delegation chain issues)
    │   ├── BrokenChain
    │   ├── CycleDetected
    │   ├── UntrustedRoot
    │   └── ParentRequired
    ├── LimitError (protocol limits exceeded)
    │   ├── DepthExceeded
    │   ├── ConstraintDepthExceeded
    │   └── PayloadTooLarge
    ├── RevokedError (warrant revoked)
    ├── ValidationError (field/format validation)
    │   ├── MissingField
    │   ├── InvalidWarrantId
    │   └── InvalidTtl
    ├── ConstraintSyntaxError (constraint definition)
    │   ├── InvalidPattern
    │   ├── InvalidRange
    │   ├── InvalidRegex
    │   └── CelError
    ├── SerializationError (wire format)
    │   ├── DeserializationError
    │   └── UnsupportedVersion
    ├── ApprovalError (multi-sig)
    │   ├── ApprovalExpired
    │   ├── InsufficientApprovals
    │   ├── InvalidApproval
    │   └── UnknownProvider
    └── ConfigurationError (invalid configuration)
"""

from typing import Optional, Any


# =============================================================================
# Canonical Error Codes (Wire Format Spec §Appendix A)
# =============================================================================


class ErrorCode:
    """Canonical Tenuo error codes from wire format spec.

    These codes (1000-2199) are the single source of truth for error
    representation. Protocol-specific formats (HTTP strings, JSON-RPC
    negative codes) derive from these.

    Ranges:
        1000-1099: Envelope errors
        1100-1199: Signature errors
        1200-1299: Payload structure errors
        1300-1399: Temporal validation errors
        1400-1499: Chain validation errors
        1500-1599: Capability errors
        1600-1699: PoP errors
        1700-1799: Multi-sig errors
        1800-1899: Revocation errors
        1900-1999: Size limit errors
        2000-2099: Extension errors
        2100-2199: Reserved namespace errors
    """

    # Envelope errors (1000-1099)
    UNSUPPORTED_ENVELOPE_VERSION = 1000
    INVALID_ENVELOPE_STRUCTURE = 1001

    # Signature errors (1100-1199)
    SIGNATURE_INVALID = 1100
    SIGNATURE_ALGORITHM_MISMATCH = 1101
    UNSUPPORTED_ALGORITHM = 1102
    INVALID_KEY_LENGTH = 1103
    INVALID_SIGNATURE_LENGTH = 1104

    # Payload structure errors (1200-1299)
    UNSUPPORTED_PAYLOAD_VERSION = 1200
    INVALID_PAYLOAD_STRUCTURE = 1201
    MALFORMED_CBOR = 1202
    UNKNOWN_PAYLOAD_FIELD = 1203
    MISSING_REQUIRED_FIELD = 1204

    # Temporal validation errors (1300-1399)
    WARRANT_EXPIRED = 1300
    WARRANT_NOT_YET_VALID = 1301
    ISSUED_IN_FUTURE = 1302
    TTL_EXCEEDED = 1303

    # Chain validation errors (1400-1499)
    INVALID_ISSUER = 1400
    PARENT_HASH_MISMATCH = 1401
    DEPTH_EXCEEDED = 1402
    DEPTH_VIOLATION = 1403
    CHAIN_TOO_LONG = 1404
    CHAIN_BROKEN = 1405
    UNTRUSTED_ROOT = 1406

    # Capability errors (1500-1599)
    TOOL_NOT_AUTHORIZED = 1500
    CONSTRAINT_VIOLATION = 1501
    INVALID_ATTENUATION = 1502
    CAPABILITY_EXPANSION = 1503
    UNKNOWN_CONSTRAINT_TYPE = 1504

    # PoP errors (1600-1699)
    POP_SIGNATURE_INVALID = 1600
    POP_EXPIRED = 1601
    POP_CHALLENGE_INVALID = 1602

    # Multi-sig errors (1700-1799)
    INSUFFICIENT_APPROVALS = 1700
    APPROVAL_INVALID = 1701
    APPROVER_NOT_AUTHORIZED = 1702
    APPROVAL_EXPIRED = 1703
    UNSUPPORTED_APPROVAL_VERSION = 1704
    APPROVAL_PAYLOAD_INVALID = 1705
    APPROVAL_REQUEST_HASH_MISMATCH = 1706

    # Revocation errors (1800-1899)
    WARRANT_REVOKED = 1800
    SRL_INVALID = 1801
    SRL_VERSION_ROLLBACK = 1802

    # Size limit errors (1900-1999)
    WARRANT_TOO_LARGE = 1900
    CHAIN_TOO_LARGE = 1901
    TOO_MANY_TOOLS = 1902
    TOO_MANY_CONSTRAINTS = 1903
    EXTENSION_TOO_LARGE = 1904
    VALUE_TOO_LARGE = 1905

    # Extension errors (2000-2099)
    RESERVED_EXTENSION_KEY = 2000
    INVALID_EXTENSION_VALUE = 2001

    # Reserved namespace errors (2100-2199)
    RESERVED_TOOL_NAME = 2100

    @staticmethod
    def to_name(code: int) -> str:
        """Convert numeric code to kebab-case string name."""
        name_map = {
            1000: "unsupported-envelope-version",
            1001: "invalid-envelope-structure",
            1100: "signature-invalid",
            1101: "signature-algorithm-mismatch",
            1102: "unsupported-algorithm",
            1103: "invalid-key-length",
            1104: "invalid-signature-length",
            1200: "unsupported-payload-version",
            1201: "invalid-payload-structure",
            1202: "malformed-cbor",
            1203: "unknown-payload-field",
            1204: "missing-required-field",
            1300: "warrant-expired",
            1301: "warrant-not-yet-valid",
            1302: "issued-in-future",
            1303: "ttl-exceeded",
            1400: "invalid-issuer",
            1401: "parent-hash-mismatch",
            1402: "depth-exceeded",
            1403: "depth-violation",
            1404: "chain-too-long",
            1405: "chain-broken",
            1406: "untrusted-root",
            1500: "tool-not-authorized",
            1501: "constraint-violation",
            1502: "invalid-attenuation",
            1503: "capability-expansion",
            1504: "unknown-constraint-type",
            1600: "pop-signature-invalid",
            1601: "pop-expired",
            1602: "pop-challenge-invalid",
            1700: "insufficient-approvals",
            1701: "approval-invalid",
            1702: "approver-not-authorized",
            1703: "approval-expired",
            1704: "unsupported-approval-version",
            1705: "approval-payload-invalid",
            1706: "approval-request-hash-mismatch",
            1800: "warrant-revoked",
            1801: "srl-invalid",
            1802: "srl-version-rollback",
            1900: "warrant-too-large",
            1901: "chain-too-large",
            1902: "too-many-tools",
            1903: "too-many-constraints",
            1904: "extension-too-large",
            1905: "value-too-large",
            2000: "reserved-extension-key",
            2001: "invalid-extension-value",
            2100: "reserved-tool-name",
        }
        return name_map.get(code, "unknown-error")

    @staticmethod
    def to_http_status(code: int) -> int:
        """Get HTTP status code from error code category."""
        category = code // 100
        status_map = {
            10: 400,  # Envelope errors -> Bad Request
            11: 401,  # Signature errors -> Unauthorized
            12: 400,  # Payload errors -> Bad Request
            13: 401,  # Temporal errors -> Unauthorized
            14: 403,  # Chain errors -> Forbidden
            15: 403,  # Capability errors -> Forbidden
            16: 401,  # PoP errors -> Unauthorized
            17: 403,  # Approval errors -> Forbidden
            18: 401,  # Revocation -> Unauthorized
            19: 413,  # Size limits -> Payload Too Large
            20: 400,  # Extensions -> Bad Request
            21: 400,  # Reserved namespace -> Bad Request
        }
        return status_map.get(category, 500)


# =============================================================================
# Error Code Registry
# =============================================================================

# Registry mapping exception classes to wire format codes
# Populated via @wire_code decorator
ERROR_CODE_REGISTRY: dict[type, int] = {}


def wire_code(code: int):
    """Decorator to assign canonical wire format error code to an exception.

    Usage:
        @wire_code(ErrorCode.SIGNATURE_INVALID)
        class SignatureInvalid(CryptoError):
            ...

    The decorator registers the exception class in ERROR_CODE_REGISTRY,
    allowing dynamic lookup via exception.get_wire_code().
    """

    def decorator(cls):
        ERROR_CODE_REGISTRY[cls] = code
        return cls

    return decorator


# =============================================================================
# Base Exception
# =============================================================================


class TenuoError(Exception):
    """Base exception for all Tenuo errors."""

    error_code: str = "tenuo_error"  # Legacy string code
    rust_variant: str = ""  # Corresponding Rust Error variant name

    def __init__(self, message: str, details: Optional[dict[str, Any]] = None, hint: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.hint = hint

    def __str__(self) -> str:
        base = super().__str__()
        if self.hint:
            return f"{base}\nHint: {self.hint}"
        return base

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for structured logging."""
        result: dict[str, Any] = {
            "error_code": self.error_code,  # Legacy string code
            "rust_variant": self.rust_variant,
            "category": self.__class__.__bases__[0].__name__ if self.__class__.__bases__ else "TenuoError",
            "type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }
        # Include canonical code if available
        wire_code = self.get_wire_code()
        if wire_code > 0:
            result["wire_code"] = wire_code
            result["wire_name"] = self.get_wire_name()
        return result

    def get_wire_code(self) -> int:
        """Get canonical wire format code (1000-2199).

        Returns 0 if no wire code registered for this exception class.
        """
        return ERROR_CODE_REGISTRY.get(type(self), 0)

    def get_wire_name(self) -> str:
        """Get kebab-case error name derived from wire code."""
        code = self.get_wire_code()
        return ErrorCode.to_name(code) if code > 0 else self.error_code

    def get_http_status(self) -> int:
        """Get HTTP status code based on error category."""
        code = self.get_wire_code()
        return ErrorCode.to_http_status(code) if code > 0 else 500


# =============================================================================
# Cryptographic Errors (Signature & Crypto)
# =============================================================================


@wire_code(ErrorCode.SIGNATURE_INVALID)
class CryptoError(TenuoError):
    """Cryptographic operation failed."""

    error_code = "crypto_error"
    rust_variant = "CryptoError"


@wire_code(ErrorCode.SIGNATURE_INVALID)
class SignatureInvalid(CryptoError):
    """Warrant signature verification failed."""

    error_code = "signature_invalid"
    rust_variant = "SignatureInvalid"

    def __init__(self, reason: str = "", hint: Optional[str] = None):
        super().__init__(
            f"Signature verification failed: {reason}" if reason else "Signature verification failed",
            {"reason": reason},
            hint=hint,
        )


@wire_code(ErrorCode.SIGNATURE_INVALID)
class MissingSignature(CryptoError):
    """Missing signature for Proof-of-Possession."""

    error_code = "missing_signature"
    rust_variant = "MissingSignature"

    def __init__(self, reason: str = "", hint: Optional[str] = None):
        super().__init__(
            f"Missing signature: {reason}" if reason else "Missing signature", {"reason": reason}, hint=hint
        )


# =============================================================================
# Scope Violations (authorization scope exceeded)
# =============================================================================


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class ScopeViolation(TenuoError):
    """Authorization scope was exceeded."""

    error_code = "scope_violation"
    rust_variant = "Unauthorized"


# User-facing alias - ScopeViolation is the internal name
AuthorizationError = ScopeViolation


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class ToolNotAuthorized(ScopeViolation):
    """Tool is not authorized by the warrant."""

    error_code = "tool_not_authorized"
    rust_variant = "Unauthorized"

    def __init__(self, tool: str, authorized_tools: Optional[list[str]] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {"tool": tool}
        if authorized_tools:
            details["authorized_tools"] = authorized_tools
        super().__init__(f"Tool '{tool}' is not authorized", details, hint=hint)


@wire_code(ErrorCode.INVALID_ATTENUATION)
class ToolMismatch(ScopeViolation):
    """Tool name mismatch during attenuation."""

    error_code = "tool_mismatch"
    rust_variant = "ToolMismatch"

    def __init__(self, parent_tool: str, child_tool: str, hint: Optional[str] = None):
        super().__init__(
            f"Tool name mismatch: parent has '{parent_tool}', child has '{child_tool}'",
            {"parent_tool": parent_tool, "child_tool": child_tool},
            hint=hint,
        )


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class ConstraintViolation(ScopeViolation):
    """Constraint was not satisfied."""

    error_code = "constraint_violation"
    rust_variant = "ConstraintNotSatisfied"

    def __init__(self, field: str, reason: str, value: Optional[Any] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {"field": field, "reason": reason}
        if value is not None:
            details["value"] = str(value)
        super().__init__(f"Constraint '{field}' not satisfied: {reason}", details, hint=hint)


@wire_code(ErrorCode.WARRANT_EXPIRED)
class ExpiredError(ScopeViolation):
    """Warrant has expired."""

    error_code = "expired"
    rust_variant = "WarrantExpired"

    def __init__(self, warrant_id: str, expired_at: Optional[str] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {"warrant_id": warrant_id}
        if expired_at:
            details["expired_at"] = expired_at
        super().__init__(f"Warrant '{warrant_id}' has expired", details, hint=hint)


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class Unauthorized(ScopeViolation):
    """Operation unauthorized."""

    error_code = "unauthorized"
    rust_variant = "Unauthorized"

    def __init__(self, reason: str = "", hint: Optional[str] = None):
        super().__init__(f"Unauthorized: {reason}" if reason else "Unauthorized", {"reason": reason}, hint=hint)


# =============================================================================
# Monotonicity Errors (Attenuation Violations)
# =============================================================================


@wire_code(ErrorCode.INVALID_ATTENUATION)
class MonotonicityError(TenuoError):
    """Attenuation would expand capabilities (violates monotonicity)."""

    error_code = "monotonicity_violation"
    rust_variant = "MonotonicityViolation"

    def __init__(self, reason: str, field: Optional[str] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {"reason": reason}
        if field:
            details["field"] = field
        super().__init__(f"Monotonicity violation: {reason}", details, hint=hint)


@wire_code(ErrorCode.INVALID_ATTENUATION)
class IncompatibleConstraintTypes(MonotonicityError):
    """Incompatible constraint types for attenuation."""

    error_code = "incompatible_constraint_types"
    rust_variant = "IncompatibleConstraintTypes"

    def __init__(self, parent_type: str, child_type: str, hint: Optional[str] = None):
        super().__init__(f"Cannot attenuate {parent_type} to {child_type}", field=None, hint=hint)
        self.details = {"parent_type": parent_type, "child_type": child_type}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class WildcardExpansion(MonotonicityError):
    """Cannot attenuate to Wildcard (would allow everything)."""

    error_code = "wildcard_expansion"
    rust_variant = "WildcardExpansion"

    def __init__(self, parent_type: str, hint: Optional[str] = None):
        super().__init__(f"Cannot attenuate to Wildcard from {parent_type}", hint=hint)
        self.details = {"parent_type": parent_type}


@wire_code(ErrorCode.INVALID_ATTENUATION)
class EmptyResultSet(MonotonicityError):
    """NotOneOf would result in an empty set (paradox)."""

    error_code = "empty_result_set"
    rust_variant = "EmptyResultSet"

    def __init__(self, parent_type: str, count: int, hint: Optional[str] = None):
        super().__init__(f"NotOneOf excludes all {count} values from parent {parent_type}", hint=hint)
        self.details = {"parent_type": parent_type, "count": count}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class ExclusionRemoved(MonotonicityError):
    """NotOneOf child doesn't exclude all values that parent excludes."""

    error_code = "exclusion_removed"
    rust_variant = "ExclusionRemoved"

    def __init__(self, value: str, hint: Optional[str] = None):
        super().__init__(f"Child must still exclude '{value}'", hint=hint)
        self.details = {"value": value}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class ValueNotInParentSet(MonotonicityError):
    """OneOf/Subset child contains value not in parent set."""

    error_code = "value_not_in_parent_set"
    rust_variant = "ValueNotInParentSet"

    def __init__(self, value: str, hint: Optional[str] = None):
        super().__init__(f"Value '{value}' is not in parent's allowed set", hint=hint)
        self.details = {"value": value}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class RangeExpanded(MonotonicityError):
    """Range child expands beyond parent bounds."""

    error_code = "range_expanded"
    rust_variant = "RangeExpanded"

    def __init__(self, bound: str, parent_value: float, child_value: float, hint: Optional[str] = None):
        super().__init__(
            f"Child {bound} ({child_value}, hint=hint) exceeds parent {bound} ({parent_value}, hint=hint)", hint=hint
        )
        self.details = {"bound": bound, "parent_value": parent_value, "child_value": child_value}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class PatternExpanded(MonotonicityError):
    """Pattern attenuation cannot be verified (complex patterns with multiple wildcards)."""

    error_code = "pattern_expanded"
    rust_variant = "PatternExpanded"

    def __init__(self, parent_pattern: str, child_pattern: str, hint: Optional[str] = None):
        msg = (
            f"Pattern attenuation cannot be verified: parent pattern '{parent_pattern}' has multiple wildcards "
            f"(child: '{child_pattern}'). "
            f"Use UrlPattern for URL constraints, or use exact equality"
        )
        super().__init__(msg, hint=hint)
        self.details = {"parent_pattern": parent_pattern, "child_pattern": child_pattern}


@wire_code(ErrorCode.CAPABILITY_EXPANSION)
class RequiredValueRemoved(MonotonicityError):
    """Contains child doesn't require all values that parent requires."""

    error_code = "required_value_removed"
    rust_variant = "RequiredValueRemoved"

    def __init__(self, value: str, hint: Optional[str] = None):
        super().__init__(f"Child must still require '{value}'", hint=hint)
        self.details = {"value": value}


@wire_code(ErrorCode.INVALID_ATTENUATION)
class ExactValueMismatch(MonotonicityError):
    """Exact value mismatch."""

    error_code = "exact_value_mismatch"
    rust_variant = "ExactValueMismatch"

    def __init__(self, parent_value: str, child_value: str, hint: Optional[str] = None):
        super().__init__(f"Parent requires '{parent_value}', child has '{child_value}'", hint=hint)
        self.details = {"parent_value": parent_value, "child_value": child_value}


# =============================================================================
# Clearance Violations
# =============================================================================


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class ClearanceViolation(TenuoError):
    """Clearance level constraint was violated."""

    error_code = "clearance_violation"
    rust_variant = ""  # No direct Rust equivalent (handled via MonotonicityViolation)


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class ClearanceLevelExceeded(ClearanceViolation):
    """Requested clearance level exceeds the issuer's clearance limit."""

    error_code = "clearance_level_exceeded"
    rust_variant = "ClearanceLevelExceeded"

    def __init__(self, requested: str, limit: str, hint: Optional[str] = None):
        super().__init__(
            f"Clearance level exceeded: requested {requested} exceeds limit {limit}",
            {"requested": requested, "limit": limit},
            hint=hint,
        )


# =============================================================================
# Issuance Errors (Issuer Warrant Operations)
# =============================================================================


@wire_code(ErrorCode.INVALID_ISSUER)
class IssuanceError(TenuoError):
    """Error during warrant issuance from an issuer warrant."""

    error_code = "issuance_error"
    rust_variant = ""


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class UnauthorizedToolIssuance(IssuanceError):
    """Tool not authorized for issuance by the issuer warrant."""

    error_code = "unauthorized_tool_issuance"
    rust_variant = "UnauthorizedToolIssuance"

    def __init__(self, tool: str, allowed: list[str], hint: Optional[str] = None):
        super().__init__(
            f"Unauthorized tool issuance: '{tool}' not in issuable_tools {allowed}", {"tool": tool, "allowed": allowed}
        )


@wire_code(ErrorCode.INVALID_ISSUER)
class SelfIssuanceProhibited(IssuanceError):
    """Self-issuance is prohibited (issuer cannot grant execution to themselves)."""

    error_code = "self_issuance_prohibited"
    rust_variant = "SelfIssuanceProhibited"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"Self-issuance prohibited: {reason}", {"reason": reason})


@wire_code(ErrorCode.DEPTH_EXCEEDED)
class IssueDepthExceeded(IssuanceError):
    """Issued warrant depth exceeds issuer's max_issue_depth."""

    error_code = "issue_depth_exceeded"
    rust_variant = "IssueDepthExceeded"

    def __init__(self, depth: int, max_depth: int, hint: Optional[str] = None):
        super().__init__(
            f"Issue depth exceeded: depth {depth} exceeds max_issue_depth {max_depth}",
            {"depth": depth, "max": max_depth},
        )


@wire_code(ErrorCode.INVALID_PAYLOAD_STRUCTURE)
class InvalidWarrantType(IssuanceError):
    """Invalid warrant type for the operation."""

    error_code = "invalid_warrant_type"
    rust_variant = "InvalidWarrantType"

    def __init__(self, message: str, hint: Optional[str] = None):
        super().__init__(f"Invalid warrant type: {message}", {"message": message})


@wire_code(ErrorCode.CHAIN_TOO_LONG)
class IssuerChainTooLong(IssuanceError):
    """Issuer chain length would exceed protocol maximum."""

    error_code = "issuer_chain_too_long"
    rust_variant = "IssuerChainTooLong"

    def __init__(self, length: int, max_length: int, hint: Optional[str] = None):
        super().__init__(
            f"Issuer chain too long: length {length} would exceed maximum {max_length}",
            {"length": length, "max": max_length},
        )


# =============================================================================
# Proof-of-Possession Errors
# =============================================================================


@wire_code(ErrorCode.POP_SIGNATURE_INVALID)
class PopError(TenuoError):
    """Proof-of-Possession verification failed."""

    error_code = "pop_error"
    rust_variant = "SignatureInvalid"  # PoP failures are signature failures in Rust


@wire_code(ErrorCode.POP_SIGNATURE_INVALID)
class MissingSigningKey(PopError):
    """No signing key available for PoP signature."""

    error_code = "missing_signing_key"
    rust_variant = "MissingSignature"

    def __init__(self, tool: str, hint: Optional[str] = None):
        super().__init__(f"No signing key available for PoP signature on tool '{tool}'", {"tool": tool}, hint=hint)


@wire_code(ErrorCode.POP_SIGNATURE_INVALID)
class SignatureMismatch(PopError):
    """PoP signature does not match authorized_holder."""

    error_code = "signature_mismatch"
    rust_variant = "SignatureInvalid"

    def __init__(self, warrant_id: Optional[str] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {}
        if warrant_id:
            details["warrant_id"] = warrant_id
        super().__init__("PoP signature does not match authorized_holder", details, hint=hint)


@wire_code(ErrorCode.POP_EXPIRED)
class PopExpired(PopError):
    """PoP signature has expired (outside valid time window)."""

    error_code = "pop_expired"
    rust_variant = "SignatureInvalid"

    def __init__(self, message: str = "PoP signature expired", hint: Optional[str] = None):
        super().__init__(message, hint=hint)


# =============================================================================
# Chain Verification Errors
# =============================================================================


@wire_code(ErrorCode.CHAIN_BROKEN)
class ChainError(TenuoError):
    """Delegation chain verification failed."""

    error_code = "chain_error"
    rust_variant = "ChainVerificationFailed"


@wire_code(ErrorCode.CHAIN_BROKEN)
class BrokenChain(ChainError):
    """Chain linkage is broken (parent_id mismatch)."""

    error_code = "broken_chain"
    rust_variant = "ChainVerificationFailed"

    def __init__(self, child_parent_hash: str, expected_hash: str, hint: Optional[str] = None):
        super().__init__(
            f"Chain broken: child references parent_hash '{child_parent_hash}' but parent payload hash is '{expected_hash}'",
            {"child_parent_hash": child_parent_hash, "expected_hash": expected_hash},
            hint=hint,
        )


@wire_code(ErrorCode.CHAIN_BROKEN)
class CycleDetected(ChainError):
    """Delegation chain contains a cycle."""

    error_code = "cycle_detected"
    rust_variant = "ChainVerificationFailed"

    def __init__(self, warrant_id: str, hint: Optional[str] = None):
        super().__init__(
            f"Cycle detected: warrant '{warrant_id}' appears multiple times",
            {"duplicate_warrant_id": warrant_id},
            hint=hint,
        )


@wire_code(ErrorCode.UNTRUSTED_ROOT)
class UntrustedRoot(ChainError):
    """Root warrant is not signed by a trusted issuer."""

    error_code = "untrusted_root"
    rust_variant = "SignatureInvalid"

    def __init__(self, issuer_fingerprint: Optional[str] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {}
        if issuer_fingerprint:
            details["issuer_fingerprint"] = issuer_fingerprint
        super().__init__("Root warrant issuer is not trusted", details, hint=hint)


@wire_code(ErrorCode.MISSING_REQUIRED_FIELD)
class ParentRequired(ChainError):
    """Parent warrant not provided for attenuation."""

    error_code = "parent_required"
    rust_variant = "ParentRequired"

    def __init__(self, hint: Optional[str] = None):
        super().__init__("Parent warrant required for attenuation", hint=hint)


@wire_code(ErrorCode.INVALID_ISSUER)
class DelegationAuthorityError(ChainError):
    """Signing key doesn't match parent warrant's holder."""

    error_code = "delegation_authority_error"
    rust_variant = "DelegationAuthorityError"

    def __init__(self, expected: str = "", actual: str = "", hint: Optional[str] = None):
        msg = (
            f"signing key mismatch: expected {expected}, got {actual}"
            if expected
            else "signing key doesn't match parent warrant's holder"
        )
        super().__init__(msg, hint=hint)
        self.details = {"expected": expected, "actual": actual}


# =============================================================================
# Limit Errors (protocol limits)
# =============================================================================


@wire_code(ErrorCode.WARRANT_TOO_LARGE)
class LimitError(TenuoError):
    """Protocol limit was exceeded."""

    error_code = "limit_error"
    rust_variant = ""


@wire_code(ErrorCode.DEPTH_EXCEEDED)
class DepthExceeded(LimitError):
    """Delegation depth exceeds maximum allowed."""

    error_code = "depth_exceeded"
    rust_variant = "DepthExceeded"

    def __init__(self, depth: int, max_depth: int, hint: Optional[str] = None):
        super().__init__(
            f"Delegation depth {depth} exceeds maximum {max_depth}", {"depth": depth, "max_depth": max_depth}, hint=hint
        )


@wire_code(ErrorCode.TOO_MANY_CONSTRAINTS)
class ConstraintDepthExceeded(LimitError):
    """Constraint nesting depth exceeds maximum allowed."""

    error_code = "constraint_depth_exceeded"
    rust_variant = "ConstraintDepthExceeded"

    def __init__(self, depth: int, max_depth: int, hint: Optional[str] = None):
        super().__init__(
            f"Constraint depth {depth} exceeds maximum {max_depth}", {"depth": depth, "max_depth": max_depth}, hint=hint
        )


@wire_code(ErrorCode.WARRANT_TOO_LARGE)
class PayloadTooLarge(LimitError):
    """Warrant payload exceeds size limit."""

    error_code = "payload_too_large"
    rust_variant = "PayloadTooLarge"

    def __init__(self, size: int, max_size: int, hint: Optional[str] = None):
        super().__init__(
            f"Payload size {size} bytes exceeds maximum {max_size} bytes",
            {"size": size, "max_size": max_size},
            hint=hint,
        )


# =============================================================================
# Revocation Errors
# =============================================================================


@wire_code(ErrorCode.WARRANT_REVOKED)
class RevokedError(TenuoError):
    """Warrant has been revoked."""

    error_code = "revoked"
    rust_variant = "WarrantRevoked"

    def __init__(self, warrant_id: str, reason: Optional[str] = None, hint: Optional[str] = None):
        details: dict[str, Any] = {"warrant_id": warrant_id}
        if reason:
            details["reason"] = reason
        super().__init__(f"Warrant '{warrant_id}' has been revoked", details, hint=hint)


# =============================================================================
# Validation Errors (field/format validation)
# =============================================================================


@wire_code(ErrorCode.MISSING_REQUIRED_FIELD)
class ValidationError(TenuoError):
    """Validation error."""

    error_code = "validation_error"
    rust_variant = "Validation"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"Validation error: {reason}", {"reason": reason}, hint=hint)


@wire_code(ErrorCode.MISSING_REQUIRED_FIELD)
class MissingField(ValidationError):
    """Missing required field."""

    error_code = "missing_field"
    rust_variant = "MissingField"

    def __init__(self, field: str, hint: Optional[str] = None):
        super().__init__(f"Missing required field: {field}", hint=hint)
        self.details = {"field": field}


@wire_code(ErrorCode.INVALID_PAYLOAD_STRUCTURE)
class InvalidWarrantId(ValidationError):
    """Invalid warrant ID format."""

    error_code = "invalid_warrant_id"
    rust_variant = "InvalidWarrantId"

    def __init__(self, warrant_id: str, hint: Optional[str] = None):
        super().__init__(f"Invalid warrant ID: {warrant_id}", hint=hint)
        self.details = {"warrant_id": warrant_id}


@wire_code(ErrorCode.TTL_EXCEEDED)
class InvalidTtl(ValidationError):
    """Invalid TTL value."""

    error_code = "invalid_ttl"
    rust_variant = "InvalidTtl"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"Invalid TTL: {reason}", hint=hint)
        self.details = {"reason": reason}


# =============================================================================
# Constraint Syntax Errors
# =============================================================================


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class ConstraintSyntaxError(TenuoError):
    """Constraint syntax/definition error."""

    error_code = "constraint_syntax_error"
    rust_variant = ""


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class InvalidPattern(ConstraintSyntaxError):
    """Invalid pattern syntax."""

    error_code = "invalid_pattern"
    rust_variant = "InvalidPattern"

    def __init__(self, pattern: str, reason: str = "", hint: Optional[str] = None):
        super().__init__(f"Invalid pattern: {pattern}" + (f" - {reason}" if reason else ""), hint=hint)
        self.details = {"pattern": pattern, "reason": reason}


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class InvalidRange(ConstraintSyntaxError):
    """Invalid range specification."""

    error_code = "invalid_range"
    rust_variant = "InvalidRange"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"Invalid range: {reason}", hint=hint)
        self.details = {"reason": reason}


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class InvalidRegex(ConstraintSyntaxError):
    """Invalid regex pattern."""

    error_code = "invalid_regex"
    rust_variant = "InvalidRegex"

    def __init__(self, pattern: str, reason: str = "", hint: Optional[str] = None):
        super().__init__(f"Invalid regex: {pattern}" + (f" - {reason}" if reason else ""), hint=hint)
        self.details = {"pattern": pattern, "reason": reason}


@wire_code(ErrorCode.CONSTRAINT_VIOLATION)
class CelError(ConstraintSyntaxError):
    """CEL expression error."""

    error_code = "cel_error"
    rust_variant = "CelError"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"CEL expression error: {reason}", hint=hint)
        self.details = {"reason": reason}


# =============================================================================
# Serialization Errors (wire format)
# =============================================================================


@wire_code(ErrorCode.MALFORMED_CBOR)
class SerializationError(TenuoError):
    """Serialization error."""

    error_code = "serialization_error"
    rust_variant = "SerializationError"

    def __init__(self, reason: str = "", hint: Optional[str] = None):
        super().__init__(f"Serialization error: {reason}" if reason else "Serialization error", hint=hint)
        self.details = {"reason": reason}


@wire_code(ErrorCode.MALFORMED_CBOR)
class DeserializationError(SerializationError):
    """Deserialization error."""

    error_code = "deserialization_error"
    rust_variant = "DeserializationError"

    def __init__(self, reason: str = "", hint: Optional[str] = None):
        super().__init__(f"Deserialization error: {reason}" if reason else "Deserialization error", hint=hint)
        self.details = {"reason": reason}


@wire_code(ErrorCode.UNSUPPORTED_PAYLOAD_VERSION)
class UnsupportedVersion(SerializationError):
    """Wire format version mismatch."""

    error_code = "unsupported_version"
    rust_variant = "UnsupportedVersion"

    def __init__(self, version: int, hint: Optional[str] = None):
        super().__init__(f"Unsupported wire format version: {version}", hint=hint)
        self.details = {"version": version}


# =============================================================================
# Approval Errors (multi-sig)
# =============================================================================


@wire_code(ErrorCode.APPROVAL_INVALID)
class ApprovalError(TenuoError):
    """Multi-sig approval error."""

    error_code = "approval_error"
    rust_variant = ""


@wire_code(ErrorCode.APPROVAL_EXPIRED)
class ApprovalExpired(ApprovalError):
    """Approval has expired."""

    error_code = "approval_expired"
    rust_variant = "ApprovalExpired"

    def __init__(self, approved_at: str, expired_at: str, hint: Optional[str] = None):
        super().__init__(f"Approval expired: approved at {approved_at}, expired at {expired_at}", hint=hint)
        self.details = {"approved_at": approved_at, "expired_at": expired_at}


@wire_code(ErrorCode.INSUFFICIENT_APPROVALS)
class InsufficientApprovals(ApprovalError):
    """Insufficient approvals for multi-sig."""

    error_code = "insufficient_approvals"
    rust_variant = "InsufficientApprovals"

    def __init__(self, required: int, received: int, detail: str = "", hint: Optional[str] = None):
        msg = f"Insufficient approvals: required {required}, received {received}"
        if detail:
            msg = f"{msg}{detail}"
        super().__init__(msg, hint=hint)
        self.details = {"required": required, "received": received, "detail": detail}


@wire_code(ErrorCode.APPROVAL_INVALID)
class InvalidApproval(ApprovalError):
    """Invalid approval (bad format, DoS attempt, etc.)."""

    error_code = "invalid_approval"
    rust_variant = "InvalidApproval"

    def __init__(self, reason: str, hint: Optional[str] = None):
        super().__init__(f"Invalid approval: {reason}", hint=hint)
        self.details = {"reason": reason}


@wire_code(ErrorCode.APPROVAL_INVALID)
class UnknownProvider(ApprovalError):
    """Unknown approval provider."""

    error_code = "unknown_provider"
    rust_variant = "UnknownProvider"

    def __init__(self, provider: str, hint: Optional[str] = None):
        super().__init__(f"Unknown approval provider: {provider}", hint=hint)
        self.details = {"provider": provider}


# =============================================================================
# Configuration Errors
# =============================================================================


@wire_code(ErrorCode.INVALID_PAYLOAD_STRUCTURE)
class ConfigurationError(TenuoError):
    """Configuration is invalid."""

    error_code = "configuration_error"
    rust_variant = ""  # ConfigError is separate in Rust


@wire_code(ErrorCode.UNKNOWN_CONSTRAINT_TYPE)
class FeatureNotEnabled(TenuoError):
    """Optional feature is not enabled."""

    error_code = "feature_not_enabled"
    rust_variant = "FeatureNotEnabled"

    def __init__(self, feature: str = "unknown", hint: Optional[str] = None):
        super().__init__(
            f"Feature '{feature}' is not enabled. Enable it in Cargo.toml: tenuo = {{ features = [\"{feature}\"] }}",
            {"feature": feature},
            hint=hint,
        )


@wire_code(ErrorCode.INVALID_PAYLOAD_STRUCTURE)
class RuntimeError(TenuoError):
    """Generic runtime error from Rust."""

    error_code = "runtime_error"
    rust_variant = "RuntimeError"

    def __init__(self, message: str = "", hint: Optional[str] = None):
        super().__init__(message or "Runtime error", {"message": message}, hint=hint)


# =============================================================================
# Diff-Style Authorization Error (DX improvement)
# =============================================================================


class ConstraintResult:
    """Result of checking a single constraint."""

    def __init__(
        self,
        name: str,
        passed: bool,
        constraint_repr: str,
        value: Any,
        explanation: str = "",
    ):
        self.name = name
        self.passed = passed
        self.constraint_repr = constraint_repr
        self.value = value
        self.explanation = explanation

    def __str__(self) -> str:
        icon = "✅" if self.passed else "❌"
        if self.passed:
            return f"{icon} {self.name}: OK"
        return f"{icon} {self.name}: {self.explanation}"


@wire_code(ErrorCode.TOOL_NOT_AUTHORIZED)
class AuthorizationDenied(ScopeViolation):
    """
    Authorization denied with diff-style error message.

    This exception provides a detailed breakdown of why authorization failed,
    showing which constraints passed and which failed with expected vs received values.

    Example output:
        AuthorizationDenied: Access denied for tool 'read_file'
          ❌ path: Pattern("/data/*") does not match "/etc/passwd"
          ✅ size: OK
    """

    error_code = "authorization_denied"
    rust_variant = "Unauthorized"

    def __init__(
        self,
        tool: str,
        constraint_results: Optional[list[ConstraintResult]] = None,
        reason: str = "",
        hint: Optional[str] = None,
    ):
        self.tool = tool
        self.constraint_results = constraint_results or []
        self.reason = reason

        # Build the message
        message = self._build_message()
        super().__init__(
            message,
            {
                "tool": tool,
                "constraints": [
                    {
                        "name": r.name,
                        "passed": r.passed,
                        "constraint": r.constraint_repr,
                        "value": str(r.value),
                        "explanation": r.explanation,
                    }
                    for r in self.constraint_results
                ],
            },
            hint=hint,
        )

    def _build_message(self) -> str:
        """Build the diff-style error message."""
        lines = [f"Access denied for tool '{self.tool}'"]

        if self.reason:
            lines.append(f"  Reason: {self.reason}")

        if self.constraint_results:
            lines.append("")
            # Show failed constraints first
            failed = [r for r in self.constraint_results if not r.passed]
            passed = [r for r in self.constraint_results if r.passed]

            for result in failed:
                lines.append(f"  ❌ {result.name}:")
                lines.append(f"     Expected: {result.constraint_repr}")
                lines.append(f"     Received: {repr(result.value)}")
                if result.explanation:
                    lines.append(f"     Reason: {result.explanation}")

            for result in passed:
                lines.append(f"  ✅ {result.name}: OK")

        return "\n".join(lines)

    @classmethod
    def from_constraint_check(
        cls,
        tool: str,
        constraints: dict[str, Any],
        args: dict[str, Any],
        failed_field: str,
        failed_reason: str,
    ) -> "AuthorizationDenied":
        """
        Create from a constraint check failure.

        Args:
            tool: Tool name
            constraints: Dict of constraint name -> constraint object
            args: Dict of argument name -> value
            failed_field: The field that failed
            failed_reason: Why it failed
        """
        results = []
        for name, constraint in constraints.items():
            value = args.get(name, "<not provided>")
            if name == failed_field:
                results.append(
                    ConstraintResult(
                        name=name,
                        passed=False,
                        constraint_repr=_constraint_repr(constraint),
                        value=value,
                        explanation=failed_reason,
                    )
                )
            else:
                results.append(
                    ConstraintResult(
                        name=name,
                        passed=True,
                        constraint_repr=_constraint_repr(constraint),
                        value=value,
                    )
                )

        return cls(tool=tool, constraint_results=results)


def _constraint_repr(constraint: Any) -> str:
    """Get a human-readable representation of a constraint."""
    # Try common constraint types
    if hasattr(constraint, "pattern"):
        return f'Pattern("{constraint.pattern}")'
    if hasattr(constraint, "value"):
        return f'Exact("{constraint.value}")'
    if hasattr(constraint, "values"):
        return f"OneOf({list(constraint.values)})"
    if hasattr(constraint, "min") or hasattr(constraint, "max"):
        min_val = getattr(constraint, "min", None)
        max_val = getattr(constraint, "max", None)
        if min_val is not None and max_val is not None:
            return f"Range({min_val}, {max_val})"
        elif min_val is not None:
            return f"Range(min={min_val})"
        elif max_val is not None:
            return f"Range(max={max_val})"
    if hasattr(constraint, "regex"):
        return f'Regex("{constraint.regex}")'
    if hasattr(constraint, "expression"):
        return f'CEL("{constraint.expression}")'
    # Fallback to repr
    return repr(constraint)


# =============================================================================
# Rust Error Variant Mapping
# =============================================================================

# Complete mapping from Rust Error variant names to Python exception classes
RUST_ERROR_MAP: dict[str, type[TenuoError]] = {
    # Signature & Crypto
    "SignatureInvalid": SignatureInvalid,
    "MissingSignature": MissingSignature,
    "CryptoError": CryptoError,
    # Warrant Lifecycle
    "WarrantRevoked": RevokedError,
    "WarrantExpired": ExpiredError,
    "DepthExceeded": DepthExceeded,
    "InvalidWarrantId": InvalidWarrantId,
    "InvalidTtl": InvalidTtl,
    "ConstraintDepthExceeded": ConstraintDepthExceeded,
    "PayloadTooLarge": PayloadTooLarge,
    "ParentRequired": ParentRequired,
    "ToolMismatch": ToolMismatch,
    # Monotonicity
    "MonotonicityViolation": MonotonicityError,
    "IncompatibleConstraintTypes": IncompatibleConstraintTypes,
    "WildcardExpansion": WildcardExpansion,
    "EmptyResultSet": EmptyResultSet,
    "ExclusionRemoved": ExclusionRemoved,
    "ValueNotInParentSet": ValueNotInParentSet,
    "RangeExpanded": RangeExpanded,
    "PatternExpanded": PatternExpanded,
    "RequiredValueRemoved": RequiredValueRemoved,
    "ExactValueMismatch": ExactValueMismatch,
    # Constraint Matching
    "ConstraintNotSatisfied": ConstraintViolation,
    # Constraint Syntax
    "InvalidPattern": InvalidPattern,
    "InvalidRange": InvalidRange,
    "InvalidRegex": InvalidRegex,
    "CelError": CelError,
    # Serialization
    "SerializationError": SerializationError,
    "DeserializationError": DeserializationError,
    "UnsupportedVersion": UnsupportedVersion,
    # General
    "MissingField": MissingField,
    "ChainVerificationFailed": ChainError,
    "DelegationAuthorityError": DelegationAuthorityError,
    # Approval
    "ApprovalExpired": ApprovalExpired,
    "InsufficientApprovals": InsufficientApprovals,
    "InvalidApproval": InvalidApproval,
    "UnknownProvider": UnknownProvider,
    "Unauthorized": Unauthorized,
    "Validation": ValidationError,
    "ClearanceLevelExceeded": ClearanceLevelExceeded,
    "InsufficientClearance": ClearanceViolation,  # Map InsufficientClearance to ClearanceViolation
    # Runtime errors
    "RuntimeError": RuntimeError,
    "FeatureNotEnabled": FeatureNotEnabled,
}

# All Rust Error variants that must have Python equivalents
RUST_ERROR_VARIANTS = list(RUST_ERROR_MAP.keys())


def categorize_rust_error(error_message: str) -> TenuoError:
    """
    Categorize a Rust error message into the appropriate Python exception.

    This is used when Rust errors cross the FFI boundary.
    """
    msg = error_message.lower()

    # Feature not enabled (check very early - messages may contain other keywords like "cel")
    if "feature" in msg and ("not enabled" in msg or "enable" in msg):
        # Try to extract feature name from message like "Feature 'cel' is not enabled"
        import re

        match = re.search(r"feature\s+['\"]?(\w+)['\"]?", msg, re.IGNORECASE)
        feature = match.group(1) if match else "unknown"
        return FeatureNotEnabled(feature)

    # Revocation
    if "revoked" in msg:
        return RevokedError("unknown")

    # Approval errors (check early - contains "invalid" which would match elsewhere)
    if "approval" in msg:
        if "expired" in msg:
            return ApprovalExpired("unknown", "unknown")
        if "insufficient" in msg:
            return InsufficientApprovals(0, 0)
        if "invalid" in msg:
            return InvalidApproval(error_message)
    if "provider" in msg and "unknown" in msg:
        return UnknownProvider("unknown")

    # PoP errors
    if "proof-of-possession" in msg:
        if "missing" in msg:
            return MissingSignature(error_message)
        if "expired" in msg:
            return PopExpired(error_message)
        return SignatureMismatch()

    # Cryptographic errors
    if "cryptographic error" in msg or "crypto error" in msg:
        return CryptoError(error_message)

    # Signature errors
    if "signature" in msg:
        if "missing" in msg:
            return MissingSignature(error_message)
        if "invalid" in msg or "failed" in msg or "verification" in msg:
            return SignatureInvalid(error_message)

    # Chain errors
    if "chain" in msg:
        if "cycle" in msg:
            return CycleDetected("unknown")
        if "broken" in msg or "linkage" in msg or "parent_id" in msg:
            return BrokenChain("unknown", "unknown")
        if "trusted" in msg or "issuer" in msg:
            return UntrustedRoot()
        return ChainError(error_message)

    # Untrusted root (can appear without "chain" in message)
    if "issuer" in msg and "not trusted" in msg:
        return UntrustedRoot()
    if "root" in msg and "trusted" in msg:
        return UntrustedRoot()

    # Limit errors
    if "depth" in msg and "exceed" in msg:
        if "constraint" in msg:
            return ConstraintDepthExceeded(0, 0)
        return DepthExceeded(0, 0)
    if "payload" in msg and ("large" in msg or "size" in msg):
        return PayloadTooLarge(0, 0)

    # Monotonicity errors - specific patterns first
    if "pattern" in msg and "expand" in msg:
        return PatternExpanded("unknown", "unknown")
    if "range" in msg and "expand" in msg:
        return RangeExpanded("unknown", 0, 0)
    if "wildcard" in msg and "expand" in msg:
        return WildcardExpansion("unknown")
    if "incompatible" in msg and "constraint" in msg:
        return IncompatibleConstraintTypes("unknown", "unknown")
    if "monotonicity" in msg or "attenuation" in msg:
        return MonotonicityError(error_message)

    # Scope violations
    if "expired" in msg:
        return ExpiredError("unknown")
    if "constraint" in msg and "not satisfied" in msg:
        return ConstraintViolation("unknown", error_message)
    if "tool" in msg and "mismatch" in msg:
        return ToolMismatch("unknown", "unknown")
    if "unauthorized" in msg:
        return Unauthorized(error_message)

    # Validation errors
    if "missing" in msg and "field" in msg:
        return MissingField("unknown")
    if "invalid" in msg:
        if "warrant id" in msg:
            return InvalidWarrantId("unknown")
        if "ttl" in msg:
            return InvalidTtl(error_message)
        if "pattern" in msg:
            return InvalidPattern("unknown", error_message)
        if "range" in msg:
            return InvalidRange(error_message)
        if "regex" in msg:
            return InvalidRegex("unknown", error_message)
    if "cel" in msg:
        return CelError(error_message)
    if "validation" in msg:
        return ValidationError(error_message)

    # Serialization errors (check deserialization first - it contains "serialization")
    if "deserialization" in msg:
        return DeserializationError(error_message)
    if "serialization" in msg:
        return SerializationError(error_message)
    if "unsupported" in msg and "version" in msg:
        return UnsupportedVersion(0)

    # Clearance violations
    if "clearance" in msg and ("level" in msg or "exceed" in msg):
        return ClearanceViolation(error_message)

    # Default to base error
    return TenuoError(error_message)
