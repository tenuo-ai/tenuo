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
    ├── TrustViolation (trust level issues)
    │   └── TrustLevelExceeded
    ├── PopError (Proof-of-Possession failures)
    │   ├── MissingKeypair
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
    │   ├── PayloadTooLarge
    │   └── TtlExceeded
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
# Base Exception
# =============================================================================

class TenuoError(Exception):
    """Base exception for all Tenuo errors."""
    
    error_code: str = "tenuo_error"
    rust_variant: str = ""  # Corresponding Rust Error variant name
    
    def __init__(self, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for structured logging."""
        return {
            "error_code": self.error_code,
            "rust_variant": self.rust_variant,
            "category": self.__class__.__bases__[0].__name__ if self.__class__.__bases__ else "TenuoError",
            "type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# Cryptographic Errors (Signature & Crypto)
# =============================================================================

class CryptoError(TenuoError):
    """Cryptographic operation failed."""
    error_code = "crypto_error"
    rust_variant = "CryptoError"


class SignatureInvalid(CryptoError):
    """Warrant signature verification failed."""
    error_code = "signature_invalid"
    rust_variant = "SignatureInvalid"
    
    def __init__(self, reason: str = ""):
        super().__init__(f"Signature verification failed: {reason}" if reason else "Signature verification failed", {"reason": reason})


class MissingSignature(CryptoError):
    """Missing signature for Proof-of-Possession."""
    error_code = "missing_signature"
    rust_variant = "MissingSignature"
    
    def __init__(self, reason: str = ""):
        super().__init__(f"Missing signature: {reason}" if reason else "Missing signature", {"reason": reason})


# Alias for backwards compatibility
InvalidSignature = SignatureInvalid


# =============================================================================
# Scope Violations (authorization scope exceeded)
# =============================================================================

class ScopeViolation(TenuoError):
    """Authorization scope was exceeded."""
    error_code = "scope_violation"
    rust_variant = "Unauthorized"


class ToolNotAuthorized(ScopeViolation):
    """Tool is not authorized by the warrant."""
    error_code = "tool_not_authorized"
    rust_variant = "Unauthorized"
    
    def __init__(self, tool: str, authorized_tools: Optional[list[str]] = None):
        details: dict[str, Any] = {"tool": tool}
        if authorized_tools:
            details["authorized_tools"] = authorized_tools
        super().__init__(f"Tool '{tool}' is not authorized", details)


class ToolMismatch(ScopeViolation):
    """Tool name mismatch during attenuation."""
    error_code = "tool_mismatch"
    rust_variant = "ToolMismatch"
    
    def __init__(self, parent_tool: str, child_tool: str):
        super().__init__(
            f"Tool name mismatch: parent has '{parent_tool}', child has '{child_tool}'",
            {"parent_tool": parent_tool, "child_tool": child_tool}
        )


class ConstraintViolation(ScopeViolation):
    """Constraint was not satisfied."""
    error_code = "constraint_violation"
    rust_variant = "ConstraintNotSatisfied"
    
    def __init__(self, field: str, reason: str, value: Optional[Any] = None):
        details: dict[str, Any] = {"field": field, "reason": reason}
        if value is not None:
            details["value"] = str(value)
        super().__init__(f"Constraint '{field}' not satisfied: {reason}", details)


class ExpiredError(ScopeViolation):
    """Warrant has expired."""
    error_code = "expired"
    rust_variant = "WarrantExpired"
    
    def __init__(self, warrant_id: str, expired_at: Optional[str] = None):
        details: dict[str, Any] = {"warrant_id": warrant_id}
        if expired_at:
            details["expired_at"] = expired_at
        super().__init__(f"Warrant '{warrant_id}' has expired", details)


class Unauthorized(ScopeViolation):
    """Operation unauthorized."""
    error_code = "unauthorized"
    rust_variant = "Unauthorized"
    
    def __init__(self, reason: str = ""):
        super().__init__(f"Unauthorized: {reason}" if reason else "Unauthorized", {"reason": reason})


# =============================================================================
# Monotonicity Errors (Attenuation Violations)
# =============================================================================

class MonotonicityError(TenuoError):
    """Attenuation would expand capabilities (violates monotonicity)."""
    error_code = "monotonicity_violation"
    rust_variant = "MonotonicityViolation"
    
    def __init__(self, reason: str, field: Optional[str] = None):
        details: dict[str, Any] = {"reason": reason}
        if field:
            details["field"] = field
        super().__init__(f"Monotonicity violation: {reason}", details)


class IncompatibleConstraintTypes(MonotonicityError):
    """Incompatible constraint types for attenuation."""
    error_code = "incompatible_constraint_types"
    rust_variant = "IncompatibleConstraintTypes"
    
    def __init__(self, parent_type: str, child_type: str):
        super().__init__(
            f"Cannot attenuate {parent_type} to {child_type}",
            field=None
        )
        self.details = {"parent_type": parent_type, "child_type": child_type}


class WildcardExpansion(MonotonicityError):
    """Cannot attenuate to Wildcard (would allow everything)."""
    error_code = "wildcard_expansion"
    rust_variant = "WildcardExpansion"
    
    def __init__(self, parent_type: str):
        super().__init__(f"Cannot attenuate to Wildcard from {parent_type}")
        self.details = {"parent_type": parent_type}


class EmptyResultSet(MonotonicityError):
    """NotOneOf would result in an empty set (paradox)."""
    error_code = "empty_result_set"
    rust_variant = "EmptyResultSet"
    
    def __init__(self, parent_type: str, count: int):
        super().__init__(f"NotOneOf excludes all {count} values from parent {parent_type}")
        self.details = {"parent_type": parent_type, "count": count}


class ExclusionRemoved(MonotonicityError):
    """NotOneOf child doesn't exclude all values that parent excludes."""
    error_code = "exclusion_removed"
    rust_variant = "ExclusionRemoved"
    
    def __init__(self, value: str):
        super().__init__(f"Child must still exclude '{value}'")
        self.details = {"value": value}


class ValueNotInParentSet(MonotonicityError):
    """OneOf/Subset child contains value not in parent set."""
    error_code = "value_not_in_parent_set"
    rust_variant = "ValueNotInParentSet"
    
    def __init__(self, value: str):
        super().__init__(f"Value '{value}' is not in parent's allowed set")
        self.details = {"value": value}


class RangeExpanded(MonotonicityError):
    """Range child expands beyond parent bounds."""
    error_code = "range_expanded"
    rust_variant = "RangeExpanded"
    
    def __init__(self, bound: str, parent_value: float, child_value: float):
        super().__init__(f"Child {bound} ({child_value}) exceeds parent {bound} ({parent_value})")
        self.details = {"bound": bound, "parent_value": parent_value, "child_value": child_value}


class PatternExpanded(MonotonicityError):
    """Pattern child is broader than parent."""
    error_code = "pattern_expanded"
    rust_variant = "PatternExpanded"
    
    def __init__(self, parent_pattern: str, child_pattern: str):
        print(f"DEBUG: PatternExpanded.__init__ called with {parent_pattern!r}, {child_pattern!r}")
        super().__init__(f"Child pattern '{child_pattern}' is broader than parent '{parent_pattern}'")
        self.details = {"parent_pattern": parent_pattern, "child_pattern": child_pattern}


class RequiredValueRemoved(MonotonicityError):
    """Contains child doesn't require all values that parent requires."""
    error_code = "required_value_removed"
    rust_variant = "RequiredValueRemoved"
    
    def __init__(self, value: str):
        super().__init__(f"Child must still require '{value}'")
        self.details = {"value": value}


class ExactValueMismatch(MonotonicityError):
    """Exact value mismatch."""
    error_code = "exact_value_mismatch"
    rust_variant = "ExactValueMismatch"
    
    def __init__(self, parent_value: str, child_value: str):
        super().__init__(f"Parent requires '{parent_value}', child has '{child_value}'")
        self.details = {"parent_value": parent_value, "child_value": child_value}


# =============================================================================
# Trust Violations
# =============================================================================

class TrustViolation(TenuoError):
    """Trust level constraint was violated."""
    error_code = "trust_violation"
    rust_variant = ""  # No direct Rust equivalent (handled via MonotonicityViolation)


class TrustLevelExceeded(TrustViolation):
    """Cannot delegate to higher trust level."""
    error_code = "trust_level_exceeded"
    rust_variant = ""
    
    def __init__(self, parent_level: str, child_level: str):
        super().__init__(
            f"Cannot delegate from {parent_level} to {child_level}",
            {"parent_level": parent_level, "child_level": child_level}
        )


# =============================================================================
# Proof-of-Possession Errors
# =============================================================================

class PopError(TenuoError):
    """Proof-of-Possession verification failed."""
    error_code = "pop_error"
    rust_variant = "SignatureInvalid"  # PoP failures are signature failures in Rust


class MissingKeypair(PopError):
    """No keypair available for PoP signature."""
    error_code = "missing_keypair"
    rust_variant = "MissingSignature"
    
    def __init__(self, tool: str):
        super().__init__(
            f"No keypair available for PoP signature on tool '{tool}'",
            {"tool": tool}
        )


class SignatureMismatch(PopError):
    """PoP signature does not match authorized_holder."""
    error_code = "signature_mismatch"
    rust_variant = "SignatureInvalid"
    
    def __init__(self, warrant_id: Optional[str] = None):
        details: dict[str, Any] = {}
        if warrant_id:
            details["warrant_id"] = warrant_id
        super().__init__(
            "PoP signature does not match authorized_holder",
            details
        )


class PopExpired(PopError):
    """PoP signature has expired (outside valid time window)."""
    error_code = "pop_expired"
    rust_variant = "SignatureInvalid"
    
    def __init__(self, message: str = "PoP signature expired"):
        super().__init__(message)


# =============================================================================
# Chain Verification Errors
# =============================================================================

class ChainError(TenuoError):
    """Delegation chain verification failed."""
    error_code = "chain_error"
    rust_variant = "ChainVerificationFailed"


class BrokenChain(ChainError):
    """Chain linkage is broken (parent_id mismatch)."""
    error_code = "broken_chain"
    rust_variant = "ChainVerificationFailed"
    
    def __init__(self, child_parent_id: str, expected_parent_id: str):
        super().__init__(
            f"Chain broken: child references '{child_parent_id}' but parent is '{expected_parent_id}'",
            {"child_parent_id": child_parent_id, "expected_parent_id": expected_parent_id}
        )


class CycleDetected(ChainError):
    """Delegation chain contains a cycle."""
    error_code = "cycle_detected"
    rust_variant = "ChainVerificationFailed"
    
    def __init__(self, warrant_id: str):
        super().__init__(
            f"Cycle detected: warrant '{warrant_id}' appears multiple times",
            {"duplicate_warrant_id": warrant_id}
        )


class UntrustedRoot(ChainError):
    """Root warrant is not signed by a trusted issuer."""
    error_code = "untrusted_root"
    rust_variant = "SignatureInvalid"
    
    def __init__(self, issuer_fingerprint: Optional[str] = None):
        details: dict[str, Any] = {}
        if issuer_fingerprint:
            details["issuer_fingerprint"] = issuer_fingerprint
        super().__init__(
            "Root warrant issuer is not trusted",
            details
        )


class ParentRequired(ChainError):
    """Parent warrant not provided for attenuation."""
    error_code = "parent_required"
    rust_variant = "ParentRequired"
    
    def __init__(self):
        super().__init__("Parent warrant required for attenuation")


# =============================================================================
# Limit Errors (protocol limits)
# =============================================================================

class LimitError(TenuoError):
    """Protocol limit was exceeded."""
    error_code = "limit_error"
    rust_variant = ""


class DepthExceeded(LimitError):
    """Delegation depth exceeds maximum allowed."""
    error_code = "depth_exceeded"
    rust_variant = "DepthExceeded"
    
    def __init__(self, depth: int, max_depth: int):
        super().__init__(
            f"Delegation depth {depth} exceeds maximum {max_depth}",
            {"depth": depth, "max_depth": max_depth}
        )


class ConstraintDepthExceeded(LimitError):
    """Constraint nesting depth exceeds maximum allowed."""
    error_code = "constraint_depth_exceeded"
    rust_variant = "ConstraintDepthExceeded"
    
    def __init__(self, depth: int, max_depth: int):
        super().__init__(
            f"Constraint depth {depth} exceeds maximum {max_depth}",
            {"depth": depth, "max_depth": max_depth}
        )


class PayloadTooLarge(LimitError):
    """Warrant payload exceeds size limit."""
    error_code = "payload_too_large"
    rust_variant = "PayloadTooLarge"
    
    def __init__(self, size: int, max_size: int):
        super().__init__(
            f"Payload size {size} bytes exceeds maximum {max_size} bytes",
            {"size": size, "max_size": max_size}
        )


class TtlExceeded(LimitError):
    """TTL exceeds parent's remaining time."""
    error_code = "ttl_exceeded"
    rust_variant = ""  # Handled via MonotonicityViolation in Rust
    
    def __init__(self, child_ttl: int, parent_remaining: int):
        super().__init__(
            f"Child TTL {child_ttl}s exceeds parent's remaining {parent_remaining}s",
            {"child_ttl": child_ttl, "parent_remaining": parent_remaining}
        )


# =============================================================================
# Revocation Errors
# =============================================================================

class RevokedError(TenuoError):
    """Warrant has been revoked."""
    error_code = "revoked"
    rust_variant = "WarrantRevoked"
    
    def __init__(self, warrant_id: str, reason: Optional[str] = None):
        details: dict[str, Any] = {"warrant_id": warrant_id}
        if reason:
            details["reason"] = reason
        super().__init__(f"Warrant '{warrant_id}' has been revoked", details)


# =============================================================================
# Validation Errors (field/format validation)
# =============================================================================

class ValidationError(TenuoError):
    """Validation error."""
    error_code = "validation_error"
    rust_variant = "Validation"
    
    def __init__(self, reason: str):
        super().__init__(f"Validation error: {reason}", {"reason": reason})


class MissingField(ValidationError):
    """Missing required field."""
    error_code = "missing_field"
    rust_variant = "MissingField"
    
    def __init__(self, field: str):
        super().__init__(f"Missing required field: {field}")
        self.details = {"field": field}


class InvalidWarrantId(ValidationError):
    """Invalid warrant ID format."""
    error_code = "invalid_warrant_id"
    rust_variant = "InvalidWarrantId"
    
    def __init__(self, warrant_id: str):
        super().__init__(f"Invalid warrant ID: {warrant_id}")
        self.details = {"warrant_id": warrant_id}


class InvalidTtl(ValidationError):
    """Invalid TTL value."""
    error_code = "invalid_ttl"
    rust_variant = "InvalidTtl"
    
    def __init__(self, reason: str):
        super().__init__(f"Invalid TTL: {reason}")
        self.details = {"reason": reason}


# =============================================================================
# Constraint Syntax Errors
# =============================================================================

class ConstraintSyntaxError(TenuoError):
    """Constraint syntax/definition error."""
    error_code = "constraint_syntax_error"
    rust_variant = ""


class InvalidPattern(ConstraintSyntaxError):
    """Invalid pattern syntax."""
    error_code = "invalid_pattern"
    rust_variant = "InvalidPattern"
    
    def __init__(self, pattern: str, reason: str = ""):
        super().__init__(f"Invalid pattern: {pattern}" + (f" - {reason}" if reason else ""))
        self.details = {"pattern": pattern, "reason": reason}


class InvalidRange(ConstraintSyntaxError):
    """Invalid range specification."""
    error_code = "invalid_range"
    rust_variant = "InvalidRange"
    
    def __init__(self, reason: str):
        super().__init__(f"Invalid range: {reason}")
        self.details = {"reason": reason}


class InvalidRegex(ConstraintSyntaxError):
    """Invalid regex pattern."""
    error_code = "invalid_regex"
    rust_variant = "InvalidRegex"
    
    def __init__(self, pattern: str, reason: str = ""):
        super().__init__(f"Invalid regex: {pattern}" + (f" - {reason}" if reason else ""))
        self.details = {"pattern": pattern, "reason": reason}


class CelError(ConstraintSyntaxError):
    """CEL expression error."""
    error_code = "cel_error"
    rust_variant = "CelError"
    
    def __init__(self, reason: str):
        super().__init__(f"CEL expression error: {reason}")
        self.details = {"reason": reason}


# =============================================================================
# Serialization Errors (wire format)
# =============================================================================

class SerializationError(TenuoError):
    """Serialization error."""
    error_code = "serialization_error"
    rust_variant = "SerializationError"
    
    def __init__(self, reason: str = ""):
        super().__init__(f"Serialization error: {reason}" if reason else "Serialization error")
        self.details = {"reason": reason}


class DeserializationError(SerializationError):
    """Deserialization error."""
    error_code = "deserialization_error"
    rust_variant = "DeserializationError"
    
    def __init__(self, reason: str = ""):
        super().__init__(f"Deserialization error: {reason}" if reason else "Deserialization error")
        self.details = {"reason": reason}


class UnsupportedVersion(SerializationError):
    """Wire format version mismatch."""
    error_code = "unsupported_version"
    rust_variant = "UnsupportedVersion"
    
    def __init__(self, version: int):
        super().__init__(f"Unsupported wire format version: {version}")
        self.details = {"version": version}


# =============================================================================
# Approval Errors (multi-sig)
# =============================================================================

class ApprovalError(TenuoError):
    """Multi-sig approval error."""
    error_code = "approval_error"
    rust_variant = ""


class ApprovalExpired(ApprovalError):
    """Approval has expired."""
    error_code = "approval_expired"
    rust_variant = "ApprovalExpired"
    
    def __init__(self, approved_at: str, expired_at: str):
        super().__init__(f"Approval expired: approved at {approved_at}, expired at {expired_at}")
        self.details = {"approved_at": approved_at, "expired_at": expired_at}


class InsufficientApprovals(ApprovalError):
    """Insufficient approvals for multi-sig."""
    error_code = "insufficient_approvals"
    rust_variant = "InsufficientApprovals"
    
    def __init__(self, required: int, received: int):
        super().__init__(f"Insufficient approvals: required {required}, received {received}")
        self.details = {"required": required, "received": received}


class InvalidApproval(ApprovalError):
    """Invalid approval (bad format, DoS attempt, etc.)."""
    error_code = "invalid_approval"
    rust_variant = "InvalidApproval"
    
    def __init__(self, reason: str):
        super().__init__(f"Invalid approval: {reason}")
        self.details = {"reason": reason}


class UnknownProvider(ApprovalError):
    """Unknown approval provider."""
    error_code = "unknown_provider"
    rust_variant = "UnknownProvider"
    
    def __init__(self, provider: str):
        super().__init__(f"Unknown approval provider: {provider}")
        self.details = {"provider": provider}


# =============================================================================
# Configuration Errors
# =============================================================================

class ConfigurationError(TenuoError):
    """Configuration is invalid."""
    error_code = "configuration_error"
    rust_variant = ""  # ConfigError is separate in Rust


# =============================================================================
# Legacy Aliases (for backwards compatibility)
# =============================================================================

WarrantError = ScopeViolation
AuthorizationError = ScopeViolation


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
    # Approval
    "ApprovalExpired": ApprovalExpired,
    "InsufficientApprovals": InsufficientApprovals,
    "InvalidApproval": InvalidApproval,
    "UnknownProvider": UnknownProvider,
    "Unauthorized": Unauthorized,
    "Validation": ValidationError,
}

# All Rust Error variants that must have Python equivalents
RUST_ERROR_VARIANTS = list(RUST_ERROR_MAP.keys())


def categorize_rust_error(error_message: str) -> TenuoError:
    """
    Categorize a Rust error message into the appropriate Python exception.
    
    This is used when Rust errors cross the FFI boundary.
    """
    msg = error_message.lower()
    
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
    
    # Trust violations
    if "trust" in msg and ("level" in msg or "exceed" in msg):
        return TrustViolation(error_message)
    
    # Default to base error
    return TenuoError(error_message)
