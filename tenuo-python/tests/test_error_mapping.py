"""
Tests to ensure Python exceptions map 1:1 to Rust Error variants.

This test reads tenuo-core/src/error.rs and verifies that every Rust
Error variant has a corresponding Python exception.

Run with: pytest tests/test_error_mapping.py -v
"""

import re
from pathlib import Path

from tenuo.exceptions import (
    RUST_ERROR_MAP,
    TenuoError,
    categorize_rust_error,
    # All exception types
    CryptoError,
    SignatureInvalid,
    MissingSignature,
    ScopeViolation,
    ToolNotAuthorized,
    ToolMismatch,
    ConstraintViolation,
    ExpiredError,
    Unauthorized,
    MonotonicityError,
    IncompatibleConstraintTypes,
    WildcardExpansion,
    EmptyResultSet,
    ExclusionRemoved,
    ValueNotInParentSet,
    RangeExpanded,
    PatternExpanded,
    RequiredValueRemoved,
    ExactValueMismatch,
    PopError,
    MissingKeypair,
    SignatureMismatch,
    PopExpired,
    ChainError,
    BrokenChain,
    CycleDetected,
    UntrustedRoot,
    ParentRequired,
    LimitError,
    DepthExceeded,
    ConstraintDepthExceeded,
    PayloadTooLarge,
    RevokedError,
    ValidationError,
    MissingField,
    InvalidWarrantId,
    InvalidTtl,
    ConstraintSyntaxError,
    InvalidPattern,
    InvalidRange,
    InvalidRegex,
    CelError,
    SerializationError,
    DeserializationError,
    UnsupportedVersion,
    ApprovalError,
    ApprovalExpired,
    InsufficientApprovals,
    InvalidApproval,
    UnknownProvider,
)


def get_rust_error_variants() -> list[str]:
    """Parse tenuo-core/src/error.rs to extract all Error variant names."""
    # Find the error.rs file
    repo_root = Path(__file__).parent.parent.parent
    error_rs = repo_root / "tenuo-core" / "src" / "error.rs"
    
    if not error_rs.exists():
        # Try alternate path structure
        error_rs = Path(__file__).parent.parent.parent.parent / "tenuo-core" / "src" / "error.rs"
    
    assert error_rs.exists(), f"Could not find error.rs at {error_rs}"
    
    content = error_rs.read_text()
    
    # Extract variant names from the Error enum
    # Matches lines like: `SignatureInvalid(String),` or `DepthExceeded(u32, u32),`
    # or `RangeExpanded { bound: String, ... }`
    pattern = r'^\s*(?:#\[error\([^\)]+\)\]\s*)?(\w+)(?:\(|\s*\{)'
    
    variants = []
    in_enum = False
    
    for line in content.split('\n'):
        if 'pub enum Error {' in line:
            in_enum = True
            continue
        if in_enum:
            if line.strip().startswith('}') and '{' not in line:
                break
            # Skip comments and attributes
            if line.strip().startswith('//') or line.strip().startswith('#['):
                continue
            # Match variant declarations
            match = re.match(pattern, line)
            if match:
                variants.append(match.group(1))
    
    return variants


def test_all_rust_variants_have_python_mapping():
    """Verify every Rust Error variant has a Python exception mapping."""
    rust_variants = get_rust_error_variants()
    
    missing = []
    for variant in rust_variants:
        if variant not in RUST_ERROR_MAP:
            missing.append(variant)
    
    if missing:
        print("\nMissing Python mappings for Rust Error variants:")
        for v in missing:
            print(f"  - {v}")
    
    assert not missing, f"Missing Python exception mappings for: {missing}"


def test_python_mappings_are_valid():
    """Verify all Python mappings point to valid exception classes."""
    for variant, exc_class in RUST_ERROR_MAP.items():
        assert issubclass(exc_class, TenuoError), \
            f"RUST_ERROR_MAP['{variant}'] = {exc_class} is not a TenuoError subclass"


def test_rust_variant_attribute_matches():
    """Verify each exception's rust_variant matches its key in RUST_ERROR_MAP."""
    for variant, exc_class in RUST_ERROR_MAP.items():
        # Some exceptions may map to multiple Rust variants, so we just verify
        # the attribute is set if not empty
        if exc_class.rust_variant:
            # The class's rust_variant should be in the map
            assert exc_class.rust_variant in RUST_ERROR_MAP, \
                f"{exc_class.__name__}.rust_variant = '{exc_class.rust_variant}' not in RUST_ERROR_MAP"


def test_exception_hierarchy():
    """Verify the exception hierarchy is correct."""
    # Base
    assert issubclass(TenuoError, Exception)
    
    # Crypto
    assert issubclass(CryptoError, TenuoError)
    assert issubclass(SignatureInvalid, CryptoError)
    assert issubclass(MissingSignature, CryptoError)
    
    # Scope
    assert issubclass(ScopeViolation, TenuoError)
    assert issubclass(ToolNotAuthorized, ScopeViolation)
    assert issubclass(ToolMismatch, ScopeViolation)
    assert issubclass(ConstraintViolation, ScopeViolation)
    assert issubclass(ExpiredError, ScopeViolation)
    assert issubclass(Unauthorized, ScopeViolation)
    
    # Monotonicity
    assert issubclass(MonotonicityError, TenuoError)
    assert issubclass(IncompatibleConstraintTypes, MonotonicityError)
    assert issubclass(WildcardExpansion, MonotonicityError)
    assert issubclass(EmptyResultSet, MonotonicityError)
    assert issubclass(ExclusionRemoved, MonotonicityError)
    assert issubclass(ValueNotInParentSet, MonotonicityError)
    assert issubclass(RangeExpanded, MonotonicityError)
    assert issubclass(PatternExpanded, MonotonicityError)
    assert issubclass(RequiredValueRemoved, MonotonicityError)
    assert issubclass(ExactValueMismatch, MonotonicityError)
    
    # PoP
    assert issubclass(PopError, TenuoError)
    assert issubclass(MissingKeypair, PopError)
    assert issubclass(SignatureMismatch, PopError)
    assert issubclass(PopExpired, PopError)
    
    # Chain
    assert issubclass(ChainError, TenuoError)
    assert issubclass(BrokenChain, ChainError)
    assert issubclass(CycleDetected, ChainError)
    assert issubclass(UntrustedRoot, ChainError)
    assert issubclass(ParentRequired, ChainError)
    
    # Limits
    assert issubclass(LimitError, TenuoError)
    assert issubclass(DepthExceeded, LimitError)
    assert issubclass(ConstraintDepthExceeded, LimitError)
    assert issubclass(PayloadTooLarge, LimitError)
    
    # Revocation
    assert issubclass(RevokedError, TenuoError)
    
    # Validation
    assert issubclass(ValidationError, TenuoError)
    assert issubclass(MissingField, ValidationError)
    assert issubclass(InvalidWarrantId, ValidationError)
    assert issubclass(InvalidTtl, ValidationError)
    
    # Constraint Syntax
    assert issubclass(ConstraintSyntaxError, TenuoError)
    assert issubclass(InvalidPattern, ConstraintSyntaxError)
    assert issubclass(InvalidRange, ConstraintSyntaxError)
    assert issubclass(InvalidRegex, ConstraintSyntaxError)
    assert issubclass(CelError, ConstraintSyntaxError)
    
    # Serialization
    assert issubclass(SerializationError, TenuoError)
    assert issubclass(DeserializationError, SerializationError)
    assert issubclass(UnsupportedVersion, SerializationError)
    
    # Approval
    assert issubclass(ApprovalError, TenuoError)
    assert issubclass(ApprovalExpired, ApprovalError)
    assert issubclass(InsufficientApprovals, ApprovalError)
    assert issubclass(InvalidApproval, ApprovalError)
    assert issubclass(UnknownProvider, ApprovalError)


def test_categorize_rust_error_coverage():
    """Test that categorize_rust_error handles common Rust error messages."""
    test_cases = [
        # Signature/Crypto
        ("signature verification failed: bad sig", SignatureInvalid),
        ("missing signature: PoP required", MissingSignature),
        ("cryptographic error: key decode failed", CryptoError),
        
        # Revocation
        ("warrant revoked: wrt_abc123", RevokedError),
        
        # Expiration
        ("warrant expired at 2024-01-01", ExpiredError),
        
        # Chain
        ("chain verification failed: broken", ChainError),
        ("cycle detected in chain", CycleDetected),
        ("root issuer not trusted", UntrustedRoot),
        
        # Limits
        ("delegation depth 5 exceeds maximum 3", DepthExceeded),
        ("constraint depth 10 exceeds maximum 5", ConstraintDepthExceeded),
        ("payload size 100000 bytes too large", PayloadTooLarge),
        
        # Monotonicity
        ("monotonicity violation: range expanded", MonotonicityError),
        ("attenuation would expand: wildcard", WildcardExpansion),
        ("pattern expanded: child broader", PatternExpanded),
        
        # Validation
        ("missing field: tool", MissingField),
        ("invalid warrant ID: bad", InvalidWarrantId),
        ("invalid TTL: negative", InvalidTtl),
        ("validation error: bad format", ValidationError),
        
        # Constraint syntax
        ("invalid pattern: [bad", InvalidPattern),
        ("invalid range: min > max", InvalidRange),
        ("invalid regex: unclosed group", InvalidRegex),
        ("CEL expression error: syntax", CelError),
        
        # Serialization
        ("serialization error: too large", SerializationError),
        ("deserialization error: corrupt", DeserializationError),
        ("unsupported wire version: 99", UnsupportedVersion),
        
        # Approval
        ("approval expired: too old", ApprovalExpired),
        ("insufficient approvals: need 3", InsufficientApprovals),
        ("invalid approval: bad signature", InvalidApproval),
        ("unknown provider: custom_oauth", UnknownProvider),
        
        # Scope
        ("tool mismatch: parent vs child", ToolMismatch),
        ("constraint not satisfied: path", ConstraintViolation),
        ("unauthorized: no access", Unauthorized),
        
        # PoP
        ("Proof-of-Possession failed", SignatureMismatch),
        ("Proof-of-Possession expired", PopExpired),
    ]
    
    for error_msg, expected_type in test_cases:
        result = categorize_rust_error(error_msg)
        assert isinstance(result, expected_type), \
            f"categorize_rust_error('{error_msg}') returned {type(result).__name__}, expected {expected_type.__name__}"


def test_exception_to_dict():
    """Test that exceptions serialize to dict correctly."""
    exc = DepthExceeded(5, 3)
    d = exc.to_dict()
    
    assert d["error_code"] == "depth_exceeded"
    assert d["rust_variant"] == "DepthExceeded"
    assert d["type"] == "DepthExceeded"
    assert d["details"]["depth"] == 5
    assert d["details"]["max_depth"] == 3


def test_exception_error_codes_unique():
    """Verify all exception error_codes are unique."""
    seen: dict[str, str] = {}
    
    # Get all exception classes from RUST_ERROR_MAP
    for exc_class in set(RUST_ERROR_MAP.values()):
        code = exc_class.error_code
        if code in seen:
            # Allow same code for same class
            assert seen[code] == exc_class.__name__, \
                f"Duplicate error_code '{code}': {seen[code]} and {exc_class.__name__}"
        seen[code] = exc_class.__name__


def test_count_matches():
    """Verify the count of Rust variants matches Python mappings."""
    rust_variants = get_rust_error_variants()
    python_mappings = len(RUST_ERROR_MAP)
    
    print(f"\nRust Error variants: {len(rust_variants)}")
    print(f"Python RUST_ERROR_MAP entries: {python_mappings}")
    
    # All Rust variants should be covered
    assert python_mappings >= len(rust_variants), \
        f"Python has {python_mappings} mappings but Rust has {len(rust_variants)} variants"
