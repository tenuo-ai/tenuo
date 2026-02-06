"""
Test exception wire code mappings.

Verifies that all TenuoError exceptions have canonical wire codes
and that the mappings are correct according to the wire format spec.
"""

from tenuo.exceptions import (
    ERROR_CODE_REGISTRY,
    ErrorCode,
    TenuoError,
    # Crypto errors
    CryptoError,
    SignatureInvalid,
    MissingSignature,
    # Scope violations
    ToolNotAuthorized,
    ConstraintViolation,
    ExpiredError,
    Unauthorized,
    # Monotonicity errors
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
    # Clearance
    PopError,
    MissingSigningKey,
    SignatureMismatch,
    PopExpired,
    # Chain
    ChainError,
    BrokenChain,
    CycleDetected,
    UntrustedRoot,
    ParentRequired,
    DelegationAuthorityError,
    # Limits
    LimitError,
    DepthExceeded,
    ConstraintDepthExceeded,
    PayloadTooLarge,
    # Revocation
    RevokedError,
    # Validation
    ValidationError,
    MissingField,
    InvalidWarrantId,
    InvalidTtl,
    # Constraint syntax
    ConstraintSyntaxError,
    InvalidPattern,
    InvalidRange,
    InvalidRegex,
    CelError,
    # Serialization
    SerializationError,
    DeserializationError,
    UnsupportedVersion,
    # Approval
    ApprovalError,
    ApprovalExpired,
    InsufficientApprovals,
    InvalidApproval,
    UnknownProvider,
    # Configuration
    ConfigurationError,
    FeatureNotEnabled,
    RuntimeError,
)


def get_all_tenuo_error_subclasses(cls=TenuoError):
    """Recursively get all TenuoError subclasses."""
    subclasses = []
    for subclass in cls.__subclasses__():
        subclasses.append(subclass)
        subclasses.extend(get_all_tenuo_error_subclasses(subclass))
    return subclasses


class TestWireCodeRegistry:
    """Test the ERROR_CODE_REGISTRY."""

    def test_registry_exists(self):
        """Test that the registry exists."""
        assert ERROR_CODE_REGISTRY is not None
        assert isinstance(ERROR_CODE_REGISTRY, dict)

    def test_registry_not_empty(self):
        """Test that the registry has entries."""
        assert len(ERROR_CODE_REGISTRY) > 50  # Should have 60+ exceptions

    def test_all_exceptions_registered(self):
        """Test that all TenuoError subclasses are registered."""
        all_exceptions = get_all_tenuo_error_subclasses()

        # Filter out base classes and internal classes
        concrete_exceptions = [
            exc
            for exc in all_exceptions
            if not exc.__name__.endswith("Result")  # Skip ConstraintResult
            and exc is not TenuoError
        ]

        missing = []
        for exc_class in concrete_exceptions:
            if exc_class not in ERROR_CODE_REGISTRY:
                missing.append(exc_class.__name__)

        assert not missing, f"Exceptions missing wire codes: {missing}"

    def test_registry_values_are_ints(self):
        """Test that all registry values are integers."""
        for exc_class, code in ERROR_CODE_REGISTRY.items():
            assert isinstance(code, int), f"{exc_class.__name__} has non-int code: {code}"

    def test_registry_values_in_valid_range(self):
        """Test that all codes are in the spec range (1000-2199)."""
        for exc_class, code in ERROR_CODE_REGISTRY.items():
            assert 1000 <= code <= 2199, f"{exc_class.__name__} code {code} outside range"


class TestWireCodeValues:
    """Test specific exception wire code mappings."""

    def test_crypto_errors(self):
        """Test cryptographic error codes."""
        assert CryptoError("test").get_wire_code() == 1100
        assert SignatureInvalid("test").get_wire_code() == 1100
        assert MissingSignature("test").get_wire_code() == 1100

    def test_temporal_errors(self):
        """Test temporal error codes."""
        assert ExpiredError("w123").get_wire_code() == 1300

    def test_chain_errors(self):
        """Test chain error codes."""
        assert ChainError("test").get_wire_code() == 1405
        assert BrokenChain("hash1", "hash2").get_wire_code() == 1405
        assert CycleDetected("w123").get_wire_code() == 1405
        assert UntrustedRoot().get_wire_code() == 1406
        assert ParentRequired().get_wire_code() == 1204
        assert DelegationAuthorityError().get_wire_code() == 1400

    def test_capability_errors(self):
        """Test capability/authorization error codes."""
        assert ToolNotAuthorized("tool").get_wire_code() == 1500
        assert ConstraintViolation("field", "reason").get_wire_code() == 1501
        assert Unauthorized("test").get_wire_code() == 1500

    def test_monotonicity_errors(self):
        """Test monotonicity violation error codes."""
        assert MonotonicityError("test").get_wire_code() == 1502
        assert IncompatibleConstraintTypes("a", "b").get_wire_code() == 1502
        assert WildcardExpansion("a").get_wire_code() == 1503
        assert EmptyResultSet("a", 1).get_wire_code() == 1502
        assert ExclusionRemoved("a").get_wire_code() == 1503
        assert ValueNotInParentSet("a").get_wire_code() == 1503
        assert RangeExpanded("max", 100.0, 200.0).get_wire_code() == 1503
        assert PatternExpanded("a", "b").get_wire_code() == 1503
        assert RequiredValueRemoved("a").get_wire_code() == 1503
        assert ExactValueMismatch("a", "b").get_wire_code() == 1502

    def test_pop_errors(self):
        """Test PoP error codes."""
        assert PopError("test").get_wire_code() == 1600
        assert MissingSigningKey("tool").get_wire_code() == 1600
        assert SignatureMismatch().get_wire_code() == 1600
        assert PopExpired().get_wire_code() == 1601

    def test_limit_errors(self):
        """Test limit error codes."""
        assert LimitError("test").get_wire_code() == 1900
        assert DepthExceeded(10, 5).get_wire_code() == 1402
        assert ConstraintDepthExceeded(10, 5).get_wire_code() == 1903
        assert PayloadTooLarge(1000, 500).get_wire_code() == 1900

    def test_revocation_errors(self):
        """Test revocation error codes."""
        assert RevokedError("w123").get_wire_code() == 1800

    def test_validation_errors(self):
        """Test validation error codes."""
        assert ValidationError("test").get_wire_code() == 1204
        assert MissingField("field").get_wire_code() == 1204
        assert InvalidWarrantId("w123").get_wire_code() == 1201
        assert InvalidTtl("test").get_wire_code() == 1303

    def test_constraint_syntax_errors(self):
        """Test constraint syntax error codes."""
        assert ConstraintSyntaxError("test").get_wire_code() == 1501
        assert InvalidPattern("test").get_wire_code() == 1501
        assert InvalidRange("test").get_wire_code() == 1501
        assert InvalidRegex("test").get_wire_code() == 1501
        assert CelError("test").get_wire_code() == 1501

    def test_serialization_errors(self):
        """Test serialization error codes."""
        assert SerializationError("test").get_wire_code() == 1202
        assert DeserializationError("test").get_wire_code() == 1202
        assert UnsupportedVersion(2).get_wire_code() == 1200

    def test_approval_errors(self):
        """Test approval error codes."""
        assert ApprovalError("test").get_wire_code() == 1701
        assert ApprovalExpired("t1", "t2").get_wire_code() == 1703
        assert InsufficientApprovals(2, 1).get_wire_code() == 1700
        assert InvalidApproval("test").get_wire_code() == 1701
        assert UnknownProvider("test").get_wire_code() == 1701

    def test_configuration_errors(self):
        """Test configuration error codes."""
        assert ConfigurationError("test").get_wire_code() == 1201
        assert FeatureNotEnabled("test").get_wire_code() == 1504
        assert RuntimeError("test").get_wire_code() == 1201


class TestWireCodeNames:
    """Test wire code name generation (kebab-case)."""

    def test_name_format(self):
        """Test that names are in kebab-case."""
        exc = SignatureInvalid("test")
        name = exc.get_wire_name()

        # Should be kebab-case
        assert name == "signature-invalid"
        assert name.islower()
        assert "-" in name
        assert " " not in name
        assert "_" not in name

    def test_specific_names(self):
        """Test specific exception names."""
        assert SignatureInvalid("test").get_wire_name() == "signature-invalid"
        assert ConstraintViolation("f", "r").get_wire_name() == "constraint-violation"
        assert ExpiredError("w").get_wire_name() == "warrant-expired"
        assert RevokedError("w").get_wire_name() == "warrant-revoked"
        assert DepthExceeded(1, 0).get_wire_name() == "depth-exceeded"
        assert ChainError("test").get_wire_name() == "chain-broken"


class TestHTTPStatusMapping:
    """Test HTTP status code mapping from wire codes."""

    def test_signature_errors_401(self):
        """Test signature errors map to 401 Unauthorized."""
        assert SignatureInvalid("test").get_http_status() == 401
        assert MissingSignature("test").get_http_status() == 401
        assert CryptoError("test").get_http_status() == 401

    def test_temporal_errors_401(self):
        """Test temporal errors map to 401 Unauthorized."""
        assert ExpiredError("w").get_http_status() == 401

    def test_chain_errors_403(self):
        """Test chain errors map to 403 Forbidden."""
        assert ChainError("test").get_http_status() == 403
        assert BrokenChain("h1", "h2").get_http_status() == 403
        assert UntrustedRoot().get_http_status() == 403

    def test_capability_errors_403(self):
        """Test capability errors map to 403 Forbidden."""
        assert ToolNotAuthorized("tool").get_http_status() == 403
        assert ConstraintViolation("f", "r").get_http_status() == 403
        assert Unauthorized("test").get_http_status() == 403

    def test_pop_errors_401(self):
        """Test PoP errors map to 401 Unauthorized."""
        assert PopError("test").get_http_status() == 401
        assert PopExpired().get_http_status() == 401

    def test_revocation_errors_401(self):
        """Test revocation errors map to 401 Unauthorized."""
        assert RevokedError("w").get_http_status() == 401

    def test_size_errors_413(self):
        """Test size limit errors map to 413 Payload Too Large."""
        assert PayloadTooLarge(1000, 500).get_http_status() == 413
        assert ConstraintDepthExceeded(10, 5).get_http_status() == 413


class TestErrorToDictWithWireCodes:
    """Test that to_dict includes wire codes."""

    def test_to_dict_includes_wire_code(self):
        """Test that to_dict includes wire_code field."""
        exc = ConstraintViolation("field", "reason")
        d = exc.to_dict()

        assert "wire_code" in d
        assert d["wire_code"] == 1501
        assert d["error_code"] == "constraint_violation"  # Legacy

    def test_to_dict_includes_wire_name(self):
        """Test that to_dict includes wire_name field."""
        exc = SignatureInvalid("test")
        d = exc.to_dict()

        assert "wire_name" in d
        assert d["wire_name"] == "signature-invalid"

    def test_to_dict_structure(self):
        """Test complete to_dict structure."""
        exc = ExpiredError("warrant123")
        d = exc.to_dict()

        # Legacy fields
        assert "error_code" in d
        assert "rust_variant" in d
        assert "category" in d
        assert "type" in d
        assert "message" in d
        assert "details" in d

        # New wire code fields
        assert "wire_code" in d
        assert d["wire_code"] == 1300
        assert "wire_name" in d
        assert d["wire_name"] == "warrant-expired"


class TestErrorCodeClass:
    """Test the ErrorCode helper class."""

    def test_to_name_method(self):
        """Test ErrorCode.to_name static method."""
        assert ErrorCode.to_name(1100) == "signature-invalid"
        assert ErrorCode.to_name(1501) == "constraint-violation"
        assert ErrorCode.to_name(1300) == "warrant-expired"
        assert ErrorCode.to_name(1800) == "warrant-revoked"

    def test_to_name_unknown_code(self):
        """Test to_name with unknown code."""
        assert ErrorCode.to_name(9999) == "unknown-error"

    def test_to_http_status_method(self):
        """Test ErrorCode.to_http_status static method."""
        assert ErrorCode.to_http_status(1100) == 401  # Signature
        assert ErrorCode.to_http_status(1300) == 401  # Temporal
        assert ErrorCode.to_http_status(1400) == 403  # Chain
        assert ErrorCode.to_http_status(1500) == 403  # Capability
        assert ErrorCode.to_http_status(1600) == 401  # PoP
        assert ErrorCode.to_http_status(1800) == 401  # Revocation
        assert ErrorCode.to_http_status(1900) == 413  # Size limits

    def test_all_code_constants_exist(self):
        """Test that all ErrorCode constants are defined."""
        # Sample of important codes
        assert hasattr(ErrorCode, "SIGNATURE_INVALID")
        assert hasattr(ErrorCode, "WARRANT_EXPIRED")
        assert hasattr(ErrorCode, "CONSTRAINT_VIOLATION")
        assert hasattr(ErrorCode, "TOOL_NOT_AUTHORIZED")
        assert hasattr(ErrorCode, "WARRANT_REVOKED")
        assert hasattr(ErrorCode, "DEPTH_EXCEEDED")

        # Verify values
        assert ErrorCode.SIGNATURE_INVALID == 1100
        assert ErrorCode.WARRANT_EXPIRED == 1300
        assert ErrorCode.CONSTRAINT_VIOLATION == 1501
        assert ErrorCode.TOOL_NOT_AUTHORIZED == 1500
        assert ErrorCode.WARRANT_REVOKED == 1800
        assert ErrorCode.DEPTH_EXCEEDED == 1402


class TestBackwardsCompatibility:
    """Test backwards compatibility with legacy error_code field."""

    def test_legacy_error_code_still_works(self):
        """Test that legacy error_code field still exists."""
        exc = ConstraintViolation("field", "reason")
        assert hasattr(exc, "error_code")
        assert exc.error_code == "constraint_violation"

    def test_both_codes_present(self):
        """Test that both legacy and wire codes are present."""
        exc = SignatureInvalid("test")

        # Legacy string code
        assert exc.error_code == "signature_invalid"

        # New wire code
        assert exc.get_wire_code() == 1100
        assert exc.get_wire_name() == "signature-invalid"

    def test_to_dict_has_both(self):
        """Test that to_dict includes both legacy and new codes."""
        exc = ExpiredError("w123")
        d = exc.to_dict()

        # Legacy
        assert d["error_code"] == "expired"

        # New
        assert d["wire_code"] == 1300
        assert d["wire_name"] == "warrant-expired"
