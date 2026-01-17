"""
Test error code mappings for A2A protocol.

Ensures that A2A JSON-RPC error codes map correctly to canonical
Tenuo wire format codes.
"""

import pytest
from tenuo.a2a.errors import A2AErrorCode, A2AError


class TestA2AErrorCodeMappings:
    """Test bidirectional mapping between A2A and wire format codes."""

    def test_to_wire_code_mappings(self):
        """Test mapping from A2A codes to wire format codes."""
        # Test all documented mappings
        mappings = {
            A2AErrorCode.INVALID_SIGNATURE: 1100,
            A2AErrorCode.UNTRUSTED_ISSUER: 1406,
            A2AErrorCode.EXPIRED: 1300,
            A2AErrorCode.SKILL_NOT_GRANTED: 1500,
            A2AErrorCode.CONSTRAINT_VIOLATION: 1501,
            A2AErrorCode.REVOKED: 1800,
            A2AErrorCode.CHAIN_INVALID: 1405,
            A2AErrorCode.SKILL_NOT_FOUND: 1500,
            A2AErrorCode.UNKNOWN_CONSTRAINT: 1504,
            A2AErrorCode.POP_REQUIRED: 1600,
            A2AErrorCode.POP_FAILED: 1600,
        }

        for a2a_code, wire_code in mappings.items():
            assert A2AErrorCode.to_wire_code(a2a_code) == wire_code, f"A2A code {a2a_code} should map to wire code {wire_code}"

    def test_a2a_specific_codes_have_no_wire_equivalent(self):
        """Test that A2A-specific codes return None for wire mapping."""
        a2a_specific = [
            A2AErrorCode.MISSING_WARRANT,
            A2AErrorCode.AUDIENCE_MISMATCH,
            A2AErrorCode.REPLAY_DETECTED,
            A2AErrorCode.CHAIN_MISSING,
            A2AErrorCode.KEY_MISMATCH,
        ]

        for code in a2a_specific:
            assert A2AErrorCode.to_wire_code(code) is None, f"A2A-specific code {code} should not have wire equivalent"

    def test_from_wire_code_mappings(self):
        """Test mapping from wire format codes to A2A codes."""
        mappings = {
            1100: A2AErrorCode.INVALID_SIGNATURE,
            1300: A2AErrorCode.EXPIRED,
            1402: A2AErrorCode.CHAIN_INVALID,
            1405: A2AErrorCode.CHAIN_INVALID,
            1406: A2AErrorCode.UNTRUSTED_ISSUER,
            1500: A2AErrorCode.SKILL_NOT_GRANTED,
            1501: A2AErrorCode.CONSTRAINT_VIOLATION,
            1504: A2AErrorCode.UNKNOWN_CONSTRAINT,
            1600: A2AErrorCode.POP_FAILED,
            1800: A2AErrorCode.REVOKED,
        }

        for wire_code, a2a_code in mappings.items():
            assert A2AErrorCode.from_wire_code(wire_code) == a2a_code, f"Wire code {wire_code} should map to A2A code {a2a_code}"

    def test_unknown_wire_code_returns_internal_error(self):
        """Test that unknown wire codes map to INTERNAL_ERROR."""
        unknown_codes = [1001, 1201, 1302, 1702, 1900, 2000]

        for code in unknown_codes:
            assert A2AErrorCode.from_wire_code(code) == A2AErrorCode.INTERNAL_ERROR

    def test_a2a_error_includes_tenuo_code(self):
        """Test that A2AError.to_jsonrpc_error includes tenuo_code in data."""
        from tenuo.a2a.errors import ConstraintViolationError

        error = ConstraintViolationError("amount", ["max_value"], "100", "50")
        jsonrpc_error = error.to_jsonrpc_error()

        # Should have standard JSON-RPC structure
        assert "code" in jsonrpc_error
        assert "message" in jsonrpc_error
        assert jsonrpc_error["code"] == A2AErrorCode.CONSTRAINT_VIOLATION

        # Should include tenuo_code in data
        assert "data" in jsonrpc_error
        assert "tenuo_code" in jsonrpc_error["data"]
        assert jsonrpc_error["data"]["tenuo_code"] == 1501

    def test_a2a_specific_error_no_tenuo_code(self):
        """Test that A2A-specific errors don't include tenuo_code."""
        from tenuo.a2a.errors import MissingWarrantError

        error = MissingWarrantError()
        jsonrpc_error = error.to_jsonrpc_error()

        # Should not include tenuo_code since MISSING_WARRANT is A2A-specific
        if "data" in jsonrpc_error:
            assert "tenuo_code" not in jsonrpc_error["data"]


class TestA2AErrorCodeValues:
    """Test that A2A error codes have expected values."""

    def test_standard_jsonrpc_codes(self):
        """Test standard JSON-RPC error codes."""
        assert A2AErrorCode.PARSE_ERROR == -32700
        assert A2AErrorCode.INVALID_REQUEST == -32600
        assert A2AErrorCode.METHOD_NOT_FOUND == -32601
        assert A2AErrorCode.INVALID_PARAMS == -32602
        assert A2AErrorCode.INTERNAL_ERROR == -32603

    def test_a2a_tenuo_code_range(self):
        """Test that A2A Tenuo codes are in -32001 to -32099 range."""
        tenuo_codes = [
            A2AErrorCode.MISSING_WARRANT,
            A2AErrorCode.INVALID_SIGNATURE,
            A2AErrorCode.UNTRUSTED_ISSUER,
            A2AErrorCode.EXPIRED,
            A2AErrorCode.AUDIENCE_MISMATCH,
            A2AErrorCode.REPLAY_DETECTED,
            A2AErrorCode.SKILL_NOT_GRANTED,
            A2AErrorCode.CONSTRAINT_VIOLATION,
            A2AErrorCode.REVOKED,
            A2AErrorCode.CHAIN_INVALID,
            A2AErrorCode.CHAIN_MISSING,
            A2AErrorCode.KEY_MISMATCH,
            A2AErrorCode.SKILL_NOT_FOUND,
            A2AErrorCode.UNKNOWN_CONSTRAINT,
            A2AErrorCode.POP_REQUIRED,
            A2AErrorCode.POP_FAILED,
        ]

        for code in tenuo_codes:
            assert -32099 <= code <= -32001, f"Code {code} outside A2A Tenuo range"

    def test_specific_code_values(self):
        """Test specific A2A code values match documentation."""
        assert A2AErrorCode.MISSING_WARRANT == -32001
        assert A2AErrorCode.INVALID_SIGNATURE == -32002
        assert A2AErrorCode.UNTRUSTED_ISSUER == -32003
        assert A2AErrorCode.EXPIRED == -32004
        assert A2AErrorCode.AUDIENCE_MISMATCH == -32005
        assert A2AErrorCode.REPLAY_DETECTED == -32006
        assert A2AErrorCode.SKILL_NOT_GRANTED == -32007
        assert A2AErrorCode.CONSTRAINT_VIOLATION == -32008
        assert A2AErrorCode.REVOKED == -32009
        assert A2AErrorCode.CHAIN_INVALID == -32010
        assert A2AErrorCode.CHAIN_MISSING == -32011
        assert A2AErrorCode.KEY_MISMATCH == -32012
        assert A2AErrorCode.SKILL_NOT_FOUND == -32013
        assert A2AErrorCode.UNKNOWN_CONSTRAINT == -32014
        assert A2AErrorCode.POP_REQUIRED == -32015
        assert A2AErrorCode.POP_FAILED == -32016


class TestErrorCodeConsistency:
    """Test consistency between error codes and wire format spec."""

    def test_wire_code_ranges(self):
        """Test that wire codes are in expected ranges."""
        # Test a sample of mappings to ensure they're in correct ranges
        assert 1100 <= A2AErrorCode.to_wire_code(A2AErrorCode.INVALID_SIGNATURE) < 1200  # Signature errors
        assert 1300 <= A2AErrorCode.to_wire_code(A2AErrorCode.EXPIRED) < 1400  # Temporal errors
        assert 1400 <= A2AErrorCode.to_wire_code(A2AErrorCode.CHAIN_INVALID) < 1500  # Chain errors
        assert 1500 <= A2AErrorCode.to_wire_code(A2AErrorCode.CONSTRAINT_VIOLATION) < 1600  # Capability errors
        assert 1600 <= A2AErrorCode.to_wire_code(A2AErrorCode.POP_FAILED) < 1700  # PoP errors
        assert 1800 <= A2AErrorCode.to_wire_code(A2AErrorCode.REVOKED) < 1900  # Revocation errors

    def test_bidirectional_mapping_consistency(self):
        """Test that bidirectional mapping is consistent where it exists."""
        # For codes that have bidirectional mapping, test round-trip
        a2a_codes = [
            A2AErrorCode.INVALID_SIGNATURE,
            A2AErrorCode.EXPIRED,
            A2AErrorCode.CONSTRAINT_VIOLATION,
            A2AErrorCode.REVOKED,
        ]

        for a2a_code in a2a_codes:
            wire_code = A2AErrorCode.to_wire_code(a2a_code)
            assert wire_code is not None
            back_to_a2a = A2AErrorCode.from_wire_code(wire_code)
            # Note: mapping is not 1:1 (multiple wire codes can map to same A2A code)
            # But we should get a valid A2A code back
            assert -32099 <= back_to_a2a <= -32001 or back_to_a2a == A2AErrorCode.INTERNAL_ERROR
