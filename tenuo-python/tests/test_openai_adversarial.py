
"""
Adversarial Test Suite for Tenuo OpenAI Adapter.

This suite tests the adapter against active attack vectors, specifically ensuring:
1. "Fail Closed" philosophy (unknowns = deny)
2. "Zero Trust" for arguments (unwanted arguments are rejected)
3. Cryptographic integrity (Replay, Binding)
"""

import pytest
from unittest.mock import MagicMock, patch

from tenuo.openai import (
    verify_tool_call,
    ConstraintViolation,
    MissingSigningKey,
)
from tenuo import Warrant, SigningKey, Pattern

# =============================================================================
# 1. Zero Trust & Argument Validation
# =============================================================================

class TestZeroTrust:
    """
    Tests ensuring that the adapter strictly enforces "unknown = deny".
    Start state: The current implementation likely allows unknown arguments (permissive).
    Goal state: The implementation should reject unknown arguments (strict).
    """

    def test_unexpected_argument_fails(self):
        """
        Attack: Pass `{"path": "/safe", "admin_flag": "true"}`
        Invariant: Unknown args must be rejected unless explicitly allowed.
        """
        tool_name = "read_file"
        constraints = {
            "read_file": {
                "path": Pattern("/safe/*")
            }
        }

        # 1. Legitimate call
        args_good = {"path": "/safe/data.txt"}
        verify_tool_call(tool_name, args_good, ["read_file"], None, constraints)

        # 2. Attack: Extra argument
        args_attack = {"path": "/safe/data.txt", "admin": "true"}

        # This SHOULD fail, but we expect it might pass currently
        with pytest.raises(ConstraintViolation, match="Unknown argument"):
            verify_tool_call(tool_name, args_attack, ["read_file"], None, constraints)


# =============================================================================
# 2. Fail Closed Philosophy
# =============================================================================

class TestFailClosed:
    """
    Tests ensuring that ambiguity or internal errors result in denial.
    """

    def test_unknown_constraint_type(self):
        """
        Attack: Inject unknown constraint object type.
        Invariant: Unknown security primitives must default to deny.
        """
        class UnknownConstraint:
            pass

        constraints = {
            "read_file": {
                "path": UnknownConstraint()
            }
        }

        # The check_constraint function handles fail-closed for the constraint check itself,
        # verifying that verify_tool_call propagates that failure.
        with pytest.raises(ConstraintViolation):
            verify_tool_call("read_file", {"path": "/any"}, ["read_file"], None, constraints)

    def test_constraint_implementation_bug(self):
        """
        Attack: Trigger internal exception in validator.
        Invariant: Internal crashes during validation must result in denial.
        """
        # Mock check_constraint to raise an exception
        with patch("tenuo.openai.check_constraint", side_effect=ValueError("Oops")):
            constraints = {"read_file": {"path": Pattern("*")}}

            # Should raise ConstraintViolation (denial), NOT ValueError (crash)
            with pytest.raises(ConstraintViolation, match="internal validation error"):
                verify_tool_call("read_file", {"path": "/any"}, ["read_file"], None, constraints)


# =============================================================================
# 3. Cryptographic Integrity
# =============================================================================

class TestCryptoIntegrity:
    """
    Tests for PoP signature binding and integrity.
    """

    @pytest.fixture
    def keypair(self):
        sk = SigningKey.generate()
        return sk, sk.public_key

    def test_missing_signature_denies(self, keypair):
        """
        Attack: Provide warrant but no signing key.
        Invariant: Tier 2 must enforce cryptographic checks.
        """
        sk, pk = keypair
        # Warrant is just a mock here as we test verify_tool_call logic
        warrant = MagicMock(spec=Warrant)

        with pytest.raises(MissingSigningKey):
            verify_tool_call("tool", {}, None, None, None, warrant=warrant, signing_key=None)


# =============================================================================
# 4. Streaming Security
# =============================================================================

class TestStreamingSecurity:
    """
    Tests ensuring buffer-verify-emit protects against TOCTOU in streaming.
    """

    def test_streaming_argument_validation(self):
        """
        Attack: Stream tool call chunks, but final assembled call has unknown argument.
        Invariant: Buffer-verify-emit MUST validate complete call before emission.
        """
        from tenuo.openai import ToolCallBuffer

        # Simulate streaming chunks building a tool call
        buffer = ToolCallBuffer(id="call_123", name="read_file")

        # Accumulate arguments
        buffer.args_json = '{"path": "/data/file.txt", "admin": "true"}'

        # Parse complete arguments
        import json
        args = json.loads(buffer.args_json)

        constraints = {
            "read_file": {
                "path": Pattern("/data/*")
            }
        }

        # Should DENY because "admin" is not in constraints (Zero Trust)
        with pytest.raises(ConstraintViolation, match="Unknown argument"):
            verify_tool_call("read_file", args, ["read_file"], None, constraints)

    def test_streaming_constraint_violation_caught(self):
        """
        Attack: Stream chunks that assemble into constraint-violating call.
        Invariant: Violation caught during buffer verification, not after emission.
        """
        from tenuo.openai import ToolCallBuffer

        buffer = ToolCallBuffer(id="call_456", name="read_file")
        buffer.args_json = '{"path": "/etc/passwd"}'

        import json
        args = json.loads(buffer.args_json)

        constraints = {
            "read_file": {
                "path": Pattern("/data/*")
            }
        }

        # Should DENY because path violates constraint
        with pytest.raises(ConstraintViolation):
            verify_tool_call("read_file", args, ["read_file"], None, constraints)

