"""
Trust Cliff Tests - Closed-World Constraint Semantics

Tests the "Trust Cliff" behavior:
1. No constraints → OPEN (any arguments allowed)
2. ≥1 constraint → CLOSED (unknown arguments rejected)
3. _allow_unknown: True → Explicit opt-out
4. Wildcard() → Allow any value for specific field
5. Non-inheritance during attenuation
"""

import pytest
import time
from tenuo import (
    Warrant,
    SigningKey,
    Pattern,
    Range,
    Wildcard,
)


@pytest.fixture
def keypair():
    """Generate a fresh keypair for each test."""
    return SigningKey.generate()


class TestTrustCliffBasics:
    """Tests for basic trust cliff behavior."""

    def test_no_constraints_allows_any_arguments(self, keypair):
        """Rule 1: Empty constraint set allows any arguments."""
        warrant = (
            Warrant.mint_builder()
            .tool("api_call")  # No constraints
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Any arguments should pass
        args = {"url": "https://any.com", "timeout": 999, "random_field": "anything"}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is True

    def test_one_constraint_blocks_unknown_fields(self, keypair):
        """Rule 2: Once any constraint is defined, unknown fields are rejected."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"))
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Unknown field 'timeout' should be blocked
        args = {"url": "https://api.example.com/v1", "timeout": 30}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is False

        # Detailed error check
        reason = warrant.check_constraints("api_call", args)
        assert "unknown field not allowed" in reason
        assert "zero-trust" in reason

    def test_known_fields_still_pass(self, keypair):
        """Verify constrained fields still work when satisfied."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"))
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Only the constrained field - should pass
        args = {"url": "https://api.example.com/v1"}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is True


class TestAllowUnknownOptOut:
    """Tests for _allow_unknown: True opt-out."""

    def test_allow_unknown_permits_unconstrained_fields(self, keypair):
        """Rule 3: _allow_unknown: True explicitly opts out of closed-world."""
        warrant = (
            Warrant.mint_builder()
            .capability(
                "api_call",
                {
                    "url": Pattern("https://api.example.com/*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Unknown fields should now pass
        args = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 5}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is True

    def test_allow_unknown_still_enforces_defined_constraints(self, keypair):
        """_allow_unknown doesn't skip validation of defined constraints."""
        warrant = (
            Warrant.mint_builder()
            .capability(
                "api_call",
                {
                    "url": Pattern("https://api.example.com/*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Unknown field OK, but defined constraint must still be satisfied
        args = {"url": "https://evil.com/attack", "timeout": 30}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is False


class TestWildcardVsAllowUnknown:
    """Tests for Wildcard() vs _allow_unknown difference."""

    def test_wildcard_allows_any_value_for_specific_field(self, keypair):
        """Rule 4: Wildcard() allows any value for a specific field."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"), timeout=Wildcard())
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # timeout can be any value
        args = {"url": "https://api.example.com/v1", "timeout": 999999}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is True

    def test_wildcard_does_not_allow_other_unknown_fields(self, keypair):
        """Wildcard() for one field doesn't open others."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"), timeout=Wildcard())
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # 'retries' is still unknown and should be blocked
        args = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 5}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is False

    def test_wildcard_with_other_constraints(self, keypair):
        """Wildcard() works alongside other constraint types."""
        warrant = (
            Warrant.mint_builder()
            .capability(
                "api_call", url=Pattern("https://api.example.com/*"), timeout=Wildcard(), retries=Range.max_value(3)
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # All fields constrained - should pass
        args = {"url": "https://api.example.com/v1", "timeout": 9999, "retries": 2}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is True

        # retries exceeds range - should fail
        args_bad = {"url": "https://api.example.com/v1", "timeout": 30, "retries": 10}
        pop_bad = warrant.sign(keypair, "api_call", args_bad, int(time.time()))
        assert warrant.authorize("api_call", args_bad, bytes(pop_bad)) is False


class TestAllowUnknownInheritance:
    """Tests for _allow_unknown non-inheritance during attenuation."""

    def test_allow_unknown_not_inherited(self, keypair):
        """Rule 5: _allow_unknown is NOT inherited during attenuation."""
        parent = (
            Warrant.mint_builder()
            .capability(
                "api_call",
                {
                    "url": Pattern("https://*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Child doesn't set _allow_unknown → defaults to closed
        child = (
            parent.grant_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"))
            .holder(keypair.public_key)
            .ttl(300)
            .grant(keypair)
        )

        # Parent allows unknown fields
        parent_args = {"url": "https://any.com/path", "unknown_field": True}
        parent_pop = parent.sign(keypair, "api_call", parent_args, int(time.time()))
        assert parent.authorize("api_call", parent_args, bytes(parent_pop)) is True

        # Child blocks unknown fields
        child_args = {"url": "https://api.example.com/v1", "unknown_field": True}
        child_pop = child.sign(keypair, "api_call", child_args, int(time.time()))
        assert child.authorize("api_call", child_args, bytes(child_pop)) is False

    def test_child_can_explicitly_set_allow_unknown(self, keypair):
        """Child can explicitly set _allow_unknown: True if parent also has it."""
        parent = (
            Warrant.mint_builder()
            .capability(
                "api_call",
                {
                    "url": Pattern("https://*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Child explicitly sets _allow_unknown
        child = (
            parent.grant_builder()
            .capability(
                "api_call",
                {
                    "url": Pattern("https://api.example.com/*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(300)
            .grant(keypair)
        )

        # Child should allow unknown fields
        args = {"url": "https://api.example.com/v1", "unknown_field": True}
        pop = child.sign(keypair, "api_call", args, int(time.time()))
        assert child.authorize("api_call", args, bytes(pop)) is True


class TestEdgeCases:
    """Edge cases and corner scenarios."""

    def test_multiple_tools_independent_constraints(self, keypair):
        """Each tool has its own constraint set."""
        warrant = (
            Warrant.mint_builder()
            .capability("read_file", path=Pattern("/data/*"))
            .capability(
                "write_file",
                {
                    "path": Pattern("/output/*"),
                    "_allow_unknown": True,
                },
            )
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # read_file is closed (no _allow_unknown)
        read_args = {"path": "/data/file.txt", "encoding": "utf-8"}
        read_pop = warrant.sign(keypair, "read_file", read_args, int(time.time()))
        assert warrant.authorize("read_file", read_args, bytes(read_pop)) is False

        # write_file is open (_allow_unknown: True)
        write_args = {"path": "/output/file.txt", "encoding": "utf-8"}
        write_pop = warrant.sign(keypair, "write_file", write_args, int(time.time()))
        assert warrant.authorize("write_file", write_args, bytes(write_pop)) is True

    def test_empty_args_with_constraints(self, keypair):
        """Empty args should fail if constraints require fields."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", url=Pattern("https://api.example.com/*"))
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # Empty args - missing required 'url'
        args = {}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is False

        reason = warrant.check_constraints("api_call", args)
        assert "missing required argument" in reason

    def test_constraint_value_type_mismatch(self, keypair):
        """Test handling of type mismatch (string pattern vs number)."""
        warrant = (
            Warrant.mint_builder()
            .capability("api_call", count=Range.max_value(10))
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair)
        )

        # String value for Range constraint - should fail
        args = {"count": "five"}
        pop = warrant.sign(keypair, "api_call", args, int(time.time()))
        assert warrant.authorize("api_call", args, bytes(pop)) is False
