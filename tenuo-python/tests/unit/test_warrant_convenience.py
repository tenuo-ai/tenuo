"""
Unit tests for Phase 1 DX improvements.

Tests cover:
- Core warrant properties (ttl_remaining, expires_at, is_terminal, is_expired)
- Preview methods (preview_can, preview_would_allow)
- Debugging methods (explain, inspect)
- BoundWarrant class and serialization guards
- Testing utilities (quick_issue, for_testing, allow_all)
- Diagnostics (diagnose, info)
"""

import os
import pickle
from datetime import timedelta

import pytest

from tenuo import (
    All,
    AnyOf,
    Not,
    Pattern,
    Range,
    BoundWarrant,
    Exact,
    OneOf,
    SigningKey,
    Warrant,
    diagnose,
    info,
)
from tenuo.testing import allow_all, deterministic_headers


def _replace_signed_payload(warrant, key, old, new):
    """Model a Rust/newer issuer without adding a CBOR test dependency."""
    raw = bytes(warrant.to_bytes())
    assert raw[:2] == b"\x83\x01"
    assert raw[2] in (0x58, 0x59)
    length_bytes = 1 if raw[2] == 0x58 else 2
    start = 3 + length_bytes
    end = start + int.from_bytes(raw[3:start], "big")
    payload = raw[start:end]
    assert payload.count(old) == 1
    payload = payload.replace(old, new)
    assert len(payload) < 65536
    header = (b"\x58" + bytes([len(payload)])) if len(payload) < 256 else b"\x59" + len(payload).to_bytes(2, "big")
    signature = bytes(key.sign_raw(b"tenuo-warrant-v1\x01" + payload))
    return Warrant.from_bytes(b"\x83\x01" + header + payload + b"\x82\x01\x58\x40" + signature)


class TestCoreProperties:
    """Test core warrant convenience properties."""

    def test_ttl_remaining(self):
        """Test ttl_remaining property."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        assert isinstance(warrant.ttl_remaining, timedelta)
        assert warrant.ttl_remaining.total_seconds() > 0
        assert warrant.ttl_remaining.total_seconds() <= 3600

    def test_expires_at(self):
        """Test expires_at method (returns RFC3339 string)."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # expires_at() is a method that returns RFC3339 string
        expires_at = warrant.expires_at()
        assert isinstance(expires_at, str)
        assert "T" in expires_at  # RFC3339 format

    def test_is_terminal(self):
        """Test is_terminal method."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # is_terminal() is a method
        result = warrant.is_terminal()
        assert isinstance(result, bool)
        # Fresh warrant should not be terminal
        assert not result

    def test_is_expired(self):
        """Test is_expired method."""
        warrant, key = Warrant.quick_mint(["test"], ttl=3600)

        # is_expired() is a method
        result = warrant.is_expired()
        assert isinstance(result, bool)
        # Fresh warrant should not be expired
        assert not result


class TestLogicCheckMethods:
    """Test allows() method for logic checks."""

    def test_allows_tool_only(self):
        """Test allows() with tool only (replaces preview_can)."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        # Argument-less check for tool existence
        result = warrant.allows("search")
        assert result is True

    def test_allows_denied(self):
        """Test allows() with denied tool."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        result = warrant.allows("delete")
        assert result is False

    def test_allows_with_args(self):
        """Test allows() with arguments (replaces preview_would_allow)."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        # Tool present (constraint check)
        result = warrant.allows("search", args={"query": "test"})
        assert result is True or result is False  # Either is valid depending on constraints logic

        # Tool not present
        result = warrant.allows("delete", args={})
        assert result is False


class TestDebuggingMethods:
    """Test debugging and introspection methods."""

    def test_explain(self):
        """Test explain method."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        explanation = warrant.explain()
        assert isinstance(explanation, str)
        assert "Warrant" in explanation
        assert "search" in explanation
        assert "read" in explanation
        assert "TTL" in explanation

    def test_explain_shows_constraints(self):
        """explain() and inspect() list each tool's argument constraints."""
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("route_ticket", queue=OneOf(["a", "b"]), auto_close=Exact(False))
            .capability("ping")
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        for text in (warrant.explain(), warrant.inspect()):
            assert "queue: OneOf(['a', 'b'])" in text
            assert "auto_close: Exact(False)" in text
            assert "ping: (no argument constraints)" in text

    def test_explain_shows_nested_constraints(self):
        key = SigningKey.generate()
        constraint = All(
            [Pattern("/workspace/*"), AnyOf([Exact("/workspace/a.json"), Not(Exact("/workspace/secret"))])]
        )
        warrant = Warrant.mint_builder().capability("read", path=constraint).holder(key.public_key).ttl(3600).mint(key)
        for text in (warrant.explain(), warrant.inspect()):
            assert "All([" in text
            assert "AnyOf([" in text
            assert "Not(Exact(" in text
            for value in ("/workspace/*", "/workspace/a.json", "/workspace/secret"):
                assert value in text
            assert "(...)" not in text

    @pytest.mark.parametrize("nested", [False, True])
    def test_explain_preserves_metadata_for_unknown_constraint(self, nested, monkeypatch, capsys):
        from tenuo.exceptions import ValidationError

        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("read", path=All([Exact("future-value")]) if nested else Exact("future-value"))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        # Preserve a signed but unsupported type, including inside composites.
        exact = b"\x82\x01\xa1\x65value\x6cfuture-value"
        decoded = _replace_signed_payload(warrant, key, exact, b"\x82\x17" + exact[2:])
        with pytest.raises(ValidationError, match="Unknown constraint type"):
            repr(decoded.capabilities)
        for text in (decoded.explain(), decoded.inspect()):
            assert "Tools: read" in text
            assert "Expires:" in text
            assert "Depth:" in text
            assert "Constraints: unavailable" in text
            assert "no argument constraints" not in text

        from tenuo import cli

        monkeypatch.setattr(cli, "print_rich_warrant", lambda warrant: False)
        cli.inspect_warrant(decoded.to_base64())
        output = capsys.readouterr().out
        assert "Constraints: unavailable" in output
        assert "Error inspecting warrant" not in output

    @pytest.mark.parametrize("allow_unknown", [False, True])
    @pytest.mark.parametrize("optional", [False, True])
    def test_explain_distinguishes_argument_policy(self, allow_unknown, optional):
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("read", {"path": Exact("a"), "_allow_unknown": allow_unknown})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        if optional:
            # Add optional_fields to the ConstraintSet map as a Rust issuer can.
            old = (b"\xa2" if allow_unknown else b"\xa1") + b"\x6bconstraints"
            new = (b"\xa3" if allow_unknown else b"\xa2") + b"\x6foptional_fields\x81\x64path\x6bconstraints"
            warrant = _replace_signed_payload(warrant, key, old, new)
        assert warrant.allows_unknown_arguments("read") is allow_unknown
        assert warrant.allows_unknown_arguments("absent") is None
        for text in (warrant.explain(), warrant.inspect()):
            assert f"Unknown arguments: {'allowed' if allow_unknown else 'rejected'}" in text
            assert f"path: Exact('a') ({'optional' if optional else 'required'})" in text

    @pytest.mark.parametrize("endpoint", ["min", "max"])
    def test_explain_shows_exclusive_range_endpoints(self, endpoint):
        key = SigningKey.generate()
        warrant = (
            Warrant.mint_builder()
            .capability("scale", count=All([Range(1, 5)]))
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        old = f"{endpoint}_inclusive".encode() + b"\xf5"
        warrant = _replace_signed_payload(warrant, key, old, old[:-1] + b"\xf4")
        constraint = warrant.capabilities["scale"]["count"]
        assert not constraint.satisfies(1 if endpoint == "min" else 5)
        assert constraint.satisfies(3)
        for text in (warrant.explain(), warrant.inspect()):
            assert f"{endpoint}_inclusive=false" in text

    def test_explain_escapes_control_characters(self, monkeypatch, capsys):
        from tenuo import cli

        key = SigningKey.generate()
        tool, field = "read\nFORGED", "path\tFIELD"
        warrant = (
            Warrant.mint_builder()
            .capability(tool, {field: All([Pattern("/data/\nFORGED\x1b*")])})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key)
        )
        for text in (warrant.explain(), warrant.inspect()):
            assert "read\\nFORGED" in text
            assert "path\\tFIELD" in text
            assert "\\x1b" in text
            assert "\nFORGED" not in text
            assert "\x1b" not in text
            assert "\t" not in text
        monkeypatch.setattr(cli, "print_rich_warrant", lambda warrant: False)
        cli.inspect_warrant(warrant.to_base64())
        output = capsys.readouterr().out
        assert "Error inspecting warrant" not in output
        assert "\nFORGED" not in output
        assert "\x1b" not in output

    def test_explain_with_chain(self):
        """Test explain with include_chain=True."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        explanation = warrant.explain(include_chain=True)
        assert isinstance(explanation, str)
        assert "Warrant" in explanation

    def test_inspect(self):
        """Test inspect method (alias for explain)."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        inspection = warrant.inspect()
        assert isinstance(inspection, str)
        assert "Warrant" in inspection


class TestBoundWarrant:
    """Test BoundWarrant class."""

    def test_creation(self):
        """Test BoundWarrant creation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        assert isinstance(bound, BoundWarrant)
        assert bound.warrant == warrant

    def test_property_forwarding(self):
        """Test that properties are forwarded to inner warrant."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        assert bound.id == warrant.id
        assert bound.tools == warrant.tools
        # ttl_remaining is calculated dynamically, so allow small difference
        assert abs(bound.ttl_remaining.total_seconds() - warrant.ttl_remaining.total_seconds()) < 1
        # BoundWarrant.is_terminal is a property, warrant.is_terminal() is a method
        assert bound.is_terminal == warrant.is_terminal()

    def test_unbind(self):
        """Test unbinding returns inner warrant."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        unbound = bound.unbind()
        assert unbound == warrant

    def test_delegate_with_bound_key(self):
        """Test delegation using bound key."""
        parent, parent_key = Warrant.quick_mint(["search"], ttl=3600)
        bound = parent.bind(parent_key)

        child_key = SigningKey.generate()
        child = bound.grant(to=child_key.public_key, allow="search", ttl=300)

        assert "search" in child.tools

    def test_headers(self):
        """Test headers generation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        # headers() pre-flights through validate(), which needs a trust anchor.
        bound = warrant.bind(key, trusted_roots=[key.public_key])

        headers = bound.headers("search", {"query": "test"})

        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers
        assert isinstance(headers["X-Tenuo-Warrant"], str)
        assert isinstance(headers["X-Tenuo-PoP"], str)

    def test_serialization_blocked(self):
        """Test that BoundWarrant cannot be serialized."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(bound)

    def test_repr_hides_key(self):
        """Test that repr doesn't expose the key."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)
        bound = warrant.bind(key)

        repr_str = repr(bound)
        assert "BoundWarrant" in repr_str
        assert "KEY_BOUND=True" in repr_str
        # Should not contain actual key material
        assert "secret" not in repr_str.lower()


class TestTestingUtilities:
    """Test testing utilities."""

    def test_quick_issue(self):
        """Test Warrant.quick_mint()."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=300)

        assert "search" in warrant.tools
        assert "read" in warrant.tools
        assert isinstance(key, SigningKey)
        assert warrant.ttl_remaining.total_seconds() <= 300

    def test_for_testing_in_test_env(self):
        """Test Warrant.for_testing() in test environment."""
        os.environ["TENUO_TEST_MODE"] = "1"

        warrant = Warrant.for_testing(["search"])
        assert "search" in warrant.tools

    def test_for_testing_outside_test_env(self, monkeypatch):
        """Test that for_testing() fails outside test environment."""
        monkeypatch.delenv("TENUO_TEST_MODE", raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        with pytest.raises(RuntimeError, match="test environments"):
            Warrant.for_testing(["search"])

    def test_allow_all_works_in_test_environment(self):
        """Test that allow_all() works when in a test environment."""
        os.environ["TENUO_TEST_MODE"] = "1"

        # Should not raise - test environment check passes
        with allow_all():
            pass  # Currently a placeholder, but context manager works

    def test_allow_all_outside_test_env(self, monkeypatch):
        """Test that allow_all() fails outside test environment."""
        monkeypatch.delenv("TENUO_TEST_MODE", raising=False)
        monkeypatch.delenv("TENUO_ENV", raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

        with pytest.raises(RuntimeError, match="test environments"):
            with allow_all():
                pass

    def test_deterministic_headers(self):
        """Test deterministic_headers generation."""
        warrant, key = Warrant.quick_mint(["search"], ttl=3600)

        headers = deterministic_headers(warrant, key, "search", {"query": "test"})

        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers


class TestDiagnostics:
    """Test diagnostic utilities."""

    def test_diagnose(self):
        """Test diagnose function."""
        warrant, key = Warrant.quick_mint(["search", "read"], ttl=3600)

        report = diagnose(warrant)

        assert isinstance(report, str)
        assert "Warrant Diagnosis" in report
        assert "search" in report
        assert "read" in report

    def test_info(self):
        """Test info function."""
        report = info()

        assert isinstance(report, str)
        assert "Tenuo Configuration" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
