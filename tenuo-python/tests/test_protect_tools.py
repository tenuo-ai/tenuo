"""
Tests for Tenuo @guard decorator and tool schemas.
"""

import pytest
from tenuo import (
    configure,
    reset_config,
    mint_sync,
    guard,
    SigningKey,
    Pattern,
    Capability,
)
from tenuo.schemas import TOOL_SCHEMAS, ToolSchema, check_constraints, get_schema, recommended_constraints, register_schema


@pytest.fixture(autouse=True)
def reset_config_fixture():
    """Reset config before and after each test."""
    reset_config()
    yield
    reset_config()


# Mock tools for testing
def read_file(path: str) -> str:
    """Mock read_file tool."""
    return f"Contents of {path}"


def send_email(to: str, body: str) -> str:
    """Mock send_email tool."""
    return f"Email sent to {to}"


def http_request(url: str) -> str:
    """Mock http_request tool (critical)."""
    return f"Response from {url}"


def list_files(directory: str = ".") -> list:
    """Mock list_files tool (low risk)."""
    return ["file1.txt", "file2.txt"]


class TestGuardedToolAuthorization:
    """Tests for @guard decorator authorization behavior."""

    def test_allows_authorized_tool(self):
        """Guarded tool allows authorized execution."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        @guard(tool="read_file")
        def my_read_file(path: str) -> str:
            return f"Contents of {path}"

        with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
            result = my_read_file(path="/data/test.txt")
            assert "Contents of" in result

    def test_blocks_unauthorized_tool(self):
        """Guarded tool blocks unauthorized execution."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        @guard(tool="send_email")
        def my_send_email(to: str, body: str) -> str:
            return f"Email sent to {to}"

        # Warrant is for read_file, not send_email
        with mint_sync(Capability("read_file", path=Pattern("/data/*"))):
            # Should raise ToolNotAuthorized or ConstraintViolation (scope violation)
            with pytest.raises(Exception):
                my_send_email(to="test@example.com", body="hello")

    def test_blocks_without_warrant(self):
        """Guarded tool blocks execution without warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        @guard(tool="read_file")
        def my_read_file(path: str) -> str:
            return f"Contents of {path}"

        # No mint - no warrant in context, should raise exception
        with pytest.raises(Exception):
            my_read_file(path="/data/test.txt")


class TestPassthrough:
    """Tests for passthrough mode."""

    def test_passthrough_blocked_without_dev_mode(self):
        """Passthrough is blocked in production mode."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, trusted_roots=[kp.public_key])

        @guard(tool="read_file")
        def my_read_file(path: str) -> str:
            return f"Contents of {path}"

        with pytest.raises(Exception):  # No warrant, should fail
            my_read_file(path="/data/test.txt")

    def test_passthrough_allowed_with_dev_mode(self):
        """Passthrough is allowed in dev mode with allow_passthrough."""
        kp = SigningKey.generate()
        configure(
            issuer_key=kp,
            dev_mode=True,
            allow_passthrough=True,
        )

        @guard(tool="read_file")
        def my_read_file(path: str) -> str:
            return f"Contents of {path}"

        # No mint - but passthrough is allowed
        result = my_read_file(path="/data/test.txt")
        assert "Contents of" in result


class TestToolSchemas:
    """Tests for tool schemas and risk levels."""

    def test_builtin_schemas_exist(self):
        """Built-in schemas exist for common tools."""
        assert "read_file" in TOOL_SCHEMAS
        assert "write_file" in TOOL_SCHEMAS
        assert "http_request" in TOOL_SCHEMAS
        assert "send_email" in TOOL_SCHEMAS

    def test_get_schema(self):
        """get_schema() returns the schema for a tool."""
        schema = get_schema("read_file")
        assert schema is not None
        assert schema.risk_level == "medium"
        assert "path" in schema.recommended_constraints

    def test_register_schema(self):
        """register_schema() adds a custom schema."""
        register_schema("my_custom_tool", ToolSchema(
            recommended_constraints=["resource_id", "action"],
            require_at_least_one=True,
            risk_level="high",
        ))

        schema = get_schema("my_custom_tool")
        assert schema is not None
        assert schema.risk_level == "high"
        assert "resource_id" in schema.recommended_constraints

    def test_schema_invalid_risk_level(self):
        """ToolSchema rejects invalid risk levels."""
        with pytest.raises(ValueError, match="Invalid risk_level"):
            ToolSchema(risk_level="super_dangerous")


class TestRecommendedConstraints:
    """Tests for recommended_constraints() helper."""

    def test_prints_recommendations(self, capsys):
        """recommended_constraints() prints tool recommendations."""
        recommended_constraints([read_file, send_email, http_request])

        captured = capsys.readouterr()
        assert "http_request" in captured.out
        assert "REQUIRED" in captured.out or "critical" in captured.out
        assert "send_email" in captured.out

    def test_empty_tools_list(self, capsys):
        """recommended_constraints() handles empty list."""
        recommended_constraints([])

        captured = capsys.readouterr()
        assert "no schemas registered" in captured.out


class TestCheckConstraints:
    """Tests for check_constraints() helper."""

    def test_returns_warnings_for_missing_constraints(self):
        """check_constraints() returns warnings for missing constraints."""
        warnings = check_constraints([http_request, send_email], {})

        # http_request is critical
        assert any("CRITICAL" in w for w in warnings)
        assert any("http_request" in w for w in warnings)

    def test_no_warnings_when_constrained(self):
        """check_constraints() returns no warnings when constrained."""
        warnings = check_constraints([http_request], {"url": "https://example.com"})

        # No critical warning because we have the 'url' constraint
        assert not any("CRITICAL" in w and "http_request" in w for w in warnings)

    def test_returns_empty_for_low_risk(self):
        """check_constraints() returns empty for low-risk tools."""
        warnings = check_constraints([list_files], {})

        # list_files is low risk, no warnings
        assert len(warnings) == 0


class TestGuardDecorator:
    """Tests for @guard decorator."""

    def test_decorator_protects_function(self):
        """@guard protects a function."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        @guard(tool="my_tool")
        def my_tool(x: int) -> int:
            return x * 2

        # Without warrant - should fail
        with pytest.raises(Exception):
            my_tool(5)

    def test_decorator_allows_with_warrant(self):
        """@guard allows execution with warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)

        @guard(tool="my_tool")
        def my_tool(x: int) -> int:
            return x * 2

        with mint_sync(Capability("my_tool")):
            result = my_tool(5)
            assert result == 10

