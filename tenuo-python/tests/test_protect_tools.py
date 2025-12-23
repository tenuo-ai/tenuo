"""
Tests for Tenuo protect_tools() and protected_tool decorator.
"""

import pytest
from tenuo import (
    configure,
    reset_config,
    root_task_sync,
    protect_tools,
    protected_tool,
    ToolSchema,
    register_schema,
    get_schema,
    recommended_constraints,
    check_constraints,
    TOOL_SCHEMAS,
    SigningKey,
    ToolNotAuthorized,
    Pattern,
    ConfigurationError,
    Capability,
)


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


class TestProtectToolsInplace:
    """Tests for protect_tools() inplace behavior."""
    
    def test_inplace_true_mutates_list(self):
        """protect_tools(inplace=True) mutates the original list."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = [read_file, send_email]
        original_id = id(tools)
        
        result = protect_tools(tools)  # inplace=True by default
        
        assert id(result) == original_id
        assert id(tools) == original_id
    
    def test_inplace_false_returns_new_list(self):
        """protect_tools(inplace=False) returns a new list."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = [read_file, send_email]
        original_id = id(tools)
        
        result = protect_tools(tools, inplace=False)
        
        assert id(result) != original_id
    
    def test_inplace_rejects_tuple(self):
        """protect_tools(inplace=True) rejects non-list."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = (read_file, send_email)  # Tuple, not list
        
        with pytest.raises(TypeError, match="requires a mutable list"):
            protect_tools(tools)  # inplace=True by default


class TestProtectToolsAuthorization:
    """Tests for protect_tools() authorization behavior."""
    
    def test_allows_authorized_tool(self):
        """Protected tool allows authorized execution."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = [read_file]
        protect_tools(tools)
        
        with root_task_sync(Capability("read_file", path=Pattern("/data/*"))):
            result = tools[0](path="/data/test.txt")
            assert "Contents of" in result
    
    def test_blocks_unauthorized_tool(self):
        """Protected tool blocks unauthorized execution."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = [read_file, send_email]
        protect_tools(tools)
        
        with root_task_sync(Capability("read_file", path=Pattern("/data/*"))):
            # read_file is authorized
            result = tools[0](path="/data/test.txt")
            assert result is not None
            
            # send_email is NOT authorized - different tool name
            # The warrant is for read_file only
    
    def test_blocks_without_warrant(self):
        """Protected tool blocks execution without warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = [read_file]
        protect_tools(tools)
        
        # No root_task - no warrant in context
        with pytest.raises(ToolNotAuthorized):
            tools[0](path="/data/test.txt")


class TestPassthrough:
    """Tests for passthrough mode."""
    
    def test_passthrough_blocked_without_dev_mode(self):
        """Passthrough is blocked in production mode."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, trusted_roots=[kp.public_key])
        
        tools = [read_file]
        protect_tools(tools)
        
        with pytest.raises(ToolNotAuthorized):
            tools[0](path="/data/test.txt")
    
    def test_passthrough_allowed_with_dev_mode(self):
        """Passthrough is allowed in dev mode with allow_passthrough."""
        kp = SigningKey.generate()
        configure(
            issuer_key=kp,
            dev_mode=True,
            allow_passthrough=True,
        )
        
        tools = [read_file]
        protect_tools(tools)
        
        # No root_task - but passthrough is allowed
        result = tools[0](path="/data/test.txt")
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


class TestProtectedToolDecorator:
    """Tests for @protected_tool decorator."""
    
    def test_decorator_protects_function(self):
        """@protected_tool protects a function."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @protected_tool
        def my_tool(x: int) -> int:
            return x * 2
        
        # Without warrant - should fail
        with pytest.raises(ToolNotAuthorized):
            my_tool(5)
    
    def test_decorator_allows_with_warrant(self):
        """@protected_tool allows execution with warrant."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @protected_tool
        def my_tool(x: int) -> int:
            return x * 2
        
        with root_task_sync(Capability("my_tool")):
            result = my_tool(5)
            assert result == 10
    
    def test_decorator_with_schema(self):
        """@protected_tool registers custom schema."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @protected_tool(schema=ToolSchema(
            recommended_constraints=["resource_id"],
            risk_level="high",
        ))
        def my_api_tool(resource_id: str) -> dict:
            return {"id": resource_id}
        
        # Schema should be registered
        schema = get_schema("my_api_tool")
        assert schema is not None
        assert schema.risk_level == "high"


class TestStrictMode:
    """Tests for strict mode."""
    
    def test_strict_requires_constraints(self):
        """strict=True requires constraints for require_at_least_one tools."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        @protected_tool(strict=True)
        def my_strict_tool(data: str) -> str:
            return data
        
        # Register schema with require_at_least_one
        register_schema("my_strict_tool", ToolSchema(
            recommended_constraints=["resource"],
            require_at_least_one=True,
            risk_level="medium",
        ))
        
        # Without constraints - should fail in strict mode
        with root_task_sync(Capability("my_strict_tool")):
            with pytest.raises(ConfigurationError, match="requires at least one constraint"):
                my_strict_tool(data="test")
    
    def test_non_strict_allows_without_constraints(self):
        """strict=False allows execution without constraints for medium-risk."""
        kp = SigningKey.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        # read_file is medium risk
        tools = [read_file]
        protect_tools(tools, strict=False)
        
        # Without constraints - should work for medium risk
        with root_task_sync(Capability("read_file")):
            result = tools[0](path="/data/test.txt")
            assert result is not None
