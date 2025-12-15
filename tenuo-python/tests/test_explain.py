"""
Tests for Tenuo explain() helper.
"""

import io

from tenuo import (
    explain,
    explain_str,
)
from tenuo.exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ExpiredError,
    MonotonicityError,
    ConfigurationError,
    ScopeViolation,
)


class TestExplain:
    """Tests for explain() function."""
    
    def test_tool_not_authorized(self, capsys):
        """explain() handles ToolNotAuthorized."""
        error = ToolNotAuthorized(tool="read_file", authorized_tools=["search"])
        
        explain(error, file=None)  # Uses stderr
        
        captured = capsys.readouterr()
        assert "Authorization failed" in captured.err
        assert "read_file" in captured.err
        assert "search" in captured.err
        assert "How to fix" in captured.err
    
    def test_constraint_violation(self, capsys):
        """explain() handles ConstraintViolation."""
        error = ConstraintViolation(
            field="path",
            reason="not within allowed pattern",
            value="/etc/passwd",
        )
        
        explain(error, file=None)
        
        captured = capsys.readouterr()
        assert "Constraint violated: path" in captured.err
        assert "/etc/passwd" in captured.err
        assert "How to fix" in captured.err
    
    def test_expired_error(self, capsys):
        """explain() handles ExpiredError."""
        error = ExpiredError(
            warrant_id="tnu_wrt_test",
            expired_at="2024-01-01T12:00:00Z",
        )
        
        explain(error, file=None)
        
        captured = capsys.readouterr()
        assert "expired" in captured.err.lower()
        assert "How to fix" in captured.err
        assert "TTL" in captured.err
    
    def test_monotonicity_error(self, capsys):
        """explain() handles MonotonicityError."""
        error = MonotonicityError("Cannot widen scope")
        
        explain(error, file=None)
        
        captured = capsys.readouterr()
        assert "Attenuation violation" in captured.err
        assert "narrow" in captured.err.lower()
        assert "How to fix" in captured.err
    
    def test_configuration_error(self, capsys):
        """explain() handles ConfigurationError."""
        error = ConfigurationError("No issuer key configured")
        
        explain(error, file=None)
        
        captured = capsys.readouterr()
        assert "Configuration error" in captured.err
        assert "configure()" in captured.err
    
    def test_generic_error(self, capsys):
        """explain() handles generic TenuoError."""
        error = TenuoError("Something went wrong")
        
        explain(error, file=None)
        
        captured = capsys.readouterr()
        assert "Something went wrong" in captured.err
    
    def test_output_to_file(self):
        """explain() writes to specified file."""
        error = ToolNotAuthorized(tool="test_tool")
        
        buffer = io.StringIO()
        explain(error, file=buffer)
        
        output = buffer.getvalue()
        assert "Authorization failed" in output
        assert "test_tool" in output
    
    def test_show_context_false(self, capsys):
        """explain() hides context when show_context=False."""
        error = ConstraintViolation(
            field="path",
            reason="test",
            value="/test",
        )
        
        explain(error, show_context=False)
        
        captured = capsys.readouterr()
        # Should not have the Context: section
        assert "Authorization failed" in captured.err


class TestExplainStr:
    """Tests for explain_str() function."""
    
    def test_returns_string(self):
        """explain_str() returns explanation as string."""
        error = ToolNotAuthorized(tool="read_file")
        
        result = explain_str(error)
        
        assert isinstance(result, str)
        assert "Authorization failed" in result
        assert "read_file" in result
    
    def test_includes_how_to_fix(self):
        """explain_str() includes how to fix."""
        error = ConstraintViolation(field="path", reason="test", value="/test")
        
        result = explain_str(error)
        
        assert "How to fix" in result


class TestExplainScopeViolation:
    """Tests for explain() with ScopeViolation errors."""
    
    def test_generic_scope_violation(self, capsys):
        """explain() handles generic ScopeViolation."""
        error = ScopeViolation("Operation outside scope")
        
        explain(error)
        
        captured = capsys.readouterr()
        assert "Scope violation" in captured.err
        assert "How to fix" in captured.err
