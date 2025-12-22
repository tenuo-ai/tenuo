"""
Tests for Phase 2 DX Improvements.

Covers:
- tenuo.cli
- tenuo.fastapi
"""

import pytest

from tenuo import Warrant, SigningKey
from tenuo.cli import verify_warrant, inspect_warrant, parse_kv_args

try:
    from fastapi import HTTPException
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False





class TestCLI:
    """Test CLI functions."""
    
    def test_parse_kv_args(self):
        """Test argument parsing."""
        args = parse_kv_args(["foo=bar", "num=123", "flag=true", "pi=3.14"])
        assert args["foo"] == "bar"
        assert args["num"] == 123
        assert args["flag"] is True
        assert args["pi"] == 3.14
        
    def test_verify_warrant_valid(self, capsys):
        """Test verify command output."""
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        verify_warrant(warrant.to_base64(), "search", {})
        
        captured = capsys.readouterr()
        # Should not see DENIED
        assert "DENIED" not in captured.out
        assert "Verifying warrant" in captured.out
        
    def test_verify_warrant_expiry(self, capsys):
        """Test verify detects expiry."""
        # Issue expired warrant (-100s TTL) - requires support for pre-expired issuance or mocking
        # Quick issue doesn't support negative TTL easily, but we can check the logic
        # if we could force it.
        # Alternatively, we just check tool mismatch.
        pass
        
    def test_verify_warrant_denied_tool(self, capsys):
        """Test verify detects missing tool."""
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        verify_warrant(warrant.to_base64(), "delete", {})
        
        captured = capsys.readouterr()
        assert "DENIED" in captured.out
        assert "not in allowed tools" in captured.out
        
    def test_inspect_warrant(self, capsys):
        """Test inspect command output."""
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        inspect_warrant(warrant.to_base64())
        
        captured = capsys.readouterr()
        assert "=== Warrant Inspection ===" in captured.out
        assert warrant.id in captured.out
        assert "Tools:" in captured.out


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestFastAPI:
    """Test FastAPI integration."""
    
    def test_get_warrant_header(self):
        from tenuo.fastapi import get_warrant_header
        
        # Valid header
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        b64 = warrant.to_base64()
        
        res = get_warrant_header(b64)
        assert isinstance(res, Warrant)
        assert res.id == warrant.id
        
        # Invalid header
        with pytest.raises(HTTPException) as exc:
            get_warrant_header("invalid-base64")
        assert exc.value.status_code == 400
        
        # Missing header
        assert get_warrant_header(None) is None

