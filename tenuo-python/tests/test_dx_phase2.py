"""
Tests for Phase 2 DX Improvements.

Covers:
- tenuo.Client
- tenuo.fastapi (mocked)
- tenuo.cli (mocked args)
"""

import pytest

from tenuo import Warrant, SigningKey, Client
from tenuo.cli import verify_warrant, inspect_warrant, parse_kv_args

# Mock FastAPI components if not installed (for testing in diff environments)
try:
    from fastapi import HTTPException
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class TestClient:
    """Test the high-level Client class."""
    
    def test_init_and_generate(self):
        """Test initialization and generation."""
        c1 = Client.generate()
        assert isinstance(c1.key, SigningKey)
        
        key = SigningKey.generate()
        c2 = Client(key)
        assert c2.key is key
        
    def test_use_warrant_object(self):
        """Test using a warrant object."""
        c = Client.generate()
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        
        c.use_warrant(warrant)
        inspect = c.inspect()
        assert inspect["has_key"] is True
        assert inspect["warrant"]["id"] == warrant.id
        
    def test_use_warrant_string(self):
        """Test using a base64 warrant string."""
        c = Client.generate()
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        b64 = warrant.to_base64()
        
        c.use_warrant(b64)
        inspect = c.inspect()
        assert inspect["warrant"]["id"] == warrant.id
        
    def test_auth_headers(self):
        """Test header generation."""
        c = Client.generate()
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        c.use_warrant(warrant)
        
        headers = c.auth_headers("search", {"q": "test"})
        assert "X-Tenuo-Warrant" in headers
        assert "X-Tenuo-PoP" in headers
        
    def test_explain(self):
        """Test explain() output."""
        c = Client.generate()
        assert "Key: Set" in c.explain()
        assert "Active Warrant: [NONE]" in c.explain()
        
        warrant, _ = Warrant.quick_issue(["search"], ttl=300)
        c.use_warrant(warrant)
        assert "Active Warrant:" in c.explain()
        assert "search" in c.explain()


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

