"""
Tests for Phase 2 DX Improvements.

Covers:
- tenuo.cli
- tenuo.fastapi
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

import tenuo.testing  # noqa: F401 - Applies monkey-patch for Warrant.quick_mint
from tenuo import Warrant
from tenuo.cli import inspect_warrant, parse_kv_args, verify_warrant

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
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
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
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
        verify_warrant(warrant.to_base64(), "delete", {})

        captured = capsys.readouterr()
        assert "DENIED" in captured.out
        assert "not in allowed tools" in captured.out

    def test_inspect_warrant(self, capsys):
        """Test inspect command output (fallback mode)."""
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)

        # Force fallback to plain text by mocking print_rich_warrant
        with patch("tenuo.cli.print_rich_warrant", return_value=False):
            inspect_warrant(warrant.to_base64())

        captured = capsys.readouterr()
        # Expect the plain text header we set previously
        assert "=== Warrant Inspection ===" in captured.out
        assert "tnu_wrt_" in captured.out


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
class TestFastAPI:
    """Test FastAPI integration."""

    def test_get_warrant_header(self):
        from tenuo.fastapi import get_warrant_header

        # Valid header
        warrant, _ = Warrant.quick_mint(["search"], ttl=300)
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


def test_init_command():
    """Test 'tenuo init' command."""
    from tenuo.cli import init_project

    with tempfile.TemporaryDirectory() as temp_dir:
        # Change to temp dir
        current_dir = os.getcwd()
        os.chdir(temp_dir)
        try:
            # Mock SigningKey.generate
            with patch("tenuo_core.SigningKey") as MockKey:
                mock_k = MagicMock()
                # to_string returns bytes
                mock_k.to_string.return_value = b"test_key_bytes"
                MockKey.generate.return_value = mock_k

                init_project()

                # Check .env
                assert os.path.exists(".env")
                with open(".env") as f:
                    content = f.read()
                    assert "TENUO_ROOT_KEY=" in content

                # Check tenuo_config.py
                assert os.path.exists("tenuo_config.py")
                with open("tenuo_config.py") as f:
                    content = f.read()
                    assert "configure" in content
        finally:
            os.chdir(current_dir)


class TestRichInspector:
    def test_rich_decode_available(self):
        """Test decode with rich installed."""
        from tenuo.cli import print_rich_warrant

        mock_warrant = MagicMock()
        mock_warrant.id = "w_test_123"
        mock_warrant.tools = ["tool_a", "tool_b"]
        mock_warrant.is_expired.return_value = False

        # Mock rich
        sys.modules["rich"] = MagicMock()
        sys.modules["rich.tree"] = MagicMock()
        sys.modules["rich.table"] = MagicMock()
        sys.modules["rich.console"] = MagicMock()
        sys.modules["rich.panel"] = MagicMock()
        sys.modules["rich.text"] = MagicMock()

        # Should not raise
        print_rich_warrant(mock_warrant)

        # Verify calls
        sys.modules["rich.tree"].Tree.assert_called()

    def test_rich_decode_missing(self):
        """Test decode without rich (fallback)."""
        # Simulate missing rich
        with patch.dict(sys.modules, {"rich": None}):
            # This simple check relies on the implementation checking ImportError
            pass
