"""
Optional-import behaviour for :mod:`tenuo.mcp.fastmcp_middleware`.

Avoids importing that module at collection time so environments without FastMCP
still collect the suite.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _middleware_source() -> str:
    root = Path(__file__).resolve().parent.parent.parent
    return (root / "tenuo" / "mcp" / "fastmcp_middleware.py").read_text(encoding="utf-8")


def test_install_hints_appear_in_fastmcp_middleware_source() -> None:
    text = _middleware_source()
    assert "tenuo[mcp]" in text
    assert "tenuo[fastmcp]" in text


@pytest.mark.skipif(
    importlib.util.find_spec("fastmcp") is not None
    or importlib.util.find_spec("mcp") is None,
    reason="needs MCP SDK installed but FastMCP absent (split extras)",
)
def test_import_fastmcp_middleware_without_fastmcp_suggests_extra() -> None:
    name = "tenuo.mcp.fastmcp_middleware"
    sys.modules.pop(name, None)
    with pytest.raises(ImportError, match=r"tenuo\[fastmcp\]"):
        __import__(name)
