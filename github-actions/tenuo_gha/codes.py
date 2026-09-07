"""Denial codes. 0.2.4 does not export these names; the strings are stable."""

from __future__ import annotations

try:
    from tenuo.mcp import TENUO_CONSTRAINT_VIOLATION, TENUO_TOOL_NOT_AUTHORIZED
except ImportError:
    TENUO_CONSTRAINT_VIOLATION = "TENUO_CONSTRAINT_VIOLATION"
    TENUO_TOOL_NOT_AUTHORIZED = "TENUO_TOOL_NOT_AUTHORIZED"
