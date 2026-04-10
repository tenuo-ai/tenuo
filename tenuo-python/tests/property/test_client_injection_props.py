"""Property tests for SecureMCPClient helper functions.

Verifies:
- _extract_tenuo_error_code: returns int or None, never crashes
- _safe_mcp_tool_error_message: always returns non-empty string, never crashes
"""

from __future__ import annotations

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo.mcp.client import _extract_tenuo_error_code, _safe_mcp_tool_error_message

from .strategies import st_simple_value, st_tool_name


class TestExtractTenuoErrorCode:
    @given(structured=st.one_of(
        st.none(),
        st.just({}),
        st.just({"tenuo": {}}),
        st.just({"tenuo": {"code": -32001}}),
        st.just({"tenuo": {"code": -32002}}),
        st.just({"tenuo": {"code": "not_an_int"}}),
        st.just({"other": "data"}),
        st.dictionaries(st.text(min_size=1, max_size=10), st_simple_value, max_size=5),
        st.text(min_size=0, max_size=20),
        st.integers(),
        st.lists(st_simple_value, max_size=3),
    ))
    @settings(max_examples=100)
    def test_returns_int_or_none(self, structured):
        """_extract_tenuo_error_code returns int or None, never crashes."""
        result = _extract_tenuo_error_code(structured)
        assert result is None or isinstance(result, int)

    def test_extracts_valid_code(self):
        """Correctly extracts tenuo.code when present and int."""
        assert _extract_tenuo_error_code({"tenuo": {"code": -32002}}) == -32002

    def test_none_for_non_int_code(self):
        """Returns None when tenuo.code is not an int."""
        assert _extract_tenuo_error_code({"tenuo": {"code": "string"}}) is None

    def test_none_for_missing_tenuo(self):
        """Returns None when tenuo key is missing."""
        assert _extract_tenuo_error_code({"other": "data"}) is None


class TestSafeMCPToolErrorMessage:
    @given(
        content=st.one_of(
            st.none(),
            st.just([]),
            st.lists(st.builds(
                lambda: MagicMock(type="text", text="error message"),
            ), max_size=3),
            st.text(min_size=0, max_size=50),
            st.integers(),
        ),
        tool=st_tool_name,
    )
    @settings(max_examples=50)
    def test_always_returns_nonempty_string(self, content, tool):
        """_safe_mcp_tool_error_message always returns a non-empty string."""
        result = _safe_mcp_tool_error_message(content, tool)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_extracts_text_block(self):
        """Extracts text from a TextContent-like block."""
        block = MagicMock()
        block.type = "text"
        block.text = "Something went wrong"
        result = _safe_mcp_tool_error_message([block], "test_tool")
        assert result == "Something went wrong"

    def test_fallback_when_no_text_blocks(self):
        """Falls back to generic message when no text blocks."""
        block = MagicMock()
        block.type = "image"
        result = _safe_mcp_tool_error_message([block], "my_tool")
        assert "my_tool" in result

    def test_fallback_for_empty_list(self):
        """Falls back for empty content list."""
        result = _safe_mcp_tool_error_message([], "test_tool")
        assert "test_tool" in result

    def test_fallback_for_none(self):
        """Falls back for None content."""
        result = _safe_mcp_tool_error_message(None, "test_tool")
        assert "test_tool" in result
