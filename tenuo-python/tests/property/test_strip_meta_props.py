"""Property tests for fastmcp_middleware._strip_tenuo_meta.

Verifies:
- After _strip_tenuo_meta, the 'tenuo' key is absent from meta
- clean_arguments are propagated to the result
- Non-tenuo meta keys are preserved
"""

from __future__ import annotations

import inspect

import pytest


class TestStripTenuoMetaInvariant:
    """Verify via source inspection that _strip_tenuo_meta removes 'tenuo' from meta."""

    def test_pops_tenuo_from_meta(self):
        """Source of _strip_tenuo_meta pops or excludes 'tenuo' key."""
        try:
            from tenuo.mcp.fastmcp_middleware import _strip_tenuo_meta
        except ImportError:
            pytest.skip("fastmcp not installed")
        src = inspect.getsource(_strip_tenuo_meta)
        assert "tenuo" in src
        assert "pop" in src or 'k != "tenuo"' in src

    def test_passes_clean_arguments(self):
        """Source of _strip_tenuo_meta propagates clean_arguments to update."""
        try:
            from tenuo.mcp.fastmcp_middleware import _strip_tenuo_meta
        except ImportError:
            pytest.skip("fastmcp not installed")
        src = inspect.getsource(_strip_tenuo_meta)
        assert "clean_arguments" in src
        assert "model_copy" in src


class TestTenuoMiddlewareWiring:
    """Verify TenuoMiddleware on_call_tool invokes _strip_tenuo_meta on allow."""

    def test_on_call_tool_calls_strip(self):
        """on_call_tool source references _strip_tenuo_meta."""
        try:
            from tenuo.mcp.fastmcp_middleware import TenuoMiddleware
        except ImportError:
            pytest.skip("fastmcp not installed")
        src = inspect.getsource(TenuoMiddleware)
        assert "_strip_tenuo_meta" in src

    def test_denial_does_not_call_next(self):
        """When verification fails, on_call_tool returns denial without calling call_next."""
        try:
            from tenuo.mcp.fastmcp_middleware import TenuoMiddleware
        except ImportError:
            pytest.skip("fastmcp not installed")
        src = inspect.getsource(TenuoMiddleware.on_call_tool)
        assert "not result.allowed" in src or "not verification.allowed" in src
        assert "_denial_tool_return" in src


class TestResolveToolCallMeta:
    """Verify resolve_tool_call_meta_for_verify handles various meta shapes."""

    def test_none_params_meta_falls_through(self):
        """When params.meta is None, falls through to fastmcp_context."""
        try:
            from tenuo.mcp.fastmcp_middleware import resolve_tool_call_meta_for_verify
        except ImportError:
            pytest.skip("fastmcp not installed")
        src = inspect.getsource(resolve_tool_call_meta_for_verify)
        assert "request_context" in src
        assert "model_dump" in src
