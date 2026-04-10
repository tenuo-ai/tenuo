"""Property tests for LangChain / LangGraph integrations.

Verifies:
- TenuoTool._check_authorization routes through enforce_tool_call to Rust
- LangGraph TenuoMiddleware routes through enforce_tool_call
- chain_scope propagation: warrant_chain is passed to enforce_tool_call
"""

from __future__ import annotations


import pytest




# ---------------------------------------------------------------------------
# LangChain: TenuoTool routes to enforce_tool_call
# ---------------------------------------------------------------------------


class TestLangChainTenuoTool:
    def test_source_calls_enforce_tool_call(self):
        """LangChain TenuoTool._check_authorization calls enforce_tool_call."""
        try:
            import tenuo.langchain as lc_mod
        except ImportError:
            pytest.skip("langchain not installed")

        import inspect
        source = inspect.getsource(lc_mod)
        assert "enforce_tool_call(" in source

    def test_imports_canonical_enforce(self):
        """LangChain imports the canonical enforce_tool_call."""
        try:
            from tenuo.langchain import enforce_tool_call as lc_enforce
            from tenuo._enforcement import enforce_tool_call as canonical
        except ImportError:
            pytest.skip("langchain not installed")

        assert lc_enforce is canonical

    def test_source_passes_trusted_roots(self):
        """LangChain source passes trusted_roots to enforce_tool_call."""
        try:
            import tenuo.langchain as lc_mod
        except ImportError:
            pytest.skip("langchain not installed")

        import inspect
        source = inspect.getsource(lc_mod)
        assert "trusted_roots" in source


# ---------------------------------------------------------------------------
# LangGraph: TenuoMiddleware routes to enforce_tool_call
# ---------------------------------------------------------------------------


class TestLangGraphMiddleware:
    def test_source_calls_enforce_tool_call(self):
        """LangGraph TenuoMiddleware uses enforce_tool_call."""
        try:
            import tenuo.langgraph as lg_mod
        except ImportError:
            pytest.skip("langgraph not installed")

        import inspect
        source = inspect.getsource(lg_mod)
        assert "enforce_tool_call(" in source

    def test_imports_canonical_enforce(self):
        """LangGraph imports the canonical enforce_tool_call."""
        try:
            from tenuo.langgraph import enforce_tool_call as lg_enforce
            from tenuo._enforcement import enforce_tool_call as canonical
        except ImportError:
            pytest.skip("langgraph not installed")

        assert lg_enforce is canonical


# ---------------------------------------------------------------------------
# chain_scope propagation
# ---------------------------------------------------------------------------


class TestChainScopePropagation:
    def test_langchain_source_reads_chain_scope(self):
        """LangChain source reads chain_scope for warrant_chain parameter."""
        try:
            import tenuo.langchain as lc_mod
        except ImportError:
            pytest.skip("langchain not installed")

        import inspect
        source = inspect.getsource(lc_mod)
        assert "chain_scope" in source, \
            "LangChain must read chain_scope for delegation chain propagation"
        assert "warrant_chain" in source, \
            "LangChain must pass warrant_chain to enforce_tool_call"
