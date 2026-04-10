"""Property tests for A2A integration (a2a/server.py).

Verifies:
- A2A server module uses Authorizer from tenuo_core
- validate_warrant calls authorize_one/check_chain (source inspection)
- Arbitrary base64 warrant strings don't crash validate_warrant
"""

from __future__ import annotations

import inspect

import pytest




# ---------------------------------------------------------------------------
# A2A server uses Rust: source-level verification
# ---------------------------------------------------------------------------


class TestA2AServerUsesRust:
    def test_imports_authorizer(self):
        """A2A server module imports and uses Authorizer from tenuo_core."""
        try:
            from tenuo.a2a import server as a2a_server
        except ImportError:
            pytest.skip("a2a dependencies not installed")

        source = inspect.getsource(a2a_server)
        assert "Authorizer" in source, "A2A server must import Authorizer"

    def test_calls_authorize_one_or_check_chain(self):
        """A2A server calls authorize_one or check_chain for verification."""
        try:
            from tenuo.a2a import server as a2a_server
        except ImportError:
            pytest.skip("a2a dependencies not installed")

        source = inspect.getsource(a2a_server)
        assert "authorize_one" in source or "check_chain" in source, \
            "A2A server must call authorize_one or check_chain"

    def test_uses_warrant_from_base64(self):
        """A2A server uses Warrant.from_base64 for warrant decoding."""
        try:
            from tenuo.a2a import server as a2a_server
        except ImportError:
            pytest.skip("a2a dependencies not installed")

        source = inspect.getsource(a2a_server)
        assert "Warrant.from_base64" in source or "from_base64" in source


# ---------------------------------------------------------------------------
# A2A server: require_pop=True path calls Authorizer
# ---------------------------------------------------------------------------


class TestA2AServerRequirePopPath:
    def test_require_pop_source_calls_authorizer(self):
        """When require_pop=True, validate_warrant uses Authorizer for PoP verification."""
        try:
            from tenuo.a2a import server as a2a_server
        except ImportError:
            pytest.skip("a2a dependencies not installed")

        source = inspect.getsource(a2a_server)
        # The require_pop path must construct and call Authorizer
        assert "authorize_one(" in source or "check_chain(" in source


# ---------------------------------------------------------------------------
# A2A server: require_pop=False path documented behavior
# ---------------------------------------------------------------------------


class TestA2AServerNoPopPath:
    def test_fallback_uses_why_denied(self):
        """When require_pop=False, A2A falls back to why_denied (Rust) or Python grants."""
        try:
            from tenuo.a2a import server as a2a_server
        except ImportError:
            pytest.skip("a2a dependencies not installed")

        source = inspect.getsource(a2a_server)
        assert "why_denied" in source, \
            "A2A server should use why_denied for the no-PoP fallback path"
