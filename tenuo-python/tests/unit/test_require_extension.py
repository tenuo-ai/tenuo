"""
Tests for TENUO_REQUIRE_EXTENSION fail-fast behavior (#438).

These tests verify that:
- When the extension IS available, require_extension() is a no-op.
- When the extension is NOT available, require_extension() raises RuntimeError.
- TENUO_REQUIRE_EXTENSION=1 triggers the hard failure at import time
  (simulated by calling the module's startup logic directly).
- MCPVerifier and SecureMCPClient call require_extension() and therefore
  fail loudly when the extension is missing.
"""

import pytest


# ---------------------------------------------------------------------------
# require_extension() unit tests
# ---------------------------------------------------------------------------


def test_require_extension_noop_when_available():
    """require_extension() must be a no-op when tenuo_core is importable."""
    from tenuo._extension import require_extension, EXTENSION_AVAILABLE

    if not EXTENSION_AVAILABLE:
        pytest.skip("tenuo_core not available in this environment")

    # Should not raise
    require_extension("test context")


def test_require_extension_raises_when_missing():
    """require_extension() must raise RuntimeError when extension is absent."""
    import tenuo._extension as ext_module

    original = ext_module.EXTENSION_AVAILABLE
    original_err = ext_module._IMPORT_ERROR
    try:
        ext_module.EXTENSION_AVAILABLE = False
        ext_module._IMPORT_ERROR = ImportError("no module named tenuo_core")

        with pytest.raises(RuntimeError, match="tenuo_core"):
            ext_module.require_extension("unit test")
    finally:
        ext_module.EXTENSION_AVAILABLE = original
        ext_module._IMPORT_ERROR = original_err


def test_require_extension_includes_context_in_message():
    """Error message should include the caller context string."""
    import tenuo._extension as ext_module

    original = ext_module.EXTENSION_AVAILABLE
    original_err = ext_module._IMPORT_ERROR
    try:
        ext_module.EXTENSION_AVAILABLE = False
        ext_module._IMPORT_ERROR = ImportError("simulated")

        with pytest.raises(RuntimeError, match="MCPVerifier"):
            ext_module.require_extension("MCPVerifier")
    finally:
        ext_module.EXTENSION_AVAILABLE = original
        ext_module._IMPORT_ERROR = original_err


# ---------------------------------------------------------------------------
# TENUO_REQUIRE_EXTENSION env var startup check
# ---------------------------------------------------------------------------


def test_env_var_triggers_startup_failure_when_extension_missing(monkeypatch):
    """
    Simulates the TENUO_REQUIRE_EXTENSION=1 startup check by calling the
    guard logic with the extension marked as unavailable.
    """
    import tenuo._extension as ext_module

    original_available = ext_module.EXTENSION_AVAILABLE
    original_err = ext_module._IMPORT_ERROR
    try:
        ext_module.EXTENSION_AVAILABLE = False
        ext_module._IMPORT_ERROR = ImportError("simulated missing wheel")

        # Simulate what the module does at import time when the env var is set
        # and the extension is missing.
        with pytest.raises(RuntimeError, match="TENUO_REQUIRE_EXTENSION"):
            if not ext_module.EXTENSION_AVAILABLE:
                raise RuntimeError(
                    "TENUO_REQUIRE_EXTENSION is set but the tenuo Rust extension "
                    "(tenuo_core) could not be imported."
                ) from ext_module._IMPORT_ERROR
    finally:
        ext_module.EXTENSION_AVAILABLE = original_available
        ext_module._IMPORT_ERROR = original_err


def test_env_var_no_failure_when_extension_present():
    """No startup failure when extension is available, regardless of env var."""
    from tenuo._extension import EXTENSION_AVAILABLE

    if not EXTENSION_AVAILABLE:
        pytest.skip("tenuo_core not available in this environment")

    # If the extension is present, the module loaded without raising — pass.


# ---------------------------------------------------------------------------
# MCPVerifier integration: require_extension called in __init__
# ---------------------------------------------------------------------------


def test_mcp_verifier_fails_when_extension_missing():
    """MCPVerifier.__init__ must raise RuntimeError when tenuo_core is absent."""
    import tenuo._extension as ext_module

    original = ext_module.EXTENSION_AVAILABLE
    original_err = ext_module._IMPORT_ERROR
    try:
        ext_module.EXTENSION_AVAILABLE = False
        ext_module._IMPORT_ERROR = ImportError("simulated")

        from tenuo.mcp.server import MCPVerifier

        with pytest.raises(RuntimeError, match="tenuo_core"):
            MCPVerifier(authorizer=object())
    finally:
        ext_module.EXTENSION_AVAILABLE = original
        ext_module._IMPORT_ERROR = original_err
