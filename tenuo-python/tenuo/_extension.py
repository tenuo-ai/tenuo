"""
Extension availability guard for the tenuo Rust core.

This module performs a single import attempt for ``tenuo_core`` at package
load time and exposes two things:

* ``EXTENSION_AVAILABLE`` — ``True`` if the native extension loaded
  successfully, ``False`` otherwise.
* ``require_extension(context)`` — raises ``RuntimeError`` with an
  actionable message if the extension is not available.  Call this at
  any enforcement boundary that must not silently degrade.

Environment variable
--------------------
``TENUO_REQUIRE_EXTENSION=1`` (also accepts ``true``, ``yes``)

    When set, the extension is required at package import time.  If
    ``tenuo_core`` cannot be imported, the process exits immediately with
    a clear error rather than silently no-op'ing later.

    **Recommended for all production deployments** — without this flag, a
    Docker image that drops the native wheel (wrong manylinux tag, missing
    arm64 wheel, etc.) will accept tool calls unconditionally with no
    warrant attached and no error logged.

Usage in enforcement code
-------------------------
    from tenuo._extension import require_extension

    class MCPVerifier:
        def __init__(self, ...):
            require_extension("MCPVerifier")  # fails loudly if core missing
            ...
"""

from __future__ import annotations

import logging
import os

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Single authoritative import attempt
# ---------------------------------------------------------------------------

try:
    import tenuo_core as _tenuo_core  # noqa: F401

    EXTENSION_AVAILABLE: bool = True
    _IMPORT_ERROR: Exception | None = None
except ImportError as _exc:
    EXTENSION_AVAILABLE = False
    _IMPORT_ERROR = _exc

# ---------------------------------------------------------------------------
# Env-var check — fail loudly at import time when TENUO_REQUIRE_EXTENSION=1
# ---------------------------------------------------------------------------

_REQUIRE_ENV = os.environ.get("TENUO_REQUIRE_EXTENSION", "").strip().lower()
_REQUIRE_AT_STARTUP: bool = _REQUIRE_ENV in ("1", "true", "yes")

if _REQUIRE_AT_STARTUP and not EXTENSION_AVAILABLE:
    raise RuntimeError(
        "TENUO_REQUIRE_EXTENSION is set but the tenuo Rust extension "
        "(tenuo_core) could not be imported.\n\n"
        f"  Original error: {_IMPORT_ERROR}\n\n"
        "Common causes:\n"
        "  • The wheel for this platform/Python version was not installed "
        "(e.g. wrong manylinux tag or missing arm64 wheel in a Docker image).\n"
        "  • The extension was removed after the package was installed "
        "(e.g. a layer-optimizing image rebuild).\n\n"
        "To fix: ensure the correct tenuo wheel is installed for this "
        "platform. Run `python -c 'import tenuo_core'` inside the container "
        "to verify."
    ) from _IMPORT_ERROR

if not EXTENSION_AVAILABLE and not _REQUIRE_AT_STARTUP:
    _log.warning(
        "tenuo Rust extension (tenuo_core) is not available — warrant "
        "enforcement will be silently skipped. Set TENUO_REQUIRE_EXTENSION=1 "
        "to make this a hard failure at startup."
    )


# ---------------------------------------------------------------------------
# Call-site guard
# ---------------------------------------------------------------------------


def require_extension(context: str = "") -> None:
    """Raise ``RuntimeError`` if the tenuo Rust extension is not available.

    Call this at the start of any function or class that must not silently
    degrade when the extension is missing (e.g. ``MCPVerifier.__init__``,
    ``SecureMCPClient.__init__``).

    Args:
        context: Short description of the call site, included in the error
            message to help operators locate the problem quickly.
    """
    if EXTENSION_AVAILABLE:
        return

    ctx = f" (context: {context})" if context else ""
    raise RuntimeError(
        f"tenuo Rust extension (tenuo_core) is required but not available{ctx}.\n\n"
        f"  Original import error: {_IMPORT_ERROR}\n\n"
        "Set TENUO_REQUIRE_EXTENSION=1 to catch this at process startup "
        "instead of at the first enforcement call."
    ) from _IMPORT_ERROR
