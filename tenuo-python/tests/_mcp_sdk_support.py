"""Skip conditions for tests that need a particular MCP SDK line.

Tenuo's own MCP code spans SDK 1.x and 2.x (see :mod:`tenuo.mcp._compat`), but
some tests stand up a real MCP *server*, and the server side is not portable
across the two lines:

* FastMCP's server extras still require ``mcp<2.0``, so importing
  ``fastmcp.server`` fails outright when only 2.x is installed.
* The lowlevel ``Server`` decorator API that the stdio fixture servers use was
  restructured in 2.0.

Tests that only exercise the client or the verifier need none of this —
``MCPVerifier`` never imports ``mcp.server``.
"""

from __future__ import annotations

FASTMCP_SERVER_AVAILABLE: bool
FASTMCP_SERVER_SKIP_REASON = (
    "FastMCP server support unavailable (its server extras require mcp<2.0)"
)

try:
    import fastmcp.server  # noqa: F401

    FASTMCP_SERVER_AVAILABLE = True
except ImportError:
    FASTMCP_SERVER_AVAILABLE = False


LOWLEVEL_SERVER_DECORATORS_AVAILABLE: bool
LOWLEVEL_SERVER_SKIP_REASON = (
    "MCP lowlevel Server decorator API unavailable (restructured in mcp 2.0)"
)

try:
    from mcp.server.lowlevel import Server as _LowlevelServer

    LOWLEVEL_SERVER_DECORATORS_AVAILABLE = hasattr(_LowlevelServer, "list_tools")
except ImportError:
    LOWLEVEL_SERVER_DECORATORS_AVAILABLE = False


#: The 2.x counterpart: handlers are registered explicitly rather than by
#: decorator. Lets the client keep end-to-end coverage on the 2.x line, where
#: the 1.x stdio fixtures cannot run.
MCP_SDK2_SERVER_AVAILABLE: bool
MCP_SDK2_SERVER_SKIP_REASON = (
    "requires the MCP 2.x lowlevel server API (Server.add_request_handler)"
)

try:
    from mcp.server.lowlevel import Server as _Sdk2Server

    MCP_SDK2_SERVER_AVAILABLE = hasattr(_Sdk2Server, "add_request_handler") and not hasattr(
        _Sdk2Server, "list_tools"
    )
except ImportError:
    MCP_SDK2_SERVER_AVAILABLE = False
