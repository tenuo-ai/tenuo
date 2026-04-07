#!/usr/bin/env python3
"""
MCP Server Integration Example

Demonstrates server-side Tenuo authorization inside an MCP server.

Three patterns are shown:
  1. MCPVerifier with fastmcp     — recommended for most servers
  2. MCPVerifier without config   — raw mode, field names = constraint names
  3. Approval-gate-triggered approval flow — re-submit protocol for gated tools

FastMCP does not pass ``params._meta`` into ``@mcp.tool()`` handlers.  Each
pattern below registers :class:`tenuo.mcp.TenuoMiddleware` so warrant + PoP
from the wire (``params._meta.tenuo``) are verified before the tool runs.
Clients should use ``inject_warrant=True`` (see ``mcp_client.py``).

Prerequisites:
  uv pip install "tenuo[fastmcp]"   # FastMCP + MCP SDK (use ``tenuo[mcp]`` for SDK-only servers)

Run:
  python mcp_server.py            # starts a stdio MCP server
  fastmcp run mcp_server.py       # alternate runner
"""

import logging
import os

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)


# ============================================================================
# 1.  MCPVerifier + fastmcp (recommended)
# ============================================================================

def create_server_with_config():
    """Full setup: MCP config maps field names to constraint names.

    This is the recommended pattern.  An ``mcp-config.yaml`` defines
    how tool argument names are mapped to warrant constraint names,
    what types they are, and which fields are required.

    The same config file should be shared with the client so both
    sides agree on the constraint view used for PoP signatures.

    :class:`TenuoMiddleware` runs :meth:`MCPVerifier.verify` on every
    ``tools/call`` and strips ``meta.tenuo`` before the handler runs, so
    handlers only see normal tool arguments (already authorized).
    """
    from fastmcp import FastMCP

    from tenuo import Authorizer, CompiledMcpConfig, McpConfig, PublicKey
    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    # In production, load the issuer key from environment/secrets
    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        # For demo: generate a throwaway keypair
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()
        log.warning("No TENUO_ISSUER_PUBLIC_KEY — using throwaway key for demo")

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    config = CompiledMcpConfig.compile(McpConfig.from_file("mcp-config.yaml"))
    verifier = MCPVerifier(authorizer=authorizer, config=config)

    mcp = FastMCP("tenuo-file-server", middleware=[TenuoMiddleware(verifier)])

    @mcp.tool()
    async def read_file(path: str, maxSize: int = 4096) -> str:
        """Read a file from disk (Tenuo-protected)."""
        log.info("Authorized read_file: %s", path)
        return open(path).read(maxSize)

    @mcp.tool()
    async def write_file(path: str, content: str) -> str:
        """Write a file to disk (Tenuo-protected)."""
        with open(path, "w") as f:
            f.write(content)
        return f"Wrote {len(content)} bytes to {path}"

    return mcp


# ============================================================================
# 2.  MCPVerifier without config (raw mode)
# ============================================================================

def create_server_raw():
    """Simple setup: no config file, argument names = constraint names.

    This works when your MCP tool schema uses the exact same field names
    as the warrant constraints.  No field-name mapping is performed.
    """
    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    verifier = MCPVerifier(authorizer=authorizer)

    mcp = FastMCP("tenuo-raw-server", middleware=[TenuoMiddleware(verifier)])

    @mcp.tool()
    async def search(query: str) -> str:
        """Search (Tenuo-protected, no config)."""
        return f"Results for: {query}"

    return mcp


# ============================================================================
# 3.  Approval-gate-triggered approval flow
# ============================================================================

def create_server_with_approval_gates():
    """Server that handles approval-gate-triggered re-submit for high-risk tools.

    Some warrants attach approval gates to specific tools — e.g. ``transfer``
    above $10,000 requires human approval.  When a gate fires:

      1. :class:`TenuoMiddleware` runs ``verifier.verify()`` before the tool
      2. The client receives an ``isError`` tool result with JSON-RPC code
         ``-32002`` in ``structuredContent.tenuo`` (the tool body does not run)
      3. The client obtains ``SignedApproval`` objects from authorized approvers
      4. The client re-submits the same call with approvals in ``_meta.tenuo.approvals``
      5. Verification passes — the handler runs and completes the transfer

    For raw MCP handlers (no FastMCP), use :meth:`MCPVerifier.verify` and
    :exc:`MCPAuthorizationError` / :meth:`MCPVerificationResult.raise_if_denied`
    in your own ``call_tool`` handler instead of this middleware pattern.
    """
    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    verifier = MCPVerifier(authorizer=authorizer)

    mcp = FastMCP("tenuo-gated-server", middleware=[TenuoMiddleware(verifier)])

    @mcp.tool()
    async def transfer(amount: float, destination: str) -> str:
        """Transfer funds (approval gate enforced in middleware before this runs)."""
        log.info("Transfer authorized: %.2f → %s", amount, destination)
        return f"Transferred {amount} to {destination}"

    return mcp


# ============================================================================
# 4.  Mixed deployment (require_warrant=False)
# ============================================================================

def create_server_mixed():
    """Gradual rollout: some calls have warrants, some don't.

    During migration you may want to accept both warranted and
    unwarranted calls.  Set ``require_warrant=False`` on the verifier.
    Calls without a warrant in ``_meta.tenuo`` are allowed through (you
    can add your own fallback AuthZ), while warranted calls are fully verified.

    Middleware performs verification first; use a verifier ``control_plane``
    hook if you need structured logging of warrant vs unwarranted calls.
    """
    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    verifier = MCPVerifier(
        authorizer=authorizer,
        require_warrant=False,  # allow unauthenticated calls during migration
    )

    mcp = FastMCP("tenuo-mixed-server", middleware=[TenuoMiddleware(verifier)])

    @mcp.tool()
    async def read_file(path: str) -> str:
        """Read file — warranted and plain calls (see verifier require_warrant)."""
        return open(path).read()

    return mcp


# ============================================================================
# 5.  Standalone verify_mcp_call (no class needed)
# ============================================================================

def standalone_example():
    """For servers that handle a handful of tools, the standalone function
    avoids constructing an MCPVerifier object."""
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import verify_mcp_call

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )

    # In a JSON-RPC handler:
    arguments = {"path": "/data/file.txt"}
    meta = None  # in production, pass params._meta from the MCP request
    result = verify_mcp_call("read_file", arguments, authorizer=authorizer, meta=meta)

    if result.allowed:
        print(f"Authorized — clean args: {result.clean_arguments}")
    else:
        print(f"Denied — {result.denial_reason}")
        print(f"JSON-RPC error: {result.to_jsonrpc_error()}")


# ============================================================================
# Main — run the fastmcp server
# ============================================================================

# Pick which server to run
mcp = create_server_with_config()

if __name__ == "__main__":
    mcp.run(transport="stdio")
