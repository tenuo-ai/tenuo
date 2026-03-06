#!/usr/bin/env python3
"""
MCP Server Integration Example

Demonstrates server-side Tenuo authorization inside an MCP server.

Three patterns are shown:
  1. MCPVerifier with fastmcp     — recommended for most servers
  2. MCPVerifier without config   — raw mode, field names = constraint names
  3. Approval-gate-triggered approval flow — re-submit protocol for gated tools

The server verifies every incoming tool call against a Tenuo warrant
embedded in ``_tenuo`` by the client (see mcp_client.py, inject_warrant=True).

Prerequisites:
  pip install "tenuo[mcp]" fastmcp

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
    """
    from fastmcp import FastMCP

    from tenuo import Authorizer, CompiledMcpConfig, McpConfig, PublicKey
    from tenuo.mcp import MCPVerifier

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

    mcp = FastMCP("tenuo-file-server")

    @mcp.tool()
    async def read_file(path: str, maxSize: int = 4096, **kwargs) -> str:
        """Read a file from disk (Tenuo-protected).

        The client sends ``_tenuo`` inside ``kwargs``.  MCPVerifier strips
        it and returns only the clean tool arguments.
        """
        clean = verifier.verify_or_raise(
            "read_file", {"path": path, "maxSize": maxSize, **kwargs}
        )
        file_path = clean["path"]
        log.info("Authorized read_file: %s", file_path)
        return open(file_path).read(clean.get("max_size", 4096))

    @mcp.tool()
    async def write_file(path: str, content: str, **kwargs) -> str:
        """Write a file to disk (Tenuo-protected)."""
        clean = verifier.verify_or_raise(
            "write_file", {"path": path, "content": content, **kwargs}
        )
        with open(clean["path"], "w") as f:
            f.write(clean["content"])
        return f"Wrote {len(clean['content'])} bytes to {clean['path']}"

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

    from tenuo.mcp import MCPVerifier

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    verifier = MCPVerifier(authorizer=authorizer)

    mcp = FastMCP("tenuo-raw-server")

    @mcp.tool()
    async def search(query: str, **kwargs) -> str:
        """Search (Tenuo-protected, no config)."""
        clean = verifier.verify_or_raise("search", {"query": query, **kwargs})
        return f"Results for: {clean['query']}"

    return mcp


# ============================================================================
# 3.  Approval-gate-triggered approval flow
# ============================================================================

def create_server_with_approval_gates():
    """Server that handles approval-gate-triggered re-submit for high-risk tools.

    Some warrants attach approval gates to specific tools — e.g. ``transfer``
    above $10,000 requires human approval.  When a gate fires:

      1. ``verifier.verify()`` returns ``result.is_approval_required == True``
      2. The server returns JSON-RPC error ``-32002`` to the client
      3. The client obtains ``SignedApproval`` objects from authorized approvers
      4. The client re-submits the same call with approvals in ``_tenuo.approvals``
      5. ``verifier.verify()`` now passes — approvals satisfy the gate

    This example shows how to detect and handle the approval-gate-triggered case
    with structured JSON-RPC errors.
    """
    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import MCPAuthorizationError, MCPVerifier

    ISSUER_KEY_HEX = os.environ.get("TENUO_ISSUER_PUBLIC_KEY", "")
    if not ISSUER_KEY_HEX:
        from tenuo import SigningKey

        kp = SigningKey.generate()
        ISSUER_KEY_HEX = bytes(kp.public_key_bytes()).hex()

    authorizer = Authorizer(
        trusted_roots=[PublicKey.from_bytes(bytes.fromhex(ISSUER_KEY_HEX))]
    )
    verifier = MCPVerifier(authorizer=authorizer)

    mcp = FastMCP("tenuo-gated-server")

    @mcp.tool()
    async def transfer(amount: float, destination: str, **kwargs) -> str:
        """Transfer funds (may require human approval).

        If the warrant has an approval gate on ``transfer`` and no approvals are
        supplied, the verification result will indicate ``-32002``.
        """
        result = verifier.verify(
            "transfer", {"amount": amount, "destination": destination, **kwargs}
        )

        if result.is_approval_required:
            log.info(
                "Approval gate triggered for transfer amount=%.2f — requesting approval",
                amount,
            )
            raise MCPAuthorizationError(result)

        # For other denials, raise a generic error
        result.raise_if_denied()

        log.info(
            "Transfer authorized: %.2f → %s (warrant=%s)",
            amount,
            destination,
            result.warrant_id,
        )
        return f"Transferred {amount} to {destination}"

    return mcp


# ============================================================================
# 4.  Mixed deployment (require_warrant=False)
# ============================================================================

def create_server_mixed():
    """Gradual rollout: some calls have warrants, some don't.

    During migration you may want to accept both warranted and
    unwarranted calls.  Set ``require_warrant=False`` on the verifier.
    Calls without ``_tenuo`` are allowed through (you can add your own
    fallback AuthZ), while calls *with* a warrant are fully verified.
    """
    from fastmcp import FastMCP
    from tenuo import Authorizer, PublicKey

    from tenuo.mcp import MCPVerifier

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

    mcp = FastMCP("tenuo-mixed-server")

    @mcp.tool()
    async def read_file(path: str, **kwargs) -> str:
        """Read file — accepts both warranted and plain calls."""
        result = verifier.verify("read_file", {"path": path, **kwargs})
        if result.allowed:
            if result.warrant_id:
                log.info("Warranted call: %s (warrant=%s)", path, result.warrant_id)
            else:
                log.info("Unwarranted call: %s (fallback policy)", path)
            return open(result.clean_arguments["path"]).read()

        result.raise_if_denied()

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
    arguments = {"path": "/data/file.txt"}  # would include _tenuo in production
    result = verify_mcp_call("read_file", arguments, authorizer=authorizer)

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
