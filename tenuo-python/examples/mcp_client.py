#!/usr/bin/env python3
"""
MCP Client Integration Example

Demonstrates all three MCP transport modes with Tenuo authorization:
  1. Local subprocess (stdio)  — wrapping a Python MCP server
  2. Remote SSE                — connecting to a legacy HTTP server
  3. Remote StreamableHTTP     — connecting to the current MCP HTTP transport

Each example shows:
  - Tool discovery and automatic protection
  - Warrant scoping with `mint()`
  - Warrant injection for server-side verification
  - Pre-supplying approval gate approvals

Prerequisites:
  uv pip install "tenuo[mcp]"

Run (with a local server):
  python mcp_client.py
"""

import logging

from tenuo import (
    Capability,
    Pattern,
    Range,
    SigningKey,
    configure,
    mint,
)
from tenuo.mcp import SecureMCPClient, discover_and_protect

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)


# ============================================================================
# 1.  Local subprocess (stdio transport)
# ============================================================================


async def stdio_example():
    """Connect to a local MCP server over stdio."""
    print("\n=== 1. stdio transport ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    # SecureMCPClient wraps the MCP SDK — tools are auto-discovered on connect
    async with SecureMCPClient("python", ["my_mcp_server.py"]) as client:
        print(f"Discovered tools: {list(client.tools.keys())}")

        # Every tool call is automatically checked against the active warrant.
        # mint() scopes the warrant to specific capabilities.
        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await client.tools["read_file"](path="/data/report.csv")
            print(f"read_file result: {result}")

        # A narrower scope — only allows managing staging clusters
        async with mint(
            Capability(
                "manage_cluster",
                cluster=Pattern("staging-*"),
                replicas=Range.max_value(5),
            )
        ):
            result = await client.tools["manage_cluster"](
                cluster="staging-web", replicas=3
            )
            print(f"manage_cluster result: {result}")


# ============================================================================
# 2.  Remote SSE transport (legacy HTTP)
# ============================================================================


async def sse_example():
    """Connect to a remote MCP server using the SSE transport."""
    print("\n=== 2. SSE transport ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    async with SecureMCPClient(
        url="https://mcp.example.com/sse",
        transport="sse",
        headers={"Authorization": "Bearer <token>"},
        inject_warrant=True,  # send warrant via params._meta.tenuo
    ) as client:
        print(f"Discovered tools: {list(client.tools.keys())}")

        async with mint(Capability("search", query=Pattern("*"))):
            result = await client.tools["search"](query="quarterly earnings")
            print(f"search result: {result}")


# ============================================================================
# 3.  Remote StreamableHTTP transport (current spec)
# ============================================================================


async def http_example():
    """Connect to a remote MCP server using StreamableHTTP."""
    print("\n=== 3. StreamableHTTP transport ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    async with SecureMCPClient(
        url="https://mcp.example.com/mcp",
        transport="http",
        headers={"Authorization": "Bearer <token>"},
        timeout=60.0,
        inject_warrant=True,
    ) as client:
        print(f"Discovered tools: {list(client.tools.keys())}")

        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await client.tools["read_file"](path="/data/metrics.json")
            print(f"read_file result: {result}")


# ============================================================================
# 4.  discover_and_protect shorthand
# ============================================================================


async def shorthand_example():
    """One-liner tool discovery with discover_and_protect()."""
    print("\n=== 4. discover_and_protect shorthand ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    async with discover_and_protect("python", ["my_mcp_server.py"]) as tools:
        print(f"Discovered tools: {list(tools.keys())}")

        async with mint(Capability("read_file", path=Pattern("/data/*"))):
            result = await tools["read_file"](path="/data/report.csv")
            print(f"read_file result: {result}")


# ============================================================================
# 5.  Pre-supplying approval gate approvals
# ============================================================================


async def approval_gate_example():
    """Forward pre-obtained approvals for gate-protected tools.

    When a warrant has approval gates that require human approval for certain
    tools, the client must supply SignedApproval objects.  These are
    serialized into ``_meta.tenuo.approvals`` and verified server-side.
    """
    print("\n=== 5. Approval gate approvals ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    async with SecureMCPClient(
        url="https://mcp.example.com/mcp",
        transport="http",
        inject_warrant=True,
    ) as client:

        async with mint(Capability("transfer", amount=Range.max_value(50_000))):
            # First attempt — server returns -32002 (approval required)
            # In production you'd catch the error, obtain approvals from
            # authorized human approvers, then re-submit:

            # signed_approvals = await obtain_approvals_from_approvers(...)
            signed_approvals = []  # placeholder

            result = await client.tools["transfer"](
                amount=10_000,
                destination="acct_123",
                _approvals=signed_approvals,  # forwarded to _meta.tenuo.approvals
            )
            print(f"transfer result: {result}")


# ============================================================================
# 6.  MCP config for constraint extraction
# ============================================================================


async def config_example():
    """Use an mcp-config.yaml to map argument names to constraint names.

    When field names in MCP tool schemas differ from warrant constraint
    names (e.g. ``maxSize`` → ``max_size``), an MCP config file provides
    the mapping.  SecureMCPClient applies the config automatically so
    both local enforcement and server-side PoP verification agree on
    constraint names.
    """
    print("\n=== 6. MCP config ===\n")

    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)

    # config_path registers the extraction rules globally for @guard
    async with SecureMCPClient(
        "python",
        ["my_mcp_server.py"],
        config_path="mcp-config.yaml",
        inject_warrant=True,
    ) as client:
        async with mint(
            Capability("read_file", path=Pattern("/data/*"), max_size=Range.max_value(1024))
        ):
            # maxSize is mapped to max_size by the config before enforcement
            result = await client.tools["read_file"](
                path="/data/log.txt", maxSize=512
            )
            print(f"read_file result: {result}")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    # Only stdio_example and shorthand_example can run locally with a real
    # server.  The rest require network endpoints and are shown for reference.
    print("MCP Client Integration Examples")
    print("================================")
    print()
    print("These examples show the patterns — each requires a running MCP server.")
    print("Comment in the example you want to try.\n")

    # asyncio.run(stdio_example())
    # asyncio.run(sse_example())
    # asyncio.run(http_example())
    # asyncio.run(shorthand_example())
    # asyncio.run(approval_gate_example())
    # asyncio.run(config_example())

    print("See each function's docstring for details.")
