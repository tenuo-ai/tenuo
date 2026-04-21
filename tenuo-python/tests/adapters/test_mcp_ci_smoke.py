"""Minimal end-to-end MCP smoke test for CI.

This test exercises a real subprocess MCP server over stdio, with
Tenuo warrant injection and server-side MCPVerifier middleware.

It intentionally covers three high-signal scenarios:
1) allowed call
2) denied call (constraint mismatch)
3) optional ``None`` arg does not crash auth paths
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

try:
    import fastmcp  # noqa: F401
except ImportError:
    pytestmark = pytest.mark.skip(reason="fastmcp not installed")
else:
    from tenuo import Capability, Pattern, SigningKey, configure, mint
    from tenuo.mcp import MCP_AVAILABLE, SecureMCPClient

    pytestmark = pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")


@pytest.mark.asyncio
async def test_mcp_end_to_end_smoke():
    server_code = """
from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware
import os

issuer_hex = os.environ["TENUO_ISSUER_PUBLIC_KEY"]
authorizer = Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(issuer_hex))])
verifier = MCPVerifier(authorizer=authorizer)
mcp = FastMCP("mcp-ci-smoke", middleware=[TenuoMiddleware(verifier)])

@mcp.tool()
async def read_file(path: str, max_size: int | None = None) -> str:
    with open(path) as f:
        return f.read(max_size if max_size is not None else 1024)

if __name__ == "__main__":
    mcp.run(transport="stdio")
"""

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as server_tmp:
        server_tmp.write(server_code)
        server_path = server_tmp.name

    test_file = Path("/tmp/tenuo_mcp_ci_smoke.txt")
    test_file.write_text("mcp smoke test content")

    issuer = SigningKey.generate()
    configure(issuer_key=issuer, dev_mode=True)
    env = {"TENUO_ISSUER_PUBLIC_KEY": bytes(issuer.public_key_bytes()).hex()}

    async with SecureMCPClient("python", [server_path], inject_warrant=True, env=env) as client:
        assert "read_file" in client.tools
        async with mint(Capability("read_file", path=Pattern("/tmp/*"))):
            # 1) allow
            ok = await client.call_tool(
                "read_file",
                {"path": str(test_file)},
                warrant_context=True,
                inject_warrant=True,
            )
            assert ok and "mcp smoke test content" in ok[0].text

            # 2) deny
            with pytest.raises(Exception):
                await client.call_tool(
                    "read_file",
                    {"path": "/etc/passwd"},
                    warrant_context=True,
                    inject_warrant=True,
                )

            # 3) None-valued optional arg should not crash
            none_ok = await client.call_tool(
                "read_file",
                {"path": str(test_file), "max_size": None},
                warrant_context=True,
                inject_warrant=True,
            )
            assert none_ok and "mcp smoke test content" in none_ok[0].text

