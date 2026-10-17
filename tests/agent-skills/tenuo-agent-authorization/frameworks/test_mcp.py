"""Real tools/call _meta transport to a server with a durable effect journal.

Run separately with MCP 1/FastMCP 3 and MCP 2 (native MCPServer).
No client authorization wrapper can intercept the negative test cases.
"""

import base64
import os
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from tenuo import Range, SigningKey, Warrant
from tenuo.mcp._compat import call_tool_result_is_error
from tenuo_core import encode_warrant_stack


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "allow",
        "constraint",
        "missing",
        "wrong-holder",
        "untrusted-root",
        "delegated",
        "missing-chain",
    ],
)
async def test_wire_call(case, tmp_path):
    issuer, holder, worker, other = [SigningKey.generate() for _ in range(4)]
    root = (
        Warrant.mint_builder()
        .holder(holder.public_key)
        .capability("refund", amount=Range(max=500))
        .ttl(300)
        .mint(other if case == "untrusted-root" else issuer)
    )
    leaf, key, token = root, holder, root.to_base64()
    if case in ("delegated", "missing-chain"):
        leaf = (
            root.grant_builder()
            .holder(worker.public_key)
            .capability("refund", amount=Range(max=300))
            .ttl(120)
            .grant(holder)
        )
        key = worker
        token = (
            encode_warrant_stack([root, leaf])
            if case == "delegated"
            else leaf.to_base64()
        )
    amount = 4900 if case == "constraint" else 200
    args = {"amount": amount}
    # Low-level signing deliberately permits a bad-holder presentation to reach server.
    pop = leaf.sign(
        other if case == "wrong-holder" else key, "refund", args, int(time.time())
    )
    meta = (
        None
        if case == "missing"
        else {
            "tenuo": {
                "warrant": token,
                "signature": base64.b64encode(bytes(pop)).decode(),
            }
        }
    )
    journal = tmp_path / "effects"
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("mcp_effect_server.py"))],
        env={
            **os.environ,
            "TENUO_TEST_ROOT": issuer.public_key.to_bytes().hex(),
            "TENUO_TEST_JOURNAL": str(journal),
        },
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        result = await session.call_tool("refund", args, meta=meta)
    allowed = case in ("allow", "delegated")
    assert call_tool_result_is_error(result) is not allowed
    assert (journal.read_text().splitlines() if journal.exists() else []) == (
        ["200"] if allowed else []
    )
    if not allowed:
        # A schema/startup error is not a successful authorization denial.
        from tenuo.mcp._compat import call_tool_result_structured_content

        assert "tenuo" in call_tool_result_structured_content(result)
