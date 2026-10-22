#!/usr/bin/env python3
"""
A stdio FastMCP server with no Tenuo code, for ``tenuo.mcp.wrap`` tests.

Each ``comment`` call appends a line to the file named by ``WRAP_TEST_LOG``,
so tests can count which calls actually ran.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

mcp = FastMCP("wrap-test")

if os.environ.get("WRAP_TEST_OWN_GUARD"):
    # A server that already guards itself, permissively, with roots of its own.
    from tenuo import SigningKey
    from tenuo.mcp import MCPVerifier
    from tenuo.mcp.fastmcp_middleware import TenuoMiddleware
    from tenuo_core import Authorizer

    own = MCPVerifier(authorizer=Authorizer(trusted_roots=[SigningKey.generate().public_key]), require_warrant=False)
    mcp.add_middleware(TenuoMiddleware(own))


@mcp.tool()
async def comment(issue_key: str, body: str) -> str:
    with open(os.environ["WRAP_TEST_LOG"], "a") as f:
        f.write(f"{issue_key} {body}\n")
    return "posted"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
