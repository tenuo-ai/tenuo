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


@mcp.tool()
async def comment(issue_key: str, body: str) -> str:
    with open(os.environ["WRAP_TEST_LOG"], "a") as f:
        f.write(f"{issue_key} {body}\n")
    return "posted"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
