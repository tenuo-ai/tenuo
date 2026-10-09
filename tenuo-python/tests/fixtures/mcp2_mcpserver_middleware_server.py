#!/usr/bin/env python3
"""Stdio ``MCPServer`` (MCP SDK 2.x) guarded by :class:`TenuoServerMiddleware`.

Usage: ``python mcp2_mcpserver_middleware_server.py <root public key hex>``

Every tool is registered with ``authorization.tool(mcp)`` and an ordinary
signature. None of them declares ``_tenuo``; the middleware verifies the
envelope, from ``_meta`` or from the reserved argument, and strips it before
the SDK validates the arguments. The tool guard rejects changes after validation.
"""

from __future__ import annotations

import sys
from typing import Annotated

from pydantic import AfterValidator

try:
    from mcp.server.mcpserver import Context, MCPServer
except ImportError:  # pragma: no cover - exercised only without the SDK
    print("MCP SDK 2.x not installed.", file=sys.stderr)
    sys.exit(1)

from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier
from tenuo.mcp.mcpserver_middleware import TenuoServerMiddleware

root_hex = sys.argv[1]
verifier = MCPVerifier(
    authorizer=Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(root_hex))])
)
authorization = TenuoServerMiddleware(verifier)
mcp = MCPServer("guarded", middleware=[authorization])
refund_effects: list[int] = []


@authorization.tool(mcp)
def read_file(path: str) -> str:
    """Pretend to read a file."""
    return f"contents of {path}"


@authorization.tool(mcp)
def argument_keys(path: str, ctx: Context) -> str:
    """Report the argument keys the handler's request context still carries."""
    params = ctx.request_context.params or {}
    arguments = params.get("arguments") or {}
    meta = ctx.request_context.meta or {}
    return f"arguments={sorted(arguments)} meta={sorted(meta)}"


@authorization.tool(mcp)
def default_refund(amount: int, destination: str = "unapproved-account") -> str:
    refund_effects.append(amount)
    return destination


@authorization.tool(mcp)
def validated_refund(amount: Annotated[int, AfterValidator(lambda value: value * 100)]) -> str:
    refund_effects.append(amount)
    return "ran"


@authorization.tool(mcp)
def refund_effect_count(path: str) -> str:
    return str(len(refund_effects))


if __name__ == "__main__":
    mcp.run()
