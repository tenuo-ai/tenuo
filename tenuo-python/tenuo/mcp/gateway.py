"""
Put Tenuo in front of an MCP server you can't (or don't want to) change.

The gateway is an MCP proxy: clients connect to it, it forwards to the upstream
server, and tool names and schemas pass through unchanged. Every ``tools/call``
is verified by :class:`~tenuo.mcp.fastmcp_middleware.TenuoMiddleware` before it
is forwarded: the warrant chain must end at a trusted root, the caller must
prove it holds the leaf warrant, and the arguments must satisfy its
constraints. Nothing about the upstream is configured beyond its address, so
the same gateway fronts any server.

The gateway trusts roots, not agents. An agent's attenuated child warrants
verify because their chain ends at the root and can only narrow.

With ``receipts`` set, every decision made over presented authority (allowed
or refused) is signed with the gateway's own key and appended to a JSONL file
that ``tenuo receipt chain`` verifies. Calls with no warrant at all are
refused without a receipt, as everywhere in Tenuo.

Keep the upstream reachable only through the gateway (a private network or
loopback); otherwise callers can skip it.

Example::

    gateway = create_gateway(
        "http://grafana-mcp:8000/mcp",
        trusted_roots=[root_public_key],
        identity=HolderIdentity.load_or_create("gateway.key"),
        receipts="receipts.jsonl",
    )
    gateway.run(transport="http", host="0.0.0.0", port=8080, path="/mcp")

Or from the command line::

    tenuo mcp gateway http://grafana-mcp:8000/mcp --root <hex> \\
        --key gateway.key --receipts receipts.jsonl --listen 0.0.0.0:8080
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from tenuo import Authorizer, PublicKey
from tenuo.identity import HolderIdentity
from tenuo.receipts import FileReceiptSink, deliver
from tenuo.runtime import Runtime

from .fastmcp_middleware import TenuoMiddleware
from .server import MCPVerifier

try:
    from fastmcp.server import create_proxy
except ImportError as exc:  # pragma: no cover - fastmcp_middleware raises first
    raise ImportError('tenuo.mcp.gateway requires FastMCP. Install with: pip install "tenuo[fastmcp]".') from exc

__all__ = ["create_gateway"]

logger = logging.getLogger(__name__)


class _ReceiptFileMiddleware(TenuoMiddleware):
    """``TenuoMiddleware`` that moves each call's signed receipts to a file.

    The Runtime signs receipts into an in-memory outbox; this hands them to the
    sink after every call and acknowledges only what the sink accepted, so a
    failed write is retried with the next call instead of lost.
    """

    def __init__(self, verifier: MCPVerifier, runtime: Runtime, sink: FileReceiptSink) -> None:
        super().__init__(verifier)
        self._runtime = runtime
        self._sink = sink

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        try:
            return await super().on_call_tool(context, call_next)
        finally:
            batch = self._runtime.drain_receipts()
            stored = 0
            for receipt in batch:
                if not deliver(self._sink, receipt):
                    break
                stored += 1
            self._runtime.acknowledge_receipts(stored)


def create_gateway(
    upstream: Any,
    *,
    trusted_roots: Sequence[PublicKey],
    identity: Optional[HolderIdentity] = None,
    receipts: Union[str, Path, None] = None,
    config: Any = None,
    name: str = "tenuo-gateway",
) -> Any:
    """Return a FastMCP server that verifies every tool call, then forwards it to ``upstream``.

    Args:
        upstream: Anything FastMCP's ``create_proxy`` accepts: an MCP URL, a
            ``FastMCP`` instance, a client transport, or an ``mcpServers`` config.
        trusted_roots: Root public keys a warrant chain must end at.
        identity: The gateway's own key, used to sign receipts. Required with
            ``receipts``; use :meth:`HolderIdentity.load_or_create` so receipts
            keep one signer across restarts.
        receipts: Path of the JSONL file signed receipts are appended to.
        config: Optional ``CompiledMcpConfig`` mapping argument fields to
            constraint names (see :class:`MCPVerifier`).
        name: Server name shown to clients.
    """
    roots = list(trusted_roots)
    if not roots:
        raise ValueError("create_gateway needs at least one trusted root")
    if receipts is not None and identity is None:
        raise ValueError("receipts need the gateway's identity to sign them")

    runtime = None
    if receipts is not None:
        runtime = Runtime(identity, roots, receipts="collect")
    verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=roots),
        config=config,
        runtime=runtime,
        control_plane=False,
    )
    if runtime is not None:
        middleware: TenuoMiddleware = _ReceiptFileMiddleware(verifier, runtime, FileReceiptSink(receipts))
    else:
        middleware = TenuoMiddleware(verifier)

    gateway = create_proxy(upstream, name=name)
    gateway.add_middleware(middleware)
    return gateway
