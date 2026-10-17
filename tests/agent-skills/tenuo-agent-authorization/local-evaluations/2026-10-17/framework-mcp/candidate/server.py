"""Local stdio refund boundary. The journal is the only effect; USD cents."""
import os
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_context
from pydantic import StrictInt, StrictStr
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier

server = FastMCP("refunds")
_verifier = None


def refund_order(order_id: StrictStr, amount_cents: StrictInt) -> str:
    """Refund order 123, from 1 to 50,000 USD cents, with caller authority."""
    # Check direct Python calls too, which bypass Pydantic validation.
    if type(order_id) is not str or type(amount_cents) is not int:
        raise ValueError("Refund arguments require an exact string and integer")
    if _verifier is None:
        raise RuntimeError("Refund verifier is not configured")
    # Actual wire request metadata on FastMCP 3 and 4. No signing key or
    # caller-selectable verification clock is accepted at this boundary.
    request = get_context().request_context
    if request is None:
        raise RuntimeError("Refund requires an active MCP request")
    clean = _verifier.verify_or_raise(
        "refund_order", {"order_id": order_id, "amount_cents": amount_cents},
        meta=request.meta,
    )
    if clean["order_id"] != "123" or not 1 <= clean["amount_cents"] <= 50_000:
        raise ValueError("Refund outside local policy: order 123, 1..50000 cents")
    with Path(os.environ["REFUND_JOURNAL"]).open("a") as journal:
        journal.write(f"{clean['order_id']}:{clean['amount_cents']}\n")
    return "refunded"


# Keep the original module callable, with enforcement inside its body.
server.tool()(refund_order)

if __name__ == "__main__":
    root = PublicKey.from_bytes(bytes.fromhex(os.environ["REFUND_TRUSTED_ROOT"]))
    _verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=[root]), require_warrant=True,
    )
    server.run(transport="stdio", show_banner=False)
