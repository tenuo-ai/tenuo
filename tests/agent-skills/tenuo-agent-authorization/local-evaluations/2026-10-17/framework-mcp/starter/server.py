"""stdio refund server; amount_cents is USD cents."""
import os
from pathlib import Path
from fastmcp import FastMCP
server = FastMCP("refunds")

@server.tool()
def refund_order(order_id: str, amount_cents: int) -> str:
    """Refund an order; amount_cents is USD cents."""
    with Path(os.environ["REFUND_JOURNAL"]).open("a") as f:
        f.write(f"{order_id}:{amount_cents}\n")
    return "refunded"

if __name__ == "__main__":
    server.run(show_banner=False)
