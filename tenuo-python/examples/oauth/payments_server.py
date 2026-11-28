"""Separate MCP process: enforced refunds with atomic business idempotency.

The SQLite ledger simulates the upstream payment service, not a real processor.
No OAuth credentials or issuer signing keys are present in this process.
"""

import asyncio
import os
import sqlite3

from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware


def main():
    path = os.environ["OAUTH_DEMO_LEDGER"]
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS refunds (operation TEXT PRIMARY KEY, payment TEXT, currency TEXT, amount INTEGER)"
        )
        db.execute("CREATE TABLE IF NOT EXISTS calls (operation TEXT)")
    verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(os.environ["OAUTH_DEMO_ROOT"]))]),
        require_warrant=True,
    )
    app = FastMCP("oauth-refunds", middleware=[TenuoMiddleware(verifier)])

    @app.tool()
    def refund(operation_id: str, payment_id: str, currency: str, amount_cents: int) -> str:
        """Refund a payment once per approved operation, rejecting conflicting retries."""
        with sqlite3.connect(path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO calls VALUES (?)", (operation_id,))
            previous = db.execute(
                "SELECT payment, currency, amount FROM refunds WHERE operation = ?", (operation_id,)
            ).fetchone()
            if previous is not None:
                if previous != (payment_id, currency, amount_cents):
                    raise ValueError("Operation already completed with different arguments")
                return "already completed"
            db.execute("INSERT INTO refunds VALUES (?, ?, ?, ?)", (operation_id, payment_id, currency, amount_cents))
        return "refunded"

    asyncio.run(app.run_stdio_async(show_banner=False, log_level="CRITICAL"))


if __name__ == "__main__":
    main()
