"""Enforced email delivery to a loopback SMTP sink.

Reserve before sending. Ambiguous failures require reconciliation, never an
automatic resend: SMTP and SQLite cannot commit atomically. This intentionally
trades automatic recovery for preventing duplicate sends from agent retries.
"""

import asyncio
import json
import os
import smtplib
import sqlite3
from email.message import EmailMessage

from fastmcp import FastMCP
from tenuo import Authorizer, PublicKey
from tenuo.mcp import MCPVerifier, TenuoMiddleware


def main():
    path = os.environ["OAUTH_DEMO_LEDGER"]
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS deliveries (operation TEXT PRIMARY KEY, payload TEXT, status TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS calls (operation TEXT)")
    verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=[PublicKey.from_bytes(bytes.fromhex(os.environ["OAUTH_DEMO_ROOT"]))]),
        require_warrant=True,
    )
    app = FastMCP("oauth-mail", middleware=[TenuoMiddleware(verifier)])

    @app.tool()
    def send_email(operation_id: str, recipient: str, subject: str, body: str, attachment: str) -> str:
        """Deliver exactly the approved message; unresolved sends need operator reconciliation."""
        with sqlite3.connect(path, timeout=5) as db:
            db.execute("INSERT INTO calls VALUES (?)", (operation_id,))
        if attachment:
            raise ValueError("Attachments are unsupported")
        message = EmailMessage()
        message["From"] = "support@example.test"
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)
        payload = json.dumps([recipient, subject, body, attachment])
        with sqlite3.connect(path, timeout=5) as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT payload, status FROM deliveries WHERE operation=?", (operation_id,)
            ).fetchone()
            if previous:
                if previous[0] != payload:
                    raise ValueError("Operation arguments changed")
                return previous[1]
            db.execute("INSERT INTO deliveries VALUES (?, ?, 'pending')", (operation_id, payload))
        # A crash or lost acknowledgement leaves pending, which is never resent automatically.
        with smtplib.SMTP("127.0.0.1", int(os.environ["OAUTH_DEMO_SMTP_PORT"]), timeout=5) as smtp:
            smtp.send_message(message, from_addr="support@example.test", to_addrs=[recipient])
        with sqlite3.connect(path) as db:
            db.execute("UPDATE deliveries SET status='sent' WHERE operation=?", (operation_id,))
        return "sent"

    asyncio.run(app.run_stdio_async(show_banner=False, log_level="CRITICAL"))


if __name__ == "__main__":
    main()
