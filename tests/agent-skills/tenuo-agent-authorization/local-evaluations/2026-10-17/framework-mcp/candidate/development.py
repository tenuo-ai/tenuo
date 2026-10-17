"""Explicit DEVELOPMENT issuer/holder loop; never a production issuer.

Run: .venv/bin/python development.py /tmp/refund-demo-journal
The launcher can replace these ephemeral roots. Production issuance and server
ownership must move outside the agent trust boundary.
"""
import asyncio
import json
import sys
import time
from pathlib import Path

from tenuo import Exact, Range, SigningKey, Warrant
from tenuo_core import sign_meta
from client import call_refund, result_is_error


def issue_task(issuer, holder):
    return Warrant.issue(
        issuer,
        capabilities={"refund_order": {
            "order_id": Exact("123"), "amount_cents": Range(min=1, max=50_000),
        }},
        ttl_seconds=300, holder=holder.public_key,
    )


def presentation(warrant, holder, order_id, amount_cents):
    return {"tenuo": sign_meta(
        [warrant], holder, "refund_order",
        json.dumps({"order_id": order_id, "amount_cents": amount_cents}),
        int(time.time()),
    )}


async def demonstrate(journal):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = issue_task(issuer, holder)
    root = issuer.public_key.to_bytes().hex()
    print("Task warrant: refund(order=123, 1<=amount_cents<=50000), TTL=300s")
    for amount in (20_000, 490_000):
        before = journal.read_text().splitlines() if journal.exists() else []
        result = await call_refund(
            journal, "123", amount, presentation(warrant, holder, "123", amount),
            trusted_root=root,
        )
        after = journal.read_text().splitlines() if journal.exists() else []
        print(f"refund(order=123, amount_cents={amount}): "
              f"{'DENIED' if result_is_error(result) else 'ALLOWED'}, effects={len(after)-len(before)}")


if __name__ == "__main__":
    asyncio.run(demonstrate(Path(sys.argv[1])))
