"""Shared task and proof plumbing; see ../task_authority.py for the effect owner."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from task_authority import PaymentService, task_authority
from tenuo import Warrant
from tenuo.exceptions import ConstraintViolation


class TransportedConstraintDenial(Exception):
    """A typed receiver constraint denial carried through a framework."""


NORMAL = {"invoice_id": "INV-123", "bank_account": "verified-bank", "amount_cents": 20_000}
CASES = [
    ("worker chooses $200 payment", NORMAL, True),
    ("fooled model changes destination", {**NORMAL, "bank_account": "attacker-bank"}, False),
    ("worker spends $400 of parent’s $500", {**NORMAL, "amount_cents": 40_000}, False),
    ("worker selects another invoice", {**NORMAL, "invoice_id": "INV-999"}, False),
]


class Task:
    def __init__(self):
        self.root, self.chain, self.worker = task_authority()
        self.service = PaymentService(self.root)

    def proof(self, args):
        return Warrant.from_base64(self.chain[-1]).sign(
            self.worker, "pay_invoice", args, int(time.time()))

    def pay(self, args):
        # Caller proof is generated even for malicious arguments, then the
        # effect owner independently verifies the complete root-first chain.
        return self.service.pay_invoice(args, self.chain, self.proof(args))


async def demonstrate(dispatch, effect_count):
    print("Task: INV-123 → verified-bank. Parent <= $500; worker <= $250, 60s.")
    for label, args, allowed in CASES:
        before = effect_count()
        try:
            await dispatch(args)
        except Exception as exc:
            cause = exc
            while cause.__cause__ is not None and not isinstance(cause, (ConstraintViolation, TransportedConstraintDenial)):
                cause = cause.__cause__
            if allowed or not isinstance(cause, (ConstraintViolation, TransportedConstraintDenial)):
                raise  # Startup/dispatch errors are never successful denials.
            assert effect_count() == before, "Denied effect executed"
            print(f"DENIED  {label}: effects=0")
        else:
            assert allowed, "Out-of-task effect executed"
            assert effect_count() == before + 1
            print(f"ALLOWED {label}: effects=1")
    print("Development only: per-call limits, not total-budget or replay protection.")
