# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2"]
# ///
"""Run: uv run --no-project tenuo-python/examples/task_authority.py

No model key, Cloud account or real payment. A scripted bad call models an
already-fooled model. Ephemeral, co-located keys make this a development demo.
"""

import time

from tenuo import Authorizer, Exact, Range, SigningKey, Warrant


class PaymentService:
    """Effect owner receives public authority only, never a caller signing key."""

    def __init__(self, trusted_root):
        self._verifier = Authorizer(trusted_roots=[trusted_root], clock_tolerance_secs=0)
        self._payments = []

    @property
    def effect_count(self):
        return len(self._payments)

    def pay_invoice(self, args, chain, proof):
        # Verify the same lossless argument values that reach the payment body.
        if type(args) is not dict:
            raise ValueError("Expected a payment argument object")
        checked = dict(args)
        if set(checked) != {"invoice_id", "bank_account", "amount_cents"}:
            raise ValueError("Unexpected payment arguments")
        if (type(checked["invoice_id"]) is not str or type(checked["bank_account"]) is not str
                or type(checked["amount_cents"]) is not int
                or not 1 <= checked["amount_cents"] <= 2**53 - 1):
            raise ValueError("Expected exact identifiers and positive integer cents")
        self._verifier.check_chain(
            [Warrant.from_base64(token) for token in chain],
            "pay_invoice", checked, signature=proof,
        )
        self._payments.append(checked)  # Only fake payment effect; after verification.
        return "paid"


def task_authority():
    # These values stand for trusted invoice/vendor records, never an invoice's
    # free-text instructions or a model-generated plan.
    issuer, coordinator, worker = [SigningKey.generate() for _ in range(3)]
    scope = {"invoice_id": Exact("INV-123"), "bank_account": Exact("verified-bank"),
             "amount_cents": Range(min=1, max=50_000)}
    parent = (Warrant.mint_builder().holder(coordinator.public_key)
              .capability("pay_invoice", **scope).ttl(300).mint(issuer))
    child = (parent.grant_builder().holder(worker.public_key)
             .capability("pay_invoice", **{**scope, "amount_cents": Range(min=1, max=25_000)})
             .ttl(60).terminal().grant(coordinator))
    # The worker gets public parent bytes and its own key, not the coordinator key.
    return issuer.public_key, (parent.to_base64(), child.to_base64()), worker


def main():
    root, chain, worker = task_authority()
    service = PaymentService(root)
    leaf = Warrant.from_base64(chain[-1])
    print("Task: pay INV-123 to verified-bank. Parent <= $500; specialist <= $250, 60s.")
    normal = {"invoice_id": "INV-123", "bank_account": "verified-bank", "amount_cents": 20_000}
    cases = [
        ("Chosen payment: $200 to verified-bank", normal, True),
        ("Injected bank change: $200 to attacker-bank", {**normal, "bank_account": "attacker-bank"}, False),
        ("Worker tries $400 (parent allows it; child does not)", {**normal, "amount_cents": 40_000}, False),
        ("Worker tries a different invoice", {**normal, "invoice_id": "INV-999"}, False),
    ]
    for label, args, allowed in cases:
        # Deliberately sign the bad calls too: rejection must occur at the service.
        proof = leaf.sign(worker, "pay_invoice", args, int(time.time()))
        before = service.effect_count
        try:
            service.pay_invoice(args, chain, proof)
        except Exception as exc:
            # Unrelated setup/type errors are not evidence of constraint enforcement.
            if allowed or "constraint" not in str(exc).lower():
                raise
            assert service.effect_count == before
            print(f"DENIED  {label} -> payment effects=0")
        else:
            assert allowed, "Out-of-task payment executed"
            assert service.effect_count == before + 1
            print(f"ALLOWED {label} -> payment effects=1")
    print("Development demo: per-call limits; no total-budget, replay or idempotency guarantee.")


if __name__ == "__main__":
    main()
