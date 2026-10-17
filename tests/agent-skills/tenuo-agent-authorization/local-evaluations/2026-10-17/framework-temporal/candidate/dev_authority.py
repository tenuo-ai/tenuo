"""Local demonstration issuer/caller. Never used by the effect verifier to sign.

Ephemeral keys make this a development loop, not deployment key management.
"""
import time
from tenuo import Exact, Range, SigningKey, Warrant

_issuer = SigningKey.generate()
_holder = SigningKey.generate()
TRUSTED_ROOT = _issuer.public_key


def issue_refund_authority():
    return (Warrant.mint_builder().holder(_holder.public_key)
            .capability("refund_order", order_id=Exact("123"),
                        amount_cents=Range(min=1, max=50000))
            .ttl(60).mint(_issuer))


def presentation(warrant, order_id, amount_cents, *, holder=None, parents=()):
    """Caller signs before starting a workflow; only public data enters history."""
    args = {"order_id": order_id, "amount_cents": amount_cents}
    proof = warrant.sign(holder or _holder, "refund_order", args, int(time.time()))
    return {"chain": [w.to_base64() for w in [*parents, warrant]],
            "proof": bytes(proof).hex()}


def authorize_refund(order_id, amount_cents):
    return presentation(issue_refund_authority(), order_id, amount_cents)
