"""Fake effect owner. Receives only public warrant transport and holder proof."""
from dataclasses import dataclass

from tenuo import Authorizer, Warrant


class RefundDenied(ValueError):
    pass


@dataclass(frozen=True)
class Presentation:
    chain: tuple[str, ...]  # root first, terminal leaf last
    proof: bytes


class RefundService:
    def __init__(self, trusted_roots, effects):
        self._authorizer = Authorizer(trusted_roots=trusted_roots, clock_tolerance_secs=0)
        self._effects = effects

    def refund_order(self, order_id, amount_cents, presentation=None):
        # Strict lossless domain: no bools, float truncation, string coercion, or
        # integers that cannot be exactly represented by the constraint engine.
        if type(order_id) is not str or type(amount_cents) is not int:
            raise RefundDenied("invalid argument types")
        if order_id != "123" or not 1 <= amount_cents <= 50000:
            raise RefundDenied("outside refund policy")
        if not isinstance(presentation, Presentation) or not presentation.chain:
            raise RefundDenied("missing authority")
        args = {"order_id": order_id, "amount_cents": amount_cents}
        try:
            chain = [Warrant.from_base64(token) for token in presentation.chain]
            self._authorizer.check_chain(chain, "refund_order", args, presentation.proof)
            if not chain[-1].is_terminal():
                raise RefundDenied("terminal authority required")
        except RefundDenied:
            raise
        except Exception as exc:
            raise RefundDenied(f"authority rejected: {exc}") from exc
        self._effects.append((args["order_id"], args["amount_cents"]))
        return "refunded"
