"""Receiving effect-boundary verification. Holds public roots, never signing keys."""
from tenuo import Authorizer, Warrant
from temporalio.exceptions import ApplicationError


class RefundVerifier:
    def __init__(self, trusted_roots):
        self._authorizer = Authorizer(trusted_roots=list(trusted_roots),
                                      clock_tolerance_secs=0)

    def verify(self, order_id, amount_cents, authority):
        try:
            # No coercion: cents must be represented identically in auth and effect.
            if type(order_id) is not str or type(amount_cents) is not int:
                raise ValueError("order must be a string and cents an integer")
            if order_id != "123" or not 1 <= amount_cents <= 50000:
                raise ValueError("local refund ceiling exceeded")
            if type(authority) is not dict or set(authority) != {"chain", "proof"}:
                raise ValueError("missing or malformed authority")
            if type(authority["chain"]) is not list or not 1 <= len(authority["chain"]) <= 8:
                raise ValueError("invalid chain length")
            chain = [Warrant.from_base64(w) for w in authority["chain"]]
            proof = bytes.fromhex(authority["proof"])
            args = {"order_id": order_id, "amount_cents": amount_cents}
            self._authorizer.check_chain(chain, "refund_order", args, signature=proof)
            return args
        except Exception as exc:
            raise ApplicationError("refund authorization denied", str(exc),
                                   type="RefundAuthorizationDenied", non_retryable=True) from exc
