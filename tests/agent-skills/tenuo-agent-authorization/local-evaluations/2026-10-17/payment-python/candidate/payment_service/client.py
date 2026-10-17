"""Fail-closed payment boundary. This example owns only an isolated fake effect."""
from dataclasses import dataclass, field
from typing import Any

from tenuo import Authorizer, PublicKey, Warrant

CAPABILITY = "payment.transfer"
MAX_AMOUNT = 2**53 - 1  # All accepted integers are exact in the core's numeric view.


class AuthorizationDenied(PermissionError):
    """The payment effect was not invoked."""


@dataclass(frozen=True)
class Presentation:
    """Public transport data, ordered root to leaf. Never contains signing keys."""

    chain: tuple[bytes, ...] = field(repr=False)
    signature: bytes = field(repr=False)


def transfer_arguments(recipient: str, amount: int) -> dict[str, Any]:
    if type(recipient) is not str or not recipient or len(recipient) > 200:
        raise AuthorizationDenied("invalid recipient")
    if type(amount) is not int or not 1 <= amount <= MAX_AMOUNT:
        raise AuthorizationDenied("invalid amount")
    return {"recipient": recipient, "amount": amount}


class PaymentClient:
    """Construct in trusted service startup with the configured issuer PUBLIC key.

    Construction is configuration, never a request operation. No private key is
    accepted. Run this component outside an untrusted caller's mutable process
    before connecting a real payment adapter.
    """

    def __init__(self, trusted_issuer: PublicKey | None = None) -> None:
        self.__authorizer = (
            Authorizer(trusted_roots=[trusted_issuer], clock_tolerance_secs=0)
            if trusted_issuer is not None else None
        )
        self.__calls: list[tuple[str, int]] = []

    @property
    def calls(self) -> list[tuple[str, int]]:
        return list(self.__calls)

    def transfer(
        self, recipient: str, amount: int, *, authority: Presentation | None = None
    ) -> dict[str, Any]:
        args = transfer_arguments(recipient, amount)
        if self.__authorizer is None:
            raise AuthorizationDenied("verifier is not configured")
        if not isinstance(authority, Presentation):
            raise AuthorizationDenied("authority required")
        if (type(authority.chain) is not tuple or not 1 <= len(authority.chain) <= 8
                or any(type(item) is not bytes or len(item) > 65536 for item in authority.chain)
                or type(authority.signature) is not bytes or len(authority.signature) != 64):
            raise AuthorizationDenied("malformed presentation")
        try:
            chain = [Warrant.from_bytes(item) for item in authority.chain]
            self.__authorizer.check_chain(chain, CAPABILITY, args, authority.signature)
        except Exception as exc:
            # Generic public error; the cause is available to protected diagnostics.
            raise AuthorizationDenied("authorization rejected") from exc
        # The only effecting path consumes the exact values checked above.
        self.__calls.append((args["recipient"], args["amount"]))
        return {**args, "status": "sent"}


# Old imports remain usable, but never silently acquire issuer trust.
client = PaymentClient()


def execute_transfer(
    recipient: str, amount: int, *, authority: Presentation | None = None,
    service: PaymentClient = client,
) -> dict[str, Any]:
    return service.transfer(recipient, amount, authority=authority)
