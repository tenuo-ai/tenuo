"""Caller-side proof creation; execute in the holder's security boundary."""
import time
from tenuo import SigningKey, Warrant
from .client import CAPABILITY, Presentation, transfer_arguments


def present_transfer(
    chain: tuple[bytes, ...], holder_key: SigningKey, recipient: str, amount: int,
) -> Presentation:
    args = transfer_arguments(recipient, amount)
    leaf = Warrant.from_bytes(chain[-1])
    return Presentation(chain, leaf.sign(holder_key, CAPABILITY, args, int(time.time())))
