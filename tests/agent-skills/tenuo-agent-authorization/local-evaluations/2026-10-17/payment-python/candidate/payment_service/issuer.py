"""Issuer-side API; deploy separately from both caller and payment verifier."""
from tenuo import Exact, PublicKey, Range, SigningKey, Warrant
from .client import CAPABILITY, transfer_arguments


def issue_transfer_authority(
    issuer_key: SigningKey, holder: PublicKey, *, recipient: str,
    max_amount: int, ttl_seconds: int = 60,
) -> tuple[bytes, ...]:
    transfer_arguments(recipient, max_amount)
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
        raise ValueError("TTL must be 1..300 seconds")
    # The root stays with the issuer. The caller receives a terminal leaf and
    # public parent chain; only configured issuer roots establish trust.
    root = (Warrant.mint_builder()
            .capability(CAPABILITY, recipient=Exact(recipient), amount=Range(1, max_amount))
            .holder(issuer_key.public_key).ttl(ttl_seconds).mint(issuer_key))
    builder = root.attenuate_builder()
    builder.with_tool(CAPABILITY)
    builder.with_holder(holder)
    builder.with_ttl(ttl_seconds)
    builder.terminal()
    leaf = builder.delegate(issuer_key)
    return (root.to_bytes(), leaf.to_bytes())
