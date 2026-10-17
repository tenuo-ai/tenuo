"""Receiving-boundary tests. Every effect is an isolated in-memory fake."""
import importlib
import time

import pytest
from tenuo import Exact, Range, SigningKey, Warrant

from payment_service import (
    AuthorizationDenied, PaymentClient, Presentation, execute_transfer,
    issue_transfer_authority, present_transfer,
)
from payment_service.client import CAPABILITY


@pytest.fixture
def setup():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    service = PaymentClient(issuer.public_key)
    chain = issue_transfer_authority(
        issuer, holder.public_key, recipient="merchant", max_amount=500
    )
    return issuer, holder, service, chain


def denied(service, action, reason=None):
    with pytest.raises(AuthorizationDenied) as caught:
        action()
    assert service.calls == []
    if reason:
        assert caught.value.__cause__ is not None
        assert reason.lower() in str(caught.value.__cause__).lower()


def test_allowed_application_flow(setup):
    _, holder, service, chain = setup
    proof = present_transfer(chain, holder, "merchant", 200)
    assert execute_transfer("merchant", 200, authority=proof, service=service) == {
        "recipient": "merchant", "amount": 200, "status": "sent"
    }
    assert service.calls == [("merchant", 200)]
    assert Warrant.from_bytes(chain[-1]).is_terminal()
    print("Allowed payment.transfer(recipient=merchant, amount=200, ceiling=500): effects=1")


def test_missing_authority(setup):
    _, _, service, _ = setup
    denied(service, lambda: service.transfer("merchant", 200))


def test_untrusted_issuer(setup):
    _, holder, service, _ = setup
    chain = issue_transfer_authority(SigningKey.generate(), holder.public_key,
                                    recipient="merchant", max_amount=500)
    denied(service, lambda: service.transfer("merchant", 200,
           authority=present_transfer(chain, holder, "merchant", 200)), "not trusted")


def test_wrong_holder(setup):
    _, _, service, chain = setup
    # Sign a mathematically valid proof with an unrelated holder key.
    proof = present_transfer(chain, SigningKey.generate(), "merchant", 200)
    denied(service, lambda: service.transfer("merchant", 200, authority=proof), "proof")


def test_expiry(setup):
    issuer, holder, service, _ = setup
    chain = issue_transfer_authority(issuer, holder.public_key, recipient="merchant",
                                    max_amount=500, ttl_seconds=1)
    proof = present_transfer(chain, holder, "merchant", 200)
    time.sleep(2.05)
    denied(service, lambda: service.transfer("merchant", 200, authority=proof), "expired")


def test_wrong_capability(setup):
    issuer, holder, service, _ = setup
    warrant = (Warrant.mint_builder().capability("payment.refund", recipient=Exact("merchant"),
               amount=Range(1, 500)).holder(holder.public_key).ttl(60).mint(issuer))
    chain = (warrant.to_bytes(),)
    denied(service, lambda: service.transfer("merchant", 200,
           authority=present_transfer(chain, holder, "merchant", 200)), "payment.transfer")


@pytest.mark.parametrize("recipient,amount,reason", [
    ("attacker", 200, "recipient"), ("merchant", 501, "amount"),
])
def test_argument_denial(setup, recipient, amount, reason):
    _, holder, service, chain = setup
    proof = present_transfer(chain, holder, recipient, amount)
    denied(service, lambda: service.transfer(recipient, amount, authority=proof), reason)


def delegated_fixture():
    issuer, holder, worker = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    root = (Warrant.mint_builder().capability(CAPABILITY, recipient=Exact("merchant"),
            amount=Range(1, 500)).holder(holder.public_key).ttl(120).mint(issuer))
    builder = root.attenuate_builder()
    builder.with_capability(CAPABILITY,
                            {"recipient": Exact("merchant"), "amount": Range(1, 250)})
    builder.with_holder(worker.public_key)
    builder.with_ttl(60)
    builder.terminal()
    child = builder.delegate(holder)
    return issuer, holder, worker, root, child


def test_narrower_child_root_only_trust():
    issuer, _, worker, root, child = delegated_fixture()
    service = PaymentClient(issuer.public_key)
    chain = (root.to_bytes(), child.to_bytes())
    service.transfer("merchant", 200, authority=present_transfer(chain, worker, "merchant", 200))
    assert service.calls == [("merchant", 200)]


def test_missing_parent_chain():
    issuer, _, worker, _, child = delegated_fixture()
    service = PaymentClient(issuer.public_key)
    chain = (child.to_bytes(),)
    denied(service, lambda: service.transfer("merchant", 200,
           authority=present_transfer(chain, worker, "merchant", 200)), "not trusted")


def test_wider_child_rejected_at_receiving_boundary():
    issuer, holder, worker, root, child = delegated_fixture()
    # Adversarial wire fixture: keep linkage, holder, TTL, and depth unchanged,
    # change only amount max 250 -> 1000, and correctly re-sign as the delegator.
    # Released native wire format: [1, payload_bytes, [1, signature_bytes]].
    # Domain below was confirmed against the installed native implementation
    # by reproducing an existing warrant signature with SigningKey.sign_raw.
    payload = child.payload_bytes
    old = b"cmax\xf9\x5b\xd0"  # CBOR text 'max', float16 250
    new = b"cmax\xf9\x63\xd0"  # float16 1000; same wire length
    assert payload.count(old) == 1
    widened = payload.replace(old, new)
    wire = child.to_bytes()
    assert wire.count(payload) == 1
    assert holder.sign_raw(b"tenuo-warrant-v1\x01" + payload) == wire[-64:]
    forged_wire = wire.replace(payload, widened)
    forged_wire = forged_wire[:-64] + holder.sign_raw(b"tenuo-warrant-v1\x01" + widened)
    forged = Warrant.from_bytes(forged_wire)
    forged.verify(holder.public_key_bytes())  # Not a malformed signature fixture.
    assert forged.capabilities[CAPABILITY]["amount"].max == 1000
    service = PaymentClient(issuer.public_key)
    chain = (root.to_bytes(), forged.to_bytes())
    # The concrete call still satisfies both envelopes. Denial must be because
    # the child envelope widened, rather than the concrete call being denied.
    proof = present_transfer(chain, worker, "merchant", 200)
    denied(service, lambda: service.transfer("merchant", 200, authority=proof), "range expanded")


def test_original_module_routes_cannot_bypass(setup):
    _, _, configured, _ = setup
    original = importlib.import_module("payment_service.client")
    raw = original.PaymentClient()
    denied(raw, lambda: raw.transfer("merchant", 200))
    denied(original.client, lambda: original.client.transfer("merchant", 200))
    denied(original.client, lambda: original.execute_transfer("merchant", 200))
    denied(configured, lambda: configured.transfer("merchant", 200))


def test_malformed_and_tampered_proof(setup):
    _, holder, service, chain = setup
    denied(service, lambda: service.transfer("merchant", 200,
           authority=Presentation((b"garbage",), bytes(64))))
    valid = present_transfer(chain, holder, "merchant", 200)
    denied(service, lambda: service.transfer("merchant", 201, authority=valid), "proof")


@pytest.mark.parametrize("amount", [True, 1.0, "200", 0, -1, 2**53])
def test_lossy_or_invalid_amount_denied(setup, amount):
    _, _, service, _ = setup
    denied(service, lambda: service.transfer("merchant", amount))
