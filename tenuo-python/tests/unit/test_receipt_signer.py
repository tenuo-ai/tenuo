"""Local ReceiptSigner: no control-plane URL, file/memory sink."""

from __future__ import annotations

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo import Pattern
from tenuo._enforcement import enforce_tool_call
from tenuo.receipts import InMemoryReceiptSink, ReceiptSigner
from tenuo_core import SigningKey, Warrant


def test_receipt_signer_rejects_a_sign_callback():
    key = SigningKey.generate()
    with pytest.raises(NotImplementedError, match="KMS"):
        ReceiptSigner(key, InMemoryReceiptSink(), sign=lambda m: m)


def test_local_client_has_no_url_requirement():
    key = SigningKey.generate()
    inner = tenuo_core.ControlPlaneClient.local(key)
    assert isinstance(inner.receipt_signer_key, str)
    assert len(inner.receipt_signer_key) == 64
    inner.shutdown(0.0)


def test_receipt_signer_signs_a_denial_without_a_control_plane():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(issuer)
    )
    bound = warrant.bind(holder)
    result = enforce_tool_call(
        "read_file",
        {"path": "/etc/passwd"},
        bound,
        trusted_roots=[issuer.public_key],
    )
    assert not result.allowed

    sink = InMemoryReceiptSink()
    signer = ReceiptSigner(issuer, sink, authorizer=result.authorizer)
    signer.emit_for_enforcement(result)
    assert signer.flush()
    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])
    assert payload.outcome == "deny"
    assert payload.decision_code == "constraint-violation"
