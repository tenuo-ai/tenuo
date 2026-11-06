"""Receiving-boundary coverage for the small, released-SDK onboarding demo."""

import importlib.util
import time
from pathlib import Path

import pytest
from tenuo import SigningKey, Warrant

path = Path(__file__).resolve().parents[2] / "examples/task_authority.py"
spec = importlib.util.spec_from_file_location("task_authority_quickstart", path)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


def test_visible_autonomy_demo(capsys):
    demo.main()  # Includes one real allow and three receiving-boundary denials.
    output = capsys.readouterr().out
    assert output.count("payment effects=1") == 1
    assert output.count("payment effects=0") == 3


@pytest.mark.parametrize("case", ["missing", "wrong-holder", "wrong-root", "missing-parent", "changed-args"])
def test_receiver_rejects_bad_transport_before_original_effect(case):
    root, chain, worker = demo.task_authority()
    service = demo.PaymentService(root)
    args = {"invoice_id": "INV-123", "bank_account": "verified-bank", "amount_cents": 20_000}
    if case == "wrong-root":
        _, chain, worker = demo.task_authority()
    leaf = Warrant.from_base64(chain[-1])
    key = SigningKey.generate() if case == "wrong-holder" else worker
    proof = leaf.sign(key, "pay_invoice", args, int(time.time()))
    if case == "missing":
        chain = ()
    if case == "missing-parent":
        chain = chain[-1:]
    if case == "changed-args":
        args = {**args, "amount_cents": 20_001}  # Still inside scope; only proof differs.
    reason = {"missing": "(?i)chain|warrant", "wrong-holder": "(?i)proof|signature",
              "wrong-root": "(?i)trust", "missing-parent": "(?i)trust",
              "changed-args": "(?i)proof|signature"}[case]
    with pytest.raises(Exception, match=reason):
        service.pay_invoice(args, chain, proof)
    assert service.effect_count == 0
    # A setup failure cannot explain every negative case: valid public transport works.
    root, valid_chain, worker = demo.task_authority()
    healthy = demo.PaymentService(root)
    proof = Warrant.from_base64(valid_chain[-1]).sign(worker, "pay_invoice", args, int(time.time()))
    assert healthy.pay_invoice(args, valid_chain, proof) == "paid"
    assert healthy.effect_count == 1


@pytest.mark.parametrize("amount", [True, "20000", 20000.5, 0, 2**53])
def test_receiver_rejects_lossy_or_invalid_amounts(amount):
    root, chain, _ = demo.task_authority()
    service = demo.PaymentService(root)
    with pytest.raises(ValueError, match="integer cents"):
        service.pay_invoice(
            {"invoice_id": "INV-123", "bank_account": "verified-bank", "amount_cents": amount},
            chain, b"",
        )
    assert service.effect_count == 0
