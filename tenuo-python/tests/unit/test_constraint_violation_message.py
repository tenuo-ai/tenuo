"""ConstraintViolation names the failed constraint once, whether or not the reason already does."""

from tenuo import Exact, SigningKey, Warrant
from tenuo.exceptions import ConstraintViolation


def test_reason_without_prefix():
    err = ConstraintViolation("approver", "value does not match constraint")
    assert str(err).startswith("Constraint 'approver' not satisfied: value does not match constraint")
    assert err.details["reason"] == "value does not match constraint"


def test_core_denial_reason_is_not_prefixed_twice():
    key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .holder(key.public_key)
        .capability("request_approval", approver=Exact("orders@example.com"))
        .ttl(60)
        .mint(key)
    )
    reason = warrant.check_constraints("request_approval", {"approver": "someone@example.com"})
    assert reason.startswith("Constraint 'approver' not satisfied: ")

    err = ConstraintViolation("approver", reason)

    assert str(err).count("not satisfied") == 1
    assert err.details["reason"] == reason.removeprefix("Constraint 'approver' not satisfied: ")


def test_prefix_for_another_field_is_kept():
    err = ConstraintViolation("amount", "Constraint 'currency' not satisfied: must be USD")
    assert "Constraint 'amount' not satisfied: Constraint 'currency' not satisfied" in str(err)
