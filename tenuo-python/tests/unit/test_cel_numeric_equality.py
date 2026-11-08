"""Decimal CEL policies must enforce the same numeric value through Python."""

import pytest
from tenuo import CEL


@pytest.mark.parametrize("amount", [1000, 1000.0])
@pytest.mark.parametrize(
    "expression, expected",
    [
        ("value == 1000.0", True),
        ("value != 1000.0", False),
        ("!(value in [1000.0, 2000.0])", False),
        ("value == double(1000)", True),
        ("[value] == [1000.0]", True),
    ],
)
def test_decimal_policy_matches_python_number_spellings(amount, expression, expected):
    assert CEL(expression).matches(amount) is expected


def test_numeric_equality_does_not_round_python_integer():
    amount = 2**53 + 1
    assert CEL("value != 9007199254740992.0").matches(amount)
    assert CEL("!(value in [9007199254740992.0])").matches(amount)
