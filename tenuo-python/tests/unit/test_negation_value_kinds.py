"""Negation preserves value kinds across Rust and Python entry points."""

import pytest

from tenuo import Not, NotOneOf, Range, SigningKey, Warrant
from tenuo.decorators import _check_annotated_constraint


# Rust-issued NotOneOf::from_values([Integer(1000)]). Decoding is clock-neutral;
# this fixture inspects the constraint, without authorizing the expired warrant.
NUMERIC_EXCLUSION_WARRANT = (
    "gwFYnaoAAQFQAaHCe8mrcBiGPmp_p7J0ZAIAA6FjcGF5oWtjb25zdHJhaW50c6FmYW1vdW50"
    "ggehaGV4Y2x1ZGVkgRkD6ASCAVggamNlRTYjCjOoecFTaqWrnL8lnyC4vnzUY7aidK4RcaIF"
    "ggFYIGpjZUU2IwozqHnBU2qlq5y_JZ8guL581GO2onSuEXGiBhpq8ky-Bxpq8k3qCBhAEgC"
    "CAVhAiXglTLflE8Tdmp-M_xVfH6_Y3m7x4O6I-iWAnkfM7Et08aQFUZPT1pbIi4MXohMpxx"
    "WAC6tp7sE1LF0PsAw3Dw"
)


def numeric_exclusion():
    return Warrant.from_base64(NUMERIC_EXCLUSION_WARRANT).capabilities["pay"]["amount"]


def test_decoded_numeric_not_one_of_allows_uses_core_kind_check():
    constraint = numeric_exclusion()
    assert constraint.excluded == [1000]
    assert constraint.satisfies(999)
    assert not constraint.satisfies(1000)
    assert not constraint.satisfies("999")
    assert not constraint.allows("999")


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_cannot_pass_negation(number):
    for constraint in [Not(Range(min=1000)), Not(Range(max=1000)), numeric_exclusion(), NotOneOf([])]:
        assert not constraint.satisfies(number)


@pytest.fixture(params=["annotation", "a2a"])
def check(request):
    if request.param == "annotation":
        return _check_annotated_constraint
    from tenuo.a2a.server import A2AServer

    key = SigningKey.generate().public_key
    return A2AServer(
        name="Negation test", url="https://agent.example.test", public_key=key, trusted_issuers=[key],
    )._check_constraint


@pytest.mark.parametrize("value", [["prod"], 5, False, {}, None])
def test_string_exclusion_does_not_stringify_other_kinds(check, value):
    constraint = NotOneOf(["prod"])
    assert not check(constraint, value)
    assert check(constraint, "staging")
    assert not check(constraint, "prod")


def test_numeric_negation_preserves_numbers_in_python_dispatch(check):
    constraint = Not(Range(min=1000))
    assert check(constraint, 999)
    assert check(constraint, 999.5)
    assert not check(constraint, 1000)
    assert not check(constraint, "999")
    constraint = numeric_exclusion()
    assert check(constraint, 999)
    assert not check(constraint, 1000)
    assert not check(constraint, "999")
