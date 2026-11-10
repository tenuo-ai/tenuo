"""Typed Python literals reach the same constraints used by signed warrants."""

import time

import pytest
from hypothesis import given, settings, strategies as st

from tenuo import Authorizer, Exact, NotOneOf, OneOf, SigningKey, Warrant
from tenuo.constraints import ensure_constraint
from tenuo.exceptions import MonotonicityError, ValidationError


VALUES = [
    "Paris",
    180,
    180.5,
    True,
    False,
    None,
    2**53 + 1,
    2**63 - 1,
    -(2**63),
    [],
    [1, "1", True, None],
    {"items": [1, False], "missing": None},
]


@pytest.mark.parametrize("value", VALUES)
def test_exact_preserves_literal_type_and_shorthand(value):
    for constraint in (Exact(value), ensure_constraint(value)):
        assert type(constraint.value) is type(value)
        assert constraint.value == value
        assert constraint.matches(value)
        assert constraint.satisfies(value)


def test_numeric_equality_does_not_coerce_strings_or_booleans():
    assert Exact(1).matches(1.0)
    assert Exact(1.0).matches(1)
    assert not Exact(1).matches(True)
    assert not Exact(True).matches(1)
    assert not Exact(180).matches("180")
    assert not Exact("180").matches(180)
    # Never round an integer through f64 to construct an exact numeric policy.
    assert not Exact(2**53 + 1).matches(float(2**53 + 1))
    assert not Exact(2**63 - 1).matches(float(2**63 - 1))
    assert not Exact([1]).matches([True])
    assert not Exact({"x": True}).matches({"x": 1})


def test_one_of_preserves_mixed_values_and_uses_typed_membership():
    values = [1, "1", False, None, [2], {"value": 3}]
    constraint = OneOf(values)
    assert constraint.values == values
    assert [type(v) for v in constraint.values] == [type(v) for v in values]
    for value in values:
        assert constraint.contains(value)
        assert constraint.satisfies(value)
    assert OneOf([1, 2]).contains(1.0)
    assert not OneOf([1, 2]).contains(True)
    assert not OneOf([1, 2]).contains("1")
    assert not OneOf([True]).contains(1)


def test_exclusion_judges_only_its_existing_value_kinds():
    constraint = NotOneOf([1, 2])
    assert constraint.excluded == [1, 2]
    assert constraint.allows(3)
    assert not constraint.allows(1.0)
    for value in (True, "3", None, [], {}):
        assert not constraint.allows(value)
    assert NotOneOf([True]).allows(False)
    assert not NotOneOf([True]).allows(0)
    assert not NotOneOf([None]).allows("anything")
    # Adding an exclusion of a new kind expands the judged domain.
    with pytest.raises(MonotonicityError):
        constraint.validate_attenuation(NotOneOf([1, 2, "blocked"]))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_values_still_cannot_pass_exclusion(value):
    for constraint in (NotOneOf([1]), NotOneOf([value]), NotOneOf([])):
        assert not constraint.allows(value)


@pytest.mark.parametrize("value", [2**63, -(2**63) - 1, object(), {1: "non-string key"}])
@pytest.mark.parametrize("constructor", [Exact, lambda v: OneOf([v]), lambda v: NotOneOf([v])])
def test_invalid_values_fail_conversion_instead_of_coercing(value, constructor):
    with pytest.raises(ValidationError):
        constructor(value)


def test_reprs_distinguish_literal_kinds():
    assert repr(Exact(180)) == "Exact(180)"
    assert repr(Exact("180")) == "Exact('180')"
    assert repr(Exact(True)) == "Exact(True)"
    assert repr(Exact(None)) == "Exact(None)"
    assert repr(OneOf([1, "1", None])) == "OneOf([1, '1', None])"
    assert repr(NotOneOf([False, 0])) == "NotOneOf([False, 0])"


@pytest.fixture(params=["annotation", "a2a"])
def check(request):
    if request.param == "annotation":
        from tenuo.decorators import _check_annotated_constraint

        return _check_annotated_constraint
    from tenuo.a2a.server import A2AServer

    key = SigningKey.generate().public_key
    return A2AServer(
        name="Typed test",
        url="https://agent.example.test",
        public_key=key,
        trusted_issuers=[key],
    )._check_constraint


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("constructor", [Exact, lambda v: OneOf([v])])
def test_adapter_checks_preserve_typed_values(check, value, constructor):
    assert check(constructor(value), value)


@pytest.mark.parametrize("constructor", [Exact, lambda v: OneOf([v])])
@pytest.mark.parametrize("policy,value", [("1", 1), (1, "1"), (True, 1), (1, True), ("None", None)])
def test_adapter_checks_do_not_stringify_or_coerce(check, constructor, policy, value):
    assert not check(constructor(policy), value)


@pytest.mark.parametrize("value", VALUES)
def test_typed_exact_roundtrips_and_authorizes_the_signed_value(value):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("t", x=Exact(value)).holder(holder.public_key).ttl(300).mint(issuer)
    decoded = Warrant.from_base64(warrant.to_base64())
    constraint = decoded.capabilities["t"]["x"]
    assert type(constraint.value) is type(value)
    assert constraint.matches(value)
    args = {"x": value}
    signature = decoded.sign(holder, "t", args, int(time.time()))
    # Exercise the native receiving boundary with the unmodified typed args.
    Authorizer(trusted_roots=[issuer.public_key]).authorize_one(decoded, "t", args, signature)


@pytest.mark.parametrize("constructor", [OneOf, NotOneOf])
def test_typed_sets_roundtrip_without_collapsing_boolean_and_integer(constructor):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    values = [1, True, None, "1", [2], {"x": False}]
    warrant = (
        Warrant.mint_builder().capability("t", x=constructor(values)).holder(holder.public_key).ttl(300).mint(issuer)
    )
    decoded = Warrant.from_base64(warrant.to_base64()).capabilities["t"]["x"]
    actual = decoded.values if constructor is OneOf else decoded.excluded
    assert actual == values
    assert [type(v) for v in actual] == [type(v) for v in values]
    assert not OneOf([1]).contains(True)


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**63 - 1)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=16),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3),
    max_leaves=8,
)


@given(json_values)
@settings(max_examples=60)
def test_typed_literal_conversion_and_wire_roundtrip_agree(value):
    issuer = SigningKey.generate()
    constraint = Exact(value)
    assert constraint.matches(value)
    warrant = Warrant.mint_builder().capability("t", x=constraint).holder(issuer.public_key).ttl(300).mint(issuer)
    decoded = Warrant.from_base64(warrant.to_base64()).capabilities["t"]["x"]
    assert decoded.matches(value)
