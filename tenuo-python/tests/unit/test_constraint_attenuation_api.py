"""Both public preflight APIs agree with signed delegation in the Rust core."""

import pytest
import tenuo
import tenuo_core

from tenuo import (
    CEL,
    All,
    AnyOf,
    Cidr,
    Contains,
    Exact,
    Not,
    NotOneOf,
    OneOf,
    Pattern,
    Range,
    Regex,
    Shlex,
    SigningKey,
    Subpath,
    Subset,
    UrlPattern,
    UrlSafe,
    Warrant,
    Wildcard,
    validate_attenuation,
)
from tenuo.exceptions import (
    ExactValueMismatch,
    IncompatibleConstraintTypes,
    MonotonicityError,
    RangeExpanded,
    ValidationError,
    ValueNotInParentSet,
    WildcardExpansion,
)


PAIRS = [
    (Wildcard(), Exact(180), None),
    (Exact("Paris"), Wildcard(), WildcardExpansion),
    (Exact(1), Exact(1.0), None),
    (Exact(1), Exact(True), ExactValueMismatch),
    (OneOf(["Paris", "Lyon"]), Exact("Paris"), None),
    (OneOf(["Paris", "Lyon"]), Exact("Rome"), ValueNotInParentSet),
    (OneOf([1, 2, 3]), OneOf([1, 2]), None),
    (OneOf([1, 2, 3]), Exact(2), None),
    (OneOf([1, 2, 3]), OneOf([2, 4]), ValueNotInParentSet),
    (OneOf([1, 2]), Exact(True), ValueNotInParentSet),
    (Range(0, 300), Range(0, 250), None),
    (Range(0, 300), Range(0, 400), RangeExpanded),
    (Range(0, 300), Exact(5), None),
    (Range(0, 300), Exact("5"), IncompatibleConstraintTypes),
    (Pattern("a*"), Exact("abc"), None),
    (Pattern("a*"), Exact("xyz"), ValueNotInParentSet),
    (Regex("^a+$"), Exact("aaa"), None),
    (Cidr("10.0.0.0/8"), Exact("10.1.2.3"), None),
    (Subpath("/data"), Exact("/data/file"), None),
    (UrlPattern("https://example.com/*"), Exact("https://example.com/a"), None),
    (UrlSafe(), Exact("https://example.com/a"), None),
    (Shlex(allow=["ls", "cat"]), Shlex(allow=["ls"]), None),
    (Contains(["a"]), Contains(["a", "b"]), None),
    (Subset(["a", "b"]), Subset(["a"]), None),
    (CEL("value > 0"), CEL("value > 0"), None),
    (All([Range(0, 100), NotOneOf([50])]), Exact(10), None),
    (All([Range(0, 100), NotOneOf([50])]), Exact(50), MonotonicityError),
    (All([]), All([]), MonotonicityError),
    (AnyOf([Exact(1), Exact(2)]), AnyOf([Exact(1)]), None),
    (AnyOf([Cidr("10.0.0.0/8"), Exact("foo")]), AnyOf([Exact("foo")]), MonotonicityError),
    (NotOneOf([1]), NotOneOf([1, 2]), None),
    (NotOneOf([1]), NotOneOf([1, "blocked"]), MonotonicityError),
    (Not(OneOf([1, 2])), Not(OneOf([1, 2, 3])), None),
]


def test_public_function_is_the_native_core_function():
    assert validate_attenuation is tenuo_core.validate_attenuation
    assert "validate_attenuation" in tenuo.__all__
    assert validate_attenuation(parent=OneOf([1, 2]), child=Exact(1)) is None


@pytest.mark.parametrize("parent,child,error", PAIRS)
def test_preflight_and_instance_method_match_real_grants(parent, child, error):
    issuer, holder, delegate = (SigningKey.generate() for _ in range(3))
    warrant = Warrant.mint_builder().capability("t", x=parent).holder(holder.public_key).ttl(300).mint(issuer)

    def grant():
        return warrant.grant_builder().capability("t", x=child).holder(delegate.public_key).ttl(60).grant(holder)

    checks = [lambda: validate_attenuation(parent, child), lambda: parent.validate_attenuation(child), grant]
    if error is None:
        assert checks[0]() is None
        assert checks[1]() is None
        assert grant().capabilities["t"]["x"] is not None
    else:
        errors = []
        for check in checks:
            with pytest.raises(error) as raised:
                check()
            errors.append(type(raised.value))
        assert errors[0] is errors[1] is errors[2]


@pytest.mark.parametrize("parent,child", [(object(), Exact(1)), (Exact(1), object()), ("not a constraint", Exact(1))])
def test_invalid_arguments_are_reported_not_converted_to_a_boolean(parent, child):
    with pytest.raises(ValidationError):
        validate_attenuation(parent, child)
