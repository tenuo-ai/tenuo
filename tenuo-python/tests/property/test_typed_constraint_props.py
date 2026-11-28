"""Typed literal conversion and signed wire round-trips agree with the core."""

from hypothesis import given, settings, strategies as st

from tenuo import Exact, SigningKey, Warrant


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
