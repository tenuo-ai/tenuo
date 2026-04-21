"""Hypothesis fuzzer for the Python→Rust PoP canonicalization boundary.

Bug #2 on PR #384 was a ``ValueError`` raised from deep inside PyO3 whenever
``None`` appeared in a tool-argument dict. The failure mode was a crash
rather than a wrong answer, and it slipped past the existing tests because
every hand-authored fixture used well-formed, `None`-free dicts.

This fuzzer generates arbitrary JSON-shaped argument dicts (scalars,
``None`` values, lists, nested lists) and asserts two invariants at the
FFI boundary:

1. ``strip_none_values`` produces a structurally clean dict that
   :class:`Warrant.sign` and :class:`Authorizer.authorize_one` accept
   without raising, for *any* reachable input.
2. A full ``sign → verify`` round-trip over the stripped dict succeeds —
   the signature computed on the client side verifies server side with
   byte-identical canonicalization.

Those are exactly the two properties we want a regression test to pin:
robustness at the FFI boundary (no latent crashes) and symmetry of
canonicalization across the boundary (no silent drift).

The strategies deliberately include edge cases the Rust side must
handle: empty dicts, empty lists, Unicode, large ints within ``i64``
range, booleans (which CBOR treats as a distinct type from integers),
and deeply nested lists-of-lists.
"""

from __future__ import annotations

import time

import pytest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ModuleNotFoundError:  # pragma: no cover
    pytest.skip("hypothesis not installed", allow_module_level=True)

from tenuo import Pattern
from tenuo_core import Authorizer, SigningKey, Warrant

from tenuo._pop_canonicalize import strip_none_values


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------
# Leaf scalars the Rust ConstraintValue accepts. We deliberately include
# None in the *input* strategy so the fuzzer pressures the stripping path.
# Floats are constrained to sane reals — NaN/inf are their own class of
# canonicalization question and aren't part of this regression surface.

_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(min_size=0, max_size=64),
)

# Lists of scalars and lists-of-lists. Nested scalars inherit None from _scalar
# so strip_none_values's list recursion is exercised at depth.
_list_scalar = st.lists(_scalar, max_size=6)
_list_of_list = st.lists(_list_scalar, max_size=4)
_value = st.one_of(_scalar, _list_scalar, _list_of_list)

# Keys are short ASCII-ish identifiers — real tool args use this shape.
_key = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_-",
    ),
    min_size=1,
    max_size=12,
)

arg_dict = st.dictionaries(keys=_key, values=_value, max_size=8)


# ---------------------------------------------------------------------------
# Per-session warrant & authorizer with a wildcard "fuzz" tool
# ---------------------------------------------------------------------------
# The fuzz tool has **no** constraints beyond the tool name, so every
# generated argument dict is constraint-satisfied and the only thing under
# test is PoP round-tripping, not policy matching.


@pytest.fixture(scope="module")
def _trust_chain():
    issuer = SigningKey.generate()
    agent = SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[issuer.public_key])
    warrant = Warrant.issue(
        issuer,
        capabilities={"fuzz": {}},  # no constraints — any args pass
        holder=agent.public_key,
    )
    return issuer, agent, authorizer, warrant


# ---------------------------------------------------------------------------
# Property 1 — strip_none_values output is well-formed and free of None
# ---------------------------------------------------------------------------


class TestStripNoneInvariants:
    @given(d=arg_dict)
    @settings(deadline=None, max_examples=200)
    def test_output_has_no_none_values(self, d):
        cleaned = strip_none_values(d)
        assert all(v is not None for v in cleaned.values())
        for v in cleaned.values():
            if isinstance(v, list):
                assert all(item is not None for item in v)

    @given(d=arg_dict)
    @settings(deadline=None, max_examples=200)
    def test_idempotent(self, d):
        once = strip_none_values(d)
        twice = strip_none_values(once)
        assert once == twice

    @given(d=arg_dict)
    @settings(deadline=None, max_examples=200)
    def test_does_not_mutate_input(self, d):
        before = {k: (list(v) if isinstance(v, list) else v) for k, v in d.items()}
        strip_none_values(d)
        assert d == before


# ---------------------------------------------------------------------------
# Property 2 — sign → verify round-trip succeeds for any stripped dict
# ---------------------------------------------------------------------------


class TestPopRoundTripOverArbitraryArgs:
    @given(d=arg_dict)
    @settings(deadline=None, max_examples=100)
    def test_sign_then_verify_succeeds(self, d, _trust_chain):
        _, agent, authorizer, warrant = _trust_chain
        canonical = strip_none_values(d)

        # Sign — must not raise, regardless of None shape in the input.
        sig = warrant.sign(agent, "fuzz", canonical, int(time.time()))

        # Verify — round-trips byte-identically because both sides apply
        # strip_none_values to their respective view.
        result = authorizer.authorize_one(warrant, "fuzz", canonical, bytes(sig))
        assert result is not None


# ---------------------------------------------------------------------------
# Property 3 — strip-asymmetry across the boundary is detected
# ---------------------------------------------------------------------------


class TestCanonicalizationAsymmetryIsRejected:
    """If the two sides canonicalize differently (e.g. one forgets to
    strip), verification must fail cleanly rather than crash. This locks
    in the integrity invariant while still tolerating the canonicalization
    drift mode as a *denial* rather than a crash."""

    @given(d=arg_dict.filter(lambda d: any(v is None for v in d.values())))
    @settings(deadline=None, max_examples=50)
    def test_signing_stripped_but_verifying_unstripped_denies(self, d, _trust_chain):
        _, agent, authorizer, warrant = _trust_chain
        # Client strips before signing (correct behavior).
        canonical = strip_none_values(d)
        sig = warrant.sign(agent, "fuzz", canonical, int(time.time()))

        # Server forgets to strip and hands the raw dict (with Nones) to
        # the authorizer. The authorizer should either:
        #   a) raise a TenuoError / ValueError (old behavior — the crash
        #      path that Bug #2 described), or
        #   b) return a denial.
        # Either outcome is acceptable for this regression — what matters
        # is that we never silently pass verification with mismatched
        # canonicalization.
        from tenuo.exceptions import TenuoError

        try:
            authorizer.authorize_one(warrant, "fuzz", d, bytes(sig))
        except (TenuoError, ValueError):
            return  # expected — the drift was detected loudly
        # If we got here, authorize_one returned a result object. We have
        # no general API for "was this a denial" on the result (different
        # builds expose different fields), so fall back to a sanity check:
        # the two dicts must have been equal (no actual None difference)
        # for the round trip to have agreed.
        assert d == canonical, (
            "sign/verify agreed on mismatched canonicalizations — "
            "this is the silent drift mode strip_none_values is meant "
            "to prevent"
        )
