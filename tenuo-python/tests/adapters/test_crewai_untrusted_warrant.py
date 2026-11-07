"""CrewAI reports trust failures as UntrustedWarrant, not a bare InvalidPoP.

UntrustedWarrant subclasses InvalidPoP, so existing handlers keep working.
"""

import pytest

pytest.importorskip("crewai")

from tenuo_core import Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.config import reset_config  # noqa: E402
from tenuo.crewai import GuardBuilder, InvalidPoP, UntrustedWarrant  # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def _keys():
    return SigningKey.generate(), SigningKey.generate(), SigningKey.generate()


def _guard(warrant, key, *, roots, chain=None):
    builder = GuardBuilder().allow("search", query=Pattern("*")).with_warrant(warrant, key, warrant_chain=chain)
    if roots is not None:
        builder = builder.with_trusted_roots(roots)
    return builder.on_denial("raise").build()


def _root_warrant(root, holder):
    return Warrant.mint_builder().capability("search", query=Pattern("*")).holder(holder.public_key).ttl(600).mint(root)


def test_untrusted_root_raises_untrusted_warrant():
    root, holder, other = _keys()
    guard = _guard(_root_warrant(root, holder), holder, roots=[other.public_key])
    with pytest.raises(UntrustedWarrant) as exc_info:
        guard._authorize("search", {"query": "x"})
    assert exc_info.value.error_code == "UNTRUSTED_WARRANT"
    assert "Proof-of-Possession" not in str(exc_info.value)


def test_delegated_warrant_without_chain_raises_untrusted_warrant():
    root, mid, leaf = _keys()
    parent = _root_warrant(root, mid)
    child = parent.grant_builder().capability("search", query=Pattern("*")).holder(leaf.public_key).ttl(300).grant(mid)
    with pytest.raises(UntrustedWarrant):
        _guard(child, leaf, roots=[root.public_key])._authorize("search", {"query": "x"})


def test_untrusted_warrant_is_still_an_invalid_pop():
    root, holder, other = _keys()
    guard = _guard(_root_warrant(root, holder), holder, roots=[other.public_key])
    with pytest.raises(InvalidPoP):
        guard._authorize("search", {"query": "x"})


def test_wrong_signing_key_is_plain_invalid_pop():
    root, holder, attacker = _keys()
    guard = _guard(_root_warrant(root, holder), attacker, roots=[root.public_key])
    with pytest.raises(InvalidPoP) as exc_info:
        guard._authorize("search", {"query": "x"})
    assert not isinstance(exc_info.value, UntrustedWarrant)
