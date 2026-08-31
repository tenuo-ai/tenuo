"""Cross-language agreement on the A.30 receipt vectors.

These are the exact bytes ``generate_test_vectors`` emits and the Rust and
TypeScript suites verify. If Python disagrees with them, the three
implementations have diverged on the receipt format.
"""

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

# A.30.1 — no revocation data loaded: payload keys 12 and 13 both absent.
A30_1 = (
    "a46f726563656970745f76657273696f6e01677061796c6f6164590156a70001"
    "0258ec81830158a3aa00010150019471f8000070008000000000003000020003"
    "a169726561645f66696c65a16b636f6e73747261696e7473a164706174688202"
    "a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6eae9"
    "0338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd74"
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200"
    "80071a65920e9008031200820158407c948aef75e62035b5a5e6ab1e07cbd5ce"
    "f372ec94ac0e514b320dbdb976a9f6fba98a81d5cbdbb3e28aca8f97f529f6ac"
    "51a36b53e547545338aba0c1cb83020369726561645f66696c650465616c6c6f"
    "77051a659200800858404aa574e10e3e19223f987a17e16839b52ae597a2b56e"
    "eaf051d14c773c30a3f790f9e24daedea9994d9618b61bd83fc76f7cf5c3764a"
    "280200962fe537c39a0909677265712d6133306a7369676e65725f6b65798201"
    "58201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af"
    "7137697369676e61747572658201584083a37f60b6aaf4b09ef318db271ce3d9"
    "bf05af64789ab35d9a00d6632dff109a78f151404c24693bfac125caf68e8597"
    "8b00e4a8b05b5af1545d2d71bc08c80a"
)

# A.30.2 — unversioned revocation list: key 13 present, key 12 absent.
A30_2 = (
    "a46f726563656970745f76657273696f6e01677061796c6f6164590179a80001"
    "0258ec81830158a3aa00010150019471f8000070008000000000003000020003"
    "a169726561645f66696c65a16b636f6e73747261696e7473a164706174688202"
    "a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6eae9"
    "0338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd74"
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200"
    "80071a65920e9008031200820158407c948aef75e62035b5a5e6ab1e07cbd5ce"
    "f372ec94ac0e514b320dbdb976a9f6fba98a81d5cbdbb3e28aca8f97f529f6ac"
    "51a36b53e547545338aba0c1cb83020369726561645f66696c650465616c6c6f"
    "77051a659200800858404aa574e10e3e19223f987a17e16839b52ae597a2b56e"
    "eaf051d14c773c30a3f790f9e24daedea9994d9618b61bd83fc76f7cf5c3764a"
    "280200962fe537c39a0909677265712d6133300d5820e135dea2864c53a124c9"
    "c42fcd7d0909f865aaf5b66d9ca5d1ee5278fffdc7126a7369676e65725f6b65"
    "79820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef763"
    "66b0af7137697369676e61747572658201584041f7bbf4806f8eadeaba1230ab"
    "a624840687a064ec09c4e1d3c1b26ce09e05b69e06f972b988eb16b7d2c10269"
    "72f465779826a75181f9af9a82b41861335802"
)

# A.30.3 — versioned revocation list: keys 12 and 13 both present.
A30_3 = (
    "a46f726563656970745f76657273696f6e01677061796c6f616459017ca90001"
    "0258ec81830158a3aa00010150019471f8000070008000000000003000020003"
    "a169726561645f66696c65a16b636f6e73747261696e7473a164706174688202"
    "a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6eae9"
    "0338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd74"
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200"
    "80071a65920e9008031200820158407c948aef75e62035b5a5e6ab1e07cbd5ce"
    "f372ec94ac0e514b320dbdb976a9f6fba98a81d5cbdbb3e28aca8f97f529f6ac"
    "51a36b53e547545338aba0c1cb83020369726561645f66696c650465616c6c6f"
    "77051a659200800858404aa574e10e3e19223f987a17e16839b52ae597a2b56e"
    "eaf051d14c773c30a3f790f9e24daedea9994d9618b61bd83fc76f7cf5c3764a"
    "280200962fe537c39a0909677265712d6133300c182f0d5820e135dea2864c53"
    "a124c9c42fcd7d0909f865aaf5b66d9ca5d1ee5278fffdc7126a7369676e6572"
    "5f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e"
    "1ef76366b0af7137697369676e617475726582015840933cca5e17fc30f194ce"
    "f193a004bfc1fd5b92cc26a7f0b796bdb247e44a844032bad41109996f26e618"
    "e81c426a862cefb4d2d13314b8e568c9b43c48ac6009"
)

# A.30.4 — denial before proof-of-possession: key 8 absent, key 10 required.
A30_4 = (
    "a46f726563656970745f76657273696f6e01677061796c6f616459014fa80001"
    "0258ec81830158a3aa00010150019471f8000070008000000000003000020003"
    "a169726561645f66696c65a16b636f6e73747261696e7473a164706174688202"
    "a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6eae9"
    "0338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd74"
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200"
    "80071a65920e9008031200820158407c948aef75e62035b5a5e6ab1e07cbd5ce"
    "f372ec94ac0e514b320dbdb976a9f6fba98a81d5cbdbb3e28aca8f97f529f6ac"
    "51a36b53e547545338aba0c1cb83020369726561645f66696c65046464656e79"
    "051a65920080096c7265712d6133302d64656e790a73746f6f6c2d6e6f742d61"
    "7574686f72697a65640d5820e135dea2864c53a124c9c42fcd7d0909f865aaf5"
    "b66d9ca5d1ee5278fffdc7126a7369676e65725f6b6579820158201ba4075b77"
    "c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137697369676e"
    "6174757265820158406272baca66717d139cc7eed64a1d7301b5518b74cc1dde"
    "6129a1512ea356e92737aaf26b3a46bfa6750143c5a282fe16e9385051e384cd"
    "a9153d116f683c550a"
)

# Fixed input the vectors commit to, so an implementation can confirm its
# digest function agrees before trusting the receipt bytes.
SRL_DIGEST_INPUT = b"tenuo-test-vector-a30-revocation-list"


def test_absent_commitment_means_revocation_was_never_consulted():
    payload = tenuo_core.verify_receipt(A30_1)

    assert payload.outcome == "allow"
    assert payload.action == "read_file"
    # Absent, not zero-filled: distinct from a loaded list that matched nothing.
    assert payload.srl_hash is None
    assert payload.srl_version is None


def test_unversioned_list_commits_without_inventing_a_version():
    payload = tenuo_core.verify_receipt(A30_2)

    assert payload.srl_hash == tenuo_core.srl_commitment_digest(SRL_DIGEST_INPUT).hex()
    assert payload.srl_version is None


def test_versioned_list_carries_both_keys():
    payload = tenuo_core.verify_receipt(A30_3)

    assert payload.srl_version == 47
    assert payload.srl_hash == tenuo_core.srl_commitment_digest(SRL_DIGEST_INPUT).hex()


def test_allow_carries_the_holders_proof_of_possession():
    payload = tenuo_core.verify_receipt(A30_3)

    # An allow without a PoP is evidence of nothing but the signer's word.
    assert payload.pop_signature is not None
    payload.check_conditional_requirements()


def test_denial_before_possession_says_so():
    payload = tenuo_core.verify_receipt(A30_4)

    assert payload.outcome == "deny"
    assert payload.decision_code == "tool-not-authorized"
    # Possession was never established, so the receipt must not imply it was.
    assert payload.pop_signature is None
    payload.check_conditional_requirements()


def test_signature_is_verified_before_the_payload_is_parsed():
    tampered = bytearray(bytes.fromhex(A30_3))
    tampered[-1] ^= 0x01

    with pytest.raises(Exception):
        tenuo_core.verify_receipt(bytes(tampered))


def test_accepts_hex_and_raw_bytes_alike():
    from_hex = tenuo_core.verify_receipt(A30_3)
    from_bytes = tenuo_core.verify_receipt(bytes.fromhex(A30_3))

    assert from_hex.request_id == from_bytes.request_id
    assert from_hex.signer_key == from_bytes.signer_key


def test_signer_key_is_the_only_field_trust_may_key_on():
    payload = tenuo_core.verify_receipt(A30_3)

    # Descriptive label, deliberately unset by these vectors; resolving
    # signer_key to a legitimate enforcement point is out of band.
    assert payload.authorizer_id is None
    assert len(payload.signer_key) == 64
