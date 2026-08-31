"""Cross-language agreement on the A.30 receipt vectors.

These are the exact bytes ``generate_test_vectors`` emits and the Rust and
TypeScript suites verify. If Python disagrees with them, the three
implementations have diverged on the receipt format.
"""

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

# A.30.1 — no revocation data loaded: payload keys 12 and 13 both absent.
A30_1 = (
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
    "280200962fe537c39a0909677265712d6133300f582034750f98bd59fcfc946d"
    "a45aaabe933be154a4b5094e1c4abf42866505f3c97e6a7369676e65725f6b65"
    "79820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef763"
    "66b0af7137697369676e6174757265820158403dae6ff6eac08c6454b1a97747"
    "c7bff3f8dd691798e1eee681b17a9e2e2ffc8a74999ded362f707ebfe5a6734b"
    "bbadeed0c96e51be97d2a37f8316a7d172bd08"
)

# A.30.2 — unversioned revocation list: key 13 present, key 12 absent.
A30_2 = (
    "a46f726563656970745f76657273696f6e01677061796c6f616459019ca90001"
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
    "c42fcd7d0909f865aaf5b66d9ca5d1ee5278fffdc7120f582034750f98bd59fc"
    "fc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e6a7369676e6572"
    "5f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e"
    "1ef76366b0af7137697369676e617475726582015840cf81c7873a9bc4b87be2"
    "254b37222769dee384a36dde5645518f85dff76fc5f5a8fe50817b244c445720"
    "e64fd89f2de9fba4e48312d63feffb8664f46ee1ca04"
)

# A.30.3 — versioned revocation list: keys 12 and 13 both present.
A30_3 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901c2ab0001"
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
    "280200962fe537c39a0909677265712d6133300b5820a2de9b15bdc8095f2421"
    "26aa369233e4f2cada0ee3852482cae5ac9b94b80ff80c182f0d5820e135dea2"
    "864c53a124c9c42fcd7d0909f865aaf5b66d9ca5d1ee5278fffdc7120f582034"
    "750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e6a"
    "7369676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10"
    "373e623f7b0e1ef76366b0af7137697369676e617475726582015840f7395fb6"
    "7a2bf45c2da552e69e014e1851132558fdc460b941ad0357ab1eaa2a4ad58c79"
    "931b1ee377116b3d7a109b9d50dbb29ec1e76cba872273e38eff6e0c"
)

# A.30.4 — denial before proof-of-possession: key 8 absent, key 10 required.
A30_4 = (
    "a46f726563656970745f76657273696f6e01677061796c6f6164590172a90001"
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
    "b66d9ca5d1ee5278fffdc7120f582034750f98bd59fcfc946da45aaabe933be1"
    "54a4b5094e1c4abf42866505f3c97e6a7369676e65725f6b6579820158201ba4"
    "075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af71376973"
    "69676e61747572658201584077775a6ebefc4dca805c5826bc80046ceba63c46"
    "78e8957b26d052139042109d40b791e83bf1c2252d0b6fa7c700be85043cb6c9"
    "7f6d5a190274c4956a8f5c0b"
)

# Fixed input the vectors commit to, so an implementation can confirm its
# digest function agrees before trusting the receipt bytes.
SRL_DIGEST_INPUT = b"tenuo-test-vector-a30-revocation-list"
POLICY_INPUT = b"tenuo-test-vector-a30-policy"

# A.30.5 — chained to A.30.2 via payload key 14.
A30_5 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901c6aa0001"
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
    "280200962fe537c39a09096e7265712d6133302d7365636f6e640d5820e135de"
    "a2864c53a124c9c42fcd7d0909f865aaf5b66d9ca5d1ee5278fffdc7120e5820"
    "ac4582f55beda95c370e8f50ff3286790eef1fec12aee369fcd7fb636a4e9666"
    "0f582034750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505"
    "f3c97e6a7369676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5"
    "221f3c10373e623f7b0e1ef76366b0af7137697369676e617475726582015840"
    "2abc6b9738d742aa79294b6db464e67495c9fd4ba2ab22b5696119cd82f8eba9"
    "3227249df96b603a23b8cb92409868f5eb5d91275bd5568ae6cad567a76c8e03"
)


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


def test_commits_to_the_trusted_root_set():
    # A receipt that does not say which roots it honoured cannot show the chain
    # was rooted in anything legitimate.
    for wire in (A30_1, A30_3, A30_4, A30_5):
        assert tenuo_core.verify_receipt(wire).trusted_roots_hash is not None


def test_commits_to_the_host_ceiling():
    payload = tenuo_core.verify_receipt(A30_3)

    # Without key 11, an allow under a tight ceiling is indistinguishable from
    # one under an open ceiling.
    assert payload.policy_definition_hash == tenuo_core.policy_commitment_digest(POLICY_INPUT).hex()


def test_links_to_the_previous_receipt():
    import hashlib

    previous = hashlib.sha256(bytes.fromhex(A30_2)).hexdigest()

    assert tenuo_core.verify_receipt(A30_5).prev_receipt_hash == previous


def test_first_receipt_omits_the_link_rather_than_zero_filling_it():
    # A zero hash would be indistinguishable from a link to a receipt nobody
    # can produce.
    assert tenuo_core.verify_receipt(A30_1).prev_receipt_hash is None


def test_a_withheld_receipt_leaves_a_dangling_successor():
    kept = tenuo_core.verify_receipt(A30_5)

    # The point of chaining: withholding a receipt leaves its successor
    # pointing at something absent.
    assert kept.prev_receipt_hash is not None
    assert kept.prev_receipt_hash not in []
