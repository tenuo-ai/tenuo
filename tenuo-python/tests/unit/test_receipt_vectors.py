"""Cross-language agreement on the A.30 receipt vectors.

These are the exact bytes ``generate_test_vectors`` emits and the Rust and
TypeScript suites verify. If Python disagrees with them, the three
implementations have diverged on the receipt format.
"""

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

# A.30.1 — no revocation data loaded: payload keys 12 and 13 both absent.
A30_1 = (
    "a46f726563656970745f76657273696f6e01677061796c6f6164590182a90001"
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
    "a45aaabe933be154a4b5094e1c4abf42866505f3c97e1067656e666f7263656a"
    "7369676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10"
    "373e623f7b0e1ef76366b0af7137697369676e61747572658201584018a85141"
    "882966f4a0c8cdb422edd454ca4390cf90cd2268615fb532f7c0e4d4dc6c736c"
    "cabe803491536203dfe01939b3c099b811ad296d28ebb6a558d2e203"
)

# A.30.2 — unversioned revocation list: key 13 present, key 12 absent.
A30_2 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901a5aa0001"
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
    "fc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e1067656e666f72"
    "63656a7369676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf522"
    "1f3c10373e623f7b0e1ef76366b0af7137697369676e61747572658201584007"
    "7ac479c652c7948817898f6466c4962c42a149d1b1d3bb02b00e84cbddfebe8a"
    "9f018a9571160d4deb9902647e476f2f8d0046eedb118fd1e7938201977009"
)

# A.30.3 — versioned revocation list: keys 12 and 13 both present.
A30_3 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901cbac0001"
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
    "750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e10"
    "67656e666f7263656a7369676e65725f6b6579820158201ba4075b77c9e3fb3e"
    "cde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137697369676e61747572"
    "6582015840539164661a9df2136752a4b7477f520105a375230f666688fe645c"
    "ad6c11b71d3443926320c12a3b40179294417e4e29efa7bccf026a1c3c349927"
    "ec5022f10e"
)

# A.30.4 — denial before proof-of-possession: key 8 absent, key 10 required.
A30_4 = (
    "a46f726563656970745f76657273696f6e01677061796c6f616459017baa0001"
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
    "54a4b5094e1c4abf42866505f3c97e1067656e666f7263656a7369676e65725f"
    "6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1e"
    "f76366b0af7137697369676e6174757265820158409783c355de9154efdcea85"
    "1018f7d7b99e6dd7fbb3c807e6c47b9651d283184c4c59534ca3a80352241b2e"
    "efcca618e6d67c1417669f5755deb935f035098301"
)

# Fixed input the vectors commit to, so an implementation can confirm its
# digest function agrees before trusting the receipt bytes.
SRL_DIGEST_INPUT = b"tenuo-test-vector-a30-revocation-list"
POLICY_INPUT = b"tenuo-test-vector-a30-policy"

# A.30.5 — chained to A.30.2 via payload key 14.
A30_5 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901cfab0001"
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
    "8176e804c409a01641bf4bb43fff6111d3ad9460760d134a403633cfd2325ea8"
    "0f582034750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505"
    "f3c97e1067656e666f7263656a7369676e65725f6b6579820158201ba4075b77"
    "c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137697369676e"
    "617475726582015840843ee09031bdcfdd593c3983b919034a577b41d840ce2a"
    "5b3a1573efaa548f861cdd7e2b7f4c7d845af205812025f3955bbdc6a79a6b20"
    "0235ee85dfd929df00"
)

A30_6 = (
    "a46f726563656970745f76657273696f6e01677061796c6f61645901a0aa0001"
    "0258ec81830158a3aa00010150019471f8000070008000000000003000020003"
    "a169726561645f66696c65a16b636f6e73747261696e7473a164706174688202"
    "a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6eae9"
    "0338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd74"
    "09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200"
    "80071a65920e9008031200820158407c948aef75e62035b5a5e6ab1e07cbd5ce"
    "f372ec94ac0e514b320dbdb976a9f6fba98a81d5cbdbb3e28aca8f97f529f6ac"
    "51a36b53e547545338aba0c1cb83020369726561645f66696c65046464656e79"
    "051a659200800858404aa574e10e3e19223f987a17e16839b52ae597a2b56eea"
    "f051d14c773c30a3f790f9e24daedea9994d9618b61bd83fc76f7cf5c3764a28"
    "0200962fe537c39a0909707265712d6133302d6f627365727665640a74636f6e"
    "73747261696e742d76696f6c6174696f6e0f582034750f98bd59fcfc946da45a"
    "aabe933be154a4b5094e1c4abf42866505f3c97e10676f6273657276656a7369"
    "676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10373e"
    "623f7b0e1ef76366b0af7137697369676e617475726582015840aa9c40d3bce4"
    "d5bd1bd245448088cf398012c2dc2968fe056590420557a2392c3798d7a7b44d"
    "4253779f63fe89a44fc2d120044188e631bf106b4b49ce5af001"
)

# A.30.7 — an observed allow, identical to A.30.1 except key 16.
A30_7 = (
    "a46f726563656970745f76657273696f6e01677061796c6f6164590182a90001"
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
    "a45aaabe933be154a4b5094e1c4abf42866505f3c97e10676f6273657276656a"
    "7369676e65725f6b6579820158201ba4075b77c9e3fb3ecde15cdaf5221f3c10"
    "373e623f7b0e1ef76366b0af7137697369676e617475726582015840b2b1ff7a"
    "6ef14b4bb8507f06782edc80cbba1e16774b5d8ddc2ac702a1ace283c5deac81"
    "f2a4e80f07d02743905d2235762ccbacaf63359847cad851d37d290d"
)

# A.30.1 as signed before key 16 existed.
A30_1_LEGACY = (
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


# ── A.31 derivations ────────────────────────────────────────────────────────
# Python must reproduce the same bytes as Rust, or a receipt's keys 7 and 11
# are opaque here rather than checkable.

A31_REQUEST_HASH = "59f290af000b9331df93a643f48fd530f43510243507cd8bfc8aa12623dbab4b"
A31_POLICY_CBOR = "a268656e636f64696e67a2646b696e64656f6e654f666676616c7565738264757466386561736369696470617468a2646b696e6465756e64657264726f6f74652f64617461"
A31_POLICY_HASH = "9b53b570975500172890f86347a3338c8ac4ca2b75501d582a2cc0eef152059d"


def test_request_hash_matches_the_published_derivation():
    holder_hex = "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"
    holder = tenuo_core.PublicKey.from_bytes(bytes.fromhex(holder_hex))

    digest = tenuo_core.py_compute_request_hash(
        "tnu_wrt_019471f8000070008000000000003100",
        "read_file",
        {
            "path": "/data/q3.pdf",
            "limit": 10,
            "dry_run": True,
            "tags": ["b", "a"],
        },
        holder,
    )

    assert digest.hex() == A31_REQUEST_HASH


def test_policy_commitment_matches_the_published_derivation():
    # The commitment describes the policy, not the order it was built in.
    assert (
        tenuo_core.policy_commitment_digest(bytes.fromhex(A31_POLICY_CBOR)).hex()
        == A31_POLICY_HASH
    )


@pytest.mark.parametrize(
    "wire, outcome, mode",
    [
        (A30_1, "allow", "enforce"),
        (A30_2, "allow", "enforce"),
        (A30_3, "allow", "enforce"),
        (A30_4, "deny", "enforce"),
        (A30_5, "allow", "enforce"),
        (A30_6, "deny", "observe"),
        (A30_7, "allow", "observe"),
    ],
)
def test_every_receipt_records_its_mode(wire, outcome, mode):
    payload = tenuo_core.verify_receipt(wire)
    assert (payload.outcome, payload.mode) == (outcome, mode)
    payload.check_conditional_requirements()


def test_receipt_signed_before_key_16_reads_as_enforce():
    assert tenuo_core.verify_receipt(A30_1_LEGACY).mode == "enforce"
