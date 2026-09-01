"""`tenuo receipt` — verifying one receipt, and walking a chain for gaps.

The chain walker is what makes the chain link worth carrying: a link that
nothing ever checks detects nothing.
"""

from __future__ import annotations

import json
import time

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import Authorizer, ControlPlaneClient, Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.cli import verify_receipt_chain, verify_receipt_cli  # noqa: E402


@pytest.fixture
def receipts():
    """Three chained receipts from one enforcement point."""
    root, worker = SigningKey.generate(), SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[root.public_key])
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", args, int(time.time()))
    result = authorizer.check_chain([warrant], "read_file", args, pop, [])

    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="t")
    client.bind_authorizer(authorizer)
    return [
        client.issue_receipt(result, "read_file", True, 1_700_000_000 + i, f"req-{i}")
        for i in range(3)
    ]


def _write(path, wires):
    path.write_text("".join(json.dumps({"receipt": w}) + "\n" for w in wires), encoding="utf-8")
    return str(path)


def test_verify_accepts_a_receipt_inline(receipts, capsys):
    assert verify_receipt_cli(receipts[0]) is True

    out = capsys.readouterr().out
    assert "Signature verifies" in out
    # The limit has to be stated, or a reader assumes the receipt proves more
    # than it does — and it now points at the flag that closes it.
    assert "your judgment" in out
    assert "--authorizer" in out


def test_verify_accepts_a_path(receipts, tmp_path, capsys):
    path = tmp_path / "one.hex"
    path.write_text(receipts[0], encoding="utf-8")

    assert verify_receipt_cli(str(path)) is True
    assert "ALLOW" in capsys.readouterr().out


def test_verify_rejects_a_tampered_receipt(receipts, capsys):
    tampered = bytearray(bytes.fromhex(receipts[0]))
    tampered[-1] ^= 0x01

    assert verify_receipt_cli(tampered.hex()) is False
    assert "does not verify" in capsys.readouterr().out


def test_verify_names_what_a_receipt_leaves_open(receipts, capsys):
    verify_receipt_cli(receipts[0])
    out = capsys.readouterr().out

    # No revocation list was installed, and the output says so rather than
    # letting a reader infer the warrant was live.
    assert "NOT consulted" in out


def test_an_intact_chain_reports_no_breaks(receipts, tmp_path, capsys):
    assert verify_receipt_chain(_write(tmp_path / "r.jsonl", receipts)) is True
    assert "Chain intact" in capsys.readouterr().out


def test_a_withheld_receipt_is_detected(receipts, tmp_path, capsys):
    # Drop the middle receipt — exactly the omission chaining exists to catch.
    path = _write(tmp_path / "r.jsonl", [receipts[0], receipts[2]])

    assert verify_receipt_chain(path) is False

    out = capsys.readouterr().out
    assert "break" in out
    assert "req-2" in out


def test_a_tampered_receipt_in_a_chain_fails_the_walk(receipts, tmp_path, capsys):
    tampered = bytearray(bytes.fromhex(receipts[1]))
    tampered[-1] ^= 0x01
    path = _write(tmp_path / "r.jsonl", [receipts[0], tampered.hex()])

    assert verify_receipt_chain(path) is False
    assert "does not verify" in capsys.readouterr().out


def test_merged_streams_are_flagged_rather_than_passed_silently(receipts, tmp_path, capsys):
    # Two receipts with no predecessor means two streams, or chaining that was
    # off for some. Links still resolve, so this must be a warning, not a pass.
    root, worker = SigningKey.generate(), SigningKey.generate()
    other = Authorizer(trusted_roots=[root.public_key])
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", args, int(time.time()))
    result = other.check_chain([warrant], "read_file", args, pop, [])
    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="t2")
    client.bind_authorizer(other)
    foreign = client.issue_receipt(result, "read_file", True, 1_700_000_000, "other-0")

    path = _write(tmp_path / "r.jsonl", [receipts[0], foreign])

    assert verify_receipt_chain(path) is True
    assert "separate streams" in capsys.readouterr().out


def test_an_empty_file_is_an_error_not_a_pass(tmp_path, capsys):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")

    # An empty evidence file must not read as "nothing wrong here".
    assert verify_receipt_chain(str(path)) is False


# ── claim checks: the full story a verifier can establish ────────────────────


@pytest.fixture
def bundle():
    """An allow receipt plus everything a verifier could hold about it."""
    root, worker = SigningKey.generate(), SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[root.public_key])
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    call_args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", call_args, int(time.time()))
    result = authorizer.check_chain([warrant], "read_file", call_args, signature=pop)

    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="t")
    client.bind_authorizer(authorizer)
    wire = client.issue_receipt(result, "read_file", True, int(time.time()), "req-1")

    import tenuo_core

    return {
        "payload": tenuo_core.verify_receipt(wire),
        "root_hex": bytes(root.public_key.to_bytes()).hex(),
        "signer": client.receipt_signer_key,
        "args": call_args,
        "authorizer": authorizer,
        "warrant": warrant,
        "worker": worker,
        "client": client,
    }


def _claim(claims, name):
    matches = [c for c in claims if c[0] == name]
    assert matches, f"no claim named {name!r} in {[c[0] for c in claims]}"
    return matches[0]


def test_chain_claim_verifies_to_the_issuing_root(bundle):
    from tenuo.cli import check_receipt_claims

    claims, ok = check_receipt_claims(bundle["payload"], roots=[bundle["root_hex"]])

    # No trust in the signer needed: the chain is signed by the root and the
    # holder, not the enforcement point.
    assert _claim(claims, "chain")[1] == "ok"
    assert _claim(claims, "anchors")[1] == "ok"
    assert ok


def test_chain_claim_fails_under_a_stranger_root(bundle):
    from tenuo.cli import check_receipt_claims

    stranger = bytes(SigningKey.generate().public_key.to_bytes()).hex()
    claims, ok = check_receipt_claims(bundle["payload"], roots=[stranger])

    assert _claim(claims, "chain")[1] == "fail"
    assert not ok


def test_authorizer_claim_is_the_verifiers_own_judgment(bundle):
    from tenuo.cli import check_receipt_claims

    good, ok_good = check_receipt_claims(bundle["payload"], authorizers=[bundle["signer"]])
    bad, ok_bad = check_receipt_claims(bundle["payload"], authorizers=["ff" * 32])

    assert _claim(good, "authorizer")[1] == "ok" and ok_good
    assert _claim(bad, "authorizer")[1] == "fail" and not ok_bad


def test_request_claim_proves_the_arguments(bundle):
    from tenuo.cli import check_receipt_claims

    claims, ok = check_receipt_claims(
        bundle["payload"], roots=[bundle["root_hex"]], args=bundle["args"]
    )

    # A matching request hash proves the arguments rather than asserting them,
    # and with them the PoP verifies — corroborating the decision instant with
    # a key the signer does not hold.
    assert _claim(claims, "request")[1] == "ok"
    assert _claim(claims, "possession")[1] == "ok"
    assert ok


def test_request_claim_rejects_different_arguments(bundle):
    from tenuo.cli import check_receipt_claims

    claims, ok = check_receipt_claims(
        bundle["payload"],
        roots=[bundle["root_hex"]],
        args={"path": "/data/other.pdf"},
    )

    assert _claim(claims, "request")[1] == "fail"
    assert not ok


def test_an_expired_denial_is_corroborated_by_its_own_chain(bundle):
    """The embedded authority independently supports the stated refusal."""
    from tenuo.cli import check_receipt_claims

    import tenuo_core

    future = int(time.time()) + 86_400
    wire = bundle["client"].issue_denial_receipt(
        [bundle["warrant"]],
        "read_file",
        bundle["args"],
        future,
        "req-deny",
        "warrant-expired",
    )
    payload = tenuo_core.verify_receipt(wire)

    claims, ok = check_receipt_claims(payload, roots=[bundle["root_hex"]])

    name, status, detail = _claim(claims, "chain")
    assert status == "ok", detail
    assert "corroborates" in detail
    assert ok


def test_supplying_an_srl_the_receipt_never_committed_to_fails(bundle):
    from tenuo.cli import check_receipt_claims

    claims, ok = check_receipt_claims(bundle["payload"], srl_bytes=b"anything")

    assert _claim(claims, "revocation")[1] == "fail"
    assert not ok
