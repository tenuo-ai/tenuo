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
    # than it does.
    assert "does not prove" in out


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
