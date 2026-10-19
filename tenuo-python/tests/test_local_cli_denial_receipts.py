"""Calls refused before the runtime evaluates them still leave a signed receipt."""

import json
import time

import pytest
import yaml

from tenuo.local_cli import main
from tenuo.local_cli.runtime import LocalAuthority
from tenuo.local_cli.warrants import load_chain
from tenuo.local_cli.workspace import Workspace

ARGS = {"order_id": "A-1001"}


@pytest.fixture
def home(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    return workspace.path


def cli(home, capsys, *args):
    code = main(["--home", str(home), "--json", *args])
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else {})


def issue(home, capsys, tmp_path, ttl):
    request = tmp_path / "request.yaml"
    request.write_text(yaml.safe_dump({
        "version": 2, "kind": "warrant-request", "holder": "agent", "ttl": ttl,
        "capabilities": {"get_order": {"order_id": "any"}},
    }))
    code, out = cli(home, capsys, "warrant", "issue", "--request", str(request))
    assert code == 0
    return out["warrant"]["id"], load_chain(out["files"][0])


def receipts(home, capsys):
    code, out = cli(home, capsys, "audit", "list")
    assert code == 0
    return out["decisions"]


def assert_receipts_verify(home, capsys):
    code, _ = cli(home, capsys, "audit", "verify")
    assert code == 0


def test_expired_warrant_denial_is_receipted(home, capsys, tmp_path):
    wid, chain = issue(home, capsys, tmp_path, "1s")
    time.sleep(2.1)
    authority = LocalAuthority(path=home, key="agent", announce=False)
    assert authority.record_denial("get_order", ARGS, "warrant-expired", chain=chain)
    [receipt] = receipts(home, capsys)
    assert (receipt["decision"], receipt["tool"], receipt["warrant_id"], receipt["reason"]) == (
        "DENY", "get_order", wid, "warrant-expired")
    assert receipt["signer_recognized"] is True
    assert_receipts_verify(home, capsys)


def test_revoked_warrant_denial_is_receipted(home, capsys, tmp_path):
    wid, chain = issue(home, capsys, tmp_path, "10m")
    assert cli(home, capsys, "revocations", "add", "--id", wid)[0] == 0
    authority = LocalAuthority(path=home, key="agent", announce=False)
    assert authority.record_denial("get_order", ARGS, "warrant-revoked", chain=chain)
    [receipt] = receipts(home, capsys)
    assert (receipt["warrant_id"], receipt["reason"]) == (wid, "warrant-revoked")
    assert_receipts_verify(home, capsys)


def test_denial_without_authority_never_raises(home, capsys):
    authority = LocalAuthority(path=home, key="agent", announce=False)
    recorded = authority.record_denial("get_order", ARGS, "authority-missing")
    if recorded:
        rows = receipts(home, capsys)
        assert [(r["decision"], r["warrant_id"], r["reason"]) for r in rows] == [("DENY", None, "authority-missing")]
        assert_receipts_verify(home, capsys)
    else:
        # Native cores that only sign denials carrying a warrant chain write nothing.
        path = home / Workspace(home).config["audit"]["receipts"]
        assert not path.exists() or path.read_text() == ""
