"""Inspect the SDK's real signed receipt sink, not invented audit records."""

import json

import pytest

from tenuo import WarrantTemplate, guard
from tenuo.local_cli import main
from tenuo.local_cli.audit import inspect_audit
from tenuo.local_cli.runtime import LocalAuthority
from tenuo.local_cli.warrants import encode_chain
from tenuo.local_cli.workspace import Workspace


@pytest.fixture
def audited(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent")
    )
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    authority = LocalAuthority(path=workspace.path, warrant=path)
    calls = []

    @guard(tool="get_order")
    def get_order(order_id: str):
        calls.append(order_id)
        return "ready"

    with authority.scope():
        assert get_order("A-1001") == "ready"
        with pytest.raises(Exception):
            get_order("OTHER")
    assert calls == ["A-1001"]
    return workspace, warrant


def test_signed_allow_and_deny_are_inspectable(audited):
    workspace, warrant = audited
    rows = inspect_audit(workspace)["decisions"]
    assert [r["decision"] for r in rows] == ["ALLOW", "DENY"]
    assert all(r["signer_recognized"] and r["warrant_id"] == warrant.id for r in rows)
    assert len(inspect_audit(workspace, denied=True)["decisions"]) == 1
    assert inspect_audit(workspace, warrant="tnu_wrt_missing")["decisions"] == []
    verified = inspect_audit(workspace, verify=True)
    assert verified["valid"] and verified["receipts"] == 2
    assert verified["history_completeness"] == "not proven"


def test_modified_receipt_and_unrecognized_signer_fail_verification(audited):
    workspace, _ = audited
    assert not inspect_audit(workspace, verify=True, authorizers=["approver"])["valid"]
    path = workspace.path / "receipts.jsonl"
    records = path.read_text().splitlines()
    row = json.loads(records[0])
    row["receipt"] = "00" + row["receipt"][2:]
    path.write_text(json.dumps(row) + "\n" + records[1] + "\n")
    assert not inspect_audit(workspace, verify=True)["valid"]


def test_cli_audit_json_and_denial_filter(audited, capsys):
    workspace, _ = audited
    capsys.readouterr()
    prefix = ["--home", str(workspace.path), "--json", "audit"]
    assert main([*prefix, "list", "--denied"]) == 0
    assert json.loads(capsys.readouterr().out)["decisions"][0]["decision"] == "DENY"
    assert main([*prefix, "verify"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_receipts_chain_across_calls_in_one_process(audited):
    workspace, _ = audited
    authority = LocalAuthority(path=workspace.path, warrant=workspace.path.parent / "agent.warrant", announce=False)

    @guard(tool="get_order")
    def get_order(order_id: str):
        return "ready"

    for _ in range(3):  # separate calls, as an adapter makes them
        with authority.scope():
            get_order("A-1001")
    verified = inspect_audit(workspace, verify=True)
    # The fixture's two receipts are one chain; these three continue a second one, from this "process".
    assert verified["valid"] and verified["receipts"] == 5
    assert verified["chains"] == verified["unlinked_receipts"] == 2
    assert "this file holds 2" in verified["message"]
    assert "no predecessor" not in verified["details"]


def test_observed_calls_leave_no_gap_in_the_receipt_chain(audited):
    """Observing with the same adapter must not advance the chain with receipts it never writes."""
    workspace, _ = audited
    authority = LocalAuthority(path=workspace.path, warrant=workspace.path.parent / "agent.warrant", announce=False)

    @guard(tool="get_order")
    def get_order(order_id: str):
        return "ready"

    with authority.scope():
        get_order("A-1001")
    workspace.set_mode("observe")
    authority.decide("get_order", {"order_id": "A-1001"})
    with authority.scope():
        get_order("A-1001")
    workspace.set_mode("enforce")
    with authority.scope():
        get_order("A-1001")
    verified = inspect_audit(workspace, verify=True)
    assert verified["valid"], verified["details"]
    assert verified["chains"] == 2  # the fixture's, and this process's: no break in between
