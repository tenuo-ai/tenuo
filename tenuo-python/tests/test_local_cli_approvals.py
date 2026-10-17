"""An approver reviews signed authority, not claims in an editable request."""

import copy
import json
import time

import pytest

from tenuo import SigningKey, WarrantTemplate
from tenuo.approval import ApprovalDenied
from tenuo.local_cli import main
from tenuo.local_cli.approvals import checked_request, request_document, response_approval, sign_response
from tenuo.local_cli.files import DocumentError, update_revocations, write_yaml
from tenuo.local_cli.workspace import Workspace


@pytest.fixture
def approval(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    template = WarrantTemplate(
        {
            "version": 2,
            "ttl": "30m",
            "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}},
            "approvals": {
                "keys": [str(workspace.path / "keys/approver.pub")],
                "required": {"refund": {"unless": {"amount_cents": "1..5000"}}},
            },
        }
    )
    warrant = template.mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    document = request_document([warrant], "refund", {"order_id": "A-1001", "amount_cents": 6000})
    return workspace, warrant, document


def test_approval_is_native_and_satisfies_the_real_gate(approval):
    workspace, warrant, document = approval
    signed = sign_response(document, workspace.authorizer(), workspace.signing_key("approver"))
    response = response_approval(document, signed, workspace.authorizer())
    args = document["arguments"]
    pop = bytes(warrant.sign(workspace.signing_key("agent"), "refund", args, int(time.time())))
    workspace.authorizer().check_chain([warrant], "refund", args, pop, [response])


def test_signer_is_read_from_signed_warrant_not_request(approval):
    workspace, _, document = approval
    with pytest.raises(DocumentError, match="not an approver"):
        sign_response(document, workspace.authorizer(), SigningKey.generate())
    document["approvers"] = ["attacker-controlled-list"]
    with pytest.raises(DocumentError, match="unknown fields"):
        sign_response(document, workspace.authorizer(), SigningKey.generate())


def test_changed_arguments_and_out_of_scope_calls_cannot_be_approved(approval):
    workspace, warrant, document = approval
    changed = copy.deepcopy(document)
    changed["arguments"]["amount_cents"] = 9000
    with pytest.raises(DocumentError, match="hash"):
        sign_response(changed, workspace.authorizer(), workspace.signing_key("approver"))
    for amount in (5000, 12001):
        changed = request_document([warrant], "refund", {"order_id": "A-1001", "amount_cents": amount})
        with pytest.raises(DocumentError):
            checked_request(changed, workspace.authorizer())


def test_refusal_binds_reason_and_cannot_be_reused_as_approval(approval):
    workspace, _, document = approval
    response = sign_response(
        document, workspace.authorizer(), workspace.signing_key("approver"), reason="Duplicate refund"
    )
    with pytest.raises(ApprovalDenied, match="Duplicate refund"):
        response_approval(document, response, workspace.authorizer())
    changed = dict(document, approval=response["denial"]["signature"])
    with pytest.raises(Exception):
        response_approval(document, changed, workspace.authorizer())
    response["denial"]["reason"] = "Different reason"
    with pytest.raises(Exception):
        response_approval(document, response, workspace.authorizer())


def test_revoked_warrant_refused_before_signing(approval):
    workspace, warrant, document = approval
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
    with pytest.raises(Exception):
        sign_response(document, workspace.authorizer(), workspace.signing_key("approver"))


def test_a10_cli_transports_yaml_without_private_key_in_request(approval, tmp_path, capsys):
    workspace, _, document = approval
    path, out = tmp_path / "request.yaml", tmp_path / "response.yaml"
    write_yaml(path, document)
    prefix = ["--home", str(workspace.path), "--json", "approval"]
    assert main([*prefix, "show", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True
    assert main([*prefix, "approve", "--file", str(path), "--yes", "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "approved"
    for private in workspace.path.glob("keys/*.key"):
        assert private.read_text().strip() not in out.read_text()


@pytest.mark.parametrize("expiry", ["2020-01-01T00:00:00Z", "2100-01-01T00:00:00Z", "2026-10-17T15:00:00"])
def test_invalid_request_expiry_refused(approval, expiry):
    workspace, _, document = approval
    document["expires_at"] = expiry
    with pytest.raises(DocumentError, match="expiry"):
        checked_request(document, workspace.authorizer())
