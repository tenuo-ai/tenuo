"""file_approval_handler: one handler for every warrant, answered by approval files."""

import time

import pytest

from tenuo import SigningKey, WarrantTemplate
from tenuo.approval import ApprovalDenied, ApprovalRequest, ApprovalRequired
from tenuo.local import file_approval_handler
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError, update_revocations
from tenuo.local_cli.workspace import Workspace
from tenuo_core import py_compute_request_hash

GATED = {"order_id": "A-1001", "amount_cents": 6000}


@pytest.fixture
def gated(tmp_path):
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
    return workspace, warrant


def request_for(warrant, arguments=GATED, chain=None):
    digest = bytes(py_compute_request_hash(warrant.id, "refund", arguments, warrant.holder_key))
    return ApprovalRequest.for_warrant_gate(
        "refund", arguments, warrant, digest, holder_key=warrant.holder_key, warrant_chain=chain
    )


def pending_file(workspace):
    (path,) = (workspace.path / "requests").glob("*.yaml")
    return path


def answer(workspace, path, *extra):
    assert main(["--home", str(workspace.path), "approval", *extra, "--file", str(path), "--yes"]) == 0


def test_waits_then_returns_the_approvers_signature(gated):
    workspace, warrant = gated
    handler = file_approval_handler(workspace.path)
    with pytest.raises(ApprovalRequired, match="tenuo-cli approval show"):
        handler(request_for(warrant, chain=[warrant]))
    answer(workspace, pending_file(workspace), "approve")
    signed = handler(request_for(warrant, chain=[warrant]))
    pop = bytes(warrant.sign(workspace.signing_key("agent"), "refund", GATED, int(time.time())))
    workspace.authorizer().check_chain([warrant], "refund", GATED, pop, [signed])


def test_one_handler_serves_every_warrant(gated):
    workspace, warrant = gated
    other = WarrantTemplate(
        {
            "version": 2,
            "ttl": "30m",
            "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}},
            "approvals": {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"refund": "always"}},
        }
    ).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    handler = file_approval_handler(workspace.path)
    for w in (warrant, other):
        with pytest.raises(ApprovalRequired):
            handler(request_for(w, chain=[w]))
    assert len(list((workspace.path / "requests").glob("*.yaml"))) == 2


def test_refusal_is_returned_as_a_denial(gated):
    workspace, warrant = gated
    handler = file_approval_handler(workspace.path)
    with pytest.raises(ApprovalRequired):
        handler(request_for(warrant, chain=[warrant]))
    answer(workspace, pending_file(workspace), "deny", "--reason", "Duplicate refund")
    with pytest.raises(ApprovalDenied, match="Duplicate refund"):
        handler(request_for(warrant, chain=[warrant]))


def test_request_without_a_chain_is_refused(gated):
    workspace, warrant = gated
    with pytest.raises(DocumentError, match="no warrant chain"):
        file_approval_handler(workspace.path)(request_for(warrant))
    assert not list((workspace.path / "requests").glob("*.yaml"))


def test_chain_that_does_not_match_the_request_is_refused(gated):
    workspace, warrant = gated
    other = WarrantTemplate(
        {"version": 2, "ttl": "30m", "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}}}
    ).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    with pytest.raises(DocumentError):
        file_approval_handler(workspace.path)(request_for(warrant, chain=[other]))


def test_untrusted_chain_is_refused(gated):
    workspace, _ = gated
    stranger = WarrantTemplate(
        {"version": 2, "ttl": "30m", "capabilities": {"refund": {"order_id": "any", "amount_cents": "any"}}}
    ).mint(SigningKey.generate(), workspace.public_key("agent"))
    with pytest.raises(Exception):
        file_approval_handler(workspace.path)(request_for(stranger, chain=[stranger]))
    assert not list((workspace.path / "requests").glob("*.yaml"))


def test_revocation_after_approval_still_refuses(gated):
    workspace, warrant = gated
    handler = file_approval_handler(workspace.path)
    with pytest.raises(ApprovalRequired):
        handler(request_for(warrant, chain=[warrant]))
    answer(workspace, pending_file(workspace), "approve")
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
    with pytest.raises(Exception):
        handler(request_for(warrant, chain=[warrant]))


def test_inside_a_temporal_activity_pending_is_retryable(gated, monkeypatch):
    pytest.importorskip("temporalio")
    from temporalio import activity
    from temporalio.exceptions import ApplicationError

    workspace, warrant = gated
    monkeypatch.setattr(activity, "in_activity", lambda: True)
    with pytest.raises(ApplicationError) as raised:
        file_approval_handler(workspace.path)(request_for(warrant, chain=[warrant]))
    assert raised.value.type == "ApprovalPending" and not raised.value.non_retryable


def test_handler_reads_no_private_keys(gated):
    workspace, warrant = gated
    for private in workspace.path.glob("keys/*.key"):
        private.unlink()
    with pytest.raises(ApprovalRequired):
        file_approval_handler(workspace.path)(request_for(warrant, chain=[warrant]))
