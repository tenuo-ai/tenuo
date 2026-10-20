"""Unsigned attachments route signed grants without activating or revoking them."""

import json

import pytest

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError
from tenuo.local_cli.sessions import attach, detach, read_session, session_path
from tenuo.local_cli.warrants import encode_chain
from tenuo.local_cli.workspace import Workspace


@pytest.fixture
def session(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    warrant = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), workspace.public_key("agent")
    )
    return workspace, warrant


def test_attachments_route_signed_warrants_and_are_independent(session):
    workspace, warrant = session
    attach(workspace, "chat-a", [warrant])
    attach(workspace, "chat-b", [warrant])
    assert read_session(workspace, "chat-a")["warrants"] == [warrant.id]
    attach(workspace, "chat-a", [warrant])
    assert len(read_session(workspace, "chat-a")["warrants"]) == 1
    detach(workspace, "chat-a", warrant.id)
    assert read_session(workspace, "chat-a")["warrants"] == []
    assert read_session(workspace, "chat-b")["warrants"] == [warrant.id]
    workspace.authorizer().verify_chain([warrant])


def test_attachment_needs_only_holder_public_key(session):
    workspace, warrant = session
    (workspace.path / "keys/agent.key").unlink()
    attach(workspace, "chat-a", [warrant])


def test_wrong_holder_and_manifest_identity_are_rejected(session):
    workspace, warrant = session
    other = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}}).mint(
        workspace.signing_key("issuer"), SigningKey.generate().public_key
    )
    with pytest.raises(DocumentError, match="holder"):
        attach(workspace, "chat-a", [other])
    attach(workspace, "chat-a", [warrant])
    path = session_path(workspace, "chat-a")
    path.write_text(path.read_text().replace("session_id: chat-a", "session_id: chat-b"))
    with pytest.raises(DocumentError, match="identity"):
        read_session(workspace, "chat-a")


def test_cli_session_attachment_and_inventory(session, tmp_path, capsys):
    workspace, warrant = session
    path = tmp_path / "grant.warrant"
    path.write_text(encode_chain([warrant]))
    prefix = ["--home", str(workspace.path), "--json", "session"]
    assert main([*prefix, "attach", "--session", "chat-a", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["session"]["session_id"] == "chat-a"
    assert main([*prefix, "list"]) == 0
    assert json.loads(capsys.readouterr().out)["sessions"][0]["warrants"] == [warrant.id]
