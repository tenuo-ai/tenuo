"""Unsigned attachments route signed grants without activating or revoking them."""


import os

import pytest

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError
from tenuo.local_cli.sessions import attach, detach, read_session, session_path
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


def test_session_commands_belong_to_the_integration(session, capsys, monkeypatch):
    workspace, _ = session
    # Sessions are a Hermes concept: the integration adds `tenuo-cli hermes session`,
    # tenuo.local is the library it builds on.
    from tenuo.local import attach, detach, list_sessions, read_session  # noqa: F401
    from tenuo.local_cli import commands

    with pytest.raises(SystemExit):
        main(["--home", str(workspace.path), "session", "list"])

    monkeypatch.setattr(commands, "integrations", lambda: {})
    assert main(["hermes", "session", "list"]) == 2
    assert "pip install hermes-tenuo" in capsys.readouterr().err

    seen = []

    class Entry:
        def load(self):
            return lambda argv: seen.append((argv, os.environ.get("TENUO_HOME"))) or 0

    # Set, so monkeypatch restores both after the test instead of leaking them.
    monkeypatch.setenv("TENUO_HOME", "unset")
    monkeypatch.setenv("TENUO_JSON", "0")
    monkeypatch.setattr(commands, "integrations", lambda: {"hermes": Entry(), "init": Entry()})
    assert main(["--home", str(workspace.path), "hermes", "session", "attach", "--session", "s", "--help"]) == 0
    assert seen == [(["session", "attach", "--session", "s", "--help"], str(workspace.path))]
    assert os.environ["TENUO_JSON"] == "0"
    # The global --json reaches the integration as TENUO_JSON=1.
    assert main(["--home", str(workspace.path), "--json", "hermes", "session", "list"]) == 0
    assert seen[-1][0] == ["session", "list"] and os.environ.get("TENUO_JSON") == "1"
    seen.pop()
    # The integration's own options reach it, before or after its subcommand.
    for tail in (["--help"], ["--version"], ["--verbose", "session", "list"], ["session", "--help"]):
        assert main(["--home", str(workspace.path), "hermes", *tail]) == 0
        assert seen.pop()[0] == tail
    # An integration can't take over a built-in command: this is the real init,
    # refusing the existing workspace.
    assert main(["--home", str(workspace.path), "init", "--dev"]) == 1
    assert len(seen) == 1


def test_global_options_are_not_abbreviated(capsys):
    with pytest.raises(SystemExit):
        main(["--ho", "/tmp/x", "doctor"])
    assert "invalid choice: '/tmp/x'" in capsys.readouterr().err
