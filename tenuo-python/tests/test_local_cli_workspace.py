"""Exercise local artifacts with real SDK verification and temporary keys."""

import base64
import json
import stat

import pytest

from tenuo import SigningKey
from tenuo.local_cli import main
from tenuo.local_cli.files import (
    DocumentError,
    keygen,
    load_public_key,
    load_signing_key,
    load_yaml,
    read_revocation_list,
    update_revocations,
)
from tenuo.local_cli.workspace import Workspace


def test_a01_dev_setup_has_separate_identities_and_no_env_secrets(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    assert workspace.config["mode"] == "enforce"
    assert len({bytes(workspace.public_key(n).to_bytes()) for n in ("issuer", "agent", "approver")}) == 3
    assert not (tmp_path / ".env").exists()
    for path in (workspace.path / "keys").glob("*.key"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    workspace.authorizer()
    before = (workspace.path / "keys/issuer.key").read_bytes()
    with pytest.raises(FileExistsError):
        workspace.initialize(dev=True)
    assert (workspace.path / "keys/issuer.key").read_bytes() == before


def test_empty_workspace_is_not_enforcement_ready(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize()
    with pytest.raises(DocumentError, match="no trusted issuers"):
        workspace.authorizer()


@pytest.mark.parametrize("encoding", ["base64", "hex", "pem"])
def test_key_formats(tmp_path, encoding):
    private, public, expected = keygen(tmp_path / "agent")
    key = load_signing_key(private)
    if encoding == "hex":
        private.write_text(bytes(key.secret_key_bytes()).hex())
        public.write_text(bytes(expected.to_bytes()).hex())
    elif encoding == "pem":
        private.write_text(key.to_pem())
        public.write_text(expected.to_pem())
    assert bytes(load_signing_key(private).public_key.to_bytes()) == bytes(expected.to_bytes())
    assert bytes(load_public_key(public).to_bytes()) == bytes(expected.to_bytes())
    with pytest.raises(FileExistsError):
        keygen(tmp_path / "agent")


def test_a17_revocation_reads_legacy_and_writes_native_cbor(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    path = workspace.path / "revocations.srl"
    initial = read_revocation_list(path)
    path.write_bytes(base64.b64encode(bytes(initial.to_bytes())))
    changed = update_revocations(path, workspace.signing_key("issuer"), ["tnu_wrt_test"])
    assert changed.version == 2 and changed.is_revoked("tnu_wrt_test")
    assert path.read_bytes() == bytes(changed.to_bytes())
    before = path.read_bytes()
    with pytest.raises(Exception):
        update_revocations(path, SigningKey.generate(), ["tnu_wrt_other"])
    assert path.read_bytes() == before
    path.unlink()
    with pytest.raises(FileNotFoundError):
        workspace.authorizer()


@pytest.mark.parametrize("text", ["a: 1\na: 2", "a: &a 1\nb: *a", "{1: x}"])
def test_strict_yaml(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(DocumentError):
        load_yaml(path)


def test_cli_json_contains_no_private_material(tmp_path, capsys):
    home = tmp_path / ".tenuo"
    assert main(["--home", str(home), "--json", "init", "--dev"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["development"] is True and output.err == ""
    for key in home.glob("keys/*.key"):
        assert key.read_text().strip() not in output.out
    assert main(["--home", str(home), "--json", "doctor"]) == 0
    assert any(c["status"] == "warning" for c in json.loads(capsys.readouterr().out)["checks"])
    assert main(["--home", str(home), "--json", "init", "--dev"]) == 1


def test_config_unknown_fields_rejected(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    with (workspace.path / "config.yaml").open("a") as stream:
        stream.write("allow_everything: true\n")
    with pytest.raises(DocumentError, match="unknown fields"):
        workspace.authorizer()
