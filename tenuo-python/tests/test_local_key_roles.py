"""Public-key inputs must not publish private seeds through a signed artifact."""
import base64
import json

import pytest

from tenuo import PublicKey, SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError, keygen, load_public_key, load_signing_key, write_yaml
from tenuo.local_cli.workspace import Workspace


def test_private_paths_and_public_aliases_to_them_are_refused(tmp_path):
    private, public, _ = keygen(tmp_path / "issuer")
    alias = tmp_path / "pretend-public.pub"
    alias.symlink_to(private)
    for path in (private, alias):
        with pytest.raises(DocumentError):
            load_public_key(path)
    with pytest.raises(DocumentError):
        load_signing_key(public)


def test_pem_roles_are_checked_independently_of_filename(tmp_path):
    key = SigningKey.generate()
    private = tmp_path / "pretend-public.pub"
    private.write_text(key.to_pem())
    with pytest.raises(DocumentError):
        load_public_key(private)
    public = tmp_path / "public.pem"
    public.write_text(key.public_key.to_pem())
    assert bytes(load_public_key(public).to_bytes()) == bytes(key.public_key.to_bytes())
    with pytest.raises(DocumentError):
        load_signing_key(public)


def test_agent_request_cannot_read_issuer_private_file_as_approver(tmp_path, capsys):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    request = {"version": 2, "kind": "warrant-request", "holder": "agent", "ttl": "30m",
               "capabilities": {"get_order": {"order_id": "A-1001"}},
               "approvals": {"keys": [str(workspace.path / "keys/issuer.key")], "required": {"get_order": "always"}}}
    path = tmp_path / "request.yaml"
    write_yaml(path, request)
    assert main(["--home", str(workspace.path), "--json", "warrant", "issue", "--request", str(path)]) != 0
    output = capsys.readouterr().out
    assert "private .key file" in json.loads(output)["error"]
    leaked = (workspace.path / "keys/issuer.key").read_text().strip() in output
    assert not leaked
    assert not list((workspace.path / "warrants").glob("*.warrant"))


def test_last_mile_refuses_signer_seed_even_if_it_was_mislabeled_public(tmp_path):
    # Some Ed25519 private seeds also parse as public points. Generate such a
    # throwaway fixture without printing it or relying on a fixed private key.
    for _ in range(256):
        key = SigningKey.generate()
        try:
            public = PublicKey.from_bytes(bytes(key.secret_key_bytes()))
            break
        except Exception:
            continue
    else:
        pytest.fail("could not generate a public-shaped temporary fixture")
    template = WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "A-1001"}}})
    blocked = False
    try:
        template.mint(key, public)
    except Exception as exc:
        blocked = isinstance(exc, DocumentError)
    assert blocked
    disguised = tmp_path / "mislabeled.pub"
    disguised.write_bytes(base64.b64encode(bytes(key.secret_key_bytes())))
    data = template.document
    data["approvals"] = {"keys": [str(disguised)], "required": {"get_order": "always"}}
    template = WarrantTemplate(data)
    blocked = False
    try:
        template.mint(key, SigningKey.generate().public_key)
    except Exception as exc:
        blocked = isinstance(exc, DocumentError)
    assert blocked
