"""CLI issuance, inspection, full-chain transport and native revocation."""

import base64
import json
import time

import pytest
import yaml

from tenuo import Authorizer, SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError, fingerprint, update_revocations
from tenuo.local_cli.warrants import describe, encode_chain, issue, load_chain, reissue
from tenuo.local_cli.workspace import Workspace


@pytest.fixture
def setup(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    document = {"version": 2, "ttl": "30m", "capabilities": {"get_order": {"order_id": "any"}}}
    path = tmp_path / "orders.yaml"
    path.write_text(yaml.safe_dump(document))
    return workspace, path


def test_a06_cli_issue_show_list_verify_revoke(setup, capsys):
    workspace, path = setup
    prefix = ["--home", str(workspace.path), "--json"]
    assert main([*prefix, "warrant", "issue", "--template", str(path), "--holder", "agent"]) == 0
    result = json.loads(capsys.readouterr().out)
    wid = result["warrant"]["id"]
    assert load_chain(result["files"][0])[-1].id == wid
    assert main([*prefix, "warrant", "show", "--id", wid]) == 0
    assert json.loads(capsys.readouterr().out)["warrant"]["verified"] is False
    assert main([*prefix, "warrant", "verify", "--id", wid]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main([*prefix, "revocations", "add", "--id", wid]) == 0
    capsys.readouterr()
    assert main([*prefix, "warrant", "verify", "--id", wid]) == 3
    assert json.loads(capsys.readouterr().out)["valid"] is False
    assert main([*prefix, "warrant", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["warrants"][0]["verified"] is False


def test_a07_delegation_transports_full_chain_and_never_widens(setup):
    workspace, path = setup
    root = issue(workspace, WarrantTemplate.load(path), workspace.public_key("agent"))
    child_holder = SigningKey.generate()
    document = {"version": 2, "ttl": "10m", "capabilities": {"get_order": {"order_id": "A-1001"}}}
    child = issue(workspace, WarrantTemplate(document), child_holder.public_key, parent=root)
    encoded = encode_chain(child)
    from tenuo.local_cli.warrants import decode_chain

    assert [w.id for w in decode_chain(encoded)] == [w.id for w in child]
    workspace.authorizer().verify_chain(child)
    document["capabilities"]["delete_order"] = {"order_id": "any"}
    with pytest.raises(Exception):
        issue(workspace, WarrantTemplate(document), child_holder.public_key, parent=root)
    with pytest.raises(Exception):
        workspace.authorizer().verify_chain([child[-1]])
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [root[-1].id])
    with pytest.raises(Exception):
        workspace.authorizer().verify_chain(child)


def test_a03_request_mints_using_only_recipient_public_key(setup, capsys):
    workspace, path = setup
    data = yaml.safe_load(path.read_text())
    data.update(kind="warrant-request", holder="agent", reason="Check an order")
    path.write_text(yaml.safe_dump(data))
    (workspace.path / "keys/agent.key").unlink()
    assert main(["--home", str(workspace.path), "--json", "warrant", "issue", "--request", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["warrant"]["holder"]


def test_a08_show_decodes_without_trust_and_verify_fails_without_it(setup, capsys):
    workspace, path = setup
    chain = issue(workspace, WarrantTemplate.load(path), workspace.public_key("agent"))
    warrant_path = path.with_suffix(".warrant")
    warrant_path.write_text(encode_chain(chain))
    (workspace.path / "trust/issuer.pub").unlink()
    assert main(["--json", "warrant", "show", "--file", str(warrant_path)]) == 0
    assert json.loads(capsys.readouterr().out)["warrant"]["capabilities"]
    assert main(["--home", str(workspace.path), "warrant", "verify", "--file", str(warrant_path)]) == 3


def test_reissue_changes_id_preserves_scope_and_keeps_old_warrant_valid(setup):
    workspace, path = setup
    original = issue(workspace, WarrantTemplate.load(path), workspace.public_key("agent"))
    replacement = reissue(workspace, original, 600)
    assert original[-1].id != replacement[-1].id
    assert describe(original)["capabilities"] == describe(replacement)["capabilities"]
    workspace.authorizer().verify_chain(original)
    workspace.authorizer().verify_chain(replacement)


def test_reissue_refuses_a_revoked_warrant_but_renews_an_expired_one(setup, capsys):
    workspace, path = setup
    prefix = ["--home", str(workspace.path), "--json"]
    assert main([*prefix, "warrant", "issue", "--template", str(path), "--holder", "agent"]) == 0
    revoked = json.loads(capsys.readouterr().out)["warrant"]["id"]
    assert main([*prefix, "revocations", "add", "--id", revoked]) == 0
    capsys.readouterr()
    assert main([*prefix, "warrant", "reissue", "--id", revoked, "--ttl", "1h"]) != 0
    assert "revoked" in capsys.readouterr().out
    assert len(list((workspace.path / "warrants").glob("*.warrant"))) == 1

    short = path.with_name("short.yaml")
    short.write_text(path.read_text().replace("ttl: 30m", "ttl: 1s"))
    assert main([*prefix, "warrant", "issue", "--template", str(short), "--holder", "agent"]) == 0
    expired = json.loads(capsys.readouterr().out)["warrant"]["id"]
    time.sleep(2.1)
    assert main([*prefix, "warrant", "verify", "--id", expired]) == 3
    capsys.readouterr()
    assert main([*prefix, "warrant", "reissue", "--id", expired, "--ttl", "1h"]) == 0
    renewed = json.loads(capsys.readouterr().out)["warrant"]["id"]
    assert main([*prefix, "warrant", "verify", "--id", renewed]) == 0


def test_holder_flag_is_relative_to_cwd_and_request_holder_to_the_request(setup, tmp_path, monkeypatch, capsys):
    workspace, path = setup
    here, there = SigningKey.generate().public_key, SigningKey.generate().public_key
    folder = tmp_path / "shared"
    folder.mkdir()
    (folder / "orders.yaml").write_text(path.read_text())
    (folder / "agent.pub").write_bytes(base64.b64encode(bytes(there.to_bytes())) + b"\n")
    (tmp_path / "agent.pub").write_bytes(base64.b64encode(bytes(here.to_bytes())) + b"\n")
    monkeypatch.chdir(tmp_path)
    prefix = ["--home", str(workspace.path), "--json"]

    assert main([*prefix, "warrant", "issue", "--template", str(folder / "orders.yaml"), "--holder", "agent.pub"]) == 0
    assert json.loads(capsys.readouterr().out)["warrant"]["holder"] == fingerprint(here)

    request = yaml.safe_load(path.read_text()) | {"kind": "warrant-request", "holder": "agent.pub"}
    (folder / "request.yaml").write_text(yaml.safe_dump(request))
    assert main([*prefix, "warrant", "issue", "--request", str(folder / "request.yaml")]) == 0
    assert json.loads(capsys.readouterr().out)["warrant"]["holder"] == fingerprint(there)


def test_reissue_refuses_unsupported_claims_instead_of_losing_them(setup):
    workspace, path = setup
    data = yaml.safe_load(path.read_text())
    data["approvals"] = {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"get_order": "always"}}
    original = issue(workspace, WarrantTemplate(data), workspace.public_key("agent"))
    with pytest.raises(DocumentError, match="cannot copy exactly"):
        reissue(workspace, original, 600)


def test_a09_expired_warrant_denies_same_operation():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    template = WarrantTemplate({"version": 2, "ttl": "1s", "capabilities": {"get_order": {"order_id": "A-1001"}}})
    warrant = template.mint(issuer, holder.public_key)
    authorizer = Authorizer(trusted_roots=[issuer.public_key])
    authorizer.set_clock_tolerance(0)
    args = {"order_id": "A-1001"}
    authorizer.check_chain(
        [warrant], "get_order", args, bytes(warrant.sign(holder, "get_order", args, int(time.time())))
    )
    time.sleep(2.1)
    with pytest.raises(Exception, match="[Ee]xpir"):
        authorizer.verify_chain([warrant])


def test_issue_replace_swaps_an_existing_out_file(setup, capsys):
    from tenuo.local_cli.commands import main as cli
    from tenuo.local_cli.warrants import load_chain

    workspace, template = setup
    home, out = workspace.path, workspace.path.parent / "agent.warrant"
    assert cli(["--home", str(home), "--json", "warrant", "issue", "--template", str(template),
                "--holder", "agent", "--out", str(out)]) == 0
    first = load_chain(out)[-1].id
    capsys.readouterr()
    assert cli(["--home", str(home), "--json", "warrant", "issue", "--template", str(template),
                "--holder", "agent", "--out", str(out)]) == 1
    assert "--replace" in capsys.readouterr().out
    assert cli(["--home", str(home), "--json", "warrant", "issue", "--template", str(template),
                "--holder", "agent", "--out", str(out), "--replace"]) == 0
    assert load_chain(out)[-1].id != first
