"""CLI issuance, inspection, full-chain transport and native revocation."""

import json
import time

import pytest
import yaml

from tenuo import Authorizer, SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError, update_revocations
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
    replacement = reissue(original, workspace.signing_key("issuer"), 600)
    assert original[-1].id != replacement[-1].id
    assert describe(original)["capabilities"] == describe(replacement)["capabilities"]
    workspace.authorizer().verify_chain(original)
    workspace.authorizer().verify_chain(replacement)


def test_reissue_refuses_unsupported_claims_instead_of_losing_them(setup):
    workspace, path = setup
    data = yaml.safe_load(path.read_text())
    data["approvals"] = {"keys": [str(workspace.path / "keys/approver.pub")], "required": {"get_order": "always"}}
    original = issue(workspace, WarrantTemplate(data), workspace.public_key("agent"))
    with pytest.raises(DocumentError, match="cannot copy exactly"):
        reissue(original, workspace.signing_key("issuer"), 600)


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
