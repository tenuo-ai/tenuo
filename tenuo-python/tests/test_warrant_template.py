"""One parser feeds both Python callers and the CLI."""

import time

import pytest
import yaml

from tenuo import Authorizer, SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.files import DocumentError, keygen


@pytest.fixture
def document():
    return {
        "version": 2,
        "name": "refunds",
        "ttl": "30m",
        "capabilities": {
            "get_order": {"order_id": "A-1001"},
            "refund": {"order_id": "A-1001", "amount_cents": "1..12000"},
        },
    }


def test_a02_template_mints_to_public_holder_and_enforces_arguments(document):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = WarrantTemplate(document).mint(issuer, holder.public_key)
    authorizer = Authorizer(trusted_roots=[issuer.public_key])
    arguments = {"order_id": "A-1001", "amount_cents": 6000}
    authorizer.check_chain(
        [warrant], "refund", arguments, bytes(warrant.sign(holder, "refund", arguments, int(time.time())))
    )
    for changed in ({"order_id": "OTHER", "amount_cents": 6000}, {"order_id": "A-1001", "amount_cents": 12001}):
        with pytest.raises(Exception):
            authorizer.check_chain(
                [warrant], "refund", changed, bytes(warrant.sign(holder, "refund", changed, int(time.time())))
            )


def test_a05_conditional_gate_uses_signed_core_exempt_semantics(tmp_path, document):
    _, public, _ = keygen(tmp_path / "support")
    document["approvals"] = {
        "keys": [public.name],
        "required": {
            "refund": {"unless": {"amount_cents": "1..5000"}},
        },
    }
    path = tmp_path / "refunds.yaml"
    path.write_text(yaml.safe_dump(document))
    template = WarrantTemplate.load(path)
    warrant = template.mint(SigningKey.generate(), SigningKey.generate().public_key)
    assert not warrant.approval_requirement("refund", {"order_id": "A-1001", "amount_cents": 5000}).requires_approval()
    assert warrant.approval_requirement("refund", {"order_id": "A-1001", "amount_cents": 5001}).requires_approval()
    assert len(warrant.required_approvers()) == 1 and warrant.approval_threshold() == 1


def test_whole_tool_gate(tmp_path, document):
    _, public, _ = keygen(tmp_path / "approver")
    document["approvals"] = {"keys": [str(public)], "required": {"refund": "always"}}
    warrant = WarrantTemplate(document).mint(SigningKey.generate(), SigningKey.generate().public_key)
    assert warrant.approval_requirement("refund", {"order_id": "A-1001", "amount_cents": 1}).requires_approval()


@pytest.mark.parametrize(
    "value",
    [
        "1..5",
        "..5",
        "1..",
        {"range": {"min": 1, "max": 5}},
        {"exact": "any"},
        ["one", "two"],
        "any",
        {"subpath": "/data"},
    ],
)
def test_supported_constraint_forms(document, value):
    document["capabilities"] = {"tool": {"arg": value}}
    WarrantTemplate(document).mint(SigningKey.generate(), SigningKey.generate().public_key)


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        [],
        {"range": {"min": 5, "max": 1}},
        {"range": {"min": float("nan")}},
        {"range": {"min": 2**54}},
        {"wildcard": False},
        {"subpath": "relative"},
        {"typo": "value"},
    ],
)
def test_invalid_constraints_refused(document, value):
    document["capabilities"] = {"tool": {"arg": value}}
    with pytest.raises(DocumentError):
        WarrantTemplate(document)


@pytest.mark.parametrize(
    "update",
    [
        {"version": True},
        {"ttl": "0m"},
        {"unknown": True},
        {"kind": "warrant-request"},
        {"holder": "agent"},
        {"capabilities": {}},
        {"capabilities": {"tool": None}},
    ],
)
def test_invalid_document_refused(document, update):
    document.update(update)
    with pytest.raises(DocumentError):
        WarrantTemplate(document)


def test_a03_ad_hoc_request_is_not_authority(document):
    document.update(kind="warrant-request", holder="agent", reason="Resolve order A-1001")
    template = WarrantTemplate(document)
    document["capabilities"].clear()
    snapshot = template.document
    snapshot["capabilities"].clear()
    assert template.document["capabilities"]


def test_template_commands_work_without_initialized_workspace(tmp_path, capsys):
    path = tmp_path / "order.yaml"
    assert main(["template", "new", "--out", str(path)]) == 0
    assert main(["--json", "template", "validate", "--file", str(path)]) == 0
    assert main(["template", "show", "--file", str(path), "--expanded"]) == 0
    assert "signed: false" in capsys.readouterr().err
    assert main(["template", "new", "--out", str(path)]) == 1
