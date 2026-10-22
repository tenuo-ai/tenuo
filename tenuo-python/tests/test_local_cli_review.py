"""Warrant review: plain-language authority and attack inputs that get through."""

import json
from pathlib import Path

import pytest
import yaml

from tenuo import SigningKey, WarrantTemplate
from tenuo.local_cli import main
from tenuo.local_cli.review import probes, kind, review_chain, review_template
from tenuo.local_cli.workspace import Workspace

LOOSE = {
    "version": 2,
    "ttl": "8h",
    "capabilities": {
        "read_file": {"path": {"pattern": "src/*"}},
        "write_file": {"path": {"regex": "src/"}, "content": "any"},
        "run_command": {"cmd": "any"},
        "fetch": {"url": {"url_pattern": "https://*"}},
        "refund": {"order_id": "any", "amount_cents": "1.."},
    },
}


def tight(root):
    return {
        "version": 2,
        "ttl": "30m",
        "capabilities": {
            "read_file": {"path": {"subpath": str(root)}},
            "write_file": {"path": {"subpath": str(root)}, "content": "any"},
            "run_command": {"cmd": ["pytest", "git status"]},
            "fetch": {"url": {"url_pattern": "https://docs.python.org/3/*"}},
            "search": {"query": "any"},
            "refund": {"order_id": "A-1001", "amount_cents": "1..12000"},
        },
    }


def by_place(result):
    return {(f.get("tool"), f.get("argument")): f for f in result["findings"]}


def test_loose_template_reports_what_gets_through():
    result = review_template(WarrantTemplate(LOOSE))
    found = by_place(result)
    assert "src/../.env" in found["read_file", "path"]["allowed_inputs"]
    assert "/tmp/elsewhere/src/x" in found["write_file", "path"]["allowed_inputs"]
    assert "cat ~/.tenuo/keys/issuer.key" in found["run_command", "cmd"]["allowed_inputs"]
    assert found["fetch", "url"]["problem"].startswith('"https://*" matches no URL')
    assert found["refund", "amount_cents"]["severity"] == "high"
    assert found["refund", None]["problem"] == "Runs without approval."
    assert found[None, None]["problem"] == "Valid for 8h."
    assert ("write_file", "content") not in found
    assert [f["severity"] for f in result["findings"]] == sorted(
        (f["severity"] for f in result["findings"]), key=["high", "medium", "low"].index
    )


def test_tight_template_has_no_findings(tmp_path):
    result = review_template(WarrantTemplate(tight(tmp_path)))
    assert [(f["tool"], f["problem"]) for f in result["findings"]] == [("refund", "Runs without approval.")]
    assert result["allows"]["run_command"]["cmd"] == "one of: pytest, git status"
    assert result["allows"]["refund"]["amount_cents"] == "1 to 12000"


@pytest.mark.parametrize("document", [LOOSE, None])
def test_allowed_inputs_match_the_issued_warrant(tmp_path, document):
    """Every reported input is allowed by the real verifier check; every other probe is denied."""
    document = document or tight(tmp_path)
    template = WarrantTemplate(document)
    warrant = template.mint(SigningKey.generate(), SigningKey.generate().public_key)
    reported = {
        (f.get("tool"), f.get("argument")): set(f.get("allowed_inputs", []))
        for f in review_chain([warrant])["findings"]
    }
    for tool, arguments in template._capabilities.items():
        if len(arguments) != 1:
            continue
        ((argument, constraint),) = arguments.items()
        for value in probes(constraint, kind(argument, tool)):
            allowed = warrant.check_constraints(tool, {argument: value}) is None
            assert allowed == (value in reported.get((tool, argument), set())), (tool, value)


def test_argument_kinds():
    assert kind("file_path") == "path"
    assert kind("amount_cents") == "money"
    assert kind("webhook_url") == "url"
    assert kind("body") == "text"
    assert kind("order_id") == "value"
    assert kind("query") == "text"
    assert kind("query", tool="run_sql") == "command"
    # Recipients match whole names: in_reply_to is a Message-ID, not an address.
    assert kind("to") == kind("bcc") == "recipient"
    assert kind("in_reply_to") == "value"
    # Filters are bounded by the path they search, not locations themselves.
    assert kind("file_glob") == kind("pattern") == "text"
    assert kind("old_string") == kind("new_string") == "text"


def test_optional_is_described_and_reviewed_by_its_inner_constraint():
    pytest.importorskip("tenuo_core").Optional  # tenuo#923
    result = review_template(WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {
        "terminal": {"command": ["pytest -q"], "timeout": {"optional": "1..600"}},
        "read_file": {"path": {"subpath": "/srv/app"}, "offset": {"optional": "any"}},
        "fetch": {"url": {"optional": "any"}},
    }}))
    assert result["allows"]["terminal"]["timeout"] == "optional: 1 to 600"
    assert result["allows"]["read_file"]["offset"] == "optional: any value"
    found = by_place(result)
    assert found["fetch", "url"]["severity"] == "high"  # absent is fine; present, it's any URL
    assert found["read_file", "offset"]["severity"] == "low"


def test_free_form_values_are_low_not_medium():
    result = review_template(WarrantTemplate({"version": 2, "ttl": "30m", "capabilities": {
        "patch": {"path": {"subpath": "/srv/app"}, "old_string": "any", "new_string": "any"},
        "search_files": {"path": {"subpath": "/srv/app"}, "pattern": "any", "file_glob": "any", "limit": "any"},
        "send_gmail_message": {"to": "bob@vendor.com", "in_reply_to": "any"},
    }}))
    severities = {(f.get("tool"), f.get("argument")): f["severity"] for f in result["findings"]}
    assert not any(s == "high" for s in severities.values()), severities
    assert severities.get(("search_files", "limit")) == "low"
    assert ("patch", "old_string") not in severities and ("search_files", "file_glob") not in severities


def test_validate_reports_literal_wildcards_as_findings(tmp_path, capsys):
    path = tmp_path / "t.yaml"
    path.write_text(
        "version: 2\nttl: 5m\ncapabilities:\n"
        "  get_order:\n    order_id: A-*\n"
        "  list_files:\n    path: {pattern: /data/*}\n    kind: [csv, '*.tsv']\n"
    )
    assert main(["--home", str(tmp_path / ".tenuo"), "--json", "template", "validate", "--file", str(path)]) == 0
    lines = json.loads(capsys.readouterr().out)["review"]["findings"]
    assert "medium: get_order.order_id: 'A-*' is an exact value, not a wildcard." in lines
    assert "medium: list_files.kind: '*.tsv' is an exact one_of value, not a wildcard." in lines


def test_home_directory_subpath_and_sql_query():
    root = {
        "version": 2,
        "ttl": "30m",
        "capabilities": {
            "read_file": {"path": {"subpath": str(Path.home())}},
            "run_sql": {"query": "any"},
        },
    }
    found = by_place(review_template(WarrantTemplate(root)))
    assert found["read_file", "path"]["problem"].startswith("This directory contains secrets")
    assert str(Path.home() / ".ssh" / "id_rsa") in found["read_file", "path"]["allowed_inputs"]
    assert found["run_sql", "query"]["severity"] == "high"


@pytest.fixture
def workspace(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(LOOSE))
    return workspace, path


def test_cli_validate_issue_and_review(workspace, capsys):
    workspace, path = workspace
    prefix = ["--home", str(workspace.path), "--json"]
    assert main([*prefix, "template", "validate", "--file", str(path)]) == 0
    brief = json.loads(capsys.readouterr().out)["review"]
    assert brief["summary"].startswith("5 tools, valid for 8h: 4 high, 1 medium")
    assert any('Gets through: "src/../.env"' in line for line in brief["findings"])
    assert brief["details"] == f"tenuo-cli warrant review --file {path}"

    out = path.parent / "agent.warrant"
    assert main([*prefix, "warrant", "issue", "--template", str(path), "--holder", "agent", "--out", str(out)]) == 0
    issued = json.loads(capsys.readouterr().out)
    assert issued["review"]["summary"].startswith("5 tools, expires in")
    assert issued["review"]["details"] == f"tenuo-cli warrant review --file {out}"

    assert main([*prefix, "warrant", "review", "--file", str(out)]) == 0
    full = json.loads(capsys.readouterr().out)["review"]
    assert full["subject"] == "warrant" and full["id"] == issued["warrant"]["id"]
    assert full["delegation"] == "can delegate narrower copies"
    assert main([*prefix, "warrant", "review", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["review"]["subject"] == "template"


def test_cli_review_needs_no_workspace(tmp_path, capsys):
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(tight(tmp_path)))
    assert main(["--home", str(tmp_path / "missing"), "--json", "warrant", "review", "--file", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["review"]["summary"] == "6 tools, valid for 30m: 1 low"


def nested_warrant():
    from tenuo import All, AnyOf, Exact, Not, Range, Regex, Warrant

    key = SigningKey.generate()
    path = All([Regex(r"^(public|web)/"), Not(Regex(r"(^|/)\.env")), Not(Regex(r"(^|/)\.\.(/|$)"))])
    return (
        Warrant.mint_builder()
        .holder(key.public_key)
        .ttl(600)
        .capability("read_file", path=path)
        .capability("refund", amount_cents=AnyOf([Range(1, 5000), Exact("0")]))
        .mint(key)
    )


def test_nested_constraints_are_described_from_the_signed_payload():
    allows = review_chain([nested_warrant()])["allows"]
    assert allows["read_file"]["path"] == (
        'all of: regex "^(public|web)/"; not (regex "(^|/)\\\\.env"); not (regex "(^|/)\\\\.\\\\.(/|$)")'
    )
    assert allows["refund"]["amount_cents"] == 'any of: 1 to 5000; exactly "0"'


def test_nested_template_constraints_are_described(tmp_path):
    from tenuo import All, Not, Regex

    template = WarrantTemplate({"version": 2, "ttl": "5m", "capabilities": {"read_file": {"path": "any"}}})
    template._capabilities["read_file"]["path"] = All([Regex("^src/"), Not(Regex(r"\.env"))])
    assert review_template(template)["allows"]["read_file"]["path"] == ('all of: regex "^src/"; not (regex "\\\\.env")')


def test_every_wire_type_decodes():
    from tenuo import (
        CEL,
        All,
        AnyOf,
        Cidr,
        Contains,
        Exact,
        Not,
        NotOneOf,
        OneOf,
        Pattern,
        Range,
        Regex,
        Subpath,
        Subset,
        UrlPattern,
        UrlSafe,
        Warrant,
        Wildcard,
    )
    from tenuo.local_cli import payload

    constraints = [
        Exact("a"),
        Pattern("s/*"),
        Range(1, 5),
        OneOf(["a"]),
        Regex("^a"),
        NotOneOf(["x"]),
        Cidr("10.0.0.0/8"),
        UrlPattern("https://x.com/*"),
        Contains(["a"]),
        Subset(["a"]),
        All([Exact("a")]),
        AnyOf([Exact("a")]),
        Not(Exact("a")),
        CEL("value > 1"),
        Wildcard(),
        Subpath("/p"),
        UrlSafe(allow_domains=["x.com"]),
    ]
    key = SigningKey.generate()
    builder = Warrant.mint_builder().holder(key.public_key).ttl(60)
    builder = builder.capability("t", **{f"a{i}": c for i, c in enumerate(constraints)})
    trees = payload.constraint_trees(builder.mint(key))["t"]
    assert len(trees) == len(constraints)
    assert all(payload.describe(tree) for tree in trees.values())


def test_unreadable_payload_falls_back_to_repr(monkeypatch):
    from tenuo.local_cli import payload

    with pytest.raises(ValueError):
        payload.decode(b"\x82\x01")
    monkeypatch.setattr(payload, "constraint_trees", lambda warrant: {})
    assert review_chain([nested_warrant()])["allows"]["read_file"]["path"] == "All(...)"
