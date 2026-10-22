"""One parser feeds both Python callers and the CLI."""

import re
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


def test_python_template_constructor_rejects_non_string_argument_names(document):
    document["capabilities"] = {"refund": {1: "any"}}
    with pytest.raises(DocumentError, match="nonempty strings"):
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


def test_optional_arguments_may_be_omitted_but_must_match_when_sent():
    from tenuo import SigningKey, WarrantTemplate

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    template = WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {
        "web_search": {"query": "any", "limit": {"optional": "1..10"}},
        "send_message": {"action": {"optional": "send"}, "target": "telegram:1", "message": "any"},
    }})
    assert template.expanded()["capabilities"]["web_search"]["limit"] == {"optional": {"range": {"min": 1, "max": 10}}}
    warrant = template.mint(issuer, holder.public_key)
    allowed = lambda tool, args: not warrant.why_denied(tool, args).denied  # noqa: E731
    assert allowed("web_search", {"query": "x"})
    assert allowed("web_search", {"query": "x", "limit": 5})
    assert not allowed("web_search", {"query": "x", "limit": 50})
    assert allowed("send_message", {"target": "telegram:1", "message": "m"})
    assert not allowed("send_message", {"action": "react", "target": "telegram:1", "message": "m"})
    assert not allowed("send_message", {"message": "m"})  # target stays required


def test_optional_cannot_nest():
    import pytest
    from tenuo import WarrantTemplate
    from tenuo.local_cli.files import DocumentError

    with pytest.raises(DocumentError):
        WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {"t": {"a": {"optional": {"optional": "x"}}}}})


def test_one_of_accepts_integers_for_numeric_ids():
    from tenuo import SigningKey, WarrantTemplate

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = WarrantTemplate({"version": 2, "ttl": "1h", "capabilities": {
        "pull_request_read": {"pullNumber": [57, 58]}}}).mint(issuer, holder.public_key)
    assert not warrant.why_denied("pull_request_read", {"pullNumber": 57}).denied
    assert warrant.why_denied("pull_request_read", {"pullNumber": 59}).denied


# -- vars -----------------------------------------------------------------------

VARS = {
    "version": 2,
    "ttl": "4h",
    "vars": {"project": {"description": "the project's absolute path"}, "commands": {"default": ["pytest -q"]},
             "branch_prefix": {"default": "agent"}},
    "capabilities": {
        "read_file": {"path": {"subpath": "${project}"}},
        "terminal": {"command": "${commands}", "workdir": ["${project}", "${project}/"]},
        "create_branch": {"branch": {"pattern": "${branch_prefix}/*"}},
    },
}


def test_vars_fill_whole_values_lists_and_text():
    from tenuo.warrant_template import WarrantTemplate

    doc = WarrantTemplate(VARS, values={"project": "/srv/app"}).document
    assert "vars" not in doc
    assert doc["capabilities"]["read_file"]["path"] == {"subpath": "/srv/app"}
    assert doc["capabilities"]["terminal"] == {"command": ["pytest -q"], "workdir": ["/srv/app", "/srv/app/"]}
    assert doc["capabilities"]["create_branch"]["branch"] == {"pattern": "agent/*"}
    doc = WarrantTemplate(VARS, values={"project": "/srv/app", "commands": ["ruff check ."]}).document
    assert doc["capabilities"]["terminal"]["command"] == ["ruff check ."]


@pytest.mark.parametrize("values, message", [
    ({}, "this template needs: --set project=...  (the project's absolute path)"),
    ({"project": "/a", "projet": "/b"}, "--set projet: not one of this template's vars"),
])
def test_vars_report_what_is_missing_or_unknown(values, message):
    from tenuo.local_cli.files import DocumentError
    from tenuo.warrant_template import WarrantTemplate

    with pytest.raises(DocumentError, match=re.escape(message)):
        WarrantTemplate(VARS, values=values)


def test_vars_must_be_declared_and_lists_are_whole_values():
    from tenuo.local_cli.files import DocumentError
    from tenuo.warrant_template import WarrantTemplate

    undeclared = {**VARS, "capabilities": {"read_file": {"path": {"subpath": "${root}"}}}}
    with pytest.raises(DocumentError, match=re.escape("${root} is used but not declared under vars")):
        WarrantTemplate(undeclared, values={"project": "/a"})
    inline_list = {**VARS, "capabilities": {"terminal": {"command": "run ${commands}"}}}
    with pytest.raises(DocumentError, match="is a list"):
        WarrantTemplate(inline_list, values={"project": "/a"})
    plain = {k: v for k, v in VARS.items() if k != "vars"}
    with pytest.raises(DocumentError, match="declares no vars"):
        WarrantTemplate(plain, values={"project": "/a"})
    with pytest.raises(DocumentError, match=re.escape("${project} is used but not declared under vars")):
        WarrantTemplate(plain)


def test_vars_values_are_used_as_written_and_keys_stay_unique():
    from tenuo.local_cli.files import DocumentError
    from tenuo.warrant_template import WarrantTemplate

    with pytest.raises(DocumentError, match=re.escape("the value of project contains ${commands}")):
        WarrantTemplate(VARS, values={"project": "${commands}"})
    nested_default = {**VARS, "vars": {**VARS["vars"], "branch_prefix": {"default": "${project}"}}}
    with pytest.raises(DocumentError, match=re.escape("the value of branch_prefix contains ${project}")):
        WarrantTemplate(nested_default, values={"project": "/a"})
    tools = {"version": 2, "name": "t", "ttl": "1h", "vars": {"tool": {}},
             "capabilities": {"${tool}": {}, "read_file": {}}}
    with pytest.raises(DocumentError, match="'read_file' appears twice"):
        WarrantTemplate(tools, values={"tool": "read_file"})
    assert set(WarrantTemplate(tools, values={"tool": "list_files"}).document["capabilities"]) == {
        "list_files", "read_file"}


def test_cli_issue_takes_set(tmp_path, capsys):
    import json

    import yaml
    from tenuo.local_cli import main

    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(VARS))
    home = ["--home", str(tmp_path / ".tenuo"), "--json"]
    assert main([*home, "init", "--dev"]) == 0
    capsys.readouterr()
    assert main([*home, "warrant", "issue", "--template", str(path), "--holder", "agent"]) == 1
    assert "--set project=" in json.loads(capsys.readouterr().out)["error"]
    assert main([*home, "warrant", "issue", "--template", str(path), "--holder", "agent",
                 "--set", f"project={tmp_path}", "--set", "commands=[git status, git diff]"]) == 0
    caps = json.loads(capsys.readouterr().out)["warrant"]["capabilities"]
    assert caps["terminal"]["command"] == ["git status", "git diff"]


def test_parse_set_reads_lists_and_whole_numbers():
    from tenuo.warrant_template import parse_set

    assert parse_set(["n=412", "prs=[57, 58]", "p=/srv/app", "v=1.5", "t=on"]) == {
        "n": 412, "prs": [57, 58], "p": "/srv/app", "v": "1.5", "t": "on"}
    with pytest.raises(DocumentError):
        parse_set(["novalue"])



def test_review_details_repeat_set():
    from tenuo.local_cli.review import brief

    finding = {"severity": "warning", "problem": "broad", "tool": "read_file"}
    shown = brief({"summary": "1 warning", "findings": [finding]}, "t.yaml", ["project=/srv/my app"])
    assert shown["details"] == "tenuo-cli warrant review --file t.yaml --set 'project=/srv/my app'"


@pytest.mark.parametrize("value", ["any", "1..9"])
def test_filled_in_strings_are_literal(value):
    from tenuo.warrant_template import WarrantTemplate

    doc = {"version": 2, "name": "t", "ttl": "1h", "vars": {"repo": {}},
           "capabilities": {"issue_read": {"repo": "${repo}", "branch": "agent/${repo}", "labels": ["${repo}"]}}}
    caps = WarrantTemplate(doc, values={"repo": value}).document["capabilities"]["issue_read"]
    assert caps["repo"] == {"exact": value}
    assert caps["labels"] == [value]
    from tenuo import SigningKey

    issuer = SigningKey.generate()
    warrant = WarrantTemplate(doc, values={"repo": value}).mint(issuer, issuer.public_key)
    assert type(warrant.capabilities["issue_read"]["repo"]).__name__ == "Exact"


def test_set_lists_read_like_the_template_file():
    from tenuo.local_cli.files import DocumentError
    from tenuo.warrant_template import parse_set

    assert parse_set(["days=[2026-10-22]"]) == {"days": ["2026-10-22"]}
    with pytest.raises(DocumentError, match="not a valid list"):
        parse_set(["commands=[pytest -q"])
    with pytest.raises(DocumentError, match="anchors and aliases"):
        parse_set(["x=[&a [1], *a]"])


def test_literals_only_where_shorthand_is_read():
    from tenuo import SigningKey
    from tenuo.warrant_template import WarrantTemplate

    doc = {"version": 2, "name": "${repo}", "ttl": "1h", "vars": {"repo": {}, "tool": {}},
           "capabilities": {"${tool}": {
               "repo": "${repo}",
               "owner": {"exact": "${repo}"},
               "branch": {"optional": "${repo}"},
               "path": {"pattern": "${repo}/*"},
           }}}
    filled = WarrantTemplate(doc, values={"repo": "any", "tool": "issue_read"})
    caps = filled.document["capabilities"]["issue_read"]
    assert filled.document["name"] == "any"
    assert caps["repo"] == {"exact": "any"}
    assert caps["owner"] == {"exact": "any"}
    assert caps["branch"] == {"optional": {"exact": "any"}}
    assert caps["path"] == {"pattern": "any/*"}
    issuer = SigningKey.generate()
    filled.mint(issuer, issuer.public_key)


def test_numbers_and_quoted_strings_from_set():
    from tenuo import SigningKey
    from tenuo.warrant_template import WarrantTemplate, parse_set

    doc = {"version": 2, "name": "t", "ttl": "1h", "vars": {"pr": {}, "account": {}},
           "capabilities": {"pull_request_read": {"pullNumber": "${pr}", "account": {"exact": "${account}"}}}}
    values = parse_set(["pr=57", 'account="00123"'])
    assert values == {"pr": 57, "account": "00123"}
    issuer = SigningKey.generate()
    warrant = WarrantTemplate(doc, values=values).mint(issuer, issuer.public_key)
    caps = warrant.capabilities["pull_request_read"]
    assert type(caps["pullNumber"]).__name__ == "Exact" and type(caps["account"]).__name__ == "Exact"


def test_set_is_refused_for_a_signed_warrant(tmp_path, capsys):
    import json

    import yaml
    from tenuo.local_cli import main

    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(VARS))
    home = ["--home", str(tmp_path / ".tenuo"), "--json"]
    assert main([*home, "init", "--dev"]) == 0
    assert main([*home, "warrant", "issue", "--template", str(path), "--holder", "agent", "--set",
                 f"project={tmp_path}", "--out", str(tmp_path / "w.warrant")]) == 0
    capsys.readouterr()
    for action in ("show", "review"):
        assert main([*home, "warrant", action, "--file", str(tmp_path / "w.warrant"), "--set", "project=/x"]) == 1
        assert "not a signed warrant" in json.loads(capsys.readouterr().out)["error"]
