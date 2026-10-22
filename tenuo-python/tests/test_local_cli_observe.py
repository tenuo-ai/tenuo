"""Observe mode: local adapters block nothing and record each call for drafting a warrant."""

import json

from tenuo.local_cli.observations import MAX_LISTED_VALUES as MAX
import stat
import time
from types import SimpleNamespace

import pytest

from tenuo import WarrantTemplate
from tenuo.local_cli.commands import main
from tenuo.local_cli.files import DocumentError, update_revocations
from tenuo.local_cli.warrants import encode_chain, load_chain
from tenuo.local_cli.workspace import Workspace

REFUND = {"version": 2, "ttl": "30m", "capabilities": {"refund": {"order_id": "A-1001", "amount_cents": "1..12000"}}}


@pytest.fixture
def observing(tmp_path):
    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    warrant = WarrantTemplate(REFUND).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    return workspace, path


def recorded(workspace):
    path = workspace.path / "observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def refund_tool(calls):
    from langchain_core.tools import tool

    @tool
    def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        calls.append(order_id)
        return "refunded"

    return refund


def test_observe_runs_every_call_and_records_what_enforcement_would_decide(observing):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, path = observing
    calls = []
    protected = TenuoTool.local(refund_tool(calls), path=workspace.path, warrant=path, step="refunds")
    for order, amount in (("A-1001", 5000), ("OTHER", 5000), ("A-1001", 12001)):
        assert protected.invoke({"order_id": order, "amount_cents": amount}) == "refunded"
    assert calls == ["A-1001", "OTHER", "A-1001"]
    lines = recorded(workspace)
    assert [line["decision"] for line in lines] == ["allow", "deny", "deny"]
    assert lines[0]["reason"] is None and all(line["reason"] for line in lines[1:])
    # warrantgen reads run, step, tool and args from each line.
    assert {line["run"] for line in lines} == {lines[0]["run"]}
    assert lines[1] | {"observed_at": None} == lines[1] | {
        "run": lines[0]["run"],
        "step": "refunds",
        "tool": "refund",
        "args": {"order_id": "OTHER", "amount_cents": 5000},
        "warrant_id": str(load_chain(path)[-1].id),
        "observed_at": None,
    }
    assert stat.S_IMODE((workspace.path / "observations.jsonl").stat().st_mode) == 0o600
    # Receipts don't yet record the mode, so observe writes none.
    assert (workspace.path / "receipts.jsonl").read_text() == ""


def test_observe_needs_no_warrant_and_enforce_does(observing):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, _ = observing
    calls = []
    protected = TenuoTool.local(refund_tool(calls), path=workspace.path)
    assert protected.invoke({"order_id": "ANY", "amount_cents": 1}) == "refunded"
    line = recorded(workspace)[0]
    assert (line["decision"], line["reason"], line["warrant_id"]) == (None, "no_warrant", None)
    workspace.set_mode("enforce")
    with pytest.raises(DocumentError, match="needs a warrant"):
        TenuoTool.local(refund_tool(calls), path=workspace.path)
    # A tool built while observing refuses once the workspace switches to enforce.
    with pytest.raises(DocumentError, match="needs a warrant"):
        protected.invoke({"order_id": "ANY", "amount_cents": 1})
    assert calls == ["ANY"]


def test_switching_to_enforce_takes_effect_on_the_next_call(observing):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, path = observing
    calls = []
    protected = TenuoTool.local(refund_tool(calls), path=workspace.path, warrant=path)
    out_of_scope = {"order_id": "OTHER", "amount_cents": 5000}
    assert protected.invoke(out_of_scope) == "refunded"
    assert main(["--home", str(workspace.path), "mode", "enforce"]) == 0
    with pytest.raises(Exception):
        protected.invoke(out_of_scope)
    assert calls == ["OTHER"]
    assert len(recorded(workspace)) == 1


def test_observe_reports_approval_gates_and_revocation_without_blocking(observing):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, path = observing
    gated = dict(
        REFUND, approvals={"keys": [str(workspace.path / "keys/approver.pub")], "required": {"refund": "always"}}
    )
    warrant = WarrantTemplate(gated).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path.write_text(encode_chain([warrant]))
    calls = []
    protected = TenuoTool.local(refund_tool(calls), path=workspace.path, warrant=path)
    args = {"order_id": "A-1001", "amount_cents": 6000}
    assert protected.invoke(args) == "refunded"
    assert not list((workspace.path / "requests").glob("*.yaml"))
    update_revocations(workspace.path / "revocations.srl", workspace.signing_key("issuer"), [warrant.id])
    assert protected.invoke(args) == "refunded"
    assert [(line["decision"], line["reason"]) for line in recorded(workspace)] == [
        ("deny", "approval_required"),
        ("deny", "revoked"),
    ]


@pytest.mark.asyncio
async def test_async_observe(observing):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool
    from tenuo.langchain import TenuoTool

    workspace, path = observing

    @tool
    async def refund(order_id: str, amount_cents: int) -> str:
        """Refund an order."""
        return "refunded"

    protected = TenuoTool.local(refund, path=workspace.path, warrant=path)
    assert await protected.ainvoke({"order_id": "OTHER", "amount_cents": 1}) == "refunded"
    assert recorded(workspace)[0]["decision"] == "deny"


def test_mcp_verifier_observes_with_and_without_a_warrant(observing):
    pytest.importorskip("mcp")
    from tenuo.mcp import MCPVerifier
    from tenuo_core import sign_meta

    workspace, path = observing
    chain, agent = load_chain(path), workspace.signing_key("agent")
    verifier = MCPVerifier.local(path=workspace.path)
    args = {"order_id": "A-1001", "amount_cents": 5000}
    wide = dict(args, order_id="OTHER")
    results = [
        verifier.verify("refund", args),
        verifier.verify(
            "refund", args, meta={"tenuo": sign_meta(chain, agent, "refund", json.dumps(args), int(time.time()))}
        ),
        verifier.verify(
            "refund", wide, meta={"tenuo": sign_meta(chain, agent, "refund", json.dumps(wide), int(time.time()))}
        ),
    ]
    assert all(result.allowed for result in results)
    assert [result.clean_arguments for result in results] == [args, args, wide]
    assert [(line["decision"], line["reason"]) for line in recorded(workspace)] == [
        (None, "no_warrant"),
        ("allow", None),
        ("deny", recorded(workspace)[2]["reason"]),
    ]
    assert recorded(workspace)[2]["reason"]
    workspace.set_mode("enforce")
    assert not verifier.verify("refund", args).allowed


@pytest.mark.asyncio
async def test_fastmcp_server_in_observe_runs_unwarranted_calls_and_records_them(observing):
    pytest.importorskip("fastmcp")
    from fastmcp import Client, FastMCP
    from tenuo.mcp import MCPVerifier, TenuoMiddleware

    workspace, _ = observing
    server = FastMCP("observe-test", middleware=[TenuoMiddleware(MCPVerifier.local(path=workspace.path))])
    calls = []

    @server.tool()
    def refund(order_id: str, amount_cents: int) -> str:
        calls.append(order_id)
        return "refunded"

    async with Client(server) as client:
        result = await client.call_tool("refund", {"order_id": "B-2", "amount_cents": 3})
    assert not result.is_error
    assert calls == ["B-2"]
    assert recorded(workspace)[0]["args"] == {"order_id": "B-2", "amount_cents": 3}


def test_cli_mode_calls_and_doctor(observing, capsys):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, path = observing
    home = ["--home", str(workspace.path), "--json"]
    protected = TenuoTool.local(refund_tool([]), path=workspace.path, warrant=path)
    for order in ("A-1001", "A-1001", "OTHER"):
        protected.invoke({"order_id": order, "amount_cents": 10})
    capsys.readouterr()

    def run(*argv):
        status = main([*home, *argv])
        return status, json.loads(capsys.readouterr().out)

    assert run("mode") == (0, {"mode": "observe"})
    status, summary = run("calls", "summary")
    assert status == 0 and summary["calls"] == 3 and summary["runs"] == 1
    assert summary["tools"] == [
        {
            "tool": "refund",
            "calls": 3,
            "runs": 1,
            "would_allow": 2,
            "would_deny": 1,
            "deny_reasons": {"constraint_violation": 1},
            "denied_on": {"order_id": 1},
            "arguments": {
                "amount_cents": {"distinct": 1, "min": 10, "max": 10},
                "order_id": {"distinct": 2, "values": ["A-1001", "OTHER"]},
            },
        }
    ]
    status, listed = run("calls", "list", "--limit", "1")
    assert listed["matching_calls"] == 3 and listed["calls"][0]["args"]["order_id"] == "OTHER"
    status, doctor = run("doctor")
    assert any("mode: observe" in check["message"] for check in doctor["checks"])
    assert run("mode", "enforce")[1]["mode"] == "enforce"
    assert Workspace(workspace.path).config["mode"] == "enforce"


def test_temporal_local_observe_records_without_changing_audit_settings(observing):
    pytest.importorskip("temporalio")
    from tenuo.exceptions import ConstraintViolation
    from tenuo.temporal import TenuoPluginConfig
    from tenuo.temporal._interceptors import TenuoActivityInboundInterceptor

    workspace, _ = observing
    forwarded = []
    config = TenuoPluginConfig.local(workspace.path, audit_callback=forwarded.append, approval_handler=lambda r: None)
    # Observe is dry_run; the user's audit callback and redaction stay as configured,
    # and an approval handler isn't kept waiting on a gate.
    assert config.dry_run is True and config.redact_args_in_logs is True
    assert config.approval_handler is None
    interceptor = TenuoActivityInboundInterceptor(None, config, "test")
    info = SimpleNamespace(workflow_id="wf", workflow_type="T", workflow_run_id="run-1", activity_type="refund",
                           activity_id="1", task_queue="q")
    warrant = SimpleNamespace(id="w1", tools=["refund"], expires_at=lambda: None)
    interceptor._emit_denial_event(info=info, warrant=warrant, tool="refund", args={"order_id": "OTHER"},
                                   reason="nope", constraint="order_id",
                                   exc=ConstraintViolation("order_id", "value does not match"))
    interceptor._emit_denial_event(info=info, warrant=warrant, tool="refund", args={"order_id": "A-1"},
                                   reason="bad chain", constraint="chain_header_invalid")
    interceptor._emit_allow_event(info=info, warrant=warrant, tool="refund", args={"order_id": "A-1"})
    lines = recorded(workspace)
    assert [(x["decision"], x["reason"], x["argument"]) for x in lines] == [
        ("deny", "constraint_violation", "order_id"),
        ("deny", "chain_invalid", None),  # a diagnostic label, not an argument
        ("allow", None, None),
    ]
    assert lines[0]["args"] == {"order_id": "OTHER"} and lines[0]["run"] == "run-1" and lines[0]["step"] == "refund"
    # The audit sink still gets redacted arguments.
    assert [e.arguments for e in forwarded] == [{"order_id": "[REDACTED]"}] * 3
    workspace.set_mode("enforce")
    assert TenuoPluginConfig.local(workspace.path).dry_run is False


@pytest.mark.asyncio
@pytest.mark.parametrize("with_warrant", [True, False])
async def test_mcp_client_and_stdio_server_both_observe(observing, tmp_path, with_warrant):
    pytest.importorskip("fastmcp")
    import os
    import sys
    from tenuo.mcp import SecureMCPClient

    workspace, path = observing
    script, marker = tmp_path / "server.py", tmp_path / "effects.txt"
    script.write_text(
        "from pathlib import Path\nfrom fastmcp import FastMCP\n"
        "from tenuo.mcp import MCPVerifier, TenuoMiddleware\n"
        f"server = FastMCP('observe', middleware=[TenuoMiddleware(MCPVerifier.local(path={str(workspace.path)!r}))])\n"
        "@server.tool()\ndef refund(order_id: str, amount_cents: int) -> str:\n"
        f"    with Path({str(marker)!r}).open('a') as out: out.write(order_id + '\\n')\n"
        "    return 'refunded'\nserver.run(show_banner=False)\n"
    )
    warrant = {"warrant": path} if with_warrant else {}
    async with SecureMCPClient.local(
        path=workspace.path, command=sys.executable, args=[str(script)], env=dict(os.environ), **warrant
    ) as client:
        for order in ("A-1001", "OTHER"):
            await client.call_tool("refund", {"order_id": order, "amount_cents": 5000})
    assert marker.read_text().splitlines() == ["A-1001", "OTHER"]
    # The client and the server each record the call they saw.
    decisions = sorted((line["args"]["order_id"], line["decision"] or "none") for line in recorded(workspace))
    if with_warrant:
        assert decisions == [("A-1001", "allow"), ("A-1001", "allow"), ("OTHER", "deny"), ("OTHER", "deny")]
    else:
        assert decisions == [("A-1001", "none"), ("A-1001", "none"), ("OTHER", "none"), ("OTHER", "none")]


def test_adapters_in_one_process_share_a_run_unless_tenuo_run_id_groups_them(observing, monkeypatch):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool
    from tenuo.langchain import TenuoTool

    workspace, _ = observing

    @tool
    def get_order(order_id: str) -> str:
        """Look up an order."""
        return "ok"

    lookup = TenuoTool.local(get_order, path=workspace.path)
    refund = TenuoTool.local(refund_tool([]), path=workspace.path)
    lookup.invoke({"order_id": "A-1"})
    refund.invoke({"order_id": "A-1", "amount_cents": 1})
    monkeypatch.setenv("TENUO_RUN_ID", "task-2")
    lookup.invoke({"order_id": "A-2"})
    runs = [line["run"] for line in recorded(workspace)]
    assert runs[0] == runs[1] != "task-2" and runs[2] == "task-2"


def test_constraint_denials_record_the_failing_argument_by_name(observing):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, path = observing
    protected = TenuoTool.local(refund_tool([]), path=workspace.path, warrant=path)
    protected.invoke({"order_id": "A-1001", "amount_cents": 99999})
    protected.invoke({"order_id": "A-1001", "amount_cents": 5})
    assert [line["argument"] for line in recorded(workspace)] == ["amount_cents", None]


def test_verifier_observe_records_the_failing_argument(observing):
    pytest.importorskip("mcp")
    from tenuo.mcp import MCPVerifier
    from tenuo_core import sign_meta

    workspace, path = observing
    chain, agent = load_chain(path), workspace.signing_key("agent")
    args = {"order_id": "OTHER", "amount_cents": 5}
    meta = {"tenuo": sign_meta(chain, agent, "refund", json.dumps(args), int(time.time()))}
    MCPVerifier.local(path=workspace.path).verify("refund", args, meta=meta)
    line = recorded(workspace)[0]
    assert (line["decision"], line["reason"], line["argument"]) == ("deny", "constraint_violation", "order_id")


def test_summary_describes_argument_values_across_runs(observing, monkeypatch, capsys):
    pytest.importorskip("langchain_core")
    from tenuo.langchain import TenuoTool

    workspace, _ = observing
    protected = TenuoTool.local(refund_tool([]), path=workspace.path)
    for run, order in enumerate(("ORD-100", "ORD-205", "ORD-311")):
        monkeypatch.setenv("TENUO_RUN_ID", f"task-{run}")
        protected.invoke({"order_id": order, "amount_cents": 500})
    capsys.readouterr()
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    row = json.loads(capsys.readouterr().out)["tools"][0]
    assert row["no_warrant"] == 3 and row["runs"] == 3
    assert row["arguments"] == {
        "amount_cents": {"distinct": 1, "same_in_every_run": True, "min": 500, "max": 500},
        "order_id": {
            "distinct": 3,
            "same_in_every_run": False,
            "values": ["ORD-100", "ORD-205", "ORD-311"],
            "common_prefix": "ORD-",
        },
    }



def test_summary_reads_paths_as_folders_skips_prose_and_prints_next_commands(observing, monkeypatch, capsys):
    workspace, _ = observing
    from tenuo.local_cli.runtime import LocalAuthority

    authority = LocalAuthority(path=workspace.path, announce=False)
    for run, quarter in enumerate(("q2", "q3")):
        authority.record("read_file", {"path": f"/data/reports/{quarter}.csv"}, run=f"nightly-{run}", step="hermes")
        authority.record(
            "write_file", {"path": f"/data/out/{quarter}.md", "content": f"# {quarter} summary\n"},
            run=f"nightly-{run}", step="hermes",
        )
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    summary = json.loads(capsys.readouterr().out)
    by_tool = {row["tool"]: row["arguments"] for row in summary["tools"]}
    assert by_tool["read_file"]["path"]["common_prefix"] == "/data/reports/"
    # Two short prose values are listed: a command allowlist is built from exactly these.
    assert by_tool["write_file"]["content"] == {
        "distinct": 2, "same_in_every_run": False, "free_text": True, "values": ["# q2 summary\n", "# q3 summary\n"]}
    calls = workspace.path / "observations.jsonl"
    # The first step works with tenuo alone; warrantgen is optional and comes as a comment.
    assert summary["next"][0] == "tenuo-cli template new --out hermes.yaml   # fill in from the summary above"
    assert summary["next"][1] == (
        f"# or draft it from the log: uvx --from git+https://github.com/RajanChavada/warrantgen warrantgen"
        f" template {calls} --step hermes --standing --ttl 7d --out hermes.yaml   # one warrant for every run")
    assert summary["next"][2].startswith("# or: uvx ") and "--from-run nightly-1" in summary["next"][2]
    assert summary["next"][-1] == "tenuo-cli mode enforce"


def test_summary_points_to_calls_list_when_prose_is_hidden(observing, capsys):
    workspace, _ = observing
    from tenuo.local_cli.runtime import LocalAuthority

    authority = LocalAuthority(path=workspace.path, announce=False)
    for n in range(MAX + 1):
        authority.record("terminal", {"command": f"pytest -q tests/test_{n}.py"}, run="r", step="dev")
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    row = json.loads(capsys.readouterr().out)["tools"][0]
    assert row["arguments"]["command"] == {"distinct": MAX + 1, "free_text": True}
    assert row["see"] == "tenuo-cli calls list --tool terminal"


def test_init_points_to_observe_first(tmp_path, capsys):
    assert main(["--home", str(tmp_path / ".tenuo"), "--json", "init", "--dev"]) == 0
    assert "tenuo-cli mode observe" in json.loads(capsys.readouterr().out)["message"]


def test_observed_decision_uses_the_calls_own_approvals(tmp_path):
    from tenuo.local_cli.approvals import request_document, response_approval, sign_response
    from tenuo.local_cli.runtime import LocalAuthority

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    warrant = WarrantTemplate({**REFUND, "approvals": {
        "keys": [str(workspace.path / "keys/approver.pub")],
        "required": {"refund": {"unless": {"amount_cents": "1..5000"}}},
    }}).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    authority = LocalAuthority(path=workspace.path, warrant=path, announce=False)
    args = {"order_id": "A-1001", "amount_cents": 6000}
    assert authority.decide("refund", args)[:2] == ("deny", "approval_required")
    document = request_document([warrant], "refund", args)
    signed = sign_response(document, workspace.authorizer(), workspace.signing_key("approver"))
    approval = response_approval(document, signed, workspace.authorizer())
    # The same call carrying a valid approval is what enforce mode would allow.
    assert authority.decide("refund", args, approvals=[approval])[0] == "allow"


def test_summary_marks_arguments_some_calls_leave_out(observing, capsys):
    workspace, _ = observing
    from tenuo.local_cli.runtime import LocalAuthority

    authority = LocalAuthority(path=workspace.path, announce=False)
    for run, args in (("r1", {"q": "x", "tenant": "A"}), ("r2", {"q": "x"}), ("r3", {"q": "x", "tenant": "A"})):
        authority.record("search", args, run=run, step="s")
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    tenant = json.loads(capsys.readouterr().out)["tools"][0]["arguments"]["tenant"]
    assert tenant["absent_in_calls"] == 1 and tenant["same_in_every_run"] is False


@pytest.mark.asyncio
async def test_mcp_client_observes_an_expired_warrant_without_blocking(tmp_path):
    pytest.importorskip("fastmcp")
    import asyncio
    import os
    import sys
    from tenuo.mcp import SecureMCPClient

    workspace = Workspace(tmp_path / ".tenuo")
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    warrant = WarrantTemplate({**REFUND, "ttl": "1s"}).mint(workspace.signing_key("issuer"), workspace.public_key("agent"))
    path = tmp_path / "agent.warrant"
    path.write_text(encode_chain([warrant]))
    script, marker = tmp_path / "server.py", tmp_path / "effects.txt"
    script.write_text(
        "from pathlib import Path\nfrom fastmcp import FastMCP\n"
        "server = FastMCP('observe')\n"
        "@server.tool()\ndef refund(order_id: str, amount_cents: int) -> str:\n"
        f"    with Path({str(marker)!r}).open('a') as out: out.write(order_id + '\\n')\n"
        "    return 'refunded'\nserver.run(show_banner=False)\n"
    )
    await asyncio.sleep(1.5)
    async with SecureMCPClient.local(
        path=workspace.path, warrant=path, command=sys.executable, args=[str(script)], env=dict(os.environ)
    ) as client:
        await client.call_tool("refund", {"order_id": "A-1001", "amount_cents": 5000})
    assert marker.read_text().splitlines() == ["A-1001"]
    (line,) = recorded(workspace)
    assert line["decision"] == "deny" and line["reason"] != "constraint_violation"


def test_summary_ends_with_the_hand_off_for_the_integration_that_saw_the_calls(observing, capsys):
    workspace, _ = observing
    from tenuo.local_cli.runtime import LocalAuthority

    authority = LocalAuthority(path=workspace.path, announce=False)
    authority.record("ha_get_state", {"entity_id": "light.porch"}, run="20261022_0900_aa", step="telegram:5550001",
                     via="hermes")
    authority.record("read_file", {"path": "/srv/a"}, run="20261022_1000_bb", step="hermes", via="hermes")
    authority.record("read_note", {"path": "team/a.md"}, run="p1", step="notes", via="mcp-server")
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    summary = json.loads(capsys.readouterr().out)
    steps = {s["step"]: s for s in summary["steps"]}
    assert steps["telegram:5550001"] == {"step": "telegram:5550001", "runs": 1, "latest_run": "20261022_0900_aa",
                                         "via": "hermes"}
    nxt = summary["next"]
    # A person's key is attached as is; a plain chat by its latest session ID; file names are safe.
    # Issuing and attaching stay separate: issue the template, then attach the file.
    issue = "tenuo-cli warrant issue --template telegram-5550001.yaml --holder agent --out telegram-5550001.warrant"
    attach = "tenuo-cli hermes session attach --session telegram:5550001 --file telegram-5550001.warrant"
    assert nxt.index(issue) < nxt.index(attach)
    assert "tenuo-cli hermes session attach --session 20261022_1000_bb --file hermes.warrant" in nxt
    (workspace.path / "recipes" / "hermes").mkdir(parents=True)
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    nxt = json.loads(capsys.readouterr().out)["next"]
    assert any(line.startswith("# or issue a recipe: tenuo-cli warrant issue --template ") for line in nxt)
    assert any(line.startswith("# give the warrant to the client that calls this server: SecureMCPClient.local")
               for line in nxt)
    assert "tenuo-cli template new --out telegram-5550001.yaml   # fill in from the summary above" in nxt
    assert nxt[-1] == "tenuo-cli mode enforce"


def test_summary_shows_a_prefix_only_when_it_ends_at_a_separator(observing, capsys):
    workspace, _ = observing
    from tenuo.local_cli.runtime import LocalAuthority

    authority = LocalAuthority(path=workspace.path, announce=False)
    for domain, order in (("light", "ORD-100"), ("lock", "ORD-205")):
        authority.record("t", {"domain": domain, "order": order}, run="r", step="s")
    assert main(["--home", str(workspace.path), "--json", "calls", "summary"]) == 0
    args = json.loads(capsys.readouterr().out)["tools"][0]["arguments"]
    assert "common_prefix" not in args["domain"] and args["order"]["common_prefix"] == "ORD-"
