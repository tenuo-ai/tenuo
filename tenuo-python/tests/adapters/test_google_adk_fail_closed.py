"""Google ADK guard and plugin fail closed in a real Runner loop.

Runs ``InMemoryRunner`` with a scripted ``BaseLlm`` in a subprocess (other
google_adk test modules mock ``google.adk`` in ``sys.modules``) and asserts
that tool bodies the policy forbids never run, and that denials come back
to the model as results instead of ending the run.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

_PROBE = "import google.adk.runners, google.adk.plugins"

_SCRIPT = textwrap.dedent(
    """
    import asyncio, builtins, json
    from google.adk.agents import Agent
    from google.adk.models import BaseLlm, LlmResponse
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from tenuo import Pattern, Range, SigningKey, Warrant, Wildcard
    from tenuo.approval import cli_prompt
    from tenuo.constraints import Subpath, UrlSafe
    from tenuo.google_adk import GuardBuilder, ScopedWarrant, TenuoGuard, TenuoPlugin, scoped_warrant

    ran = []

    def fetch(url: str, timeout: int = 5, headers: str = "") -> str:
        \"\"\"Fetch.\"\"\"
        ran.append("fetch")
        return "ok"

    def read_file(path: str = "/etc/passwd") -> str:
        \"\"\"Read a file.\"\"\"
        ran.append("read_file:" + path)
        return "contents"

    def run_cmd(_cmd: str) -> str:
        \"\"\"Run a command.\"\"\"
        ran.append("run_cmd:" + _cmd)
        return "ran"

    def transfer_funds(amount: int) -> str:
        \"\"\"Transfer funds.\"\"\"
        ran.append("transfer_funds")
        return "TRANSFERRED"

    class ScriptedLlm(BaseLlm):
        model: str = "scripted"
        call: list = []

        async def generate_content_async(self, llm_request, stream=False):
            last = llm_request.contents[-1]
            if any(p.function_response for p in last.parts or []):
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="done")]))
                return
            name, args = self.call
            yield LlmResponse(content=types.Content(
                role="model", parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))]))

    async def run(tool, args, *, callback=None, plugins=(), state=None, agent_name="assistant"):
        kw = {"before_tool_callback": callback} if callback is not None else {}
        agent = Agent(name=agent_name, model=ScriptedLlm(call=[tool.__name__, args]), tools=[tool], **kw)
        runner = InMemoryRunner(agent=agent, app_name="app", plugins=list(plugins))
        session = await runner.session_service.create_session(app_name="app", user_id="u", state=state or {})
        responses = []
        async for event in runner.run_async(
            user_id="u", session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part.from_text(text="go")]),
        ):
            for part in (event.content.parts if event.content else None) or []:
                if part.function_response:
                    responses.append(part.function_response.response)
        return responses

    issuer, agent_key, approver = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    read_warrant = (Warrant.mint_builder().capability("read_file", path=Subpath("/data"))
                    .holder(agent_key.public_key).ttl(3600).mint(issuer))
    gated = (Warrant.mint_builder().capability("transfer_funds", amount=Range(0, 100_000))
             .approval_gates({"transfer_funds": {"args": None, "message": "confirm"}})
             .required_approvers([approver.public_key]).min_approvals(1)
             .holder(agent_key.public_key).ttl(3600).mint(issuer))

    def guard_t1(**allow):
        b = GuardBuilder()
        for tool, constraints in allow.items():
            b = b.allow(tool, **constraints)
        return b.build().before_tool

    def gated_guard(handler):
        b = GuardBuilder().with_warrant(gated, agent_key).with_trusted_roots([issuer.public_key])
        if handler is not None:
            b = b.on_approval(handler)
        return b.build()

    def plugin(**kw):
        return TenuoPlugin(signing_key=agent_key, trusted_roots=[issuer.public_key], **kw)

    def scoped_state(warrant, agent):
        state = {}
        with scoped_warrant(state, warrant, agent_name=agent):
            return dict(state)

    answers = {"value": "n"}
    builtins.input = lambda *_: answers["value"]

    CASES = {
        # A1: Tier 1 closed world
        "wildcard_does_not_admit_unlisted": lambda: run(
            fetch, {"url": "https://example.com", "timeout": 1, "headers": "evil"},
            callback=guard_t1(fetch={"url": UrlSafe(), "timeout": Wildcard()})),
        "listed_args_allowed": lambda: run(
            fetch, {"url": "https://example.com", "timeout": 1, "headers": "h"},
            callback=guard_t1(fetch={"url": UrlSafe(), "timeout": Wildcard(), "headers": Wildcard()})),
        "omitted_constrained_arg": lambda: run(
            read_file, {}, callback=guard_t1(read_file={"path": Subpath("/data")})),
        "underscore_arg_checked": lambda: run(
            run_cmd, {"_cmd": "rm -rf /"}, callback=guard_t1(run_cmd={"_cmd": Pattern("ls*")})),
        "underscore_arg_allowed": lambda: run(
            run_cmd, {"_cmd": "ls -l"}, callback=guard_t1(run_cmd={"_cmd": Pattern("ls*")})),
        "tier1_warrant_omitted_arg": lambda: run(
            read_file, {}, callback=TenuoGuard(warrant=read_warrant, require_pop=False).before_tool),
        # A2: ScopedWarrant scope enforced by the guard itself
        "guard_scoped_other_agent": lambda: run(
            read_file, {"path": "/data/a"},
            callback=TenuoGuard(signing_key=agent_key, trusted_roots=[issuer.public_key]).before_tool,
            state={"__tenuo_warrant__": ScopedWarrant(read_warrant.to_base64(), "research_agent")},
            agent_name="other_agent"),
        "guard_scoped_same_agent": lambda: run(
            read_file, {"path": "/data/a"},
            callback=TenuoGuard(signing_key=agent_key, trusted_roots=[issuer.public_key]).before_tool,
            state={"__tenuo_warrant__": ScopedWarrant(read_warrant.to_base64(), "research_agent")},
            agent_name="research_agent"),
        # A3: documented session-state patterns run under InMemoryRunner
        "plugin_scoped_warrant_object": lambda: run(
            read_file, {"path": "/data/a"}, plugins=[plugin(warrant_key="my_warrant")],
            state={"my_warrant": ScopedWarrant(read_warrant, "research_agent")}, agent_name="research_agent"),
        "plugin_scoped_warrant_object_other_agent": lambda: run(
            read_file, {"path": "/data/a"}, plugins=[plugin(warrant_key="my_warrant")],
            state={"my_warrant": ScopedWarrant(read_warrant, "research_agent")}, agent_name="other_agent"),
        "scoped_warrant_helper_default_key": lambda: run(
            read_file, {"path": "/data/a"}, plugins=[plugin()],
            state=scoped_state(read_warrant, "research_agent"), agent_name="research_agent"),
        # A4: approvals deny with a result instead of ending the run
        "approval_refused": lambda: run(
            transfer_funds, {"amount": 50000}, callback=gated_guard(cli_prompt(approver_key=approver)).before_tool),
        "approval_refused_async": lambda: run(
            transfer_funds, {"amount": 50000},
            callback=gated_guard(cli_prompt(approver_key=approver)).async_before_tool),
        "approval_no_handler": lambda: run(
            transfer_funds, {"amount": 50000}, callback=gated_guard(None).before_tool),
        "plugin_approval_no_handler": lambda: run(
            transfer_funds, {"amount": 50000}, plugins=[plugin(warrant=gated)]),
        "plugin_approval_refused": lambda: run(
            transfer_funds, {"amount": 50000},
            plugins=[plugin(warrant=gated, approval_handler=cli_prompt(approver_key=approver))]),
        "plugin_approval_granted": lambda: run(
            transfer_funds, {"amount": 50000},
            plugins=[plugin(warrant=gated, approval_handler=cli_prompt(approver_key=approver))]),
    }

    async def main():
        out = {}
        for name, case in CASES.items():
            ran.clear()
            answers["value"] = "y" if name.endswith("_granted") else "n"
            try:
                responses = await case()
                error = None
            except Exception as e:  # a crash is a failure the test reports
                responses, error = [], f"{type(e).__name__}: {e}"
            out[name] = {"ran": list(ran), "responses": [json.loads(json.dumps(r, default=str)) for r in responses],
                         "error": error}
        print("RESULT " + json.dumps(out))

    asyncio.run(main())
    """
)

ALLOWED = {
    "listed_args_allowed": ["fetch"],
    "underscore_arg_allowed": ["run_cmd:ls -l"],
    "guard_scoped_same_agent": ["read_file:/data/a"],
    "plugin_scoped_warrant_object": ["read_file:/data/a"],
    "scoped_warrant_helper_default_key": ["read_file:/data/a"],
    "plugin_approval_granted": ["transfer_funds"],
}

# case -> text the denial message must contain
DENIED = {
    "wildcard_does_not_admit_unlisted": "Unknown argument 'headers'",
    "omitted_constrained_arg": "Missing required argument 'path'",
    "underscore_arg_checked": "Argument '_cmd' violates constraint",
    "tier1_warrant_omitted_arg": "Missing required argument 'path'",
    "guard_scoped_other_agent": "scoped to a different agent",
    "plugin_scoped_warrant_object_other_agent": "No warrant",
    "approval_refused": "Approval denied",
    "approval_refused_async": "Approval denied",
    "approval_no_handler": "Approval required",
    "plugin_approval_no_handler": "Approval required",
    "plugin_approval_refused": "Approval denied",
}


@pytest.fixture(scope="module")
def results():
    if subprocess.run([sys.executable, "-c", _PROBE], capture_output=True).returncode != 0:
        pytest.skip("google-adk not installed")
    proc = subprocess.run([sys.executable, "-c", _SCRIPT], capture_output=True, text=True, timeout=300)
    lines = [line for line in proc.stdout.splitlines() if line.startswith("RESULT ")]
    assert lines, proc.stdout[-2000:] + proc.stderr[-4000:]
    return json.loads(lines[-1][len("RESULT "):])


@pytest.mark.parametrize("case", sorted(ALLOWED))
def test_permitted_call_runs(results, case):
    result = results[case]
    assert result["error"] is None, result
    assert result["ran"] == ALLOWED[case], result


@pytest.mark.parametrize("case", sorted(DENIED))
def test_forbidden_call_never_runs_and_is_denied_with_a_result(results, case):
    result = results[case]
    assert result["error"] is None, result  # denied in-band, the run did not crash
    assert result["ran"] == [], result
    assert result["responses"], result
    response = result["responses"][0]
    assert response.get("error") == "authorization_denied", result
    assert DENIED[case] in response.get("message", ""), result
