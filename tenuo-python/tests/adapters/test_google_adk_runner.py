"""TenuoPlugin against a real google-adk Runner (no model, no network).

The other google_adk test modules replace ``google.adk`` with mocks in
``sys.modules``, which hid that ADK awaits plugin callbacks, passes their
arguments by keyword (``tool_args=``), and reads ``plugin.name``. This test
runs the real ``InMemoryRunner`` in a subprocess so those mocks cannot leak
in, with a scripted ``BaseLlm`` emitting the tool calls.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

_PROBE = "import google.adk.runners, google.adk.plugins"

_SCRIPT = textwrap.dedent(
    """
    import asyncio
    from typing import AsyncGenerator

    from google.adk.agents import Agent
    from google.adk.models import BaseLlm, LlmResponse
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    from tenuo import SigningKey, Warrant
    from tenuo.constraints import Subpath
    from tenuo.google_adk import TenuoPlugin

    ran = []

    def read_file(path: str) -> str:
        \"\"\"Read a file.\"\"\"
        ran.append(("read_file", path))
        return "contents of " + path

    def delete_file(path: str) -> str:
        \"\"\"Delete a file.\"\"\"
        ran.append(("delete_file", path))
        return "deleted " + path

    CALLS = {
        "allowed": ("read_file", {"path": "/data/report.txt"}),
        "outside": ("read_file", {"path": "/etc/passwd"}),
        "traversal": ("read_file", {"path": "/data/../etc/passwd"}),
        "ungranted": ("delete_file", {"path": "/data/report.txt"}),
    }

    class ScriptedLlm(BaseLlm):
        model: str = "scripted"

        async def generate_content_async(self, llm_request, stream=False) -> AsyncGenerator[LlmResponse, None]:
            last = llm_request.contents[-1]
            if any(p.function_response for p in last.parts):
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="done")]))
                return
            name, args = CALLS[last.parts[0].text]
            yield LlmResponse(content=types.Content(
                role="model", parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))]))

    issuer = SigningKey.generate()
    agent_key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/data"))
        .holder(agent_key.public_key)
        .ttl(300)
        .mint(issuer)
    )
    plugin = TenuoPlugin(warrant=warrant, signing_key=agent_key, trusted_roots=[issuer.public_key])
    assert plugin.name == "tenuo"

    agent = Agent(name="files", model=ScriptedLlm(), instruction="", tools=[read_file, delete_file])
    runner = InMemoryRunner(agent=agent, app_name="files", plugins=[plugin])

    async def main():
        results = {}
        for case in CALLS:
            session = await runner.session_service.create_session(app_name="files", user_id="u")
            msg = types.Content(role="user", parts=[types.Part.from_text(text=case)])
            async for event in runner.run_async(user_id="u", session_id=session.id, new_message=msg):
                for part in (event.content.parts if event.content else []):
                    if part.function_response:
                        results[case] = part.function_response.response
        return results

    results = asyncio.run(main())
    assert results["allowed"] == {"result": "contents of /data/report.txt"}, results["allowed"]
    for case in ("outside", "traversal", "ungranted"):
        assert results[case].get("error") == "authorization_denied", (case, results[case])
    assert ran == [("read_file", "/data/report.txt")], ran
    print("OK")
    """
)


def _adk_available() -> bool:
    return subprocess.run([sys.executable, "-c", _PROBE], capture_output=True).returncode == 0


@pytest.mark.skipif(not _adk_available(), reason="google-adk not installed")
def test_plugin_authorizes_through_real_runner() -> None:
    proc = subprocess.run([sys.executable, "-c", _SCRIPT], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and proc.stdout.strip().endswith("OK"), proc.stdout + proc.stderr
