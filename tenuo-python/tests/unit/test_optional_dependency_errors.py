"""Missing optional dependencies must point at the right Tenuo extra.

Each case runs in a fresh interpreter with the optional dependency made
unavailable by an import blocker, then calls the API that needs it. We assert
on the ``ImportError`` the integration actually raises (integration name plus
the exact ``pip install "tenuo[<extra>]"`` command), so nothing else in the
source file can make a case pass. Nothing is uninstalled from the developer
environment.

Extras are the ones declared in ``tenuo-python/pyproject.toml``.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from typing import Optional, Sequence

import pytest

# Installed at the top of every subprocess. A blocked module behaves as if it
# were not installed: imports raise ModuleNotFoundError and
# importlib.util.find_spec() returns None.
_BLOCKER = """
import importlib.abc
import importlib.util
import sys

BLOCKED = {blocked!r}


def _is_blocked(name):
    return any(name == b or name.startswith(b + ".") for b in BLOCKED)


class _Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if _is_blocked(fullname):
            raise ModuleNotFoundError(f"No module named {{fullname!r}}", name=fullname)
        return None


for _name in list(sys.modules):
    if _is_blocked(_name):
        del sys.modules[_name]
sys.meta_path.insert(0, _Blocker())

_real_find_spec = importlib.util.find_spec


def _find_spec(name, package=None):
    if _is_blocked(name):
        return None
    return _real_find_spec(name, package)


importlib.util.find_spec = _find_spec
"""

# Runs the case body and reports the outcome as JSON on the last stdout line.
_RUNNER = """
import json as _json

_result = {{"raised": None, "message": None}}
try:
{body}
except ImportError as _exc:
    _result = {{"raised": type(_exc).__name__, "message": str(_exc)}}
print(_json.dumps(_result))
"""


def _run_blocked(blocked: Sequence[str], body: str) -> dict:
    script = _BLOCKER.format(blocked=tuple(blocked)) + _RUNNER.format(
        body=textwrap.indent(textwrap.dedent(body).strip(), "    ")
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"subprocess failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _install(extra: str) -> str:
    return f'pip install "tenuo[{extra}]"'


# (case id, blocked modules, code that should raise, integration name, extra,
#  module that must be importable for the case to be meaningful)
RAISING_CASES = [
    (
        "langchain-guard_tools",
        ["langchain_core", "langchain"],
        "from tenuo.langchain import guard_tools\nguard_tools([])",
        "LangChain",
        "langchain",
        None,
    ),
    (
        "langchain-guard_agent",
        ["langchain_core", "langchain"],
        "from tenuo.langchain import guard_agent\nguard_agent(object())",
        "LangChain",
        "langchain",
        None,
    ),
    (
        "langchain-SecureAgentExecutor",
        ["langchain_core", "langchain"],
        "from tenuo.langchain import SecureAgentExecutor\nSecureAgentExecutor(agent=object(), tools=[])",
        "LangChain",
        "langchain",
        None,
    ),
    (
        "langgraph-TenuoToolNode",
        ["langgraph"],
        "from tenuo.langgraph import TenuoToolNode\nTenuoToolNode([])",
        "LangGraph",
        "langgraph",
        None,
    ),
    (
        "langgraph-TenuoMiddleware",
        ["langchain.agents", "langchain.tools"],
        "from tenuo.langgraph import TenuoMiddleware\nTenuoMiddleware()",
        "LangGraph",
        "langgraph",
        None,
    ),
    (
        "crewai-register",
        ["crewai"],
        "from tenuo.crewai import GuardBuilder\nGuardBuilder().allow('read_file').build().register()",
        "CrewAI",
        "crewai",
        None,
    ),
    (
        "crewai-GuardedCrew",
        ["crewai"],
        "from tenuo.crewai import GuardedCrew\n"
        "GuardedCrew(agents=[], tasks=[]).policy({}).build().kickoff()",
        "CrewAI",
        "crewai",
        None,
    ),
    (
        "fastapi-require_warrant",
        ["fastapi"],
        "from tenuo.fastapi import require_warrant\nrequire_warrant()",
        "FastAPI",
        "fastapi",
        None,
    ),
    (
        "fastapi-get_warrant_header",
        ["fastapi"],
        "from tenuo.fastapi import get_warrant_header\nget_warrant_header()",
        "FastAPI",
        "fastapi",
        None,
    ),
    (
        "fastapi-SecureAPIRouter",
        ["fastapi"],
        "from tenuo.fastapi import SecureAPIRouter\nSecureAPIRouter()",
        "FastAPI",
        "fastapi",
        None,
    ),
    (
        "mcp-SecureMCPClient",
        ["mcp", "fastmcp"],
        "from tenuo.mcp.client import SecureMCPClient\nSecureMCPClient(command='true')",
        "MCP",
        "mcp",
        None,
    ),
    (
        "mcp-TenuoServerMiddleware",
        ["mcp", "fastmcp"],
        "from tenuo.mcp import TenuoServerMiddleware\nTenuoServerMiddleware()",
        "MCP",
        "mcp",
        None,
    ),
    (
        "mcp-mcp_tool_to_langchain-missing-mcp",
        ["mcp", "fastmcp"],
        "from tenuo.mcp.langchain import mcp_tool_to_langchain\nmcp_tool_to_langchain(object(), object())",
        "MCP",
        "mcp",
        "langchain_core",
    ),
    (
        "mcp-mcp_tool_to_langchain-missing-langchain",
        ["langchain_core", "langchain"],
        "from tenuo.mcp.langchain import mcp_tool_to_langchain\nmcp_tool_to_langchain(object(), object())",
        "LangChain",
        "langchain",
        None,
    ),
    (
        "mcp-MCPToolAdapter-missing-langchain",
        ["langchain_core", "langchain"],
        "from tenuo.mcp.langchain import MCPToolAdapter\nMCPToolAdapter(object())",
        "LangChain",
        "langchain",
        None,
    ),
    (
        "fastmcp-TenuoMiddleware",
        ["fastmcp"],
        "from tenuo.mcp import TenuoMiddleware\nTenuoMiddleware()",
        "FastMCP",
        "fastmcp",
        "mcp",
    ),
    (
        "fastmcp-fastmcp_middleware-import",
        ["fastmcp"],
        "import tenuo.mcp.fastmcp_middleware",
        "FastMCP",
        "fastmcp",
        "mcp",
    ),
    (
        "a2a-client-httpx",
        ["httpx"],
        "import asyncio\n"
        "from tenuo.a2a import A2AClient\n"
        "asyncio.run(A2AClient('http://localhost:1')._get_client())",
        "A2A",
        "a2a",
        None,
    ),
    (
        "a2a-server-starlette",
        ["starlette"],
        "from tenuo import SigningKey\n"
        "from tenuo.a2a import A2AServer\n"
        "key = SigningKey.generate()\n"
        "A2AServer(name='t', url='http://localhost:1', public_key=key.public_key,"
        " trusted_issuers=[key.public_key]).app",
        "A2A",
        "a2a",
        None,
    ),
]


@pytest.mark.parametrize(
    "blocked,body,integration,extra,requires",
    [pytest.param(*case[1:], id=case[0]) for case in RAISING_CASES],
)
def test_missing_dependency_raises_standard_install_error(
    blocked: Sequence[str],
    body: str,
    integration: str,
    extra: str,
    requires: Optional[str],
) -> None:
    if requires is not None and not _installed(requires):
        pytest.skip(f"{requires} must be installed for this case")

    result = _run_blocked(blocked, body)

    assert result["raised"] is not None, f"expected ImportError, call succeeded: {body!r}"
    message = result["message"]
    assert integration in message, message
    assert _install(extra) in message, message


def test_langgraph_middleware_error_keeps_langchain_requirement() -> None:
    # tenuo[langgraph] does not pull in langchain>=1.0, so the message has to
    # say so rather than imply the extra alone fixes it.
    result = _run_blocked(
        ["langchain.agents", "langchain.tools"],
        "from tenuo.langgraph import TenuoMiddleware\nTenuoMiddleware()",
    )
    assert result["raised"] is not None
    assert "langchain>=1.0" in result["message"]
    assert _install("langgraph") in result["message"]


def test_fastmcp_middleware_without_mcp_sdk_points_at_mcp_extra() -> None:
    result = _run_blocked(["mcp", "fastmcp"], "import tenuo.mcp.fastmcp_middleware")
    assert result["raised"] is not None
    assert _install("mcp") in result["message"]


# Integrations that only wrap objects the caller already built. They must stay
# importable (and usable) without the framework installed; the module docs
# carry the install command.
IMPORT_SAFE_CASES = [
    (
        "openai",
        ["openai", "agents"],
        "import tenuo.openai as m\n"
        "m.create_tier1_guardrail(allow_tools=['search'])\n"
        "assert m.GuardrailResult(output_info='ok').to_agents_sdk() is not None\n"
        "print('DOC:' + repr(m.__doc__))",
        "openai",
    ),
    (
        "autogen",
        ["autogen_agentchat", "autogen_core", "autogen_ext"],
        "import tenuo.autogen as m\n"
        "assert m.AUTOGEN_AVAILABLE is False\n"
        "print('DOC:' + repr(m.__doc__))",
        "autogen",
    ),
    (
        "google_adk",
        ["google.adk"],
        "import tenuo.google_adk as m\n"
        "m.GuardBuilder()\n"
        "print('DOC:' + repr(m.__doc__))",
        "google_adk",
    ),
]


@pytest.mark.parametrize(
    "blocked,body,extra",
    [pytest.param(*case[1:], id=case[0]) for case in IMPORT_SAFE_CASES],
)
def test_import_safe_integration_works_without_dependency(blocked: Sequence[str], body: str, extra: str) -> None:
    script = _BLOCKER.format(blocked=tuple(blocked)) + textwrap.dedent(body)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"import failed without dependency:\n{proc.stderr}"
    doc_line = next(line for line in proc.stdout.splitlines() if line.startswith("DOC:"))
    assert _install(extra) in doc_line
