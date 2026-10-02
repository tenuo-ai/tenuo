"""Coverage for optional-integration installation errors.

Source checks only confirm the helper/extra is referenced on the missing-dep
path's neighboring raise sites. Runtime checks build ImportError via the
helper so fragments are asserted without scanning whole files.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "tenuo"


def _load_optional_deps():
    path = ROOT / "optional_deps.py"
    spec = importlib.util.spec_from_file_location("tenuo_optional_deps_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


optional_deps = _load_optional_deps()
extra_install_command = optional_deps.extra_install_command
missing_optional_dependency = optional_deps.missing_optional_dependency

CASES = [
    ("FastAPI", "fastapi", ROOT / "fastapi.py"),
    ("LangChain", "langchain", ROOT / "langchain.py"),
    ("LangGraph", "langgraph", ROOT / "langgraph.py"),
    ("CrewAI", "crewai", ROOT / "crewai.py"),
    ("MCP", "mcp", ROOT / "mcp" / "client.py"),
    ("LangChain", "langchain", ROOT / "mcp" / "langchain.py"),
    ("MCP", "mcp", ROOT / "mcp" / "langchain.py"),
    ("FastMCP", "fastmcp", ROOT / "mcp" / "__init__.py"),
    ("FastMCP", "fastmcp", ROOT / "mcp" / "fastmcp_middleware.py"),
    ("A2A", "a2a", ROOT / "a2a" / "client.py"),
    ("OpenAI", "openai", ROOT / "openai.py"),
    ("AutoGen", "autogen", ROOT / "autogen.py"),
    ("Google ADK", "google_adk", ROOT / "google_adk" / "__init__.py"),
]


@pytest.mark.parametrize("integration,extra,path", CASES)
def test_integration_source_names_tenuo_extra(integration: str, extra: str, path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    has_literal = f"tenuo[{extra}]" in text
    helper_call = f'missing_optional_dependency("{integration}", "{extra}")'
    has_helper = helper_call in text
    assert has_literal or has_helper, f"{path} missing extra {extra} or helper call"
    assert extra in text


@pytest.mark.parametrize(
    "integration,extra",
    [
        ("OpenAI", "openai"),
        ("AutoGen", "autogen"),
        ("LangChain", "langchain"),
        ("LangGraph", "langgraph"),
        ("CrewAI", "crewai"),
        ("Google ADK", "google_adk"),
        ("A2A", "a2a"),
        ("MCP", "mcp"),
        ("FastMCP", "fastmcp"),
        ("FastAPI", "fastapi"),
    ],
)
def test_missing_optional_dependency_message_fragments(integration: str, extra: str) -> None:
    message = missing_optional_dependency(integration, extra)
    err = ImportError(message)
    assert isinstance(err, ImportError)
    assert integration in str(err)
    assert extra in str(err)
    assert extra_install_command(extra) in str(err)
    assert f"tenuo[{extra}]" in str(err)


def test_langgraph_middleware_message_keeps_langchain_requirement() -> None:
    text = (ROOT / "langgraph.py").read_text(encoding="utf-8")
    assert "langchain>=1.0" in text
    assert 'missing_optional_dependency("LangGraph", "langgraph")' in text
