"""Parameterized coverage for optional-integration installation errors.

Does not uninstall packages. Checks source and helper output for stable
fragments: exception type, integration name, and extra name.
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
    has_helper = f"missing_optional_dependency(" in text and f'\"{extra}\"' in text
    assert has_literal or has_helper
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
