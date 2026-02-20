"""
Validates that all example files stay in sync with the SDK.

Three tiers of checks:

1. **Syntax** - ast.parse() every example, catching broken code early.
2. **Tenuo imports** - statically resolve every ``from tenuo import X`` and
   ``from tenuo.mod import Y`` and verify the name actually exists.  This is
   the single highest-value check: it catches wrong imports, removed exports,
   and mis-spelled symbols.
3. **Deprecated patterns** - flag uses of retired APIs
   (Warrant.issue, from tenuo_core import, etc.) so they don't silently rot.
"""

from __future__ import annotations

import ast
import importlib
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

SKIP_DIRS = {"__pycache__", "demo_venv", ".venv", "venv", "node_modules", ".git"}


def _collect_example_files() -> List[Path]:
    """Walk examples/ and return every .py file, skipping venvs/caches."""
    files: List[Path] = []
    for root, dirs, names in os.walk(EXAMPLES_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            if name.endswith(".py"):
                files.append(Path(root) / name)
    return files


EXAMPLE_FILES = _collect_example_files()


def _rel(path: Path) -> str:
    """Short label for parametrize IDs."""
    return str(path.relative_to(EXAMPLES_DIR))


# ---------------------------------------------------------------------------
# 1. Syntax check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", EXAMPLE_FILES, ids=[_rel(p) for p in EXAMPLE_FILES])
def test_syntax(path: Path):
    """Every example must be valid Python."""
    source = path.read_text(encoding="utf-8")
    try:
        ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        pytest.fail(f"Syntax error in {_rel(path)}: {exc}")


# ---------------------------------------------------------------------------
# 2. Tenuo import validation
# ---------------------------------------------------------------------------


def _resolve_tenuo_exports(module_name: str):
    """Import module_name and return its public namespace, or None."""
    try:
        mod = importlib.import_module(module_name)
        return set(dir(mod))
    except Exception:
        return None


_EXPORT_CACHE: Dict[str, object] = {}


def _exports(module_name: str):
    if module_name not in _EXPORT_CACHE:
        _EXPORT_CACHE[module_name] = _resolve_tenuo_exports(module_name)
    return _EXPORT_CACHE[module_name]


def _extract_tenuo_imports(tree: ast.Module) -> List[Tuple[str, str, int]]:
    """Return [(module, name, lineno)] for every from tenuo... import name."""
    results: List[Tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top == "tenuo":
                for alias in node.names:
                    results.append((node.module, alias.name, node.lineno))
    return results


@pytest.mark.parametrize("path", EXAMPLE_FILES, ids=[_rel(p) for p in EXAMPLE_FILES])
def test_tenuo_imports_resolve(path: Path):
    """Every from tenuo... import X must reference a name that exists."""
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        pytest.skip("syntax error (covered by test_syntax)")

    imports = _extract_tenuo_imports(tree)
    if not imports:
        pytest.skip("no tenuo imports")

    bad: List[str] = []
    for module, name, lineno in imports:
        exports = _exports(module)
        if exports is None:
            bad.append(f"  L{lineno}: cannot import module '{module}'")
        elif name not in exports:
            bad.append(f"  L{lineno}: '{name}' not found in '{module}'")

    if bad:
        pytest.fail(
            f"{_rel(path)} has invalid tenuo imports:\n" + "\n".join(bad)
        )


# ---------------------------------------------------------------------------
# 3. Deprecated / disallowed patterns
# ---------------------------------------------------------------------------

DEPRECATED_PATTERNS: List[Tuple[str, str]] = [
    (
        "Warrant.issue(",
        "Use Warrant.mint_builder()...mint() or Warrant.grant_builder()...grant()",
    ),
    ("Warrant.issue_root(", "Use Warrant.mint_builder()...mint()"),
]


def _check_deprecated(source: str) -> List[Tuple[int, str, str]]:
    """Return [(lineno, pattern, hint)] for deprecated API usage."""
    hits: List[Tuple[int, str, str]] = []
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for pattern, hint in DEPRECATED_PATTERNS:
            if pattern in line:
                hits.append((i, pattern, hint))
    return hits


@pytest.mark.parametrize("path", EXAMPLE_FILES, ids=[_rel(p) for p in EXAMPLE_FILES])
def test_no_deprecated_apis(path: Path):
    """Examples must not use deprecated Tenuo APIs."""
    source = path.read_text(encoding="utf-8")
    hits = _check_deprecated(source)
    if hits:
        lines = [f"  L{ln}: found '{pat}' -- {hint}" for ln, pat, hint in hits]
        pytest.fail(
            f"{_rel(path)} uses deprecated APIs:\n" + "\n".join(lines)
        )


# ---------------------------------------------------------------------------
# 4. Prefer `from tenuo import` over `from tenuo_core import` in examples
# ---------------------------------------------------------------------------


def _uses_tenuo_core_import(tree: ast.Module) -> List[Tuple[str, int]]:
    """Return [(name, lineno)] for raw from tenuo_core import X."""
    hits: List[Tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] == "tenuo_core":
                for alias in node.names:
                    hits.append((alias.name, node.lineno))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "tenuo_core":
                    hits.append((alias.name, node.lineno))
    return hits


# Names that are only available from tenuo_core (not re-exported by tenuo)
TENUO_CORE_ONLY: Set[str] = {
    "Subpath", "UrlSafe", "Shlex", "CompiledMcpConfig", "McpConfig",
    "Clearance", "ChainVerificationResult",
}


@pytest.mark.parametrize("path", EXAMPLE_FILES, ids=[_rel(p) for p in EXAMPLE_FILES])
def test_prefer_tenuo_over_tenuo_core(path: Path):
    """Examples should use from tenuo import X instead of from tenuo_core import X.

    tenuo_core is the Rust extension -- users should not need to know about it.
    Exceptions: names only exposed via tenuo_core (Subpath, UrlSafe, etc.).
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        pytest.skip("syntax error")

    hits = _uses_tenuo_core_import(tree)
    bad = [(name, ln) for name, ln in hits if name not in TENUO_CORE_ONLY]
    if bad:
        lines = [
            f"  L{ln}: from tenuo_core import {name} -- use from tenuo import {name}"
            for name, ln in bad
        ]
        pytest.fail(
            f"{_rel(path)} imports from tenuo_core (prefer tenuo):\n"
            + "\n".join(lines)
        )
