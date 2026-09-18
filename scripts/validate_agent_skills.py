#!/usr/bin/env python3
"""Validate repository agent skills and their canonical API-example links."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
INTEGRATION_SKILL = SKILLS / "tenuo-agent-authorization"

FRONTMATTER_RE = re.compile(r"\A---\n(?P<body>.*?)\n---\n", re.DOTALL)
LINK_RE = re.compile(r"\[[^\]]+\]\((?P<target>[^)]+)\)")
API_FENCE_RE = re.compile(
    r"^```(?:py|python|js|javascript|ts|typescript)(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)

CANONICAL_EXAMPLES = (
    ROOT / "tenuo-ts/packages/core/examples/concurrent-sessions.ts",
    ROOT / "tenuo-ts/packages/core/examples/mcp/host.ts",
    ROOT / "tenuo-ts/packages/core/test/example-sessions.test.ts",
    ROOT / "tenuo-ts/packages/core/test/mcp-host.smoke.test.ts",
    ROOT / "tenuo-python/examples/mcp_server.py",
    ROOT / "tenuo-python/examples/mcp/mcp_delegation_demo.py",
    ROOT / "tenuo-python/tests/examples/test_examples.py",
    ROOT / "tenuo-python/tests/adapters/test_mcp_integration.py",
    ROOT / "tenuo-python/tests/adapters/test_mcp_delegation.py",
)

REQUIRED_SOURCE_TEXT = {
    ROOT / "tenuo-ts/packages/core/src/api.ts": (
        "present(",
        "verify(",
        "readonly mcp: TenuoMcp",
    ),
    ROOT / "tenuo-ts/packages/core/test/example-sessions.test.ts": (
        'from "../examples/concurrent-sessions.ts"',
    ),
    ROOT / "tenuo-ts/packages/core/test/mcp-host.smoke.test.ts": (
        'from "../examples/mcp/host.ts"',
    ),
    ROOT / "tenuo-python/tenuo/mcp/server.py": (
        "class MCPVerifier:",
        "def verify_or_raise(",
        "require_warrant",
    ),
    ROOT / "tenuo-python/tenuo/mcp/fastmcp_middleware.py": (
        "class TenuoMiddleware(",
    ),
    ROOT / "tenuo-python/tests/examples/test_examples.py": (
        "os.walk(EXAMPLES_DIR)",
        "test_tenuo_imports_resolve",
    ),
    ROOT / ".github/workflows/ci.yml": (
        "pytest tests/examples/test_examples.py -v",
        "pnpm --filter @tenuo/core test",
    ),
}


def frontmatter_value(body: str, key: str) -> Optional[str]:
    match = re.search(rf"^{re.escape(key)}:\s*(.+)$", body, re.MULTILINE)
    return match.group(1).strip() if match else None


def validate_skill(skill_dir: Path, errors: list[str]) -> None:
    entrypoint = skill_dir / "SKILL.md"
    if not entrypoint.is_file():
        errors.append(f"{skill_dir.relative_to(ROOT)}: missing SKILL.md")
        return

    text = entrypoint.read_text(encoding="utf-8")
    match = FRONTMATTER_RE.match(text)
    if match is None:
        errors.append(f"{entrypoint.relative_to(ROOT)}: missing YAML frontmatter")
        return

    name = frontmatter_value(match.group("body"), "name")
    description = frontmatter_value(match.group("body"), "description")
    if name != skill_dir.name:
        errors.append(
            f"{entrypoint.relative_to(ROOT)}: name {name!r} must match directory {skill_dir.name!r}"
        )
    if not description:
        errors.append(f"{entrypoint.relative_to(ROOT)}: missing description")


def validate_links(markdown: Path, errors: list[str]) -> None:
    text = markdown.read_text(encoding="utf-8")
    for match in LINK_RE.finditer(text):
        target = match.group("target").strip().strip("<>")
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path_text = target.split("#", 1)[0]
        if not path_text:
            continue
        resolved = (markdown.parent / path_text).resolve()
        if not resolved.exists():
            errors.append(
                f"{markdown.relative_to(ROOT)}: broken relative link {target!r}"
            )


def main() -> int:
    errors: list[str] = []
    skill_dirs = sorted(path for path in SKILLS.iterdir() if path.is_dir())
    if not skill_dirs:
        errors.append("skills: no skill directories found")

    for skill_dir in skill_dirs:
        validate_skill(skill_dir, errors)
        for markdown in sorted(skill_dir.rglob("*.md")):
            validate_links(markdown, errors)

    for example in CANONICAL_EXAMPLES:
        if not example.is_file():
            errors.append(f"missing canonical example or test: {example.relative_to(ROOT)}")

    for source, required_fragments in REQUIRED_SOURCE_TEXT.items():
        if not source.is_file():
            errors.append(f"missing API or test source: {source.relative_to(ROOT)}")
            continue
        source_text = source.read_text(encoding="utf-8")
        for fragment in required_fragments:
            if fragment not in source_text:
                errors.append(
                    f"{source.relative_to(ROOT)}: missing API/test anchor {fragment!r}; "
                    "update the canonical example or the skill reference"
                )

    for markdown in sorted(INTEGRATION_SKILL.rglob("*.md")):
        text = markdown.read_text(encoding="utf-8")
        if API_FENCE_RE.search(text):
            errors.append(
                f"{markdown.relative_to(ROOT)}: move Python/JavaScript/TypeScript API snippets "
                "to a canonical SDK example exercised by CI"
            )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(skill_dirs)} skills, {len(CANONICAL_EXAMPLES)} canonical "
        "example/test links, and current SDK anchors."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
