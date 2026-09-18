#!/usr/bin/env python3
"""Validate repository agent skills and their portable documentation links."""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
INTEGRATION_SKILL = SKILLS / "tenuo-agent-authorization"
REPOSITORY_BLOB_PREFIX = "/tenuo-ai/tenuo/blob/"

LINK_RE = re.compile(r"\[[^\]]+\]\((?P<target>[^)]+)\)")
API_FENCE_RE = re.compile(
    r"^```(?:py|python|js|javascript|ts|typescript|rs|rust)(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
BLOCK_SCALAR_MARKERS = {"|", "|-", "|+", ">", ">-", ">+"}


def _plain_scalar(value: str) -> Optional[str]:
    value = value.strip()
    if not value or value in BLOCK_SCALAR_MARKERS:
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1].strip()
    return value or None


def parse_frontmatter(text: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """Parse the single-line scalar metadata used by skill entrypoints."""
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, "missing YAML frontmatter"

    try:
        closing = lines.index("---", 1)
    except ValueError:
        return None, "unterminated YAML frontmatter"

    metadata: Dict[str, str] = {}
    for line in lines[1:closing]:
        if not line.strip() or line.lstrip().startswith("#") or ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if key in {"name", "description"}:
            value = _plain_scalar(raw_value)
            if value is None:
                return None, f"{key} must be a non-empty single-line scalar"
            metadata[key] = value
    return metadata, None


def markdown_link_destination(raw_target: str) -> Optional[str]:
    """Return a Markdown inline-link destination without its optional title."""
    raw_target = raw_target.strip()
    if not raw_target:
        return None
    if raw_target.startswith("<"):
        closing = raw_target.find(">")
        if closing == -1:
            return None
        return raw_target[1:closing]
    try:
        parts = shlex.split(raw_target)
    except ValueError:
        return None
    return parts[0] if parts else None


def repository_ref_and_path_for_url(target: str) -> Optional[Tuple[str, Path]]:
    """Map this repository's canonical branch or tag URLs to a ref and path."""
    parsed = urlsplit(target)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    if not parsed.path.startswith(REPOSITORY_BLOB_PREFIX):
        return None
    ref_and_path = parsed.path[len(REPOSITORY_BLOB_PREFIX) :]
    if "/" not in ref_and_path:
        return None
    ref, relative = ref_and_path.split("/", 1)
    relative = unquote(relative)
    return ref, Path(relative)


def repository_path_for_url(target: str) -> Optional[Path]:
    """Map this repository's canonical URL to the equivalent checkout path."""
    parsed = repository_ref_and_path_for_url(target)
    return ROOT / parsed[1] if parsed is not None else None


def repository_file_exists(ref: str, relative: Path) -> bool:
    if ref == "main":
        return (ROOT / relative).is_file()
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{ref}:{relative.as_posix()}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def validate_skill(skill_dir: Path, documents: Dict[Path, str], errors: list[str]) -> None:
    entrypoint = skill_dir / "SKILL.md"
    text = documents.get(entrypoint)
    if text is None:
        errors.append(f"{skill_dir.relative_to(ROOT)}: missing SKILL.md")
        return

    metadata, parse_error = parse_frontmatter(text)
    if parse_error:
        errors.append(f"{entrypoint.relative_to(ROOT)}: {parse_error}")
        return
    assert metadata is not None

    name = metadata.get("name")
    description = metadata.get("description")
    if name != skill_dir.name:
        errors.append(
            f"{entrypoint.relative_to(ROOT)}: name {name!r} must match directory {skill_dir.name!r}"
        )
    if not description:
        errors.append(f"{entrypoint.relative_to(ROOT)}: missing description")


def validate_links(
    markdown: Path, text: str, skill_dir: Path, errors: list[str]
) -> int:
    checked = 0
    skill_root = skill_dir.resolve()
    for match in LINK_RE.finditer(text):
        raw_target = match.group("target")
        target = markdown_link_destination(raw_target)
        if target is None:
            errors.append(
                f"{markdown.relative_to(ROOT)}: malformed Markdown link target {raw_target!r}"
            )
            continue

        repository_target = repository_ref_and_path_for_url(target)
        if repository_target is not None:
            checked += 1
            ref, relative = repository_target
            if not repository_file_exists(ref, relative):
                errors.append(
                    f"{markdown.relative_to(ROOT)}: canonical repository link does not name a file at {ref}: {target!r}"
                )
            continue

        if target.startswith(("http://", "https://", "mailto:", "#", "/", "//")):
            continue

        path_text = target.split("#", 1)[0].split("?", 1)[0]
        if not path_text:
            continue
        resolved = (markdown.parent / unquote(path_text)).resolve()
        try:
            resolved.relative_to(skill_root)
        except ValueError:
            errors.append(
                f"{markdown.relative_to(ROOT)}: relative link escapes the installed skill: {target!r}; "
                "use a portable repository URL"
            )
            continue
        checked += 1
        if not resolved.exists():
            errors.append(f"{markdown.relative_to(ROOT)}: broken relative link {target!r}")
    return checked


def main() -> int:
    errors: list[str] = []
    skill_dirs = sorted(path for path in SKILLS.iterdir() if path.is_dir())
    if not skill_dirs:
        errors.append("skills: no skill directories found")

    checked_links = 0
    for skill_dir in skill_dirs:
        documents = {
            markdown: markdown.read_text(encoding="utf-8")
            for markdown in sorted(skill_dir.rglob("*.md"))
        }
        validate_skill(skill_dir, documents, errors)
        for markdown, text in documents.items():
            checked_links += validate_links(markdown, text, skill_dir, errors)
            if skill_dir == INTEGRATION_SKILL and API_FENCE_RE.search(text):
                errors.append(
                    f"{markdown.relative_to(ROOT)}: move Python, JavaScript/TypeScript, or Rust "
                    "API snippets to a canonical SDK example exercised by CI"
                )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"Validated {len(skill_dirs)} skills and {checked_links} portable links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
