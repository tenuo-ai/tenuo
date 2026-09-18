#!/usr/bin/env python3
"""Validate repository agent skills and their portable documentation links."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
INTEGRATION_SKILL = SKILLS / "tenuo-agent-authorization"
RELEASE_CONTRACT = INTEGRATION_SKILL / "release.json"
REPOSITORY_BLOB_PREFIX = "/tenuo-ai/tenuo/blob/"

LINK_RE = re.compile(r"\[[^\]]+\]\((?P<target>[^)]+)\)")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
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
    """Map this repository's canonical blob URL to a ref and path."""
    parsed = urlsplit(target)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    if not parsed.path.startswith(REPOSITORY_BLOB_PREFIX):
        return None
    ref_and_path = parsed.path[len(REPOSITORY_BLOB_PREFIX) :]
    if "/" not in ref_and_path:
        return None
    ref, relative = ref_and_path.split("/", 1)
    return ref, Path(unquote(relative))


def repository_path_for_url(target: str) -> Optional[Path]:
    """Map this repository's canonical URL to the equivalent checkout path."""
    parsed = repository_ref_and_path_for_url(target)
    return ROOT / parsed[1] if parsed is not None else None


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def repository_tag_exists(tag: str) -> bool:
    return _git("show-ref", "--verify", "--quiet", f"refs/tags/{tag}").returncode == 0


def repository_file_exists(tag: str, relative: Path) -> bool:
    return _git("cat-file", "-e", f"refs/tags/{tag}:{relative.as_posix()}").returncode == 0


def repository_file_text(tag: str, relative: Path) -> Optional[str]:
    result = _git("show", f"refs/tags/{tag}:{relative.as_posix()}")
    return result.stdout if result.returncode == 0 else None


def manifest_version(text: str, manifest: Dict[str, Any]) -> Optional[str]:
    if manifest.get("format") == "json":
        try:
            value = json.loads(text).get("version")
        except (json.JSONDecodeError, AttributeError):
            return None
        return value if isinstance(value, str) else None

    section = manifest.get("section")
    if not isinstance(section, str):
        return None
    match = re.search(
        rf"(?ms)^\[{re.escape(section)}\]\s*$\n(?P<body>.*?)(?=^\[|\Z)", text
    )
    if match is None:
        return None
    version = re.search(r'^version\s*=\s*"([^"]+)"', match.group("body"), re.MULTILINE)
    return version.group(1) if version else None


def load_release_contract(errors: list[str]) -> Optional[Dict[str, Any]]:
    try:
        contract = json.loads(RELEASE_CONTRACT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: invalid release contract: {exc}")
        return None

    tag = contract.get("repository_tag")
    if not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None:
        errors.append(
            f"{RELEASE_CONTRACT.relative_to(ROOT)}: repository_tag must be an immutable semver tag"
        )
        return None
    return contract


def validate_release_contract(contract: Dict[str, Any], errors: list[str]) -> bool:
    tag = contract["repository_tag"]
    if not repository_tag_exists(tag):
        errors.append(
            f"{RELEASE_CONTRACT.relative_to(ROOT)}: required tag {tag!r} is unavailable; "
            "fetch tags (git fetch --tags --force) before validating"
        )
        return False

    packages = contract.get("packages")
    if not isinstance(packages, list) or not packages:
        errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: packages must be a non-empty list")
        return True

    for package in packages:
        if not isinstance(package, dict):
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: invalid package entry")
            continue
        path_value = package.get("manifest")
        expected = package.get("version")
        name = package.get("name", path_value)
        if not isinstance(path_value, str) or not isinstance(expected, str):
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: invalid package contract {name!r}")
            continue
        relative = Path(path_value)
        text = repository_file_text(tag, relative)
        if text is None:
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: {relative} is missing at {tag}")
            continue
        actual = manifest_version(text, package)
        if actual != expected:
            errors.append(
                f"{RELEASE_CONTRACT.relative_to(ROOT)}: {name} expects {expected!r} "
                f"but {relative} at {tag} declares {actual!r}"
            )
    return True


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
    if name != skill_dir.name:
        errors.append(
            f"{entrypoint.relative_to(ROOT)}: name {name!r} must match directory {skill_dir.name!r}"
        )
    if not metadata.get("description"):
        errors.append(f"{entrypoint.relative_to(ROOT)}: missing description")


def validate_links(
    markdown: Path,
    text: str,
    skill_dir: Path,
    errors: list[str],
    required_repository_tag: Optional[str] = None,
    repository_tag_available: bool = True,
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
            expected = required_repository_tag
            if TAG_RE.fullmatch(ref) is None or (expected is not None and ref != expected):
                suffix = f" {expected!r}" if expected is not None else " an immutable semver tag"
                errors.append(
                    f"{markdown.relative_to(ROOT)}: repository link must use pinned tag{suffix}, "
                    f"not {ref!r}: {target!r}"
                )
            elif repository_tag_available and not repository_file_exists(ref, relative):
                errors.append(
                    f"{markdown.relative_to(ROOT)}: canonical repository link does not name a file "
                    f"at tag {ref}: {target!r}"
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


def validate_no_api_fences(markdown: Path, text: str, errors: list[str]) -> None:
    if API_FENCE_RE.search(text):
        errors.append(
            f"{markdown.relative_to(ROOT)}: move Python, JavaScript/TypeScript, or Rust "
            "API snippets to a canonical SDK example exercised by CI"
        )


def main() -> int:
    errors: list[str] = []
    contract = load_release_contract(errors)
    required_tag = contract.get("repository_tag") if contract else None
    tag_available = validate_release_contract(contract, errors) if contract else False

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
            checked_links += validate_links(
                markdown,
                text,
                skill_dir,
                errors,
                required_repository_tag=required_tag if skill_dir == INTEGRATION_SKILL else None,
                repository_tag_available=tag_available,
            )
            if skill_dir == INTEGRATION_SKILL:
                validate_no_api_fences(markdown, text, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(skill_dirs)} skills, {checked_links} portable links, "
        f"and release contract {required_tag}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
