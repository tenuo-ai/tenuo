#!/usr/bin/env python3
"""Validate repository agent skills and their portable documentation links."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
INTEGRATION_SKILL = SKILLS / "tenuo-agent-authorization"
RELEASE_CONTRACT = INTEGRATION_SKILL / "release.json"
BEHAVIORAL_EVAL_DIR = ROOT / "tests/agent-skills/tenuo-agent-authorization"
BEHAVIORAL_EVAL_GLOB = "payment-boundary-result.*.json"
LANGUAGE_REFERENCES = {
    "python": "references/python.md",
    "typescript": "references/typescript.md",
    "rust": "references/rust.md",
}
REPOSITORY_BLOB_PREFIX = "/tenuo-ai/tenuo/blob/"

LINK_RE = re.compile(r"\[[^\]]+\]\((?P<target>[^)]+)\)")
# CommonMark inline-link target: a <...> destination or a run of non-space
# characters, followed by an optional "…", '…', or (…) title.
LINK_DESTINATION_RE = re.compile(
    r"""^(?:<(?P<angle>[^<>]*)>|(?P<plain>[^\s<>]+))(?:\s+(?:"[^"]*"|'[^']*'|\([^()]*\)))?$"""
)
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
VERSION_LITERAL_RE = re.compile(r"(?<![0-9A-Za-z])\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")
API_FENCE_RE = re.compile(
    r"^```(?:py|python|js|javascript|ts|typescript|rs|rust)(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
BLOCK_SCALAR_MARKERS = {"|", "|-", "|+", ">", ">-", ">+"}
EVIDENCE_KINDS = {"fresh", "carried_forward"}


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
    match = LINK_DESTINATION_RE.fullmatch(raw_target.strip())
    if match is None:
        return None
    angle = match.group("angle")
    return angle if angle is not None else match.group("plain")


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


def contract_packages(contract: Dict[str, Any], errors: list[str]) -> List[Dict[str, Any]]:
    """Return the well-formed package entries, reporting malformed ones once."""
    packages = contract.get("packages")
    if not isinstance(packages, list) or not packages:
        errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: packages must be a non-empty list")
        return []
    valid: List[Dict[str, Any]] = []
    for package in packages:
        if not isinstance(package, dict):
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: invalid package entry")
            continue
        name = package.get("name", package.get("manifest"))
        if not all(
            isinstance(package.get(key), str) for key in ("manifest", "reference", "version")
        ):
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: invalid package contract {name!r}")
            continue
        valid.append(package)
    return valid


def validate_release_contract(contract: Dict[str, Any], errors: list[str]) -> bool:
    tag = contract["repository_tag"]
    if not repository_tag_exists(tag):
        errors.append(
            f"{RELEASE_CONTRACT.relative_to(ROOT)}: required tag {tag!r} is unavailable; "
            "fetch tags (git fetch --tags --force) before validating"
        )
        return False

    checked_references: set[Path] = set()
    for package in contract_packages(contract, errors):
        name = package.get("name", package["manifest"])
        relative = Path(package["manifest"])
        expected = package["version"]
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
        reference = INTEGRATION_SKILL / package["reference"]
        if reference in checked_references:
            continue
        checked_references.add(reference)
        try:
            reference_text = reference.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{RELEASE_CONTRACT.relative_to(ROOT)}: cannot read {reference}: {exc}")
            continue
        prose_without_links = LINK_RE.sub("", reference_text)
        duplicate = VERSION_LITERAL_RE.search(prose_without_links)
        if duplicate:
            errors.append(
                f"{reference.relative_to(ROOT)}: package version {duplicate.group(0)!r} is "
                "duplicated in prose; refer to release.json instead"
            )
    return True


def check_release_drift(
    contract: Dict[str, Any],
    errors: list[str],
    warnings: list[str],
    require_current: bool,
    tag_exists: Callable[[str], bool] = repository_tag_exists,
) -> None:
    """Compare the pinned contract with the manifests at HEAD.

    The contract must name a tag that already exists, so a version-bump pull
    request cannot update it before the release is tagged. Drift is a warning
    while the release is still pending. Once a tag matching a HEAD manifest
    version exists, the release happened and the skill was not re-pinned, which
    is an error. ``--require-current-release`` makes any drift an error.
    """
    for package in contract_packages(contract, []):
        name = package.get("name", package["manifest"])
        manifest = ROOT / package["manifest"]
        try:
            head_version = manifest_version(manifest.read_text(encoding="utf-8"), package)
        except OSError:
            head_version = None
        if head_version == package["version"]:
            continue
        message = (
            f"{RELEASE_CONTRACT.relative_to(ROOT)}: {name} pins {package['version']!r} but "
            f"{package['manifest']} at HEAD declares {head_version!r}"
        )
        release_tag = f"v{head_version}" if head_version else None
        if release_tag and tag_exists(release_tag):
            errors.append(
                f"{message}; release {release_tag} exists, so re-pin the skill with "
                f"`python3 scripts/repin_agent_skill.py --tag {release_tag}` (the "
                "agent-skill-repin workflow opens this change automatically on release)"
            )
        elif require_current:
            errors.append(f"{message}; the release is not tagged yet")
        else:
            warnings.append(
                f"{message}; after tagging the release, the agent-skill-repin workflow "
                "re-pins release.json, the reference links, and the behavioral evidence"
            )


def behavioral_eval_fingerprint(inputs: Iterable[str]) -> str:
    """Fingerprint the skill files a behavioral scenario actually reads.

    Line endings are normalized so a checkout with ``core.autocrlf`` produces the
    same fingerprint as CI.
    """
    digest = hashlib.sha256()
    for relative in sorted(set(inputs)):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update((INTEGRATION_SKILL / relative).read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()


def skill_instruction_files() -> List[str]:
    return sorted(
        path.relative_to(INTEGRATION_SKILL).as_posix()
        for path in INTEGRATION_SKILL.rglob("*.md")
        if path.is_file()
    )


def validate_behavioral_eval_result(
    result: Dict[str, Any],
    errors: list[str],
    location: str = "payment-boundary-result.json",
    language: Optional[str] = None,
) -> List[str]:
    """Validate one language's result file and return the inputs it covers."""
    inputs = result.get("inputs")
    if (
        not isinstance(inputs, list)
        or not inputs
        or not all(isinstance(item, str) for item in inputs)
    ):
        errors.append(
            f"{location}: inputs must list the skill files the scenario reads, "
            "relative to the skill directory"
        )
        return []
    if "SKILL.md" not in inputs:
        errors.append(f"{location}: inputs must include SKILL.md")
    if language is not None:
        if result.get("language") != language:
            errors.append(f"{location}: language must be {language!r} to match the file name")
        reference = LANGUAGE_REFERENCES.get(language)
        if reference is None:
            errors.append(f"{location}: unknown language {language!r}")
        elif reference not in inputs:
            errors.append(f"{location}: inputs must include {reference}")
    missing = [item for item in inputs if not (INTEGRATION_SKILL / item).is_file()]
    if missing:
        errors.append(f"{location}: inputs name missing skill files: {missing}")
        return []

    kind = result.get("evidence_kind")
    if kind not in EVIDENCE_KINDS:
        errors.append(f"{location}: evidence_kind must be one of {sorted(EVIDENCE_KINDS)}")
    elif kind == "carried_forward" and not str(result.get("carried_forward_review", "")).strip():
        errors.append(
            f"{location}: carried_forward evidence requires a carried_forward_review rationale"
        )

    if result.get("result") != "pass":
        errors.append(f"{location}: latest behavioral eval did not pass")

    current = behavioral_eval_fingerprint(inputs)
    if result.get("skill_fingerprint") != current:
        errors.append(
            f"{location}: behavioral eval evidence is stale for {sorted(set(inputs))}; "
            "rerun payment-boundary-eval.md (or record a carried_forward review for a "
            f"non-behavioral change) with skill fingerprint {current}"
        )
    return list(inputs)


def load_behavioral_eval_results(errors: list[str], notices: list[str]) -> None:
    """Validate every per-language result and report skill files none of them cover."""
    covered: set[str] = set()
    result_files = sorted(BEHAVIORAL_EVAL_DIR.glob(BEHAVIORAL_EVAL_GLOB))
    if not result_files:
        errors.append(
            f"{BEHAVIORAL_EVAL_DIR.relative_to(ROOT)}: no {BEHAVIORAL_EVAL_GLOB} evidence found"
        )
        return
    for path in result_files:
        location = str(path.relative_to(ROOT))
        language = path.name[len("payment-boundary-result.") : -len(".json")]
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{location}: invalid eval result: {exc}")
            continue
        if not isinstance(result, dict):
            errors.append(f"{location}: eval result must be an object")
            continue
        covered.update(validate_behavioral_eval_result(result, errors, location, language))

    uncovered = [item for item in skill_instruction_files() if item not in covered]
    if uncovered:
        notices.append(
            f"{BEHAVIORAL_EVAL_DIR.relative_to(ROOT)}: no committed behavioral evidence "
            f"covers {uncovered}"
        )


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


def validate_repository_link(
    markdown: Path,
    target: str,
    ref: str,
    relative: Path,
    errors: list[str],
    required_repository_tag: Optional[str],
    repository_tag_available: bool,
) -> None:
    location = markdown.relative_to(ROOT)
    if required_repository_tag is not None:
        if ref != required_repository_tag:
            errors.append(
                f"{location}: repository link must be pinned to release tag "
                f"{required_repository_tag!r}, not {ref!r}: {target!r}"
            )
        elif repository_tag_available and not repository_file_exists(ref, relative):
            errors.append(
                f"{location}: canonical repository link does not name a file at tag {ref}: "
                f"{target!r}"
            )
        return

    if TAG_RE.fullmatch(ref):
        if not repository_tag_exists(ref):
            errors.append(
                f"{location}: tag {ref!r} is unavailable; fetch tags (git fetch --tags --force) "
                f"before validating: {target!r}"
            )
        elif not repository_file_exists(ref, relative):
            errors.append(
                f"{location}: repository link does not name a file at tag {ref}: {target!r}"
            )
        return

    if not (ROOT / relative).exists():
        errors.append(
            f"{location}: repository link to {ref!r} does not name a file in this checkout: "
            f"{target!r}"
        )


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
            validate_repository_link(
                markdown,
                target,
                ref,
                relative,
                errors,
                required_repository_tag,
                repository_tag_available,
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


def _emit(level: str, message: str) -> None:
    """Print a diagnostic, as a workflow annotation when running in GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message}")
    else:
        print(f"{level.upper()}: {message}", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-current-release",
        action="store_true",
        help="fail when release.json does not match the SDK manifests at HEAD "
        "(use in the pull request that re-pins the skill after a release)",
    )
    args = parser.parse_args(argv)

    errors: list[str] = []
    warnings: list[str] = []
    notices: list[str] = []

    contract = load_release_contract(errors)
    required_tag = contract.get("repository_tag") if contract else None
    tag_available = validate_release_contract(contract, errors) if contract else False
    if contract:
        check_release_drift(contract, errors, warnings, args.require_current_release)
    load_behavioral_eval_results(errors, notices)

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

    for notice in notices:
        _emit("notice", notice)
    for warning in warnings:
        _emit("warning", warning)
    if errors:
        for error in errors:
            _emit("error", error)
        return 1

    print(
        f"Validated {len(skill_dirs)} skills, {checked_links} portable links, "
        f"and release contract {required_tag}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
