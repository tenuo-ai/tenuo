#!/usr/bin/env python3
"""Re-pin the tenuo-agent-authorization skill to a released repository tag.

Rewrites the skill's release contract and pinned reference links, then
refreshes each behavioral result whose inputs changed as a carried-forward
result that names this re-pin. The agent-skill-repin workflow runs this on
every published release and opens the resulting change for review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_agent_skills import (  # noqa: E402
    BEHAVIORAL_EVAL_DIR,
    BEHAVIORAL_EVAL_GLOB,
    INTEGRATION_SKILL,
    RELEASE_CONTRACT,
    REPOSITORY_BLOB_PREFIX,
    ROOT,
    TAG_RE,
    behavioral_eval_fingerprint,
    manifest_version,
    repository_file_text,
    repository_tag_exists,
)


class RepinError(RuntimeError):
    """A re-pin could not be computed for the requested tag."""


def rewrite_links(text: str, old_tag: str, new_tag: str) -> str:
    """Retarget this repository's pinned blob links from one tag to another."""
    return text.replace(
        f"https://github.com{REPOSITORY_BLOB_PREFIX}{old_tag}/",
        f"https://github.com{REPOSITORY_BLOB_PREFIX}{new_tag}/",
    )


def updated_contract(
    contract: Dict[str, Any],
    tag: str,
    file_text: Callable[[str, Path], Optional[str]] = repository_file_text,
) -> Dict[str, Any]:
    """Return the contract re-pinned to ``tag`` with versions read at that tag."""
    updated = json.loads(json.dumps(contract))
    updated["repository_tag"] = tag
    for package in updated.get("packages", []):
        manifest = package.get("manifest")
        text = file_text(tag, Path(manifest)) if isinstance(manifest, str) else None
        if text is None:
            raise RepinError(f"{manifest} is missing at {tag}")
        version = manifest_version(text, package)
        if version is None:
            raise RepinError(f"could not read a version from {manifest} at {tag}")
        package["version"] = version
    return updated


def default_review(old_tag: str, new_tag: str) -> str:
    return (
        f"Automated re-pin from {old_tag} to {new_tag} after the release was published. "
        "Only release.json and the pinned repository links changed; skill instructions "
        "did not. Before merging, confirm the linked examples at the new tag still match "
        "the reference prose, and rerun payment-boundary-eval.md if any behavioral input "
        "changed."
    )


def refresh_results(review: str) -> List[Path]:
    """Re-fingerprint every result whose inputs changed and mark it carried forward."""
    changed: List[Path] = []
    for path in sorted(BEHAVIORAL_EVAL_DIR.glob(BEHAVIORAL_EVAL_GLOB)):
        result = json.loads(path.read_text(encoding="utf-8"))
        inputs = result.get("inputs")
        if not isinstance(inputs, list):
            continue
        current = behavioral_eval_fingerprint(inputs)
        if result.get("skill_fingerprint") == current:
            continue
        result["skill_fingerprint"] = current
        result["evidence_kind"] = "carried_forward"
        result["carried_forward_review"] = review
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        changed.append(path)
    return changed


def repin(tag: str, review: Optional[str] = None, dry_run: bool = False) -> List[Path]:
    """Re-pin the skill to ``tag``; return the files that change (or would change)."""
    if TAG_RE.fullmatch(tag) is None:
        raise RepinError(f"{tag!r} is not a semver release tag")
    if not repository_tag_exists(tag):
        raise RepinError(f"tag {tag!r} is unavailable; fetch tags first")

    contract = json.loads(RELEASE_CONTRACT.read_text(encoding="utf-8"))
    old_tag = contract.get("repository_tag")
    if old_tag == tag:
        return []

    new_contract = updated_contract(contract, tag)
    changed: List[Path] = [RELEASE_CONTRACT]
    rewritten: Dict[Path, str] = {}
    for markdown in sorted(INTEGRATION_SKILL.rglob("*.md")):
        text = markdown.read_text(encoding="utf-8")
        new_text = rewrite_links(text, old_tag, tag)
        if new_text != text:
            rewritten[markdown] = new_text
            changed.append(markdown)
    if dry_run:
        return changed + sorted(BEHAVIORAL_EVAL_DIR.glob(BEHAVIORAL_EVAL_GLOB))

    RELEASE_CONTRACT.write_text(json.dumps(new_contract, indent=2) + "\n", encoding="utf-8")
    for markdown, new_text in rewritten.items():
        markdown.write_text(new_text, encoding="utf-8")
    changed.extend(refresh_results(review or default_review(old_tag, tag)))
    return changed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag to pin, e.g. v0.4.0")
    parser.add_argument("--review", help="carried_forward_review text for refreshed results")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 without writing when the skill is not pinned to --tag",
    )
    args = parser.parse_args(argv)
    try:
        changed = repin(args.tag, args.review, dry_run=args.check)
    except RepinError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not changed:
        print(f"Skill already pinned to {args.tag}.")
        return 0
    verb = "would change" if args.check else "changed"
    for path in changed:
        print(f"{verb}: {path.relative_to(ROOT)}")
    return 1 if args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
