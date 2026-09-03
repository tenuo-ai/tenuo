"""Tool catalog. Ceiling tools are registered and always refused."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments: Tuple[str, ...]
    tripwire: bool = False
    mutating: bool = False
    method: str = "GET"
    path: Optional[str] = None
    body: Optional[Dict[str, str]] = None
    response: Optional[Dict[str, str]] = None


TRIAGE: Tuple[ToolSpec, ...] = (
    ToolSpec(
        "github.get_issue",
        "Read one issue.",
        ("repository", "issue"),
        path="/repos/{repository}/issues/{issue}",
        response={"number": "number", "title": "title", "html_url": "html_url", "state": "state"},
    ),
    ToolSpec(
        "github.list_issue_comments",
        "List comments on an issue.",
        ("repository", "issue"),
        path="/repos/{repository}/issues/{issue}/comments",
    ),
    ToolSpec(
        "github.add_comment",
        "Add a comment.",
        ("repository", "issue", "body"),
        mutating=True,
        method="POST",
        path="/repos/{repository}/issues/{issue}/comments",
        body={"body": "{body}"},
        response={"comment_id": "id", "html_url": "html_url"},
    ),
    ToolSpec(
        "github.add_labels",
        "Add labels.",
        ("repository", "issue", "labels"),
        mutating=True,
        method="POST",
        path="/repos/{repository}/issues/{issue}/labels",
        body={"labels": "{labels}"},
    ),
    ToolSpec(
        "github.remove_label",
        "Remove a label.",
        ("repository", "issue", "name"),
        mutating=True,
        method="DELETE",
        path="/repos/{repository}/issues/{issue}/labels/{name}",
    ),
    ToolSpec(
        "github.close_issue",
        "Close an issue.",
        ("repository", "issue", "state_reason"),
        mutating=True,
        method="PATCH",
        path="/repos/{repository}/issues/{issue}",
        body={"state": "closed", "state_reason": "{state_reason}"},
    ),
)

TRIPWIRES: Tuple[ToolSpec, ...] = (
    ToolSpec("github.workflow_dispatch", "Start a workflow.", ("repository", "workflow"), tripwire=True, mutating=True),
    ToolSpec("github.get_file_contents", "Read a file.", ("repository", "path", "ref"), tripwire=True),
    ToolSpec("github.update_workflow", "Write a workflow file.", ("repository", "path"), tripwire=True, mutating=True),
    ToolSpec("github.get_secret", "Read a secret.", ("repository", "name"), tripwire=True),
    ToolSpec("github.create_deploy_key", "Create a deploy key.", ("repository",), tripwire=True, mutating=True),
    ToolSpec("github.create_release", "Create a release.", ("repository", "tag"), tripwire=True, mutating=True),
    ToolSpec("install_package", "Install a package on the runner.", ("name",), tripwire=True, mutating=True),
)

PACKS: Dict[str, Tuple[ToolSpec, ...]] = {"github-triage": TRIAGE}

# Free-text comment body: non-empty, 64KiB ceiling. The leaf binds the exact digest.
COMMENT_BODY_CEL = "value.size() >= 1 && value.size() <= 65536"


def comment_body_digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def comment_digest_matches(arguments: Mapping[str, Any]) -> bool:
    """True when body_sha256 is the SHA-256 of the body the gateway would post."""
    body = arguments.get("body")
    claimed = arguments.get("body_sha256")
    return isinstance(body, str) and isinstance(claimed, str) and comment_body_digest(body) == claimed

TRIPWIRE_NAMES = frozenset(spec.name for spec in TRIPWIRES)


def tools_for_packs(packs: List[str]) -> List[ToolSpec]:
    chosen: List[ToolSpec] = []
    seen = set()
    for pack in packs:
        if pack not in PACKS:
            raise ValueError(f"unknown pack {pack!r}")
        for spec in PACKS[pack]:
            if spec.name not in seen:
                chosen.append(spec)
                seen.add(spec.name)
    for spec in TRIPWIRES:
        if spec.name not in seen:
            chosen.append(spec)
            seen.add(spec.name)
    return chosen


def spec_by_name(name: str, tools: List[ToolSpec]) -> Optional[ToolSpec]:
    for spec in tools:
        if spec.name == name:
            return spec
    return None
