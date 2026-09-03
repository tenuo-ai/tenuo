"""Tool catalog for the verify-only gateway.

``github-triage`` tools are registered and execute nothing. Tripwires are
registered so the containment check can call them; the gateway ceiling
refuses them even if a warrant names them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    arguments: Tuple[str, ...]
    tripwire: bool = False
    mutating: bool = False


TRIAGE: Tuple[ToolSpec, ...] = (
    ToolSpec("github.get_issue", "Read one issue.", ("repository", "issue")),
    ToolSpec("github.list_issue_comments", "List comments on an issue.", ("repository", "issue")),
    ToolSpec("github.add_comment", "Add a comment.", ("repository", "issue", "body"), mutating=True),
    ToolSpec("github.add_labels", "Add labels.", ("repository", "issue", "labels"), mutating=True),
    ToolSpec("github.remove_label", "Remove a label.", ("repository", "issue", "name"), mutating=True),
    ToolSpec(
        "github.close_issue",
        "Close an issue.",
        ("repository", "issue", "state_reason"),
        mutating=True,
    ),
)

TRIPWIRES: Tuple[ToolSpec, ...] = (
    ToolSpec("github.workflow_dispatch", "Tripwire: start a workflow.", ("repository", "workflow"), tripwire=True, mutating=True),
    ToolSpec("github.get_file_contents", "Tripwire until github-review.", ("repository", "path", "ref"), tripwire=True),
    ToolSpec("github.update_workflow", "Tripwire: write a workflow file.", ("repository", "path"), tripwire=True, mutating=True),
    ToolSpec("github.get_secret", "Tripwire: read a secret.", ("repository", "name"), tripwire=True),
    ToolSpec("github.create_deploy_key", "Tripwire: create a deploy key.", ("repository",), tripwire=True, mutating=True),
    ToolSpec("github.create_release", "Tripwire: create a release.", ("repository", "tag"), tripwire=True, mutating=True),
    ToolSpec("install_package", "Tripwire: install a package on the runner.", ("name",), tripwire=True, mutating=True),
)

PACKS: Dict[str, Tuple[ToolSpec, ...]] = {"github-triage": TRIAGE}

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
