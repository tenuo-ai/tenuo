"""Infer the run's capabilities from the GitHub event.

``infer_capabilities`` is the job's request, not a ceiling. Open comment
fields are filled at issuance (OSS stand-in for a Cloud template) so they
land on the warrant. The gateway does not re-apply them.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from tenuo import CEL, Pattern

from .catalog import COMMENT_BODY_CEL


class TaskError(ValueError):
    """The job event does not determine a task."""


_ISSUE_EVENTS = frozenset({"issues", "issue_comment"})


def infer_capabilities(
    *,
    event_name: str,
    event: Optional[Mapping[str, Any]] = None,
    repository: str = "",
    issue: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    """Bind github-triage to the triggering issue. Repository comes from OIDC."""
    if event_name not in _ISSUE_EVENTS:
        raise TaskError(f"cannot infer a task from event {event_name!r}")
    number = issue
    if number is None and event is not None:
        raw = (event.get("issue") or {}).get("number")
        if raw is not None:
            number = int(raw)
    if number is None:
        raise TaskError("issue number is required")
    bound: Dict[str, Any] = {"issue": int(number)}
    if repository:
        bound["repository"] = repository
    return {
        "github.get_issue": dict(bound),
        "github.list_issue_comments": dict(bound),
        "github.add_comment": dict(bound),
    }


def expand_issuance_constraints(tool: str, constraints: Dict[str, Any]) -> Dict[str, Any]:
    """Write inferred comment fields into the warrant. Cloud templates do this."""
    if tool != "github.add_comment":
        return constraints
    out = dict(constraints)
    if "body" not in out:
        out["body"] = CEL(COMMENT_BODY_CEL)
    if "body_sha256" not in out:
        out["body_sha256"] = Pattern("*")
    return out


def infer_task_binding(
    *,
    event_name: str,
    event: Optional[Mapping[str, Any]] = None,
    issue: Optional[int] = None,
) -> Dict[str, Any]:
    """Send only ``{type, number}``. Cloud assigns assurance; do not supply it.

    GitHub OIDC does not attest the issue number. The runner asserts it; Cloud
    may upgrade a pull-request binding after an independent provider lookup.
    """
    if event_name not in _ISSUE_EVENTS:
        raise TaskError(f"cannot infer a task from event {event_name!r}")
    number = issue
    if number is None and event is not None:
        raw = (event.get("issue") or {}).get("number")
        if raw is not None:
            number = int(raw)
    if number is None:
        raise TaskError("issue number is required")
    return {"type": "issue", "number": int(number)}
