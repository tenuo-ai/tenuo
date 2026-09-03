"""Infer the run's capabilities from the GitHub event."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


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
