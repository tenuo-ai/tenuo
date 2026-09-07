"""Job summary: what this run may do. No secrets, no holder key."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


def format_job_summary(
    *,
    tools: Iterable[str],
    repository: str = "",
    issue: Optional[int] = None,
    warrant_id: str = "",
    expires_at: str = "",
    ttl_seconds: int = 0,
    gateway_url: str = "",
    task_binding: Optional[Mapping[str, Any]] = None,
) -> str:
    """Markdown for GITHUB_STEP_SUMMARY. Safe to print in the Actions UI."""
    names = [str(item) for item in tools if str(item).strip()]
    binding = dict(task_binding or {})
    number = issue
    if number is None and binding.get("number") is not None:
        try:
            number = int(binding["number"])
        except (TypeError, ValueError):
            number = None
    kind = str(binding.get("type") or "issue")
    if repository and number is not None:
        bound = f"{repository}#{number}"
    elif number is not None:
        bound = f"{kind} {number}"
    elif repository:
        bound = repository
    else:
        bound = "this run's triggering object"

    lines = [
        "## Tenuo",
        "",
        "This run may:",
        "",
    ]
    if names:
        for name in names:
            lines.append(f"- `{name}` on `{bound}`")
    else:
        lines.append(f"- no tools advertised for `{bound}`")
    lines.extend(["", "Bounds", ""])
    if ttl_seconds:
        lines.append(f"- TTL {ttl_seconds}s")
    if expires_at:
        lines.append(f"- Expires `{expires_at}`")
    if warrant_id:
        lines.append(f"- Warrant `{warrant_id}`")
    if gateway_url:
        lines.append(f"- Gateway `{gateway_url}`")
    lines.extend(
        [
            "",
            "The GitHub App installation may reach every repository it is installed on. "
            "This warrant cannot.",
            "",
        ]
    )
    return "\n".join(lines)


def write_job_summary(text: str, *, path: Optional["str | Path"] = None) -> None:
    """Append to GITHUB_STEP_SUMMARY when GitHub provides one."""
    if not path:
        return
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")
