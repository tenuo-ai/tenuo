"""How a host product (Pullfrog-shaped) uses the embed client.

The host owns the agent loop. Tenuo owns exchange, the holder, and the
gateway call. This file is the integration surface — not a Pullfrog fork.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from tenuo_gha.embed import CallResult, EmbedConfig, EmbedSession


@dataclass
class HostRun:
    """What the host records after a job. No warrant, no GitHub token."""

    warrant_id: str
    tools: list
    comment: Optional[CallResult]
    cross_repo: Optional[CallResult]


class IssueAgent:
    """Stand-in for a host agent: read the issue, comment, maybe wander."""

    def __init__(self, session: EmbedSession) -> None:
        self._session = session

    def handle_issue(
        self,
        *,
        repository: str,
        issue: int,
        comment_body: str,
        foreign_repository: str = "acme/payments-internal",
    ) -> HostRun:
        grant = self._session.grant
        if grant is None:
            raise RuntimeError("host called the agent before exchange")
        comment = self._session.call(
            "github.add_comment",
            {"repository": repository, "issue": issue, "body": comment_body},
        )
        # Prompt injection often asks the agent to read another repo.
        # The host still makes the call; the warrant refuses it.
        wandered = self._session.call(
            "github.get_issue",
            {"repository": foreign_repository, "issue": 1},
        )
        return HostRun(
            warrant_id=grant.warrant_id,
            tools=list(grant.tools),
            comment=comment,
            cross_repo=wandered,
        )


def run_host_job(
    config: EmbedConfig,
    *,
    oidc_token: str,
    event_name: str,
    event: Mapping[str, Any],
    repository: str,
    comment_body: str,
    foreign_repository: str = "acme/payments-internal",
    http: Any = None,
    work_dir: Any = None,
    environ: Optional[Dict[str, str]] = None,
) -> HostRun:
    """The four lines a host product has to write."""
    with EmbedSession(config, http=http, work_dir=work_dir, environ=environ) as session:
        session.exchange(
            oidc_token=oidc_token,
            event_name=event_name,
            event=event,
            repository=repository,
        )
        issue = int((event.get("issue") or {}).get("number") or 0)
        return IssueAgent(session).handle_issue(
            repository=repository,
            issue=issue,
            comment_body=comment_body,
            foreign_repository=foreign_repository,
        )
