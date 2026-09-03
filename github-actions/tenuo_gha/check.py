"""Replay fixture calls the way the demo worker did: through the holder."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from tenuo.mcp import (
    TENUO_CONSTRAINT_VIOLATION,
    TENUO_TOOL_NOT_AUTHORIZED,
)

from .app import Gateway
from .holder import HolderClient
from .shim import call_gateway


@dataclass
class CheckRow:
    name: str
    expected: str
    actual: str
    ok: bool


def _call(
    holder: HolderClient,
    gateway_url: str,
    tool: str,
    arguments: Dict[str, Any],
    *,
    client: Any = None,
) -> Dict[str, Any]:
    envelope = holder.envelope(tool, arguments)
    return call_gateway(gateway_url, tool, arguments, envelope, client=client)


def run_agent_table(
    holder: HolderClient,
    gateway_url: str,
    *,
    bound_repository: str,
    bound_issue: int,
    foreign_repository: str,
    comment_body: str = "looks good",
    client: Any = None,
    environ: Optional[Dict[str, str]] = None,
) -> List[CheckRow]:
    """Same scenarios as the isolated-gateway worker in the 2026 demo."""
    rows: List[CheckRow] = []

    def row(name: str, expected: str, actual: str) -> None:
        rows.append(CheckRow(name, expected, actual, actual == expected))

    def attempt(name: str, tool: str, arguments: Dict[str, Any], expected: str) -> None:
        outcome = _call(holder, gateway_url, tool, arguments, client=client)
        if outcome.get("allowed"):
            actual = "allow"
        else:
            actual = str(outcome.get("error_code") or "deny")
        row(name, expected, actual)

    allowed = {"repository": bound_repository, "issue": bound_issue}
    attempt("allowed get_issue", "github.get_issue", allowed, "allow")
    attempt(
        "exact delegated issue comment",
        "github.add_comment",
        {**allowed, "body": comment_body},
        "allow",
    )
    attempt(
        "same worker targets a different issue",
        "github.add_comment",
        {**allowed, "issue": bound_issue + 1, "body": comment_body},
        TENUO_CONSTRAINT_VIOLATION,
    )
    attempt(
        "GitLost cross-repo read",
        "github.get_issue",
        {"repository": foreign_repository, "issue": 1},
        TENUO_CONSTRAINT_VIOLATION,
    )
    attempt(
        "Gemini workflow_dispatch",
        "github.workflow_dispatch",
        {"repository": bound_repository, "workflow": "release.yml"},
        TENUO_TOOL_NOT_AUTHORIZED,
    )
    attempt(
        "Clinejection install_package",
        "install_package",
        {"name": "evil-pkg"},
        TENUO_TOOL_NOT_AUTHORIZED,
    )
    attempt(
        "tripwire get_file_contents (not in github-triage)",
        "github.get_file_contents",
        {"repository": bound_repository, "path": ".env", "ref": "main"},
        TENUO_TOOL_NOT_AUTHORIZED,
    )
    attempt(
        "same worker attempts a workflow edit",
        "github.update_workflow",
        {"repository": bound_repository, "path": ".github/workflows/backdoor.yml"},
        TENUO_TOOL_NOT_AUTHORIZED,
    )

    bare = call_gateway(
        gateway_url,
        "github.add_comment",
        {**allowed, "body": comment_body},
        {},
        client=client,
    )
    row(
        "request omits warrant and proof",
        "deny",
        "allow" if bare.get("allowed") else "deny",
    )

    env = environ if environ is not None else os.environ
    has_token = bool(env.get("GITHUB_TOKEN") or env.get("GH_TOKEN"))
    row("worker has no GitHub token", "absent", "present" if has_token else "absent")
    return rows


def run_containment(
    gateway: Gateway,
    warrant: Any,
    holder_key: Any,
    *,
    bound_repository: str,
    bound_issue: int,
    foreign_repository: str,
) -> List[CheckRow]:
    """In-process verify table used by the image check."""
    import base64
    import time

    rows: List[CheckRow] = []

    def meta(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        sig = warrant.sign(holder_key, tool, args, int(time.time()))
        return {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(bytes(sig)).decode(),
            }
        }

    def row(name: str, expected: str, result: Any) -> None:
        actual = "allow" if result.allowed else (result.error_code or "deny")
        rows.append(CheckRow(name, expected, actual, actual == expected))

    allowed_args = {"repository": bound_repository, "issue": bound_issue}
    row(
        "allowed get_issue",
        "allow",
        gateway.verify("github.get_issue", allowed_args, meta=meta("github.get_issue", allowed_args)),
    )
    cross = {"repository": foreign_repository, "issue": 1}
    row(
        "GitLost cross-repo read",
        TENUO_CONSTRAINT_VIOLATION,
        gateway.verify("github.get_issue", cross, meta=meta("github.get_issue", cross)),
    )
    dispatch = {"repository": bound_repository, "workflow": "release.yml"}
    row(
        "Gemini workflow_dispatch",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify("github.workflow_dispatch", dispatch, meta=meta("github.workflow_dispatch", dispatch)),
    )
    install = {"name": "evil-pkg"}
    row(
        "Clinejection install_package",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify("install_package", install, meta=meta("install_package", install)),
    )
    unsafe = {"repository": bound_repository, "path": ".env", "ref": "main"}
    row(
        "tripwire get_file_contents (not in github-triage)",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify("github.get_file_contents", unsafe, meta=meta("github.get_file_contents", unsafe)),
    )
    bare = gateway.verify("github.get_issue", allowed_args, meta={})
    rows.append(
        CheckRow(
            "no envelope",
            "deny-no-receipt",
            "deny-no-receipt" if (not bare.allowed and not bare.presented_chain) else "unexpected",
            not bare.allowed and not bare.presented_chain,
        )
    )
    gateway.flush_receipts()
    return rows


def all_passed(rows: List[CheckRow]) -> bool:
    return all(row.ok for row in rows)


def format_table(rows: List[CheckRow]) -> str:
    lines = [f"{'name':<42} {'expected':<28} {'actual':<28} result"]
    for row in rows:
        mark = "ok" if row.ok else "FAIL"
        lines.append(f"{row.name:<42} {row.expected:<28} {row.actual:<28} {mark}")
    return "\n".join(lines)


def main() -> None:
    """Mint an in-process issuer and replay the fixture table."""
    import tempfile
    from pathlib import Path

    from tenuo import Exact, Range
    from tenuo_core import SigningKey, Warrant

    from .config import GatewayConfig

    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    receipts = Path(tempfile.mkdtemp()) / "receipts.jsonl"
    environ = {
        "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
        "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
    }
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {"provider": "memory"},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "receipts": {"path": str(receipts)},
        },
        environ=environ,
    )
    warrant = (
        Warrant.mint_builder()
        .capability("github.get_issue", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .capability("github.add_comment", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )
    rows = run_containment(
        Gateway(config),
        warrant,
        holder,
        bound_repository="acme/widgets",
        bound_issue=4127,
        foreign_repository="acme/payments-internal",
    )
    print(format_table(rows))
    if not all_passed(rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
