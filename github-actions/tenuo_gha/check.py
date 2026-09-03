"""Replay fixture calls against a local gateway and print expected vs actual."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from tenuo.mcp import (
    TENUO_CONSTRAINT_VIOLATION,
    TENUO_TOOL_NOT_AUTHORIZED,
)

from .app import Gateway


@dataclass
class CheckRow:
    name: str
    expected: str
    actual: str
    ok: bool


def _meta(warrant: Any, key: Any, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    sig = warrant.sign(key, tool, args, int(time.time()))
    return {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(sig)).decode(),
        }
    }


def run_containment(
    gateway: Gateway,
    warrant: Any,
    holder_key: Any,
    *,
    bound_repository: str,
    bound_issue: int,
    foreign_repository: str,
) -> List[CheckRow]:
    """Replay the fixture table. Allowed stubs execute nothing."""
    rows: List[CheckRow] = []

    def row(name: str, expected: str, result: Any) -> None:
        actual = "allow" if result.allowed else (result.error_code or "deny")
        rows.append(CheckRow(name, expected, actual, actual == expected))

    allowed_args = {"repository": bound_repository, "issue": bound_issue}
    row(
        "allowed get_issue",
        "allow",
        gateway.verify(
            "github.get_issue",
            allowed_args,
            meta=_meta(warrant, holder_key, "github.get_issue", allowed_args),
        ),
    )

    cross = {"repository": foreign_repository, "issue": 1}
    row(
        "GitLost cross-repo read",
        TENUO_CONSTRAINT_VIOLATION,
        gateway.verify(
            "github.get_issue",
            cross,
            meta=_meta(warrant, holder_key, "github.get_issue", cross),
        ),
    )

    dispatch = {"repository": bound_repository, "workflow": "release.yml"}
    row(
        "Gemini workflow_dispatch",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify(
            "github.workflow_dispatch",
            dispatch,
            meta=_meta(warrant, holder_key, "github.workflow_dispatch", dispatch),
        ),
    )

    install = {"name": "evil-pkg"}
    row(
        "Clinejection install_package",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify(
            "install_package",
            install,
            meta=_meta(warrant, holder_key, "install_package", install),
        ),
    )

    unsafe = {"repository": bound_repository, "path": ".env", "ref": "main"}
    row(
        "unsafe path read",
        TENUO_TOOL_NOT_AUTHORIZED,
        gateway.verify(
            "github.get_file_contents",
            unsafe,
            meta=_meta(warrant, holder_key, "github.get_file_contents", unsafe),
        ),
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
    lines = [f"{'name':<36} {'expected':<28} {'actual':<28} result"]
    for row in rows:
        mark = "ok" if row.ok else "FAIL"
        lines.append(f"{row.name:<36} {row.expected:<28} {row.actual:<28} {mark}")
    return "\n".join(lines)


def main() -> None:
    """Mint an in-process issuer and replay the fixture table."""
    import tempfile
    from pathlib import Path

    from tenuo import Exact, Range
    from tenuo_core import SigningKey, Warrant

    from .app import Gateway
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
