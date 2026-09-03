"""I3 / I6 and I10 for the verify-only gateway."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("tenuo_core")

from tenuo import Exact, Range
from tenuo.mcp import TENUO_CONSTRAINT_VIOLATION, TENUO_TOOL_NOT_AUTHORIZED
from tenuo_core import SigningKey, Warrant, verify_receipt

from tenuo_gha.app import Gateway
from tenuo_gha.check import all_passed, run_containment
from tenuo_gha.config import ConfigError, GatewayConfig


def _config(tmp_path: Path, issuer: SigningKey, environ: dict) -> GatewayConfig:
    root = issuer.public_key.to_bytes().hex()
    env = {
        "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
        "TENUO_ROOT_PUBLIC_KEY": root,
        **environ,
    }
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {"provider": "memory"},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "receipts": {"path": str(tmp_path / "receipts.jsonl")},
        },
        environ=env,
    )


def _triage_warrant(issuer: SigningKey, holder: SigningKey) -> Warrant:
    return (
        Warrant.mint_builder()
        .capability("github.get_issue", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .capability("github.add_comment", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )


def test_i10_refuses_github_token(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="I10"):
        _config(tmp_path, issuer, {"GITHUB_TOKEN": "ghs_not_a_real_token"})


def test_memory_keys_require_the_escape(tmp_path):
    issuer = SigningKey.generate()
    env = {"TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex()}
    with pytest.raises(ConfigError, match="TENUO_ALLOW_INSECURE_MEMORY_KEYS"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ=env,
        )


def test_github_credentials_are_a_startup_error(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="credentials.github"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "credentials": {"github": {"provider": "token", "token_env": "GITHUB_TOKEN"}},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_i10_refuses_pem_in_env(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="PEM"):
        _config(
            tmp_path,
            issuer,
            {"SIGNING_KEY": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"},
        )


def test_i10_refuses_embedded_token_in_yaml(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="I10"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "notes": "ghs_not_a_real_token",
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_containment_fixtures_deny_and_allowed_read_passes(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    os.environ["TENUO_ALLOW_INSECURE_MEMORY_KEYS"] = "1"
    gateway = Gateway(_config(tmp_path, issuer, {}))
    warrant = _triage_warrant(issuer, holder)
    rows = run_containment(
        gateway,
        warrant,
        holder,
        bound_repository="acme/widgets",
        bound_issue=4127,
        foreign_repository="acme/payments-internal",
    )
    assert all_passed(rows), "\n".join(f"{r.name}: expected {r.expected} got {r.actual}" for r in rows)
    text = Path(tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
    assert text.strip(), "I6: denials and the allow must produce receipts"


def test_cross_repo_receipt_is_a_constraint_denial(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    gateway = Gateway(_config(tmp_path, issuer, {}))
    warrant = _triage_warrant(issuer, holder)
    rows = run_containment(
        gateway,
        warrant,
        holder,
        bound_repository="acme/widgets",
        bound_issue=4127,
        foreign_repository="acme/payments-internal",
    )
    lost = next(r for r in rows if r.name.startswith("GitLost"))
    assert lost.actual == TENUO_CONSTRAINT_VIOLATION
    dispatch = next(r for r in rows if "workflow_dispatch" in r.name)
    assert dispatch.actual == TENUO_TOOL_NOT_AUTHORIZED
    gateway.flush_receipts()
    lines = Path(tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 2
    # File sink stores JSON {"receipt": "hex"}; verify the first hex we find.
    import json

    payload = verify_receipt(json.loads(lines[0])["receipt"])
    assert payload.outcome in {"allow", "deny"}


def test_tripwire_denies_even_when_the_warrant_names_it(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    os.environ["TENUO_ALLOW_INSECURE_MEMORY_KEYS"] = "1"
    gateway = Gateway(_config(tmp_path, issuer, {}))
    warrant = (
        Warrant.mint_builder()
        .capability("github.workflow_dispatch", repository=Exact("acme/widgets"))
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )
    import base64
    import time

    args = {"repository": "acme/widgets", "workflow": "release.yml"}
    sig = warrant.sign(holder, "github.workflow_dispatch", args, int(time.time()))
    result = gateway.verify(
        "github.workflow_dispatch",
        args,
        meta={
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(bytes(sig)).decode(),
            }
        },
    )
    assert not result.allowed
    assert result.error_code == TENUO_TOOL_NOT_AUTHORIZED
    assert result.presented_chain
    assert gateway.flush_receipts()
    import json

    lines = Path(tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = verify_receipt(json.loads(lines[0])["receipt"])
    assert payload.outcome == "deny"
