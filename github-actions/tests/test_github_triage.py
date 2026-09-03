"""Allowed triage calls hit GitHub; denials do not."""

from __future__ import annotations

import base64
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("tenuo_core")

from tenuo import Exact, Pattern, Range
from tenuo.mcp import TENUO_CONSTRAINT_VIOLATION
from tenuo_core import SigningKey, Warrant

from tenuo_gha.app import Gateway
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.github import GitHubApp


def _config(tmp_path: Path, issuer: SigningKey, *, with_app: bool = True) -> GatewayConfig:
    raw: dict = {
        "version": 1,
        "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
        "signing": {"provider": "memory"},
        "ceiling": {"repositories": ["acme/widgets"]},
        "tools": {"packs": ["github-triage"]},
        "receipts": {"path": str(tmp_path / "receipts.jsonl")},
    }
    if with_app:
        raw["credentials"] = {
            "github": {
                "provider": "app",
                "app_id": "123",
                "api_url": "https://api.github.com",
                "installation_id": "9",
            }
        }
    return GatewayConfig.from_mapping(
        raw,
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def _warrant(issuer: SigningKey, holder: SigningKey) -> Warrant:
    return (
        Warrant.mint_builder()
        .capability("github.get_issue", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .capability(
            "github.add_comment",
            repository=Exact("acme/widgets"),
            issue=Range(4127, 4127),
            body=Pattern("*"),
        )
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )


def _meta(warrant: Warrant, key: SigningKey, tool: str, args: dict) -> dict:
    sig = warrant.sign(key, tool, args, int(time.time()))
    return {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(sig)).decode(),
        }
    }


def _mock_github(tmp_path: Path, issuer: SigningKey, recorded: list) -> tuple[Gateway, GitHubApp]:
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, request.url.path, request.read()))
        if request.method == "POST" and request.url.path.endswith("/comments"):
            return httpx.Response(
                201,
                json={"id": 77, "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-77"},
            )
        if request.method == "GET" and "/issues/" in request.url.path:
            return httpx.Response(
                200,
                json={"number": 4127, "title": "bug", "html_url": "https://github.com/acme/widgets/issues/4127", "state": "open"},
            )
        return httpx.Response(404, json={"message": "not mocked"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url="https://api.github.com")
    config = _config(tmp_path, issuer)
    github = GitHubApp(
        config,
        client=client,
        mint_token=lambda _repo: ("installation-token", int(time.time()) + 3600),
    )
    return Gateway(config, github=github), github


def test_app_provider_is_allowed_on_gateway(tmp_path):
    issuer = SigningKey.generate()
    config = _config(tmp_path, issuer)
    assert config.github_app_id == "123"


def test_app_without_client_refuses_to_construct(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="GitHub App signing"):
        Gateway(_config(tmp_path, issuer))


def test_exchange_role_refuses_github_credentials(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="exchange role"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "credentials": {"github": {"provider": "app", "app_id": "1"}},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROLE": "exchange",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_allowed_comment_hits_github(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = _warrant(issuer, holder)
    args = {"repository": "acme/widgets", "issue": 4127, "body": "looks good"}
    result, payload = gateway.execute(
        "github.add_comment",
        args,
        meta=_meta(warrant, holder, "github.add_comment", args),
    )
    assert result.allowed
    assert payload == {
        "comment_id": 77,
        "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-77",
    }
    assert recorded
    assert recorded[0][0] == "POST"
    assert "/repos/acme/widgets/issues/4127/comments" in recorded[0][1]


def test_cross_repo_read_does_not_call_github(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = _warrant(issuer, holder)
    args = {"repository": "acme/payments-internal", "issue": 1}
    result, payload = gateway.execute(
        "github.get_issue",
        args,
        meta=_meta(warrant, holder, "github.get_issue", args),
    )
    assert not result.allowed
    assert result.error_code == TENUO_CONSTRAINT_VIOLATION
    assert payload is None
    assert recorded == []
    assert gateway.flush_receipts()
    text = Path(tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
    assert text.strip()


def test_token_is_not_in_github_error_text(tmp_path):
    issuer = SigningKey.generate()
    config = _config(tmp_path, issuer)

    def fail(_repo: str):
        raise RuntimeError("mint failed")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "bad credentials"})

    github = GitHubApp(
        config,
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://api.github.com",
        ),
        mint_token=lambda _repo: ("installation-token", int(time.time()) + 3600),
    )
    from tenuo_gha.catalog import spec_by_name, tools_for_packs
    from tenuo_gha.github import GitHubError

    spec = spec_by_name("github.get_issue", tools_for_packs(["github-triage"]))
    with pytest.raises(GitHubError) as caught:
        github.call(spec, {"repository": "acme/widgets", "issue": 1})
    assert "installation-token" not in str(caught.value)
