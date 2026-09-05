"""Allowed triage calls hit GitHub; denials do not."""

from __future__ import annotations

import base64
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("tenuo_core")

from tenuo import CEL, Exact, Pattern, Range
from tenuo.mcp import TENUO_CONSTRAINT_VIOLATION
from tenuo_core import SigningKey, Warrant

from tenuo_gha.app import Gateway
from tenuo_gha.catalog import COMMENT_BODY_CEL
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.github import GitHubApp, GitHubError, format_path, parse_github_expiry
from tenuo_gha.holder import Holder, bind_call_arguments


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
            body=CEL(COMMENT_BODY_CEL),
            body_sha256=Pattern("*"),
        )
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )


def _present(warrant: Warrant, key: SigningKey, tool: str, args: dict) -> dict:
    holder = Holder(key=key)
    holder.set_warrant(warrant.to_base64())
    return holder.envelope(tool, args)


def _call(gateway: Gateway, warrant: Warrant, key: SigningKey, tool: str, args: dict):
    envelope = _present(warrant, key, tool, args)
    return gateway.execute(tool, envelope["arguments"], meta={"tenuo": envelope})


def _mock_github(tmp_path: Path, issuer: SigningKey, recorded: list) -> tuple[Gateway, GitHubApp]:
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, request.url.raw_path.decode(), request.read()))
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
        if request.method == "DELETE" and "/labels/" in request.url.path:
            return httpx.Response(204)
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
    result, payload = _call(
        gateway,
        warrant,
        holder,
        "github.add_comment",
        {"repository": "acme/widgets", "issue": 4127, "body": "looks good"},
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
    result, payload = _call(
        gateway,
        warrant,
        holder,
        "github.get_issue",
        {"repository": "acme/payments-internal", "issue": 1},
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


def test_warrant_repository_is_the_authorization(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = (
        Warrant.mint_builder()
        .capability("github.get_issue", repository=Exact("acme/canary"), issue=Range(1, 1))
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )
    result, payload = _call(
        gateway,
        warrant,
        holder,
        "github.get_issue",
        {"repository": "acme/canary", "issue": 1},
    )
    assert result.allowed
    assert payload is not None
    assert recorded
    assert gateway.flush_receipts()
    assert (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip()


def test_remove_label_encodes_slash_in_the_path(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = (
        Warrant.mint_builder()
        .capability(
            "github.remove_label",
            repository=Exact("acme/widgets"),
            issue=Range(4127, 4127),
            name=Exact("triage/demo"),
        )
        .holder(holder.public_key)
        .ttl(900)
        .mint(issuer)
    )
    result, payload = _call(
        gateway,
        warrant,
        holder,
        "github.remove_label",
        {"repository": "acme/widgets", "issue": 4127, "name": "triage/demo"},
    )
    assert result.allowed
    assert payload == {"ok": True}
    assert recorded
    assert recorded[0][0] == "DELETE"
    assert recorded[0][1].endswith("/labels/triage%2Fdemo")
    assert "/labels/triage/demo" not in recorded[0][1]


def test_path_encoding_keeps_repository_slash():
    path = format_path(
        "/repos/{repository}/issues/{issue}/labels/{name}",
        {"repository": "acme/widgets", "issue": 4127, "name": "triage/demo"},
    )
    assert path == "/repos/acme/widgets/issues/4127/labels/triage%2Fdemo"


def test_network_error_is_a_github_error(tmp_path):
    issuer = SigningKey.generate()
    config = _config(tmp_path, issuer)

    def boom(request: httpx.Request):
        raise httpx.ConnectError("connection refused", request=request)

    github = GitHubApp(
        config,
        client=httpx.Client(
            transport=httpx.MockTransport(boom),
            base_url="https://api.github.com",
        ),
        mint_token=lambda _repo: ("installation-token", int(time.time()) + 3600),
    )
    from tenuo_gha.catalog import spec_by_name, tools_for_packs

    spec = spec_by_name("github.get_issue", tools_for_packs(["github-triage"]))
    with pytest.raises(GitHubError, match="network") as caught:
        github.call(spec, {"repository": "acme/widgets", "issue": 1})
    assert "installation-token" not in str(caught.value)
    assert "connection refused" not in str(caught.value)


def test_installation_token_expiry_is_parsed(tmp_path):
    issuer = SigningKey.generate()
    config = _config(tmp_path, issuer)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/access_tokens")
        return httpx.Response(
            201,
            json={"token": "ghs_not_a_real_token", "expires_at": "2099-01-15T12:00:00Z"},
        )

    github = GitHubApp(
        config,
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://api.github.com",
        ),
        sign_app_jwt=lambda _app_id: "app-jwt",
    )
    token = github.token_for("acme/widgets")
    assert token == "ghs_not_a_real_token"
    _cached_token, expires_at = github._cache["acme/widgets"]
    assert expires_at == parse_github_expiry("2099-01-15T12:00:00Z")
    assert expires_at > int(time.time()) + 3600 * 24


def test_dispatch_uses_cleaned_arguments(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = _warrant(issuer, holder)
    envelope = _present(
        warrant,
        holder,
        "github.add_comment",
        {"repository": "acme/widgets", "issue": 4127, "body": "looks good"},
    )
    result = gateway.verify(
        "github.add_comment",
        envelope["arguments"],
        meta={"tenuo": envelope},
    )
    assert result.allowed
    payload = gateway.dispatch(result)
    assert payload == {
        "comment_id": 77,
        "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-77",
    }
    assert recorded


def test_leaf_digest_mismatch_is_a_verifier_deny(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = _warrant(issuer, holder)
    envelope = _present(
        warrant,
        holder,
        "github.add_comment",
        {"repository": "acme/widgets", "issue": 4127, "body": "looks good"},
    )
    args = dict(envelope["arguments"])
    args["body_sha256"] = "0" * 64
    result, payload = gateway.execute(
        "github.add_comment",
        args,
        meta={"tenuo": envelope},
    )
    assert not result.allowed
    assert result.error_code in {TENUO_CONSTRAINT_VIOLATION, "TENUO_INVALID_POP"}
    assert payload is None
    assert recorded == []


def test_parent_only_stack_cannot_allow(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    recorded: list = []
    gateway, _ = _mock_github(tmp_path, issuer, recorded)
    warrant = _warrant(issuer, holder)
    args = bind_call_arguments(
        "github.add_comment",
        {"repository": "acme/widgets", "issue": 4127, "body": "looks good"},
    )
    sig = warrant.sign(holder, "github.add_comment", args, int(time.time()))
    result, payload = gateway.execute(
        "github.add_comment",
        args,
        meta={
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(bytes(sig)).decode(),
            }
        },
    )
    assert not result.allowed
    assert result.error_code == TENUO_CONSTRAINT_VIOLATION
    assert "terminal leaf" in (result.denial_reason or "")
    assert payload is None
    assert recorded == []
