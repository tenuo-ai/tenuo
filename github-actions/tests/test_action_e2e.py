"""OIDC → holder → gateway, at the same scenarios as the isolated-gateway demo."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jwt
import pytest
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

pytest.importorskip("tenuo_core")

from cryptography.hazmat.primitives.asymmetric import rsa
from tenuo_core import SigningKey

from tenuo_gha.action import ActionError, guardrails, run_job
from tenuo_gha.app import Gateway
from tenuo_gha.check import all_passed, format_table, run_agent_table
from tenuo_gha.config import GatewayConfig
from tenuo_gha.exchange import Exchange
from tenuo_gha.github import GitHubApp
from tenuo_gha.holder import HolderClient, HolderServer
from tenuo_gha.http import build_http
from tenuo_gha.oidc import fetch_actions_oidc
from tenuo_gha.task import TaskError, infer_capabilities


AUDIENCE = "tenuo:org/acme"
ISSUER = "https://token.actions.githubusercontent.com"


def _rsa_jwks():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "test"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}, key


def _claims(**overrides):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "jti": "e2e-1",
        "repository": "acme/widgets",
        "repository_id": "7890",
        "repository_owner": "acme",
        "repository_owner_id": "123456",
        "job_workflow_ref": "acme/widgets/.github/workflows/triage.yml@refs/heads/main",
        "event_name": "issues",
        "run_id": "77",
        "sub": "repo:acme/widgets:ref:refs/heads/main",
    }
    base.update(overrides)
    return base


def _token(key, **overrides) -> str:
    return jwt.encode(_claims(**overrides), key, algorithm="RS256", headers={"kid": "test"})


class _Http:
    def __init__(self, app) -> None:
        self._client = TestClient(app)

    def post(self, url, headers=None, json=None):
        return self._client.post(urlparse(url).path or url, headers=headers, json=json)

    def close(self) -> None:
        return None


def _combined_config(tmp_path: Path, issuer: SigningKey) -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {
                "root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"],
                "issuer": ISSUER,
            },
            "signing": {"provider": "memory"},
            "role": "both",
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "credentials": {
                "github": {
                    "provider": "app",
                    "app_id": "123",
                    "api_url": "https://api.github.com",
                    "installation_id": "9",
                }
            },
            "exchange": {
                "audience": AUDIENCE,
                "ttl_max": "15m",
                "jwks_url": "https://example.invalid/jwks",
                "conditions": {
                    "repository_owner_id": "123456",
                    "repository_id": ["7890"],
                    "event_name": ["issues", "issue_comment"],
                },
            },
            "receipts": {"path": str(tmp_path / "receipts.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ALLOW_COMBINED_ROLES": "1",
            "TENUO_ROLE": "both",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def _stack(tmp_path: Path, issuer: SigningKey, recorded: list):
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, request.url.raw_path.decode(), request.read()))
        if request.method == "POST" and request.url.path.endswith("/comments"):
            return httpx.Response(
                201,
                json={"id": 88, "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-88"},
            )
        if request.method == "GET" and "/issues/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "number": 4127,
                    "title": "bug",
                    "html_url": "https://github.com/acme/widgets/issues/4127",
                    "state": "open",
                },
            )
        return httpx.Response(404, json={"message": "not mocked"})

    config = _combined_config(tmp_path, issuer)
    github = GitHubApp(
        config,
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://api.github.com",
        ),
        mint_token=lambda _repo: ("installation-token", int(time.time()) + 3600),
    )
    gateway = Gateway(config, github=github)
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(config, issuer_key=issuer, jwks=jwks)
    app = build_http(config, exchange=exchange, gateway=gateway)
    return gateway, _Http(app), rsa_key


def _sock(name: str) -> Path:
    path = Path(f"/tmp/tenuo-e2e-{name}.sock")
    if path.exists():
        path.unlink()
    return path


def test_infer_capabilities_from_an_issues_event():
    caps = infer_capabilities(
        event_name="issues",
        event={"issue": {"number": 4127}},
        repository="acme/widgets",
    )
    assert caps["github.get_issue"] == {"issue": 4127, "repository": "acme/widgets"}
    assert "github.add_comment" in caps
    with pytest.raises(TaskError, match="pull_request"):
        infer_capabilities(event_name="pull_request", event={})


def test_oidc_fetch_uses_the_actions_url(monkeypatch):
    class _Resp:
        def read(self) -> bytes:
            return b'{"value":"oidc-jwt"}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    seen = {}

    def opener(request, timeout=10.0):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        return _Resp()

    token = fetch_actions_oidc(
        AUDIENCE,
        {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token?v=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token",
        },
        opener=opener,
    )
    assert token == "oidc-jwt"
    assert "audience=tenuo" in seen["url"]
    assert seen["auth"] == "Bearer req-token"


def test_job_refuses_a_github_token():
    with pytest.raises(Exception, match="GITHUB_TOKEN"):
        guardrails({"GITHUB_TOKEN": "ghs_not_a_real_token", "PATH": "/usr/bin"})


def test_oidc_exchange_holder_and_demo_scenarios(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway, http, rsa_key = _stack(tmp_path, issuer, recorded)
    socket = _sock("job")
    server = HolderServer(socket)
    server.start()
    try:
        result = run_job(
            gateway_url="http://test",
            exchange_url="http://test",
            audience=AUDIENCE,
            socket_path=socket,
            mcp_config=tmp_path / "mcp-config.json",
            event_name="issues",
            repository="acme/widgets",
            event={"issue": {"number": 4127}},
            oidc_token=_token(rsa_key),
            environ={
                "PATH": "/usr/bin",
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            },
            http=http,
            holder_server=server,
        )
        assert result["warrant_id"]
        assert result["expires_at"]
        text = Path(result["mcp_config"]).read_text(encoding="utf-8")
        assert "TENUO_HOLDER_SECRET" not in text
        assert "warrant" not in text
        assert "ghs_" not in text

        rows = run_agent_table(
            HolderClient(socket),
            "http://test",
            bound_repository="acme/widgets",
            bound_issue=4127,
            foreign_repository="acme/payments-internal",
            comment_body="Authorized by a holder-bound warrant.",
            client=http,
            environ={"PATH": "/usr/bin"},
        )
        print(format_table(rows))
        assert all_passed(rows), format_table(rows)
        assert gateway.flush_receipts()
        journal = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
        assert journal.strip()
        methods = [item[0] for item in recorded]
        assert "GET" in methods
        assert "POST" in methods
        assert any("/repos/acme/widgets/issues/4127/comments" in item[1] for item in recorded)
        assert not any("payments-internal" in item[1] for item in recorded)
        assert not any("installation-token" in str(item[2]) for item in recorded)
    finally:
        server.stop()
