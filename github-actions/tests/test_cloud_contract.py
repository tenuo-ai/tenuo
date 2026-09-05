"""Contract tests against a Cloud-compatible POST /v1/exchange fixture."""

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
from tenuo import SignedRevocationList
from tenuo.mcp import TENUO_REVOKED
from tenuo_core import SigningKey, decode_warrant_stack_base64

from tenuo_gha.action import ActionError, run_job, verify_exchange_roots
from tenuo_gha.app import Gateway
from tenuo_gha.cloud import CloudCompatibleExchange
from tenuo_gha.config import GatewayConfig
from tenuo_gha.exchange import ExchangeError
from tenuo_gha.github import GitHubApp
from tenuo_gha.holder import HolderClient, HolderServer
from tenuo_gha.http import build_http
from tenuo_gha.shim import call_gateway
from tenuo_gha.commitment import (
    encode_proof,
    exchange_proof_preimage,
    exchange_request_hash,
    hash_json,
)
from tenuo_gha.task import infer_task_binding

from exchange_helpers import exchange_body, holder_proof


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
        "jti": "cloud-1",
        "repository": "acme/widgets",
        "repository_id": "7890",
        "repository_owner": "acme",
        "repository_owner_id": "123456",
        "job_workflow_ref": "acme/widgets/.github/workflows/triage.yml@refs/heads/main",
        "event_name": "issues",
        "run_id": "88",
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


def _config(tmp_path: Path, root: SigningKey, *, role: str = "exchange") -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "role": "both" if role == "both" else role,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"], "issuer": ISSUER},
            "signing": {"provider": "memory"},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "credentials": {
                "github": {
                    "provider": "app",
                    "app_id": "123",
                    "api_url": "https://api.github.com",
                    "installation_id": "9",
                }
            }
            if role != "exchange"
            else {},
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
            "TENUO_ROLE": "both" if role == "both" else role,
            "TENUO_ROOT_PUBLIC_KEY": root.public_key.to_bytes().hex(),
        },
    )


def _sock(name: str) -> Path:
    path = Path(f"/tmp/tenuo-cloud-{name}.sock")
    if path.exists():
        path.unlink()
    return path


def _cloud_stack(tmp_path: Path, root: SigningKey, recorded: list):
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, request.url.raw_path.decode(), request.read()))
        if request.method == "POST" and request.url.path.endswith("/comments"):
            return httpx.Response(
                201,
                json={"id": 91, "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-91"},
            )
        return httpx.Response(404, json={"message": "not mocked"})

    config = _config(tmp_path, root, role="both")
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
    exchange = CloudCompatibleExchange(config, tenant_root=root, jwks=jwks)
    app = build_http(config, exchange=exchange, gateway=gateway)
    return gateway, exchange, _Http(app), rsa_key


def test_infer_task_binding_omits_assurance():
    binding = infer_task_binding(event_name="issues", event={"issue": {"number": 4127}})
    assert binding == {"type": "issue", "number": 4127}
    assert "assurance" not in binding


def test_successful_stack_response(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = CloudCompatibleExchange(_config(tmp_path, root), tenant_root=root, jwks=jwks)
    token = _token(rsa_key, jti="stack-ok")
    task = {"type": "issue", "number": 4127}
    result = exchange.mint(
        token,
        exchange_body(
            holder,
            token,
            ttl_seconds=180,
            capabilities={
                "github.get_issue": {"issue": 4127},
                "github.add_comment": {"issue": 4127},
            },
            task_binding=task,
        ),
    )
    stack = decode_warrant_stack_base64(result.warrant)
    assert len(stack) == 2
    assert result.task_binding == {"number": 4127, "type": "issue"}
    assert result.root_public_keys == [root.public_key.to_bytes().hex()]
    verify_exchange_roots(result.root_public_keys, [root.public_key.to_bytes().hex()])


def test_holder_proof_failure(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = CloudCompatibleExchange(_config(tmp_path, root), tenant_root=root, jwks=jwks)
    token = _token(rsa_key, jti="bad-proof")
    body = exchange_body(holder, token, ttl_seconds=120)
    body["holder_proof"] = "not-a-signature"
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(token, body)
    assert caught.value.code == "holder_proof_invalid"


def test_outside_ceiling_repository(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = CloudCompatibleExchange(_config(tmp_path, root), tenant_root=root, jwks=jwks)
    token = _token(rsa_key, jti="ceiling")
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(
            token,
            exchange_body(
                holder,
                token,
                ttl_seconds=60,
                capabilities={"github.get_issue": {"repository": "acme/other", "issue": 1}},
            ),
        )
    assert caught.value.code == "outside_ceiling"


def test_token_replay(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = CloudCompatibleExchange(_config(tmp_path, root), tenant_root=root, jwks=jwks)
    token = _token(rsa_key, jti="replay")
    body = exchange_body(holder, token, ttl_seconds=60)
    exchange.mint(token, body)
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(token, body)
    assert caught.value.code == "token_reused"


def test_request_rejects_tenant_and_policy_identifiers(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = CloudCompatibleExchange(_config(tmp_path, root), tenant_root=root, jwks=jwks)
    token = _token(rsa_key, jti="ids")
    with pytest.raises(ExchangeError, match="unknown field: policy_id|unknown field: tenant_id"):
        exchange.mint(
            token,
            exchange_body(holder, token, extra={"tenant_id": "ten_x", "policy_id": "pol_y"}),
        )


def test_strict_cloud_handler_rejects_unknown_fields_and_legacy_proof(tmp_path):
    root = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    config = _config(tmp_path, root)
    exchange = CloudCompatibleExchange(config, tenant_root=root, jwks=jwks)
    client = TestClient(build_http(config, exchange=exchange))
    token = _token(rsa_key, jti="jti-gha")
    capabilities = {
        "github.add_comment": {"issue": 4127},
        "github.get_issue": {"issue": 4127},
    }
    binding = {"type": "issue", "number": 4127}
    body = exchange_body(
        holder,
        token,
        ttl_seconds=900,
        capabilities=capabilities,
        task_binding=binding,
    )
    compact = exchange_request_hash(
        issuer=ISSUER,
        jti="jti-gha",
        holder_public_key=holder.public_key.to_bytes().hex(),
        ttl_seconds=900,
        capabilities=capabilities,
        task_binding=binding,
    )
    assert len(compact) == 64

    aliased = dict(body)
    aliased["task_context"] = {"type": "issue", "number": 4127}
    refused = client.post("/v1/exchange", headers={"Authorization": f"Bearer {token}"}, json=aliased)
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_request"

    assured = dict(body)
    assured["task_binding"] = {"type": "issue", "number": 4127, "assurance": "runner_asserted"}
    refused_assurance = client.post(
        "/v1/exchange",
        headers={"Authorization": f"Bearer {token}"},
        json=assured,
    )
    assert refused_assurance.status_code == 400
    assert refused_assurance.json()["error"] == "invalid_request"

    legacy = hash_json(
        {
            "tenant_id": "",
            "policy_id": "",
            "issuer": ISSUER,
            "jti": "jti-gha",
            "holder_public_key": holder.public_key.to_bytes().hex(),
            "actions": ["github.add_comment", "github.get_issue"],
            "ttl_seconds": 900,
            "task_binding": binding,
        }
    )
    stale = dict(body)
    stale["holder_proof"] = encode_proof(bytes(holder.sign_raw(exchange_proof_preimage(legacy))))
    replayed = client.post("/v1/exchange", headers={"Authorization": f"Bearer {token}"}, json=stale)
    assert replayed.status_code == 403
    assert replayed.json()["error"] == "holder_proof_invalid"

    allowed = client.post("/v1/exchange", headers={"Authorization": f"Bearer {token}"}, json=body)
    assert allowed.status_code == 200
    assert decode_warrant_stack_base64(allowed.json()["warrant"])


def test_action_posts_task_binding_without_assurance(tmp_path):
    root = SigningKey.generate()
    recorded: list = []
    _gateway, _exchange, http, rsa_key = _cloud_stack(tmp_path, root, recorded)
    captured: list = []

    class _Capture(_Http):
        def post(self, url, headers=None, json=None):
            captured.append(json)
            return super().post(url, headers=headers, json=json)

    http = _Capture(http._client.app)
    socket = _sock("compact")
    server = HolderServer(socket)
    server.start()
    try:
        run_job(
            gateway_url="http://test",
            exchange_url="http://test",
            audience=AUDIENCE,
            socket_path=socket,
            mcp_config=tmp_path / "mcp-config.json",
            event_name="issues",
            repository="acme/widgets",
            event={"issue": {"number": 4127}},
            oidc_token=_token(rsa_key, jti="compact-1"),
            environ={"PATH": "/usr/bin", "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1"},
            http=http,
            holder_server=server,
            trusted_roots=[root.public_key.to_bytes().hex()],
        )
    finally:
        server.stop()
    body = next(item for item in captured if item and "holder_proof" in item)
    assert "task_context" not in body
    assert "tenant_id" not in body
    assert "policy_id" not in body
    assert body["task_binding"] == {"number": 4127, "type": "issue"}
    assert "assurance" not in body["task_binding"]
    expected = exchange_request_hash(
        issuer=ISSUER,
        jti="compact-1",
        holder_public_key=body["holder_public_key"],
        ttl_seconds=int(body["ttl_seconds"]),
        capabilities=body["capabilities"],
        task_binding=body["task_binding"],
    )
    from tenuo_gha.commitment import verify_holder_proof

    verify_holder_proof(body["holder_public_key"], body["holder_proof"], expected)


def test_run_provided_root_is_not_trusted():
    with pytest.raises(ActionError, match="not in configured trust"):
        verify_exchange_roots(["aa" * 32], ["bb" * 32])


def test_full_stack_terminal_attenuation_revocation_and_receipts(tmp_path):
    """Cloud /v1/exchange contract: stack, terminal leaf, one GitHub call, trust, revocation, receipts."""
    root = SigningKey.generate()
    recorded: list = []
    exchanged: list = []
    gateway, _exchange, http, rsa_key = _cloud_stack(tmp_path, root, recorded)

    class _Capture(_Http):
        def post(self, url, headers=None, json=None):
            response = super().post(url, headers=headers, json=json)
            if url.endswith("/v1/exchange") or str(urlparse(url).path) == "/v1/exchange":
                exchanged.append(response.json())
            return response

    http = _Capture(http._client.app)
    socket = _sock("accept")
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
            oidc_token=_token(rsa_key, jti="accept-1"),
            environ={"PATH": "/usr/bin", "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1"},
            http=http,
            holder_server=server,
            trusted_roots=[root.public_key.to_bytes().hex()],
        )
        config_text = Path(result["mcp_config"]).read_text(encoding="utf-8")
        assert "warrant" not in config_text
        assert "TENUO_HOLDER_SECRET" not in config_text
        assert "ghs_" not in config_text
        assert "tenant_id" not in config_text

        minted = exchanged[0]
        issued = decode_warrant_stack_base64(minted["warrant"])
        assert len(issued) == 2
        assert not issued[0].is_terminal()
        assert not issued[1].is_terminal()
        verify_exchange_roots(minted["root_public_keys"], [root.public_key.to_bytes().hex()])
        assert set(HolderClient(socket).tools()) == {
            "github.get_issue",
            "github.list_issue_comments",
            "github.add_comment",
        }

        args = {"repository": "acme/widgets", "issue": 4127, "body": "Authorized by a Cloud stack."}
        envelope = HolderClient(socket).envelope("github.add_comment", args)
        assert envelope["leaf_derived"] is True
        presented = decode_warrant_stack_base64(envelope["warrant"])
        assert len(presented) == 3
        assert presented[-1].is_terminal()
        outcome = call_gateway("http://test", "github.add_comment", args, envelope, client=http)
        assert outcome["allowed"] is True
        github_calls = [item for item in recorded if item[0] in {"GET", "POST", "PATCH", "PUT", "DELETE"}]
        assert len(github_calls) == 1
        assert github_calls[0][0] == "POST"
        assert "/repos/acme/widgets/issues/4127/comments" in github_calls[0][1]
        assert not any(b"installation-token" in item[2] for item in recorded)

        denied_args = {"repository": "acme/payments-internal", "issue": 1}
        denied_env = HolderClient(socket).envelope("github.get_issue", denied_args)
        denied = call_gateway("http://test", "github.get_issue", denied_args, denied_env, client=http)
        assert denied["allowed"] is False
        assert len([item for item in recorded if item[0] in {"GET", "POST", "PATCH", "PUT", "DELETE"}]) == 1

        assert gateway.flush_receipts()
        journal = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
        assert journal.strip()
        assert "installation-token" not in journal

        srl_builder = SignedRevocationList.builder()
        srl_builder.revoke(result["warrant_id"])
        srl = srl_builder.build(root)
        gateway.authorizer.set_revocation_list(srl)
        after = call_gateway("http://test", "github.add_comment", args, envelope, client=http)
        assert after["allowed"] is False
        assert TENUO_REVOKED in str(after.get("error_code") or after.get("message") or "")
        assert len([item for item in recorded if item[0] in {"GET", "POST", "PATCH", "PUT", "DELETE"}]) == 1
    finally:
        server.stop()
