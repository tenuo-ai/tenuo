"""OIDC exchange: mint, refuse, reuse, and role isolation."""

from __future__ import annotations

import json
import time
from pathlib import Path

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

pytest.importorskip("tenuo_core")

from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from tenuo_core import SigningKey, Warrant

from tenuo_gha.app import Gateway
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.exchange import Exchange, ExchangeError
from tenuo_gha.http import build_http


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
        "jti": "jti-1",
        "repository": "acme/widgets",
        "repository_id": "7890",
        "repository_owner": "acme",
        "repository_owner_id": "123456",
        "job_workflow_ref": "acme/widgets/.github/workflows/triage.yml@refs/heads/main",
        "event_name": "issues",
        "run_id": "99",
        "sub": "repo:acme/widgets:ref:refs/heads/main",
    }
    base.update(overrides)
    return base


def _token(key, **overrides) -> str:
    return jwt.encode(_claims(**overrides), key, algorithm="RS256", headers={"kid": "test"})


def _exchange_config(tmp_path: Path, issuer: SigningKey, environ: dict | None = None) -> GatewayConfig:
    return GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {
                "root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"],
                "issuer": ISSUER,
            },
            "signing": {"provider": "memory"},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "exchange": {
                "audience": AUDIENCE,
                "ttl_max": "15m",
                "jwks_url": "https://example.invalid/jwks",
                "conditions": {
                    "repository_owner_id": "123456",
                    "repository_id": ["7890"],
                    "job_workflow_ref": "acme/*/.github/workflows/triage.yml@refs/heads/main",
                    "event_name": ["issues", "pull_request"],
                },
            },
            "receipts": {"path": str(tmp_path / "receipts.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "exchange",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            **(environ or {}),
        },
    )


def test_combined_role_requires_the_escape(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="TENUO_ALLOW_COMBINED_ROLES"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "role": "both",
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_exchange_refuses_receipt_and_app_key_ids(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="receipt or App"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {
                    "provider": "memory",
                    "kms": {
                        "receipt_key_id": "arn:aws:kms:us-east-1:1:key/receipt",
                    },
                },
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROLE": "exchange",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_gateway_refuses_issuer_key_id(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="issuer key id"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {
                    "provider": "memory",
                    "kms": {"issuer_key_id": "arn:aws:kms:us-east-1:1:key/issuer"},
                },
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROLE": "gateway",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_fixture_jwt_mints_a_warrant(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(_exchange_config(tmp_path, issuer), issuer_key=issuer, jwks=jwks)
    result = exchange.mint(
        _token(rsa_key),
        {
            "holder_public_key": holder.public_key.to_bytes().hex(),
            "ttl_seconds": 900,
            "capabilities": {
                "github.get_issue": {"issue": 4127},
                "github.add_comment": {"issue": 4127},
            },
        },
    )
    warrant = Warrant.from_base64(result.warrant)
    assert result.warrant_id
    assert result.expires_at
    holder_pk = warrant.authorized_holder
    holder_pk = holder_pk() if callable(holder_pk) else holder_pk
    assert holder_pk.to_bytes() == holder.public_key.to_bytes()
    import base64 as b64

    args = {"repository": "acme/widgets", "issue": 4127}
    sig = warrant.sign(holder, "github.get_issue", args, int(time.time()))
    gateway = Gateway(
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "ceiling": {"repositories": ["acme/widgets"]},
                "tools": {"packs": ["github-triage"]},
                "receipts": {"path": str(tmp_path / "gw.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROLE": "gateway",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )
    )
    verified = gateway.verify(
        "github.get_issue",
        args,
        meta={"tenuo": {"warrant": result.warrant, "signature": b64.b64encode(bytes(sig)).decode()}},
    )
    assert verified.allowed


def test_reused_token_is_forbidden(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(_exchange_config(tmp_path, issuer), issuer_key=issuer, jwks=jwks)
    body = {
        "holder_public_key": holder.public_key.to_bytes().hex(),
        "ttl_seconds": 60,
        "capabilities": {"github.get_issue": {"issue": 1}},
    }
    token = _token(rsa_key)
    exchange.mint(token, body)
    with pytest.raises(ExchangeError, match="already exchanged") as caught:
        exchange.mint(token, body)
    assert caught.value.code == "token_reused"


def test_ttl_above_max_is_refused(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(_exchange_config(tmp_path, issuer), issuer_key=issuer, jwks=jwks)
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(
            _token(rsa_key),
            {
                "holder_public_key": holder.public_key.to_bytes().hex(),
                "ttl_seconds": 3600,
                "capabilities": {"github.get_issue": {"issue": 1}},
            },
        )
    assert caught.value.code == "outside_ceiling"


def test_tripwire_capability_is_refused(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(_exchange_config(tmp_path, issuer), issuer_key=issuer, jwks=jwks)
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(
            _token(rsa_key),
            {
                "holder_public_key": holder.public_key.to_bytes().hex(),
                "ttl_seconds": 60,
                "capabilities": {"github.workflow_dispatch": {"workflow": "x.yml"}},
            },
        )
    assert caught.value.code == "outside_ceiling"


def test_foreign_repository_is_refused(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(_exchange_config(tmp_path, issuer), issuer_key=issuer, jwks=jwks)
    with pytest.raises(ExchangeError) as caught:
        exchange.mint(
            _token(rsa_key, repository="acme/payments-internal", repository_id="999"),
            {
                "holder_public_key": holder.public_key.to_bytes().hex(),
                "ttl_seconds": 60,
                "capabilities": {"github.get_issue": {"issue": 1}},
            },
        )
    assert caught.value.code in {"outside_ceiling", "untrusted_workflow"}


def test_http_exchange_mints(tmp_path):
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    jwks, rsa_key = _rsa_jwks()
    config = _exchange_config(tmp_path, issuer)
    exchange = Exchange(config, issuer_key=issuer, jwks=jwks)
    client = TestClient(build_http(config, exchange=exchange))
    response = client.post(
        "/v1/exchange",
        headers={"Authorization": f"Bearer {_token(rsa_key, jti='http-1')}"},
        json={
            "holder_public_key": holder.public_key.to_bytes().hex(),
            "ttl_seconds": 120,
            "capabilities": {"github.get_issue": {"issue": 4127}},
        },
    )
    assert response.status_code == 200
    payload = response.json()
    Warrant.from_base64(payload["warrant"])
    health = client.get("/health")
    assert health.status_code == 200
