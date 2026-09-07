"""Secret-mount custody and App JWT minting."""

from __future__ import annotations

from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey

from starlette.testclient import TestClient

from tenuo_gha.app import Gateway
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.http import build_http
from tenuo_gha.secrets import sign_github_app_jwt


def _rsa_pem() -> tuple[bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    return pem, key


def _secret_env(issuer: SigningKey) -> dict:
    return {"TENUO_ROLE": "gateway", "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex()}


def _write_mount(tmp_path: Path, *, receipt: SigningKey, app_pem: bytes) -> Path:
    mount = tmp_path / "secrets"
    mount.mkdir()
    (mount / "receipt.pem").write_text(receipt.to_pem(), encoding="utf-8")
    (mount / "app.pem").write_bytes(app_pem)
    return mount


def _secret_mapping(tmp_path: Path, mount: Path, *, app_id: str = "123") -> dict:
    return {
        "version": 1,
        "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
        "signing": {
            "profile": "secret",
            "secret": {
                "mount": str(mount),
                "receipt_key": "receipt.pem",
                "github_app_key": "app.pem",
            },
        },
        "ceiling": {"repositories": ["acme/widgets"]},
        "tools": {"packs": ["github-triage"]},
        "credentials": {"github": {"provider": "app", "app_id": app_id, "installation_id": "9"}},
        "receipts": {"path": str(tmp_path / "receipts.jsonl")},
    }


def test_app_jwt_is_rs256_and_names_the_app():
    pem, key = _rsa_pem()
    token = sign_github_app_jwt(pem, "4242")
    claims = jwt.decode(token, key.public_key(), algorithms=["RS256"])
    assert claims["iss"] == "4242"
    assert claims["exp"] - claims["iat"] == 600
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"


def test_secret_profile_wires_github_app(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    config = GatewayConfig.from_mapping(_secret_mapping(tmp_path, mount), environ=_secret_env(issuer))
    gateway = Gateway(config)
    assert gateway.github is not None
    assert gateway.config.signing_provider == "secret"


def test_secret_profile_mints_with_signed_jwt(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, key = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            bearer = request.headers["Authorization"].removeprefix("Bearer ")
            seen.append(bearer)
            jwt.decode(bearer, key.public_key(), algorithms=["RS256"])
            return httpx.Response(
                201,
                json={"token": "ghs_not_a_real_token", "expires_at": "2099-01-15T12:00:00Z"},
            )
        return httpx.Response(404)

    config = GatewayConfig.from_mapping(_secret_mapping(tmp_path, mount), environ=_secret_env(issuer))
    gateway = Gateway(
        config,
        github_http=httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com"),
    )
    token = gateway.github.token_for("acme/widgets")
    assert token == "ghs_not_a_real_token"
    assert seen
    assert "ghs_not_a_real_token" not in str(gateway.github)


def test_secret_refuses_key_outside_mount(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    config_dir = tmp_path / "etc"
    config_dir.mkdir()
    (config_dir / "app.pem").write_bytes(pem)
    with pytest.raises(ConfigError, match="outside the Secret mount"):
        GatewayConfig.from_mapping(
            _secret_mapping(tmp_path, mount),
            environ=_secret_env(issuer),
            scan_roots=[config_dir],
        )


def test_secret_refuses_absolute_key_path(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    raw = _secret_mapping(tmp_path, mount)
    raw["signing"]["secret"]["github_app_key"] = str(mount / "app.pem")
    with pytest.raises(ConfigError, match="filename under the Secret mount"):
        GatewayConfig.from_mapping(raw, environ=_secret_env(issuer))


def test_secret_refuses_env_signing_keys(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    with pytest.raises(ConfigError, match="environment"):
        GatewayConfig.from_mapping(
            _secret_mapping(tmp_path, mount),
            environ={**_secret_env(issuer), "TENUO_RECEIPT_SIGNING_KEY": receipt.secret_key_bytes().hex()},
        )


def test_gateway_role_refuses_issuer_secret_file(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    (mount / "issuer.pem").write_text(issuer.to_pem(), encoding="utf-8")
    raw = _secret_mapping(tmp_path, mount)
    raw["signing"]["secret"]["issuer_key"] = "issuer.pem"
    with pytest.raises(ConfigError, match="issuer Secret file"):
        GatewayConfig.from_mapping(raw, environ=_secret_env(issuer))


def test_exchange_role_refuses_app_secret_file(tmp_path):
    issuer = SigningKey.generate()
    mount = tmp_path / "secrets"
    mount.mkdir()
    (mount / "issuer.pem").write_text(issuer.to_pem(), encoding="utf-8")
    with pytest.raises(ConfigError, match="receipt or App Secret"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {
                    "profile": "secret",
                    "secret": {
                        "mount": str(mount),
                        "issuer_key": "issuer.pem",
                        "github_app_key": "app.pem",
                    },
                },
                "exchange": {"audience": "tenuo:org/acme"},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ROLE": "exchange",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
            },
        )


def test_memory_app_still_requires_injected_client(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="GitHub App signing"):
        Gateway(
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
                    "TENUO_ROLE": "gateway",
                    "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
                },
            )
        )


def test_ready_is_ok_after_secret_self_test(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = _write_mount(tmp_path, receipt=receipt, app_pem=pem)
    config = GatewayConfig.from_mapping(_secret_mapping(tmp_path, mount), environ=_secret_env(issuer))
    gateway = Gateway(config)
    client = TestClient(build_http(config, gateway=gateway))
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "role": "gateway"}


def test_ready_is_503_when_gateway_self_test_fails(tmp_path):
    issuer = SigningKey.generate()
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {"provider": "memory"},
            "receipts": {"path": str(tmp_path / "r.jsonl")},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )

    class _Broken:
        def self_test(self) -> None:
            raise ConfigError("receipt key self-test failed")

    client = TestClient(build_http(config, gateway=_Broken()))
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["detail"] == "gateway sign self-test failed"


def test_from_yaml_scans_the_config_directory(tmp_path):
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem, _ = _rsa_pem()
    mount = tmp_path / "secrets"
    mount.mkdir()
    (mount / "receipt.pem").write_text(receipt.to_pem(), encoding="utf-8")
    (mount / "app.pem").write_bytes(pem)
    config_dir = tmp_path / "etc"
    config_dir.mkdir()
    (config_dir / "leaked.pem").write_bytes(pem)
    path = config_dir / "gateway.yaml"
    path.write_text(
        "\n".join(
            [
                "version: 1",
                "trust:",
                "  root_public_keys: [\"${TENUO_ROOT_PUBLIC_KEY}\"]",
                "signing:",
                "  profile: secret",
                "  secret:",
                f"    mount: {mount}",
                "    receipt_key: receipt.pem",
                "    github_app_key: app.pem",
                "credentials:",
                "  github:",
                "    provider: app",
                "    app_id: \"123\"",
                "receipts:",
                f"  path: {tmp_path / 'receipts.jsonl'}",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="outside the Secret mount"):
        GatewayConfig.from_yaml(path, environ=_secret_env(issuer))
