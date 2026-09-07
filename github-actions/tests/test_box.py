"""Concierge box check: Secret mount + config, no HTTP."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey

from tenuo_gha.box import check_box, format_ok
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.init_secrets import init_secrets


def _rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


def test_box_check_loads_secret_mount(tmp_path):
    issuer = SigningKey.generate()
    source = tmp_path / "download.pem"
    source.write_bytes(_rsa_pem())
    mount = tmp_path / "secrets"
    init_secrets(mount, app_pem=source)
    config = GatewayConfig.from_mapping(
        {
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
            "credentials": {"github": {"provider": "app", "app_id": "4819143"}},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "receipts": {"path": str(tmp_path / "receipts.jsonl")},
        },
        environ={
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )
    gateway = check_box(config)
    assert gateway.github is not None
    text = format_ok(config)
    assert "box ready" in text
    assert "BEGIN " not in text
    assert "4819143" in text
    assert "--gateway-only" in text


def test_box_check_overrides_compose_mount(tmp_path):
    issuer = SigningKey.generate()
    source = tmp_path / "download.pem"
    source.write_bytes(_rsa_pem())
    mount = tmp_path / "secrets"
    init_secrets(mount, app_pem=source)
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {
                "profile": "secret",
                "secret": {
                    "mount": "/var/run/secrets/tenuo",
                    "receipt_key": "receipt.pem",
                    "github_app_key": "app.pem",
                },
            },
            "credentials": {"github": {"provider": "app", "app_id": "4819143"}},
            "ceiling": {"repositories": ["acme/widgets"]},
            "tools": {"packs": ["github-triage"]},
            "receipts": {"path": "/state/receipts.jsonl"},
        },
        environ={
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )
    gateway = check_box(config, mount=mount)
    assert gateway.config.secret_mount == mount.resolve()
    assert gateway.config.receipt_path != Path("/state/receipts.jsonl")
    assert "BEGIN " not in format_ok(config)


def test_box_check_refuses_exchange_role(tmp_path):
    issuer = SigningKey.generate()
    mount = tmp_path / "secrets"
    init_secrets(mount, issuer=True)
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
            "signing": {
                "profile": "secret",
                "secret": {"mount": str(mount), "issuer_key": "issuer.pem"},
            },
            "exchange": {"audience": "tenuo:org/acme"},
            "receipts": {"path": str(tmp_path / "r.jsonl")},
        },
        environ={
            "TENUO_ROLE": "exchange",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )
    with pytest.raises(ConfigError, match="TENUO_ROLE=gateway"):
        check_box(config)
