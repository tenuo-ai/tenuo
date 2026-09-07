"""Secret mount bootstrap. Never prints a private key."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey

from tenuo_gha.config import ConfigError
from tenuo_gha.init_secrets import format_report, init_secrets


def _rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


def test_init_secrets_writes_receipt_and_copies_app(tmp_path):
    source = tmp_path / "download.pem"
    source.write_bytes(_rsa_pem())
    mount = tmp_path / "secrets"
    result = init_secrets(mount, app_pem=source)
    assert result.created == ["receipt.pem", "app.pem"]
    assert (mount / "receipt.pem").stat().st_mode & 0o777 == 0o600
    assert (mount / "app.pem").read_bytes() == source.read_bytes()
    report = format_report(result)
    assert "BEGIN " not in report
    assert "PRIVATE KEY" not in report
    assert result.receipt_public_key
    loaded = SigningKey.from_pem((mount / "receipt.pem").read_text(encoding="utf-8"))
    assert loaded.public_key.to_bytes().hex() == result.receipt_public_key


def test_init_secrets_keeps_existing_files(tmp_path):
    mount = tmp_path / "secrets"
    first = init_secrets(mount)
    pem = (mount / "receipt.pem").read_text(encoding="utf-8")
    second = init_secrets(mount)
    assert second.skipped == ["receipt.pem"]
    assert (mount / "receipt.pem").read_text(encoding="utf-8") == pem
    assert second.receipt_public_key == first.receipt_public_key


def test_init_secrets_refuses_a_non_rsa_app_pem(tmp_path):
    source = tmp_path / "not-app.pem"
    source.write_text(SigningKey.generate().to_pem(), encoding="utf-8")
    with pytest.raises(ConfigError, match="RSA PEM"):
        init_secrets(tmp_path / "secrets", app_pem=source)
    assert not (tmp_path / "secrets" / "app.pem").exists()
