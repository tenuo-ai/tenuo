"""HolderIdentity: derivation, persistence, redaction."""

from __future__ import annotations

import os
import pickle
import stat
import threading

import pytest
from tenuo_core import SigningKey

from tenuo import HolderIdentity
from tenuo.exceptions import ConfigurationError


def test_generate_and_from_signing_key_derive_public_key():
    generated = HolderIdentity.generate()
    imported = HolderIdentity(generated.signing_key)
    assert generated.public_key == imported.public_key
    assert generated.public_key == generated.signing_key.public_key


def test_from_bytes_matches_signing_key():
    key = SigningKey.generate()
    identity = HolderIdentity.from_bytes(bytes(key.secret_key_bytes()))
    assert identity.public_key == key.public_key


def test_rejects_wrong_length_secret():
    with pytest.raises(ConfigurationError, match="32-byte"):
        HolderIdentity(b"\x00" * 16)


def test_repr_and_str_never_include_secret():
    key = SigningKey.generate()
    secret_hex = bytes(key.secret_key_bytes()).hex()
    identity = HolderIdentity(key)
    for rendered in (repr(identity), str(identity)):
        assert secret_hex not in rendered
        assert "HolderIdentity" in rendered
    with pytest.raises(TypeError):
        pickle.dumps(identity)


def test_load_or_create_reuses_same_key_and_sets_permissions(tmp_path):
    path = tmp_path / "nested" / "agent" / "holder.key"
    first = HolderIdentity.load_or_create(path)
    second = HolderIdentity.load_or_create(path)
    assert first.public_key == second.public_key
    assert path.exists()
    assert first.path == path
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600


def test_load_or_create_rejects_corrupt_file(tmp_path):
    path = tmp_path / "holder.key"
    path.write_text("not-hex\n", encoding="ascii")
    with pytest.raises(ConfigurationError, match="hex"):
        HolderIdentity.load_or_create(path)
    assert path.read_text(encoding="ascii") == "not-hex\n"


def test_load_or_create_rejects_wrong_length(tmp_path):
    path = tmp_path / "holder.key"
    path.write_text("aa\n", encoding="ascii")
    with pytest.raises(ConfigurationError, match="32 bytes"):
        HolderIdentity.load_or_create(path)


def test_load_or_create_race_returns_persisted_winner(tmp_path):
    path = tmp_path / "holder.key"
    results = []
    errors = []

    def worker():
        try:
            results.append(HolderIdentity.load_or_create(path).public_key)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(results) == 16
    persisted = HolderIdentity.load_or_create(path)
    assert all(key == persisted.public_key for key in results)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
