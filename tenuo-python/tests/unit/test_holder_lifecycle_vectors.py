"""Load the shared holder-lifecycle vectors used by sibling SDKs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tenuo import ConnectToken, HolderIdentity
from tenuo.exceptions import ConfigurationError

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "holder-lifecycle.json"


def _vectors() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_connect_token_vectors():
    for case in _vectors()["connect_tokens"]:
        if case["expect"] == "error":
            with pytest.raises(ConfigurationError, match=case["error_contains"]):
                ConnectToken.parse(case["raw"])
            continue
        token = ConnectToken.parse(case["raw"])
        assert token.version == case["version"]
        assert token.endpoint == case["endpoint"]
        assert token.api_key == case["api_key"]
        assert token.agent_id == case["agent_id"]
        assert token.registration_token == case["registration_token"]
        assert token.needs_endpoint_base is case["needs_endpoint_base"]
        if case.get("resolve_base"):
            token.resolve_endpoint(case["resolve_base"])
            assert token.endpoint == case["resolved_endpoint"]
            assert not token.needs_endpoint_base


def test_identity_vector_derives_and_redacts():
    case = _vectors()["identity"]
    secret = bytes.fromhex(case["secret_hex"])
    identity = HolderIdentity.from_bytes(secret)
    assert bytes(identity.public_key.to_bytes()).hex() == case["public_key_hex"]
    rendered = repr(identity)
    assert rendered == case["repr_prefix"]
    assert case["secret_hex"] not in rendered
    assert case["secret_hex"] not in str(identity)


def test_receipt_contract_flags():
    receipts = _vectors()["receipts"]
    assert receipts["drain_is_snapshot"] is True
    assert receipts["remove_only_on_acknowledge"] is True
    assert receipts["overflow_does_not_deny_authorized_call"] is True
    assert receipts["overflow_is_observable"] is True
