"""Conformance against tenuo-cloud's compact exchange fixture."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tenuo_gha.commitment import (
    EXCHANGE_PROOF_CONTEXT,
    encode_proof,
    exchange_proof_preimage,
    exchange_request_canonical,
    exchange_request_hash,
    verify_holder_proof,
)

FIXTURE_NAME = "ci_exchange_v1.json"


def _cloud_fixture_path() -> Path | None:
    env = os.environ.get("TENUO_CLOUD_FIXTURE")
    if env:
        path = Path(env)
        return path if path.is_file() else None
    sibling = Path(__file__).resolve().parents[2].parent / "tenuo-cloud" / "internal" / "service" / "testdata" / FIXTURE_NAME
    return sibling if sibling.is_file() else None


def _vendored_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / FIXTURE_NAME


def load_ci_exchange_fixture() -> dict:
    vendored = _vendored_fixture_path()
    cloud = _cloud_fixture_path()
    if cloud is not None and vendored.is_file() and cloud.read_bytes() != vendored.read_bytes():
        pytest.fail(f"vendored {FIXTURE_NAME} drifted from {cloud}")
    source = cloud or vendored
    return json.loads(source.read_text(encoding="utf-8"))


def test_cloud_ci_exchange_fixture_vectors():
    fixture = load_ci_exchange_fixture()
    assert fixture["schema"] == "tenuo.ci_exchange.v1"
    assert fixture["proof_context"] == EXCHANGE_PROOF_CONTEXT
    assert len(fixture["vectors"]) == 5
    for vector in fixture["vectors"]:
        request = vector["request"]
        canonical = exchange_request_canonical(
            issuer=vector["issuer"],
            jti=vector["jti"],
            holder_public_key=request["holder_public_key"],
            ttl_seconds=request["ttl_seconds"],
            capabilities=request["capabilities"],
            task_binding=request["task_binding"],
        )
        assert canonical == vector["canonical_json"], vector["name"]
        digest = exchange_request_hash(
            issuer=vector["issuer"],
            jti=vector["jti"],
            holder_public_key=request["holder_public_key"],
            ttl_seconds=request["ttl_seconds"],
            capabilities=request["capabilities"],
            task_binding=request["task_binding"],
        )
        assert digest == vector["expected_hash"], vector["name"]
        verify_holder_proof(
            fixture["signing_public_key_hex"],
            vector["expected_proof"],
            digest,
        )


def test_holder_proof_roundtrip():
    from tenuo import SigningKey

    key = SigningKey.generate()
    request_hash = "ab12"
    proof = encode_proof(bytes(key.sign_raw(exchange_proof_preimage(request_hash))))
    verify_holder_proof(key.public_key.to_bytes().hex(), proof, request_hash)
