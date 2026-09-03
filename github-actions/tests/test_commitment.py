"""Cloud/OSS shared exchange commitment vectors."""

from __future__ import annotations

from tenuo_gha.commitment import (
    cloud_exchange_request_hash,
    encode_proof,
    exchange_proof_preimage,
    exchange_request_hash,
    verify_holder_proof,
)

# Go/Node vectors from tenuo-cloud/internal/service/warrant_exchange_test.go
CLOUD_ACTIONS_VECTOR = "3e3cfc45ed2d830a10c0c4f4a92f03d7c1cbd749f51f2462adbfedb8dbe738e9"
CLOUD_AUTO_VECTOR = "85838c1a2c042acda3e9f97b7f2eab6d566a2f8653b6a047aec72678a3ea9db0"
# Identifier-free POST /v1/exchange mapping. Also asserted in tenuo-cloud.
GHA_CAPABILITIES_VECTOR = "a4549e0f30c20a522f49ec3b1a3af96594be9073719424912fc3a700624b862f"


def test_cloud_go_node_action_order_vector():
    pub = bytes(range(32)).hex()
    assert (
        cloud_exchange_request_hash(
            issuer="https://token.actions.githubusercontent.com",
            jti="jti-1",
            holder_public_key=pub,
            actions=["b", "a"],
            ttl_seconds=600,
            tenant_id="tenant",
            policy_id="wpol_test",
            constraints={"z": 1, "a": "x"},
        )
        == CLOUD_ACTIONS_VECTOR
    )


def test_cloud_go_node_automatic_resolution_vector():
    assert (
        cloud_exchange_request_hash(
            issuer="https://token.actions.githubusercontent.com",
            jti="jti-auto",
            holder_public_key="00" * 32,
            actions=["a"],
            constraints={},
            per_action_constraints={},
        )
        == CLOUD_AUTO_VECTOR
    )


def test_gha_identifier_free_capabilities_vector():
    assert (
        exchange_request_hash(
            issuer="https://token.actions.githubusercontent.com",
            jti="jti-gha",
            holder_public_key="00" * 32,
            ttl_seconds=900,
            capabilities={
                "github.add_comment": {"issue": 4127},
                "github.get_issue": {"issue": 4127},
            },
            task_context={"type": "issue", "number": 4127, "assurance": "runner_asserted"},
        )
        == GHA_CAPABILITIES_VECTOR
    )


def test_holder_proof_roundtrip():
    from tenuo import SigningKey

    key = SigningKey.generate()
    request_hash = "ab12"
    proof = encode_proof(bytes(key.sign_raw(exchange_proof_preimage(request_hash))))
    verify_holder_proof(key.public_key.to_bytes().hex(), proof, request_hash)
