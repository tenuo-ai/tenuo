"""Cloud/OSS shared compact GitHub exchange commitment vectors."""

from __future__ import annotations

from tenuo_gha.commitment import (
    GHA_COMPACT_VECTOR,
    encode_proof,
    exchange_proof_preimage,
    exchange_request_hash,
    verify_holder_proof,
)


def test_gha_compact_task_binding_vector():
    """Shared with tenuo-cloud TestGitHubExchangeRequestHashTaskBindingVector."""
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
            task_binding={"type": "issue", "number": 4127},
        )
        == GHA_COMPACT_VECTOR
        == "a6e5f6e8d6f2454c167343e57cbe1ce0dcfef675a969c1607c82a4ba589568ae"
    )


def test_compact_hash_omits_runner_assurance():
    with_extra = exchange_request_hash(
        issuer="https://token.actions.githubusercontent.com",
        jti="jti-gha",
        holder_public_key="00" * 32,
        ttl_seconds=900,
        capabilities={
            "github.add_comment": {"issue": 4127},
            "github.get_issue": {"issue": 4127},
        },
        task_binding={"type": "issue", "number": 4127, "assurance": "runner_asserted"},
    )
    assert with_extra == GHA_COMPACT_VECTOR


def test_holder_proof_roundtrip():
    from tenuo import SigningKey

    key = SigningKey.generate()
    request_hash = "ab12"
    proof = encode_proof(bytes(key.sign_raw(exchange_proof_preimage(request_hash))))
    verify_holder_proof(key.public_key.to_bytes().hex(), proof, request_hash)
