"""Shared helpers for signing Cloud-compatible exchange proofs in tests."""

from __future__ import annotations

from typing import Any, Mapping, Optional

import jwt

from tenuo_gha.commitment import encode_proof, exchange_proof_preimage, exchange_request_hash


def peek_claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


def holder_proof(
    key,
    token: str,
    *,
    holder_public_key: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_context: Optional[Mapping[str, Any]] = None,
) -> str:
    claims = peek_claims(token)
    request_hash = exchange_request_hash(
        issuer=str(claims["iss"]),
        jti=str(claims["jti"]),
        holder_public_key=holder_public_key,
        ttl_seconds=ttl_seconds,
        capabilities=capabilities,
        task_context=task_context,
    )
    return encode_proof(bytes(key.sign_raw(exchange_proof_preimage(request_hash))))


def exchange_body(
    key,
    token: str,
    *,
    ttl_seconds: int = 120,
    capabilities: Optional[Mapping[str, Any]] = None,
    task_context: Optional[Mapping[str, Any]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> dict:
    caps = dict(capabilities or {"github.get_issue": {"issue": 4127}})
    pubkey = key.public_key.to_bytes().hex()
    body = {
        "holder_public_key": pubkey,
        "holder_proof": holder_proof(
            key,
            token,
            holder_public_key=pubkey,
            ttl_seconds=ttl_seconds,
            capabilities=caps,
            task_context=task_context,
        ),
        "ttl_seconds": ttl_seconds,
        "capabilities": caps,
    }
    if task_context is not None:
        body["task_context"] = dict(task_context)
    if extra:
        body.update(extra)
    return body
