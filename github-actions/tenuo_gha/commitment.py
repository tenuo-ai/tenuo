"""Cloud-compatible GitHub exchange commitment and holder proof.

The hash matches tenuo-cloud ``ComputeGitHubExchangeRequestHash``: compact
UTF-8 JSON with recursively sorted object keys, then SHA-256. Do not invent a
second canonicalization — the golden vector is shared with tenuo-cloud.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping, Optional

EXCHANGE_PROOF_CONTEXT = "tenuo-warrant-exchange-v1"

class CommitmentError(ValueError):
    """The exchange commitment could not be built or verified."""


def normalize_holder_public_key(value: str) -> str:
    """Return lowercase hex for a 32-byte Ed25519 public key."""
    raw = (value or "").strip()
    if raw.startswith("hex:"):
        raw = raw[4:]
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = _decode_b64(raw)
    if len(key) != 32:
        raise CommitmentError("holder_public_key must be 32 bytes")
    return key.hex()


def _decode_b64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(value + padding)
        except Exception:
            continue
    raise CommitmentError("holder_public_key is not hex or base64")


def encode_proof(signature: bytes) -> str:
    """URL-safe unpadded base64, matching tenuo-cloud's EncodeBase64."""
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def decode_proof(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    padded = encoded + padding
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        pass
    try:
        return base64.b64decode(padded, validate=True)
    except Exception as exc:
        raise CommitmentError("holder_proof is not valid base64") from exc


def _stable_maps(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _stable_maps(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_maps(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Compact UTF-8 JSON with recursively sorted object keys."""
    return json.dumps(_stable_maps(value), separators=(",", ":"), ensure_ascii=False)


def hash_json(value: Any) -> str:
    """SHA-256 hex of compact JSON with recursively sorted object keys."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def exchange_proof_preimage(request_hash: str) -> bytes:
    """``tenuo-warrant-exchange-v1 || 0x00 || lowercase_hex(request_sha256)``."""
    return f"{EXCHANGE_PROOF_CONTEXT}\x00{request_hash}".encode("utf-8")


def compact_task_binding(raw: Optional[Mapping[str, Any]]) -> Optional[dict[str, Any]]:
    """``{type, number}`` only. Assurance is assigned by Cloud, never signed here."""
    if raw is None:
        return None
    return {"number": int(raw["number"]), "type": str(raw["type"])}


def exchange_request_payload(
    *,
    issuer: str,
    jti: str,
    holder_public_key: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_binding: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "issuer": issuer,
        "jti": jti,
        "holder_public_key": normalize_holder_public_key(holder_public_key),
        "ttl_seconds": int(ttl_seconds),
        "capabilities": dict(capabilities),
        "task_binding": compact_task_binding(task_binding),
    }


def exchange_request_canonical(
    *,
    issuer: str,
    jti: str,
    holder_public_key: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_binding: Optional[Mapping[str, Any]] = None,
) -> str:
    return canonical_json(
        exchange_request_payload(
            issuer=issuer,
            jti=jti,
            holder_public_key=holder_public_key,
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
            task_binding=task_binding,
        )
    )


def exchange_request_hash(
    *,
    issuer: str,
    jti: str,
    holder_public_key: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_binding: Optional[Mapping[str, Any]] = None,
) -> str:
    """Hash the compact ``POST /v1/exchange`` commitment Cloud verifies."""
    return hash_json(
        exchange_request_payload(
            issuer=issuer,
            jti=jti,
            holder_public_key=holder_public_key,
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
            task_binding=task_binding,
        )
    )


def verify_holder_proof(holder_public_key: str, encoded: str, request_hash: str) -> None:
    """Raise ``CommitmentError`` if the proof does not match the holder key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        signature = decode_proof(encoded)
        public = bytes.fromhex(normalize_holder_public_key(holder_public_key))
        key = Ed25519PublicKey.from_public_bytes(public)
    except Exception as exc:
        raise CommitmentError("holder_proof is invalid") from exc
    if len(signature) != 64:
        raise CommitmentError("holder_proof is invalid")
    try:
        key.verify(signature, exchange_proof_preimage(request_hash))
    except InvalidSignature as exc:
        raise CommitmentError("holder_proof is invalid") from exc
