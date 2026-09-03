"""Cloud-compatible exchange commitment and holder proof.

The hash and proof preimage match tenuo-cloud's
``ComputeWarrantExchangeRequestHash`` / ``ExchangeProofPreimage``. Nested maps
use sorted keys, matching Go ``encoding/json``. Do not invent a second
canonicalization — add golden vectors here and in tenuo-cloud together.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping, Optional, Sequence

EXCHANGE_PROOF_CONTEXT = "tenuo-warrant-exchange-v1"

# Field order matches the Go commitment struct in warrant_exchange.go.
_CLOUD_FIELDS = (
    "tenant_id",
    "policy_id",
    "issuer",
    "jti",
    "holder_public_key",
    "actions",
    "constraints",
    "per_action_constraints",
    "ttl_seconds",
    "max_depth",
    "task_binding",
)


class CommitmentError(ValueError):
    """The exchange commitment could not be built or verified."""


class _Struct(dict):
    """JSON object with declaration order, matching a Go struct."""


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


def _stable_maps(value: Any, *, sort_object: bool) -> Any:
    if isinstance(value, _Struct):
        return {str(key): _stable_maps(value[key], sort_object=True) for key in value}
    if isinstance(value, dict):
        keys = sorted(value) if sort_object else list(value)
        return {str(key): _stable_maps(value[key], sort_object=True) for key in keys}
    if isinstance(value, (list, tuple)):
        return [_stable_maps(item, sort_object=True) for item in value]
    return value


def hash_json(value: Any, *, sort_object: bool = False) -> str:
    """SHA-256 hex of compact JSON.

    Top-level struct field order is preserved (Go ``encoding/json``). Nested
    maps use sorted keys, matching both Go map encoding and the Node action.
    """
    canonical = json.dumps(
        _stable_maps(value, sort_object=sort_object),
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def exchange_proof_preimage(request_hash: str) -> bytes:
    """``tenuo-warrant-exchange-v1 || 0x00 || lowercase_hex(request_sha256)``."""
    return f"{EXCHANGE_PROOF_CONTEXT}\x00{request_hash}".encode("utf-8")


def cloud_exchange_request_hash(
    *,
    issuer: str,
    jti: str,
    holder_public_key: str,
    actions: Sequence[str],
    ttl_seconds: int = 0,
    tenant_id: str = "",
    policy_id: str = "",
    constraints: Optional[Mapping[str, Any]] = None,
    per_action_constraints: Optional[Mapping[str, Mapping[str, Any]]] = None,
    max_depth: Optional[int] = None,
    task_binding: Optional[Mapping[str, Any]] = None,
) -> str:
    """Hash used by tenuo-cloud ``ComputeWarrantExchangeRequestHash``."""
    binding = None
    if task_binding is not None:
        binding = _Struct(
            (
                ("type", str(task_binding["type"])),
                ("number", int(task_binding["number"])),
            )
        )
    payload = {
        "tenant_id": tenant_id,
        "policy_id": policy_id,
        "issuer": issuer,
        "jti": jti,
        "holder_public_key": normalize_holder_public_key(holder_public_key),
        "actions": sorted(str(item) for item in actions),
        "constraints": dict(constraints) if constraints is not None else None,
        "per_action_constraints": (
            {str(key): dict(value) for key, value in per_action_constraints.items()}
            if per_action_constraints is not None
            else None
        ),
        "ttl_seconds": int(ttl_seconds),
        "max_depth": max_depth,
        "task_binding": binding,
    }
    return hash_json({key: payload[key] for key in _CLOUD_FIELDS})


def exchange_request_hash(
    *,
    issuer: str,
    jti: str,
    holder_public_key: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_context: Optional[Mapping[str, Any]] = None,
) -> str:
    """Hash the identifier-free ``POST /v1/exchange`` body via Cloud's function.

    Capabilities become sorted ``actions`` plus ``per_action_constraints``.
    ``task_context.assurance`` is not part of the commitment — Cloud's
    ``task_binding`` is only ``type`` and ``number``.
    """
    binding = None
    if task_context is not None:
        binding = {
            "type": str(task_context["type"]),
            "number": int(task_context["number"]),
        }
    return cloud_exchange_request_hash(
        issuer=issuer,
        jti=jti,
        holder_public_key=holder_public_key,
        actions=list(capabilities.keys()),
        ttl_seconds=ttl_seconds,
        constraints={},
        per_action_constraints={
            str(tool): dict(args or {}) for tool, args in capabilities.items()
        },
        task_binding=binding,
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
