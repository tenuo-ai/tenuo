"""
Control-plane approval flow — JSON wire schema and verification helpers.

Covers the **protocol layer only**: serialisation, deserialisation, hash
recomputation, and optional context-attestation verification.  All
cryptographic checks use ``tenuo_core`` (request hash, context attestation,
``SignedApproval`` verification).

HTTP transport lives in :mod:`tenuo.cp_transport`.

The worker should build :class:`~tenuo.approval.ApprovalRequest` with
:meth:`~tenuo.approval.ApprovalRequest.for_warrant_gate` so ``request_id``,
approvers, and expiry align with Rust ``approval::ApprovalRequest``.
"""

from __future__ import annotations

import base64
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence

from tenuo_core import (
    PublicKey,
    Signature,
    SignedApproval,
    py_build_approval_context_attestation as build_approval_context_attestation,
    py_compute_request_hash as compute_request_hash,
    py_verify_approval_context_attestation as verify_approval_context_attestation,
)

from .approval import ApprovalRequest, _new_approval_request_id_bytes

APPROVAL_FLOW_SCHEMA_VERSION = 1


def _pk_hex(pk: PublicKey) -> str:
    return pk.to_bytes().hex()


def _pk_from_hex(h: str) -> PublicKey:
    return PublicKey.from_bytes(bytes.fromhex(h))


def _same_pk(a: PublicKey, b: PublicKey) -> bool:
    return a.to_bytes() == b.to_bytes()


@dataclass
class ControlPlaneApprovalRequestV1:
    """JSON-serializable body for ``POST …/approvals/requests``-style APIs."""

    schema_version: int
    request_id_hex: str
    warrant_id: str
    tool: str
    arguments: Dict[str, Any]
    request_hash_hex: str
    holder_public_key_hex: str
    required_approver_keys_hex: List[str]
    min_approvals: int
    warrant_expires_at_unix: int
    created_at_unix: int
    attestation: Optional[Dict[str, Any]] = None
    temporal: Optional[Dict[str, str]] = None

    def to_json_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get("attestation") is None:
            d.pop("attestation", None)
        if d.get("temporal") is None:
            d.pop("temporal", None)
        return d

    @staticmethod
    def from_json_dict(data: Dict[str, Any]) -> ControlPlaneApprovalRequestV1:
        ver = data.get("schema_version")
        if ver != APPROVAL_FLOW_SCHEMA_VERSION:
            raise ValueError(f"unsupported approval flow schema_version: {ver!r}")
        return ControlPlaneApprovalRequestV1(
            schema_version=int(data["schema_version"]),
            request_id_hex=str(data["request_id_hex"]),
            warrant_id=str(data["warrant_id"]),
            tool=str(data["tool"]),
            arguments=dict(data["arguments"]),
            request_hash_hex=str(data["request_hash_hex"]),
            holder_public_key_hex=str(data["holder_public_key_hex"]),
            required_approver_keys_hex=[str(x) for x in data["required_approver_keys_hex"]],
            min_approvals=int(data["min_approvals"]),
            warrant_expires_at_unix=int(data["warrant_expires_at_unix"]),
            created_at_unix=int(data["created_at_unix"]),
            attestation=dict(data["attestation"]) if data.get("attestation") is not None else None,
            temporal=dict(data["temporal"]) if data.get("temporal") is not None else None,
        )


@dataclass
class ControlPlaneApprovalResponseV1:
    status: str
    signed_approvals_b64: Optional[List[str]] = None
    error: Optional[str] = None
    server_request_id: Optional[str] = None

    @staticmethod
    def from_json_dict(data: Dict[str, Any]) -> ControlPlaneApprovalResponseV1:
        sa = data.get("signed_approvals_b64")
        return ControlPlaneApprovalResponseV1(
            status=str(data.get("status", "error")),
            signed_approvals_b64=[str(x) for x in sa] if sa is not None else None,
            error=(str(data["error"]) if data.get("error") is not None else None),
            server_request_id=(
                str(data["server_request_id"]) if data.get("server_request_id") is not None else None
            ),
        )


def build_control_plane_approval_request_v1(
    req: ApprovalRequest,
    holder: PublicKey,
    *,
    attest_signing_key: Any = None,
    temporal: Optional[Dict[str, str]] = None,
) -> ControlPlaneApprovalRequestV1:
    """Map a gate :class:`ApprovalRequest` + holder to the v1 wire payload.

    If ``attest_signing_key`` is set (a :class:`SigningKey`), includes an
    approval-context attestation signed by that key (witness / worker).
    """
    rid = req.request_id or _new_approval_request_id_bytes()
    if len(rid) != 16:
        raise ValueError("request_id must be 16 bytes")

    approver_hex: List[str] = []
    if req.required_approvers:
        approver_hex = [_pk_hex(pk) for pk in req.required_approvers]

    min_ap = int(req.min_approvals) if req.min_approvals is not None else max(1, len(approver_hex) or 1)
    exp = int(req.warrant_expires_at_unix) if req.warrant_expires_at_unix is not None else 0
    created = int(req.created_at_unix) if req.created_at_unix is not None else int(time.time())

    att: Optional[Dict[str, Any]] = None
    if attest_signing_key is not None:
        _, meta = build_approval_context_attestation(
            attest_signing_key,
            req.warrant_id,
            req.tool,
            req.arguments,
            holder,
        )
        att = dict(meta)

    return ControlPlaneApprovalRequestV1(
        schema_version=APPROVAL_FLOW_SCHEMA_VERSION,
        request_id_hex=rid.hex(),
        warrant_id=req.warrant_id,
        tool=req.tool,
        arguments=dict(req.arguments),
        request_hash_hex=req.request_hash.hex(),
        holder_public_key_hex=_pk_hex(holder),
        required_approver_keys_hex=approver_hex,
        min_approvals=min_ap,
        warrant_expires_at_unix=exp,
        created_at_unix=created,
        attestation=att,
        temporal=dict(temporal) if temporal else None,
    )


def verify_control_plane_approval_request_v1(
    body: ControlPlaneApprovalRequestV1,
    *,
    holder: PublicKey,
    trusted_attestation_signers: Optional[Sequence[PublicKey]] = None,
) -> None:
    """Control-plane: recompute hash and optionally verify context attestation.

    Args:
        body: Parsed request payload.
        holder: Holder public key for this invocation (must match hex field).
        trusted_attestation_signers: If set, attestation (when present) must be
            signed by one of these keys; signature and binding are verified.
    """
    if _pk_hex(holder) != body.holder_public_key_hex:
        raise ValueError("holder_public_key_hex does not match provided holder key")
    rh = compute_request_hash(body.warrant_id, body.tool, body.arguments, holder)
    if rh.hex() != body.request_hash_hex:
        raise ValueError("request_hash_hex does not match recomputed hash for arguments")

    if body.attestation:
        if not trusted_attestation_signers:
            raise ValueError("attestation present but trusted_attestation_signers is empty")
        sig_b64 = body.attestation.get("signature")
        signer_hex = body.attestation.get("signer_key")
        if not sig_b64 or not signer_hex:
            raise ValueError("attestation missing signature or signer_key")
        signer = _pk_from_hex(str(signer_hex))
        if not any(_same_pk(signer, t) for t in trusted_attestation_signers):
            raise ValueError("attestation signer is not in trusted_attestation_signers")
        sig = Signature.from_bytes(base64.b64decode(sig_b64))
        verify_approval_context_attestation(
            signer,
            body.warrant_id,
            body.tool,
            body.arguments,
            holder,
            sig,
        )


def signed_approvals_from_response(
    resp: ControlPlaneApprovalResponseV1,
) -> List[SignedApproval]:
    """Decode CBOR ``SignedApproval`` blobs from a successful response."""
    if not resp.signed_approvals_b64:
        return []
    out: List[SignedApproval] = []
    for item in resp.signed_approvals_b64:
        out.append(SignedApproval.from_bytes(base64.b64decode(item)))
    return out


__all__ = [
    "APPROVAL_FLOW_SCHEMA_VERSION",
    "ControlPlaneApprovalRequestV1",
    "ControlPlaneApprovalResponseV1",
    "build_control_plane_approval_request_v1",
    "verify_control_plane_approval_request_v1",
    "signed_approvals_from_response",
]
