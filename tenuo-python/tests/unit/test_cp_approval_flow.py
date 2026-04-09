"""Control-plane approval flow: wire schema, hash parity, attestation verification."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

import pytest

from tenuo import (
    PublicKey,
    Range,
    SigningKey,
    Warrant,
    build_control_plane_approval_request_v1,
    compute_request_hash,
    submit_control_plane_approval_request_v1,
    verify_control_plane_approval_request_v1,
)
from tenuo.approval import ApprovalRequest, warrant_expires_at_unix
from tenuo.cp_approval import ControlPlaneApprovalRequestV1, signed_approvals_from_response


def _mint_warrant_with_gate(issuer: SigningKey, holder: SigningKey, approver: PublicKey) -> Warrant:
    return Warrant.issue(
        keypair=issuer,
        capabilities={"risky": {"amount": Range(0, 999_999)}},
        ttl_seconds=3600,
        holder=holder.public_key,
        required_approvers=[approver],
        min_approvals=1,
        approval_gates={"risky": None},
    )


class TestControlPlaneApprovalFlow:
    def test_json_round_trip_payload_hash_stable(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 42}
        rh = compute_request_hash(w.id, "risky", args, holder.public_key)
        req = ApprovalRequest.for_warrant_gate("risky", args, w, rh)
        body = build_control_plane_approval_request_v1(req, holder.public_key)

        raw = json.dumps(body.to_json_dict())
        data = json.loads(raw)
        parsed = ControlPlaneApprovalRequestV1.from_json_dict(data)

        holder_pk = holder.public_key
        verify_control_plane_approval_request_v1(parsed, holder=holder_pk)

        # JSON round-trip of arguments must preserve types Tenuo accepts (int stays int).
        assert parsed.arguments["amount"] == 42

    def test_worker_and_cp_hash_match_explicit(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 7}
        h1 = compute_request_hash(w.id, "risky", args, holder.public_key)
        h2 = compute_request_hash(w.id, "risky", args, holder.public_key)
        assert h1 == h2

    def test_verify_fails_on_tampered_arguments(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 1}
        rh = compute_request_hash(w.id, "risky", args, holder.public_key)
        req = ApprovalRequest.for_warrant_gate("risky", args, w, rh)
        body = build_control_plane_approval_request_v1(req, holder.public_key)
        d = body.to_json_dict()
        d["arguments"] = {"amount": 2}
        bad = ControlPlaneApprovalRequestV1.from_json_dict(d)
        with pytest.raises(ValueError, match="request_hash"):
            verify_control_plane_approval_request_v1(bad, holder=holder.public_key)

    def test_attestation_verified_when_trusted_signer_set(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        witness = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 99}
        rh = compute_request_hash(w.id, "risky", args, holder.public_key)
        req = ApprovalRequest.for_warrant_gate("risky", args, w, rh)
        body = build_control_plane_approval_request_v1(
            req,
            holder.public_key,
            attest_signing_key=witness,
        )
        assert body.attestation is not None
        verify_control_plane_approval_request_v1(
            body,
            holder=holder.public_key,
            trusted_attestation_signers=[witness.public_key],
        )

    def test_attestation_rejected_wrong_trusted_set(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        witness = SigningKey.generate()
        other = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 3}
        rh = compute_request_hash(w.id, "risky", args, holder.public_key)
        req = ApprovalRequest.for_warrant_gate("risky", args, w, rh)
        body = build_control_plane_approval_request_v1(
            req,
            holder.public_key,
            attest_signing_key=witness,
        )
        with pytest.raises(ValueError, match="not in trusted"):
            verify_control_plane_approval_request_v1(
                body,
                holder=holder.public_key,
                trusted_attestation_signers=[other.public_key],
            )

    def test_warrant_expires_at_unix_from_warrant(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        w = Warrant.issue(
            keypair=issuer,
            capabilities={"t": {}},
            ttl_seconds=120,
            holder=holder.public_key,
        )
        u = warrant_expires_at_unix(w)
        assert u is not None and u > 0

    def test_submit_parses_json_response(self):
        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver = SigningKey.generate()
        w = _mint_warrant_with_gate(issuer, holder, approver.public_key)
        args = {"amount": 1}
        rh = compute_request_hash(w.id, "risky", args, holder.public_key)
        req = ApprovalRequest.for_warrant_gate("risky", args, w, rh)
        body = build_control_plane_approval_request_v1(req, holder.public_key)

        from tenuo.approval import ApprovalRequest as AR, sign_approval

        sa = sign_approval(
            AR(
                tool=req.tool,
                arguments=req.arguments,
                warrant_id=req.warrant_id,
                request_hash=req.request_hash,
            ),
            approver,
        )
        import base64

        resp_obj: Dict[str, Any] = {
            "status": "approved",
            "signed_approvals_b64": [base64.b64encode(sa.to_bytes()).decode("ascii")],
        }

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                payload = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_port
            url = f"http://127.0.0.1:{port}/v1/approvals/requests"
            resp = submit_control_plane_approval_request_v1(url, body, timeout_sec=5.0)
            assert resp.status == "approved"
            decoded = signed_approvals_from_response(resp)
            assert len(decoded) == 1
        finally:
            server.shutdown()
            thread.join(timeout=2.0)
