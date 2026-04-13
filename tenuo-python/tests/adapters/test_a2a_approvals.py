"""
Tests for A2A approval transport (issue #353).

Covers:
- _decode_approvals extracts from header and params
- validate_warrant threads approvals into authorize_one / check_chain
- ApprovalRequired error is surfaced as ApprovalRequiredError JSON-RPC
- InsufficientApprovals error is surfaced as InsufficientApprovalsError
- End-to-end: gated skill succeeds with valid approvals
"""

import base64
import json
import time as _time
from unittest.mock import MagicMock

import pytest

from tenuo.a2a import A2AServer
from tenuo.a2a.errors import (
    A2AErrorCode,
    ApprovalRequiredError,
    InsufficientApprovalsError,
    InvalidApprovalError,
)
from tenuo.a2a.server import APPROVALS_HEADER


# =============================================================================
# Helpers
# =============================================================================


def _make_server(*, trusted_issuers=None, require_pop=True):
    """Build a minimal A2AServer with mocked core deps."""
    key = MagicMock()
    key.to_bytes.return_value = b"\x01" * 32
    return A2AServer(
        name="Test",
        url="https://test.example.com",
        public_key="01" * 32,
        trusted_issuers=trusted_issuers or ["aa" * 32],
        require_pop=require_pop,
        require_warrant=True,
        require_audience=False,
        check_replay=False,
    )


def _make_request(headers=None):
    """Build a mock Starlette request."""
    req = MagicMock()
    req.headers = headers or {}
    return req


# =============================================================================
# _decode_approvals
# =============================================================================


class TestDecodeApprovals:
    """Unit tests for A2AServer._decode_approvals."""

    def test_returns_none_when_no_header_or_param(self):
        req = _make_request()
        params: dict = {}
        assert A2AServer._decode_approvals(req, params) is None

    def test_returns_none_when_header_empty(self):
        req = _make_request({APPROVALS_HEADER: ""})
        assert A2AServer._decode_approvals(req, {}) is None

    def test_reads_from_header(self):
        """Approvals in the HTTP header are decoded."""
        core = pytest.importorskip("tenuo_core")

        approver = core.SigningKey.generate()

        payload = core.ApprovalPayload(
            request_hash=bytes(32),
            nonce=bytes(16),
            external_id="test@test.com",
            approved_at=1000,
            expires_at=9999999999,
        )
        approval = core.SignedApproval.create(payload, approver)
        item_b64 = base64.b64encode(approval.to_bytes()).decode()

        # Wire format: base64(json(["<base64(cbor)>", ...]))
        wire_value = base64.b64encode(json.dumps([item_b64]).encode()).decode()

        req = _make_request({APPROVALS_HEADER: wire_value})
        result = A2AServer._decode_approvals(req, {})
        assert result is not None
        assert len(result) == 1

    def test_reads_from_params_fallback(self):
        """Approvals in JSON-RPC params are decoded when header is absent."""
        core = pytest.importorskip("tenuo_core")

        approver = core.SigningKey.generate()
        payload = core.ApprovalPayload(
            request_hash=bytes(32),
            nonce=bytes(16),
            external_id="test@test.com",
            approved_at=1000,
            expires_at=9999999999,
        )
        approval = core.SignedApproval.create(payload, approver)
        item_b64 = base64.b64encode(approval.to_bytes()).decode()

        wire_value = base64.b64encode(json.dumps([item_b64]).encode()).decode()

        req = _make_request()  # no header
        result = A2AServer._decode_approvals(req, {"x-tenuo-approvals": wire_value})
        assert result is not None
        assert len(result) == 1

    def test_returns_none_on_malformed_payload(self):
        """Malformed approval data returns None (logged, not raised)."""
        wire_value = base64.b64encode(b"not valid json").decode()
        req = _make_request({APPROVALS_HEADER: wire_value})
        assert A2AServer._decode_approvals(req, {}) is None


# =============================================================================
# Error classes
# =============================================================================


class TestApprovalErrors:
    """Verify the new A2A approval error types."""

    def test_approval_required_error_code(self):
        err = ApprovalRequiredError("deploy", request_hash="abc", min_approvals=2)
        assert err.code == A2AErrorCode.APPROVAL_REQUIRED
        rpc = err.to_jsonrpc_error()
        assert rpc["data"]["min_approvals"] == 2
        assert rpc["data"]["request_hash"] == "abc"
        assert rpc["data"]["tenuo_code"] == 1707

    def test_insufficient_approvals_error_code(self):
        err = InsufficientApprovalsError("not enough", required=3, received=1)
        assert err.code == A2AErrorCode.INSUFFICIENT_APPROVALS
        rpc = err.to_jsonrpc_error()
        assert rpc["data"]["required"] == 3
        assert rpc["data"]["received"] == 1
        assert rpc["data"]["tenuo_code"] == 1702

    def test_invalid_approval_error_code(self):
        err = InvalidApprovalError("bad format")
        assert err.code == A2AErrorCode.INVALID_APPROVAL
        rpc = err.to_jsonrpc_error()
        assert rpc["data"]["tenuo_code"] == 1701


# =============================================================================
# validate_warrant approval threading (integration with real crypto)
# =============================================================================


class TestValidateWarrantApprovals:
    """Integration tests: validate_warrant passes approvals to the Authorizer."""

    @pytest.mark.asyncio
    async def test_approval_required_raised_when_gate_fires_without_approvals(self):
        """A gated warrant with no approvals raises ApprovalRequiredError."""
        core = pytest.importorskip("tenuo_core")

        root_key = core.SigningKey.generate()
        approver = core.SigningKey.generate()

        warrant = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"deploy": {}},
            ttl_seconds=3600,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"deploy": None},
        )

        server = A2AServer(
            name="Test",
            url="https://test.example.com",
            public_key=root_key.public_key.to_bytes().hex(),
            trusted_issuers=[root_key.public_key.to_bytes().hex()],
            require_pop=True,
            require_warrant=True,
            require_audience=False,
            check_replay=False,
        )

        now = int(_time.time())
        pop_sig = warrant.sign(root_key, "deploy", {}, now)

        with pytest.raises(ApprovalRequiredError) as exc_info:
            await server.validate_warrant(
                warrant.to_base64(),
                "deploy",
                {},
                pop_signature=pop_sig,
                approvals=None,
            )
        assert "deploy" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_gated_skill_succeeds_with_valid_approval(self):
        """A gated warrant with a valid approval succeeds."""
        core = pytest.importorskip("tenuo_core")

        root_key = core.SigningKey.generate()
        approver = core.SigningKey.generate()

        warrant = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"deploy": {}},
            ttl_seconds=3600,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"deploy": None},
        )

        server = A2AServer(
            name="Test",
            url="https://test.example.com",
            public_key=root_key.public_key.to_bytes().hex(),
            trusted_issuers=[root_key.public_key.to_bytes().hex()],
            require_pop=True,
            require_warrant=True,
            require_audience=False,
            check_replay=False,
        )

        now = int(_time.time())
        pop_sig = warrant.sign(root_key, "deploy", {}, now)
        request_hash = core.py_compute_request_hash(
            warrant.id, "deploy", {}, warrant.authorized_holder,
        )
        approval_payload = core.ApprovalPayload(
            request_hash=request_hash,
            nonce=bytes(range(16)),
            external_id="admin@test.com",
            approved_at=now,
            expires_at=now + 300,
        )
        signed_approval = core.SignedApproval.create(approval_payload, approver)

        result = await server.validate_warrant(
            warrant.to_base64(),
            "deploy",
            {},
            pop_signature=pop_sig,
            approvals=[signed_approval],
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_wrong_approver_raises_invalid_approval(self):
        """An approval from an untrusted approver raises InvalidApprovalError."""
        core = pytest.importorskip("tenuo_core")

        root_key = core.SigningKey.generate()
        trusted_approver = core.SigningKey.generate()
        wrong_approver = core.SigningKey.generate()

        warrant = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"deploy": {}},
            ttl_seconds=3600,
            required_approvers=[trusted_approver.public_key],
            min_approvals=1,
            approval_gates={"deploy": None},
        )

        server = A2AServer(
            name="Test",
            url="https://test.example.com",
            public_key=root_key.public_key.to_bytes().hex(),
            trusted_issuers=[root_key.public_key.to_bytes().hex()],
            require_pop=True,
            require_warrant=True,
            require_audience=False,
            check_replay=False,
        )

        now = int(_time.time())
        pop_sig = warrant.sign(root_key, "deploy", {}, now)
        request_hash = core.py_compute_request_hash(
            warrant.id, "deploy", {}, warrant.authorized_holder,
        )
        bad_payload = core.ApprovalPayload(
            request_hash=request_hash,
            nonce=bytes(range(16)),
            external_id="wrong@test.com",
            approved_at=now,
            expires_at=now + 300,
        )
        bad_approval = core.SignedApproval.create(bad_payload, wrong_approver)

        with pytest.raises(InvalidApprovalError):
            await server.validate_warrant(
                warrant.to_base64(),
                "deploy",
                {},
                pop_signature=pop_sig,
                approvals=[bad_approval],
            )
