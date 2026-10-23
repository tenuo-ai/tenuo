"""Approval exceptions subclass TenuoError without changing how integrations handle them."""

from __future__ import annotations

import asyncio
import base64
import os
import time

import pytest
from tenuo_core import ApprovalPayload, SignedApproval
from tenuo_core import py_compute_request_hash as compute_request_hash

from tenuo import SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async, verify_inbound_call
from tenuo.approval import (
    ApprovalDenied,
    ApprovalRequest,
    ApprovalRequired,
    ApprovalTimeout,
    ApprovalVerificationError,
)
from tenuo.exceptions import TenuoError

ALL_APPROVAL_ERRORS = (ApprovalRequired, ApprovalDenied, ApprovalTimeout, ApprovalVerificationError)


def _request() -> ApprovalRequest:
    return ApprovalRequest(tool="transfer", arguments={}, warrant_id="wrt_1", request_hash=b"\x00" * 32)


def _gated_warrant(agent_key: SigningKey, approver_key: SigningKey) -> Warrant:
    return Warrant.issue(
        agent_key,
        capabilities={"transfer": {}},
        ttl_seconds=3600,
        holder=agent_key.public_key,
        required_approvers=[approver_key.public_key],
        min_approvals=1,
        approval_gates={"transfer": None},
    )


def _signed(warrant: Warrant, holder_key: SigningKey, approver_key: SigningKey, args: dict) -> SignedApproval:
    now = int(time.time())
    payload = ApprovalPayload(
        request_hash=compute_request_hash(warrant.id, "transfer", args, holder_key.public_key),
        nonce=os.urandom(16),
        external_id="approver",
        approved_at=now,
        expires_at=now + 300,
    )
    return SignedApproval.create(payload, approver_key)


def _too_many(warrant: Warrant, holder_key: SigningKey, approver_key: SigningKey, args: dict) -> list:
    # More than 2x required_approvers -> core rejects -> ApprovalVerificationError.
    return [_signed(warrant, holder_key, approver_key, args) for _ in range(3)]


# -----------------------------------------------------------------------------
# Hierarchy
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_APPROVAL_ERRORS)
def test_is_tenuo_error(cls):
    assert issubclass(cls, TenuoError)


def test_attributes_and_messages_unchanged():
    req = _request()

    required = ApprovalRequired(req)
    assert required.request is req
    assert str(required) == "Approval required for tool \x27transfer\x27"

    denied = ApprovalDenied(req, reason="nope")
    assert (denied.request, denied.reason) == (req, "nope")
    assert str(denied) == "Approval denied for \x27transfer\x27: nope"
    assert ApprovalDenied(req).reason == "denied by approver"

    timeout = ApprovalTimeout(req, 5.0)
    assert isinstance(timeout, ApprovalDenied)
    assert timeout.timeout_seconds == 5.0
    assert str(timeout) == "Approval denied for \x27transfer\x27: timed out after 5.0s"

    verify = ApprovalVerificationError(req, reason="bad sig")
    assert (verify.request, verify.reason) == (req, "bad sig")
    assert str(verify) == "Approval verification failed for \x27transfer\x27: bad sig"
    assert not isinstance(verify, ApprovalDenied)


def test_caught_by_except_tenuo_error():
    with pytest.raises(TenuoError):
        raise ApprovalDenied(_request())


# -----------------------------------------------------------------------------
# _enforcement: approval outcomes still propagate, not mapped to a deny result
# -----------------------------------------------------------------------------


class TestEnforcementPropagation:
    def setup_method(self):
        self.agent = SigningKey.generate()
        self.approver = SigningKey.generate()
        self.warrant = _gated_warrant(self.agent, self.approver)
        self.bound = self.warrant.bind(self.agent, trusted_roots=[self.agent.public_key])

    def test_sign_path_no_handler_raises_approval_required(self):
        with pytest.raises(ApprovalRequired):
            enforce_tool_call("transfer", {}, self.bound, approval_handler=None)

    @pytest.mark.parametrize("exc_type", [ApprovalDenied, ApprovalTimeout])
    def test_sync_handler_denial_propagates(self, exc_type):
        def handler(req):
            raise exc_type(req, 1.0) if exc_type is ApprovalTimeout else exc_type(req)

        with pytest.raises(exc_type):
            enforce_tool_call("transfer", {}, self.bound, approval_handler=handler)

    def test_sync_verification_error_propagates(self):
        approvals = _too_many(self.warrant, self.agent, self.approver, {})
        with pytest.raises(ApprovalVerificationError):
            enforce_tool_call("transfer", {}, self.bound, approval_handler=lambda _r: approvals)

    def test_async_handler_denial_propagates(self):
        async def handler(req):
            raise ApprovalDenied(req)

        with pytest.raises(ApprovalDenied):
            asyncio.run(enforce_tool_call_async("transfer", {}, self.bound, approval_handler=handler))

    def test_async_verification_error_propagates(self):
        approvals = _too_many(self.warrant, self.agent, self.approver, {})
        with pytest.raises(ApprovalVerificationError):
            asyncio.run(enforce_tool_call_async("transfer", {}, self.bound, approval_handler=lambda _r: approvals))

    def test_verify_path_verification_error_propagates(self):
        from tenuo_core import Authorizer

        pop = bytes(self.warrant.sign(self.agent, "transfer", {}, int(time.time())))
        with pytest.raises(ApprovalVerificationError):
            verify_inbound_call(
                tool_name="transfer",
                tool_args={},
                warrant=self.warrant,
                pop_signature=pop,
                authorizer=Authorizer(trusted_roots=[self.agent.public_key]),
                approvals=_too_many(self.warrant, self.agent, self.approver, {}),
            )


# -----------------------------------------------------------------------------
# MCP: approval verification failures keep the internal-error mapping
# -----------------------------------------------------------------------------


def test_mcp_verification_error_keeps_internal_error_mapping():
    from tenuo_core import Authorizer

    from tenuo.mcp.server import MCPVerifier

    issuer, agent, approver = (SigningKey.generate() for _ in range(3))
    warrant = Warrant.issue(
        issuer,
        capabilities={"transfer": {}},
        ttl_seconds=3600,
        holder=agent.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates={"transfer": None},
    )
    args: dict = {}
    sig = bytes(warrant.sign(agent, "transfer", args, int(time.time())))
    meta = {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(sig).decode(),
            "approvals": [
                base64.b64encode(bytes(a.to_bytes())).decode() for a in _too_many(warrant, agent, approver, args)
            ],
        }
    }

    result = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key])).verify("transfer", args, meta=meta)

    assert not result.allowed
    assert result.jsonrpc_error_code == -32001
    assert result.denial_reason.startswith("Internal verification error: Approval verification failed")


# -----------------------------------------------------------------------------
# FastAPI: global TenuoError handler leaves approval outcomes alone
# -----------------------------------------------------------------------------


class TestFastAPIGlobalHandler:
    @pytest.fixture
    def app(self):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI

        from tenuo.fastapi import configure_tenuo

        app = FastAPI()
        configure_tenuo(app)

        @app.get("/denied")
        def denied():
            raise ApprovalDenied(_request(), reason="no")

        @app.get("/required")
        def required():
            raise ApprovalRequired(_request())

        return app

    @pytest.mark.parametrize("path,exc_type", [("/denied", ApprovalDenied), ("/required", ApprovalRequired)])
    def test_approval_exception_propagates(self, app, path, exc_type):
        from fastapi.testclient import TestClient

        with pytest.raises(exc_type):
            TestClient(app).get(path)

    def test_approval_exception_is_plain_500(self, app):
        from fastapi.testclient import TestClient

        resp = TestClient(app, raise_server_exceptions=False).get("/denied")
        assert resp.status_code == 500
        assert resp.text == "Internal Server Error"
