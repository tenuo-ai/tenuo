"""
Tests for tenuo.approval and enforcement with warrant approval gates (no runtime policies).
"""

from __future__ import annotations

import base64
import os
import time
from unittest.mock import patch

import pytest
from tenuo_core import ApprovalPayload, SignedApproval
from tenuo_core import py_compute_request_hash as compute_request_hash

from tenuo import (
    SigningKey,
    Signature,
    Subpath,
    Warrant,
    build_approval_context_attestation,
    verify_approval_context_attestation,
)
from tenuo.constraints import Constraints
from tenuo._enforcement import enforce_tool_call
from tenuo.approval import (
    ApprovalDenied,
    ApprovalRequest,
    ApprovalRequired,
    ApprovalTimeout,
    ApprovalVerificationError,
    auto_approve,
    auto_deny,
    cli_prompt,
    sign_approval,
    webhook,
)


# -----------------------------------------------------------------------------
# Fixtures & helpers
# -----------------------------------------------------------------------------


@pytest.fixture
def agent_key():
    return SigningKey.generate()


@pytest.fixture
def approver_key():
    return SigningKey.generate()


@pytest.fixture
def keys():
    """Root issuer, warrant holder, and approver (same layout as test_guards)."""
    root = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    return root, holder, approver


@pytest.fixture
def bound_warrant(agent_key):
    """Tier-2 bound warrant without approval gates (open tools)."""
    w = Warrant.issue(
        agent_key,
        capabilities={"search": {}, "transfer": {}, "delete_user": {}},
        ttl_seconds=3600,
        holder=agent_key.public_key,
    )
    return w.bind(agent_key, trusted_roots=[agent_key.public_key])


def _bound_gated(agent_key: SigningKey, approver_key: SigningKey, *, gates: dict, caps: dict | None = None):
    caps = caps or {"search": {}, "transfer": {}, "delete_user": {}, "read_file": {}, "deploy": {}}
    w = Warrant.issue(
        agent_key,
        capabilities=caps,
        ttl_seconds=3600,
        holder=agent_key.public_key,
        required_approvers=[approver_key.public_key],
        min_approvals=1,
        approval_gates=gates,
    )
    return w.bind(agent_key, trusted_roots=[agent_key.public_key])


# -----------------------------------------------------------------------------
# sign_approval
# -----------------------------------------------------------------------------


class TestSignApproval:
    def test_produces_valid_signed_approval(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="transfer", arguments={}, warrant_id="w", request_hash=h)
        signed = sign_approval(req, approver_key)
        payload = signed.verify()
        assert payload.request_hash == h
        assert signed.approver_key == approver_key.public_key

    def test_nonce_is_unique(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        s1 = sign_approval(req, approver_key)
        s2 = sign_approval(req, approver_key)
        assert s1.verify().nonce != s2.verify().nonce

    def test_custom_external_id(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        signed = sign_approval(req, approver_key, external_id="admin@co.com")
        assert signed.verify().external_id == "admin@co.com"

    def test_expiry_set(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        before = int(time.time())
        signed = sign_approval(req, approver_key, ttl_seconds=600)
        payload = signed.verify()
        assert payload.expires_at >= before + 600


# -----------------------------------------------------------------------------
# Handlers
# -----------------------------------------------------------------------------


class TestAutoApprove:
    def test_returns_signed_approval(self, approver_key):
        handler = auto_approve(approver_key=approver_key)
        h = os.urandom(32)
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50_000}, warrant_id="w", request_hash=h)
        signed = handler(req)
        payload = signed.verify()
        assert payload.request_hash == h
        assert signed.approver_key == approver_key.public_key


class TestAutoDeny:
    def test_raises(self, approver_key):
        handler = auto_deny()
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=os.urandom(32))
        with pytest.raises(ApprovalDenied):
            handler(req)


class TestCliPrompt:
    @staticmethod
    def _make_request():
        return ApprovalRequest(
            tool="transfer",
            arguments={"amount": 50_000},
            warrant_id="wrt_test",
            request_hash=os.urandom(32),
        )

    def test_approve_y(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", return_value="y"):
            signed = handler(req)
        assert signed.verify().request_hash == req.request_hash

    def test_deny_n(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", return_value="n"):
            with pytest.raises(ApprovalDenied, match="denied via CLI"):
                handler(req)

    def test_show_args_false_hides_arguments(self, approver_key, capsys):
        handler = cli_prompt(approver_key=approver_key, show_args=False)
        req = ApprovalRequest(
            tool="transfer",
            arguments={"amount": 50_000, "to": "secret"},
            warrant_id="w",
            request_hash=os.urandom(32),
        )
        with patch("builtins.input", return_value="y"):
            handler(req)
        captured = capsys.readouterr()
        assert "secret" not in captured.err


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class TestExceptions:
    def test_approval_required_message(self):
        req = ApprovalRequest(
            tool="transfer", arguments={}, warrant_id="wrt_123", request_hash=b"\x00" * 32
        )
        exc = ApprovalRequired(req)
        assert "transfer" in str(exc)
        assert "wrt_123" in str(exc)

    def test_verification_error_not_approval_denied(self):
        assert not issubclass(ApprovalVerificationError, ApprovalDenied)

    def test_approval_timeout_is_approval_denied(self):
        assert issubclass(ApprovalTimeout, ApprovalDenied)


# -----------------------------------------------------------------------------
# Crypto & hashes
# -----------------------------------------------------------------------------


class TestCryptographicVerification:
    def test_compute_request_hash_deterministic(self, agent_key):
        h1 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        h2 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        assert h1 == h2

    def test_full_sign_verify_cycle(self, approver_key, agent_key):
        h = compute_request_hash("wrt_1", "transfer", {"amount": 50000}, agent_key.public_key)
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50000}, warrant_id="wrt_1", request_hash=h)
        signed = sign_approval(req, approver_key)
        payload = signed.verify()
        assert payload.request_hash == h

    def test_build_approval_context_attestation_metadata(self, approver_key, agent_key):
        args = {"amount": 42}
        holder = agent_key.public_key
        args_b64, meta = build_approval_context_attestation(
            approver_key, "wrt_ac", "pay", args, holder
        )
        rh = compute_request_hash("wrt_ac", "pay", args, holder)
        assert meta["request_hash"] == rh.hex()
        sig = Signature.from_bytes(base64.b64decode(meta["signature"]))
        verify_approval_context_attestation(
            approver_key.public_key, "wrt_ac", "pay", args, holder, sig
        )

    def test_warrant_holder_key_matches_authorized_holder(self, agent_key):
        w = Warrant.mint(
            keypair=agent_key,
            capabilities=Constraints.for_tool("test", {}),
            ttl_seconds=60,
        )
        assert w.holder_key.to_bytes() == w.authorized_holder.to_bytes()


# -----------------------------------------------------------------------------
# enforce_tool_call + gates
# -----------------------------------------------------------------------------


class TestEnforcementIntegration:
    def test_ungated_tool_passes(self, bound_warrant):
        result = enforce_tool_call("search", {"query": "test"}, bound_warrant)
        assert result.allowed

    def test_gate_auto_approve(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})
        result = enforce_tool_call(
            "transfer",
            {"amount": 50_000},
            bound,
            approval_handler=auto_approve(approver_key=approver_key),
        )
        assert result.allowed

    def test_gate_auto_deny(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})
        with pytest.raises(ApprovalDenied):
            enforce_tool_call(
                "transfer",
                {"amount": 50_000},
                bound,
                approval_handler=auto_deny(),
            )

    def test_gate_no_handler_raises(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"delete_user": None})
        with pytest.raises(ApprovalRequired):
            enforce_tool_call("delete_user", {"id": "42"}, bound, approval_handler=None)

    def test_warrant_denial_before_approval(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})
        result = enforce_tool_call(
            "forbidden_tool",
            {},
            bound,
            approval_handler=auto_approve(approver_key=approver_key),
        )
        assert not result.allowed

    def test_constraint_violation_before_approval(self, approver_key):
        key = SigningKey.generate()
        w = Warrant.issue(
            key,
            capabilities={"read_file": {"path": Subpath("/allowed")}},
            ttl_seconds=3600,
            holder=key.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"read_file": None},
        )
        bound = w.bind(key, trusted_roots=[key.public_key])
        result = enforce_tool_call(
            "read_file",
            {"path": "/etc/shadow"},
            bound,
            approval_handler=auto_approve(approver_key=approver_key),
            trusted_roots=[key.public_key],
        )
        assert not result.allowed

    def test_handler_exception_fail_closed(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"search": None})

        def buggy(_req):
            raise ValueError("handler bug")

        result = enforce_tool_call(
            "search",
            {"query": "test"},
            bound,
            approval_handler=buggy,
        )
        assert not result.allowed
        assert result.error_type == "internal_error"


class TestTamperResistance:
    def test_wrong_hash_rejected(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})

        def forging_handler(request):
            fake_hash = os.urandom(32)
            now = int(time.time())
            payload = ApprovalPayload(
                request_hash=fake_hash,
                nonce=os.urandom(16),
                external_id="forger",
                approved_at=now,
                expires_at=now + 300,
            )
            return SignedApproval.create(payload, approver_key)

        with pytest.raises(ApprovalVerificationError, match="request hash mismatch"):
            enforce_tool_call(
                "transfer",
                {"amount": 50_000},
                bound,
                approval_handler=forging_handler,
            )

    def test_untrusted_key_rejected(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})
        rogue = SigningKey.generate()
        with pytest.raises(ApprovalVerificationError, match="approver not in trusted set"):
            enforce_tool_call(
                "transfer",
                {"amount": 50_000},
                bound,
                approval_handler=auto_approve(approver_key=rogue),
            )


class TestAsyncHandler:
    def test_async_approve(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"transfer": None})

        async def async_approve_handler(req):
            return sign_approval(req, approver_key)

        result = enforce_tool_call(
            "transfer",
            {"amount": 50_000},
            bound,
            approval_handler=async_approve_handler,
        )
        assert result.allowed


class TestMultiApprover:
    def test_any_required_approver_key_works(self, agent_key):
        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        k3 = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[k1.public_key, k2.public_key, k3.public_key],
            min_approvals=1,
            approval_gates={"transfer": None},
        )
        bound = w.bind(agent_key, trusted_roots=[agent_key.public_key])
        for key in (k1, k2, k3):
            result = enforce_tool_call(
                "transfer",
                {"amount": 100},
                bound,
                approval_handler=auto_approve(approver_key=key),
            )
            assert result.allowed

    def test_outsider_rejected(self, agent_key):
        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        outsider = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[k1.public_key, k2.public_key],
            min_approvals=1,
            approval_gates={"transfer": None},
        )
        bound = w.bind(agent_key, trusted_roots=[agent_key.public_key])
        with pytest.raises(ApprovalVerificationError, match="approver not in trusted set"):
            enforce_tool_call(
                "transfer",
                {"amount": 100},
                bound,
                approval_handler=auto_approve(approver_key=outsider),
            )


class TestRequestHashBinding:
    def test_approval_reuse_across_warrants_fails(self, approver_key):
        agent = SigningKey.generate()
        w_a = Warrant.issue(
            agent,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"transfer": None},
        )
        w_b = Warrant.issue(
            agent,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"transfer": None},
        )
        bound_a = w_a.bind(agent, trusted_roots=[agent.public_key])
        bound_b = w_b.bind(agent, trusted_roots=[agent.public_key])
        captured: list = [None]

        def capture_handler(request):
            signed = sign_approval(request, approver_key)
            captured[0] = signed
            return signed

        enforce_tool_call(
            "transfer",
            {"amount": 100},
            bound_a,
            approval_handler=capture_handler,
        )

        def replay_handler(_request):
            return captured[0]

        with pytest.raises(ApprovalVerificationError, match="request hash mismatch"):
            enforce_tool_call(
                "transfer",
                {"amount": 100},
                bound_b,
                approval_handler=replay_handler,
            )


class TestSerialization:
    def test_to_bytes_from_bytes_roundtrip(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        original = sign_approval(req, approver_key)
        restored = SignedApproval.from_bytes(original.to_bytes())
        assert restored.verify().request_hash == h


class TestWebhook:
    def test_webhook_raises_not_implemented(self):
        handler = webhook("https://example.com/approve")
        req = ApprovalRequest(
            tool="transfer",
            arguments={"amount": 50_000},
            warrant_id="w",
            request_hash=os.urandom(32),
        )
        with pytest.raises(NotImplementedError, match="placeholder"):
            handler(req)


class TestTTLPropagation:
    def test_sign_approval_default_300(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        before = int(time.time())
        signed = sign_approval(req, approver_key)
        p = signed.verify()
        assert p.expires_at >= before + 300

    def test_explicit_ttl(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        before = int(time.time())
        signed = sign_approval(req, approver_key, ttl_seconds=60)
        assert signed.verify().expires_at <= before + 61


class TestApprovalsAsInput:
    def _setup(self):
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"transfer": None},
        )
        bound = w.bind(agent_key, trusted_roots=[agent_key.public_key])
        return agent_key, approver_key, bound

    def test_pre_signed_accepted(self):
        from tenuo_core import py_compute_request_hash as _compute_hash

        agent_key, approver_key, bound = self._setup()
        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {"to": "acct-1"}, agent_key.public_key)
        request = ApprovalRequest(
            tool="transfer",
            arguments={"to": "acct-1"},
            warrant_id=warrant_id,
            request_hash=request_hash,
        )
        signed = sign_approval(request, approver_key, external_id="cloud-user")
        result = enforce_tool_call(
            "transfer",
            {"to": "acct-1"},
            bound,
            approvals=[signed],
        )
        assert result.allowed

    def test_approvals_precedence_over_handler(self):
        from tenuo_core import py_compute_request_hash as _compute_hash

        agent_key, approver_key, bound = self._setup()
        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {}, agent_key.public_key)
        request = ApprovalRequest(
            tool="transfer",
            arguments={},
            warrant_id=warrant_id,
            request_hash=request_hash,
        )
        signed = sign_approval(request, approver_key)
        result = enforce_tool_call(
            "transfer",
            {},
            bound,
            approval_handler=auto_deny(),
            approvals=[signed],
        )
        assert result.allowed


class TestMofN:
    @staticmethod
    def _bound_mn(agent_key: SigningKey, keys: list[SigningKey], m: int):
        w = Warrant.issue(
            agent_key,
            capabilities={"deploy": {}, "transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[k.public_key for k in keys],
            min_approvals=m,
            approval_gates={"deploy": None, "transfer": None},
        )
        return w.bind(agent_key, trusted_roots=[agent_key.public_key])

    @staticmethod
    def _sign_for_request(approver_key, request_hash, ttl=300):
        now = int(time.time())
        payload = ApprovalPayload(
            request_hash=request_hash,
            nonce=os.urandom(16),
            external_id=f"approver-{id(approver_key) % 10000}",
            approved_at=now,
            expires_at=now + ttl,
        )
        return SignedApproval.create(payload, approver_key)

    def test_two_of_three_with_caller_approvals(self):
        agent_key = SigningKey.generate()
        k1, k2, k3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
        bound = self._bound_mn(agent_key, [k1, k2, k3], m=2)
        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)
        a1 = self._sign_for_request(k1, rh)
        a2 = self._sign_for_request(k2, rh)
        result = enforce_tool_call("deploy", {}, bound, approvals=[a1, a2])
        assert result.allowed

    def test_two_of_three_insufficient(self):
        agent_key = SigningKey.generate()
        k1, k2, k3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
        bound = self._bound_mn(agent_key, [k1, k2, k3], m=2)
        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)
        a1 = self._sign_for_request(k1, rh)
        with pytest.raises(ApprovalVerificationError, match="Insufficient approvals"):
            enforce_tool_call("deploy", {}, bound, approvals=[a1])


class TestCrewAIApproval:
    def test_builder_passes_handler(self, agent_key, approver_key):
        from tenuo import Wildcard
        from tenuo.crewai import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"search": None},
        )
        handler = auto_approve(approver_key=approver_key)
        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .on_approval(handler)
            .build()
        )
        assert guard._approval_handler is handler

    def test_approval_required_without_handler(self, agent_key, approver_key):
        from tenuo import Wildcard
        from tenuo.crewai import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"search": None},
        )
        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .with_trusted_roots([agent_key.public_key])
            .build()
        )
        with pytest.raises(ApprovalRequired):
            guard._authorize("search", {"query": "test"})


class TestAutoGenApproval:
    def test_builder_passes_handler(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
            required_approvers=[approver_key.public_key],
            min_approvals=1,
            approval_gates={"search": None},
        )
        handler = auto_approve(approver_key=approver_key)
        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, agent_key)
            .on_approval(handler)
            .build()
        )
        assert guard._approval_handler is handler


class TestAutoApproveWarning:
    def test_warns_once(self, agent_key, approver_key):
        bound = _bound_gated(agent_key, approver_key, gates={"search": None})
        handler = auto_approve(approver_key=approver_key)
        with patch("tenuo.approval.logger") as mock_logger:
            enforce_tool_call("search", {"query": "a"}, bound, approval_handler=handler)
            enforce_tool_call("search", {"query": "b"}, bound, approval_handler=handler)
            assert mock_logger.warning.call_count == 1


class TestEdgeCases:
    def test_approval_request_is_frozen(self):
        req = ApprovalRequest(
            tool="x", arguments={}, warrant_id="w", request_hash=b"\x00" * 32
        )
        with pytest.raises(AttributeError):
            req.tool = "hacked"  # type: ignore[misc]


def test_verified_approval_includes_signed_envelope_base64(keys):
    """ChainVerificationResult exposes base64 CBOR SignedApproval for audit / CP verification."""
    from tenuo import Authorizer, SignedApproval, VerifiedApproval
    from tenuo.approval import ApprovalRequest, sign_approval
    from tenuo_core import py_compute_request_hash as compute_hash

    root, holder, approver = keys
    w = Warrant.issue(
        keypair=root,
        capabilities={"delete_file": {}},
        ttl_seconds=3600,
        holder=holder.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates={"delete_file": None},
    )
    tool = "delete_file"
    args = {"path": "/tmp/x"}
    request_hash = compute_hash(w.id, tool, args, holder.public_key)
    req = ApprovalRequest(
        tool=tool, arguments=args, warrant_id=w.id, request_hash=request_hash
    )
    signed = sign_approval(req, approver)

    auth = Authorizer(trusted_roots=[root.public_key])
    sig = w.sign(holder, tool, args, int(time.time()))
    result = auth.authorize_one(w, tool, args, bytes(sig), [signed])

    assert len(result.verified_approvals) == 1
    va = result.verified_approvals[0]
    assert isinstance(va, VerifiedApproval)
    b64 = va.signed_approval_cbor_b64
    assert b64
    expected_wire = base64.standard_b64encode(bytes(signed.to_bytes())).decode("ascii")
    assert b64 == expected_wire

    raw = base64.standard_b64decode(b64)
    restored = SignedApproval.from_bytes(raw)
    restored.verify()
