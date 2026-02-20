"""
Test suite for tenuo.approval - cryptographically verified human-in-the-loop authorization.

Tests cover:
- ApprovalRule matching (always, conditional, predicate failures)
- ApprovalPolicy checking (with request_hash, trusted_approvers)
- Built-in handlers (auto_approve, auto_deny, cli_prompt, webhook)
- Full cryptographic flow (sign -> verify -> hash match -> key trust -> expiry)
- Integration with enforce_tool_call() (end-to-end)
- Tamper resistance (wrong hash, untrusted key, expired approval)
- Exception hierarchy (ApprovalRequired, ApprovalDenied, ApprovalVerificationError)
- Async handler support
- Handler exceptions (fail-closed behavior)
- Constraint violation priority over approval
"""

import os
import time

import pytest
from unittest.mock import patch

from tenuo import SigningKey, Warrant, Subpath
from tenuo.approval import (
    ApprovalPolicy,
    ApprovalRule,
    ApprovalRequest,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalVerificationError,
    require_approval,
    sign_approval,
    auto_approve,
    auto_deny,
    cli_prompt,
    webhook,
)
from tenuo._enforcement import enforce_tool_call
from tenuo_core import (
    ApprovalPayload,
    SignedApproval,
    py_compute_request_hash as compute_request_hash,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def agent_key():
    return SigningKey.generate()


@pytest.fixture
def approver_key():
    return SigningKey.generate()


@pytest.fixture
def bound_warrant(agent_key):
    w = Warrant.issue(
        agent_key,
        capabilities={"search": {}, "transfer": {}, "delete_user": {}},
        ttl_seconds=3600,
        holder=agent_key.public_key,
    )
    return w.bind(agent_key)


@pytest.fixture
def high_value_policy(approver_key):
    return ApprovalPolicy(
        require_approval("transfer", when=lambda a: a.get("amount", 0) > 10_000),
        require_approval("delete_user"),
        trusted_approvers=[approver_key.public_key],
    )


@pytest.fixture
def open_policy():
    """Policy without trusted_approvers -- any valid key accepted."""
    return ApprovalPolicy(
        require_approval("transfer"),
    )


# =============================================================================
# ApprovalRule Tests
# =============================================================================


class TestApprovalRule:

    def test_unconditional_rule_matches(self):
        rule = ApprovalRule(tool="delete_user")
        assert rule.matches("delete_user", {"id": "42"})

    def test_unconditional_rule_ignores_other_tools(self):
        rule = ApprovalRule(tool="delete_user")
        assert not rule.matches("search", {"query": "test"})

    def test_conditional_rule_triggers_when_true(self):
        rule = ApprovalRule(tool="transfer", when=lambda a: a["amount"] > 10_000)
        assert rule.matches("transfer", {"amount": 50_000})

    def test_conditional_rule_skips_when_false(self):
        rule = ApprovalRule(tool="transfer", when=lambda a: a["amount"] > 10_000)
        assert not rule.matches("transfer", {"amount": 5_000})

    def test_predicate_exception_defaults_to_true(self):
        rule = ApprovalRule(tool="transfer", when=lambda a: a["missing_key"] > 0)
        assert rule.matches("transfer", {"amount": 100})

    def test_description_preserved(self):
        rule = require_approval("send_email", description="External emails need approval")
        assert rule.description == "External emails need approval"


# =============================================================================
# ApprovalPolicy Tests
# =============================================================================


class TestApprovalPolicy:

    def test_no_rules_never_triggers(self):
        policy = ApprovalPolicy()
        assert policy.check("anything", {}, "wrt_x", b"\x00" * 32) is None

    def test_matching_rule_returns_request(self, high_value_policy):
        req = high_value_policy.check("delete_user", {"id": "42"}, "wrt_1", b"\x00" * 32)
        assert req is not None
        assert req.tool == "delete_user"
        assert req.arguments == {"id": "42"}

    def test_conditional_rule_below_threshold(self, high_value_policy):
        assert high_value_policy.check("transfer", {"amount": 5_000}, "w", b"\x00" * 32) is None

    def test_conditional_rule_above_threshold(self, high_value_policy):
        req = high_value_policy.check("transfer", {"amount": 50_000}, "w", b"\x00" * 32)
        assert req is not None
        assert req.tool == "transfer"

    def test_unrelated_tool_not_matched(self, high_value_policy):
        assert high_value_policy.check("search", {"query": "test"}, "w", b"\x00" * 32) is None

    def test_request_hash_passed_through(self, high_value_policy):
        h = os.urandom(32)
        req = high_value_policy.check("delete_user", {}, "wrt_123", h)
        assert req.request_hash == h
        assert req.warrant_id == "wrt_123"

    def test_first_matching_rule_wins(self):
        policy = ApprovalPolicy(
            require_approval("transfer", description="rule-1"),
            require_approval("transfer", description="rule-2"),
        )
        req = policy.check("transfer", {}, "w", b"\x00" * 32)
        assert req.rule.description == "rule-1"

    def test_len(self, high_value_policy):
        assert len(high_value_policy) == 2

    def test_rules_returns_copy(self, high_value_policy):
        rules = high_value_policy.rules
        rules.clear()
        assert len(high_value_policy) == 2

    def test_trusted_approvers_set(self, approver_key):
        policy = ApprovalPolicy(
            require_approval("x"),
            trusted_approvers=[approver_key.public_key],
        )
        assert policy.trusted_approvers is not None
        assert len(policy.trusted_approvers) == 1

    def test_trusted_approvers_none_by_default(self):
        policy = ApprovalPolicy(require_approval("x"))
        assert policy.trusted_approvers is None


# =============================================================================
# sign_approval Tests
# =============================================================================


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


# =============================================================================
# Handler Tests
# =============================================================================


class TestAutoApprove:

    def test_returns_signed_approval(self, approver_key):
        handler = auto_approve(approver_key=approver_key)
        h = os.urandom(32)
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50_000}, warrant_id="w", request_hash=h)
        signed = handler(req)
        payload = signed.verify()
        assert payload.request_hash == h
        assert signed.approver_key == approver_key.public_key

    def test_external_id_is_auto_approve(self, approver_key):
        handler = auto_approve(approver_key=approver_key)
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        assert handler(req).verify().external_id == "auto-approve"


class TestAutoDeny:

    def test_raises_approval_denied(self):
        handler = auto_deny()
        h = os.urandom(32)
        req = ApprovalRequest(tool="transfer", arguments={}, warrant_id="w", request_hash=h)
        with pytest.raises(ApprovalDenied, match="auto-denied"):
            handler(req)

    def test_custom_reason(self):
        handler = auto_deny(reason="policy forbids this")
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        with pytest.raises(ApprovalDenied, match="policy forbids this"):
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
        payload = signed.verify()
        assert payload.request_hash == req.request_hash

    def test_approve_yes(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", return_value="yes"):
            signed = handler(req)
        assert signed.verify().request_hash == req.request_hash

    def test_deny_n(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", return_value="n"):
            with pytest.raises(ApprovalDenied, match="denied via CLI"):
                handler(req)

    def test_deny_empty(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", return_value=""):
            with pytest.raises(ApprovalDenied):
                handler(req)

    def test_deny_on_eof(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", side_effect=EOFError):
            with pytest.raises(ApprovalDenied):
                handler(req)

    def test_deny_on_keyboard_interrupt(self, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        req = self._make_request()
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with pytest.raises(ApprovalDenied):
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

    def test_description_shown(self, approver_key, capsys):
        rule = require_approval("transfer", description="High-value transfer")
        handler = cli_prompt(approver_key=approver_key)
        req = ApprovalRequest(
            tool="transfer",
            arguments={},
            warrant_id="w",
            request_hash=os.urandom(32),
            rule=rule,
        )
        with patch("builtins.input", return_value="n"):
            with pytest.raises(ApprovalDenied):
                handler(req)
        captured = capsys.readouterr()
        assert "High-value transfer" in captured.err

    def test_hash_shown_in_prompt(self, approver_key, capsys):
        handler = cli_prompt(approver_key=approver_key)
        req = ApprovalRequest(
            tool="x",
            arguments={},
            warrant_id="w",
            request_hash=b"\xab" * 32,
        )
        with patch("builtins.input", return_value="y"):
            handler(req)
        captured = capsys.readouterr()
        assert "abababab" in captured.err


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptions:

    def test_approval_required_message(self):
        req = ApprovalRequest(
            tool="transfer", arguments={}, warrant_id="wrt_123", request_hash=b"\x00" * 32
        )
        exc = ApprovalRequired(req)
        assert "transfer" in str(exc)
        assert "wrt_123" in str(exc)
        assert exc.request is req

    def test_approval_denied_message(self):
        req = ApprovalRequest(
            tool="transfer", arguments={}, warrant_id="w", request_hash=b"\x00" * 32
        )
        exc = ApprovalDenied(req, reason="too risky")
        assert "too risky" in str(exc)
        assert exc.request is req
        assert exc.reason == "too risky"

    def test_approval_timeout(self):
        req = ApprovalRequest(
            tool="transfer", arguments={}, warrant_id="w", request_hash=b"\x00" * 32
        )
        exc = ApprovalTimeout(req, timeout_seconds=30.0)
        assert "timed out" in str(exc)
        assert exc.timeout_seconds == 30.0
        assert isinstance(exc, ApprovalDenied)

    def test_verification_error_message(self):
        req = ApprovalRequest(
            tool="transfer", arguments={}, warrant_id="w", request_hash=b"\x00" * 32
        )
        exc = ApprovalVerificationError(req, reason="hash mismatch")
        assert "hash mismatch" in str(exc)
        assert exc.request is req


# =============================================================================
# Cryptographic Verification Tests
# =============================================================================


class TestCryptographicVerification:

    def test_compute_request_hash_deterministic(self, agent_key):
        h1 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        h2 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        assert h1 == h2

    def test_compute_request_hash_different_args(self, agent_key):
        h1 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        h2 = compute_request_hash("w", "transfer", {"amount": 200}, agent_key.public_key)
        assert h1 != h2

    def test_compute_request_hash_different_holder(self):
        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        h1 = compute_request_hash("w", "t", {}, k1.public_key)
        h2 = compute_request_hash("w", "t", {}, k2.public_key)
        assert h1 != h2

    def test_compute_request_hash_no_holder(self):
        h = compute_request_hash("w", "t", {}, None)
        assert len(h) == 32

    def test_full_sign_verify_cycle(self, approver_key, agent_key):
        h = compute_request_hash("wrt_1", "transfer", {"amount": 50000}, agent_key.public_key)
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50000}, warrant_id="wrt_1", request_hash=h)
        signed = sign_approval(req, approver_key)

        payload = signed.verify()
        assert payload.request_hash == h
        assert signed.approver_key == approver_key.public_key
        assert payload.expires_at > int(time.time())


# =============================================================================
# Enforcement Integration Tests
# =============================================================================


class TestEnforcementIntegration:

    def test_no_policy_passes_through(self, bound_warrant):
        result = enforce_tool_call("search", {"query": "test"}, bound_warrant)
        assert result.allowed

    def test_policy_no_match_passes_through(self, bound_warrant, high_value_policy):
        result = enforce_tool_call(
            "search", {"query": "test"}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_deny(),
        )
        assert result.allowed

    def test_policy_match_auto_approve(self, bound_warrant, high_value_policy, approver_key):
        result = enforce_tool_call(
            "transfer", {"amount": 50_000}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_approve(approver_key=approver_key),
        )
        assert result.allowed

    def test_policy_match_auto_deny_raises(self, bound_warrant, high_value_policy):
        with pytest.raises(ApprovalDenied):
            enforce_tool_call(
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=auto_deny(),
            )

    def test_policy_match_no_handler_raises(self, bound_warrant, high_value_policy):
        with pytest.raises(ApprovalRequired):
            enforce_tool_call(
                "delete_user", {"id": "42"}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=None,
            )

    def test_below_threshold_no_approval_needed(self, bound_warrant, high_value_policy):
        result = enforce_tool_call(
            "transfer", {"amount": 5_000}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_deny(),
        )
        assert result.allowed

    def test_warrant_denial_takes_priority(self, bound_warrant, high_value_policy, approver_key):
        """If the warrant denies the tool, approval policy is never checked."""
        result = enforce_tool_call(
            "forbidden_tool", {}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_approve(approver_key=approver_key),
        )
        assert not result.allowed

    def test_cli_prompt_integration(self, bound_warrant, high_value_policy, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        with patch("builtins.input", return_value="y"):
            result = enforce_tool_call(
                "delete_user", {"id": "42"}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=handler,
            )
        assert result.allowed

    def test_cli_prompt_deny_integration(self, bound_warrant, high_value_policy, approver_key):
        handler = cli_prompt(approver_key=approver_key)
        with patch("builtins.input", return_value="n"):
            with pytest.raises(ApprovalDenied):
                enforce_tool_call(
                    "delete_user", {"id": "42"}, bound_warrant,
                    approval_policy=high_value_policy,
                    approval_handler=handler,
                )

    def test_constraint_violation_skips_approval(self, approver_key):
        """Constraint failure short-circuits before the approval check runs."""
        key = SigningKey.generate()
        w = Warrant.issue(
            key,
            capabilities={"read_file": {"path": Subpath("/allowed")}},
            ttl_seconds=3600,
            holder=key.public_key,
        )
        bound = w.bind(key)

        policy = ApprovalPolicy(
            require_approval("read_file"),
            trusted_approvers=[approver_key.public_key],
        )

        result = enforce_tool_call(
            "read_file", {"path": "/etc/shadow"}, bound,
            approval_policy=policy,
            approval_handler=auto_approve(approver_key=approver_key),
        )
        assert not result.allowed
        assert "path" in (result.constraint_violated or result.denial_reason or "")

    def test_handler_exception_is_fail_closed(self, bound_warrant):
        """A buggy handler should fail closed (internal_error), not allow."""
        def buggy_handler(req):
            raise ValueError("handler bug")

        policy = ApprovalPolicy(require_approval("search"))

        result = enforce_tool_call(
            "search", {"query": "test"}, bound_warrant,
            approval_policy=policy,
            approval_handler=buggy_handler,
        )
        assert not result.allowed
        assert result.error_type == "internal_error"
        assert "handler bug" in (result.denial_reason or "")


# =============================================================================
# Tamper Resistance Tests
# =============================================================================


class TestTamperResistance:

    def test_wrong_hash_rejected(self, bound_warrant, high_value_policy, approver_key):
        """Approval signed for a different request hash is rejected."""
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
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=forging_handler,
            )

    def test_untrusted_key_rejected(self, bound_warrant, high_value_policy):
        """Approval from an untrusted key is rejected."""
        rogue_key = SigningKey.generate()
        with pytest.raises(ApprovalVerificationError, match="approver not in trusted set"):
            enforce_tool_call(
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=auto_approve(approver_key=rogue_key),
            )

    def test_expired_approval_rejected(self, bound_warrant, high_value_policy, approver_key):
        """Approval that has already expired is rejected (beyond clock tolerance)."""
        def expired_handler(request):
            now = int(time.time())
            payload = ApprovalPayload(
                request_hash=request.request_hash,
                nonce=os.urandom(16),
                external_id="slow",
                approved_at=now - 600,
                expires_at=now - 120,  # Well beyond 30s clock tolerance
            )
            return SignedApproval.create(payload, approver_key)

        with pytest.raises(ApprovalVerificationError, match="expired"):
            enforce_tool_call(
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=expired_handler,
            )

    def test_open_policy_accepts_any_valid_key(self, bound_warrant, open_policy):
        """Without trusted_approvers, any valid signature is accepted."""
        random_key = SigningKey.generate()
        result = enforce_tool_call(
            "transfer", {"amount": 100}, bound_warrant,
            approval_policy=open_policy,
            approval_handler=auto_approve(approver_key=random_key),
        )
        assert result.allowed


# =============================================================================
# Async Handler Tests
# =============================================================================


class TestAsyncHandler:

    def test_async_handler_approve(self, bound_warrant, high_value_policy, approver_key):
        async def async_approve_handler(req):
            return sign_approval(req, approver_key)

        result = enforce_tool_call(
            "transfer", {"amount": 50_000}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=async_approve_handler,
        )
        assert result.allowed

    def test_async_handler_deny(self, bound_warrant, high_value_policy):
        async def async_deny_handler(req):
            raise ApprovalDenied(req, reason="async denied")

        with pytest.raises(ApprovalDenied, match="async denied"):
            enforce_tool_call(
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=async_deny_handler,
            )


# =============================================================================
# Multi-Approver Tests
# =============================================================================


class TestMultiApprover:

    def test_any_trusted_key_accepted(self, bound_warrant):
        """When multiple keys are trusted, any of them can approve."""
        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        k3 = SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("transfer"),
            trusted_approvers=[k1.public_key, k2.public_key, k3.public_key],
        )

        for key in (k1, k2, k3):
            result = enforce_tool_call(
                "transfer", {"amount": 100}, bound_warrant,
                approval_policy=policy,
                approval_handler=auto_approve(approver_key=key),
            )
            assert result.allowed

    def test_none_of_trusted_keys_rejects_outsider(self, bound_warrant):
        k1 = SigningKey.generate()
        k2 = SigningKey.generate()
        outsider = SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("transfer"),
            trusted_approvers=[k1.public_key, k2.public_key],
        )

        with pytest.raises(ApprovalVerificationError, match="approver not in trusted set"):
            enforce_tool_call(
                "transfer", {"amount": 100}, bound_warrant,
                approval_policy=policy,
                approval_handler=auto_approve(approver_key=outsider),
            )

    def test_trusted_approvers_returns_copy(self):
        k = SigningKey.generate()
        policy = ApprovalPolicy(
            require_approval("x"),
            trusted_approvers=[k.public_key],
        )
        lst = policy.trusted_approvers
        lst.clear()
        assert len(policy.trusted_approvers) == 1


# =============================================================================
# Request Hash Binding Tests
# =============================================================================


class TestRequestHashBinding:

    def test_different_warrant_different_hash(self, agent_key):
        h1 = compute_request_hash("wrt_aaa", "transfer", {"amount": 100}, agent_key.public_key)
        h2 = compute_request_hash("wrt_bbb", "transfer", {"amount": 100}, agent_key.public_key)
        assert h1 != h2

    def test_different_tool_different_hash(self, agent_key):
        h1 = compute_request_hash("w", "transfer", {"amount": 100}, agent_key.public_key)
        h2 = compute_request_hash("w", "search", {"amount": 100}, agent_key.public_key)
        assert h1 != h2

    def test_arg_order_does_not_affect_hash(self, agent_key):
        """Args are sorted before hashing, so insertion order doesn't matter."""
        h1 = compute_request_hash("w", "t", {"a": 1, "b": 2}, agent_key.public_key)
        h2 = compute_request_hash("w", "t", {"b": 2, "a": 1}, agent_key.public_key)
        assert h1 == h2

    def test_empty_args_hash(self, agent_key):
        h = compute_request_hash("w", "t", {}, agent_key.public_key)
        assert len(h) == 32

    def test_various_arg_types(self, agent_key):
        """Hash works with str, int, float, bool, list args."""
        h = compute_request_hash("w", "t", {
            "s": "hello",
            "i": 42,
            "f": 3.14,
            "b": True,
            "l": [1, 2, 3],
        }, agent_key.public_key)
        assert len(h) == 32

    def test_approval_reuse_across_warrants_fails(self, approver_key):
        """An approval signed for warrant A cannot pass verification for warrant B."""
        agent = SigningKey.generate()
        w_a = Warrant.issue(agent, capabilities={"transfer": {}}, ttl_seconds=3600, holder=agent.public_key)
        w_b = Warrant.issue(agent, capabilities={"transfer": {}}, ttl_seconds=3600, holder=agent.public_key)
        bound_a = w_a.bind(agent)
        bound_b = w_b.bind(agent)

        policy = ApprovalPolicy(
            require_approval("transfer"),
            trusted_approvers=[approver_key.public_key],
        )

        # Get a valid approval for warrant A
        signed_for_a = [None]

        def capture_handler(request):
            signed = sign_approval(request, approver_key)
            signed_for_a[0] = signed
            return signed

        result = enforce_tool_call(
            "transfer", {"amount": 100}, bound_a,
            approval_policy=policy,
            approval_handler=capture_handler,
        )
        assert result.allowed

        # Try to replay that approval for warrant B (different warrant_id)
        def replay_handler(request):
            return signed_for_a[0]

        with pytest.raises(ApprovalVerificationError, match="request hash mismatch"):
            enforce_tool_call(
                "transfer", {"amount": 100}, bound_b,
                approval_policy=policy,
                approval_handler=replay_handler,
            )


# =============================================================================
# SignedApproval Serialization Tests
# =============================================================================


class TestSerialization:

    def test_to_bytes_from_bytes_roundtrip(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        original = sign_approval(req, approver_key)

        wire = original.to_bytes()
        restored = SignedApproval.from_bytes(wire)

        payload = restored.verify()
        assert payload.request_hash == h
        assert restored.approver_key == approver_key.public_key

    def test_tampered_bytes_fail_verify(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        signed = sign_approval(req, approver_key)

        wire = bytearray(signed.to_bytes())
        wire[-1] ^= 0xFF  # flip last byte (in signature)

        restored = SignedApproval.from_bytes(bytes(wire))
        with pytest.raises(Exception):
            restored.verify()


# =============================================================================
# Custom Handler Tests
# =============================================================================


class TestCustomHandler:

    def test_custom_sync_handler(self, bound_warrant, approver_key):
        """A custom handler that adds external_id works end-to-end."""
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )

        def custom_handler(request):
            return sign_approval(
                request,
                approver_key,
                external_id="ops-team@company.com",
                ttl_seconds=60,
            )

        result = enforce_tool_call(
            "search", {"query": "test"}, bound_warrant,
            approval_policy=policy,
            approval_handler=custom_handler,
        )
        assert result.allowed

    def test_custom_async_handler(self, bound_warrant, approver_key):
        """A custom async handler works end-to-end."""
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )

        async def custom_async(request):
            return sign_approval(request, approver_key, external_id="async-ops")

        result = enforce_tool_call(
            "search", {"query": "test"}, bound_warrant,
            approval_policy=policy,
            approval_handler=custom_async,
        )
        assert result.allowed

    def test_custom_handler_conditional_deny(self, bound_warrant, approver_key):
        """A handler that conditionally denies based on args."""
        policy = ApprovalPolicy(
            require_approval("transfer"),
            trusted_approvers=[approver_key.public_key],
        )

        def amount_gate(request):
            if request.arguments.get("amount", 0) > 100_000:
                raise ApprovalDenied(request, reason="amount exceeds handler limit")
            return sign_approval(request, approver_key)

        result = enforce_tool_call(
            "transfer", {"amount": 50_000}, bound_warrant,
            approval_policy=policy,
            approval_handler=amount_gate,
        )
        assert result.allowed

        with pytest.raises(ApprovalDenied, match="handler limit"):
            enforce_tool_call(
                "transfer", {"amount": 200_000}, bound_warrant,
                approval_policy=policy,
                approval_handler=amount_gate,
            )


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:

    def test_approval_request_is_frozen(self):
        req = ApprovalRequest(
            tool="x", arguments={}, warrant_id="w", request_hash=b"\x00" * 32
        )
        with pytest.raises(AttributeError):
            req.tool = "hacked"

    def test_approval_rule_is_frozen(self):
        rule = ApprovalRule(tool="x")
        with pytest.raises(AttributeError):
            rule.tool = "hacked"

    def test_verification_error_not_approval_denied(self):
        """ApprovalVerificationError is a separate exception, not a subclass of ApprovalDenied."""
        assert not issubclass(ApprovalVerificationError, ApprovalDenied)

    def test_approval_timeout_is_approval_denied(self):
        assert issubclass(ApprovalTimeout, ApprovalDenied)

    def test_sign_approval_default_ttl(self, approver_key):
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        before = int(time.time())
        signed = sign_approval(req, approver_key)
        payload = signed.verify()
        assert payload.expires_at >= before + 300
        assert payload.expires_at <= before + 301


# =============================================================================
# TTL Propagation Tests
# =============================================================================


class TestTTLPropagation:
    """Verify that TTL is configurable at every level and propagates correctly."""

    def test_policy_default_ttl_propagates_to_request(self):
        """ApprovalPolicy.default_ttl flows into ApprovalRequest.suggested_ttl."""
        policy = ApprovalPolicy(
            require_approval("deploy"),
            default_ttl=86400,
        )
        req = policy.check("deploy", {}, "w", b"\x00" * 32)
        assert req is not None
        assert req.suggested_ttl == 86400

    def test_policy_no_default_ttl_leaves_none(self):
        """Without default_ttl, suggested_ttl is None."""
        policy = ApprovalPolicy(require_approval("deploy"))
        req = policy.check("deploy", {}, "w", b"\x00" * 32)
        assert req.suggested_ttl is None

    def test_sign_approval_uses_suggested_ttl(self, approver_key):
        """sign_approval() uses request.suggested_ttl when ttl_seconds is not given."""
        h = os.urandom(32)
        req = ApprovalRequest(
            tool="x", arguments={}, warrant_id="w",
            request_hash=h, suggested_ttl=7200,
        )
        before = int(time.time())
        signed = sign_approval(req, approver_key)
        payload = signed.verify()
        assert payload.expires_at >= before + 7200
        assert payload.expires_at <= before + 7201

    def test_sign_approval_explicit_overrides_suggested(self, approver_key):
        """Explicit ttl_seconds takes precedence over suggested_ttl."""
        h = os.urandom(32)
        req = ApprovalRequest(
            tool="x", arguments={}, warrant_id="w",
            request_hash=h, suggested_ttl=7200,
        )
        before = int(time.time())
        signed = sign_approval(req, approver_key, ttl_seconds=60)
        payload = signed.verify()
        assert payload.expires_at >= before + 60
        assert payload.expires_at <= before + 61

    def test_sign_approval_no_ttl_anywhere_uses_300(self, approver_key):
        """Without any TTL config, falls back to 300 seconds."""
        h = os.urandom(32)
        req = ApprovalRequest(tool="x", arguments={}, warrant_id="w", request_hash=h)
        before = int(time.time())
        signed = sign_approval(req, approver_key)
        payload = signed.verify()
        assert payload.expires_at >= before + 300
        assert payload.expires_at <= before + 301

    def test_policy_ttl_flows_through_handler(self, approver_key):
        """Policy TTL flows through auto_approve handler to the signed approval."""
        agent_key = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"deploy": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        bound = w.bind(agent_key)

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[approver_key.public_key],
            default_ttl=3600,
        )
        handler = auto_approve(approver_key=approver_key)

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approval_handler=handler,
        )
        assert result.allowed

    def test_handler_explicit_ttl_overrides_policy(self, approver_key):
        """Handler with explicit ttl_seconds overrides policy default_ttl."""
        h = os.urandom(32)
        req = ApprovalRequest(
            tool="x", arguments={}, warrant_id="w",
            request_hash=h, suggested_ttl=86400,
        )
        handler = auto_approve(approver_key=approver_key, ttl_seconds=60)
        signed = handler(req)
        before = int(time.time())
        payload = signed.verify()
        assert payload.expires_at <= before + 61

    def test_policy_default_ttl_validation(self):
        """default_ttl must be >= 1 if provided."""
        with pytest.raises(ValueError, match="default_ttl must be >= 1"):
            ApprovalPolicy(require_approval("x"), default_ttl=0)

        with pytest.raises(ValueError, match="default_ttl must be >= 1"):
            ApprovalPolicy(require_approval("x"), default_ttl=-1)

    def test_policy_default_ttl_property(self):
        """default_ttl is accessible via property."""
        policy = ApprovalPolicy(require_approval("x"), default_ttl=3600)
        assert policy.default_ttl == 3600

        policy2 = ApprovalPolicy(require_approval("x"))
        assert policy2.default_ttl is None


# =============================================================================
# Webhook Handler Tests
# =============================================================================


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


# =============================================================================
# auto_approve Production Warning
# =============================================================================


class TestAutoApproveWarning:

    def test_auto_approve_emits_production_warning(self, approver_key, bound_warrant):
        handler = auto_approve(approver_key=approver_key)
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        with patch("tenuo.approval.logger") as mock_logger:
            enforce_tool_call(
                "search", {"query": "test"}, bound_warrant,
                approval_policy=policy, approval_handler=handler,
            )
            mock_logger.warning.assert_called_once()
            warning_msg = mock_logger.warning.call_args[0][0]
            assert "DO NOT USE IN PRODUCTION" in warning_msg

    def test_auto_approve_warns_only_once(self, approver_key, bound_warrant):
        handler = auto_approve(approver_key=approver_key)
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        with patch("tenuo.approval.logger") as mock_logger:
            enforce_tool_call(
                "search", {"query": "a"}, bound_warrant,
                approval_policy=policy, approval_handler=handler,
            )
            enforce_tool_call(
                "search", {"query": "b"}, bound_warrant,
                approval_policy=policy, approval_handler=handler,
            )
            assert mock_logger.warning.call_count == 1


# =============================================================================
# Framework Integration: CrewAI
# =============================================================================


class TestCrewAIApproval:
    """Verify approval flows through CrewAI's GuardBuilder -> CrewAIGuard -> enforce_tool_call."""

    def test_crewai_builder_passes_approval_through(self, agent_key, approver_key):
        from tenuo.crewai import GuardBuilder
        from tenuo import Wildcard

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        assert guard._approval_policy is policy
        assert guard._approval_handler is handler

    def test_crewai_approval_required_raises(self, agent_key, approver_key):
        from tenuo.crewai import GuardBuilder
        from tenuo import Wildcard

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )

        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .build()
        )
        # No handler set -> ApprovalRequired should bubble up
        with pytest.raises(ApprovalRequired):
            guard._authorize("search", {"query": "test"})

    def test_crewai_approval_auto_approve_succeeds(self, agent_key, approver_key):
        from tenuo.crewai import GuardBuilder
        from tenuo import Wildcard

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        result = guard._authorize("search", {"query": "test"})
        assert result is None  # None means authorized

    def test_crewai_approval_denied_raises(self, agent_key, approver_key):
        from tenuo.crewai import GuardBuilder
        from tenuo import Wildcard

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_deny()

        guard = (
            GuardBuilder()
            .allow("search", query=Wildcard())
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        with pytest.raises(ApprovalDenied):
            guard._authorize("search", {"query": "test"})


# =============================================================================
# Framework Integration: AutoGen
# =============================================================================


class TestAutoGenApproval:
    """Verify approval flows through AutoGen's GuardBuilder -> _Guard -> enforce_tool_call."""

    def test_autogen_builder_passes_approval_through(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        assert guard._approval_policy is policy
        assert guard._approval_handler is handler

    def test_autogen_approval_required_raises(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .build()
        )
        with pytest.raises(ApprovalRequired):
            guard._authorize("search", {"query": "test"})

    def test_autogen_approval_auto_approve_succeeds(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_approve(approver_key=approver_key)

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        # Should not raise — auto_approve signs a valid approval
        guard._authorize("search", {"query": "test"})

    def test_autogen_no_rule_match_skips_approval(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}, "list_files": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )

        guard = (
            GuardBuilder()
            .allow("list_files")
            .allow("search")
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .build()
        )
        # list_files has no matching rule, should proceed without handler
        guard._authorize("list_files", {})

    def test_autogen_approval_denied_raises(self, agent_key, approver_key):
        from tenuo.autogen import GuardBuilder

        w = Warrant.issue(
            agent_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        policy = ApprovalPolicy(
            require_approval("search"),
            trusted_approvers=[approver_key.public_key],
        )
        handler = auto_deny()

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, agent_key)
            .approval_policy(policy)
            .on_approval(handler)
            .build()
        )
        with pytest.raises(ApprovalDenied):
            guard._authorize("search", {"query": "test"})


class TestApprovalsAsInput:
    """Tests for the spec §6 path: caller-provided SignedApproval objects."""

    def _setup(self):
        """Create common fixtures."""
        agent_key = SigningKey.generate()
        approver_key = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        bound = w.bind(agent_key)
        policy = ApprovalPolicy(
            require_approval("transfer"),
            trusted_approvers=[approver_key.public_key],
        )
        return agent_key, approver_key, bound, policy

    def test_matching_approval_succeeds(self):
        """A caller-provided SignedApproval that matches is accepted."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import sign_approval, ApprovalRequest
        from tenuo_core import py_compute_request_hash as _compute_hash

        agent_key, approver_key, bound, policy = self._setup()

        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {"to": "acct-1"}, agent_key.public_key)
        request = ApprovalRequest(
            tool="transfer", arguments={"to": "acct-1"},
            warrant_id=warrant_id, request_hash=request_hash,
        )
        signed = sign_approval(request, approver_key, external_id="cloud-user")

        result = enforce_tool_call(
            "transfer", {"to": "acct-1"}, bound,
            approval_policy=policy,
            approvals=[signed],
        )
        assert result.allowed

    def test_approvals_take_precedence_over_handler(self):
        """When both approvals and handler are provided, approvals win."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import sign_approval, ApprovalRequest, auto_deny
        from tenuo_core import py_compute_request_hash as _compute_hash

        agent_key, approver_key, bound, policy = self._setup()

        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {}, agent_key.public_key)
        request = ApprovalRequest(
            tool="transfer", arguments={},
            warrant_id=warrant_id, request_hash=request_hash,
        )
        signed = sign_approval(request, approver_key)

        result = enforce_tool_call(
            "transfer", {}, bound,
            approval_policy=policy,
            approval_handler=auto_deny(),
            approvals=[signed],
        )
        assert result.allowed

    def test_no_matching_approval_raises_verification_error(self):
        """If no provided approval matches the request hash, raises."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import sign_approval, ApprovalRequest, ApprovalVerificationError

        agent_key, approver_key, bound, policy = self._setup()

        wrong_request = ApprovalRequest(
            tool="transfer", arguments={},
            warrant_id="wrong-warrant", request_hash=b"\x00" * 32,
        )
        wrong_signed = sign_approval(wrong_request, approver_key)

        with pytest.raises(ApprovalVerificationError, match="request hash mismatch"):
            enforce_tool_call(
                "transfer", {}, bound,
                approval_policy=policy,
                approvals=[wrong_signed],
            )

    def test_untrusted_approver_key_rejected(self):
        """An approval signed by an untrusted key is rejected."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import sign_approval, ApprovalRequest, ApprovalVerificationError
        from tenuo_core import py_compute_request_hash as _compute_hash

        agent_key, approver_key, bound, policy = self._setup()
        untrusted_key = SigningKey.generate()

        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {}, agent_key.public_key)
        request = ApprovalRequest(
            tool="transfer", arguments={},
            warrant_id=warrant_id, request_hash=request_hash,
        )
        signed = sign_approval(request, untrusted_key)

        with pytest.raises(ApprovalVerificationError, match="approver not in trusted set"):
            enforce_tool_call(
                "transfer", {}, bound,
                approval_policy=policy,
                approvals=[signed],
            )

    def test_expired_approval_rejected(self):
        """An expired SignedApproval is rejected (beyond clock tolerance)."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalVerificationError
        from tenuo_core import (
            py_compute_request_hash as _compute_hash,
            ApprovalPayload, SignedApproval,
        )

        agent_key, approver_key, bound, policy = self._setup()

        warrant_id = bound.id or ""
        request_hash = _compute_hash(warrant_id, "transfer", {}, agent_key.public_key)

        now = int(time.time())
        payload = ApprovalPayload(
            request_hash=request_hash,
            nonce=os.urandom(16),
            external_id="test",
            approved_at=now - 600,
            expires_at=now - 120,  # Well beyond 30s clock tolerance
        )
        signed = SignedApproval.create(payload, approver_key)

        with pytest.raises(ApprovalVerificationError, match="expired"):
            enforce_tool_call(
                "transfer", {}, bound,
                approval_policy=policy,
                approvals=[signed],
            )

    def test_no_rule_match_skips_check(self):
        """When no rule matches, approvals are ignored and call succeeds."""
        from tenuo._enforcement import enforce_tool_call

        _, _, _, policy = self._setup()

        other_key = SigningKey.generate()
        w = Warrant.issue(
            other_key, capabilities={"search": {}},
            ttl_seconds=3600, holder=other_key.public_key,
        )
        bound = w.bind(other_key)

        result = enforce_tool_call(
            "search", {"query": "test"}, bound,
            approval_policy=policy,
            approvals=[],
        )
        assert result.allowed

    def test_empty_approvals_falls_through_to_handler(self):
        """Empty approvals list falls through to handler."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import auto_approve

        agent_key, approver_key, bound, policy = self._setup()

        result = enforce_tool_call(
            "transfer", {}, bound,
            approval_policy=policy,
            approval_handler=auto_approve(approver_key=approver_key),
            approvals=[],
        )
        assert result.allowed

    def test_empty_approvals_no_handler_raises_required(self):
        """Empty approvals + no handler raises ApprovalRequired."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalRequired

        _, _, bound, policy = self._setup()

        with pytest.raises(ApprovalRequired):
            enforce_tool_call(
                "transfer", {}, bound,
                approval_policy=policy,
                approvals=[],
            )


# =============================================================================
# M-of-N Multi-sig Tests
# =============================================================================


class TestMofN:
    """Comprehensive m-of-n approval tests through the full enforcement path."""

    @staticmethod
    def _make_bound_warrant():
        agent_key = SigningKey.generate()
        w = Warrant.issue(
            agent_key,
            capabilities={"deploy": {}, "transfer": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )
        return agent_key, w.bind(agent_key)

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
        """2-of-3 multi-sig via caller-provided SignedApprovals."""
        agent_key, bound = self._make_bound_warrant()
        k1, k2, k3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k1.public_key, k2.public_key, k3.public_key],
            threshold=2,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)

        a1 = self._sign_for_request(k1, rh)
        a2 = self._sign_for_request(k2, rh)

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approvals=[a1, a2],
        )
        assert result.allowed

    def test_three_of_five_via_handler(self):
        """3-of-5 multi-sig via handler returning list of SignedApprovals."""
        agent_key, bound = self._make_bound_warrant()
        keys = [SigningKey.generate() for _ in range(5)]

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k.public_key for k in keys],
            threshold=3,
        )

        def multi_handler(request):
            return [
                sign_approval(request, keys[0]),
                sign_approval(request, keys[2]),
                sign_approval(request, keys[4]),
            ]

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approval_handler=multi_handler,
        )
        assert result.allowed

    def test_two_of_three_insufficient(self):
        """2-of-3 with only 1 approval → InsufficientApprovals."""
        agent_key, bound = self._make_bound_warrant()
        k1, k2, k3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k1.public_key, k2.public_key, k3.public_key],
            threshold=2,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)

        a1 = self._sign_for_request(k1, rh)

        with pytest.raises(ApprovalVerificationError, match="Insufficient approvals"):
            enforce_tool_call(
                "deploy", {}, bound,
                approval_policy=policy,
                approvals=[a1],
            )

    def test_two_of_three_with_mixed_valid_and_invalid(self):
        """2-of-3: 2 valid + 1 expired → succeeds (expired silently skipped)."""
        agent_key, bound = self._make_bound_warrant()
        k1, k2, k3 = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k1.public_key, k2.public_key, k3.public_key],
            threshold=2,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)

        valid1 = self._sign_for_request(k1, rh)
        valid2 = self._sign_for_request(k3, rh)

        # Expired approval from k2
        now = int(time.time())
        expired_payload = ApprovalPayload(
            request_hash=rh,
            nonce=os.urandom(16),
            external_id="expired-approver",
            approved_at=now - 600,
            expires_at=now - 120,
        )
        expired = SignedApproval.create(expired_payload, k2)

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approvals=[valid1, expired, valid2],
        )
        assert result.allowed

    def test_duplicate_approver_counted_once(self):
        """Same key signing twice only counts once toward threshold."""
        agent_key, bound = self._make_bound_warrant()
        k1, k2 = SigningKey.generate(), SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k1.public_key, k2.public_key],
            threshold=2,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)

        # k1 signs twice
        dup1 = self._sign_for_request(k1, rh)
        dup2 = self._sign_for_request(k1, rh)

        with pytest.raises(ApprovalVerificationError, match="Insufficient approvals"):
            enforce_tool_call(
                "deploy", {}, bound,
                approval_policy=policy,
                approvals=[dup1, dup2],
            )

    def test_threshold_validation_in_policy(self):
        """ApprovalPolicy rejects threshold > len(trusted_approvers)."""
        k1 = SigningKey.generate()
        with pytest.raises(ValueError, match="threshold.*exceeds"):
            ApprovalPolicy(
                require_approval("x"),
                trusted_approvers=[k1.public_key],
                threshold=2,
            )

    def test_threshold_must_be_positive(self):
        """ApprovalPolicy rejects threshold < 1."""
        with pytest.raises(ValueError, match="threshold must be >= 1"):
            ApprovalPolicy(require_approval("x"), threshold=0)

    def test_three_of_five_all_invalid_shows_rejection_detail(self):
        """3-of-5 with all invalid → error includes rejection summary."""
        agent_key, bound = self._make_bound_warrant()
        keys = [SigningKey.generate() for _ in range(5)]
        outsider = SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k.public_key for k in keys],
            threshold=3,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)
        now = int(time.time())

        # 1 expired
        expired_payload = ApprovalPayload(
            request_hash=rh, nonce=os.urandom(16),
            external_id="expired", approved_at=now - 600, expires_at=now - 120,
        )
        expired = SignedApproval.create(expired_payload, keys[0])

        # 1 untrusted
        untrusted = self._sign_for_request(outsider, rh)

        # 1 wrong hash
        wrong_hash = self._sign_for_request(keys[1], os.urandom(32))

        with pytest.raises(ApprovalVerificationError, match="Insufficient approvals"):
            enforce_tool_call(
                "deploy", {}, bound,
                approval_policy=policy,
                approvals=[expired, untrusted, wrong_hash],
            )

    def test_m_of_n_with_all_five_approvals_early_exits(self):
        """3-of-5 with all 5 valid → succeeds after checking first 3."""
        agent_key, bound = self._make_bound_warrant()
        keys = [SigningKey.generate() for _ in range(5)]

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k.public_key for k in keys],
            threshold=3,
        )

        warrant_id = bound.id or ""
        rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)

        all_approvals = [self._sign_for_request(k, rh) for k in keys]

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approvals=all_approvals,
        )
        assert result.allowed

    def test_one_of_one_is_default_threshold(self):
        """Default threshold=1 works for single approver."""
        agent_key, bound = self._make_bound_warrant()
        k = SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            trusted_approvers=[k.public_key],
        )
        assert policy.threshold == 1

        result = enforce_tool_call(
            "deploy", {}, bound,
            approval_policy=policy,
            approval_handler=auto_approve(approver_key=k),
        )
        assert result.allowed

    def test_m_of_n_cross_tool_replay_blocked(self):
        """Approval for tool A cannot satisfy threshold for tool B."""
        agent_key, bound = self._make_bound_warrant()
        k1, k2 = SigningKey.generate(), SigningKey.generate()

        policy = ApprovalPolicy(
            require_approval("deploy"),
            require_approval("transfer"),
            trusted_approvers=[k1.public_key, k2.public_key],
            threshold=2,
        )

        warrant_id = bound.id or ""
        deploy_rh = compute_request_hash(warrant_id, "deploy", {}, agent_key.public_key)
        transfer_rh = compute_request_hash(warrant_id, "transfer", {}, agent_key.public_key)

        # Sign for "deploy"
        a1_deploy = self._sign_for_request(k1, deploy_rh)
        a2_deploy = self._sign_for_request(k2, deploy_rh)

        # Try to use deploy approvals for transfer → fails (hash mismatch)
        with pytest.raises(ApprovalVerificationError):
            enforce_tool_call(
                "transfer", {}, bound,
                approval_policy=policy,
                approvals=[a1_deploy, a2_deploy],
            )

        # Correct approvals for transfer → succeeds
        a1_transfer = self._sign_for_request(k1, transfer_rh)
        a2_transfer = self._sign_for_request(k2, transfer_rh)

        result = enforce_tool_call(
            "transfer", {}, bound,
            approval_policy=policy,
            approvals=[a1_transfer, a2_transfer],
        )
        assert result.allowed
