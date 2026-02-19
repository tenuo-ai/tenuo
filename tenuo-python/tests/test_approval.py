"""
Test suite for tenuo.approval module - human-in-the-loop authorization.

Tests cover:
- ApprovalRule matching (always, conditional, predicate failures)
- ApprovalPolicy checking
- Built-in handlers (auto_approve, auto_deny, cli_prompt, webhook)
- Integration with enforce_tool_call()
- Exception hierarchy (ApprovalRequired, ApprovalDenied, ApprovalTimeout)
- Async handler support
- Handler exceptions (fail-closed behavior)
- Constraint violation priority over approval
"""

import pytest
from unittest.mock import patch

from tenuo import SigningKey, Warrant, Subpath
from tenuo.approval import (
    ApprovalPolicy,
    ApprovalRule,
    ApprovalRequest,
    ApprovalResponse,
    ApprovalRequired,
    ApprovalDenied,
    ApprovalTimeout,
    require_approval,
    auto_approve,
    auto_deny,
    cli_prompt,
    webhook,
)
from tenuo._enforcement import enforce_tool_call


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def signing_key():
    return SigningKey.generate()


@pytest.fixture
def bound_warrant(signing_key):
    w = (
        Warrant.mint_builder()
        .capability("search")
        .capability("transfer")
        .capability("delete_user")
        .holder(signing_key.public_key)
        .ttl(3600)
        .mint(signing_key)
    )
    return w.bind(signing_key)


@pytest.fixture
def high_value_policy():
    return ApprovalPolicy(
        require_approval("transfer", when=lambda a: a.get("amount", 0) > 10_000),
        require_approval("delete_user"),
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
        assert policy.check("anything", {}) is None

    def test_matching_rule_returns_request(self, high_value_policy):
        req = high_value_policy.check("delete_user", {"id": "42"})
        assert req is not None
        assert req.tool == "delete_user"
        assert req.arguments == {"id": "42"}

    def test_conditional_rule_below_threshold(self, high_value_policy):
        assert high_value_policy.check("transfer", {"amount": 5_000}) is None

    def test_conditional_rule_above_threshold(self, high_value_policy):
        req = high_value_policy.check("transfer", {"amount": 50_000})
        assert req is not None
        assert req.tool == "transfer"

    def test_unrelated_tool_not_matched(self, high_value_policy):
        assert high_value_policy.check("search", {"query": "test"}) is None

    def test_warrant_id_passed_through(self, high_value_policy):
        req = high_value_policy.check("delete_user", {}, warrant_id="wrt_123")
        assert req.warrant_id == "wrt_123"

    def test_first_matching_rule_wins(self):
        policy = ApprovalPolicy(
            require_approval("transfer", description="rule-1"),
            require_approval("transfer", description="rule-2"),
        )
        req = policy.check("transfer", {})
        assert req.rule.description == "rule-1"

    def test_len(self, high_value_policy):
        assert len(high_value_policy) == 2

    def test_rules_returns_copy(self, high_value_policy):
        rules = high_value_policy.rules
        rules.clear()
        assert len(high_value_policy) == 2


# =============================================================================
# Handler Tests
# =============================================================================


class TestAutoApprove:

    def test_approves(self):
        handler = auto_approve()
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50_000})
        resp = handler(req)
        assert resp.approved
        assert resp.approver == "auto"

    def test_returns_approval_response(self):
        handler = auto_approve()
        req = ApprovalRequest(tool="x", arguments={})
        assert isinstance(handler(req), ApprovalResponse)


class TestAutoDeny:

    def test_denies(self):
        handler = auto_deny()
        req = ApprovalRequest(tool="transfer", arguments={})
        resp = handler(req)
        assert not resp.approved
        assert "auto-denied" in resp.reason

    def test_custom_reason(self):
        handler = auto_deny(reason="policy forbids this")
        req = ApprovalRequest(tool="x", arguments={})
        resp = handler(req)
        assert resp.reason == "policy forbids this"


class TestCliPrompt:

    def test_approve_y(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50_000})
        with patch("builtins.input", return_value="y"):
            resp = handler(req)
        assert resp.approved

    def test_approve_yes(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={})
        with patch("builtins.input", return_value="yes"):
            resp = handler(req)
        assert resp.approved

    def test_deny_n(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={})
        with patch("builtins.input", return_value="n"):
            resp = handler(req)
        assert not resp.approved

    def test_deny_empty(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={})
        with patch("builtins.input", return_value=""):
            resp = handler(req)
        assert not resp.approved

    def test_deny_on_eof(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={})
        with patch("builtins.input", side_effect=EOFError):
            resp = handler(req)
        assert not resp.approved

    def test_deny_on_keyboard_interrupt(self):
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={})
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            resp = handler(req)
        assert not resp.approved

    def test_show_args_false_hides_arguments(self, capsys):
        handler = cli_prompt(show_args=False)
        req = ApprovalRequest(
            tool="transfer",
            arguments={"amount": 50_000, "to": "secret"},
        )
        with patch("builtins.input", return_value="y"):
            handler(req)
        captured = capsys.readouterr()
        assert "secret" not in captured.err

    def test_description_shown(self, capsys):
        rule = require_approval("transfer", description="High-value transfer")
        handler = cli_prompt()
        req = ApprovalRequest(tool="transfer", arguments={}, rule=rule)
        with patch("builtins.input", return_value="n"):
            handler(req)
        captured = capsys.readouterr()
        assert "High-value transfer" in captured.err


# =============================================================================
# Exception Tests
# =============================================================================


class TestExceptions:

    def test_approval_required_message(self):
        req = ApprovalRequest(tool="transfer", arguments={}, warrant_id="wrt_123")
        exc = ApprovalRequired(req)
        assert "transfer" in str(exc)
        assert "wrt_123" in str(exc)
        assert exc.request is req

    def test_approval_denied_message(self):
        req = ApprovalRequest(tool="transfer", arguments={})
        resp = ApprovalResponse(approved=False, reason="too risky")
        exc = ApprovalDenied(req, resp)
        assert "too risky" in str(exc)
        assert exc.request is req
        assert exc.response is resp

    def test_approval_timeout(self):
        req = ApprovalRequest(tool="transfer", arguments={})
        exc = ApprovalTimeout(req, timeout_seconds=30.0)
        assert "timed out" in str(exc)
        assert exc.timeout_seconds == 30.0
        assert isinstance(exc, ApprovalDenied)


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

    def test_policy_match_auto_approve(self, bound_warrant, high_value_policy):
        result = enforce_tool_call(
            "transfer", {"amount": 50_000}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_approve(),
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

    def test_warrant_denial_takes_priority(self, bound_warrant, high_value_policy):
        """If the warrant denies the tool, approval policy is never checked."""
        result = enforce_tool_call(
            "forbidden_tool", {}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=auto_approve(),
        )
        assert not result.allowed

    def test_cli_prompt_integration(self, bound_warrant, high_value_policy):
        handler = cli_prompt()
        with patch("builtins.input", return_value="y"):
            result = enforce_tool_call(
                "delete_user", {"id": "42"}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=handler,
            )
        assert result.allowed

    def test_cli_prompt_deny_integration(self, bound_warrant, high_value_policy):
        handler = cli_prompt()
        with patch("builtins.input", return_value="n"):
            with pytest.raises(ApprovalDenied):
                enforce_tool_call(
                    "delete_user", {"id": "42"}, bound_warrant,
                    approval_policy=high_value_policy,
                    approval_handler=handler,
                )

    def test_constraint_violation_skips_approval(self, signing_key):
        """Constraint failure short-circuits before the approval check runs."""
        w = (
            Warrant.mint_builder()
            .capability("read_file", path=Subpath("/allowed"))
            .holder(signing_key.public_key)
            .ttl(3600)
            .mint(signing_key)
        )
        bound = w.bind(signing_key)

        never_called = auto_approve()
        policy = ApprovalPolicy(require_approval("read_file"))

        result = enforce_tool_call(
            "read_file", {"path": "/etc/shadow"}, bound,
            approval_policy=policy,
            approval_handler=never_called,
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
# Async Handler Tests
# =============================================================================


class TestAsyncHandler:

    def test_async_handler_approve(self, bound_warrant, high_value_policy):
        async def async_approve(req):
            return ApprovalResponse(approved=True, approver="async-test")

        result = enforce_tool_call(
            "transfer", {"amount": 50_000}, bound_warrant,
            approval_policy=high_value_policy,
            approval_handler=async_approve,
        )
        assert result.allowed

    def test_async_handler_deny(self, bound_warrant, high_value_policy):
        async def async_deny(req):
            return ApprovalResponse(approved=False, reason="async denied")

        with pytest.raises(ApprovalDenied, match="async denied"):
            enforce_tool_call(
                "transfer", {"amount": 50_000}, bound_warrant,
                approval_policy=high_value_policy,
                approval_handler=async_deny,
            )


# =============================================================================
# Webhook Handler Tests
# =============================================================================


class TestWebhook:

    def test_webhook_raises_not_implemented(self):
        handler = webhook("https://example.com/approve")
        req = ApprovalRequest(tool="transfer", arguments={"amount": 50_000})
        with pytest.raises(NotImplementedError, match="placeholder"):
            handler(req)
