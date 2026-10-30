"""Observe mode: the full decision runs, would-be denials are logged, the call proceeds."""

import asyncio
import logging
import time
from typing import Any, List

import pytest

from tenuo import Exact, Range, SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call, enforce_tool_call_async, verify_inbound_call
from tenuo.config import (
    EnforcementMode,
    auto_configure,
    configure,
    get_config,
    is_audit_mode,
    is_observe_mode,
    reset_config,
    should_block_violation,
)
from tenuo.exceptions import ConfigurationError

ISSUER, AGENT, APPROVER = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
ROOTS = [ISSUER.public_key]
WARRANT = (
    Warrant.mint_builder()
    .capability("issue_payout", payee=Exact("ACCT-CLAIMANT"), amount=Range(0, 5000))
    .holder(AGENT.public_key)
    .ttl(3600)
    .mint(ISSUER)
)
BOUND = WARRANT.bind(AGENT, trusted_roots=ROOTS)
BAD_ARGS = {"payee": "ACCT-ATTACKER", "amount": 2500}


@pytest.fixture(autouse=True)
def _reset_config():
    reset_config()
    yield
    reset_config()


def _observe() -> None:
    configure(trusted_roots=ROOTS, mode="observe")


def _observe_records(caplog) -> List[logging.LogRecord]:
    return [r for r in caplog.records if r.getMessage().startswith("OBSERVE: would deny")]


# -- mode parsing -------------------------------------------------------------


def test_aliases_are_observe():
    assert EnforcementMode.AUDIT is EnforcementMode.OBSERVE
    assert EnforcementMode.PERMISSIVE is EnforcementMode.OBSERVE
    assert EnforcementMode("audit") is EnforcementMode.OBSERVE
    assert EnforcementMode("permissive") is EnforcementMode.OBSERVE
    assert EnforcementMode("observe").value == "observe"


@pytest.mark.parametrize("mode", ["observe", "audit", "permissive"])
def test_configure_mode_aliases(mode):
    configure(trusted_roots=ROOTS, mode=mode)
    assert get_config().mode is EnforcementMode.OBSERVE
    assert is_observe_mode() and is_audit_mode()
    assert not should_block_violation()


def test_configure_rejects_unknown_mode():
    with pytest.raises(ConfigurationError):
        configure(trusted_roots=ROOTS, mode="lenient")  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["observe", "audit", "PERMISSIVE"])
def test_env_mode_aliases(monkeypatch, value):
    monkeypatch.setenv("OBSTEST_TENUO_MODE", value)
    monkeypatch.setenv("OBSTEST_TENUO_DEV_MODE", "1")
    assert auto_configure(prefix="OBSTEST_TENUO_")
    assert get_config().mode is EnforcementMode.OBSERVE


def test_env_mode_rejects_unknown(monkeypatch):
    monkeypatch.setenv("OBSTEST_TENUO_MODE", "lenient")
    with pytest.raises(ConfigurationError):
        auto_configure(prefix="OBSTEST_TENUO_")


# -- sign path ----------------------------------------------------------------


def test_enforce_mode_still_denies(caplog):
    configure(trusted_roots=ROOTS)
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = enforce_tool_call("issue_payout", BAD_ARGS, BOUND, trusted_roots=ROOTS)
    assert not result.allowed
    assert not result.observed
    assert _observe_records(caplog) == []


def test_observe_allows_constraint_violation_and_logs(caplog):
    _observe()
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = enforce_tool_call("issue_payout", BAD_ARGS, BOUND, trusted_roots=ROOTS)
    assert result.allowed and result.observed
    assert result.error_type == "constraint_violation"
    assert result.constraint_violated == "payee"
    assert result.denial_reason
    result.raise_if_denied()  # allowed: must not raise

    [rec] = _observe_records(caplog)
    assert rec.levelno == logging.WARNING
    assert rec.getMessage() == "OBSERVE: would deny issue_payout (constraint_violation)"
    assert rec.tool == "issue_payout"
    assert rec.args_keys == ["payee", "amount"]
    assert rec.arg_types == {"payee": "str", "amount": "int"}
    assert rec.error_type == "constraint_violation"
    assert rec.constraint_violated == "payee"
    assert not hasattr(rec, "denial_reason")
    assert "ACCT-ATTACKER" not in rec.getMessage()
    assert rec.warrant_id == result.warrant_id


def test_observe_allows_tool_not_in_warrant(caplog):
    _observe()
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = enforce_tool_call("delete_everything", {"path": "/"}, BOUND, trusted_roots=ROOTS)
    assert result.allowed and result.observed
    assert result.error_type == "tool_not_allowed"
    [rec] = _observe_records(caplog)
    assert rec.tool == "delete_everything"
    assert rec.error_type == "tool_not_allowed"


def test_observe_async_path():
    _observe()
    result = asyncio.run(enforce_tool_call_async("issue_payout", BAD_ARGS, BOUND, trusted_roots=ROOTS))
    assert result.allowed and result.observed
    assert result.error_type == "constraint_violation"


def test_observe_does_not_touch_real_allows():
    _observe()
    result = enforce_tool_call("issue_payout", {"payee": "ACCT-CLAIMANT", "amount": 10}, BOUND, trusted_roots=ROOTS)
    assert result.allowed and not result.observed
    assert result.error_type is None


def test_guard_decorator_observes_missing_warrant(caplog):
    from tenuo.decorators import guard

    _observe()

    @guard(tool="unscoped_tool")
    def unscoped_tool():
        return "executed"

    with caplog.at_level(logging.WARNING, logger="tenuo"):
        assert unscoped_tool() == "executed"
    [record] = _observe_records(caplog)
    assert record.tool == "unscoped_tool"
    assert record.error_type == "missing_warrant"


def test_guard_decorator_observes_expired_warrant(caplog):
    from tenuo.decorators import guard

    expired = (
        Warrant.mint_builder()
        .capability("expired_tool", value=Exact("ok"))
        .holder(AGENT.public_key)
        .ttl(0)
        .mint(ISSUER)
    )
    _observe()

    @guard(expired, tool="expired_tool", keypair=AGENT, trusted_roots=ROOTS)
    def expired_tool(value):
        return value

    with caplog.at_level(logging.WARNING, logger="tenuo"):
        assert expired_tool("ok") == "ok"
    [record] = _observe_records(caplog)
    assert record.tool == "expired_tool"
    assert record.error_type == "expired"


def test_guard_decorator_collects_expired_warrant_denial_receipt():
    from tenuo import HolderIdentity, Runtime
    from tenuo.decorators import guard

    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    expired = (
        Warrant.mint_builder()
        .capability("expired_tool", value=Exact("ok"))
        .holder(holder.public_key)
        .ttl(0)
        .mint(root)
    )
    runtime = Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
    )
    configure(trusted_roots=[root.public_key], mode="observe")

    @guard(
        expired,
        tool="expired_tool",
        keypair=holder.signing_key,
        trusted_roots=[root.public_key],
    )
    def expired_tool(value):
        return value

    with runtime.bind():
        assert expired_tool("ok") == "ok"

    assert len(runtime.peek_receipts()) == 1


def test_receipt_collected_as_denial(monkeypatch):
    """The runtime receipt sees the denial, not the observe-mode allow."""
    import tenuo.receipts as receipts

    seen: List[Any] = []
    monkeypatch.setattr(receipts, "collect_enforcement_receipt", lambda r, c=None, runtime=None: seen.append(r.allowed))
    _observe()
    result = enforce_tool_call("issue_payout", BAD_ARGS, BOUND, trusted_roots=ROOTS)
    assert seen == [False]
    assert result.allowed


def test_mcp_conversion_preserves_observed_denial_metadata():
    from tenuo._enforcement import EnforcementResult
    from tenuo.mcp.server import _mcp_result_from_enforcement

    enforcement = EnforcementResult(
        allowed=True,
        observed=True,
        tool="issue_payout",
        arguments=BAD_ARGS,
        denial_reason="denied",
        error_type="constraint_violation",
        constraint_violated="payee",
        warrant_id="w1",
        verified_pop=b"proof",
        pop_auth_args=BAD_ARGS,
    )
    result = _mcp_result_from_enforcement(
        enforcement,
        tool_name="issue_payout",
        clean_arguments=BAD_ARGS,
        constraints=BAD_ARGS,
        warrant_id="w1",
    )
    assert result.allowed and result.observed
    assert result.error_type == "constraint_violation"
    assert result.constraint_violated == "payee"
    assert result.verified_pop == b"proof"
    assert result.pop_auth_args == BAD_ARGS


# -- verify path --------------------------------------------------------------


def _inbound(args, pop):
    from tenuo_core import Authorizer

    return verify_inbound_call(
        tool_name="issue_payout",
        tool_args=args,
        warrant=WARRANT,
        pop_signature=pop,
        authorizer=Authorizer(trusted_roots=ROOTS),
    )


def test_verify_path_enforce_denies():
    configure(trusted_roots=ROOTS)
    pop = bytes(WARRANT.sign(AGENT, "issue_payout", BAD_ARGS, int(time.time())))
    result = _inbound(BAD_ARGS, pop)
    assert not result.allowed and not result.observed


def test_verify_path_observed(caplog):
    _observe()
    pop = bytes(WARRANT.sign(AGENT, "issue_payout", BAD_ARGS, int(time.time())))
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = _inbound(BAD_ARGS, pop)
    assert result.allowed and result.observed
    assert result.error_type == "constraint_violation"
    assert len(_observe_records(caplog)) == 1


def test_verify_path_integrity_failure_observed_with_error_type():
    _observe()
    forged = bytes(WARRANT.sign(SigningKey.generate(), "issue_payout", BAD_ARGS, int(time.time())))
    result = _inbound(BAD_ARGS, forged)
    assert result.allowed and result.observed
    assert result.error_type == "invalid_pop"


# -- approval gates -----------------------------------------------------------


GATED = (
    Warrant.mint_builder()
    .capability("issue_payout", payee=Exact("ACCT-CLAIMANT"), amount=Range(0, 5000))
    .approval_gates({"issue_payout": {"amount": {"exempt": Range(0, 1000)}}})
    .required_approvers([APPROVER.public_key])
    .min_approvals(1)
    .holder(AGENT.public_key)
    .ttl(3600)
    .mint(ISSUER)
)
GATED_ARGS = {"payee": "ACCT-CLAIMANT", "amount": 2500}


def _never_called(request: Any) -> Any:
    raise AssertionError("approval handler must not be called in observe mode")


def test_observe_approval_gate_records_would_require_approval(caplog):
    _observe()
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = enforce_tool_call(
            "issue_payout",
            GATED_ARGS,
            GATED.bind(AGENT, trusted_roots=ROOTS),
            trusted_roots=ROOTS,
            approval_handler=_never_called,
        )
    assert result.allowed and result.observed
    assert result.error_type == "approval_required"
    [rec] = _observe_records(caplog)
    assert rec.error_type == "approval_required"


def test_observe_approval_gate_async():
    _observe()
    result = asyncio.run(
        enforce_tool_call_async(
            "issue_payout",
            GATED_ARGS,
            GATED.bind(AGENT, trusted_roots=ROOTS),
            trusted_roots=ROOTS,
            approval_handler=_never_called,
        )
    )
    assert result.allowed and result.observed
    assert result.error_type == "approval_required"


def test_observe_approval_gate_reports_invalid_pop_before_missing_approval():
    _observe()
    forged = bytes(
        GATED.sign(SigningKey.generate(), "issue_payout", GATED_ARGS, int(time.time()))
    )
    from tenuo_core import Authorizer

    result = verify_inbound_call(
        tool_name="issue_payout",
        tool_args=GATED_ARGS,
        warrant=GATED,
        pop_signature=forged,
        authorizer=Authorizer(trusted_roots=ROOTS),
    )
    assert result.allowed and result.observed
    assert result.error_type == "invalid_pop"


def test_observe_invalid_presented_approval_is_recorded_not_raised():
    from tenuo.approval import ApprovalRequest, sign_approval
    from tenuo_core import py_compute_request_hash

    _observe()
    rogue = SigningKey.generate()
    request_hash = py_compute_request_hash(
        GATED.id,
        "issue_payout",
        GATED_ARGS,
        AGENT.public_key,
    )
    request = ApprovalRequest.for_warrant_gate(
        "issue_payout",
        GATED_ARGS,
        GATED,
        request_hash,
        holder_key=AGENT.public_key,
    )
    invalid = sign_approval(request, rogue)
    result = enforce_tool_call(
        "issue_payout",
        GATED_ARGS,
        GATED.bind(AGENT, trusted_roots=ROOTS),
        trusted_roots=ROOTS,
        approvals=[invalid],
    )
    assert result.allowed and result.observed
    assert result.error_type == "approval_verification_failed"


def test_enforce_approval_gate_still_asks():
    from tenuo.approval import sign_approval

    configure(trusted_roots=ROOTS)
    asked: List[Any] = []

    def handler(request: Any) -> Any:
        asked.append(request)
        return sign_approval(request, APPROVER)

    result = enforce_tool_call(
        "issue_payout",
        GATED_ARGS,
        GATED.bind(AGENT, trusted_roots=ROOTS),
        trusted_roots=ROOTS,
        approval_handler=handler,
    )
    assert result.allowed and not result.observed
    assert len(asked) == 1
