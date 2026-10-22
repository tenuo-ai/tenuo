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
    assert rec.getMessage().startswith("OBSERVE: would deny issue_payout: ")
    assert rec.tool == "issue_payout"
    assert rec.args_keys == ["payee", "amount"]
    assert rec.arg_types == {"payee": "str", "amount": "int"}
    assert rec.error_type == "constraint_violation"
    assert rec.constraint_violated == "payee"
    assert not hasattr(rec, "denial_reason")  # free text can quote argument values
    assert rec.getMessage() == "OBSERVE: would deny issue_payout: constraint_violation on 'payee'"
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


def test_receipt_collected_as_denial(monkeypatch):
    """The runtime receipt sees the denial, not the observe-mode allow."""
    import tenuo.receipts as receipts

    seen: List[Any] = []
    monkeypatch.setattr(receipts, "collect_enforcement_receipt", lambda r, c=None, runtime=None: seen.append(r.allowed))
    _observe()
    result = enforce_tool_call("issue_payout", BAD_ARGS, BOUND, trusted_roots=ROOTS)
    assert seen == [False]
    assert result.allowed


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


def test_guard_runs_an_expired_warrant_in_observe_and_refuses_it_in_enforce(caplog):
    """@guard checks expiry before the shared path; observe mode must let the call run there too."""
    from tenuo import guard
    from tenuo.exceptions import ExpiredError

    expired = (
        Warrant.mint_builder()
        .capability("issue_payout", payee=Exact("ACCT-CLAIMANT"), amount=Range(0, 5000))
        .holder(AGENT.public_key)
        .ttl(1)
        .mint(ISSUER)
    )
    time.sleep(1.2)
    calls = []

    @guard(expired, tool="issue_payout", keypair=AGENT)
    def issue_payout(payee: str, amount: int) -> str:
        calls.append(payee)
        return "paid"

    configure(trusted_roots=ROOTS)
    with pytest.raises(ExpiredError):
        issue_payout(payee="ACCT-CLAIMANT", amount=100)
    reset_config()
    _observe()
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        assert issue_payout(payee="ACCT-CLAIMANT", amount=100) == "paid"
    assert calls == ["ACCT-CLAIMANT"]
    assert _observe_records(caplog), "the expiry is recorded as an observed denial"


def test_observe_gate_still_verifies_the_warrant_before_recording_approval_required():
    """A gated call with an untrusted issuer is recorded as that, not as approval_required."""
    _observe()
    stranger = SigningKey.generate()
    untrusted = (
        Warrant.mint_builder()
        .capability("issue_payout", payee=Exact("ACCT-CLAIMANT"), amount=Range(0, 5000))
        .approval_gates({"issue_payout": {"amount": {"exempt": Range(0, 1000)}}})
        .required_approvers([APPROVER.public_key])
        .min_approvals(1)
        .holder(AGENT.public_key)
        .ttl(3600)
        .mint(stranger)
    )
    for call in (enforce_tool_call, enforce_tool_call_async):
        result = call("issue_payout", GATED_ARGS, untrusted.bind(AGENT, trusted_roots=ROOTS),
                      trusted_roots=ROOTS, approval_handler=_never_called)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
        assert result.allowed and result.observed
        assert result.error_type != "approval_required", result.error_type


def test_observe_records_an_invalid_approval_instead_of_aborting(caplog):
    from tenuo.approval import sign_approval

    seen: List[Any] = []

    def wrong_signer(request: Any) -> Any:
        seen.append(request)
        return sign_approval(request, SigningKey.generate())

    configure(trusted_roots=ROOTS)
    bound = GATED.bind(AGENT, trusted_roots=ROOTS)
    # Collect a real but wrongly signed approval in enforce mode, then present it while observing.
    try:
        enforce_tool_call("issue_payout", GATED_ARGS, bound, trusted_roots=ROOTS, approval_handler=wrong_signer)
    except Exception:
        pass
    assert seen, "the handler should have produced an approval to present"
    bad = sign_approval(seen[0], SigningKey.generate())
    _observe()
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        result = enforce_tool_call("issue_payout", GATED_ARGS, bound, trusted_roots=ROOTS, approvals=[bad])
    assert result.allowed and result.observed
    assert result.error_type in ("invalid_approval", "approval_expired", "insufficient_approvals")


def test_observe_logs_one_warning_for_an_integrity_failure(caplog):
    _observe()
    forged = bytes(WARRANT.sign(SigningKey.generate(), "issue_payout", BAD_ARGS, int(time.time())))
    with caplog.at_level(logging.WARNING, logger="tenuo"):
        _inbound(BAD_ARGS, forged)
    call_warnings = [r for r in caplog.records if r.levelno >= logging.WARNING and r.name != "tenuo.config"]
    assert [r.getMessage() for r in call_warnings] == ["OBSERVE: would deny issue_payout: invalid_pop"]


def test_observe_records_too_many_approvals_instead_of_aborting():
    from tenuo.approval import sign_approval

    seen: List[Any] = []
    configure(trusted_roots=ROOTS)
    bound = GATED.bind(AGENT, trusted_roots=ROOTS)
    try:
        enforce_tool_call("issue_payout", GATED_ARGS, bound, trusted_roots=ROOTS,
                          approval_handler=lambda r: seen.append(r) or sign_approval(r, APPROVER))
    except Exception:
        pass
    assert seen
    # More than twice the approver count fails approval verification itself.
    approvals = [sign_approval(seen[0], APPROVER) for _ in range(3)]
    _observe()
    result = enforce_tool_call("issue_payout", GATED_ARGS, bound, trusted_roots=ROOTS, approvals=approvals)
    assert result.allowed and result.observed
    assert result.error_type == "invalid_approval"

    # Inbound, the observed denial keeps the Authorizer that decided, for its receipt.
    from tenuo_core import Authorizer

    authorizer = Authorizer(trusted_roots=ROOTS)
    pop = bytes(GATED.sign(AGENT, "issue_payout", GATED_ARGS, int(time.time())))
    inbound = verify_inbound_call(tool_name="issue_payout", tool_args=GATED_ARGS, warrant=GATED,
                                  pop_signature=pop, authorizer=authorizer, approvals=approvals)
    assert inbound.allowed and inbound.observed
    assert inbound.authorizer is authorizer


def test_mcp_verifier_keeps_the_observed_denial(monkeypatch):
    from tenuo_core import Authorizer, sign_meta

    from tenuo.mcp.server import MCPVerifier
    from tenuo.meta import argument_json

    emitted: List[Any] = []
    _observe()
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=ROOTS))
    monkeypatch.setattr(verifier, "_control_plane", type("CP", (), {
        "emit_for_enforcement": lambda self, result, **kw: emitted.append(result)})())
    meta = {"tenuo": sign_meta([WARRANT], AGENT, "issue_payout", argument_json(BAD_ARGS), int(time.time()))}
    result = verifier.verify("issue_payout", dict(BAD_ARGS), meta)
    assert result.allowed and result.observed
    assert result.error_type == "constraint_violation"
    assert emitted == [result]


def test_nexus_records_the_observed_denial_with_its_own_category(monkeypatch):
    import types

    from tenuo._enforcement import EnforcementResult
    from tenuo.exceptions import ToolNotAuthorized
    from tenuo.temporal import _nexus

    sent: List[Any] = []
    monkeypatch.setattr(_nexus, "_encode_nexus_warrant_stack_for_denial", lambda warrant, chain: None)
    config = types.SimpleNamespace(
        control_plane=types.SimpleNamespace(emit_for_enforcement=lambda result, **kw: sent.append(result)),
        audit_callback=None, metrics=None, runtime=None, redact_args_in_logs=True,
    )
    observed = EnforcementResult(allowed=True, observed=True, tool="op", arguments={"a": 1},
                                 denial_reason="approval expired", error_type="approval_expired")
    _nexus._emit_nexus_control_plane_event(
        config, types.SimpleNamespace(request_id=None), WARRANT, None, "op", {"a": 1},
        start_ns=time.perf_counter_ns(), exc=ToolNotAuthorized("x"), observed=observed,
    )
    assert [r.error_type for r in sent] == ["approval_expired"]
    assert sent[0].arguments == {"a": "[REDACTED]"}
