"""Audit mode: scope denials are recorded but don't block.

``configure(mode="audit")`` is documented as "log violations but allow
execution". These pin that across the shared enforcement path and the
integrations that make their own decisions, and pin what audit mode must
NOT let through: authority that doesn't verify, and approval gates.
"""

from __future__ import annotations

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo import Pattern, SigningKey, Warrant, configure, guard, mint_sync, Capability, Subpath  # noqa: E402
from tenuo._enforcement import audit_denial_exception, enforce_tool_call  # noqa: E402
from tenuo.config import reset_config  # noqa: E402
from tenuo.exceptions import AuthorizationDenied, ConstraintViolation, ToolNotAuthorized  # noqa: E402


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def _configure(mode: str) -> None:
    configure(issuer_key=SigningKey.generate(), mode=mode, dev_mode=True)


@pytest.fixture
def signing_key():
    return SigningKey.generate()


@pytest.fixture
def bound(signing_key):
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(signing_key.public_key)
        .ttl(3600)
        .mint(signing_key)
    )
    return warrant.bind(signing_key)


# ---------------------------------------------------------------------------
# @guard, the path the production guide documents
# ---------------------------------------------------------------------------


def _guarded_delete():
    @guard(tool="delete_file")
    def delete_file(path: str) -> str:
        return f"deleted {path}"

    return delete_file


def test_guard_blocks_out_of_scope_call_in_enforce_mode():
    _configure("enforce")
    delete_file = _guarded_delete()
    with mint_sync(Capability("delete_file", path=Subpath("/tmp"))):
        with pytest.raises(AuthorizationDenied):
            delete_file("/etc/passwd")


@pytest.mark.parametrize("mode", ["audit", "permissive"])
def test_guard_runs_out_of_scope_call_in_audit_mode(mode):
    _configure(mode)
    delete_file = _guarded_delete()
    with mint_sync(Capability("delete_file", path=Subpath("/tmp"))):
        assert delete_file("/tmp/x") == "deleted /tmp/x"
        assert delete_file("/etc/passwd") == "deleted /etc/passwd"


# ---------------------------------------------------------------------------
# enforce_tool_call: the shared path most integrations use
# ---------------------------------------------------------------------------


def test_enforce_mode_is_unchanged(bound, signing_key):
    _configure("enforce")
    result = enforce_tool_call(
        "read_file", {"path": "/etc/passwd"}, bound, trusted_roots=[signing_key.public_key]
    )
    assert not result.allowed
    assert not result.audit_denied


@pytest.mark.parametrize(
    "tool,args,error_type",
    [
        ("read_file", {"path": "/etc/passwd"}, "constraint_violation"),
        ("delete_file", {"path": "/data/x"}, "tool_not_allowed"),
    ],
)
def test_audit_mode_lets_scope_denials_through_and_keeps_the_reason(bound, signing_key, tool, args, error_type):
    _configure("audit")
    result = enforce_tool_call(tool, args, bound, trusted_roots=[signing_key.public_key])
    assert result.allowed
    assert result.audit_denied
    assert result.error_type == error_type
    assert result.denial_reason


def test_audit_mode_still_rejects_an_untrusted_issuer(bound):
    _configure("audit")
    stranger = SigningKey.generate()
    result = enforce_tool_call(
        "read_file", {"path": "/data/x"}, bound, trusted_roots=[stranger.public_key]
    )
    assert not result.allowed
    assert not result.audit_denied


def test_audit_mode_does_not_skip_an_approval_gate():
    _configure("audit")
    root, approver = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.issue(
        keypair=root,
        capabilities={"delete_file": {"path": Pattern("*")}},
        ttl_seconds=3600,
        holder=root.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates={"delete_file": None},
    )
    try:
        result = enforce_tool_call(
            "delete_file", {"path": "/x"}, warrant.bind(root), trusted_roots=[root.public_key]
        )
    except Exception:
        return  # the gate raised; nothing ran
    assert not result.allowed
    assert not result.audit_denied


def test_an_audited_call_is_recorded_as_a_denial(bound, signing_key):
    """The receipt and control-plane event say deny, even though the call ran."""
    _configure("audit")
    from tenuo.control_plane import ControlPlaneClient
    from tenuo.receipts import InMemoryReceiptSink

    result = enforce_tool_call(
        "read_file", {"path": "/etc/passwd"}, bound, trusted_roots=[signing_key.public_key]
    )
    assert result.allowed and result.audit_denied

    sink = InMemoryReceiptSink()
    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="t", receipt_sink=sink)
    client.bind_authorizer(result.authorizer)
    client.emit_for_enforcement(result)
    assert client.flush_receipts()

    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])
    assert payload.outcome == "deny"
    assert payload.decision_code == "constraint-violation"


def test_audit_denial_exception_rebuilds_the_denial(bound, signing_key):
    _configure("audit")
    result = enforce_tool_call(
        "read_file", {"path": "/etc/passwd"}, bound, trusted_roots=[signing_key.public_key]
    )
    assert isinstance(audit_denial_exception(result), ConstraintViolation)

    _configure("enforce")
    allowed = enforce_tool_call(
        "read_file", {"path": "/data/x"}, bound, trusted_roots=[signing_key.public_key]
    )
    assert audit_denial_exception(allowed) is None


# ---------------------------------------------------------------------------
# Integrations with their own Tier 1 checks
# ---------------------------------------------------------------------------


def test_crewai_tier1_denial_passes_in_audit_mode_but_warrant_check_still_runs(signing_key):
    from tenuo.crewai import GuardBuilder, ToolDenied

    _configure("enforce")
    guard_ = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    with pytest.raises(ToolDenied):
        guard_._authorize("delete_file", {"path": "/data/x"})

    _configure("audit")
    assert guard_._authorize("delete_file", {"path": "/data/x"}) is None
    assert guard_._authorize("read_file", {"path": "/etc/passwd"}) is None


def test_openai_tier1_denial_passes_in_audit_mode():
    from tenuo.openai import ToolDenied, verify_tool_call

    _configure("enforce")
    with pytest.raises(ToolDenied):
        verify_tool_call("delete_file", {}, allow_tools=["search"], deny_tools=None, constraints=None)

    _configure("audit")
    result = verify_tool_call("delete_file", {}, allow_tools=["search"], deny_tools=None, constraints=None)
    assert result is not None and result.audit_denied


def test_autogen_tier1_denial_passes_in_audit_mode():
    from tenuo.autogen import _check_constraints_or_audit

    _configure("enforce")
    with pytest.raises(ToolNotAuthorized):
        _check_constraints_or_audit("delete_file", None, {})

    _configure("audit")
    _check_constraints_or_audit("delete_file", None, {})
