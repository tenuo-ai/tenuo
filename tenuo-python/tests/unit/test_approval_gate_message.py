"""Optional approval-gate display message: one resolved string, copied everywhere."""

from __future__ import annotations

import base64
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tenuo import Authorizer, BoundWarrant, SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call
from tenuo.a2a.errors import ApprovalRequiredError
from tenuo.approval import ApprovalRequest, ApprovalRequired, cli_prompt
from tenuo.cp_approval import build_control_plane_approval_request_v1
from tenuo.exceptions import ApprovalGateTriggered
from tenuo.mcp.server import MCPVerifier
from tenuo_core import py_compute_request_hash as compute_request_hash

CUSTOM = "A human must confirm this deletion."


def _mint(issuer, holder, approver, gates):
    return Warrant.issue(
        keypair=issuer,
        capabilities={"email.delete": {}},
        ttl_seconds=3600,
        holder=holder.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates=gates,
    )


def _authorize(warrant, holder, issuer_pk, approvals=None):
    auth = Authorizer(trusted_roots=[issuer_pk])
    args = {"id": "42"}
    sig = warrant.sign(holder, "email.delete", args, int(time.time()))
    auth.authorize_one(warrant, "email.delete", args, bytes(sig), approvals or [])


def test_custom_message_on_authorizer_exception():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    assert w.approval_gate_message("email.delete") == CUSTOM

    with pytest.raises(ApprovalGateTriggered) as exc_info:
        _authorize(w, holder, issuer.public_key)
    assert exc_info.value.message == CUSTOM
    assert str(exc_info.value) == CUSTOM
    assert exc_info.value.details["message"] == CUSTOM


def test_default_message_when_gate_has_none():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(issuer, holder, approver, {"email.delete": None})
    assert w.approval_gate_message("email.delete") is None

    with pytest.raises(ApprovalGateTriggered) as exc_info:
        _authorize(w, holder, issuer.public_key)
    assert exc_info.value.message == "Approval required for tool 'email.delete'"


def test_empty_message_omitted():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": "   "}},
    )
    assert w.approval_gate_message("email.delete") is None


def test_message_capped_at_200_chars():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    long = "é" * 250
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": long}},
    )
    stored = w.approval_gate_message("email.delete")
    assert stored is not None
    assert len(stored) == 200


def test_approval_required_and_for_warrant_gate_copy_message():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    args = {"id": "42"}
    rh = compute_request_hash(w.id, "email.delete", args, holder.public_key)
    req = ApprovalRequest.for_warrant_gate("email.delete", args, w, rh)
    assert req.message == CUSTOM
    assert str(ApprovalRequired(req)) == CUSTOM


def test_shared_enforcement_raises_resolved_message():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    bound = BoundWarrant(w, holder)

    with pytest.raises(ApprovalRequired) as exc_info:
        enforce_tool_call(
            "email.delete",
            {"id": "42"},
            bound,
            trusted_roots=[issuer.public_key],
        )

    assert str(exc_info.value) == CUSTOM
    assert exc_info.value.request.message == CUSTOM


def test_fastapi_and_mcp_share_resolved_message():
    pytest.importorskip("fastapi")

    from fastapi import FastAPI, HTTPException
    from tenuo.fastapi import TenuoGuard, configure_tenuo

    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    args = {"id": "42"}
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    sig = w.sign(holder, "email.delete", args, int(time.time()))

    app = FastAPI()
    configure_tenuo(app, trusted_issuers=[issuer.public_key])
    request = SimpleNamespace(
        state=SimpleNamespace(tenuo_parents=[]),
        path_params={},
        query_params={},
    )
    guard = TenuoGuard("email.delete", extract_args=lambda _: args)

    with pytest.raises(HTTPException) as fastapi_exc:
        guard(
            request,
            warrant=w,
            x_tenuo_pop=base64.b64encode(bytes(sig)).decode(),
            x_tenuo_approvals=None,
        )

    authorizer = Authorizer(trusted_roots=[issuer.public_key])
    meta = {
        "tenuo": {
            "warrant": w.to_base64(),
            "signature": base64.b64encode(bytes(sig)).decode(),
        }
    }
    mcp = MCPVerifier(authorizer=authorizer).verify("email.delete", args, meta=meta)

    assert fastapi_exc.value.detail["message"] == CUSTOM
    assert mcp.denial_reason == CUSTOM


def test_a2a_and_control_plane_share_resolved_message():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    args = {"id": "42"}
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    rh = compute_request_hash(w.id, "email.delete", args, holder.public_key)
    req = ApprovalRequest.for_warrant_gate("email.delete", args, w, rh)

    a2a = ApprovalRequiredError("email.delete", message=req.message)
    cp = build_control_plane_approval_request_v1(req, holder.public_key)

    assert a2a.message == CUSTOM
    assert a2a.data["message"] == CUSTOM
    assert cp.to_json_dict()["message"] == CUSTOM


def test_same_bytes_across_surfaces():
    issuer = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    w = _mint(
        issuer,
        holder,
        approver,
        {"email.delete": {"args": None, "message": CUSTOM}},
    )
    args = {"id": "42"}

    with pytest.raises(ApprovalGateTriggered) as gate_info:
        _authorize(w, holder, issuer.public_key)
    gate = gate_info.value

    rh = compute_request_hash(w.id, "email.delete", args, holder.public_key)
    req = ApprovalRequest.for_warrant_gate("email.delete", args, w, rh)
    approval_required = ApprovalRequired(req)

    authorizer = Authorizer(trusted_roots=[issuer.public_key])
    sig = w.sign(holder, "email.delete", args, int(time.time()))
    meta = {
        "tenuo": {
            "warrant": w.to_base64(),
            "signature": __import__("base64").b64encode(bytes(sig)).decode(),
        }
    }
    mcp = MCPVerifier(authorizer=authorizer).verify("email.delete", args, meta=meta)

    fastapi_from_gate = gate.message
    fastapi_from_required = req.message or str(approval_required)
    a2a = ApprovalRequiredError("email.delete", message=gate.message)

    cp = build_control_plane_approval_request_v1(req, holder.public_key)
    cp_dict = cp.to_json_dict()

    expected = CUSTOM
    assert str(gate) == expected
    assert str(approval_required) == expected
    assert fastapi_from_gate == expected
    assert fastapi_from_required == expected
    assert mcp.denial_reason == expected
    assert a2a.message == expected
    assert a2a.data["message"] == expected
    assert cp.message == expected
    assert cp_dict["message"] == expected

    try:
        from tenuo.temporal.exceptions import _build_non_retryable_application_error
    except Exception:
        pytest.skip("temporal adapter extras not installed")
    try:
        app_err = _build_non_retryable_application_error(gate)
    except ImportError:
        pytest.skip("temporalio not installed")
    assert app_err.message == expected


def test_cli_prompt_prints_message(capsys):
    approver = SigningKey.generate()
    req = ApprovalRequest(
        tool="email.delete",
        arguments={"id": "42"},
        warrant_id="w",
        request_hash=b"\x00" * 32,
        message=CUSTOM,
    )
    handler = cli_prompt(approver_key=approver)
    with patch("builtins.input", return_value="y"):
        handler(req)
    err = capsys.readouterr().err
    assert CUSTOM in err


def test_positional_four_tuple_still_constructs():
    exc = ApprovalGateTriggered("email.delete", "rid", "rhash", 2)
    assert exc.tool == "email.delete"
    assert exc.request_id == "rid"
    assert exc.request_hash == "rhash"
    assert exc.min_approvals == 2
    assert exc.message == "Approval required for tool 'email.delete'"


def test_merge_inherits_parent_message():
    issuer = SigningKey.generate()
    approver = SigningKey.generate()
    child_key = SigningKey.generate()
    parent = Warrant.issue(
        keypair=issuer,
        capabilities={"email.delete": {}, "email.read": {}},
        ttl_seconds=3600,
        holder=issuer.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates={"email.delete": {"args": None, "message": "parent text"}},
    )
    child = (
        parent.grant_builder()
        .capability("email.delete")
        .holder(child_key.public_key)
        .ttl(1800)
        .approval_gates({"email.delete": None})
        .grant(issuer)
    )
    assert child.approval_gate_message("email.delete") == "parent text"


def test_merge_child_message_wins():
    issuer = SigningKey.generate()
    approver = SigningKey.generate()
    child_key = SigningKey.generate()
    parent = Warrant.issue(
        keypair=issuer,
        capabilities={"email.delete": {}},
        ttl_seconds=3600,
        holder=issuer.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates={"email.delete": {"args": None, "message": "parent text"}},
    )
    child = (
        parent.grant_builder()
        .capability("email.delete")
        .holder(child_key.public_key)
        .ttl(1800)
        .approval_gates({"email.delete": {"args": None, "message": "child text"}})
        .grant(issuer)
    )
    assert child.approval_gate_message("email.delete") == "child text"
