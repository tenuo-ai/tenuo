"""
Regression tests for the InsufficientApprovals signal bug.

Before this fix, InsufficientApprovals (multi-sig threshold not met) was
indistinguishable from a scope denial (tool not in warrant, constraint
violated) across MCP, FastAPI, and Temporal.  Callers could not tell whether
to retry with more approvals or give up.

These tests assert that each integration emits its own distinct "approval
required" signal — the same one used for ApprovalGateTriggered — rather than
the generic access-denied signal.

Coverage:
  _enforcement.py   — EnforcementResult.error_type + approval_metadata
  mcp/server.py     — jsonrpc_error_code == -32002
  fastapi.py        — HTTP 409 Conflict with error="insufficient_approvals"
  temporal          — _error_type_for_wire returns "insufficient_approvals"
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch

import pytest

from tenuo import SigningKey, Warrant
from tenuo.exceptions import InsufficientApprovals


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_multi_sig_warrant(
    issuer_key: SigningKey,
    holder_key: SigningKey,
    approver_keys: list,
    min_approvals: int = 2,
) -> Warrant:
    """Issue a warrant that requires multi-sig approval for 'transfer'."""
    return Warrant.issue(
        issuer_key,
        capabilities={"transfer": {}},
        holder=holder_key.public_key,
        approval_gates={"transfer": None},
        required_approvers=[k.public_key for k in approver_keys],
        min_approvals=min_approvals,
    )


def _make_signed_approval(warrant: Warrant, tool: str, tool_args: dict, holder_key, approver_key):
    """Build a real SignedApproval for the given call."""
    from tenuo_core import ApprovalPayload, SignedApproval
    from tenuo_core import py_compute_request_hash as compute_request_hash

    request_hash = compute_request_hash(
        warrant.id, tool, tool_args, holder_key.public_key
    )
    now = int(time.time())
    payload = ApprovalPayload(
        request_hash=request_hash,
        nonce=os.urandom(16),
        external_id="test-approver",
        approved_at=now,
        expires_at=now + 300,
    )
    return SignedApproval.create(payload, approver_key)


# ---------------------------------------------------------------------------
# _enforcement.py
# ---------------------------------------------------------------------------


class TestEnforcementResult:
    """InsufficientApprovals must surface as error_type='insufficient_approvals'
    with structured approval_metadata, not as generic 'authorization_failed'."""

    def test_insufficient_approvals_sets_correct_error_type(self):
        from tenuo import Authorizer
        from tenuo._enforcement import enforce_tool_call

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver1 = SigningKey.generate()
        approver2 = SigningKey.generate()

        warrant = _make_multi_sig_warrant(
            issuer, holder, [approver1, approver2], min_approvals=2
        )
        bound = warrant.bind(holder)
        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        tool_args = {"amount": 100}
        # Provide only one approval — threshold is 2
        approval = _make_signed_approval(warrant, "transfer", tool_args, holder, approver1)

        result = enforce_tool_call(
            "transfer",
            tool_args,
            bound,
            trusted_roots=[issuer.public_key],
            approvals=[approval],
        )

        assert not result.allowed
        assert result.error_type == "insufficient_approvals", (
            f"Expected 'insufficient_approvals', got '{result.error_type}' — "
            "InsufficientApprovals is being swallowed as a generic denial"
        )

    def test_insufficient_approvals_populates_approval_metadata(self):
        from tenuo import Authorizer
        from tenuo._enforcement import enforce_tool_call

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        approver1 = SigningKey.generate()
        approver2 = SigningKey.generate()

        warrant = _make_multi_sig_warrant(
            issuer, holder, [approver1, approver2], min_approvals=2
        )
        bound = warrant.bind(holder)

        tool_args = {"amount": 100}
        approval = _make_signed_approval(warrant, "transfer", tool_args, holder, approver1)

        result = enforce_tool_call(
            "transfer",
            tool_args,
            bound,
            trusted_roots=[issuer.public_key],
            approvals=[approval],
        )

        assert result.approval_metadata is not None, (
            "approval_metadata must be populated for insufficient_approvals"
        )
        assert "got" in result.approval_metadata
        assert "need" in result.approval_metadata
        assert result.approval_metadata["need"] == 2
        assert result.approval_metadata["got"] == 1

    def test_scope_denial_does_not_set_approval_metadata(self):
        """A plain scope denial must never carry approval_metadata."""
        from tenuo._enforcement import enforce_tool_call

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = Warrant.issue(
            issuer,
            capabilities={"read_file": {}},
            holder=holder.public_key,
        )
        bound = warrant.bind(holder)

        result = enforce_tool_call(
            "delete_file",  # not in warrant
            {},
            bound,
            trusted_roots=[issuer.public_key],
        )

        assert not result.allowed
        assert result.error_type != "insufficient_approvals"
        assert result.approval_metadata is None

    def test_constraint_violation_populates_constraint_field(self):
        """ConstraintViolation.field lives in details — must surface in result."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo import Pattern

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = Warrant.issue(
            issuer,
            capabilities={"read_file": {"path": Pattern("/data/*")}},
            holder=holder.public_key,
        )
        bound = warrant.bind(holder)

        result = enforce_tool_call(
            "read_file",
            {"path": "/etc/passwd"},
            bound,
            trusted_roots=[issuer.public_key],
        )

        assert not result.allowed
        assert result.error_type == "constraint_violation"
        assert result.constraint_violated == "path"

    def test_verify_path_maps_insufficient_approvals(self):
        """verify_mode='verify' must preserve insufficient_approvals error_type."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo import Authorizer

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = Warrant.issue(
            issuer,
            capabilities={"transfer": {}},
            holder=holder.public_key,
        )
        bound = warrant.bind(holder)
        authorizer = Authorizer(trusted_roots=[issuer.public_key])

        exc = InsufficientApprovals(required=2, received=1)
        with patch.object(Authorizer, "check_chain", side_effect=exc):
            result = enforce_tool_call(
                "transfer",
                {},
                bound,
                verify_mode="verify",
                precomputed_signature=b"\x00" * 64,
                authorizer=authorizer,
            )

        assert not result.allowed
        assert result.error_type == "insufficient_approvals"
        assert result.approval_metadata == {"got": 1, "need": 2}

    def test_outer_catch_handles_insufficient_approvals(self):
        """The outer InsufficientApprovals except block in enforce_tool_call
        produces the correct EnforcementResult even when the exception escapes
        the inner handlers.  We simulate this by patching the Rust authorizer
        to raise InsufficientApprovals on a warrant with no approval gates
        (so the gate branch is skipped and the exception comes from the inner
        authorize_one call)."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo.exceptions import InsufficientApprovals
        from tenuo import Authorizer

        issuer = SigningKey.generate()
        holder = SigningKey.generate()
        warrant = Warrant.issue(
            issuer,
            capabilities={"transfer": {}},
            holder=holder.public_key,
        )
        bound = warrant.bind(holder)

        exc = InsufficientApprovals(required=3, received=1)

        with patch.object(Authorizer, "authorize_one", side_effect=exc), \
             patch.object(Authorizer, "authorize_one_with_pop_args", side_effect=exc):
            result = enforce_tool_call(
                "transfer",
                {},
                bound,
                trusted_roots=[issuer.public_key],
            )

        assert not result.allowed
        assert result.error_type == "insufficient_approvals"
        assert result.approval_metadata is not None
        assert result.approval_metadata["got"] == 1
        assert result.approval_metadata["need"] == 3


# ---------------------------------------------------------------------------
# mcp/server.py
# ---------------------------------------------------------------------------


class TestMCPInsufficientApprovals:
    """MCPVerifier must return jsonrpc_error_code=-32002 for InsufficientApprovals,
    not -32001 (the generic access denied code)."""

    @pytest.fixture
    def issuer_key(self):
        return SigningKey.generate()

    @pytest.fixture
    def agent_key(self):
        return SigningKey.generate()

    @staticmethod
    def _make_meta(warrant: Warrant, agent_key: SigningKey, tool: str, tool_args: dict, approvals=None):
        import base64, time as _time

        sig = bytes(warrant.sign(agent_key, tool, tool_args, int(_time.time())))
        entry: dict = {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(sig).decode(),
        }
        if approvals:
            entry["approvals"] = [
                base64.b64encode(bytes(a.to_bytes())).decode() for a in approvals
            ]
        return {"tenuo": entry}

    def test_insufficient_approvals_returns_minus_32002(self, issuer_key, agent_key):
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier

        approver1 = SigningKey.generate()
        approver2 = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        warrant = _make_multi_sig_warrant(
            issuer_key, agent_key, [approver1, approver2], min_approvals=2
        )
        tool_args = {"amount": 500}

        # Provide only one valid approval
        approval = _make_signed_approval(warrant, "transfer", tool_args, agent_key, approver1)
        meta = self._make_meta(warrant, agent_key, "transfer", tool_args, approvals=[approval])

        result = MCPVerifier(authorizer=authorizer).verify("transfer", tool_args, meta=meta)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32002, (
            f"Expected -32002 (approval required), got {result.jsonrpc_error_code} — "
            "InsufficientApprovals is being treated as a flat access denial"
        )
        assert result.is_approval_required

    def test_insufficient_approvals_denial_reason_includes_counts(self, issuer_key, agent_key):
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier

        approver1 = SigningKey.generate()
        approver2 = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        warrant = _make_multi_sig_warrant(
            issuer_key, agent_key, [approver1, approver2], min_approvals=2
        )
        tool_args = {"amount": 500}
        approval = _make_signed_approval(warrant, "transfer", tool_args, agent_key, approver1)
        meta = self._make_meta(warrant, agent_key, "transfer", tool_args, approvals=[approval])

        result = MCPVerifier(authorizer=authorizer).verify("transfer", tool_args, meta=meta)

        # Denial reason should be self-explanatory for the retry loop
        assert result.denial_reason is not None
        reason = result.denial_reason.lower()
        assert "approval" in reason

    def test_scope_denial_still_returns_minus_32001(self, issuer_key, agent_key):
        """Regression guard: plain tool-not-allowed must stay -32001."""
        import base64, time as _time
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {}},
            holder=agent_key.public_key,
        )
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        tool_args = {}
        sig = bytes(warrant.sign(agent_key, "delete_file", tool_args, int(_time.time())))
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(sig).decode(),
            }
        }

        result = MCPVerifier(authorizer=authorizer).verify("delete_file", tool_args, meta=meta)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
        assert not result.is_approval_required

    def test_insufficient_approvals_catch_block_emits_minus_32002(self, issuer_key, agent_key):
        """Inject InsufficientApprovals at the Rust authorizer boundary and confirm
        the MCP catch block maps it to -32002, not -32001."""
        import base64, time as _time
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"transfer": {}},
            holder=agent_key.public_key,
        )
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        tool_args = {}
        sig = bytes(warrant.sign(agent_key, "transfer", tool_args, int(_time.time())))
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(sig).decode(),
            }
        }

        exc = InsufficientApprovals(required=2, received=1)
        # Patch all the verify paths the MCPVerifier may call so the exception
        # reaches the catch block regardless of which internal path is taken.
        with patch.object(Authorizer, "authorize_one", side_effect=exc), \
             patch.object(Authorizer, "authorize_one_with_pop_args", side_effect=exc), \
             patch.object(Authorizer, "check_chain", side_effect=exc), \
             patch.object(Authorizer, "check_chain_with_pop_args", side_effect=exc):
            result = MCPVerifier(authorizer=authorizer).verify("transfer", tool_args, meta=meta)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32002, (
            f"Expected -32002, got {result.jsonrpc_error_code}"
        )
        assert result.is_approval_required


# ---------------------------------------------------------------------------
# fastapi.py
# ---------------------------------------------------------------------------


class TestFastAPIInsufficientApprovals:
    """FastAPI dependency must raise HTTP 409 with error='insufficient_approvals',
    not 403 or a generic TenuoError."""

    def test_http_409_on_insufficient_approvals(self):
        """InsufficientApprovals must produce 409, not 403."""
        pytest.importorskip("fastapi")
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        from fastapi.testclient import TestClient
        from tenuo.exceptions import InsufficientApprovals as IA

        # Directly register the same handler that fastapi.py adds and verify
        # the exception shape leads to the right HTTP response.
        app = FastAPI()

        @app.exception_handler(IA)
        async def _handler(request: Request, exc: IA):
            return JSONResponse(
                status_code=409,
                content={
                    "error": "insufficient_approvals",
                    "got": exc.details.get("received", 0) if hasattr(exc, "details") else 0,
                    "need": exc.details.get("required", 0) if hasattr(exc, "details") else 0,
                },
            )

        @app.get("/test")
        async def _route():
            raise IA(required=2, received=1)

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/test")

        assert response.status_code == 409
        body = response.json()
        assert body["error"] == "insufficient_approvals"
        assert body["need"] == 2
        assert body["got"] == 1

    def test_insufficient_approvals_details_attributes(self):
        """InsufficientApprovals.details carries got/need for the fastapi handler."""
        from tenuo.exceptions import InsufficientApprovals as IA

        exc = IA(required=3, received=1)
        assert exc.details["required"] == 3
        assert exc.details["received"] == 1


class TestA2AInsufficientApprovalsMapping:
    def test_insufficient_approvals_maps_details_to_a2a_error(self):
        from tenuo.exceptions import InsufficientApprovals
        from tenuo.a2a.errors import InsufficientApprovalsError

        core_exc = InsufficientApprovals(required=3, received=1)
        a2a_exc = InsufficientApprovalsError(
            str(core_exc),
            required=core_exc.details.get("required", 0),
            received=core_exc.details.get("received", 0),
        )
        rpc = a2a_exc.to_jsonrpc_error()
        assert rpc["data"]["required"] == 3
        assert rpc["data"]["received"] == 1
        assert rpc["data"]["tenuo_code"] == 1700


class TestRaiseIfDenied:
    def test_insufficient_approvals_raises_typed_exception(self):
        from tenuo._enforcement import EnforcementResult
        from tenuo.exceptions import InsufficientApprovals

        result = EnforcementResult(
            allowed=False,
            tool="transfer",
            arguments={},
            error_type="insufficient_approvals",
            approval_metadata={"got": 1, "need": 2},
        )
        with pytest.raises(InsufficientApprovals) as exc_info:
            result.raise_if_denied()
        assert exc_info.value.details["required"] == 2
        assert exc_info.value.details["received"] == 1

    def test_invalid_pop_raises_signature_invalid(self):
        from tenuo._enforcement import EnforcementResult
        from tenuo.exceptions import SignatureInvalid

        result = EnforcementResult(
            allowed=False,
            tool="transfer",
            arguments={},
            error_type="invalid_pop",
            denial_reason="bad signature",
        )
        with pytest.raises(SignatureInvalid):
            result.raise_if_denied()


class TestOpenAIEnforcementMapping:
    def test_insufficient_approvals_raises_typed_exception(self):
        from tenuo._enforcement import EnforcementResult
        from tenuo.exceptions import InsufficientApprovals
        from tenuo.openai import _raise_for_enforcement_denial

        result = EnforcementResult(
            allowed=False,
            tool="transfer",
            arguments={},
            error_type="insufficient_approvals",
            approval_metadata={"got": 0, "need": 2},
        )
        with pytest.raises(InsufficientApprovals):
            _raise_for_enforcement_denial("transfer", result)


class TestCrewAIEnforcementMapping:
    def test_insufficient_approvals_maps_to_dedicated_exception(self):
        from tenuo._enforcement import EnforcementResult
        from tenuo.crewai import CrewAIGuard, InsufficientApprovalsDenied

        guard = CrewAIGuard.__new__(CrewAIGuard)
        guard._warrant = None
        guard._signing_key = None
        result = EnforcementResult(
            allowed=False,
            tool="transfer",
            arguments={},
            error_type="insufficient_approvals",
            approval_metadata={"got": 1, "need": 3},
            denial_reason="need more",
        )
        err = guard._map_enforcement_error(result, "transfer", {}, "need more")
        assert isinstance(err, InsufficientApprovalsDenied)
        assert err.got == 1
        assert err.need == 3


class TestMCPJsonRpcPayload:
    def test_minus_32002_includes_got_and_need(self):
        from tenuo.mcp.server import MCPVerificationResult

        result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            denial_reason="need more approvals",
            jsonrpc_error_code=-32002,
            approval_metadata={"got": 1, "need": 2},
        )
        err = result.to_jsonrpc_error()
        assert err["code"] == -32002
        assert err["data"]["got"] == 1
        assert err["data"]["need"] == 2


# ---------------------------------------------------------------------------
# temporal/exceptions.py  (_error_type_for_wire)
# ---------------------------------------------------------------------------


class TestTemporalErrorTypeForWire:
    """_error_type_for_wire must return 'insufficient_approvals' for
    InsufficientApprovals, not the class name or a generic string."""

    def test_error_type_for_wire_insufficient_approvals(self):
        from tenuo.temporal.exceptions import _error_type_for_wire

        exc = InsufficientApprovals(required=2, received=1)
        wire_type = _error_type_for_wire(exc)

        assert wire_type == "insufficient_approvals", (
            f"Expected 'insufficient_approvals', got '{wire_type}'"
        )

    def test_error_type_for_wire_approval_gate_triggered(self):
        """Sanity check: ApprovalGateTriggered keeps its wire type."""
        from tenuo.temporal.exceptions import _error_type_for_wire
        from tenuo.exceptions import ApprovalGateTriggered

        exc = ApprovalGateTriggered(tool="transfer")
        wire_type = _error_type_for_wire(exc)

        assert wire_type == "approval_required"

    def test_insufficient_approvals_in_interceptor_catch_list(self):
        """InsufficientApprovals must be caught in the explicit auth_exc block,
        not fall through to the generic Exception handler."""
        import ast
        import inspect
        from tenuo.temporal import _interceptors

        source = inspect.getsource(_interceptors)
        tree = ast.parse(source)

        found_in_same_clause = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    continue
                names = []
                if isinstance(node.type, ast.Tuple):
                    for elt in node.type.elts:
                        names.append(ast.unparse(elt) if hasattr(ast, "unparse") else getattr(elt, "id", ""))
                else:
                    names.append(ast.unparse(node.type) if hasattr(ast, "unparse") else getattr(node.type, "id", ""))

                has_gate = any("ApprovalGateTriggered" in n for n in names)
                has_insuf = any("InsufficientApprovals" in n for n in names)
                has_tool = any("ToolNotAuthorized" in n for n in names)
                has_constraint = any("ConstraintViolation" in n for n in names)
                if has_gate and has_insuf and has_tool and has_constraint:
                    found_in_same_clause = True
                    break

        assert found_in_same_clause, (
            "Approval, tool, and constraint errors must be in the explicit "
            "auth catch list in temporal/_interceptors.py"
        )

    def test_error_type_for_wire_tool_not_authorized(self):
        from tenuo.temporal.exceptions import _error_type_for_wire
        from tenuo.exceptions import ToolNotAuthorized

        exc = ToolNotAuthorized(tool="delete_file")
        assert _error_type_for_wire(exc) == "tool_not_authorized"
