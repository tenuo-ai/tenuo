"""Tests for warrant-level approval gate API (per-tool approval gates)."""

import time

import pytest

from tenuo import Authorizer, Pattern, SigningKey, Warrant
from tenuo.exceptions import ApprovalGateTriggered
from tenuo_core import evaluate_approval_gates as _evaluate_approval_gates


@pytest.fixture
def keys():
    root = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    return root, holder, approver


def _mint_gated(root, holder, approver, approval_gates, capabilities=None):
    caps = capabilities or {
        "delete_file": {"path": Pattern("*")},
        "read_file": {"path": Pattern("*")},
    }
    return Warrant.issue(
        keypair=root,
        capabilities=caps,
        ttl_seconds=3600,
        holder=holder.public_key,
        required_approvers=[approver.public_key],
        min_approvals=1,
        approval_gates=approval_gates,
    )


def _authorize(warrant, key, tool, args, root_pk, approvals=None):
    auth = Authorizer(trusted_roots=[root_pk])
    sig = warrant.sign(key, tool, args, int(time.time()))
    auth.authorize_one(warrant, tool, args, bytes(sig), approvals or [])


# ============================================================================
# Whole-tool approval gates
# ============================================================================


class TestWholeToolApprovalGate:
    def test_ungated_tool_allowed(self, keys):
        root, holder, approver = keys
        w = _mint_gated(root, holder, approver, approval_gates={"delete_file": None})
        _authorize(w, holder, "read_file", {"path": "/tmp/x"}, root.public_key)

    def test_gated_tool_raises_approval_gate_triggered(self, keys):
        root, holder, approver = keys
        w = _mint_gated(root, holder, approver, approval_gates={"delete_file": None})
        with pytest.raises(ApprovalGateTriggered) as exc_info:
            _authorize(w, holder, "delete_file", {"path": "/tmp/x"}, root.public_key)
        assert exc_info.value.tool == "delete_file"

    def test_multiple_tools_gated(self, keys):
        root, holder, approver = keys
        w = _mint_gated(
            root,
            holder,
            approver,
            approval_gates={"delete_file": None, "read_file": None},
        )
        with pytest.raises(ApprovalGateTriggered):
            _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)
        with pytest.raises(ApprovalGateTriggered):
            _authorize(w, holder, "read_file", {"path": "/x"}, root.public_key)


# ============================================================================
# Per-argument approval gates
# ============================================================================


class TestArgApprovalGate:
    def test_matching_arg_triggers_gate(self, keys):
        root, holder, approver = keys
        w = _mint_gated(
            root,
            holder,
            approver,
            approval_gates={"delete_file": {"path": Pattern("/etc/*")}},
        )
        with pytest.raises(ApprovalGateTriggered):
            _authorize(
                w, holder, "delete_file", {"path": "/etc/passwd"}, root.public_key
            )

    def test_non_matching_arg_allowed(self, keys):
        root, holder, approver = keys
        w = _mint_gated(
            root,
            holder,
            approver,
            approval_gates={"delete_file": {"path": Pattern("/etc/*")}},
        )
        _authorize(w, holder, "delete_file", {"path": "/tmp/safe"}, root.public_key)

    def test_arg_gate_all_values(self, keys):
        """None as arg gate value means all values trigger."""
        root, holder, approver = keys
        w = _mint_gated(
            root,
            holder,
            approver,
            approval_gates={"delete_file": {"path": None}},
        )
        with pytest.raises(ApprovalGateTriggered):
            _authorize(
                w, holder, "delete_file", {"path": "/anything"}, root.public_key
            )


# ============================================================================
# MintBuilder API
# ============================================================================


class TestMintBuilderApprovalGates:
    def test_mint_builder_whole_tool(self, keys):
        root, holder, approver = keys
        w = (
            Warrant.mint_builder()
            .capability("delete_file", path=Pattern("*"))
            .capability("read_file", path=Pattern("*"))
            .required_approvers([approver.public_key])
            .min_approvals(1)
            .approval_gates({"delete_file": None})
            .holder(holder.public_key)
            .ttl(3600)
            .mint(root)
        )
        _authorize(w, holder, "read_file", {"path": "/x"}, root.public_key)
        with pytest.raises(ApprovalGateTriggered):
            _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)

    def test_mint_builder_per_arg(self, keys):
        root, holder, approver = keys
        w = (
            Warrant.mint_builder()
            .capability("write_file", path=Pattern("*"))
            .required_approvers([approver.public_key])
            .min_approvals(1)
            .approval_gates({"write_file": {"path": Pattern("/etc/*")}})
            .holder(holder.public_key)
            .ttl(3600)
            .mint(root)
        )
        _authorize(w, holder, "write_file", {"path": "/tmp/ok"}, root.public_key)
        with pytest.raises(ApprovalGateTriggered):
            _authorize(
                w, holder, "write_file", {"path": "/etc/shadow"}, root.public_key
            )


# ============================================================================
# Approval gate propagation via delegation
# ============================================================================


class TestApprovalGatePropagation:
    def test_child_inherits_approval_gates(self, keys):
        """Attenuated warrants inherit parent approval gates scoped to their tool set."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={
                "delete_file": {"path": Pattern("*")},
                "read_file": {"path": Pattern("*")},
            },
            ttl_seconds=3600,
            holder=root.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"delete_file": None, "read_file": None},
        )
        child = (
            parent.grant_builder()
            .capability("read_file", path=Pattern("*"))
            .holder(child_key.public_key)
            .ttl(1800)
            .grant(root)
        )
        # Child inherits read_file gate from parent (delete_file dropped since
        # child doesn't have that capability)
        with pytest.raises(ApprovalGateTriggered):
            _authorize(
                child, child_key, "read_file", {"path": "/x"}, root.public_key
            )


# ============================================================================
# Edge cases
# ============================================================================


class TestApprovalGateEdgeCases:
    def test_no_gates_no_approval_gate_triggered(self, keys):
        """Warrant without approval gates should never raise ApprovalGateTriggered."""
        root, holder, approver = keys
        w = Warrant.issue(
            keypair=root,
            capabilities={"delete_file": {"path": Pattern("*")}},
            ttl_seconds=3600,
            holder=holder.public_key,
        )
        _authorize(w, holder, "delete_file", {"path": "/etc/passwd"}, root.public_key)

    def test_empty_approval_gate_map(self, keys):
        """Empty approval gate map means no tools are gated."""
        root, holder, approver = keys
        w = _mint_gated(root, holder, approver, approval_gates={})
        _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)


# ============================================================================
# GrantBuilder.approval_gates() — attenuation
# ============================================================================


class TestGrantBuilderApprovalGates:
    def test_grant_builder_adds_gate_on_ungated_parent(self, keys):
        """Parent has no approval gates; child adds a gate via GrantBuilder."""
        root, _holder, _approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={
                "exec": {},
                "read_file": {},
            },
            ttl_seconds=3600,
            holder=root.public_key,
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .capability("read_file")
            .holder(child_key.public_key)
            .ttl(1800)
            .approval_gates({"exec": None})
            .grant(root)
        )

        # gate fires for exec
        assert _evaluate_approval_gates(child, "exec", {})
        # gate doesn't fire for read_file (not gated)
        assert not _evaluate_approval_gates(child, "read_file", {})

    def test_grant_builder_inherits_and_adds_second_gate(self, keys):
        """Parent has exec gate; child adds read_file gate as well."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={
                "exec": {},
                "read_file": {},
            },
            ttl_seconds=3600,
            holder=root.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .capability("read_file")
            .holder(child_key.public_key)
            .ttl(1800)
            .approval_gates({"read_file": None})
            .grant(root)
        )

        # both gates should be present
        assert _evaluate_approval_gates(child, "exec", {})
        assert _evaluate_approval_gates(child, "read_file", {})

    def test_grant_builder_gate_merge_whole_tool_wins(self, keys):
        """Parent: exec=per_arg; child adds exec=whole-tool → whole wins."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=root.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": {"command": None}},  # per-arg
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .holder(child_key.public_key)
            .ttl(1800)
            .approval_gates({"exec": None})  # upgrade to whole-tool
            .grant(root)
        )

        # whole-tool wins: always fires regardless of args
        assert _evaluate_approval_gates(child, "exec", {})

    def test_grant_builder_no_gates_preserves_inherited(self, keys):
        """GrantBuilder without .approval_gates() should still preserve parent gates."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}, "read_file": {}},
            ttl_seconds=3600,
            holder=root.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .holder(child_key.public_key)
            .ttl(1800)
            .grant(root)
        )

        # inherited exec gate should be present
        assert _evaluate_approval_gates(child, "exec", {})


# ============================================================================
# IssuanceBuilder.approval_gates()
# ============================================================================


class TestIssuanceBuildApprovalGates:
    def test_issuance_builder_adds_gate(self, keys):
        """IssuanceBuilder.approval_gates() embeds gates into the issued execution warrant."""
        root, holder, approver = keys

        issuer = Warrant.issue_issuer(
            issuable_tools=["exec", "read_file"],
            keypair=root,
            ttl_seconds=3600,
            holder=root.public_key,
        )

        exec_warrant = (
            issuer.issue_execution()
            .tool("exec")
            .tool("read_file")
            .holder(holder.public_key)
            .ttl(1800)
            .approval_gates({"exec": None})
            .build(root)
        )

        assert _evaluate_approval_gates(exec_warrant, "exec", {})
        assert not _evaluate_approval_gates(exec_warrant, "read_file", {})

    def test_issuance_builder_merges_gates_from_two_calls(self, keys):
        """Calling .approval_gates() twice on IssuanceBuilder merges both gate maps."""
        root, holder, _approver = keys

        issuer = Warrant.issue_issuer(
            issuable_tools=["exec", "read_file"],
            keypair=root,
            ttl_seconds=3600,
            holder=root.public_key,
        )

        exec_warrant = (
            issuer.issue_execution()
            .tool("exec")
            .tool("read_file")
            .holder(holder.public_key)
            .ttl(1800)
            .approval_gates({"exec": None})
            .approval_gates({"read_file": None})  # second call merges
            .build(root)
        )

        assert _evaluate_approval_gates(exec_warrant, "exec", {})
        assert _evaluate_approval_gates(exec_warrant, "read_file", {})


# ============================================================================
# evaluate_approval_gates Python binding
# ============================================================================


class TestEvaluateApprovalGatesBinding:
    def test_evaluate_approval_gates_no_gate_map_returns_false(self, keys):
        root, holder, _ = keys
        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
        )
        assert not _evaluate_approval_gates(w, "exec", {})

    def test_evaluate_approval_gates_whole_tool_fires(self, keys):
        root, holder, approver = keys
        w = _mint_gated(root, holder, approver, approval_gates={"delete_file": None})
        assert _evaluate_approval_gates(w, "delete_file", {"path": "/x"})

    def test_evaluate_approval_gates_ungated_tool_returns_false(self, keys):
        root, holder, approver = keys
        w = _mint_gated(root, holder, approver, approval_gates={"delete_file": None})
        assert not _evaluate_approval_gates(w, "read_file", {"path": "/x"})

    def test_evaluate_approval_gates_per_arg_match_fires(self, keys):
        root, holder, approver = keys
        w = _mint_gated(
            root, holder, approver,
            approval_gates={"delete_file": {"path": Pattern("/etc/*")}},
        )
        assert _evaluate_approval_gates(w, "delete_file", {"path": "/etc/passwd"})

    def test_evaluate_approval_gates_per_arg_no_match_returns_false(self, keys):
        root, holder, approver = keys
        w = _mint_gated(
            root, holder, approver,
            approval_gates={"delete_file": {"path": Pattern("/etc/*")}},
        )
        assert not _evaluate_approval_gates(w, "delete_file", {"path": "/tmp/safe"})


# ============================================================================
# Enforcement integration: gate fires, no required_approvers → denied
# ============================================================================


class TestEnforcementApprovalGates:
    def test_gate_fires_no_required_approvers_denied(self, keys):
        """Gate fires but warrant has no required_approvers → denied with approval_gate_misconfigured."""
        root, holder, _approver = keys
        # Warrant with gate but WITHOUT required_approvers
        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            # No required_approvers!
            approval_gates={"exec": None},
        )
        bound = w.bind(holder)

        from tenuo._enforcement import enforce_tool_call

        result = enforce_tool_call("exec", {}, bound)
        assert not result.allowed
        assert result.error_type == "approval_gate_misconfigured"

    def test_gate_fires_valid_approval_allowed(self, keys):
        """Gate fires, valid approval provided → allowed."""
        root, holder, approver = keys
        from tenuo.approval import sign_approval
        from tenuo._enforcement import enforce_tool_call
        from tenuo_core import py_compute_request_hash as compute_hash

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},
        )
        bound = w.bind(holder)

        # Compute request hash and pre-sign an approval
        warrant_id = w.id
        holder_key = holder.public_key
        request_hash = compute_hash(warrant_id, "exec", {}, holder_key)

        from tenuo.approval import ApprovalRequest
        approval_request = ApprovalRequest(
            tool="exec",
            arguments={},
            warrant_id=warrant_id,
            request_hash=request_hash,
        )
        signed = sign_approval(approval_request, approver)

        result = enforce_tool_call("exec", {}, bound, approvals=[signed])
        assert result.allowed

    def test_gate_does_not_fire_no_approval_needed(self, keys):
        """Gate does not fire (tool not gated) → allowed without approval."""
        root, holder, approver = keys
        from tenuo._enforcement import enforce_tool_call

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}, "read_file": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},  # only exec is gated
        )
        bound = w.bind(holder)

        # read_file is not gated → should be allowed
        result = enforce_tool_call("read_file", {}, bound)
        assert result.allowed

    def test_gate_fires_no_approvals_raises_approval_required(self, keys):
        """Gate fires, no approvals provided, no handler → ApprovalRequired."""
        root, holder, approver = keys
        from tenuo.approval import ApprovalRequired
        from tenuo._enforcement import enforce_tool_call

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},
        )
        bound = w.bind(holder)

        with pytest.raises(ApprovalRequired):
            enforce_tool_call("exec", {}, bound)

    def test_gate_takes_precedence_approval_policy_skipped(self, keys):
        """When gate fires and is satisfied, approval_policy is not checked."""
        root, holder, approver = keys
        extra_approver = SigningKey.generate()

        from tenuo.approval import (
            ApprovalPolicy,
            require_approval,
            sign_approval,
            ApprovalRequest,
        )
        from tenuo._enforcement import enforce_tool_call
        from tenuo_core import py_compute_request_hash as compute_hash

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            approval_gates={"exec": None},
        )
        bound = w.bind(holder)

        # Compute request hash and pre-sign an approval
        warrant_id = w.id
        holder_key = holder.public_key
        request_hash = compute_hash(warrant_id, "exec", {}, holder_key)
        approval_request = ApprovalRequest(
            tool="exec",
            arguments={},
            warrant_id=warrant_id,
            request_hash=request_hash,
        )
        signed = sign_approval(approval_request, approver)

        # Policy requires a different approver (extra_approver), but gate uses
        # warrant's required_approvers (approver). Gate fires first.
        strict_policy = ApprovalPolicy(
            require_approval("exec"),
            trusted_approvers=[extra_approver.public_key],
        )

        # Since gate is satisfied (valid approval from warrant's approver),
        # the strict policy is never reached → allowed
        result = enforce_tool_call(
            "exec", {}, bound,
            approvals=[signed],
            approval_policy=strict_policy,
        )
        assert result.allowed
