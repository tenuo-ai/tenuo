"""Tests for warrant-level guard API (per-tool approval gates)."""

import time

import pytest

from tenuo import Authorizer, Pattern, SigningKey, Warrant
from tenuo.exceptions import GuardTriggered
from tenuo_core import evaluate_guards as _evaluate_guards


@pytest.fixture
def keys():
    root = SigningKey.generate()
    holder = SigningKey.generate()
    approver = SigningKey.generate()
    return root, holder, approver


def _mint_guarded(root, holder, approver, guards, capabilities=None):
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
        guards=guards,
    )


def _authorize(warrant, key, tool, args, root_pk, approvals=None):
    auth = Authorizer(trusted_roots=[root_pk])
    sig = warrant.sign(key, tool, args, int(time.time()))
    auth.authorize_one(warrant, tool, args, bytes(sig), approvals or [])


# ============================================================================
# Whole-tool guards
# ============================================================================


class TestWholeToolGuard:
    def test_unguarded_tool_allowed(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(root, holder, approver, guards={"delete_file": None})
        _authorize(w, holder, "read_file", {"path": "/tmp/x"}, root.public_key)

    def test_guarded_tool_raises_guard_triggered(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(root, holder, approver, guards={"delete_file": None})
        with pytest.raises(GuardTriggered) as exc_info:
            _authorize(w, holder, "delete_file", {"path": "/tmp/x"}, root.public_key)
        assert exc_info.value.tool == "delete_file"

    def test_multiple_tools_guarded(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(
            root,
            holder,
            approver,
            guards={"delete_file": None, "read_file": None},
        )
        with pytest.raises(GuardTriggered):
            _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)
        with pytest.raises(GuardTriggered):
            _authorize(w, holder, "read_file", {"path": "/x"}, root.public_key)


# ============================================================================
# Per-argument guards
# ============================================================================


class TestArgGuard:
    def test_matching_arg_triggers_guard(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(
            root,
            holder,
            approver,
            guards={"delete_file": {"path": Pattern("/etc/*")}},
        )
        with pytest.raises(GuardTriggered):
            _authorize(
                w, holder, "delete_file", {"path": "/etc/passwd"}, root.public_key
            )

    def test_non_matching_arg_allowed(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(
            root,
            holder,
            approver,
            guards={"delete_file": {"path": Pattern("/etc/*")}},
        )
        _authorize(w, holder, "delete_file", {"path": "/tmp/safe"}, root.public_key)

    def test_arg_guard_all_values(self, keys):
        """None as arg guard value means all values trigger."""
        root, holder, approver = keys
        w = _mint_guarded(
            root,
            holder,
            approver,
            guards={"delete_file": {"path": None}},
        )
        with pytest.raises(GuardTriggered):
            _authorize(
                w, holder, "delete_file", {"path": "/anything"}, root.public_key
            )


# ============================================================================
# MintBuilder API
# ============================================================================


class TestMintBuilderGuards:
    def test_mint_builder_whole_tool(self, keys):
        root, holder, approver = keys
        w = (
            Warrant.mint_builder()
            .capability("delete_file", path=Pattern("*"))
            .capability("read_file", path=Pattern("*"))
            .required_approvers([approver.public_key])
            .min_approvals(1)
            .guards({"delete_file": None})
            .holder(holder.public_key)
            .ttl(3600)
            .mint(root)
        )
        _authorize(w, holder, "read_file", {"path": "/x"}, root.public_key)
        with pytest.raises(GuardTriggered):
            _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)

    def test_mint_builder_per_arg(self, keys):
        root, holder, approver = keys
        w = (
            Warrant.mint_builder()
            .capability("write_file", path=Pattern("*"))
            .required_approvers([approver.public_key])
            .min_approvals(1)
            .guards({"write_file": {"path": Pattern("/etc/*")}})
            .holder(holder.public_key)
            .ttl(3600)
            .mint(root)
        )
        _authorize(w, holder, "write_file", {"path": "/tmp/ok"}, root.public_key)
        with pytest.raises(GuardTriggered):
            _authorize(
                w, holder, "write_file", {"path": "/etc/shadow"}, root.public_key
            )


# ============================================================================
# Guard propagation via delegation
# ============================================================================


class TestGuardPropagation:
    def test_child_inherits_guards(self, keys):
        """Attenuated warrants inherit parent guards scoped to their tool set."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        # Self-signed parent so chain verification works with authorize_one
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
            guards={"delete_file": None, "read_file": None},
        )
        child = (
            parent.grant_builder()
            .capability("read_file", path=Pattern("*"))
            .holder(child_key.public_key)
            .ttl(1800)
            .grant(root)
        )
        # Child inherits read_file guard from parent (delete_file dropped since
        # child doesn't have that capability)
        with pytest.raises(GuardTriggered):
            _authorize(
                child, child_key, "read_file", {"path": "/x"}, root.public_key
            )


# ============================================================================
# Edge cases
# ============================================================================


class TestGuardEdgeCases:
    def test_no_guards_no_guard_triggered(self, keys):
        """Warrant without guards should never raise GuardTriggered."""
        root, holder, approver = keys
        w = Warrant.issue(
            keypair=root,
            capabilities={"delete_file": {"path": Pattern("*")}},
            ttl_seconds=3600,
            holder=holder.public_key,
        )
        _authorize(w, holder, "delete_file", {"path": "/etc/passwd"}, root.public_key)

    def test_empty_guard_map(self, keys):
        """Empty guard map means no tools are guarded."""
        root, holder, approver = keys
        w = _mint_guarded(root, holder, approver, guards={})
        _authorize(w, holder, "delete_file", {"path": "/x"}, root.public_key)


# ============================================================================
# GrantBuilder.guards() — attenuation
# ============================================================================


class TestGrantBuilderGuards:
    def test_grant_builder_adds_guard_on_unguarded_parent(self, keys):
        """Parent has no guards; child adds a guard via GrantBuilder."""
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
            .guards({"exec": None})
            .grant(root)
        )

        # guard fires for exec
        assert _evaluate_guards(child, "exec", {})
        # guard doesn't fire for read_file (not guarded)
        assert not _evaluate_guards(child, "read_file", {})

    def test_grant_builder_inherits_and_adds_second_guard(self, keys):
        """Parent has exec guard; child adds read_file guard as well."""
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
            guards={"exec": None},
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .capability("read_file")
            .holder(child_key.public_key)
            .ttl(1800)
            .guards({"read_file": None})
            .grant(root)
        )

        # both guards should be present
        assert _evaluate_guards(child, "exec", {})
        assert _evaluate_guards(child, "read_file", {})

    def test_grant_builder_guard_merge_whole_tool_wins(self, keys):
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
            guards={"exec": {"command": None}},  # per-arg
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .holder(child_key.public_key)
            .ttl(1800)
            .guards({"exec": None})  # upgrade to whole-tool
            .grant(root)
        )

        # whole-tool wins: always fires regardless of args
        assert _evaluate_guards(child, "exec", {})

    def test_grant_builder_no_guards_preserves_inherited(self, keys):
        """GrantBuilder without .guards() should still preserve parent guards."""
        root, _holder, approver = keys
        child_key = SigningKey.generate()

        parent = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}, "read_file": {}},
            ttl_seconds=3600,
            holder=root.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            guards={"exec": None},
        )

        child = (
            parent.grant_builder()
            .capability("exec")
            .holder(child_key.public_key)
            .ttl(1800)
            .grant(root)
        )

        # inherited exec guard should be present
        assert _evaluate_guards(child, "exec", {})


# ============================================================================
# IssuanceBuilder.guards()
# ============================================================================


class TestIssuanceBuildGuards:
    def test_issuance_builder_adds_guard(self, keys):
        """IssuanceBuilder.guards() embeds guards into the issued execution warrant."""
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
            .guards({"exec": None})
            .build(root)
        )

        assert _evaluate_guards(exec_warrant, "exec", {})
        assert not _evaluate_guards(exec_warrant, "read_file", {})

    def test_issuance_builder_merges_guards_from_two_calls(self, keys):
        """Calling .guards() twice on IssuanceBuilder merges both guard maps."""
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
            .guards({"exec": None})
            .guards({"read_file": None})  # second call merges
            .build(root)
        )

        assert _evaluate_guards(exec_warrant, "exec", {})
        assert _evaluate_guards(exec_warrant, "read_file", {})


# ============================================================================
# evaluate_guards Python binding
# ============================================================================


class TestEvaluateGuardsBinding:
    def test_evaluate_guards_no_guard_map_returns_false(self, keys):
        root, holder, _ = keys
        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
        )
        assert not _evaluate_guards(w, "exec", {})

    def test_evaluate_guards_whole_tool_fires(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(root, holder, approver, guards={"delete_file": None})
        assert _evaluate_guards(w, "delete_file", {"path": "/x"})

    def test_evaluate_guards_unguarded_tool_returns_false(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(root, holder, approver, guards={"delete_file": None})
        assert not _evaluate_guards(w, "read_file", {"path": "/x"})

    def test_evaluate_guards_per_arg_match_fires(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(
            root, holder, approver,
            guards={"delete_file": {"path": Pattern("/etc/*")}},
        )
        assert _evaluate_guards(w, "delete_file", {"path": "/etc/passwd"})

    def test_evaluate_guards_per_arg_no_match_returns_false(self, keys):
        root, holder, approver = keys
        w = _mint_guarded(
            root, holder, approver,
            guards={"delete_file": {"path": Pattern("/etc/*")}},
        )
        assert not _evaluate_guards(w, "delete_file", {"path": "/tmp/safe"})


# ============================================================================
# Enforcement integration: guard fires, no required_approvers → denied
# ============================================================================


class TestEnforcementGuards:
    def test_guard_fires_no_required_approvers_denied(self, keys):
        """Guard fires but warrant has no required_approvers → denied with guard_misconfigured."""
        root, holder, _approver = keys
        # Warrant with guard but WITHOUT required_approvers
        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            # No required_approvers!
            guards={"exec": None},
        )
        bound = w.bind(holder)

        from tenuo._enforcement import enforce_tool_call

        result = enforce_tool_call("exec", {}, bound)
        assert not result.allowed
        assert result.error_type == "guard_misconfigured"

    def test_guard_fires_valid_approval_allowed(self, keys):
        """Guard fires, valid approval provided → allowed."""
        root, holder, approver = keys
        from tenuo.approval import ApprovalRequired, require_approval, sign_approval
        from tenuo._enforcement import enforce_tool_call
        from tenuo_core import py_compute_request_hash as compute_hash

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            guards={"exec": None},
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

    def test_guard_does_not_fire_no_approval_needed(self, keys):
        """Guard does not fire (tool not guarded) → allowed without approval."""
        root, holder, approver = keys
        from tenuo._enforcement import enforce_tool_call

        w = Warrant.issue(
            keypair=root,
            capabilities={"exec": {}, "read_file": {}},
            ttl_seconds=3600,
            holder=holder.public_key,
            required_approvers=[approver.public_key],
            min_approvals=1,
            guards={"exec": None},  # only exec is guarded
        )
        bound = w.bind(holder)

        # read_file is not guarded → should be allowed
        result = enforce_tool_call("read_file", {}, bound)
        assert result.allowed

    def test_guard_fires_no_approvals_raises_approval_required(self, keys):
        """Guard fires, no approvals provided, no handler → ApprovalRequired."""
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
            guards={"exec": None},
        )
        bound = w.bind(holder)

        with pytest.raises(ApprovalRequired):
            enforce_tool_call("exec", {}, bound)

    def test_guard_takes_precedence_approval_policy_skipped(self, keys):
        """When guard fires and is satisfied, approval_policy is not checked."""
        root, holder, approver = keys
        extra_approver = SigningKey.generate()

        from tenuo.approval import (
            ApprovalPolicy,
            ApprovalRequired,
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
            guards={"exec": None},
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

        # Policy requires a different approver (extra_approver), but guard uses
        # warrant's required_approvers (approver). Guard fires first.
        strict_policy = ApprovalPolicy(
            require_approval("exec"),
            trusted_approvers=[extra_approver.public_key],
        )

        # Since guard is satisfied (valid approval from warrant's approver),
        # the strict policy is never reached → allowed
        result = enforce_tool_call(
            "exec", {}, bound,
            approvals=[signed],
            approval_policy=strict_policy,
        )
        assert result.allowed
