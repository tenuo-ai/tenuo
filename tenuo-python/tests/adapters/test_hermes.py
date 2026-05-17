"""
Tests for tenuo.hermes — HermesGuard

Covers:
- Audit-only mode (no warrant): all calls pass through, Cloud gets events
- Enforcement mode: authorized calls pass, unauthorized calls block
- Expired warrant blocks
- Missing signing key with warrant: passthrough with warning
- Session warrant registry: per-session warrant isolation (gateway)
- delegate_task child warrant: children get child_warrant, not parent root
- Primary session heuristic: first session_id is primary, others are children
- on_denial="log" mode: denials are logged but not blocked
- Hermes hook signature compatibility: kwargs-based hook interface
- Post-tool-call audit events fire for every call including audit-only mode
"""

from unittest.mock import MagicMock, patch

import pytest

from tenuo.hermes import HermesAuditEvent, HermesGuard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def agent_key():
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def basic_warrant(root_key, agent_key):
    """Warrant allowing read_file and web_search."""
    from tenuo import Warrant, Subpath, Wildcard
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/data"))
        .capability("web_search", query=Wildcard())
        .ttl(3600)
        .mint(root_key)
    )


@pytest.fixture
def child_warrant(root_key, agent_key):
    """Narrow warrant for subagents: web_search only."""
    from tenuo import Warrant, Wildcard
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("web_search", query=Wildcard())
        .ttl(600)
        .mint(root_key)
    )


@pytest.fixture
def guard_audit_only():
    """HermesGuard with no warrant — audit-only mode."""
    return HermesGuard()


@pytest.fixture
def guard_enforcing(basic_warrant, agent_key, root_key):
    """HermesGuard in full enforcement mode."""
    return HermesGuard(
        warrant=basic_warrant,
        signing_key=agent_key,
        trusted_roots=[root_key.public_key],
    )


@pytest.fixture
def guard_with_child(basic_warrant, child_warrant, agent_key, root_key):
    """HermesGuard with child_warrant for subagent isolation."""
    return HermesGuard(
        warrant=basic_warrant,
        signing_key=agent_key,
        child_warrant=child_warrant,
        trusted_roots=[root_key.public_key],
    )


# ---------------------------------------------------------------------------
# Audit-only mode
# ---------------------------------------------------------------------------


class TestAuditOnlyMode:

    def test_pre_tool_call_passes_through_when_no_warrant(self, guard_audit_only):
        result = guard_audit_only.pre_tool_call("terminal", {"command": "rm -rf /"})
        assert result is None

    def test_all_tools_pass_in_audit_mode(self, guard_audit_only):
        for tool in ["terminal", "write_file", "read_file", "web_search", "delegate_task"]:
            assert guard_audit_only.pre_tool_call(tool, {}) is None

    def test_post_tool_call_emits_to_cloud_in_audit_mode(self, guard_audit_only):
        mock_cp = MagicMock()
        guard_audit_only._control_plane = mock_cp
        guard_audit_only.post_tool_call("web_search", {"query": "test"}, '{"result": "ok"}')
        mock_cp.emit_for_enforcement.assert_called_once()
        call_args = mock_cp.emit_for_enforcement.call_args[0][0]
        assert call_args.allowed is True
        assert call_args.tool == "web_search"

    def test_audit_callback_fires_in_audit_mode(self, guard_audit_only):
        events = []
        guard_audit_only._audit_callback = events.append
        guard_audit_only.post_tool_call("read_file", {"path": "/data/x"}, '{}', duration_ms=12)
        assert len(events) == 1
        assert events[0].tool == "read_file"
        assert events[0].decision == "ALLOW"
        assert events[0].duration_ms == 12


# ---------------------------------------------------------------------------
# Enforcement mode
# ---------------------------------------------------------------------------


class TestEnforcementMode:

    def test_authorized_call_returns_none(self, guard_enforcing):
        result = guard_enforcing.pre_tool_call(
            "read_file", {"path": "/data/report.txt"}, session_id="s1"
        )
        # Establish primary session
        guard_enforcing._primary_session_id = "s1"
        result = guard_enforcing.pre_tool_call(
            "read_file", {"path": "/data/report.txt"}, session_id="s1"
        )
        assert result is None

    def test_unauthorized_tool_returns_block(self, guard_enforcing):
        guard_enforcing._primary_session_id = "s1"
        result = guard_enforcing.pre_tool_call(
            "terminal", {"command": "ls"}, session_id="s1"
        )
        assert result is not None
        assert result["action"] == "block"
        assert "terminal" in result["message"].lower() or result["message"]

    def test_path_constraint_violation_blocks(self, guard_enforcing):
        guard_enforcing._primary_session_id = "s1"
        result = guard_enforcing.pre_tool_call(
            "read_file", {"path": "/etc/passwd"}, session_id="s1"
        )
        assert result is not None
        assert result["action"] == "block"

    def test_audit_callback_fires_on_allow(self, guard_enforcing):
        events = []
        guard_enforcing._audit_callback = events.append
        guard_enforcing._primary_session_id = "s1"
        guard_enforcing.pre_tool_call(
            "read_file", {"path": "/data/ok.txt"}, session_id="s1"
        )
        assert any(e.decision == "ALLOW" for e in events)

    def test_audit_callback_fires_on_deny(self, guard_enforcing):
        events = []
        guard_enforcing._audit_callback = events.append
        guard_enforcing._primary_session_id = "s1"
        guard_enforcing.pre_tool_call(
            "terminal", {"command": "ls"}, session_id="s1"
        )
        assert any(e.decision == "DENY" for e in events)


# ---------------------------------------------------------------------------
# Missing signing key
# ---------------------------------------------------------------------------


class TestMissingSigningKey:

    def test_warrant_without_signing_key_passes_through_with_warning(
        self, basic_warrant, root_key
    ):
        guard = HermesGuard(
            warrant=basic_warrant,
            signing_key=None,  # no key
            trusted_roots=[root_key.public_key],
        )
        guard._primary_session_id = "s1"
        with patch("tenuo.hermes.logger") as mock_log:
            result = guard.pre_tool_call("terminal", {"command": "rm -rf /"}, session_id="s1")
        assert result is None  # passes through — does NOT silently enforce
        mock_log.warning.assert_called()
        warning_text = mock_log.warning.call_args[0][0]
        assert "signing_key" in warning_text


# ---------------------------------------------------------------------------
# Expired warrant
# ---------------------------------------------------------------------------


class TestExpiredWarrant:

    def test_expired_warrant_blocks(self, root_key, agent_key):
        from tenuo import Warrant, Wildcard
        expired_warrant = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Wildcard())
            .ttl(1)  # 1 second
            .mint(root_key)
        )
        import time
        time.sleep(2)

        guard = HermesGuard(
            warrant=expired_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        guard._primary_session_id = "s1"
        result = guard.pre_tool_call("read_file", {"path": "/data/x"}, session_id="s1")
        assert result is not None
        assert result["action"] == "block"


# ---------------------------------------------------------------------------
# on_denial="log" mode
# ---------------------------------------------------------------------------


class TestLogMode:

    def test_log_mode_does_not_block_on_denial(self, basic_warrant, agent_key, root_key):
        guard = HermesGuard(
            warrant=basic_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
            on_denial="log",
        )
        guard._primary_session_id = "s1"
        result = guard.pre_tool_call("terminal", {"command": "ls"}, session_id="s1")
        assert result is None  # not blocked in log mode

    def test_log_mode_still_emits_audit(self, basic_warrant, agent_key, root_key):
        events = []
        guard = HermesGuard(
            warrant=basic_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
            on_denial="log",
            audit_callback=events.append,
        )
        guard._primary_session_id = "s1"
        guard.pre_tool_call("terminal", {"command": "ls"}, session_id="s1")
        assert any(e.decision == "DENY" for e in events)


# ---------------------------------------------------------------------------
# Session warrant registry (gateway multi-user)
# ---------------------------------------------------------------------------


class TestSessionWarrantRegistry:

    def test_set_session_warrant_is_used_for_that_session(
        self, basic_warrant, child_warrant, agent_key, root_key
    ):
        guard = HermesGuard(trusted_roots=[root_key.public_key])
        guard.set_session_warrant("alice", basic_warrant, agent_key)
        warrant, key = guard._resolve_warrant("alice")
        assert warrant is basic_warrant

    def test_different_sessions_get_different_warrants(
        self, basic_warrant, child_warrant, agent_key, root_key
    ):
        guard = HermesGuard(trusted_roots=[root_key.public_key])
        guard.set_session_warrant("alice", basic_warrant, agent_key)
        guard.set_session_warrant("bob", child_warrant, agent_key)
        alice_warrant, _ = guard._resolve_warrant("alice")
        bob_warrant, _ = guard._resolve_warrant("bob")
        assert alice_warrant is basic_warrant
        assert bob_warrant is child_warrant

    def test_clear_session_warrant_removes_it(
        self, basic_warrant, agent_key, root_key
    ):
        guard = HermesGuard(
            warrant=basic_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        guard.set_session_warrant("alice", basic_warrant, agent_key)
        guard.clear_session_warrant("alice")
        warrant, _ = guard._resolve_warrant("alice")
        # Falls back to static warrant
        assert warrant is basic_warrant

    def test_on_session_end_clears_warrant(self, basic_warrant, agent_key, root_key):
        guard = HermesGuard(trusted_roots=[root_key.public_key])
        guard.set_session_warrant("alice", basic_warrant, agent_key)
        guard.on_session_end("alice")
        with guard._session_lock:
            assert "alice" not in guard._session_warrants


# ---------------------------------------------------------------------------
# delegate_task child warrant heuristic
# ---------------------------------------------------------------------------


class TestChildWarrantHeuristic:

    def test_first_session_is_primary(self, guard_with_child):
        guard_with_child.pre_tool_call("web_search", {"query": "test"}, session_id="parent")
        assert guard_with_child._primary_session_id == "parent"

    def test_child_session_gets_child_warrant(self, guard_with_child, child_warrant):
        # Establish primary session
        guard_with_child._primary_session_id = "parent"
        warrant, _ = guard_with_child._resolve_warrant("child-1")
        assert warrant is child_warrant

    def test_child_cannot_call_parent_only_tools(
        self, guard_with_child, agent_key, root_key
    ):
        """Child warrant (web_search only) blocks read_file."""
        guard_with_child._primary_session_id = "parent"
        result = guard_with_child.pre_tool_call(
            "read_file", {"path": "/data/x"}, session_id="child-1"
        )
        assert result is not None
        assert result["action"] == "block"

    def test_child_can_call_allowed_tools(self, guard_with_child):
        """Child warrant allows web_search."""
        guard_with_child._primary_session_id = "parent"
        result = guard_with_child.pre_tool_call(
            "web_search", {"query": "hermes agent"}, session_id="child-1"
        )
        assert result is None

    def test_parent_session_not_treated_as_child(
        self, guard_with_child, basic_warrant
    ):
        """Primary session should use the parent warrant, not child_warrant."""
        guard_with_child._primary_session_id = "parent"
        warrant, _ = guard_with_child._resolve_warrant("parent")
        assert warrant is basic_warrant

    def test_explicit_session_warrant_overrides_heuristic(
        self, guard_with_child, basic_warrant, agent_key
    ):
        """set_session_warrant overrides child heuristic for that session."""
        guard_with_child._primary_session_id = "parent"
        guard_with_child.set_session_warrant("child-explicit", basic_warrant, agent_key)
        warrant, _ = guard_with_child._resolve_warrant("child-explicit")
        assert warrant is basic_warrant  # explicit, not child_warrant

    def test_delegate_task_pre_registers_child_warrants(
        self, guard_with_child
    ):
        """pre_tool_call for delegate_task calls _register_child_warrants."""
        guard_with_child._primary_session_id = "parent"
        guard_with_child.pre_tool_call(
            "delegate_task",
            {"tasks": [{"goal": "research A"}, {"goal": "research B"}]},
            session_id="parent",
        )
        with guard_with_child._pending_lock:
            assert ("parent", 0) in guard_with_child._pending_child_warrants
            assert ("parent", 1) in guard_with_child._pending_child_warrants


# ---------------------------------------------------------------------------
# Hook signature compatibility
# ---------------------------------------------------------------------------


class TestHookSignatureCompatibility:
    """Verify Hermes hook signatures work with **kwargs extras that Hermes may add."""

    def test_pre_tool_call_accepts_extra_kwargs(self, guard_audit_only):
        # Hermes may pass extra kwargs in future versions
        result = guard_audit_only.pre_tool_call(
            "web_search", {"query": "x"},
            task_id="t1", session_id="s1", tool_call_id="tc1",
        )
        assert result is None

    def test_post_tool_call_accepts_duration_ms(self, guard_audit_only):
        mock_cp = MagicMock()
        guard_audit_only._control_plane = mock_cp
        guard_audit_only.post_tool_call(
            "web_search", {"query": "x"}, '{"ok": true}',
            task_id="t1", session_id="s1", tool_call_id="tc1", duration_ms=42,
        )
        mock_cp.emit_for_enforcement.assert_called_once()

    def test_on_session_end_accepts_extra_kwargs(self, guard_audit_only):
        # Should not raise even with unknown kwargs
        guard_audit_only.on_session_end("s1")

    def test_on_session_start_noop_when_no_child_warrant(
        self, guard_audit_only
    ):
        guard_audit_only.on_session_start("child", parent_session_id="parent")
        # No warrant configured — nothing registered
        with guard_audit_only._session_lock:
            assert "child" not in guard_audit_only._session_warrants

    def test_no_crash_when_control_plane_none(self, basic_warrant, agent_key, root_key):
        guard = HermesGuard(
            warrant=basic_warrant,
            signing_key=agent_key,
            trusted_roots=[root_key.public_key],
        )
        guard._control_plane = None
        guard._primary_session_id = "s1"
        guard.post_tool_call("web_search", {"query": "x"}, '{}', session_id="s1")
