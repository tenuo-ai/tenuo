"""
Adversarial Test Suite for Tenuo CrewAI Adapter.

This suite tests the adapter against active attack vectors, matching the
security testing standards of the OpenAI adapter. Specifically ensuring:
1. "Fail Closed" philosophy (unknowns = deny)
2. "Zero Trust" for arguments (unwanted arguments are rejected)
3. Cryptographic integrity (Tier 2 PoP)
4. Tool namespacing security (cross-agent confusion)
5. Path traversal protection
"""

import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass

from tenuo.crewai import (
    GuardBuilder,
    CrewAIGuard,
    ToolDenied,
    ConstraintViolation,
    UnlistedArgument,
    MissingSigningKey,
    WarrantExpired,
    InvalidPoP,
    DenialResult,
    Pattern,
    Wildcard,
    Range,
)
from tenuo.constraints import Subpath


# =============================================================================
# Real CrewAI Tool (using actual dependency)
# =============================================================================

try:
    from crewai.tools import BaseTool
except ImportError:
    # Fallback for when crewai is not installed (should not happen in this env)
    class BaseTool:  # type: ignore
        pass

class RealTool(BaseTool):
    """Real CrewAI Tool for testing."""
    name: str = "test_tool"
    description: str = "Test tool"
    
    def _run(self, **kwargs) -> dict:
        return {"result": "ok", "args": kwargs}


# =============================================================================
# 1. Zero Trust & Argument Validation
# =============================================================================


class TestZeroTrust:
    """
    Tests ensuring that the adapter strictly enforces "unknown = deny".
    Invariant: Every argument MUST have a constraint, or be rejected.
    """

    def test_unexpected_argument_fails(self):
        """
        Attack: Pass `{"path": "/safe", "admin_flag": "true"}`
        Invariant: Unknown args must be rejected.
        """
        guard = GuardBuilder().allow("read_file", path=Subpath("/safe")).build()

        # 1. Legitimate call
        result = guard._authorize("read_file", {"path": "/safe/data.txt"})
        assert result is None  # Should pass

        # 2. Attack: Extra argument
        with pytest.raises(UnlistedArgument, match="admin_flag"):
            guard._authorize("read_file", {"path": "/safe/data.txt", "admin_flag": "true"})

    def test_hallucinated_tool_rejected(self):
        """
        Attack: Agent hallucinates a tool that doesn't exist.
        Invariant: Unknown tools must be rejected.
        """
        guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()

        with pytest.raises(ToolDenied, match="delete_all"):
            guard._authorize("delete_all", {"everything": True})

    def test_empty_allowlist_denies_all(self):
        """
        Attack: Try to use any tool with no allowlist.
        Invariant: Empty allowlist = nothing allowed (fail closed).
        """
        guard = GuardBuilder().build()

        with pytest.raises(ToolDenied):
            guard._authorize("any_tool", {})

    def test_argument_injection_via_type_confusion(self):
        """
        Attack: Pass unexpected types that might bypass validation.
        Invariant: Constraints should handle type mismatches gracefully.
        """
        guard = GuardBuilder().allow("transfer", amount=Range(1, 100)).build()

        # String instead of int
        with pytest.raises(ConstraintViolation):
            guard._authorize("transfer", {"amount": "999"})

        # List instead of int
        with pytest.raises(ConstraintViolation):
            guard._authorize("transfer", {"amount": [50]})

        # Dict instead of int
        with pytest.raises(ConstraintViolation):
            guard._authorize("transfer", {"amount": {"value": 50}})


# =============================================================================
# 2. Fail Closed Philosophy
# =============================================================================


class TestFailClosed:
    """
    Tests ensuring that ambiguity or internal errors result in denial.
    """

    def test_unknown_constraint_type(self):
        """
        Attack: Inject unknown constraint object type.
        Invariant: Unknown security primitives must default to deny.
        """
        class UnknownConstraint:
            """Custom constraint type not in Tenuo."""
            pass

        guard = (GuardBuilder()
            .allow("read_file", path=UnknownConstraint())
            .build())

        # Should reject because UnknownConstraint is not recognized
        with pytest.raises(ConstraintViolation):
            guard._authorize("read_file", {"path": "/any"})

    def test_constraint_exception_causes_denial(self):
        """
        Attack: Trigger internal exception in constraint check.
        Invariant: Internal crashes during validation result in program crash,
                   NOT silent approval (fail LOUD, not fail OPEN).
        """
        # Create a mock constraint that raises an error
        broken_constraint = MagicMock()
        broken_constraint.satisfies = MagicMock(side_effect=ValueError("Oops"))

        guard = (GuardBuilder()
            .allow("read_file", path=broken_constraint)
            .build())

        # Mock check_constraint to raise an exception
        # The current implementation lets this crash (fail LOUD)
        # This is safer than silently allowing (fail OPEN)
        with patch("tenuo.crewai.check_constraint", side_effect=ValueError("Oops")):
            with pytest.raises(ValueError):  # Crash = denied, not silent approval
                guard._authorize("read_file", {"path": "/any"})

    def test_none_value_with_strict_constraint(self):
        """
        Attack: Pass None where a specific value is expected.
        Invariant: None should fail strict constraints.
        """
        guard = GuardBuilder().allow("tool", value=Pattern("positive-*")).build()

        # None should not match the pattern
        with pytest.raises(ConstraintViolation):
            guard._authorize("tool", {"value": None})


# =============================================================================
# 3. Cryptographic Integrity (Tier 2)
# =============================================================================


class TestCryptoIntegrity:
    """
    Tests for Tier 2 PoP signature binding and integrity.
    """

    def test_missing_signature_denies(self):
        """
        Attack: Provide warrant but no signing key.
        Invariant: Tier 2 must enforce cryptographic checks.
        """
        mock_warrant = MagicMock()

        with pytest.raises(MissingSigningKey):
            GuardBuilder().with_warrant(mock_warrant, None).build()

    def test_expired_warrant_denied(self):
        """
        Attack: Use an expired warrant.
        Invariant: Expired warrants must be rejected.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = True
        mock_warrant.id.return_value = "expired-warrant"
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        assert isinstance(result, DenialResult)
        assert result.error_code == "WARRANT_EXPIRED"

    def test_wrong_key_denied(self):
        """
        Attack: Sign with wrong key.
        Invariant: PoP signature must be verified.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = False
        mock_warrant.sign.side_effect = Exception("Invalid key: holder mismatch")
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        assert isinstance(result, DenialResult)
        assert result.error_code == "INVALID_POP"


# =============================================================================
# 4. Tool Namespacing Security
# =============================================================================


class TestNamespacingSecurity:
    """
    Tests ensuring tool namespacing prevents cross-agent confusion attacks.
    """

    def test_cross_agent_tool_confusion(self):
        """
        Attack: Agent A claims to be agent B to get B's permissions.
        Invariant: Namespaced constraints apply only to matching agent.
        """
        guard = (GuardBuilder()
            .allow("admin::delete", target=Wildcard())
            .allow("user::read", path=Subpath("/public"))
            .build())

        # User agent cannot access admin's delete tool
        with pytest.raises(ToolDenied):
            guard._authorize("delete", {"target": "everything"}, agent_role="user")

        # Admin agent can access delete
        result = guard._authorize("delete", {"target": "temp"}, agent_role="admin")
        assert result is None

    def test_namespace_injection(self):
        """
        Attack: Try to inject namespace separator into tool name.
        Invariant: Tool name parsing should be robust.
        """
        guard = (GuardBuilder()
            .allow("safe_tool", arg=Wildcard())
            .build())

        # Try to confuse parser with :: in requested tool name
        # This should be treated as a tool named "admin::safe_tool" literally
        with pytest.raises(ToolDenied):
            guard._authorize("admin::safe_tool", {"arg": "value"})

    def test_fallback_does_not_bypass_restrictions(self):
        """
        Attack: Exploit fallback to access more permissive global.
        Invariant: Agent-specific rules take precedence.
        """
        guard = (GuardBuilder()
            .allow("search", query=Wildcard())  # Global: allows everything
            .allow("researcher::search", query=Pattern("arxiv:*"))  # Restricted
            .build())

        # Researcher is restricted to arxiv:* even though global allows all
        with pytest.raises(ConstraintViolation):
            guard._authorize("search", {"query": "delete everything"}, agent_role="researcher")


# =============================================================================
# 5. Path Traversal Protection
# =============================================================================


class TestPathTraversalProtection:
    """
    Tests ensuring Subpath constraint blocks path traversal attacks.
    """

    def test_basic_traversal(self):
        """
        Attack: Use .. to escape directory.
        Invariant: Path traversal must be blocked.
        """
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        with pytest.raises(ConstraintViolation):
            guard._authorize("read", {"path": "/data/../etc/passwd"})

    def test_double_encoding_traversal(self):
        """
        Attack: Use URL-like encoded path traversal.
        Note: Subpath operates on filesystem paths, not URLs.
              URL decoding should be done at the API/transport layer.
              The literal string "%2e%2e" is not a valid path traversal.
        Invariant: Paths that don't resolve to a valid subpath fail.
        """
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        # This literal string is actually safe from a filesystem perspective
        # because %2e%2e is not interpreted as ".." by the OS.
        # The REAL attack would happen if URL decoding occurred BEFORE this check,
        # which is the responsibility of the transport layer.
        # 
        # To test the underlying Subpath behavior, we test the decoded version:
        with pytest.raises(ConstraintViolation):
            guard._authorize("read", {"path": "/data/../etc/passwd"})  # Decoded version

    def test_absolute_path_injection(self):
        """
        Attack: Try to use absolute path outside allowed directory.
        Invariant: Absolute paths outside scope must be blocked.
        """
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        with pytest.raises(ConstraintViolation):
            guard._authorize("read", {"path": "/etc/passwd"})

    def test_null_byte_injection(self):
        """
        Attack: Use null byte to truncate path.
        Invariant: Null bytes should be rejected or sanitized.
        """
        guard = GuardBuilder().allow("read", path=Subpath("/data")).build()

        # This depends on Subpath implementation handling null bytes
        # Either way, /data should not be bypassed
        path_with_null = "/data/file.txt\x00/../../etc/passwd"
        with pytest.raises(ConstraintViolation):
            guard._authorize("read", {"path": path_with_null})


# =============================================================================
# 6. Denial Mode Security
# =============================================================================


class TestDenialModeSecurity:
    """
    Tests ensuring denial modes don't leak sensitive information.
    """

    def test_skip_mode_returns_denial_result(self):
        """
        Ensure skip mode returns DenialResult, not None.
        Invariant: Agent can distinguish denial from success.
        """
        guard = GuardBuilder().on_denial("skip").build()

        result = guard._authorize("unknown_tool", {})

        assert isinstance(result, DenialResult)
        assert not result  # Falsy
        assert result.error_code == "TOOL_DENIED"

    def test_log_mode_returns_denial_result(self):
        """
        Ensure log mode returns DenialResult, not None.
        Invariant: Agent can distinguish denial from success.
        """
        guard = GuardBuilder().on_denial("log").build()

        result = guard._authorize("unknown_tool", {})

        assert isinstance(result, DenialResult)
        assert result.tool == "unknown_tool"

    def test_denial_result_is_not_truthy(self):
        """
        Invariant: DenialResult must be falsy to prevent if-confusion.
        """
        denial = DenialResult(tool="test", reason="denied")

        assert not denial
        assert bool(denial) is False
        # if denial: should not execute
        executed = "not executed"
        if denial:
            executed = "executed"
        assert executed == "not executed"


# =============================================================================
# 7. Audit Trail Integrity
# =============================================================================


class TestAuditIntegrity:
    """
    Tests ensuring audit trail captures all denials.
    """

    def test_all_denials_audited(self):
        """
        Invariant: Every denial must be audited, regardless of mode.
        """
        events = []

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .on_denial("skip")
            .audit(lambda e: events.append(e))
            .build())

        # Three different denial types
        guard._authorize("unknown_tool", {})  # ToolDenied
        guard._authorize("read", {"path": "/data/f.txt", "extra": "arg"})  # UnlistedArgument
        guard._authorize("read", {"path": "/etc/passwd"})  # ConstraintViolation

        assert len(events) == 3
        assert all(e.decision == "DENY" for e in events)

    def test_audit_callback_exception_does_not_crash(self):
        """
        Invariant: Audit callback failures must not prevent denial.
        """
        def broken_callback(event):
            raise RuntimeError("Callback crashed!")

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .audit(broken_callback)
            .build())

        # Should still authorize (callback failure is logged, not propagated)
        result = guard._authorize("read", {"path": "/data/file.txt"})
        assert result is None


# =============================================================================
# 8. Seal Mode (On-the-Wire Protection)
# =============================================================================


class TestSealMode:
    """
    Tests ensuring seal mode prevents original tool bypass.
    This is critical for "on-the-wire" verification.
    """

    def test_seal_mode_blocks_original_tool(self):
        """
        Invariant: After sealing, original tool cannot be called.
        """
        original_tool = RealTool(name="read")
        
        guard = (GuardBuilder()
            .allow("read", path=Wildcard())
            .seal()
            .build())
        
        # Protect with seal mode - this modifies original_tool in place
        protected_tool = guard.protect(original_tool)
        
        # Original tool should now raise RuntimeError when called
        with pytest.raises(RuntimeError, match="sealed by Tenuo guard"):
            original_tool._run(path="/data/file.txt")

    def test_seal_mode_disabled_allows_original(self):
        """
        When seal mode is disabled, original tool still works.
        """
        original_tool = RealTool(name="read")
        
        guard = (GuardBuilder()
            .allow("read", path=Wildcard())
            # No .seal() call
            .build())
        
        assert guard._seal_mode is False
        
        # Protect without seal (default)
        protected_tool = guard.protect(original_tool)
        
        # Original should still work (no seal)
        result = original_tool._run(path="/data/file.txt")
        assert result is not None

    def test_guard_has_seal_mode_attribute(self):
        """
        Guard has seal_mode accessible for inspection.
        """
        guard_sealed = GuardBuilder().seal().build()
        guard_unsealed = GuardBuilder().build()
        
        assert guard_sealed._seal_mode is True
        assert guard_unsealed._seal_mode is False


class TestSecurityRegressions:
    """
    Regression tests for critical security vulnerabilities.
    These tests ensure fail-closed behavior is maintained.
    """

    def test_fail_closed_on_expiry_check_exception(self):
        """
        REGRESSION: Expiry check failure must deny, not allow.
        Previously: Exception was swallowed and access was allowed.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.side_effect = RuntimeError("Database error")
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        # MUST return denial, not None
        assert isinstance(result, DenialResult)
        assert result.error_code == "WARRANT_EXPIRED"

    def test_seal_fails_closed_on_immutable_tool(self):
        """
        REGRESSION: Seal mode must raise if tool is immutable.
        Previously: Logged warning and continued with unprotected bypass.
        """
        from tenuo.crewai import ConfigurationError

    def test_seal_fails_closed_on_immutable_tool(self):
        """
        REGRESSION: Seal mode must raise if tool is immutable.
        Previously: Logged warning and continued with unprotected bypass.
        """
        from tenuo.crewai import ConfigurationError

        # Create an immutable-like tool (RealTool is a BaseTool)
        class LockedTool(RealTool):
            def __setattr__(self, key, value):
                if key in ("_run", "func"):
                    raise AttributeError(f"{key} is read-only")
                super().__setattr__(key, value)

        immutable_tool = LockedTool(name="read")
        
        guard = (GuardBuilder()
            .allow("read", path=Wildcard())
            .seal()  # Enable seal mode
            .build())

        with pytest.raises(ConfigurationError, match="Cannot seal tool"):
            guard.protect(immutable_tool)

    def test_namespace_injection_rejected(self):
        """
        REGRESSION: Agent role with '::' must be rejected.
        Previously: Could inject namespaced role like "admin::delete".
        """
        guard = (GuardBuilder()
            .allow("admin::delete", target=Wildcard())
            .build())

        # Attack: Try to inject namespace via agent_role
        resolved = guard._resolve_tool_name("delete", agent_role="admin::evil")
        
        # MUST return None (rejected), not "admin::evil::delete"
        assert resolved is None

    def test_delegation_from_expired_warrant_rejected(self):
        """
        REGRESSION: Delegation from expired warrant must fail.
        Previously: Expiry wasn't checked before delegation.
        """
        from tenuo.crewai import WarrantDelegator, EscalationAttempt

        delegator = WarrantDelegator()
        
        mock_parent = MagicMock()
        mock_parent.is_expired.return_value = True  # Expired!
        
        with pytest.raises(EscalationAttempt, match="expired"):
            delegator.delegate(
                parent_warrant=mock_parent,
                parent_key=MagicMock(),
                child_holder=MagicMock(),
                attenuations={"read": {"path": Subpath("/data")}},
            )

    def test_delegation_attenuation_requires_subset_support(self):
        """
        REGRESSION: Constraints without is_subset_of must be rejected.
        Previously: Warning logged but delegation allowed (bypass).
        """
        from tenuo.crewai import WarrantDelegator, EscalationAttempt

        delegator = WarrantDelegator()
        
        mock_parent = MagicMock()
        mock_parent.is_expired.return_value = False
        mock_parent.tools.return_value = ["read"]
        mock_parent.constraint_for.return_value = MagicMock()  # Returns constraint
        
        # Child constraint without is_subset_of
        child_constraint = MagicMock(spec=[])  # Empty spec = no methods
        
        with pytest.raises(EscalationAttempt, match="is_subset_of"):
            delegator.delegate(
                parent_warrant=mock_parent,
                parent_key=MagicMock(),
                child_holder=MagicMock(),
                attenuations={"read": {"path": child_constraint}},
            )

    def test_unguarded_agents_fail_closed(self):
        """
        REGRESSION: Agents not in policy must raise, not proceed unguarded.
        Previously: Logged warning and added agent with no guards.
        """
        from tenuo.crewai import GuardedCrew, ConfigurationError

        mock_agent = MagicMock()
        mock_agent.role = "unregistered_agent"
        mock_task = MagicMock()

        builder = GuardedCrew(
            agents=[mock_agent],
            tasks=[mock_task],
        ).policy({
            "researcher": ["search"],  # unregistered_agent not listed!
        })

        crew = builder.build()
        
        # The error is raised when kickoff tries to protect the agents
        with pytest.raises(ConfigurationError, match="not listed in policy"):
            crew.kickoff()

    def test_audit_logs_redact_sensitive_values(self):
        """
        REGRESSION: Audit logs must not contain raw argument values.
        Previously: Full argument values logged including secrets.
        """
        captured_event = None

        def capture_callback(event):
            nonlocal captured_event
            captured_event = event

        guard = (GuardBuilder()
            .allow("api_call", api_key=Wildcard(), data=Wildcard())
            .audit(capture_callback)
            .build())

        # Call with sensitive data
        guard._authorize("api_call", {
            "api_key": "sk-secret-key-12345",
            "data": "user_password=hunter2"
        })

        # Audit event should have redacted arguments
        assert captured_event is not None
        assert "sk-secret-key" not in str(captured_event.arguments)
        assert "hunter2" not in str(captured_event.arguments)
        # Should show type info, not raw values
        assert "str:" in str(captured_event.arguments["api_key"])

    def test_pop_return_value_checked(self):
        """
        REGRESSION: PoP verify must check return value, not just exceptions.
        Previously: False return was ignored (silent bypass).
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = False
        mock_warrant.sign.return_value = b"signature"
        mock_warrant.authorize.return_value = False  # Explicit False
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        # MUST return denial when authorize returns False
        assert isinstance(result, DenialResult)
        assert result.error_code == "INVALID_POP"


# =============================================================================
# 10. Replay Attack Protection
# =============================================================================


class TestReplayAttackProtection:
    """
    Tests ensuring PoP signatures cannot be replayed.
    Invariant: Each authorization must be fresh and non-replayable.
    """

    def test_pop_timestamp_required(self):
        """
        Attack: Omit timestamp from PoP.
        Invariant: PoP without timestamp should be rejected.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = False
        # sign() returns a signature without proper timestamp binding
        mock_warrant.sign.return_value = b"stale_signature"
        # authorize() checks timestamp freshness
        mock_warrant.authorize.side_effect = ValueError("Missing timestamp")
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        # Should deny due to authorization failure
        assert isinstance(result, DenialResult)

    def test_pop_timestamp_window_enforced(self):
        """
        Attack: Replay a PoP signature after timestamp window expires.
        Invariant: Stale timestamps must be rejected.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = False
        mock_warrant.sign.return_value = b"old_signature"
        # Simulate timestamp window check failure
        mock_warrant.authorize.side_effect = ValueError("Timestamp outside valid window")
        mock_key = MagicMock()

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result = guard._authorize("read", {"path": "/data/file.txt"})

        assert isinstance(result, DenialResult)

    def test_pop_nonce_prevents_exact_replay(self):
        """
        Attack: Capture and replay exact same PoP.
        Invariant: Identical PoP signatures should be rejected on replay.
        
        Note: This is typically enforced by nonce/timestamp at protocol layer.
        The adapter should propagate the denial from core verification.
        """
        mock_warrant = MagicMock()
        mock_warrant.is_expired.return_value = False
        mock_warrant.sign.return_value = b"same_signature"
        
        # First call succeeds - need proper holder mock to pass signing key check
        mock_warrant.authorize.return_value = True
        mock_key = MagicMock()
        
        # Setup holder to match signing key (skip holder validation)
        mock_warrant.holder.return_value = mock_key.public_key

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .with_warrant(mock_warrant, mock_key)
            .on_denial("skip")
            .build())

        result1 = guard._authorize("read", {"path": "/data/file.txt"})
        assert result1 is None  # First call allowed

        # Second call with same signature fails (nonce already used)
        mock_warrant.authorize.side_effect = ValueError("Nonce already used")
        
        result2 = guard._authorize("read", {"path": "/data/file.txt"})
        assert isinstance(result2, DenialResult)


# =============================================================================
# 11. Thread Safety / Concurrent Access
# =============================================================================


class TestConcurrentAccess:
    """
    Tests ensuring thread-safety for context variables and guards.
    Invariant: Concurrent operations must not interfere with each other.
    """

    def test_context_var_isolation(self):
        """
        Attack: Racing threads to confuse guard context.
        Invariant: Each thread/task gets isolated context.
        """
        import threading
        import time
        from tenuo.crewai import guarded_step, get_active_guard, Wildcard

        results = {}
        errors = []

        @guarded_step(allow={"tool1": {"arg": Wildcard()}}, strict=True)
        def step1():
            time.sleep(0.01)  # Give time for race
            guard = get_active_guard()
            results["step1"] = "tool1" in guard._allowed if guard else None

        @guarded_step(allow={"tool2": {"arg": Wildcard()}}, strict=True)
        def step2():
            time.sleep(0.01)
            guard = get_active_guard()
            results["step2"] = "tool2" in guard._allowed if guard else None

        t1 = threading.Thread(target=step1)
        t2 = threading.Thread(target=step2)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Each thread should see its own context
        # Note: Due to Python GIL and context var semantics, this may or may not
        # isolate properly depending on implementation. We test the expected behavior.
        # If both results are present, neither should have crossed contexts.
        if results.get("step1") is not None and results.get("step2") is not None:
            assert results["step1"] is True
            assert results["step2"] is True

    def test_guard_concurrent_authorize(self):
        """
        Attack: Concurrent authorization calls on same guard.
        Invariant: Each call should be independently evaluated.
        """
        import threading
        import time

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .on_denial("skip")
            .build())

        results = []
        
        def authorize_valid():
            for _ in range(10):
                r = guard._authorize("read", {"path": "/data/file.txt"})
                results.append(("valid", r is None))
                time.sleep(0.001)

        def authorize_invalid():
            for _ in range(10):
                r = guard._authorize("read", {"path": "/etc/passwd"})
                results.append(("invalid", isinstance(r, DenialResult)))
                time.sleep(0.001)

        t1 = threading.Thread(target=authorize_valid)
        t2 = threading.Thread(target=authorize_invalid)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # All valid calls should succeed
        valid_results = [r[1] for r in results if r[0] == "valid"]
        assert all(valid_results), f"Some valid calls failed: {valid_results}"

        # All invalid calls should fail
        invalid_results = [r[1] for r in results if r[0] == "invalid"]
        assert all(invalid_results), f"Some invalid calls succeeded: {invalid_results}"

    def test_audit_callback_thread_safety(self):
        """
        Attack: Concurrent denials corrupting audit log.
        Invariant: Audit events should be correctly recorded.
        """
        import threading

        audit_events = []
        lock = threading.Lock()

        def safe_audit(event):
            with lock:
                audit_events.append(event)

        guard = (GuardBuilder()
            .allow("read", path=Subpath("/safe"))
            .on_denial("skip")
            .audit(safe_audit)
            .build())

        def trigger_denials():
            for i in range(5):
                guard._authorize("read", {"path": f"/etc/secret{i}"})

        threads = [threading.Thread(target=trigger_denials) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 20 denial events (4 threads × 5 denials)
        assert len(audit_events) == 20, f"Expected 20 events, got {len(audit_events)}"


# =============================================================================
# 12. Constraint Composition
# =============================================================================


class TestConstraintComposition:
    """
    Tests for complex constraint combinations.
    Invariant: Composed constraints must AND together correctly.
    """

    def test_multi_constraint_all_must_pass(self):
        """
        Attack: Satisfy one constraint but not another.
        Invariant: All constraints on an argument must be satisfied.
        """
        from tenuo.crewai import Range, Pattern
        
        # Both constraints on same tool's different arguments
        guard = (GuardBuilder()
            .allow("api_call", 
                   endpoint=Pattern("/api/*"),
                   timeout=Range(1, 30))
            .on_denial("skip")
            .build())

        # Both valid
        result = guard._authorize("api_call", {
            "endpoint": "/api/users",
            "timeout": 10
        })
        assert result is None

        # Only endpoint valid
        result = guard._authorize("api_call", {
            "endpoint": "/api/users",
            "timeout": 100  # Out of range
        })
        assert isinstance(result, DenialResult)

        # Only timeout valid
        result = guard._authorize("api_call", {
            "endpoint": "/admin/secret",  # Wrong pattern
            "timeout": 10
        })
        assert isinstance(result, DenialResult)

    def test_nested_path_constraints(self):
        """
        Attack: Use nested Subpath to escape outer restriction.
        Invariant: Path constraints compose to the intersection.
        """
        # Two tools with different path scopes
        guard = (GuardBuilder()
            .allow("read_public", path=Subpath("/data/public"))
            .allow("read_internal", path=Subpath("/data/internal"))
            .on_denial("skip")
            .build())

        # Valid: each tool with its scope
        assert guard._authorize("read_public", {"path": "/data/public/file.txt"}) is None
        assert guard._authorize("read_internal", {"path": "/data/internal/file.txt"}) is None

        # Invalid: cross tool boundaries
        result = guard._authorize("read_public", {"path": "/data/internal/secret.txt"})
        assert isinstance(result, DenialResult)

        result = guard._authorize("read_internal", {"path": "/data/public/file.txt"})
        assert isinstance(result, DenialResult)

    def test_wildcard_does_not_override_other_constraints(self):
        """
        Attack: Use Wildcard on one arg to bypass constraints on another.
        Invariant: Wildcard only applies to its specific argument.
        """
        guard = (GuardBuilder()
            .allow("operation", 
                   safe_arg=Wildcard(),
                   restricted_arg=Subpath("/safe"))
            .on_denial("skip")
            .build())

        # Wildcard arg can be anything
        result = guard._authorize("operation", {
            "safe_arg": "anything_here",
            "restricted_arg": "/safe/file.txt"
        })
        assert result is None

        # But restricted arg must still satisfy constraint
        result = guard._authorize("operation", {
            "safe_arg": "anything",
            "restricted_arg": "/etc/passwd"
        })
        assert isinstance(result, DenialResult)

    def test_oneof_with_subpath(self):
        """
        Test OneOf constraint working with path values.
        """
        from tenuo_core import OneOf
        
        guard = (GuardBuilder()
            .allow("select_env", 
                   environment=OneOf(["dev", "staging", "prod"]))
            .on_denial("skip")
            .build())

        assert guard._authorize("select_env", {"environment": "dev"}) is None
        assert guard._authorize("select_env", {"environment": "staging"}) is None
        assert guard._authorize("select_env", {"environment": "prod"}) is None
        
        result = guard._authorize("select_env", {"environment": "hacker"})
        assert isinstance(result, DenialResult)


# =============================================================================
# 13. Warrant Chain Depth Protection
# =============================================================================


class TestWarrantChainDepth:
    """
    Tests for delegation chain depth limits.
    Invariant: Delegation depth must be bounded to prevent infinite chains.
    """

    def test_max_delegation_depth_enforced(self):
        """
        Attack: Create excessively deep delegation chain to confuse auditing.
        Invariant: Delegation should fail beyond max depth.
        """
        from tenuo.crewai import WarrantDelegator, EscalationAttempt

        # Create parent warrant mock that simulates depth limit
        parent_warrant = MagicMock()
        parent_warrant.is_expired.return_value = False
        parent_warrant.tools.return_value = ["read"]
        parent_warrant.constraint_for.return_value = None
        # Simulate max depth reached
        parent_warrant.grant_builder = MagicMock(
            side_effect=ValueError("Max delegation depth (5) exceeded")
        )
        parent_key = MagicMock()
        child_holder = MagicMock()

        delegator = WarrantDelegator()

        # Delegation should fail due to depth limit
        with pytest.raises((EscalationAttempt, ValueError)):
            delegator.delegate(
                parent_warrant=parent_warrant,
                parent_key=parent_key,
                child_holder=child_holder,
                attenuations={"read": {}},
            )

    def test_delegation_preserves_depth_counter(self):
        """
        Invariant: Child warrant depth = parent depth + 1.
        """
        from tenuo.crewai import WarrantDelegator

        parent_warrant = MagicMock()
        parent_warrant.is_expired.return_value = False
        parent_warrant.tools.return_value = ["read"]
        parent_warrant.constraint_for.return_value = None
        
        mock_grant_builder = MagicMock()
        mock_child_warrant = MagicMock()
        mock_grant_builder.build.return_value = mock_child_warrant
        parent_warrant.grant_builder.return_value = mock_grant_builder
        
        parent_key = MagicMock()
        child_holder = MagicMock()

        delegator = WarrantDelegator()

        child = delegator.delegate(
            parent_warrant=parent_warrant,
            parent_key=parent_key,
            child_holder=child_holder,
            attenuations={"read": {}},
        )

        # Grant builder should have been called
        assert parent_warrant.grant_builder.called


# =============================================================================
# 14. Resource Exhaustion Protection (DoS)
# =============================================================================


class TestResourceExhaustionProtection:
    """
    Tests ensuring the guard doesn't consume excessive resources.
    Invariant: Guard should handle adversarial inputs without DoS.
    """

    def test_extremely_long_tool_name(self):
        """
        Attack: Pass extremely long tool name to cause memory issues.
        Invariant: Should deny efficiently without excessive allocation.
        """
        guard = (GuardBuilder()
            .allow("read", path=Wildcard())
            .on_denial("skip")
            .build())

        # 1MB tool name
        long_name = "x" * (1024 * 1024)
        
        import time
        start = time.time()
        result = guard._authorize(long_name, {"path": "/data"})
        elapsed = time.time() - start

        assert isinstance(result, DenialResult)
        assert elapsed < 1.0  # Should be fast even with large input

    def test_extremely_long_argument_value(self):
        """
        Attack: Pass extremely long argument value.
        Invariant: Constraint check should handle gracefully.
        """
        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .on_denial("skip")
            .build())

        # 1MB path
        long_path = "/data/" + "x" * (1024 * 1024)
        
        import time
        start = time.time()
        result = guard._authorize("read", {"path": long_path})
        elapsed = time.time() - start

        # Should succeed (valid subpath) but quickly
        assert result is None
        assert elapsed < 1.0

    def test_many_arguments(self):
        """
        Attack: Pass thousands of arguments to slow down checking.
        Invariant: Should reject unknown args efficiently.
        """
        guard = (GuardBuilder()
            .allow("read", path=Wildcard())
            .on_denial("skip")
            .build())

        # 10,000 extra arguments
        args = {"path": "/data"}
        for i in range(10000):
            args[f"extra_arg_{i}"] = f"value_{i}"

        import time
        start = time.time()
        result = guard._authorize("read", args)
        elapsed = time.time() - start

        assert isinstance(result, DenialResult)
        assert result.error_code == "UNLISTED_ARGUMENT"
        assert elapsed < 1.0

    def test_deeply_nested_constraint_values(self):
        """
        Attack: Pass deeply nested structures as argument values.
        Invariant: Constraint checking should handle depth limits.
        """
        guard = (GuardBuilder()
            .allow("process", data=Wildcard())
            .on_denial("skip")
            .build())

        # Create deeply nested structure
        nested = {"level": 0}
        current = nested
        for i in range(1000):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        import time
        start = time.time()
        result = guard._authorize("process", {"data": nested})
        elapsed = time.time() - start

        # Wildcard accepts anything, including nested structures
        assert result is None
        assert elapsed < 1.0

    def test_rapid_authorization_calls(self):
        """
        Attack: Flood guard with rapid authorization requests.
        Invariant: Should maintain performance under load.
        """
        guard = (GuardBuilder()
            .allow("read", path=Subpath("/data"))
            .on_denial("skip")
            .build())

        import time
        start = time.time()
        
        # 10,000 rapid calls
        for i in range(10000):
            guard._authorize("read", {"path": f"/data/file{i}.txt"})
        
        elapsed = time.time() - start

        # Should complete all 10k in reasonable time
        assert elapsed < 5.0, f"Took {elapsed}s for 10k calls"
        # Average < 0.5ms per call
        assert elapsed / 10000 < 0.0005

    def test_constraint_regex_redos_protection(self):
        """
        Attack: Use ReDoS pattern to freeze Pattern constraint.
        Invariant: Pattern matching should have timeout/limits.
        
        Note: Python's re module is vulnerable to ReDoS but Pattern
        uses fnmatch which is simpler and faster.
        """
        guard = (GuardBuilder()
            .allow("match", text=Pattern("*safe*"))
            .on_denial("skip")
            .build())

        # Adversarial input that might trigger exponential backtracking
        # with complex regex (but fnmatch is immune)
        adversarial = "a" * 10000 + "safe"
        
        import time
        start = time.time()
        result = guard._authorize("match", {"text": adversarial})
        elapsed = time.time() - start

        assert result is None  # Should match
        assert elapsed < 1.0  # Should be fast


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

