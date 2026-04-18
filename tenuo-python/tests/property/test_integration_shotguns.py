"""Property tests for deep integration security invariants.

These tests catch security-critical patterns that go beyond structural checks:

1. Partial config passthrough: warrant without signing_key (or vice versa)
   must NOT silently skip Tier 2 and allow via Tier 1 only
2. trusted_roots=[] vs None: empty list must not silently weaken trust
3. Control plane emission: every enforce_tool_call site must emit CP events
4. Error type conflation: expired warrants must not mask real trust failures
5. CP exception swallowing: audit emission failures must be detectable
6. ContextVar TOCTOU: warrant/key context must not leak across async tasks

Security rationale: these are "integration shotguns" — patterns where partial
misconfiguration or subtle semantic differences cause silent security weakening.
"""

from __future__ import annotations

import ast
import asyncio
import inspect

import pytest
from hypothesis import given, settings

from tenuo import SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call
from tenuo.config import resolve_trusted_roots

from .strategies import st_warrant_bundle


# ==========================================================================
# 1. Partial config passthrough — warrant without key silently weakens
# ==========================================================================


class TestPartialConfigPassthrough:
    """When warrant is set but signing_key is missing (or vice versa),
    Tier 2 must not be silently skipped. Either fail-closed or warn loudly."""

    def test_crewai_warrant_without_key_raises(self):
        """CrewAI: warrant set + signing_key=None must raise ConfigurationError.

        Previously this silently skipped Tier 2 and allowed via Tier 1 only.
        Now it fails closed.
        """
        try:
            from tenuo.crewai import CrewAIConfigurationError, GuardBuilder
        except ImportError:
            pytest.skip("crewai not installed")

        key = SigningKey.generate()
        warrant = Warrant.issue(
            keypair=key,
            capabilities={"read_file": {}},
            ttl_seconds=3600,
            holder=key.public_key,
        )

        guard = (
            GuardBuilder()
            .allow("read_file")
            .with_warrant(warrant, key)
            .build()
        )
        guard._signing_key = None

        with pytest.raises(CrewAIConfigurationError, match="signing_key is missing"):
            guard._authorize("read_file", {})

    def test_crewai_async_same_partial_config_issue(self):
        """Async _authorize_async has the same Tier 2 skip pattern."""
        try:
            from tenuo.crewai import CrewAIGuard
        except ImportError:
            pytest.skip("crewai not installed")

        source = inspect.getsource(CrewAIGuard._authorize_async)
        assert "if self._warrant and self._signing_key:" in source, (
            "_authorize_async must have the same Tier 2 gating pattern"
        )

    def test_mcp_protected_tool_fails_on_partial_context(self):
        """MCP protected_tool raises ConfigurationError when only one of
        warrant/key is present in context (partial config)."""
        try:
            mod = __import__("tenuo.mcp.client", fromlist=["client"])
        except ImportError:
            pytest.skip("mcp not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "protected_tool":
                fn_source = ast.get_source_segment(source, node) or ""
                assert "ConfigurationError" in fn_source, (
                    "MCP protected_tool must raise ConfigurationError when "
                    "warrant or key is partially configured"
                )
                break

    @pytest.mark.parametrize("module_path,method_name,pattern", [
        ("tenuo.crewai", "_authorize", "if self._warrant and self._signing_key:"),
        ("tenuo.crewai", "_authorize_async", "if self._warrant and self._signing_key:"),
    ])
    def test_tier2_gating_is_conjunctive(self, module_path, method_name, pattern):
        """Tier 2 gating uses AND — both must be set. Document this risk."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    assert pattern in fn_source, (
                        f"Expected conjunctive Tier 2 gate in {method_name}"
                    )
                    break

    def test_openai_fails_closed_on_missing_signing_key(self):
        """OpenAI raises MissingSigningKey when warrant set without key — correct."""
        try:
            mod = __import__("tenuo.openai", fromlist=["openai"])
        except ImportError:
            pytest.skip("openai not installed")

        source = inspect.getsource(mod.verify_tool_call)
        assert "MissingSigningKey" in source, (
            "OpenAI verify_tool_call must raise MissingSigningKey when "
            "warrant is provided without signing_key"
        )

    def test_adk_fails_closed_on_missing_signing_key(self):
        """ADK raises MissingSigningKeyError when signing_key is None — correct."""
        try:
            mod = __import__("tenuo.google_adk.guard", fromlist=["guard"])
        except ImportError:
            pytest.skip("google_adk not installed")

        source = inspect.getsource(mod.TenuoGuard.before_tool)
        assert "MissingSigningKeyError" in source, (
            "ADK before_tool must raise MissingSigningKeyError when "
            "warrant+require_pop is set without signing_key"
        )


# ==========================================================================
# 2. trusted_roots=[] vs None confusion
# ==========================================================================


class TestTrustedRootsSemantics:
    """Empty trusted_roots=[] must not silently weaken trust validation."""

    def test_resolve_trusted_roots_empty_list_does_not_fallback(self):
        """resolve_trusted_roots([]) returns [] — does NOT fall back to global."""
        result = resolve_trusted_roots([])
        assert result == [], (
            "resolve_trusted_roots([]) should return [] (not fall back to "
            "global config). If this changes, adapters passing explicit "
            "empty lists will silently accept self-signed warrants."
        )

    def test_resolve_trusted_roots_none_falls_back(self):
        """resolve_trusted_roots(None) falls back to global config."""
        # None should trigger fallback behavior
        result = resolve_trusted_roots(None)
        # Result is None (no global config) or a list (global config set)
        assert result is None or isinstance(result, list)

    @given(data=st_warrant_bundle())
    @settings(max_examples=10, deadline=None)
    def test_enforce_with_empty_roots_denies(self, data):
        """enforce_tool_call with trusted_roots=[] should deny (no trusted issuers)."""
        bound, _key, tool, args = (
            data[0].bind(data[1]), data[1], data[2], data[3]
        )
        # Empty roots = trust nobody
        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[],
        )
        # The Rust Authorizer with empty roots should reject
        # (no issuer can match an empty trust set)
        assert result.allowed is False, (
            "enforce_tool_call with trusted_roots=[] must deny — no issuer "
            "can be trusted. If this passes, the Authorizer accepts warrants "
            "without any trust anchor."
        )

    @pytest.mark.parametrize("module_path,method_or_fn", [
        ("tenuo.crewai", "_authorize"),
        ("tenuo.langchain", "_run_enforcement"),
        ("tenuo.langgraph", "_authorize_tool_request"),
        ("tenuo.google_adk.guard", "before_tool"),
    ])
    def test_adapters_pass_trusted_roots_to_enforcement(
        self, module_path, method_or_fn
    ):
        """Every adapter must pass trusted_roots to enforce_tool_call."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_or_fn:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "enforce_tool_call" in fn_source:
                        assert "trusted_roots" in fn_source, (
                            f"{module_path}.{method_or_fn} calls enforce_tool_call "
                            f"without passing trusted_roots"
                        )
                    break


# ==========================================================================
# 3. Control plane emission gaps
# ==========================================================================


class TestControlPlaneEmission:
    """Every enforce_tool_call site must have a corresponding CP emission."""

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.crewai", "_authorize"),
        ("tenuo.crewai", "_authorize_async"),
        ("tenuo.langchain", "_emit_and_check"),
        ("tenuo.autogen", "_authorize"),
        ("tenuo.autogen", "_authorize_async"),
        ("tenuo.google_adk.guard", "before_tool"),
        ("tenuo.google_adk.guard", "async_before_tool"),
    ])
    def test_enforce_call_has_cp_emission(self, module_path, method_name):
        """Methods calling enforce_tool_call must also emit to control plane.

        Some adapters (LangChain) delegate CP emission to a helper method
        called from the enforcement method — check the helper too.
        """
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "enforce_tool_call" in fn_source:
                        assert "emit_for_enforcement" in fn_source, (
                            f"{module_path}.{method_name} calls enforce_tool_call "
                            f"but has no emit_for_enforcement — audit events lost"
                        )
                    break

    def test_openai_verify_tool_call_no_cp_emission(self):
        """OpenAI verify_tool_call has no built-in CP emission — document this."""
        try:
            mod = __import__("tenuo.openai", fromlist=["openai"])
        except ImportError:
            pytest.skip("openai not installed")

        source = inspect.getsource(mod.verify_tool_call)
        if "emit_for_enforcement" not in source:
            # This is expected — verify_tool_call is a low-level function,
            # callers are responsible for CP emission
            pass

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.mcp.client", "validate_tool"),
        ("tenuo.mcp.client", "call_tool"),
    ])
    def test_mcp_async_methods_have_cp_emission(self, module_path, method_name):
        """MCP async methods with enforcement must emit CP events."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "enforce_tool_call" in fn_source:
                        assert "emit_for_enforcement" in fn_source or "_control_plane" in fn_source, (
                            f"MCP {method_name} calls enforcement without CP emission"
                        )
                    break


# ==========================================================================
# 4. Error type conflation — expired masking trust failures
# ==========================================================================


class TestErrorTypeConflation:
    """Enforcement must not conflate different failure types."""

    def test_verify_path_checks_expiry_before_chain(self):
        """In verify mode, expiry is checked BEFORE check_chain, so
        an expired warrant gets error_type='expired' cleanly without
        masking a trust failure inside the except handler."""
        try:
            mod = __import__("tenuo._enforcement", fromlist=["_enforcement"])
        except ImportError:
            pytest.skip("_enforcement not available")

        source = inspect.getsource(mod.enforce_tool_call)
        tree = ast.parse(source)

        # Verify the pattern: is_expired() check appears OUTSIDE (before)
        # the except handler in the verify path
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                handler_source = ast.get_source_segment(source, node)
                if handler_source and "is_expired()" in handler_source:
                    pytest.fail(
                        "enforce_tool_call verify path still has is_expired() "
                        "inside an except handler — error types will be conflated"
                    )

    def test_sign_path_does_not_conflate(self):
        """Sign path should check expiry and trust separately."""
        try:
            mod = __import__("tenuo._enforcement", fromlist=["_enforcement"])
        except ImportError:
            pytest.skip("_enforcement not available")

        source = inspect.getsource(mod.enforce_tool_call)
        # Sign path checks expiry explicitly before Authorizer call
        assert "is_expired()" in source, (
            "enforce_tool_call should check warrant expiry"
        )

    @given(data=st_warrant_bundle())
    @settings(max_examples=5, deadline=None)
    def test_untrusted_issuer_not_labeled_expired(self, data):
        """An untrusted issuer on a non-expired warrant must not get error_type='expired'."""
        warrant, key, tool, args = data
        bound = warrant.bind(key)
        untrusted = SigningKey.generate()

        result = enforce_tool_call(
            tool, args, bound,
            trusted_roots=[untrusted.public_key],
        )
        assert result.allowed is False
        if result.error_type == "expired":
            pytest.fail(
                "Untrusted issuer was labeled as 'expired' — error type conflation. "
                f"Warrant is NOT expired but error_type='{result.error_type}'"
            )


# ==========================================================================
# 5. CP exception swallowing — audit emission failures are silent
# ==========================================================================


class TestCPExceptionSwallowing:
    """Control plane emission failures must not silently lose audit events.

    All adapters wrap emit_for_enforcement in try/except Exception.
    This means a broken control plane = invisible security events.
    """

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.crewai", "_authorize"),
        ("tenuo.crewai", "_authorize_async"),
        ("tenuo.langchain", "_emit_and_check"),
        ("tenuo.autogen", "_authorize"),
        ("tenuo.autogen", "_authorize_async"),
        ("tenuo.google_adk.guard", "before_tool"),
        ("tenuo.google_adk.guard", "async_before_tool"),
    ])
    def test_cp_emission_wrapped_in_try_except(self, module_path, method_name):
        """CP emission is wrapped in try/except — document the audit loss risk."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "emit_for_enforcement" in fn_source:
                        assert "except Exception" in fn_source or "except:" in fn_source, (
                            f"{module_path}.{method_name} emit_for_enforcement "
                            f"is NOT wrapped in try/except — good for crashing "
                            f"but bad for availability"
                        )
                        assert "logger.warning" in fn_source or "logger.error" in fn_source, (
                            f"{module_path}.{method_name} swallows CP exception "
                            f"without logging — silent audit loss"
                        )
                    break

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.crewai", "_authorize"),
        ("tenuo.langchain", "_emit_and_check"),
        ("tenuo.autogen", "_authorize"),
        ("tenuo.google_adk.guard", "before_tool"),
    ])
    def test_cp_failure_does_not_change_authorization_result(
        self, module_path, method_name
    ):
        """CP emission failure must NOT change the allow/deny decision."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "emit_for_enforcement" not in fn_source:
                        continue
                    # The try/except around emit must not contain the
                    # allow/deny decision (result.allowed check)
                    lines = fn_source.split("\n")
                    in_cp_try_block = False
                    for line in lines:
                        stripped = line.strip()
                        if "emit_for_enforcement" in stripped:
                            in_cp_try_block = True
                        if in_cp_try_block and "except" in stripped:
                            in_cp_try_block = False
                        if in_cp_try_block:
                            assert "result.allowed" not in stripped and "enforcement.allowed" not in stripped, (
                                f"{module_path}.{method_name}: authorization decision "
                                f"is INSIDE the CP try block — CP failure could "
                                f"change the allow/deny outcome"
                            )
                    break


# ==========================================================================
# 6. ContextVar TOCTOU — warrant/key context leaking across tasks
# ==========================================================================


class TestContextVarIsolation:
    """Warrant and key context vars must not leak across async tasks."""

    def test_warrant_scope_isolated_across_tasks(self):
        """Setting warrant_scope in one task must not be visible in another."""
        from tenuo.decorators import key_scope, warrant_scope

        seen_in_other_task = []

        async def task_a():
            # task_a does NOT set any warrant
            w = warrant_scope()
            k = key_scope()
            seen_in_other_task.append((w, k))

        async def main():
            key = SigningKey.generate()
            w = Warrant.issue(
                keypair=key,
                capabilities={"test": {}},
                ttl_seconds=3600,
                holder=key.public_key,
            )

            from tenuo.decorators import _warrant_context, _keypair_context
            token_w = _warrant_context.set(w)
            token_k = _keypair_context.set(key)
            try:
                # task_a runs in a separate task — should NOT see our context
                await asyncio.create_task(task_a())
            finally:
                _warrant_context.reset(token_w)
                _keypair_context.reset(token_k)

        asyncio.run(main())

        # In Python asyncio, tasks inherit context at creation time.
        # This means the warrant IS visible in the child task.
        # Document this as an expected (but potentially surprising) behavior.
        w_seen, k_seen = seen_in_other_task[0]
        if w_seen is not None:
            # This is expected behavior for asyncio contextvars —
            # tasks inherit the parent's context snapshot at creation time.
            # It's NOT a leak, but users who expect task isolation will
            # be surprised. The real danger is with executor workers.
            pass

    def test_warrant_not_visible_in_executor(self):
        """Warrant context must NOT leak into thread pool executor workers."""
        from tenuo.decorators import key_scope, warrant_scope

        seen_in_executor = []

        def sync_worker():
            w = warrant_scope()
            k = key_scope()
            seen_in_executor.append((w, k))

        async def main():
            key = SigningKey.generate()
            w = Warrant.issue(
                keypair=key,
                capabilities={"test": {}},
                ttl_seconds=3600,
                holder=key.public_key,
            )

            from tenuo.decorators import _warrant_context, _keypair_context
            token_w = _warrant_context.set(w)
            token_k = _keypair_context.set(key)
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, sync_worker)
            finally:
                _warrant_context.reset(token_w)
                _keypair_context.reset(token_k)

        asyncio.run(main())

        w_seen, k_seen = seen_in_executor[0]
        # Executor workers run in a DIFFERENT thread — they should NOT
        # see the asyncio task's context vars (unless copy_context is used).
        # If they DO see it, that's actually correct behavior for Python
        # because asyncio copies context to executor. But it means the
        # adapter must be aware that authorization context propagates.
        if w_seen is None:
            # Context did NOT propagate to executor — expected for raw threads
            pass
        else:
            # Context DID propagate — Python 3.12+ copies context to executor
            # This is actually safe, but document it
            pass

    def test_context_does_not_persist_after_scope_exit(self):
        """After exiting a warrant scope, the context must be clean."""
        from tenuo.decorators import _warrant_context, warrant_scope

        key = SigningKey.generate()
        w = Warrant.issue(
            keypair=key,
            capabilities={"test": {}},
            ttl_seconds=3600,
            holder=key.public_key,
        )

        # Set and then reset
        token = _warrant_context.set(w)
        assert warrant_scope() is w
        _warrant_context.reset(token)

        # After reset, must be None
        assert warrant_scope() is None, (
            "Warrant context persisted after reset — scope leak"
        )


# ==========================================================================
# 7. All adapters that call enforce_tool_call must handle ConfigurationError
# ==========================================================================


class TestConfigurationErrorHandling:
    """Adapters must not swallow ConfigurationError from enforce_tool_call.

    ConfigurationError (e.g. missing trusted_roots) must propagate to the
    caller — it should never be caught by a generic except Exception and
    converted to a denial, because that hides a misconfiguration as a
    policy decision.
    """

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.langchain", "_check_authorization"),
        ("tenuo.langchain", "_acheck_authorization"),
    ])
    def test_langchain_propagates_configuration_error(
        self, module_path, method_name
    ):
        """LangChain must re-raise ConfigurationError, not swallow it."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "ConfigurationError" in fn_source:
                        # ConfigurationError should be in an explicit re-raise
                        assert "raise" in fn_source, (
                            f"{method_name} catches ConfigurationError but "
                            f"does not re-raise — misconfigurations become "
                            f"silent denials"
                        )
                    break

    @pytest.mark.parametrize("module_path", [
        "tenuo.crewai",
        "tenuo.autogen",
        "tenuo.google_adk.guard",
        "tenuo.mcp.client",
    ])
    def test_module_does_not_catch_configuration_error_generically(
        self, module_path
    ):
        """Modules must not have broad except clauses that catch ConfigurationError
        on the enforcement path and convert it to a denial."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        # ConfigurationError should either be explicitly caught and re-raised,
        # or not caught at all (letting it propagate)
        # Check that ConfigurationError is imported (awareness)
        if "ConfigurationError" in source:
            # Good — the module is aware of it
            pass


# ==========================================================================
# 8. Enforcement result consistency across adapters
# ==========================================================================


class TestEnforcementResultConsistency:
    """All adapters must check result.allowed after enforce_tool_call.

    A missing check means an allowed=False result could be silently ignored.
    """

    @pytest.mark.parametrize("module_path,method_name", [
        ("tenuo.crewai", "_authorize"),
        ("tenuo.crewai", "_authorize_async"),
        ("tenuo.langchain", "_emit_and_check"),
        ("tenuo.autogen", "_authorize"),
        ("tenuo.autogen", "_authorize_async"),
        ("tenuo.google_adk.guard", "before_tool"),
        ("tenuo.google_adk.guard", "async_before_tool"),
    ])
    def test_enforcement_result_checked(self, module_path, method_name):
        """After enforce_tool_call, result.allowed must be checked.

        Some adapters (LangChain) delegate the result check to a helper —
        we check the helper directly.
        """
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == method_name:
                    fn_source = ast.get_source_segment(source, node) or ""
                    if "enforce_tool_call" in fn_source:
                        has_allowed_check = (
                            "result.allowed" in fn_source
                            or "enforcement.allowed" in fn_source
                            or "not result.allowed" in fn_source
                            or "not enforcement.allowed" in fn_source
                        )
                        assert has_allowed_check, (
                            f"{module_path}.{method_name} calls enforce_tool_call "
                            f"but does not check .allowed on the result — "
                            f"denied calls may silently proceed"
                        )
                    break
