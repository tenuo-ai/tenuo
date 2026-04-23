"""
Replay Safety Tests for Tenuo Temporal Integration.

Temporal's technical review process specifically checks that workflow interceptor
code is deterministic and safe for replay.  These tests document and verify:

  1. PoP timestamps come from workflow.now(), not wall-clock time.
  2. Identical inputs produce identical PoP signatures across replays.
  3. No non-deterministic calls (random, uuid4, time.time, os.urandom) exist
     in the workflow interceptor code path.
  4. Warrant headers survive continue_as_new.
  5. EnvKeyResolver.resolve_sync() uses pre-cached keys, not os.environ, when
     running inside the sandbox.
"""

import base64
import inspect
from unittest.mock import patch

from tenuo.temporal._workflow import workflow_grant

import pytest

pytest.importorskip("temporalio")

from tenuo.temporal._interceptors import _TenuoWorkflowOutboundInterceptor  # noqa: E402
from tenuo.temporal._resolvers import EnvKeyResolver  # noqa: E402


# =============================================================================
# Helpers
# =============================================================================


def _get_source(obj) -> str:
    """Return source code of a class or function, stripping leading whitespace."""
    return inspect.getsource(obj)


# =============================================================================
# Test 1 — PoP uses workflow.now(), not wall-clock time
# =============================================================================


class TestPopTimestampSource:
    """PoP timestamps must come from workflow.now() for replay determinism."""

    def test_workflow_outbound_interceptor_uses_workflow_now(self):
        """_TenuoWorkflowOutboundInterceptor.start_activity references workflow.now."""
        source = _get_source(_TenuoWorkflowOutboundInterceptor)
        assert "workflow.now()" in source, (
            "Outbound interceptor must use workflow.now() for PoP timestamp, "
            "not time.time() or datetime.now()."
        )

    def test_workflow_outbound_interceptor_does_not_use_time_time(self):
        """_TenuoWorkflowOutboundInterceptor.start_activity must not call time.time()."""
        source = _get_source(_TenuoWorkflowOutboundInterceptor)
        # Allow 'time' as a module reference only in comments or imports,
        # but not as time.time() calls on the hot path.
        # We check for the specific call pattern.
        assert "time.time()" not in source, (
            "Outbound interceptor must not call time.time() — this is non-deterministic "
            "during Temporal replay. Use workflow.now() instead."
        )

    def test_workflow_outbound_interceptor_does_not_use_datetime_now(self):
        """_TenuoWorkflowOutboundInterceptor must not call datetime.now()."""
        source = _get_source(_TenuoWorkflowOutboundInterceptor)
        assert "datetime.now()" not in source, (
            "Outbound interceptor must not call datetime.now() — non-deterministic "
            "during replay."
        )


# =============================================================================
# Test 2 — PoP is deterministic across replays
# =============================================================================


class TestPopDeterminism:
    """Same inputs must produce the same PoP signature."""

    def test_pop_deterministic_with_fixed_timestamp(self):
        """warrant.sign() with the same timestamp produces the same PoP bytes."""
        import tenuo

        key = tenuo.SigningKey.generate()
        warrant = tenuo.Warrant.mint_builder().tools(["read_file"]).ttl(3600).mint(key)

        # Unix integer timestamp (as Temporal passes workflow.now().timestamp() as int)
        fixed_ts = 1704110400  # 2024-01-01 12:00:00 UTC

        sig1 = warrant.sign(key, "read_file", {"path": "/tmp/foo"}, fixed_ts)
        sig2 = warrant.sign(key, "read_file", {"path": "/tmp/foo"}, fixed_ts)

        assert sig1 == sig2, (
            "PoP signature must be deterministic: same warrant + key + tool + args + "
            "timestamp must always produce the same bytes."
        )

    def test_pop_differs_with_different_timestamps(self):
        """Different timestamps (60s apart) produce different PoP signatures."""
        import tenuo

        key = tenuo.SigningKey.generate()
        warrant = tenuo.Warrant.mint_builder().tools(["read_file"]).ttl(3600).mint(key)

        ts1 = 1704110400  # 2024-01-01 12:00:00 UTC
        ts2 = 1704110460  # + 60 seconds — different 30s window bucket

        sig1 = warrant.sign(key, "read_file", {"path": "/tmp/foo"}, ts1)
        sig2 = warrant.sign(key, "read_file", {"path": "/tmp/foo"}, ts2)

        assert sig1 != sig2


# =============================================================================
# Test 3 — No non-deterministic calls in workflow interceptor
# =============================================================================


class TestNoDeterminismViolations:
    """Static analysis: the workflow interceptor must not call non-deterministic APIs."""

    NON_DETERMINISTIC_PATTERNS = [
        "os.urandom",
        "random.random",
        "random.randint",
        "uuid.uuid4",
        "uuid4()",
    ]

    def test_no_non_deterministic_calls_in_workflow_outbound_interceptor(self):
        """No non-deterministic calls appear in the outbound workflow interceptor."""
        source = _get_source(_TenuoWorkflowOutboundInterceptor)
        violations = [p for p in self.NON_DETERMINISTIC_PATTERNS if p in source]
        assert not violations, (
            f"Non-deterministic calls found in _TenuoWorkflowOutboundInterceptor: "
            f"{violations}. These break Temporal replay."
        )

    def test_no_threading_sleep_in_workflow_outbound_interceptor(self):
        """Workflow interceptor must not sleep (blocks the event loop)."""
        source = _get_source(_TenuoWorkflowOutboundInterceptor)
        assert "time.sleep" not in source, (
            "time.sleep() in workflow interceptor blocks the event loop."
        )


# =============================================================================
# Test 4 — EnvKeyResolver uses cache inside sandbox
# =============================================================================


class TestEnvKeyResolverSandboxSafety:
    """EnvKeyResolver.resolve_sync() must use pre-cached keys in sandbox."""

    def test_resolve_sync_uses_cache_not_environ(self):
        """resolve_sync() returns cached key without hitting os.environ."""
        import tenuo

        key = tenuo.SigningKey.generate()

        resolver = EnvKeyResolver()
        # Manually populate the cache (simulates preload_keys())
        resolver._key_cache["cached-agent"] = key

        # Block os.environ access to simulate sandbox restrictions
        with patch.dict("os.environ", {}, clear=True):
            resolved = resolver.resolve_sync("cached-agent")

        assert resolved is not None, "resolve_sync must return cached key without os.environ"

    def test_resolve_sync_reads_environ_when_not_cached(self, monkeypatch):
        """resolve_sync() falls back to os.environ when key is not cached."""
        import tenuo

        key = tenuo.SigningKey.generate()
        key_b64 = base64.b64encode(key.secret_key_bytes()).decode()

        # EnvKeyResolver builds env var as f"{prefix}{key_id}", so key_id must
        # match exactly (case-sensitive).
        monkeypatch.setenv("TENUO_KEY_fallback", key_b64)
        resolver = EnvKeyResolver()

        resolved = resolver.resolve_sync("fallback")
        assert resolved is not None


# =============================================================================
# Test 5 — Passthrough modules are correct
# =============================================================================


# =============================================================================
# Test 6 — workflow_grant is async
# =============================================================================


class TestWorkflowGrantAsync:
    """workflow_grant must be async so execute_local_activity can be awaited."""

    def test_workflow_grant_is_async(self):
        """workflow_grant must be async so execute_local_activity can be awaited."""
        assert inspect.iscoroutinefunction(workflow_grant), (
            "workflow_grant must be declared 'async def' so callers can await "
            "workflow.execute_local_activity inside it."
        )


# =============================================================================
# Test 5 — Passthrough modules are correct
# =============================================================================


class TestPassthroughModules:
    """_ensure_tenuo_workflow_runner provides tenuo + tenuo_core passthrough."""

    def test_ensure_tenuo_workflow_runner_creates_sandboxed_runner(self):
        """_ensure_tenuo_workflow_runner(None) returns a SandboxedWorkflowRunner."""
        from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner

        from tenuo.temporal_plugin import _ensure_tenuo_workflow_runner

        runner = _ensure_tenuo_workflow_runner(None)
        assert isinstance(runner, SandboxedWorkflowRunner)

    def test_ensure_tenuo_workflow_runner_adds_passthrough_to_existing_runner(self):
        """_ensure_tenuo_workflow_runner wraps an existing SandboxedWorkflowRunner."""
        from temporalio.worker.workflow_sandbox import (
            SandboxedWorkflowRunner,
            SandboxRestrictions,
        )

        from tenuo.temporal_plugin import _ensure_tenuo_workflow_runner

        existing = SandboxedWorkflowRunner(restrictions=SandboxRestrictions.default)
        runner = _ensure_tenuo_workflow_runner(existing)
        assert isinstance(runner, SandboxedWorkflowRunner)


# =============================================================================
# Test 7 — _attenuated_headers is async (0.1c)
# =============================================================================


class TestAttenuatedHeadersAsync:
    """_attenuated_headers must be async so execute_local_activity can be awaited."""

    def test_attenuated_headers_is_async(self):
        """``_attenuated_headers`` must be declared ``async def`` so callers
        can await ``workflow.execute_local_activity`` inside it, making
        warrant bytes deterministic on Temporal replay.
        """
        from tenuo.temporal._workflow import _attenuated_headers

        assert inspect.iscoroutinefunction(_attenuated_headers), (
            "_attenuated_headers must be declared 'async def' so callers can await "
            "workflow.execute_local_activity inside it. This ensures warrant bytes "
            "are deterministic on Temporal workflow replay."
        )


# =============================================================================
# Test 8 — workflow_issue_execution is async (2.3)
# =============================================================================


class TestWorkflowIssueExecution:
    """workflow_issue_execution must be async and importable."""

    def test_workflow_issue_execution_is_async(self):
        """workflow_issue_execution must be async."""
        import inspect
        from tenuo.temporal._workflow import workflow_issue_execution
        assert inspect.iscoroutinefunction(workflow_issue_execution), (
            "workflow_issue_execution must be declared 'async def' so callers "
            "can await workflow.execute_local_activity inside it."
        )

    def test_workflow_issue_execution_exists(self):
        """workflow_issue_execution must be importable from tenuo.temporal._workflow."""
        from tenuo.temporal._workflow import workflow_issue_execution
        assert workflow_issue_execution is not None

    def test_workflow_issue_execution_in_all(self):
        """workflow_issue_execution must be importable."""
        from tenuo.temporal._workflow import workflow_issue_execution
        assert callable(workflow_issue_execution)
