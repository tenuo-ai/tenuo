"""
End-to-end integration tests for the Tenuo-Temporal module.

Tests the full production flow using real Tenuo objects (SigningKey, Warrant,
Authorizer) with mocked Temporal infrastructure.  No running Temporal server
required.

Covers:
  - TenuoClientInterceptor header injection + module-level store
  - tenuo_execute_activity() PoP signing via warrant.sign()
  - TenuoActivityInboundInterceptor authorization (Authorizer path)
  - Constraint enforcement (authorized vs. unauthorized)
  - PoP round-trip: workflow signs -> interceptor verifies
  - Module-level store lifecycle (_workflow_headers_store, _pending_pop)
  - Audit event emission
"""

import asyncio
import base64
import pytest
from dataclasses import dataclass
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

pytest.importorskip("temporalio")

from tenuo import SigningKey, Warrant  # noqa: E402
from tenuo_core import Subpath  # noqa: E402
from tenuo.temporal import (  # noqa: E402
    TenuoInterceptor,
    TenuoInterceptorConfig,
    TenuoClientInterceptor,
    EnvKeyResolver,
    ConstraintViolation,
    tenuo_headers,
    TENUO_WARRANT_HEADER,
    TENUO_KEY_ID_HEADER,
    TENUO_POP_HEADER,
    TENUO_SIGNING_KEY_HEADER,
    TENUO_COMPRESSED_HEADER,
    _workflow_headers_store,
    _pending_pop,
    _pop_dedup_cache,
    _pop_key,
    _store_lock,
    _extract_warrant_from_headers,
    _TenuoWorkflowInboundInterceptor,
)


# -- Fixtures ----------------------------------------------------------------

@pytest.fixture
def control_key():
    return SigningKey.generate()

@pytest.fixture
def agent_key():
    return SigningKey.generate()

@pytest.fixture
def warrant(control_key, agent_key):
    return (
        Warrant.mint_builder()
        .holder(agent_key.public_key)
        .capability("read_file", path=Subpath("/tmp/demo"))
        .capability("list_directory", path=Subpath("/tmp/demo"))
        .ttl(3600)
        .mint(control_key)
    )

@pytest.fixture
def headers_dict(warrant, agent_key):
    return tenuo_headers(warrant, "agent1", agent_key)

@pytest.fixture(autouse=True)
def clean_stores():
    _workflow_headers_store.clear()
    _pending_pop.clear()
    _pop_dedup_cache.clear()
    yield
    _workflow_headers_store.clear()
    _pending_pop.clear()
    _pop_dedup_cache.clear()


# -- Helpers -----------------------------------------------------------------

@dataclass
class FakeStartWorkflowInput:
    id: str = "wf-test-001"
    headers: Optional[Dict[str, Any]] = None

@dataclass
class FakeActivityInfo:
    activity_type: str = "read_file"
    activity_id: str = "1"
    workflow_id: str = "wf-test-001"
    workflow_type: str = "TestWorkflow"
    workflow_run_id: str = "run-001"
    task_queue: str = "test-queue"
    is_local: bool = False
    attempt: int = 1

@dataclass
class FakeExecuteActivityInput:
    fn: Any = None
    args: tuple = ()
    headers: Optional[Dict[str, Any]] = None

def _populate_store(wf_id, hdict):
    raw = {}
    for k, v in hdict.items():
        raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
        if k.startswith("x-tenuo-"):
            raw[k] = raw_v
    _workflow_headers_store[wf_id] = raw

def _set_pop(wf_id, warrant, agent_key, tool, args_dict, raw_args=None):
    """Store a PoP signature in the new queue-based _pending_pop.

    raw_args: positional args tuple as passed to execute_activity (for key computation).
              Defaults to the values of args_dict.
    """
    from collections import deque
    pop = warrant.sign(agent_key, tool, args_dict)
    if raw_args is None:
        raw_args = tuple(args_dict.values())
    key = _pop_key(wf_id, tool, raw_args)
    with _store_lock:
        _pending_pop.setdefault(key, deque()).append(base64.b64encode(bytes(pop)))


def _run(coro):
    """Run a coroutine on a fresh event loop (avoids Py3.13 deprecation)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# -- TenuoClientInterceptor -------------------------------------------------

class TestTenuoClientInterceptor:
    def test_stores_headers_in_module_store(self, headers_dict):
        ci = TenuoClientInterceptor()
        ci.set_headers(headers_dict)
        nxt = MagicMock()
        nxt.start_workflow = AsyncMock(return_value="h")
        out = ci.intercept_client(nxt)
        _run(
            out.start_workflow(FakeStartWorkflowInput(id="wf-123")))
        assert "wf-123" in _workflow_headers_store
        s = _workflow_headers_store["wf-123"]
        assert TENUO_WARRANT_HEADER in s
        assert TENUO_KEY_ID_HEADER in s
        assert TENUO_SIGNING_KEY_HEADER in s

    def test_stored_warrant_roundtrips(self, warrant, headers_dict):
        ci = TenuoClientInterceptor()
        ci.set_headers(headers_dict)
        nxt = MagicMock()
        nxt.start_workflow = AsyncMock(return_value="h")
        out = ci.intercept_client(nxt)
        _run(
            out.start_workflow(FakeStartWorkflowInput(id="wf-rt")))
        extracted = _extract_warrant_from_headers(_workflow_headers_store["wf-rt"])
        assert extracted is not None
        assert extracted.id == warrant.id
        assert set(extracted.tools) == set(warrant.tools)

    def test_clear_headers_prevents_injection(self, headers_dict):
        ci = TenuoClientInterceptor()
        ci.set_headers(headers_dict)
        ci.clear_headers()
        nxt = MagicMock()
        nxt.start_workflow = AsyncMock(return_value="h")
        out = ci.intercept_client(nxt)
        _run(
            out.start_workflow(FakeStartWorkflowInput(id="wf-empty")))
        assert "wf-empty" not in _workflow_headers_store


# -- tenuo_headers() with real objects ---------------------------------------

class TestTenuoHeadersReal:
    def test_produces_valid_headers(self, warrant, agent_key):
        h = tenuo_headers(warrant, "agent1", agent_key)
        assert isinstance(h[TENUO_WARRANT_HEADER], bytes)
        assert h[TENUO_KEY_ID_HEADER] == b"agent1"
        assert h[TENUO_COMPRESSED_HEADER] == b"1"

    def test_signing_key_roundtrips(self, warrant, agent_key):
        h = tenuo_headers(warrant, "agent1", agent_key)
        raw = base64.b64decode(h[TENUO_SIGNING_KEY_HEADER])
        restored = SigningKey.from_bytes(raw)
        assert restored.public_key == agent_key.public_key

    def test_warrant_extraction_roundtrip(self, warrant, agent_key):
        h = tenuo_headers(warrant, "agent1", agent_key)
        extracted = _extract_warrant_from_headers(h)
        assert extracted.id == warrant.id


# -- PoP round-trip ----------------------------------------------------------

class TestPopRoundTrip:
    def test_sign_verify(self, warrant, agent_key, control_key):
        from tenuo_core import Authorizer
        pop = warrant.sign(agent_key, "read_file", {"path": "/tmp/demo/f.txt"})
        assert len(pop) == 64
        auth = Authorizer(trusted_roots=[control_key.public_key])
        auth.authorize(warrant, "read_file", {"path": "/tmp/demo/f.txt"}, signature=pop)

    def test_wrong_key_rejected(self, warrant, control_key):
        from tenuo_core import Authorizer
        wrong = SigningKey.generate()
        pop = warrant.sign(wrong, "read_file", {"path": "/tmp/demo/f.txt"})
        auth = Authorizer(trusted_roots=[control_key.public_key])
        with pytest.raises(Exception):
            auth.authorize(warrant, "read_file", {"path": "/tmp/demo/f.txt"}, signature=pop)

    def test_wrong_tool_rejected(self, warrant, agent_key, control_key):
        from tenuo_core import Authorizer
        pop = warrant.sign(agent_key, "read_file", {"path": "/tmp/demo/f.txt"})
        auth = Authorizer(trusted_roots=[control_key.public_key])
        with pytest.raises(Exception):
            auth.authorize(warrant, "list_directory", {"path": "/tmp/demo"}, signature=pop)


# -- Activity interceptor (Authorizer path) ----------------------------------

class TestActivityInterceptorAuthorizer:
    def _make(self, ck, events=None):
        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[ck.public_key],
            audit_callback=events.append if events is not None else None,
        )
        return TenuoInterceptor(cfg)

    def test_allows_authorized_activity(self, warrant, agent_key, control_key, headers_dict):
        events = []
        ti = self._make(control_key, events)
        wf = "wf-ok"
        _populate_store(wf, headers_dict)
        _set_pop(wf, warrant, agent_key, "read_file", {"path": "/tmp/demo/f.txt"})
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="content")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(fn=lambda path: path, args=("/tmp/demo/f.txt",))
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            r = _run(ai.execute_activity(inp))
        assert r == "content"
        assert any(e.decision == "ALLOW" for e in events)

    def test_denies_unauthorized_path(self, warrant, agent_key, control_key, headers_dict):
        events = []
        ti = self._make(control_key, events)
        wf = "wf-deny"
        _populate_store(wf, headers_dict)
        _set_pop(wf, warrant, agent_key, "read_file", {"path": "/etc/passwd"})
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(fn=lambda path: path, args=("/etc/passwd",))
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))
        assert any(e.decision == "DENY" for e in events)
        nxt.execute_activity.assert_not_called()

    def test_denies_missing_warrant(self, control_key):
        ti = self._make(control_key)
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="read_file", workflow_id="wf-none")
        inp = FakeExecuteActivityInput(fn=lambda: None, args=())
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            with pytest.raises(ConstraintViolation, match="No warrant"):
                _run(ai.execute_activity(inp))

    def test_denies_unknown_tool(self, warrant, agent_key, control_key, headers_dict):
        ti = self._make(control_key)
        wf = "wf-tool"
        _populate_store(wf, headers_dict)
        _set_pop(wf, warrant, agent_key, "delete_file", {"path": "/tmp/demo/f"})
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="delete_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(fn=lambda path: path, args=("/tmp/demo/f",))
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))


# -- Store lifecycle ---------------------------------------------------------

class TestStoreLifecycle:
    def test_pop_consumed_on_read(self, warrant, agent_key, headers_dict):
        _populate_store("wf-pop", headers_dict)
        _set_pop("wf-pop", warrant, agent_key, "read_file", {"path": "/tmp/demo/f"})
        key = _pop_key("wf-pop", "read_file", ("/tmp/demo/f",))
        assert key in _pending_pop
        with _store_lock:
            _pending_pop[key].popleft()
            if not _pending_pop[key]:
                del _pending_pop[key]
        assert key not in _pending_pop

    def test_pop_keyed_by_tool_and_args(self, warrant, agent_key, headers_dict):
        """Different (tool, args) get different slots — no collision."""
        _populate_store("wf-k", headers_dict)
        _set_pop("wf-k", warrant, agent_key, "read_file", {"path": "/tmp/demo/a"})
        _set_pop("wf-k", warrant, agent_key, "list_directory", {"path": "/tmp/demo"})
        k1 = _pop_key("wf-k", "read_file", ("/tmp/demo/a",))
        k2 = _pop_key("wf-k", "list_directory", ("/tmp/demo",))
        assert k1 != k2
        assert k1 in _pending_pop
        assert k2 in _pending_pop

    def test_workflows_isolated(self, headers_dict):
        a = {k: v for k, v in headers_dict.items() if k.startswith("x-tenuo-")}
        b = dict(a)
        b[TENUO_KEY_ID_HEADER] = b"agent2"
        _workflow_headers_store["wf-a"] = a
        _workflow_headers_store["wf-b"] = b
        assert _workflow_headers_store["wf-a"][TENUO_KEY_ID_HEADER] == b"agent1"
        assert _workflow_headers_store["wf-b"][TENUO_KEY_ID_HEADER] == b"agent2"


# -- Audit events ------------------------------------------------------------

class TestAuditEvents:
    def test_allow_event_fields(self, warrant, agent_key, control_key, headers_dict):
        events = []
        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
            audit_callback=events.append, redact_args_in_logs=False,
        )
        ti = TenuoInterceptor(cfg)
        wf = "wf-ae"
        _populate_store(wf, headers_dict)
        _set_pop(wf, warrant, agent_key, "read_file", {"path": "/tmp/demo/a.txt"})
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(fn=lambda path: path, args=("/tmp/demo/a.txt",))
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            _run(ai.execute_activity(inp))
        assert len(events) == 1
        e = events[0]
        assert e.decision == "ALLOW"
        assert e.tool == "read_file"
        assert e.warrant_id == warrant.id
        assert e.workflow_id == wf

    def test_deny_event_has_reason(self, warrant, agent_key, control_key, headers_dict):
        events = []
        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
            audit_callback=events.append,
        )
        ti = TenuoInterceptor(cfg)
        wf = "wf-de"
        _populate_store(wf, headers_dict)
        _set_pop(wf, warrant, agent_key, "read_file", {"path": "/etc/shadow"})
        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)
        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(fn=lambda path: path, args=("/etc/shadow",))
        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))
        assert len(events) == 1
        assert events[0].decision == "DENY"
        assert events[0].denial_reason


# -- Parallel activities (race condition regression) -------------------------

class TestParallelActivities:
    """Verify that parallel activities get independent PoP slots."""

    def _make(self, ck):
        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[ck.public_key],
        )
        return TenuoInterceptor(cfg)

    def test_two_different_activities_both_authorized(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """Simulates asyncio.gather(read_file(a), list_directory(b))."""
        ti = self._make(control_key)
        wf = "wf-par-1"
        _populate_store(wf, headers_dict)

        # Both PoPs stored before either activity runs (simulates gather)
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})
        _set_pop(wf, warrant, agent_key, "list_directory",
                 {"path": "/tmp/demo"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        # Activity 1: read_file
        info1 = FakeActivityInfo(
            activity_type="read_file", activity_id="1", workflow_id=wf)
        inp1 = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info1
            r1 = _run(ai.execute_activity(inp1))
        assert r1 == "ok"

        # Activity 2: list_directory
        info2 = FakeActivityInfo(
            activity_type="list_directory", activity_id="2", workflow_id=wf)
        inp2 = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info2
            r2 = _run(ai.execute_activity(inp2))
        assert r2 == "ok"

    def test_same_tool_different_args_both_authorized(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """gather(read_file(a.txt), read_file(b.txt)) — same tool, diff args."""
        ti = self._make(control_key)
        wf = "wf-par-2"
        _populate_store(wf, headers_dict)

        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/a.txt"})
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/b.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="data")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        for aid, path in [("1", "/tmp/demo/a.txt"), ("2", "/tmp/demo/b.txt")]:
            info = FakeActivityInfo(
                activity_type="read_file", activity_id=aid, workflow_id=wf)
            inp = FakeExecuteActivityInput(
                fn=lambda path: path, args=(path,))
            with patch("temporalio.activity.info") as m:
                m.return_value = info
                r = _run(ai.execute_activity(inp))
            assert r == "data"

    def test_same_tool_same_args_queued(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """Exact duplicate calls share a key — FIFO queue handles both."""
        ti = self._make(control_key)
        wf = "wf-par-3"
        _populate_store(wf, headers_dict)

        # Two identical calls
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        key = _pop_key(wf, "read_file", ("/tmp/demo/f.txt",))
        assert len(_pending_pop[key]) == 2

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="x")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        for aid in ["1", "2"]:
            info = FakeActivityInfo(
                activity_type="read_file", activity_id=aid, workflow_id=wf)
            inp = FakeExecuteActivityInput(
                fn=lambda path: path, args=("/tmp/demo/f.txt",))
            with patch("temporalio.activity.info") as m:
                m.return_value = info
                r = _run(ai.execute_activity(inp))
            assert r == "x"

        # Queue fully consumed
        assert key not in _pending_pop

    def test_no_pop_leaks_across_workflows(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """PoP for wf-A is invisible to wf-B."""
        ti = self._make(control_key)
        _populate_store("wf-A", headers_dict)
        _set_pop("wf-A", warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        # Activity runs under wf-B which has NO store entry → denial
        info = FakeActivityInfo(
            activity_type="read_file", activity_id="1", workflow_id="wf-B")
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation, match="No warrant"):
                _run(ai.execute_activity(inp))


# -- Activity retries --------------------------------------------------------

class TestActivityRetries:
    """PoP must survive retries (same tool + same args = same queue slot)."""

    def _make(self, ck):
        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[ck.public_key],
        )
        return TenuoInterceptor(cfg)

    def test_retry_with_fresh_pop(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """If the workflow re-signs before retry, a fresh PoP is available."""
        ti = self._make(control_key)
        wf = "wf-retry"
        _populate_store(wf, headers_dict)

        # First attempt — stores PoP
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="ok")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(
            activity_type="read_file", activity_id="1", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))

        # First attempt succeeds
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            _run(ai.execute_activity(inp))

        # Queue drained — simulate retry by adding another PoP
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        retry_info = FakeActivityInfo(
            activity_type="read_file", activity_id="1",
            workflow_id=wf, attempt=2)
        with patch("temporalio.activity.info") as m:
            m.return_value = retry_info
            r = _run(ai.execute_activity(inp))
        assert r == "ok"


# -- Concurrent workflows (thread safety) ------------------------------------

class TestConcurrentWorkflows:
    """Basic test that stores don't collide between concurrent workflows."""

    def test_two_workflows_independent_stores(
        self, warrant, agent_key, control_key, headers_dict
    ):
        ti_cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(ti_cfg)

        for wf in ["wf-c1", "wf-c2"]:
            _populate_store(wf, headers_dict)
            _set_pop(wf, warrant, agent_key, "read_file",
                     {"path": "/tmp/demo/f.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="data")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        # Each workflow's activity succeeds independently
        for wf in ["wf-c1", "wf-c2"]:
            info = FakeActivityInfo(
                activity_type="read_file", activity_id="1", workflow_id=wf)
            inp = FakeExecuteActivityInput(
                fn=lambda path: path, args=("/tmp/demo/f.txt",))
            with patch("temporalio.activity.info") as m:
                m.return_value = info
                r = _run(ai.execute_activity(inp))
            assert r == "data"


# -- Warrant expiration -------------------------------------------------------

class TestWarrantExpiration:
    """Expired warrants must be denied regardless of valid PoP."""

    def test_expired_warrant_denied_authorizer_path(self, agent_key, control_key):
        """Authorizer path: expired warrant is rejected even with valid PoP.

        We mint with ttl=1 and sleep so the warrant is valid at serialization
        time but expired by the time the activity interceptor runs.
        """
        import time

        expired = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/demo"))
            .ttl(1)
            .mint(control_key)
        )
        # Serialize headers while warrant is still valid
        h = tenuo_headers(expired, "agent1", agent_key)

        # Wait for expiration
        time.sleep(1.5)
        assert expired.is_expired()

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(cfg)
        wf = "wf-exp-auth"
        _populate_store(wf, h)
        _set_pop(wf, expired, agent_key, "read_file", {"path": "/tmp/demo/f"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation, match="expired"):
                _run(ai.execute_activity(inp))
        nxt.execute_activity.assert_not_called()

    def test_expired_warrant_denied_lightweight_path(self, agent_key, control_key):
        """Lightweight path (no trusted_roots): expired warrant raises WarrantExpired."""
        import time
        from tenuo.temporal import WarrantExpired

        expired = (
            Warrant.mint_builder()
            .holder(agent_key.public_key)
            .capability("read_file", path=Subpath("/tmp/demo"))
            .ttl(1)
            .mint(control_key)
        )
        h = tenuo_headers(expired, "agent1", agent_key)

        time.sleep(1.5)
        assert expired.is_expired()

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=None,  # lightweight path
        )
        ti = TenuoInterceptor(cfg)
        wf = "wf-exp-light"
        _populate_store(wf, h)

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(WarrantExpired):
                _run(ai.execute_activity(inp))
        nxt.execute_activity.assert_not_called()


# -- PoP validation edge cases -----------------------------------------------

class TestPopValidation:
    """PoP signature must match exactly — wrong key, wrong args, missing PoP."""

    def _make(self, ck):
        return TenuoInterceptor(TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[ck.public_key],
        ))

    def test_pop_signed_with_wrong_key_rejected(
        self, warrant, control_key, headers_dict
    ):
        """PoP signed by an unrelated key is rejected by the Authorizer."""
        wrong_key = SigningKey.generate()
        ti = self._make(control_key)
        wf = "wf-pop-wrong"
        _populate_store(wf, headers_dict)
        # Sign PoP with the wrong key
        _set_pop(wf, warrant, wrong_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))
        nxt.execute_activity.assert_not_called()

    def test_pop_for_wrong_args_rejected(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """PoP signed for different args than the actual call is rejected."""
        ti = self._make(control_key)
        wf = "wf-pop-args"
        _populate_store(wf, headers_dict)
        # Sign PoP for a.txt but activity will be called with b.txt
        _set_pop(wf, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/a.txt"},
                 raw_args=("/tmp/demo/b.txt",))  # key uses the actual args

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/b.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))

    def test_missing_pop_with_trusted_roots_rejected(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """Activity without PoP is rejected when trusted_roots is set."""
        ti = self._make(control_key)
        wf = "wf-no-pop"
        _populate_store(wf, headers_dict)
        # Intentionally don't call _set_pop — no PoP available

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(activity_type="read_file", workflow_id=wf)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))


# -- Concurrent workflows (full round-trip) -----------------------------------

class TestConcurrentWorkflowsFullRoundTrip:
    """Two workflows with different warrants execute activities correctly."""

    def test_different_warrants_different_scopes(self, control_key):
        """Each workflow gets its own warrant scope — no cross-contamination."""
        agent1 = SigningKey.generate()
        agent2 = SigningKey.generate()

        warrant1 = (
            Warrant.mint_builder()
            .holder(agent1.public_key)
            .capability("read_file", path=Subpath("/tmp/project-a"))
            .ttl(3600)
            .mint(control_key)
        )
        warrant2 = (
            Warrant.mint_builder()
            .holder(agent2.public_key)
            .capability("read_file", path=Subpath("/tmp/project-b"))
            .ttl(3600)
            .mint(control_key)
        )

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(cfg)

        # Populate stores for both workflows
        _populate_store("wf-A", tenuo_headers(warrant1, "a1", agent1))
        _populate_store("wf-B", tenuo_headers(warrant2, "a2", agent2))
        _set_pop("wf-A", warrant1, agent1, "read_file",
                 {"path": "/tmp/project-a/data.txt"})
        _set_pop("wf-B", warrant2, agent2, "read_file",
                 {"path": "/tmp/project-b/data.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="content")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        # wf-A reads from project-a: allowed
        info_a = FakeActivityInfo(
            activity_type="read_file", workflow_id="wf-A")
        inp_a = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/project-a/data.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info_a
            r = _run(ai.execute_activity(inp_a))
        assert r == "content"

        # wf-B reads from project-b: allowed
        info_b = FakeActivityInfo(
            activity_type="read_file", workflow_id="wf-B")
        inp_b = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/project-b/data.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info_b
            r = _run(ai.execute_activity(inp_b))
        assert r == "content"

    def test_cross_scope_denied(self, control_key):
        """wf-A's warrant can't access wf-B's path scope."""
        agent1 = SigningKey.generate()

        warrant1 = (
            Warrant.mint_builder()
            .holder(agent1.public_key)
            .capability("read_file", path=Subpath("/tmp/project-a"))
            .ttl(3600)
            .mint(control_key)
        )

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(cfg)

        _populate_store("wf-cross", tenuo_headers(warrant1, "a1", agent1))
        # PoP for an out-of-scope path
        _set_pop("wf-cross", warrant1, agent1, "read_file",
                 {"path": "/tmp/project-b/secret.txt"})

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock()
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(
            activity_type="read_file", workflow_id="wf-cross")
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/project-b/secret.txt",))
        with patch("temporalio.activity.info") as m:
            m.return_value = info
            with pytest.raises(ConstraintViolation):
                _run(ai.execute_activity(inp))
        nxt.execute_activity.assert_not_called()


# -- Distributed header propagation (workflow interceptor) --------------------

@dataclass
class FakePayload:
    """Mimics temporalio.api.common.v1.Payload for testing."""
    data: bytes = b""

@dataclass
class FakeExecuteWorkflowInput:
    type: Any = None
    run_fn: Any = None
    args: tuple = ()
    headers: Optional[Dict[str, Any]] = None

@dataclass
class FakeWorkflowInfo:
    workflow_id: str = "wf-dist-001"


class TestDistributedHeaderPropagation:
    """Simulate production: client and worker in separate processes.

    The workflow interceptor must extract Tenuo headers from
    input.headers (Temporal Payload objects delivered by the server)
    and populate _workflow_headers_store.  Without this, the activity
    interceptor has no warrant.
    """

    def _make_payload_headers(self, hdict):
        """Convert raw header dict → dict of FakePayload (simulates Temporal Payload)."""
        payloads = {}
        for k, v in hdict.items():
            raw = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                payloads[k] = FakePayload(data=raw)
        return payloads

    def test_workflow_interceptor_extracts_headers(self, warrant, agent_key):
        """Worker-only test: store is empty, headers arrive via Payload."""
        # Ensure store is empty (simulates separate process)
        assert "wf-dist-001" not in _workflow_headers_store

        h = tenuo_headers(warrant, "agent1", agent_key)
        payload_headers = self._make_payload_headers(h)

        nxt = MagicMock()
        nxt.execute_workflow = AsyncMock(return_value="done")
        nxt.init = MagicMock()

        wi = _TenuoWorkflowInboundInterceptor(nxt)

        wf_input = FakeExecuteWorkflowInput(headers=payload_headers)

        with patch("temporalio.workflow.info") as mock_info:
            mock_info.return_value = FakeWorkflowInfo(workflow_id="wf-dist-001")
            result = _run(wi.execute_workflow(wf_input))

        assert result == "done"
        # Store should have been populated then cleaned up (finally block)
        assert "wf-dist-001" not in _workflow_headers_store

    def test_workflow_interceptor_populates_store_for_activity(
        self, warrant, agent_key, control_key
    ):
        """Full round-trip: workflow interceptor → store → activity interceptor."""
        h = tenuo_headers(warrant, "agent1", agent_key)
        payload_headers = self._make_payload_headers(h)

        wf_id = "wf-dist-rt"

        # Workflow interceptor: extract headers into store, but DON'T
        # clean up (we need to test the activity interceptor reading).
        # We'll manually simulate the "before finally" state.
        with _store_lock:
            incoming = {}
            for key, payload in payload_headers.items():
                if key.startswith("x-tenuo-"):
                    incoming[key] = payload.data
            _workflow_headers_store[wf_id] = incoming

        # Verify the store has the warrant
        extracted = _extract_warrant_from_headers(
            _workflow_headers_store[wf_id]
        )
        assert extracted is not None
        assert extracted.id == warrant.id

        # Now run an activity against this store
        _set_pop(wf_id, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(cfg)

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="content")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(
            activity_type="read_file", workflow_id=wf_id)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path, args=("/tmp/demo/f.txt",))

        with patch("temporalio.activity.info") as m:
            m.return_value = info
            r = _run(ai.execute_activity(inp))
        assert r == "content"

    def test_no_tenuo_headers_leaves_store_empty(self):
        """Non-Tenuo workflow: no x-tenuo-* headers → store stays empty."""
        nxt = MagicMock()
        nxt.execute_workflow = AsyncMock(return_value="ok")
        nxt.init = MagicMock()

        wi = _TenuoWorkflowInboundInterceptor(nxt)
        # Only non-Tenuo headers
        wf_input = FakeExecuteWorkflowInput(
            headers={"x-custom-header": FakePayload(data=b"value")}
        )

        with patch("temporalio.workflow.info") as mock_info:
            mock_info.return_value = FakeWorkflowInfo(workflow_id="wf-notenuo")
            _run(wi.execute_workflow(wf_input))

        assert "wf-notenuo" not in _workflow_headers_store

    def test_payload_headers_override_stale_store(self, warrant, agent_key):
        """If client store has stale data, Payload headers take precedence."""
        wf_id = "wf-override"

        # Stale entry
        with _store_lock:
            _workflow_headers_store[wf_id] = {
                TENUO_KEY_ID_HEADER: b"stale-key"
            }

        h = tenuo_headers(warrant, "fresh-agent", agent_key)
        payload_headers = self._make_payload_headers(h)

        nxt = MagicMock()
        # Capture the store state during workflow execution
        captured = {}
        async def capture_and_return(inp):
            captured.update(_workflow_headers_store.get(wf_id, {}))
            return "done"
        nxt.execute_workflow = AsyncMock(side_effect=capture_and_return)
        nxt.init = MagicMock()

        wi = _TenuoWorkflowInboundInterceptor(nxt)
        wf_input = FakeExecuteWorkflowInput(headers=payload_headers)

        with patch("temporalio.workflow.info") as mock_info:
            mock_info.return_value = FakeWorkflowInfo(workflow_id=wf_id)
            _run(wi.execute_workflow(wf_input))

        # During execution, the key_id should be "fresh-agent", not "stale-key"
        assert captured.get(TENUO_KEY_ID_HEADER) == b"fresh-agent"


# -- Cross-worker activity header injection (outbound interceptor) -----------

class TestOutboundInterceptorHeaderInjection:
    """Verify _TenuoWorkflowOutboundInterceptor injects Tenuo headers
    into StartActivityInput so activities on remote workers receive them.
    """

    def test_activity_input_receives_headers_via_outbound(
        self, warrant, agent_key, headers_dict
    ):
        """Outbound interceptor reads store + PoP and injects into activity headers."""
        from tenuo.temporal import _TenuoWorkflowOutboundInterceptor

        wf_id = "wf-outbound"
        _populate_store(wf_id, headers_dict)
        _set_pop(wf_id, warrant, agent_key, "read_file",
                 {"path": "/tmp/demo/f.txt"})

        # Fake outbound that captures the modified input
        captured_input = {}
        class FakeNextOutbound:
            def start_activity(self, input):
                captured_input["headers"] = dict(input.headers or {})
                return AsyncMock()()

        outbound = _TenuoWorkflowOutboundInterceptor(FakeNextOutbound())

        @dataclass
        class FakeStartActivityInput:
            activity: str = "read_file"
            args: tuple = ("/tmp/demo/f.txt",)
            headers: Optional[Dict[str, Any]] = None

        inp = FakeStartActivityInput()

        with patch("temporalio.workflow.info") as mock_info:
            mock_info.return_value = FakeWorkflowInfo(workflow_id=wf_id)
            outbound.start_activity(inp)

        h = captured_input["headers"]
        assert TENUO_WARRANT_HEADER in h
        assert TENUO_KEY_ID_HEADER in h
        assert TENUO_SIGNING_KEY_HEADER in h
        assert TENUO_POP_HEADER in h

        # Verify warrant can be extracted from the injected Payload headers
        raw = {k: v.data for k, v in h.items() if hasattr(v, "data")}
        extracted = _extract_warrant_from_headers(raw)
        assert extracted is not None
        assert extracted.id == warrant.id

    def test_activity_interceptor_reads_from_input_headers(
        self, warrant, agent_key, control_key, headers_dict
    ):
        """Full cross-worker simulation: activity interceptor reads from
        input.headers (Payloads) with NO module-level store entries.
        """
        wf_id = "wf-cross-worker"

        # Store is EMPTY — simulates a different worker process.
        assert wf_id not in _workflow_headers_store

        # Build Payload headers as the outbound interceptor would
        from temporalio.api.common.v1 import Payload  # type: ignore

        raw_h = {}
        for k, v in headers_dict.items():
            raw_v = v if isinstance(v, bytes) else str(v).encode("utf-8")
            if k.startswith("x-tenuo-"):
                raw_h[k] = raw_v

        # Compute PoP manually
        pop = warrant.sign(agent_key, "read_file", {"path": "/tmp/demo/f.txt"})
        raw_h[TENUO_POP_HEADER] = base64.b64encode(bytes(pop))

        payload_headers = {k: Payload(data=v) for k, v in raw_h.items()}

        cfg = TenuoInterceptorConfig(
            key_resolver=EnvKeyResolver(), on_denial="raise",
            trusted_roots=[control_key.public_key],
        )
        ti = TenuoInterceptor(cfg)

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="remote-result")
        nxt.init = MagicMock()
        ai = ti.intercept_activity(nxt)

        info = FakeActivityInfo(
            activity_type="read_file", workflow_id=wf_id)
        inp = FakeExecuteActivityInput(
            fn=lambda path: path,
            args=("/tmp/demo/f.txt",),
            headers=payload_headers,
        )

        with patch("temporalio.activity.info") as m:
            m.return_value = info
            r = _run(ai.execute_activity(inp))
        assert r == "remote-result"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
