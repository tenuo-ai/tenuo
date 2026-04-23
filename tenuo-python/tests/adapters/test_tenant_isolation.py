"""Tenant-isolation regressions for the Temporal adapter.

Two real, production-grade failure modes — both invisible to interceptor-shape
unit tests — motivated this module:

1. ``workflow_id`` collisions in workflow-internal stores.
   Two workers running in the same Python process for different namespaces
   (``tenant-a`` and ``tenant-b``) may each execute a workflow named
   ``"onboarding-wf"``. Keying internal stores by ``workflow_id`` would let
   one tenant overwrite the other's entry and leak headers or config across
   the namespace boundary. The fix: key by the server-assigned, globally
   unique ``run_id``.

2. ``_worker_config`` global overwrite.
   A single module-level ``_worker_config`` slot gets overwritten when a
   second worker registers its plugin in the same process, and the first
   worker's internal-mint activity then signs with the second worker's
   key resolver. The fix: a ``task_queue → config`` registry and
   ``activity.info().task_queue`` lookup inside the mint activity.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("temporalio")


from tenuo.temporal._state import (  # noqa: E402
    _clear_worker_config,
    _get_worker_config,
    _pending_activity_approvals,
    _pending_activity_fn,
    _set_worker_config,
    _store_lock,
    _worker_configs,
    _workflow_config_store,
    _workflow_headers_store,
)


# ── Helpers ──────────────────────────────────────────────────────────────

class _FakeWorkflowInfo:
    def __init__(self, workflow_id: str, run_id: str) -> None:
        self.workflow_id = workflow_id
        self.run_id = run_id


class _FakeActivityInfo:
    def __init__(
        self,
        activity_type: str = "__tenuo_internal_mint",
        task_queue: str = "",
        workflow_id: str = "wf",
        workflow_run_id: str = "run",
    ) -> None:
        self.activity_type = activity_type
        self.task_queue = task_queue
        self.workflow_id = workflow_id
        self.workflow_run_id = workflow_run_id
        self.attempt = 1
        self.is_local = True
        self.activity_id = "1"


@pytest.fixture(autouse=True)
def _clean_stores():
    """Reset all module-level stores before and after each test.

    These stores are intentionally global (PyO3 passthrough is mandatory for
    Tenuo modules, so a per-test isolation layer is not available). The
    fixture guarantees tests can assume a clean slate even when a previous
    test left state behind.
    """
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()
        _pending_activity_approvals.clear()
        _pending_activity_fn.clear()
    _clear_worker_config()
    yield
    with _store_lock:
        _workflow_headers_store.clear()
        _workflow_config_store.clear()
        _pending_activity_approvals.clear()
        _pending_activity_fn.clear()
    _clear_worker_config()


# =============================================================================
# 1. Cross-namespace / cross-run isolation (run_id keying)
# =============================================================================


class TestRunIdKeyingIsolatesTenants:
    """Same ``workflow_id`` + different ``run_id`` must never collide.

    Prior to the run_id keying fix, two workers in the same Python process
    serving different namespaces could each execute a workflow named
    ``"onboarding-wf"`` and the second inbound interceptor would silently
    overwrite the first tenant's Tenuo header entry.
    """

    def test_same_workflow_id_different_run_ids_do_not_overwrite(self):
        """Two concurrent workflows with the same ``workflow_id`` but distinct
        ``run_id``s each see their own headers."""
        from tenuo.temporal._interceptors import _TenuoWorkflowInboundInterceptor
        from tenuo.temporal._constants import TENUO_WARRANT_HEADER

        class _Payload:
            def __init__(self, data: bytes) -> None:
                self.data = data

        class _Input:
            def __init__(self, headers: Dict[str, Any]) -> None:
                self.headers = headers

        async def _run_inbound(run_id: str, warrant_bytes: bytes) -> None:
            nxt = MagicMock()
            nxt.execute_workflow = AsyncMock(return_value=None)
            nxt.init = MagicMock()

            cls = type(
                "_Inbound",
                (_TenuoWorkflowInboundInterceptor,),
                {"_config": None},
            )
            inbound = cls(next_interceptor=nxt)
            inp = _Input(headers={TENUO_WARRANT_HEADER: _Payload(warrant_bytes)})
            info = _FakeWorkflowInfo(workflow_id="onboarding-wf", run_id=run_id)

            captured: Dict[str, Dict[str, bytes]] = {}

            async def _capture_store(*args, **kwargs):
                with _store_lock:
                    captured[run_id] = dict(
                        _workflow_headers_store.get(run_id, {})
                    )
                return None

            nxt.execute_workflow = AsyncMock(side_effect=_capture_store)

            with patch("temporalio.workflow.info", return_value=info):
                await inbound.execute_workflow(inp)
            return captured[run_id]

        import asyncio as _asyncio

        loop = _asyncio.new_event_loop()
        try:
            snap_a = loop.run_until_complete(_run_inbound("run-tenant-a", b"warrant-A"))
            snap_b = loop.run_until_complete(_run_inbound("run-tenant-b", b"warrant-B"))
        finally:
            loop.close()

        # Each run saw its own warrant bytes inside the store even though the
        # workflow_id was identical — no cross-tenant leakage.
        assert snap_a[TENUO_WARRANT_HEADER] == b"warrant-A"
        assert snap_b[TENUO_WARRANT_HEADER] == b"warrant-B"

        # Final state: both runs cleaned up in their ``finally`` block.
        with _store_lock:
            assert "run-tenant-a" not in _workflow_headers_store
            assert "run-tenant-b" not in _workflow_headers_store
            assert "onboarding-wf" not in _workflow_headers_store

    def test_client_outbound_does_not_write_workflow_id_keyed_entry(self, tmp_path):
        """The client-side interceptor must not populate the workflow-internal
        store keyed by ``workflow_id`` — that would collide across namespaces.
        """
        from tenuo.temporal._client import TenuoClientInterceptor

        class _FakeInput:
            def __init__(self, id: str) -> None:
                self.id = id
                self.headers: Dict[str, Any] = {}

        ci = TenuoClientInterceptor()
        ci.set_headers_for_workflow("onboarding-wf", {"x-tenuo-warrant": b"A"})

        nxt = MagicMock()
        nxt.start_workflow = AsyncMock(return_value="h")
        out = ci.intercept_client(nxt)

        import asyncio as _asyncio

        loop = _asyncio.new_event_loop()
        try:
            loop.run_until_complete(out.start_workflow(_FakeInput(id="onboarding-wf")))
        finally:
            loop.close()

        with _store_lock:
            assert "onboarding-wf" not in _workflow_headers_store, (
                "Client-side write to _workflow_headers_store would collide "
                "with a workflow named the same in a different namespace."
            )


# =============================================================================
# 2. Multi-worker task_queue routing for _tenuo_internal_mint_activity
# =============================================================================


class TestWorkerConfigIsRoutedByTaskQueue:
    """``_tenuo_internal_mint_activity`` must use the config registered for the
    activity's task queue, not whichever config was registered last.

    Prior to the ``_worker_configs`` registry, two workers in the same
    process would share a single ``_worker_config`` slot: Worker B's
    registration overwrote Worker A's, and Worker A's mint activity then
    signed with Worker B's key resolver. That manifested either as a
    ``KeyResolutionError`` (different key ids between tenants) or, worse,
    a silently mis-signed child warrant.
    """

    def test_set_and_get_roundtrip_by_task_queue(self):
        cfg_a = MagicMock(name="config-A")
        cfg_b = MagicMock(name="config-B")

        _set_worker_config(cfg_a, task_queue="tq-a")
        _set_worker_config(cfg_b, task_queue="tq-b")

        assert _get_worker_config("tq-a") is cfg_a
        assert _get_worker_config("tq-b") is cfg_b

    def test_multiple_workers_do_not_overwrite_each_other(self):
        cfg_a = MagicMock(name="config-A")
        cfg_b = MagicMock(name="config-B")

        _set_worker_config(cfg_a, task_queue="tq-a")
        _set_worker_config(cfg_b, task_queue="tq-b")

        assert _worker_configs == {"tq-a": cfg_a, "tq-b": cfg_b}

    def test_lookup_is_exact_match_no_fallback(self):
        """Strict routing: ``None``, empty, or non-matching task_queue
        must all return ``None`` regardless of how many configs are
        registered. There is no "last registered wins" or "if only one
        config, use it" fallback — that was exactly the class of bug
        the run_id / task_queue split was meant to close.
        """
        _set_worker_config(MagicMock(name="a"), task_queue="tq-a")
        _set_worker_config(MagicMock(name="b"), task_queue="tq-b")

        assert _get_worker_config(None) is None
        assert _get_worker_config("") is None
        assert _get_worker_config("tq-missing") is None

    def test_set_worker_config_rejects_empty_task_queue(self):
        """``task_queue=""`` or ``None`` at registration time is a
        programmer error — the whole point of the kwarg is to key the
        config under a queue. Failing loud at registration beats silently
        swallowing the registration and failing at mint time.
        """
        with pytest.raises(ValueError, match="non-empty task_queue"):
            _set_worker_config(MagicMock(), task_queue="")

    def test_single_registration_lookup_is_still_exact_match(self):
        """Even with just one registration, lookup is exact-match —
        there is no "singleton fallback" path.
        """
        cfg = MagicMock(name="only")
        _set_worker_config(cfg, task_queue="the-only-queue")
        assert _get_worker_config("the-only-queue") is cfg
        assert _get_worker_config(None) is None
        assert _get_worker_config("something-else") is None

    def test_mint_activity_uses_task_queue_to_select_config(self):
        """Simulate two workers in one process: each mint activity must
        resolve its own worker's config via ``activity.info().task_queue``."""
        from tenuo.temporal._observability import _MintRequest
        from tenuo.temporal._state import _pending_mint_capabilities
        from tenuo.temporal._workflow import _tenuo_internal_mint_activity

        if _tenuo_internal_mint_activity is None:
            pytest.skip("temporalio not installed; mint activity unavailable")

        signing_key_a = MagicMock(name="signing-key-A")
        signing_key_b = MagicMock(name="signing-key-B")

        resolver_a = MagicMock()
        resolver_a.resolve_sync = MagicMock(return_value=signing_key_a)
        resolver_b = MagicMock()
        resolver_b.resolve_sync = MagicMock(return_value=signing_key_b)

        cfg_a = MagicMock(name="cfg-A", key_resolver=resolver_a)
        cfg_b = MagicMock(name="cfg-B", key_resolver=resolver_b)

        _set_worker_config(cfg_a, task_queue="tq-a")
        _set_worker_config(cfg_b, task_queue="tq-b")

        cap_ref = "tenant-routing-ref"
        with _store_lock:
            _pending_mint_capabilities[cap_ref] = {"read_file": {}}

        minted: List[Any] = []

        class _FakeParentWarrant:
            def __init__(self, tag: str) -> None:
                self._tag = tag

            def attenuate(
                self, *, capabilities, signing_key, ttl_seconds
            ):
                minted.append((self._tag, signing_key))
                out = MagicMock()
                out.to_bytes = MagicMock(return_value=b"minted-" + self._tag.encode())
                return out

        class _FakeWarrantClass:
            @staticmethod
            def from_bytes(data):
                return _FakeParentWarrant(data.decode())

        async def _invoke_via_task_queue(task_queue: str, parent: bytes) -> bytes:
            req = _MintRequest(
                kind="attenuate",
                parent_warrant_bytes=parent,
                key_id="k",
                capabilities_ref=cap_ref,
                ttl_seconds=300,
            )
            activity_info = _FakeActivityInfo(task_queue=task_queue)
            with patch("temporalio.activity.info", return_value=activity_info):
                with patch("tenuo_core.Warrant", _FakeWarrantClass):
                    # Activities registered via ``@activity.defn`` are
                    # callable directly; calling the underlying coroutine
                    # returns the would-be activity result.
                    return await _tenuo_internal_mint_activity(req)

        import asyncio as _asyncio

        loop = _asyncio.new_event_loop()
        try:
            out_a = loop.run_until_complete(_invoke_via_task_queue("tq-a", b"parent-A"))
            out_b = loop.run_until_complete(_invoke_via_task_queue("tq-b", b"parent-B"))
        finally:
            loop.close()
            with _store_lock:
                _pending_mint_capabilities.pop(cap_ref, None)

        assert out_a == b"minted-parent-A"
        assert out_b == b"minted-parent-B"

        # Worker A's mint activity must have asked resolver A for the key,
        # and Worker B's must have asked resolver B. Neither may have
        # resolved the other's key resolver.
        resolver_a.resolve_sync.assert_called_once_with("k")
        resolver_b.resolve_sync.assert_called_once_with("k")

        assert minted[0] == ("parent-A", signing_key_a)
        assert minted[1] == ("parent-B", signing_key_b)


# =============================================================================
# 3. Manual-setup registration paths (non-plugin users)
# =============================================================================


class TestManualSetupRegistrationPaths:
    """Three paths to register a worker config, all equivalent:

      1. :class:`TenuoTemporalPlugin` — automatic during
         ``configure_worker`` (covered elsewhere).
      2. ``TenuoWorkerInterceptor(config, task_queue=...)`` — self-
         registers at interceptor construction so plugin-less setups
         don't need a second call.
      3. ``register_worker_config(config, task_queue=...)`` — explicit
         helper for setups that construct the interceptor before
         knowing the task queue (dynamic orchestrators, test
         harnesses).

    And one failure path: forgot to register at all → clear
    :class:`TenuoContextError` from the mint activity with the exact
    remediation steps, **not** a cryptic deep-stack ``KeyResolutionError``.
    """

    def _make_config(self) -> "object":
        """Minimal real config; we only need the interceptor to
        construct without error and the mint activity to read back
        ``key_resolver``.
        """
        from tenuo import SigningKey
        from tenuo.temporal import KeyResolver, TenuoPluginConfig

        control = SigningKey.generate()
        agent = SigningKey.generate()

        class _InlineDictResolver(KeyResolver):
            """Sandbox-safe minimal resolver for the tenant-isolation sweep."""

            def __init__(self, keys: Dict[str, Any]) -> None:
                self._keys = keys

            async def resolve(self, key_id: str) -> Any:
                return self.resolve_sync(key_id)

            def resolve_sync(self, key_id: str) -> Any:
                return self._keys[key_id]

        return TenuoPluginConfig(
            key_resolver=_InlineDictResolver({"agent1": agent}),
            trusted_roots=[control.public_key],
        )

    def test_interceptor_constructor_self_registers(self):
        """Passing ``task_queue=`` to the interceptor should register the
        config under that queue with no second call.
        """
        from tenuo.temporal import TenuoWorkerInterceptor

        config = self._make_config()
        assert _get_worker_config("queue-self-register") is None

        TenuoWorkerInterceptor(config, task_queue="queue-self-register")

        resolved = _get_worker_config("queue-self-register")
        # Config may be shallow-copied by the interceptor to attach a
        # control_plane; the key_resolver identity should still match.
        assert resolved is not None
        assert resolved.key_resolver is config.key_resolver  # type: ignore[attr-defined]

    def test_interceptor_without_task_queue_does_not_register(self):
        """Omitting ``task_queue=`` must *not* register anywhere — no
        implicit "default queue", no fallback slot. Users who skip the
        kwarg are explicitly opting into the manual-register path and
        must call ``register_worker_config`` themselves (or accept that
        delegation features will raise at mint time).
        """
        from tenuo.temporal import TenuoWorkerInterceptor

        config = self._make_config()
        TenuoWorkerInterceptor(config)  # no task_queue
        assert _worker_configs == {}

    def test_register_worker_config_helper(self):
        """The public helper must be importable from the top-level
        ``tenuo.temporal`` package and register under the exact queue
        name given.
        """
        from tenuo.temporal import register_worker_config

        config = self._make_config()
        register_worker_config(config, task_queue="helper-queue")

        assert _get_worker_config("helper-queue") is config

    def test_register_worker_config_rejects_empty_queue(self):
        """The helper shares ``_set_worker_config``'s ValueError; users
        should find out at registration time, not at mint time.
        """
        from tenuo.temporal import register_worker_config

        with pytest.raises(ValueError, match="non-empty task_queue"):
            register_worker_config(self._make_config(), task_queue="")

    def test_mint_activity_raises_clear_error_when_unregistered(self):
        """The remediation message must name *all three* registration
        paths and match the actual public API surface, because this is
        the error users hit first when they forget to register.
        """
        from tenuo.temporal._observability import _MintRequest
        from tenuo.temporal._state import _pending_mint_capabilities
        from tenuo.temporal._workflow import _tenuo_internal_mint_activity

        if _tenuo_internal_mint_activity is None:
            pytest.skip("temporalio not installed; mint activity unavailable")

        cap_ref = "unregistered-ref"
        with _store_lock:
            _pending_mint_capabilities[cap_ref] = {"read_file": {}}

        req = _MintRequest(
            kind="attenuate",
            parent_warrant_bytes=b"irrelevant",
            key_id="k",
            capabilities_ref=cap_ref,
            ttl_seconds=300,
        )

        import asyncio as _asyncio

        activity_info = _FakeActivityInfo(task_queue="forgotten-queue")
        loop = _asyncio.new_event_loop()
        try:
            with patch("temporalio.activity.info", return_value=activity_info):
                with pytest.raises(Exception) as excinfo:
                    loop.run_until_complete(_tenuo_internal_mint_activity(req))
        finally:
            loop.close()
            with _store_lock:
                _pending_mint_capabilities.pop(cap_ref, None)

        msg = str(excinfo.value)
        # The message must name the exact remediation — every path a
        # plugin-less user might be using — so the error is self-
        # solving rather than forcing a trip to the docs.
        assert "forgotten-queue" in msg, "error must name the unresolved queue"
        assert "TenuoTemporalPlugin" in msg, "error must mention the plugin path"
        assert "TenuoWorkerInterceptor" in msg and "task_queue" in msg, (
            "error must mention the interceptor constructor path"
        )
        assert "register_worker_config" in msg, (
            "error must mention the explicit helper path"
        )

    def test_async_completion_honors_task_queue_kwarg(self):
        """``tenuo_complete_async_activity`` dropped its singleton
        lookup; callers must pass ``task_queue=`` to get PoP signing.
        Verify the resolver is actually hit when the queue matches.
        """
        from tenuo.temporal._workflow import tenuo_complete_async_activity

        config = self._make_config()
        _set_worker_config(config, task_queue="async-complete-q")

        handle = AsyncMock()
        warrant = MagicMock()
        warrant.sign_pop = MagicMock()

        import asyncio as _asyncio

        loop = _asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                tenuo_complete_async_activity(
                    handle,
                    "result-payload",
                    warrant,
                    "agent1",
                    task_queue="async-complete-q",
                )
            )
        finally:
            loop.close()

        warrant.sign_pop.assert_called_once()
        handle.complete.assert_awaited_once_with("result-payload")
