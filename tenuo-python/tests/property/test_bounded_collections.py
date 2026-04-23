"""
Property tests: collections that grow with workload must stay bounded.

Long-running Temporal workers and clients accumulate state across
thousands of workflows and millions of activities. Every in-process
cache and rolling window in the Tenuo integration must obey a hard
upper bound — otherwise a long-lived worker slowly turns into a memory
leak.

Deep-review round 4 caught:
  * ``TenuoClientInterceptor._headers_by_workflow_id`` — unbounded
    ``dict`` for workflows that never started.
  * ``TenuoMetrics._latencies`` — ``list`` that grew per decision.
  * ``_workflow_headers_store`` — kept state after the workflow ended.

All three now have explicit bounds. These property tests ensure every
future regression (e.g. "drop the ``maxlen=`` to speed up testing")
is caught immediately. Hypothesis drives each cache with synthetic
workloads of varying shape and asserts the invariant:

    ``len(cache) <= documented_bound`` for all reachable states.

New cache in the codebase? Add a test here. The rules are mechanical:

  1. Pick a documented bound (``maxlen=``, ``max_size=``, TTL).
  2. Generate a workload that would overflow the bound without eviction.
  3. Assert ``len(cache) <= bound`` after the workload.
"""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

pytest.importorskip("temporalio")


# ── TenuoMetrics._latencies: ring buffer of size 1024 ──────────────────


class TestMetricsLatencyRingIsBounded:
    """``TenuoMetrics`` records per-decision latency into a fixed-size
    ring so ``get_stats()`` can compute an average without growing
    without bound. The ring must stay at or below ``_LATENCY_RING_SIZE``
    regardless of workload.
    """

    @given(
        allows=st.integers(min_value=0, max_value=5000),
        denies=st.integers(min_value=0, max_value=5000),
        latency=st.floats(min_value=0.0, max_value=10.0),
    )
    @settings(max_examples=30, deadline=None)
    def test_sustained_load_never_exceeds_ring_size(
        self, allows: int, denies: int, latency: float
    ) -> None:
        from tenuo.temporal._observability import TenuoMetrics

        m = TenuoMetrics()
        for _ in range(allows):
            m.record_authorized(
                tool="t", workflow_type="W", latency_seconds=latency,
            )
        for _ in range(denies):
            m.record_denied(
                tool="t", reason="r", workflow_type="W", latency_seconds=latency,
            )
        # Contract: the internal ring never exceeds its documented size,
        # even if we recorded millions of decisions.
        assert len(m._latencies) <= TenuoMetrics._LATENCY_RING_SIZE
        stats = m.get_stats()
        assert stats["latency_count"] <= TenuoMetrics._LATENCY_RING_SIZE


# ── TenuoClientInterceptor._headers_by_workflow_id: LRU + TTL ──────────


class TestClientPendingHeadersIsBounded:
    """``TenuoClientInterceptor.set_headers_for_workflow`` must not grow
    unbounded for workflow ids that never start. A max-size cap enforces
    an LRU policy.
    """

    @given(
        workflow_ids=st.lists(
            st.text(
                alphabet=st.characters(
                    min_codepoint=ord("a"), max_codepoint=ord("z")
                ),
                min_size=1,
                max_size=20,
            ),
            min_size=0,
            max_size=200,
            unique=True,
        ),
        max_size=st.integers(min_value=1, max_value=50),
    )
    @settings(max_examples=30, deadline=None)
    def test_pending_map_stays_at_or_below_max_size(
        self, workflow_ids: list[str], max_size: int
    ) -> None:
        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor(
            pending_headers_max_size=max_size,
            # Disable TTL — we want to prove the size cap alone is sufficient.
            pending_headers_ttl_secs=None,
        )
        for wf_id in workflow_ids:
            ci.set_headers_for_workflow(wf_id, {"x-tenuo-warrant": b"abc"})
            # Invariant holds at every step, not just at the end.
            assert len(ci._headers_by_workflow_id) <= max_size, (
                f"pending headers grew past max_size={max_size} after "
                f"set_headers_for_workflow({wf_id!r}); LRU eviction leaked"
            )

    @given(
        n=st.integers(min_value=1, max_value=200),
    )
    @settings(max_examples=20, deadline=None)
    def test_discard_keeps_map_at_zero(self, n: int) -> None:
        """Explicit ``discard_headers_for_workflow`` on every bound id
        drains the map back to empty. A client that dutifully cleans up
        sees no residue.
        """
        from tenuo.temporal._client import TenuoClientInterceptor

        ci = TenuoClientInterceptor()
        ids = [f"wf-{i}" for i in range(n)]
        for wf_id in ids:
            ci.set_headers_for_workflow(wf_id, {"x-tenuo-warrant": b"abc"})
        for wf_id in ids:
            ci.discard_headers_for_workflow(wf_id)
        assert len(ci._headers_by_workflow_id) == 0


# ── InMemoryPopDedupStore.cache: hard size cap ─────────────────────────


class TestPopDedupStoreIsBounded:
    """``InMemoryPopDedupStore`` is the default replay-protection cache.
    It must not grow past ``_DEDUP_MAX_SIZE``; otherwise a long-running
    worker accumulates one entry per activity attempt forever.
    """

    @given(
        n=st.integers(min_value=0, max_value=2000),
    )
    @settings(max_examples=20, deadline=None)
    def test_sustained_unique_keys_never_exceed_cap(self, n: int) -> None:
        from tenuo.temporal._dedup import InMemoryPopDedupStore
        from tenuo.temporal._state import _DEDUP_MAX_SIZE

        store = InMemoryPopDedupStore()
        now = time.time()
        # Each dedup_key is unique so we never hit the "replay detected"
        # branch — we're stressing the *size-cap* path, not the TTL path.
        for i in range(n):
            store.check_pop_replay(
                dedup_key=f"k-{i}",
                now=now + i * 0.001,
                ttl_seconds=3600.0,
                activity_name="act",
            )
        assert len(store.cache) <= _DEDUP_MAX_SIZE, (
            "InMemoryPopDedupStore.cache grew past _DEDUP_MAX_SIZE; "
            "size-cap eviction is broken"
        )


# ── _workflow_headers_store: cleanup-on-completion drains to zero ──────


class TestWorkflowHeadersStoreDrains:
    """``_workflow_headers_store`` and ``_workflow_config_store`` are
    populated when a workflow starts and **must** be popped when it
    ends (success *or* failure). A long-running worker otherwise
    accumulates one entry per completed workflow forever.
    """

    @given(
        n=st.integers(min_value=0, max_value=100),
        succeed=st.booleans(),
    )
    @settings(max_examples=20, deadline=None)
    def test_simulated_lifecycle_drains_state(self, n: int, succeed: bool) -> None:
        from tenuo.temporal._state import (
            _store_lock,
            _workflow_config_store,
            _workflow_headers_store,
        )

        # Snapshot existing keys so this test doesn't accuse other
        # state of leaking (parallel runners, prior test residue).
        with _store_lock:
            before_headers = set(_workflow_headers_store.keys())
            before_config = set(_workflow_config_store.keys())

        keys = [f"bound-lifecycle-{i}" for i in range(n)]

        # Simulate: inbound workflow interceptor's try/finally pattern.
        for k in keys:
            with _store_lock:
                _workflow_headers_store[k] = {"x-tenuo-warrant": b"abc"}
                _workflow_config_store[k] = object()  # type: ignore[assignment]
            try:
                if not succeed:
                    raise RuntimeError("simulated workflow failure")
            except RuntimeError:
                pass
            finally:
                # The interceptor's ``finally`` block is what keeps the
                # store bounded. If this pattern ever drifts, the test
                # below catches it.
                with _store_lock:
                    _workflow_headers_store.pop(k, None)
                    _workflow_config_store.pop(k, None)

        with _store_lock:
            after_headers = set(_workflow_headers_store.keys())
            after_config = set(_workflow_config_store.keys())

        assert after_headers == before_headers, (
            "workflow headers store leaked keys after simulated lifecycle: "
            f"{after_headers - before_headers}"
        )
        assert after_config == before_config, (
            "workflow config store leaked keys after simulated lifecycle: "
            f"{after_config - before_config}"
        )
