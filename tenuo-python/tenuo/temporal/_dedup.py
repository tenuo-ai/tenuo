"""Proof-of-Possession replay deduplication for Tenuo-Temporal."""

from __future__ import annotations

import threading
from typing import Protocol

from tenuo.temporal._state import _DEDUP_EVICT_INTERVAL, _DEDUP_MAX_SIZE
from tenuo.temporal.exceptions import PopVerificationError


class PopDedupStore(Protocol):
    """Pluggable PoP replay suppression (default: process-local in-memory).

    Enterprise deployments often run many worker processes. A shared backend
    (Redis, Memcached, DynamoDB, etc.) can implement this protocol so the same
    logical activity attempt cannot pass PoP dedup on two different pods within
    the warrant dedup TTL.

    Implementations must be safe under concurrent activity execution on one
    worker (Temporal may run multiple activities in parallel).

    The method is synchronous; wrap async I/O with ``asyncio.to_thread`` or a
    small connection pool if needed.
    """

    def check_pop_replay(
        self,
        dedup_key: str,
        now: float,
        ttl_seconds: float,
        *,
        activity_name: str,
    ) -> None:
        """Record *dedup_key* or raise ``PopVerificationError`` if seen within TTL.

        Args:
            dedup_key: Stable key for this workflow run + activity + warrant facet.
            now: Unix timestamp (seconds, UTC).
            ttl_seconds: Warrant dedup TTL; suppress reuse inside this window.
            activity_name: Activity type for error messages.

        Raises:
            PopVerificationError: If this key was already recorded within TTL.
        """
        ...


class InMemoryPopDedupStore:
    """Default ``PopDedupStore``: thread-safe ordered dict in this process only.

    Insertion order tracks age (timestamps are monotonically non-decreasing),
    so size-cap eviction pops from the front in O(excess) instead of sorting.
    """

    __slots__ = ("cache", "_last_evict", "_lock")

    def __init__(self) -> None:
        from collections import OrderedDict
        self.cache: OrderedDict[str, float] = OrderedDict()
        self._last_evict: float = 0.0
        self._lock = threading.Lock()

    def check_pop_replay(
        self,
        dedup_key: str,
        now: float,
        ttl_seconds: float,
        *,
        activity_name: str,
    ) -> None:
        with self._lock:
            last_seen = self.cache.get(dedup_key)
            if last_seen is not None and (now - last_seen) < ttl_seconds:
                raise PopVerificationError(
                    reason=(
                        f"replay detected (dedup_key seen {now - last_seen:.1f}s ago)"
                    ),
                    activity_name=activity_name,
                )
            if dedup_key in self.cache:
                del self.cache[dedup_key]
            self.cache[dedup_key] = now

            if (now - self._last_evict) >= _DEDUP_EVICT_INTERVAL:
                self._last_evict = now
                expired = [
                    k for k, t in self.cache.items()
                    if (now - t) >= ttl_seconds
                ]
                for k in expired:
                    del self.cache[k]

            while len(self.cache) > _DEDUP_MAX_SIZE:
                self.cache.popitem(last=False)


_default_pop_dedup_store = InMemoryPopDedupStore()
_pop_dedup_cache = _default_pop_dedup_store.cache
