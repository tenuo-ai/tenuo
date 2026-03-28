"""
In-process PoP nonce store for replay prevention.

Ed25519 signing is deterministic: ``Warrant.sign(key, tool, args, timestamp)``
always produces the same bytes for the same inputs.  Within a single second two
identical calls are therefore indistinguishable from a replay without an
explicit nonce check.

:class:`NonceStore` tracks seen PoP signatures (SHA-256 of the raw bytes) with
a configurable TTL window.  When a PoP is first seen it is admitted and
recorded; subsequent presentations of the *exact same* PoP bytes are rejected
as replays until the TTL expires.

**Scope**: this is an *in-process* defence.  For multi-process or distributed
deployments (multiple worker replicas) the store must be backed by a shared
cache (Redis, Memcached, …).  The :class:`RedisNonceBackend` interface below
provides the extension point.

Usage::

    from tenuo.nonce import NonceStore

    store = NonceStore(ttl_seconds=60)

    result = enforce_tool_call(
        tool_name, args, bound_warrant,
        trusted_roots=[...],
        nonce_store=store,
    )
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger("tenuo.nonce")


# ---------------------------------------------------------------------------
# Backend protocol — swap the in-memory default for Redis/Memcached in prod
# ---------------------------------------------------------------------------


@runtime_checkable
class NonceBackend(Protocol):
    """Pluggable storage backend for the nonce store.

    Implementations must be thread-safe.
    """

    def seen(self, nonce_hex: str) -> bool:
        """Return ``True`` if ``nonce_hex`` has been recorded (replay)."""
        ...

    def record(self, nonce_hex: str, ttl_seconds: int) -> None:
        """Record ``nonce_hex`` as consumed for ``ttl_seconds``."""
        ...


# ---------------------------------------------------------------------------
# In-memory backend (default)
# ---------------------------------------------------------------------------


class _InMemoryBackend:
    """Thread-safe in-process nonce store with TTL eviction."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # nonce_hex → expiry timestamp (float)
        self._store: dict[str, float] = {}

    def seen(self, nonce_hex: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            return nonce_hex in self._store

    def record(self, nonce_hex: str, ttl_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            self._store[nonce_hex] = now + ttl_seconds

    def _evict(self, now: float) -> None:
        expired = [k for k, exp in self._store.items() if exp < now]
        for k in expired:
            del self._store[k]

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class NonceStore:
    """PoP replay-prevention store.

    Parameters
    ----------
    ttl_seconds:
        How long to remember a PoP signature.  Should be at least as long as
        the Authorizer's ``pop_window_secs * pop_max_windows`` (default: 120 s)
        so every PoP that could be accepted is tracked.
    backend:
        Optional custom :class:`NonceBackend`.  Defaults to an in-process
        ``threading.Lock``-guarded dict.  For multi-process deployments pass a
        Redis-backed implementation.

    Example::

        # Single-process worker
        store = NonceStore(ttl_seconds=120)

        # Multi-process — plug in Redis
        class RedisBackend:
            def seen(self, h): return redis.exists(h)
            def record(self, h, ttl): redis.setex(h, ttl, "1")

        store = NonceStore(backend=RedisBackend())
    """

    def __init__(
        self,
        ttl_seconds: int = 120,
        backend: Optional[Any] = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._backend: NonceBackend = backend if backend is not None else _InMemoryBackend()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def check_and_record(self, pop_bytes: bytes) -> bool:
        """Admit a PoP if it has not been seen before; record it for TTL.

        Returns
        -------
        bool
            ``True`` if the PoP is fresh (admitted).
            ``False`` if it is a replay (reject the call).
        """
        nonce_hex = hashlib.sha256(pop_bytes).hexdigest()
        if self._backend.seen(nonce_hex):
            logger.warning(
                "PoP replay detected — nonce %s…%s was already consumed.",
                nonce_hex[:8], nonce_hex[-4:],
            )
            return False
        self._backend.record(nonce_hex, self._ttl)
        return True

    def is_replay(self, pop_bytes: bytes) -> bool:
        """Return ``True`` if ``pop_bytes`` has already been consumed.

        Unlike :meth:`check_and_record` this does **not** record the nonce.
        Use it for read-only inspection (e.g. logging).
        """
        nonce_hex = hashlib.sha256(pop_bytes).hexdigest()
        return self._backend.seen(nonce_hex)


# ---------------------------------------------------------------------------
# Module-level shared instance (opt-in singleton)
# ---------------------------------------------------------------------------

_default_store: Optional[NonceStore] = None


def get_default_nonce_store() -> Optional[NonceStore]:
    """Return the process-wide default :class:`NonceStore`, or ``None``."""
    return _default_store


def enable_default_nonce_store(ttl_seconds: int = 120, backend: Optional[Any] = None) -> NonceStore:
    """Enable the process-wide nonce store and return it.

    Call this once at application startup alongside ``tenuo.configure()``:

    .. code-block:: python

        import tenuo
        tenuo.configure(trusted_roots=[control_key.public_key])
        tenuo.enable_nonce_store()  # activates replay prevention globally

    After this, every ``enforce_tool_call`` call that does not pass an explicit
    ``nonce_store`` will automatically use the shared store.
    """
    global _default_store
    _default_store = NonceStore(ttl_seconds=ttl_seconds, backend=backend)
    logger.info("Tenuo nonce store enabled (ttl=%ds, backend=%s)", ttl_seconds, type(_default_store._backend).__name__)
    return _default_store


def disable_default_nonce_store() -> None:
    """Disable the process-wide nonce store (mainly for testing)."""
    global _default_store
    _default_store = None
