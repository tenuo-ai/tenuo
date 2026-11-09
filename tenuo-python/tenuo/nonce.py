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
cache (Redis, Memcached, …).  The :class:`NonceBackend` interface below
provides the extension point.

Usage::

    from tenuo.nonce import NonceStore

    store = NonceStore(ttl_seconds=150)

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

    def check_and_record(self, nonce_hex: str, ttl_seconds: int) -> bool:
        """Atomically admit and insert an unseen nonce with the given TTL.

        Shared backends must use a single atomic operation, such as Redis
        SET with NX and EX. A separate exists/set pair is not sufficient.
        """
        ...

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

    def check_and_record(self, nonce_hex: str, ttl_seconds: int) -> bool:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            if nonce_hex in self._store:
                return False
            self._store[nonce_hex] = now + ttl_seconds
            return True

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
        the Authorizer's ``pop_window_secs * pop_max_windows`` (default: 150 s).
        Enforcement raises retention to the verifier's full validity
        interval when a shorter TTL was configured.
    backend:
        Optional custom :class:`NonceBackend`.  Defaults to an in-process
        ``threading.Lock``-guarded dict.  For multi-process deployments pass a
        Redis-backed implementation.

    Example::

        # Single-process worker
        store = NonceStore(ttl_seconds=150)

        # Multi-process — plug in Redis
        class RedisBackend:
            def check_and_record(self, h, ttl):
                return bool(redis.set(h, "1", nx=True, ex=ttl))
            def seen(self, h): return redis.exists(h)
            def record(self, h, ttl): redis.setex(h, ttl, "1")

        store = NonceStore(backend=RedisBackend())
    """

    def __init__(
        self,
        ttl_seconds: int = 150,
        backend: Optional[Any] = None,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("nonce TTL must be a positive integer")
        self._ttl = ttl_seconds
        self._backend: NonceBackend = backend if backend is not None else _InMemoryBackend()
        if not callable(getattr(self._backend, "check_and_record", None)):
            raise TypeError("NonceBackend must implement atomic check_and_record(nonce_hex, ttl_seconds)")

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def check_and_record(self, pop_bytes: bytes, *, min_ttl_seconds: int = 0) -> bool:
        """Atomically admit an unseen PoP for at least ``min_ttl_seconds``.

        Returns
        -------
        bool
            ``True`` if the PoP is fresh (admitted).
            ``False`` if it is a replay (reject the call).
        """
        nonce_hex = hashlib.sha256(pop_bytes).hexdigest()
        if not self._backend.check_and_record(nonce_hex, max(self._ttl, min_ttl_seconds)):
            logger.warning(
                "PoP replay detected — nonce %s…%s was already consumed.",
                nonce_hex[:8], nonce_hex[-4:],
            )
            return False
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


class _RequestNonceAdmissions:
    """Reuse nonce admission inside one HTTP request, after each guard verifies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._admitted: set[tuple[int, bytes]] = set()

    def admit(self, store: Any, signature: bytes, authorizer: Any) -> bool:
        with self._lock:
            key = (id(store), signature)
            if key in self._admitted:
                return True
            if not _admit_verified_pop(store, signature, authorizer):
                return False
            self._admitted.add(key)
            return True


def _admit_verified_pop(store: Any, signature: bytes, authorizer: Any) -> bool:
    """Retain the signature for every time window the verifier can accept."""
    validity = authorizer.pop_validity_secs()
    if not isinstance(validity, int) or isinstance(validity, bool) or validity <= 0:
        raise ValueError("Cannot determine the verifier's PoP validity interval")
    return bool(store.check_and_record(signature, min_ttl_seconds=validity))


_default_store: Optional[NonceStore] = None


def get_default_nonce_store() -> Optional[NonceStore]:
    """Return the process-wide default :class:`NonceStore`, or ``None``."""
    return _default_store


def enable_default_nonce_store(ttl_seconds: int = 150, backend: Optional[Any] = None) -> NonceStore:
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
