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
import secrets
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

    Implementations must be thread-safe. ``retention_seconds`` is an
    immutable floor shared by every client of the backend's nonce namespace.
    Shared backends must reject inconsistent namespace configurations.
    """

    @property
    def retention_seconds(self) -> int:
        """Minimum lifetime of every admitted nonce, fixed before serving."""
        ...

    @property
    def pop_window_secs(self) -> int:
        """Immutable time-bucket size shared by every verifier in the namespace."""
        ...

    def reserve(self, nonce_hex: str, ttl_seconds: int, owner: str) -> bool:
        """Atomically insert owner with NX and TTL, rejecting existing entries."""
        ...

    def release(self, nonce_hex: str, owner: str) -> None:
        """Atomically delete only an entry whose stored owner still matches."""
        ...

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

    def __init__(self, retention_seconds: int = 150, pop_window_secs: int = 30) -> None:
        self._retention_seconds = retention_seconds
        self._pop_window_secs = pop_window_secs
        self._owners: dict[str, str] = {}
        self._lock = threading.Lock()
        # nonce_hex → expiry timestamp (float)
        self._store: dict[str, float] = {}

    @property
    def retention_seconds(self) -> int:
        return self._retention_seconds

    @property
    def pop_window_secs(self) -> int:
        return self._pop_window_secs

    def check_and_record(self, nonce_hex: str, ttl_seconds: int) -> bool:
        return self.reserve(nonce_hex, ttl_seconds, secrets.token_hex(16))

    def reserve(self, nonce_hex: str, ttl_seconds: int, owner: str) -> bool:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            if nonce_hex in self._store:
                return False
            self._store[nonce_hex] = now + max(ttl_seconds, self.retention_seconds)
            self._owners[nonce_hex] = owner
            return True

    def release(self, nonce_hex: str, owner: str) -> None:
        with self._lock:
            if self._owners.get(nonce_hex) == owner:
                self._store.pop(nonce_hex, None)
                self._owners.pop(nonce_hex, None)

    def seen(self, nonce_hex: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            return nonce_hex in self._store

    def record(self, nonce_hex: str, ttl_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            self._store[nonce_hex] = now + max(ttl_seconds, self.retention_seconds)
            self._owners[nonce_hex] = secrets.token_hex(16)

    def _evict(self, now: float) -> None:
        expired = [k for k, exp in self._store.items() if exp < now]
        for k in expired:
            del self._store[k]
            self._owners.pop(k, None)

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
        Configure this before serving to cover the longest validity interval
        of every verifier sharing the backend. Wider verifiers are rejected.
        All verifiers in a namespace must use the same PoP bucket size.
    pop_window_secs:
        Immutable PoP bucket size, default 30 seconds for a new backend.
        When sharing a backend, defaults to its declared bucket size.
    backend:
        Optional custom :class:`NonceBackend`.  Defaults to an in-process
        ``threading.Lock``-guarded dict.  For multi-process deployments pass a
        Redis-backed implementation.

    Example::

        # Single-process worker
        store = NonceStore(ttl_seconds=150)

        # Multi-process — plug in Redis
        class RedisBackend:
            retention_seconds = 300  # fixed for every client of this namespace
            pop_window_secs = 30
            def __init__(self):
                # Register both settings atomically in persistent namespace metadata.
                config = f"{self.retention_seconds}:{self.pop_window_secs}"
                redis.set("tenuo:nonce-config", config, nx=True)
                if redis.get("tenuo:nonce-config").decode() != config:
                    raise ValueError("inconsistent nonce namespace configuration")
            def reserve(self, h, ttl, owner):
                return bool(redis.set("tenuo:nonce:" + h, owner, nx=True, ex=max(ttl, self.retention_seconds)))
            def release(self, h, owner):
                # Compare and delete in one Redis operation, never DEL blindly.
                redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                           1, "tenuo:nonce:" + h, owner)
            def check_and_record(self, h, ttl):
                return self.reserve(h, ttl, secrets.token_hex(16))
            def seen(self, h): return bool(redis.exists("tenuo:nonce:" + h))
            def record(self, h, ttl):
                redis.setex("tenuo:nonce:" + h, max(ttl, self.retention_seconds), secrets.token_hex(16))

        store = NonceStore(backend=RedisBackend())
    """

    def __init__(
        self,
        ttl_seconds: int = 150,
        backend: Optional[Any] = None,
        *, pop_window_secs: Optional[int] = None,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("nonce TTL must be a positive integer")
        self._backend: NonceBackend = backend if backend is not None else _InMemoryBackend(ttl_seconds, pop_window_secs if pop_window_secs is not None else 30)
        if not callable(getattr(self._backend, "check_and_record", None)):
            raise TypeError("NonceBackend must implement atomic check_and_record(nonce_hex, ttl_seconds)")
        floor = getattr(self._backend, "retention_seconds", None)
        if isinstance(floor, bool) or not isinstance(floor, int) or floor <= 0:
            raise TypeError("NonceBackend must declare an immutable positive retention_seconds floor")
        if ttl_seconds > floor:
            raise ValueError("Configure the shared backend retention floor before creating a wider nonce store")
        window = getattr(self._backend, "pop_window_secs", None)
        if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
            raise TypeError("NonceBackend must declare an immutable positive pop_window_secs")
        if pop_window_secs is not None and (isinstance(pop_window_secs, bool) or pop_window_secs != window):
            raise ValueError("inconsistent nonce namespace PoP window size")
        self._pop_window_secs = window
        self._ttl = floor

    @property
    def retention_seconds(self) -> int:
        return self._ttl

    @property
    def pop_window_secs(self) -> int:
        return self._pop_window_secs

    def reserve(self, pop_bytes: bytes, *, min_ttl_seconds: int = 0) -> Optional[_NonceReservation]:
        """Reserve a verified signature until all admission checks succeed.

        The caller must commit before dispatch or release on admission failure.
        Shared backends require atomic owner-aware reserve/release operations.
        """
        if min_ttl_seconds > self.retention_seconds:
            raise ValueError("nonce reservation exceeds namespace retention floor")
        if not callable(getattr(self._backend, "reserve", None)) or not callable(getattr(self._backend, "release", None)):
            raise TypeError("A2A nonce backend requires atomic owner-aware reserve and release")
        nonce = hashlib.sha256(pop_bytes).hexdigest()
        owner = secrets.token_hex(16)
        if not self._backend.reserve(nonce, self.retention_seconds, owner):
            return None
        return _NonceReservation(self._backend, nonce, owner)

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
        if min_ttl_seconds > self.retention_seconds:
            from .exceptions import ConfigurationError

            raise ConfigurationError(
                f"Nonce retention floor {self.retention_seconds}s cannot cover a {min_ttl_seconds}s PoP interval; "
                "configure every client of the shared backend for the longest verifier interval before serving"
            )
        nonce_hex = hashlib.sha256(pop_bytes).hexdigest()
        if not self._backend.check_and_record(nonce_hex, self.retention_seconds):
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


class _NonceReservation:
    def __init__(self, backend: NonceBackend, nonce: str, owner: str) -> None:
        self._backend, self._nonce, self._owner = backend, nonce, owner
        self._active = True

    def commit(self) -> None:
        self._active = False

    def release(self) -> None:
        if self._active:
            self._backend.release(self._nonce, self._owner)
            self._active = False


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
            _validate_retention(store, authorizer)
            key = (id(store), signature)
            if key in self._admitted:
                return True
            if not _admit_verified_pop(store, signature, authorizer):
                return False
            self._admitted.add(key)
            return True


def _admit_verified_pop(store: Any, signature: bytes, authorizer: Any) -> bool:
    """Retain the signature for every time window the verifier can accept."""
    validity = _validate_retention(store, authorizer)
    return bool(store.check_and_record(signature, min_ttl_seconds=validity))


def _validate_retention(store: Any, authorizer: Any) -> int:
    from .exceptions import ConfigurationError

    window, _ = authorizer.pop_window_config()
    if getattr(store, "pop_window_secs", None) != window:
        raise ConfigurationError("Nonce namespace PoP window size must match every shared verifier")
    validity = authorizer.pop_validity_secs()
    if not isinstance(validity, int) or isinstance(validity, bool) or validity <= 0:
        raise ValueError("Cannot determine the verifier's PoP validity interval")
    floor = getattr(store, "retention_seconds", None)
    if not isinstance(floor, int) or isinstance(floor, bool) or floor < validity:
        from .exceptions import ConfigurationError

        raise ConfigurationError(
            f"Nonce retention floor must cover every shared verifier ({validity}s required); "
            "configure the shared backend before serving"
        )
    return validity


_default_store: Optional[NonceStore] = None


def get_default_nonce_store() -> Optional[NonceStore]:
    """Return the process-wide default :class:`NonceStore`, or ``None``."""
    return _default_store


def enable_default_nonce_store(ttl_seconds: int = 150, backend: Optional[Any] = None, *, pop_window_secs: Optional[int] = None) -> NonceStore:
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
    _default_store = NonceStore(ttl_seconds=ttl_seconds, backend=backend, pop_window_secs=pop_window_secs)
    logger.info("Tenuo nonce store enabled (ttl=%ds, backend=%s)", ttl_seconds, type(_default_store._backend).__name__)
    return _default_store


def disable_default_nonce_store() -> None:
    """Disable the process-wide nonce store (mainly for testing)."""
    global _default_store
    _default_store = None
