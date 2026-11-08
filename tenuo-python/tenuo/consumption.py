"""
At-most-once use of approvals at the enforcement point.

Approval verification is stateless: a signed approval that is still within its
TTL authorizes its request every time the holder presents it. That holds even
for an honest holder that has been rewound — a run restored from a checkpoint
taken before the approved call, a fork of that checkpoint, or a worker retried
after a crash. Each of those re-signs a fresh PoP, so the PoP
:class:`~tenuo.nonce.NonceStore` does not see a repeat.

:class:`ApprovalConsumptionStore` records each approval the authorizer verified
(keyed on approver key and approval nonce) and denies a second use with
``error_type="approval_consumed"``. One-time state cannot live in rewindable
agent state; it belongs here, at the enforcement point.

Reserve / commit
----------------
A successful authorization *reserves* its approvals ("in flight"). The host may
:meth:`ApprovalReservation.commit` once the action has run ("consumed") or
:meth:`ApprovalReservation.release` when it knows the action did not run. A
crash between the two leaves the reservation in flight, so a retry is denied
rather than treated as unused; reconcile it downstream with the idempotency key.
Hosts that never call either still get at-most-once: an in-flight reservation
denies like a consumed one.

Idempotency key
---------------
:attr:`EnforcementResult.idempotency_key` is a stable hex key derived by the
core from the request hash and the approvals that authorized it. Pass it to the
system that performs the action so the action itself happens at most once. It
is also kept on ``approval_consumed`` denials, for reconciling after a crash.
:func:`current_idempotency_key` is a convenience for paths that enforce one call
and then run it; when several calls are authorized before any runs (a batch),
use the key on each call's result.

Scope: the in-memory backend is per process. Replicas need a shared backend
(Redis ``SET NX``, a database row with a unique key) implementing
:class:`ConsumptionBackend`.

Usage::

    from tenuo.consumption import ApprovalConsumptionStore

    store = ApprovalConsumptionStore()
    result = enforce_tool_call(..., consumption_store=store)

    # or process-wide, picked up by every adapter:
    tenuo.enable_approval_consumption()
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from typing import Any, List, Literal, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger("tenuo.consumption")

ConsumptionState = Literal["in_flight", "consumed"]

IN_FLIGHT: ConsumptionState = "in_flight"
CONSUMED: ConsumptionState = "consumed"


@runtime_checkable
class ConsumptionBackend(Protocol):
    """Pluggable storage for approval consumption.

    Implementations must be safe for concurrent use, and :meth:`reserve` must be
    atomic (insert-if-absent), or two concurrent uses can both succeed.
    """

    def reserve(self, key: str, ttl_seconds: int) -> Optional[ConsumptionState]:
        """Record ``key`` as in flight if absent.

        Returns ``None`` when this call reserved it, or the existing state.
        """
        ...

    def commit(self, key: str) -> None:
        """Mark a reserved ``key`` consumed, keeping its expiry."""
        ...

    def release(self, key: str) -> None:
        """Drop ``key`` if it is still in flight. A consumed key stays."""
        ...


class InMemoryConsumptionBackend:
    """Thread-safe in-process backend with TTL eviction."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (state, expiry on the monotonic clock)
        self._store: dict[str, Tuple[ConsumptionState, float]] = {}

    def reserve(self, key: str, ttl_seconds: int) -> Optional[ConsumptionState]:
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            existing = self._store.get(key)
            if existing is not None:
                return existing[0]
            self._store[key] = (IN_FLIGHT, now + ttl_seconds)
            return None

    def commit(self, key: str) -> None:
        with self._lock:
            existing = self._store.get(key)
            if existing is not None:
                self._store[key] = (CONSUMED, existing[1])

    def release(self, key: str) -> None:
        with self._lock:
            existing = self._store.get(key)
            if existing is not None and existing[0] == IN_FLIGHT:
                del self._store[key]

    def ttl_remaining(self, key: str) -> Optional[float]:
        with self._lock:
            existing = self._store.get(key)
            return None if existing is None else existing[1] - time.monotonic()

    def _evict(self, now: float) -> None:
        for k in [k for k, (_, exp) in self._store.items() if exp < now]:
            del self._store[k]

    def __len__(self) -> int:
        with self._lock:
            self._evict(time.monotonic())
            return len(self._store)


class ApprovalReservation:
    """The approvals one authorization reserved. Commit or release once."""

    def __init__(self, backend: ConsumptionBackend, keys: List[str]) -> None:
        self._backend = backend
        self.keys = list(keys)
        self._done = False

    def commit(self) -> None:
        """The action ran: record its approvals as consumed."""
        if self._done:
            return
        self._done = True
        for key in self.keys:
            self._backend.commit(key)

    def release(self) -> None:
        """The action did not run: make the approvals usable again.

        Only call this when the action certainly had no effect. When in doubt,
        leave the reservation in flight.
        """
        if self._done:
            return
        self._done = True
        for key in self.keys:
            self._backend.release(key)


class ApprovalConsumptionStore:
    """Denies a second use of an approval the authorizer already verified.

    Parameters
    ----------
    backend:
        A :class:`ConsumptionBackend`. Defaults to an in-process store; use a
        shared one when several processes enforce for the same holders.
    margin_seconds:
        Kept past each approval's ``expires_at`` to cover clock differences
        between replicas. After that the core rejects the approval as expired
        anyway, so the entry is no longer needed.
    """

    def __init__(self, backend: Optional[ConsumptionBackend] = None, margin_seconds: int = 60) -> None:
        self._backend: ConsumptionBackend = backend if backend is not None else InMemoryConsumptionBackend()
        self._margin = margin_seconds

    @staticmethod
    def key_for(verified_approval: Any) -> str:
        """Storage key for one verified approval, as defined by the core."""
        return str(verified_approval.consumption_key)

    def reserve(self, chain_result: Any) -> Tuple[Optional[ApprovalReservation], Optional[ConsumptionState]]:
        """Reserve every approval ``chain_result`` verified.

        Returns ``(reservation, None)`` on success, ``(None, None)`` when the
        call carried no approvals, or ``(None, state)`` when one was already in
        flight or consumed. A partial reservation is rolled back.
        """
        verified = list(getattr(chain_result, "verified_approvals", None) or [])
        if not verified:
            return None, None
        now = int(time.time())
        reserved: List[str] = []
        try:
            for va in verified:
                key = self.key_for(va)
                ttl = max(1, int(va.expires_at) - now + self._margin)
                state = self._backend.reserve(key, ttl)
                if state is not None:
                    self._rollback(reserved)
                    logger.warning("Approval reuse denied (%s): %s…", state, key[-8:])
                    return None, state
                reserved.append(key)
        except BaseException:
            # A backend failure part-way must not leave earlier approvals
            # reserved for an action that never ran.
            self._rollback(reserved)
            raise
        return ApprovalReservation(self._backend, reserved), None

    def _rollback(self, keys: List[str]) -> None:
        for k in keys:
            try:
                self._backend.release(k)
            except Exception:
                logger.warning("Approval reservation rollback failed: %s…", k[-8:], exc_info=True)

    def __len__(self) -> int:
        return len(self._backend)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Process-wide default (opt-in)
# ---------------------------------------------------------------------------

_default_store: Optional[ApprovalConsumptionStore] = None


def get_default_consumption_store() -> Optional[ApprovalConsumptionStore]:
    """Return the process-wide store, or ``None`` when not enabled."""
    return _default_store


def enable_default_consumption_store(
    backend: Optional[ConsumptionBackend] = None, margin_seconds: int = 60
) -> ApprovalConsumptionStore:
    """Enable at-most-once approvals for every ``enforce_tool_call`` that does
    not pass its own ``consumption_store``, and return the store."""
    global _default_store
    _default_store = ApprovalConsumptionStore(backend=backend, margin_seconds=margin_seconds)
    logger.info("Tenuo approval consumption enabled (backend=%s)", type(_default_store._backend).__name__)
    return _default_store


def disable_default_consumption_store() -> None:
    """Disable the process-wide store (mainly for testing)."""
    global _default_store
    _default_store = None


# ---------------------------------------------------------------------------
# Idempotency key for the tool handler
# ---------------------------------------------------------------------------

_current_idempotency_key: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "tenuo_idempotency_key", default=None
)


def current_idempotency_key() -> Optional[str]:
    """Idempotency key of the call the most recent enforcement in this context
    authorized, or ``None`` when it was denied or carried no approvals."""
    return _current_idempotency_key.get()


def _set_current_idempotency_key(key: Optional[str]) -> None:
    _current_idempotency_key.set(key)
