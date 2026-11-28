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
import heapq
import logging
import secrets
import threading
import time
from typing import Any, List, Literal, NamedTuple, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger("tenuo.consumption")

ConsumptionState = Literal["in_flight", "consumed"]

IN_FLIGHT: ConsumptionState = "in_flight"
CONSUMED: ConsumptionState = "consumed"


class ConsumptionEntry(NamedTuple):
    """What a backend holds for one approval: its state and the idempotency
    key of the authorization that reserved it."""

    state: ConsumptionState
    idempotency_key: Optional[str]


class ConsumptionDenial(NamedTuple):
    """Why :meth:`ApprovalConsumptionStore.reserve` refused a call.

    ``idempotency_key`` is the key of the authorization that first used the
    approval, which may differ from the current call's key when fewer
    approvals verify on a retry (for example a surplus approval expired).
    """

    state: ConsumptionState
    idempotency_key: Optional[str]


@runtime_checkable
class ConsumptionBackend(Protocol):
    """Pluggable storage for approval consumption.

    Implementations must be safe for concurrent use. ``reserve`` must atomically
    insert-if-absent, storing ``owner_token`` with the entry. ``commit`` and
    ``release`` must atomically compare that token before changing an entry.
    An idempotency key names the authorization; the owner token identifies one
    acquisition and must not be reused after a release or expiry.
    """

    def reserve(
        self, key: str, ttl_seconds: int, idempotency_key: Optional[str] = None,
        *, owner_token: str,
    ) -> Optional[ConsumptionEntry]:
        """Record ``key`` as in flight, with ``idempotency_key``, if absent.

        Returns ``None`` when this call reserved it, or the existing entry.
        """
        ...

    def commit(self, key: str, *, owner_token: str) -> None:
        """Mark ``key`` consumed only if its owner matches; preserve expiry.

        Missing entries and entries owned by another acquisition are no-ops.
        """
        ...

    def release(self, key: str, *, owner_token: str) -> None:
        """Drop ``key`` only if still in flight and its owner matches.

        Missing entries, consumed entries and other owners are no-ops.
        """
        ...


class InMemoryConsumptionBackend:
    """Thread-safe in-process backend with TTL eviction."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (entry, expiry on the monotonic clock, acquisition owner)
        self._store: dict[str, Tuple[ConsumptionEntry, float, str]] = {}
        self._expiries: List[Tuple[float, str, str]] = []

    def reserve(
        self, key: str, ttl_seconds: int, idempotency_key: Optional[str] = None,
        *, owner_token: str,
    ) -> Optional[ConsumptionEntry]:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            existing = self._store.get(key)
            if existing is not None:
                return existing[0]
            expiry = now + ttl_seconds
            self._store[key] = (ConsumptionEntry(IN_FLIGHT, idempotency_key), expiry, owner_token)
            heapq.heappush(self._expiries, (expiry, key, owner_token))
            return None

    def commit(self, key: str, *, owner_token: str) -> None:
        with self._lock:
            existing = self._store.get(key)
            if existing is not None and existing[2] == owner_token:
                self._store[key] = (existing[0]._replace(state=CONSUMED), existing[1], owner_token)

    def release(self, key: str, *, owner_token: str) -> None:
        with self._lock:
            existing = self._store.get(key)
            if existing is not None and existing[2] == owner_token and existing[0].state == IN_FLIGHT:
                del self._store[key]
                self._compact_expiries()

    def ttl_remaining(self, key: str) -> Optional[float]:
        with self._lock:
            existing = self._store.get(key)
            return None if existing is None else existing[1] - time.monotonic()

    def _evict(self, now: float) -> None:
        while self._expiries and self._expiries[0][0] <= now:
            expiry, key, owner_token = heapq.heappop(self._expiries)
            existing = self._store.get(key)
            if existing is not None and existing[1:] == (expiry, owner_token):
                del self._store[key]
        self._compact_expiries()

    def _compact_expiries(self) -> None:
        # Released acquisitions leave tombstones. Rebuild only after they
        # outnumber live entries (with a small floor), keeping memory bounded
        # and the rebuild cost amortized across releases and expirations.
        if len(self._expiries) > max(64, 2 * len(self._store)):
            self._expiries = [
                (expiry, key, owner_token)
                for key, (_, expiry, owner_token) in self._store.items()
            ]
            heapq.heapify(self._expiries)

    def __len__(self) -> int:
        with self._lock:
            self._evict(time.monotonic())
            return len(self._store)


class ApprovalReservation:
    """The approvals one authorization reserved. Commit or release once.

    The first of :meth:`commit` / :meth:`release` decides the outcome. If the
    backend fails for some keys, those stay pending and the error propagates;
    calling the same method again finishes them. The other method is then
    ignored.
    """

    def __init__(self, backend: ConsumptionBackend, keys: List[str], *, owner_token: str) -> None:
        self._backend = backend
        self._owner_token = owner_token
        self.keys = list(keys)
        self._pending = list(keys)
        self._outcome: Optional[str] = None

    @property
    def done(self) -> bool:
        """True once every key has been committed or released."""
        return self._outcome is not None and not self._pending

    def commit(self) -> None:
        """The action ran: record its approvals as consumed."""
        self._finish("commit", self._backend.commit)

    def release(self) -> None:
        """The action did not run: make the approvals usable again.

        Only call this when the action certainly had no effect. When in doubt,
        leave the reservation in flight.
        """
        self._finish("release", self._backend.release)

    def _finish(self, outcome: str, apply: Any) -> None:
        if self._outcome is None:
            self._outcome = outcome
        elif self._outcome != outcome:
            return
        failed: List[str] = []
        first_error: Optional[BaseException] = None
        for key in self._pending:
            try:
                apply(key, owner_token=self._owner_token)
            except Exception as e:
                failed.append(key)
                if first_error is None:
                    first_error = e
        self._pending = failed
        if first_error is not None:
            raise first_error


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
        if not isinstance(margin_seconds, int) or margin_seconds < 0:
            raise ValueError("margin_seconds must be a non-negative integer")
        self._backend: ConsumptionBackend = backend if backend is not None else InMemoryConsumptionBackend()
        self._margin = margin_seconds

    @staticmethod
    def key_for(verified_approval: Any) -> str:
        """Storage key for one verified approval, as defined by the core."""
        return str(verified_approval.consumption_key)

    def reserve(
        self, chain_result: Any, idempotency_key: Optional[str] = None
    ) -> Tuple[Optional[ApprovalReservation], Optional[ConsumptionDenial]]:
        """Reserve every approval ``chain_result`` verified, recording
        ``idempotency_key`` with each.

        Returns ``(reservation, None)`` on success, ``(None, None)`` when the
        call carried no approvals, or ``(None, denial)`` when one was already
        in flight or consumed; ``denial.idempotency_key`` is the key stored by
        the authorization that used it first. A partial reservation is rolled
        back.
        """
        verified = list(getattr(chain_result, "verified_approvals", None) or [])
        if not verified:
            return None, None
        now = int(time.time())
        owner_token = secrets.token_hex(16)
        reserved: List[str] = []
        try:
            for va in verified:
                key = self.key_for(va)
                ttl = max(1, int(va.expires_at) - now + self._margin)
                # Include this attempt before the backend call: it may insert
                # successfully and then raise after losing its response.
                reserved.append(key)
                existing = self._backend.reserve(key, ttl, idempotency_key, owner_token=owner_token)
                if existing is not None:
                    self._rollback(reserved, owner_token)
                    logger.warning("Approval reuse denied (%s): %s…", existing.state, key[-8:])
                    return None, ConsumptionDenial(existing.state, existing.idempotency_key or idempotency_key)
        except BaseException:
            # A backend failure part-way must not leave earlier approvals
            # reserved for an action that never ran.
            self._rollback(reserved, owner_token)
            raise
        return ApprovalReservation(self._backend, reserved, owner_token=owner_token), None

    def _rollback(self, keys: List[str], owner_token: str) -> None:
        for k in keys:
            try:
                self._backend.release(k, owner_token=owner_token)
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
