"""
Token budgets handed out in leases.

.. note:: Experimental. The interface may change.

A warrant's token budget is fixed when the warrant is issued. A *lease* is a
short-lived warrant for a slice of a larger budget that an issuer keeps: "this
agent may spend 2,000,000 tokens a day" is handed out 100,000 at a time. When a
slice runs short the holder returns it, with what it really used, and takes the
next one. The issuer charges a lease in full until it comes back, so two hosts
are never given the same tokens, and what a lease did not use goes back to the
budget (at once, or when the lease expires if the issuer is set to be strict).

A lease is for one process. Another process should take its own lease from the
same budget, not a warrant delegated from this one: its spending would be
counted in its own store and would not be part of what this process returns.

    import tenuo.budget_http
    from tenuo.budget_lease import CloudLeases, LeasedBudget

    lease = LeasedBudget(CloudLeases("trg_research_budget"))
    tenuo.budget_http.install(lease=lease, signing_key=agent_key, trusted_roots=[root])

Nothing else changes: model calls are metered against the current lease, and
the lease is renewed and returned for you. Returns are signed with the agent's
key, so only the holder of a lease can say what it used.

:class:`CloudLeases` takes leases from Tenuo Cloud. Anything with ``acquire()``
and ``release()`` can stand in for it (see :class:`LeaseSource`).

Not covered: a process killed by a signal it does not handle (SIGTERM, SIGKILL)
does not return its lease, which then stays charged in full until the period
resets (a budget for one total never does).
"""

from __future__ import annotations

import atexit
import base64
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import weakref
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Tuple

logger = logging.getLogger("tenuo.budget")

__all__ = ["CloudLeases", "Lease", "LeaseSource", "LeaseUnavailable", "LeasedBudget", "lease_return_message"]

_MAX_REPLY = 1 << 20  # bytes read from the control plane for one answer
_MODEL_CHARS = 200    # the issuer refuses longer model names


@dataclass
class Lease:
    """A warrant for a slice of a budget."""

    warrant: Any
    warrant_id: str
    expires_at: float  # Unix time
    granted_tokens: int
    info: Dict[str, Any] = field(default_factory=dict)  # what the issuer said about the budget


class LeaseUnavailable(Exception):
    """No lease can be had right now.

    ``exhausted`` is true when the issuer said the budget is spent or all
    leased out (as opposed to being unreachable). ``retry_at`` is the Unix time
    at which asking again could succeed, when the issuer gave one.
    """

    def __init__(self, message: str, *, exhausted: bool = False, retry_at: Optional[float] = None) -> None:
        super().__init__(message)
        self.exhausted = exhausted
        self.retry_at = retry_at


class LeaseSource(Protocol):
    """Where leases come from."""

    def acquire(self) -> Lease:
        """Take the next lease. Raise :class:`LeaseUnavailable` when there is none."""

    def release(self, warrant_id: str, usage: List[Dict[str, Any]]) -> None:
        """Return a lease with what it used: ``[{"model", "input_tokens", "output_tokens"}]``."""


def lease_return_message(warrant_id: str, usage: List[Dict[str, Any]]) -> bytes:
    """What a holder signs to return a lease.

    The warrant id and the usage, each model name length-prefixed so no name
    can run into the next field.
    """
    parts = [b"tenuo-lease-return-v1\n", warrant_id.encode(), b"\n"]
    for entry in usage:
        model = str(entry["model"]).encode()
        parts.append(b"%d:%s:%d:%d\n" % (len(model), model, int(entry["input_tokens"]), int(entry["output_tokens"])))
    return b"".join(parts)


def _unix(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """The API key goes to the control plane it was configured for, nowhere it points to."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class CloudLeases:
    """Leases from Tenuo Cloud: each one is a fire of a trigger that has a ``token_budget``.

    Args:
        trigger_id: The trigger to fire.
        signing_key: The agent's key, which signs each return. ``install()``
            supplies its own ``signing_key`` when this is left out.
        url: The control plane. Defaults to ``TENUO_CONTROL_PLANE_URL``.
        api_key: Defaults to ``TENUO_API_KEY``.
        event_data: Sent with every fire, for triggers that bind from it.
        timeout: Seconds to wait on the control plane's socket.
        acquisition_id: Optional durable operation ID for recovering an unfinished
            acquisition after a restart. Reuse it only for that acquisition, never
            across independent workers. Cloud must support acquisition idempotency.
    """

    def __init__(self, trigger_id: str, *, signing_key: Any = None, url: Optional[str] = None,
                 api_key: Optional[str] = None, event_data: Optional[Mapping[str, Any]] = None,
                 timeout: float = 10.0, acquisition_id: Optional[str] = None) -> None:
        self.trigger_id = trigger_id
        self.signing_key = signing_key
        self.url = (url or os.environ.get("TENUO_CONTROL_PLANE_URL") or "").rstrip("/")
        self.api_key = api_key or os.environ.get("TENUO_API_KEY") or ""
        if not self.url or not self.api_key:
            raise ValueError("CloudLeases needs a control plane URL and an API key "
                             "(TENUO_CONTROL_PLANE_URL and TENUO_API_KEY)")
        self.event_data = dict(event_data or {})
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirects)
        if acquisition_id is not None and (not acquisition_id or len(acquisition_id) > 128 or
                any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in acquisition_id)):
            raise ValueError("acquisition_id must be 1-128 ASCII letters, digits, underscores or hyphens")
        self._pending_acquisition_id = acquisition_id or uuid.uuid4().hex
        self._pending_event_data: Optional[Dict[str, Any]] = None
        self._acquire_lock = threading.Lock()
        self._acquire_pid = os.getpid()
        self._protocol_error: Optional[str] = None

    def _post(self, path: str, body: Mapping[str, Any]) -> Tuple[int, Dict[str, Any]]:
        # urllib, not httpx: this request must not pass through the meter it serves.
        request = urllib.request.Request(
            self.url + path, method="POST", data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status, raw = response.status, response.read(_MAX_REPLY)
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read(_MAX_REPLY)
        try:
            parsed = json.loads(raw or b"{}")
        except ValueError:
            parsed = {}
        return status, parsed if isinstance(parsed, dict) else {}

    @property
    def pending_acquisition_id(self) -> Optional[str]:
        """ID retained after an uncertain response; checkpoint before acquisition
        or pass your own durable ID to the constructor for crash recovery."""
        return self._pending_acquisition_id

    def acquire(self) -> Lease:
        # Forked workers must neither inherit a locked mutex nor recover/spend
        # their parent's pending lease. Each process acquires its own slice.
        if self._acquire_pid != os.getpid():
            self._acquire_pid = os.getpid()
            self._acquire_lock = threading.Lock()
            self._pending_acquisition_id = None
            self._pending_event_data = None
        with self._acquire_lock:
            if self._protocol_error:
                raise LeaseUnavailable(self._protocol_error)
            if self._pending_acquisition_id is None:
                self._pending_acquisition_id = uuid.uuid4().hex
            try:
                if self._pending_event_data is None:
                    self._pending_event_data = json.loads(json.dumps(self.event_data))
                lease = self._acquire()
                self._pending_acquisition_id = None
                self._pending_event_data = None
                return lease
            except LeaseUnavailable:
                raise
            except Exception as e:
                # Preserve the ID and exact event data on an ambiguous failure.
                raise LeaseUnavailable(f"no lease from the control plane: {type(e).__name__}: {e}") from e

    def _acquire(self) -> Lease:
        from tenuo import Warrant

        status, body = self._post(f"/v1/triggers/{self.trigger_id}/fire", {"event_data": self._pending_event_data, "acquisition_id": self._pending_acquisition_id})
        error: Dict[str, Any] = body["error"] if isinstance(body.get("error"), dict) else {}
        if status == 410 and error.get("code") == "acquisition_closed":
            # The server positively identified a terminal acquisition. A later
            # attempt may request a new lease; the old one remains accounted for.
            self._pending_acquisition_id = None
            self._pending_event_data = None
            raise LeaseUnavailable(str(error.get("message") or "the previous acquisition is closed"))
        if status == 409 and error.get("code") == "token_budget_exhausted":
            raise LeaseUnavailable(str(error.get("message") or "the token budget for this period is spent"),
                                   exhausted=True, retry_at=_unix(error.get("retry_at")))
        if status != 200 or not body.get("warrant"):
            code = str(error.get("code") or "")
            if status == 404:
                why = f"trigger {self.trigger_id} was not found; check the trigger id"
            elif status == 401:
                why = "the control plane did not accept the API key (TENUO_API_KEY)"
            elif status == 403:
                why = f"this API key may not fire trigger {self.trigger_id}; allow its service account on the trigger"
            elif code == "trigger_inactive":
                why = f"trigger {self.trigger_id} is paused"
            else:
                why = "the control plane did not grant a lease"
            detail = " ".join(part for part in (f"HTTP {status}", code, str(error.get("message") or "")) if part)
            raise LeaseUnavailable(f"{why} ({detail})")
        info = body.get("lease")
        if not isinstance(info, dict):
            raise LeaseUnavailable(f"trigger {self.trigger_id} has no token_budget, so its warrants are not leases")
        warrant = Warrant.from_base64(body["warrant"])
        granted = int(info.get("granted_tokens") or 0)
        expires_at = _unix(body.get("expires_at")) or _unix(info.get("expires_at"))
        # A lease is only a lease if the warrant itself carries the slice: the
        # meter enforces what the warrant says, not what the reply says.
        carried = getattr((warrant.capabilities.get("llm.chat") or {}).get("total_tokens"), "max", None)
        if granted < 1 or carried is None or int(carried) != granted or expires_at is None:
            raise LeaseUnavailable("the control plane's reply is not a usable lease "
                                   f"(granted {granted}, warrant carries {carried}, expires {expires_at})")
        if body.get("acquisition_id") != self._pending_acquisition_id:
            self._protocol_error = "the control plane did not confirm acquisition idempotency; upgrade Cloud before using this SDK"
            raise LeaseUnavailable(self._protocol_error)
        return Lease(warrant=warrant, warrant_id=str(warrant.id), expires_at=expires_at, granted_tokens=granted, info=info)

    def release(self, warrant_id: str, usage: List[Dict[str, Any]]) -> None:
        if self.signing_key is None:
            raise OSError("CloudLeases has no signing_key, so it cannot sign the return of a lease")
        signature = bytes(self.signing_key.sign_raw(lease_return_message(warrant_id, usage)))
        status, body = self._post("/v1/metrics/tokens/leases/release", {
            "warrant_id": warrant_id, "usage": usage, "signature": base64.b64encode(signature).decode(),
        })
        if status != 200:
            raise OSError(f"lease {warrant_id} was not returned: HTTP {status} {body}")


def _close_at_exit(ref: Any) -> None:
    budget = ref()
    if budget is not None:
        budget.close()


# Every live LeasedBudget, so a forked child can put each one right before it
# is used: a lock copied while another thread held it would never open again.
_BUDGETS: "weakref.WeakSet[LeasedBudget]" = weakref.WeakSet()


def _reset_budgets_in_child() -> None:
    for budget in list(_BUDGETS):
        budget._reset_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_budgets_in_child)


class _Held:
    """A lease this process has taken, and what was spent under it."""

    def __init__(self, lease: Lease, taken_at: float, taken_mono: float) -> None:
        from tenuo.budget import _expiry

        self.lease = lease
        # Calls can start on it until the earlier of what the issuer said and
        # what the signed warrant says: past either, the call would be refused.
        signed = _expiry(lease.warrant)
        self.usable_until = min(lease.expires_at, signed) if signed else lease.expires_at
        self.taken_at = taken_at      # wall clock, for the lease's lifetime
        self.taken_mono = taken_mono  # monotonic, for "how long have we had it"
        self.inflight = 0
        self.usage: Dict[str, List[int]] = {}  # model -> [input, output]
        self.retired = False   # no new calls start on it
        self.returning = False  # a return is on its way to the issuer
        self.returned = False   # the issuer has acknowledged the return
        self.final: Optional[List[Dict[str, Any]]] = None  # what the return says, once it has been sent

    def report(self) -> List[Dict[str, Any]]:
        """What the return says. Fixed the first time it is sent: a retry repeats it."""
        if self.final is None:
            self.final = [{"model": model[:_MODEL_CHARS], "input_tokens": counts[0], "output_tokens": counts[1]}
                          for model, counts in sorted(self.usage.items())]
        return self.final


class LeasedBudget:
    """Keeps this process on a current lease.

    Give it to :func:`tenuo.budget_http.install` as ``lease=``. It takes a
    lease on the first model call, takes the next one when a call does not fit
    in what the current one has left or when it is about to expire, and returns
    every lease with what was used under it. Leases still held when the process
    exits are returned then; call :meth:`close` to do it sooner.

    Args:
        source: Where leases come from, usually :class:`CloudLeases`.
        renew_before: Take the next lease this many seconds before the current
            one expires, so a call does not start on a warrant about to lapse.
            Never more than half the lease's lifetime.
        recheck_after: While the issuer says the budget is spent, ask again at
            most this often (seconds). Calls in between are refused locally.
        clock: Wall clock, for tests.
    """

    def __init__(self, source: LeaseSource, *, renew_before: float = 15.0, recheck_after: float = 30.0,
                 clock: Optional[Callable[[], float]] = None) -> None:
        self.source = source
        self.renew_before = renew_before
        self.recheck_after = recheck_after
        self._clock = clock or time.time
        # Waiting is measured on a clock that cannot be set back. A test clock stands in for both.
        self._mono = clock or time.monotonic
        self._lock = threading.RLock()     # state
        self._renewing = threading.Lock()  # one renewal at a time
        self._current: Optional[_Held] = None
        self._held: Dict[str, _Held] = {}
        # Leases no call may start on any more, until their warrants expire.
        # Kept after the lease itself is forgotten: a warrant delegated from a
        # returned lease must stay refused for as long as it is valid.
        self._retired: Dict[str, float] = {}
        self._blocked_until = 0.0
        self._blocked: Optional[Tuple[str, bool, Optional[float]]] = None
        self._retry_returns_at = 0.0
        self._closes = 0  # how many times close() has run: a rotation that spans one must not leave a lease behind
        self._closing = False  # closed and not in use again: what is still out goes back as soon as it can
        self._pid = os.getpid()
        _BUDGETS.add(self)
        atexit.register(_close_at_exit, weakref.ref(self))

    # -- what the meter asks ---------------------------------------------------

    @property
    def current(self) -> Optional[Lease]:
        """The lease new calls start on, if one is held."""
        with self._lock:
            self._after_fork()
            return self._current.lease if self._current is not None else None

    def describe(self, warrant_id: str) -> Optional[Dict[str, Any]]:
        """What the issuer said about the budget when it granted lease ``warrant_id``, if it is still held."""
        with self._lock:
            held = self._held.get(warrant_id)
            return dict(held.lease.info) if held is not None else None

    def knows(self, warrant_id: str) -> bool:
        """True when ``warrant_id`` is a lease this object took, current or not."""
        with self._lock:
            return warrant_id in self._held or warrant_id in self._retired

    def warrant(self) -> Any:
        """The current lease's warrant, taking a lease first when none is usable.

        Raises :class:`LeaseUnavailable` when there is none to be had.
        """
        with self._lock:
            self._after_fork()
            held = self._current
            if held is not None and self._usable(held):
                return held.lease.warrant
        return self._rotate(held).warrant

    def renew(self, warrant_id: str, used: bool = True) -> bool:
        """The lease ``warrant_id`` is too small for the next call: move to another.

        ``used`` says whether anything was spent under it. An untouched lease
        is only swapped once it has been held for ``recheck_after`` seconds:
        asking sooner would get the same small slice again.

        Returns True when a different lease is now current (plan the call
        again), False when this one is all there is for now. Raises
        :class:`LeaseUnavailable` when the lease has been sent back and no
        other could be taken.
        """
        with self._lock:
            held = self._current
            if held is None or held.lease.warrant_id != warrant_id:
                return True  # the process has already moved on from it: plan on whatever is current now
            if not used and self._mono() - held.taken_mono < self.recheck_after:
                return False
        try:
            return self._rotate(held).warrant_id != warrant_id
        except LeaseUnavailable:
            with self._lock:
                if self._current is held:
                    return False  # still ours: the call runs on what is left of it
            raise

    def enter(self, warrant_ids: Iterable[str]) -> bool:
        """A call is about to spend from these warrants.

        Returns False, and counts nothing, when one of them is a lease that has
        been retired: it is being returned (or already was), so nothing new may
        be spent under it. The caller gives its reservation back and plans the
        call again on the current lease.
        """
        ids = list(warrant_ids)
        with self._lock:
            self._after_fork()
            now = self._clock()
            for warrant_id in ids:
                held = self._held.get(warrant_id)
                if held is not None and not held.retired and held.usable_until <= now:
                    # Past its deadline: the issuer no longer counts on it, so
                    # nothing new starts on it, whoever holds a warrant from it.
                    self._retire(held)
                    if self._current is held:
                        self._current = None
            if any(w in self._retired for w in ids):
                return False
            for warrant_id in ids:
                held = self._held.get(warrant_id)
                if held is not None:
                    held.inflight += 1
            return True

    def exit(self, warrant_ids: Iterable[str], model: Optional[str], usage: Optional[Mapping[str, Any]]) -> None:
        """That call is over. ``usage`` is its settled record, or None if it never ran."""
        with self._lock:
            for warrant_id in warrant_ids:
                held = self._held.get(warrant_id)
                if held is None:
                    continue
                held.inflight = max(0, held.inflight - 1)
                if usage is not None:
                    counts = held.usage.setdefault(model or "unknown", [0, 0])
                    counts[0] += int(usage.get("input_tokens") or 0)
                    counts[1] += int(usage.get("output_tokens") or 0)
            closing = self._closing
        # After close() no later call will come by to retry a return, so the
        # last calls to end send theirs without waiting out a retry interval.
        self._return_idle(force=closing)

    def close(self) -> None:
        """Return every lease that has no call running on it. Safe to call twice."""
        with self._lock:
            self._after_fork()
            self._closes += 1
            self._closing = True
            for held in self._held.values():
                self._retire(held)
            self._current = None
        self._return_idle(force=True)

    # -- internals -------------------------------------------------------------

    def _reset_in_child(self) -> None:
        """Called in a forked child before anything else touches this object."""
        self._lock = threading.RLock()
        self._renewing = threading.Lock()
        self._after_fork()

    def _after_fork(self) -> None:
        """In a forked child, the parent's leases are the parent's to spend and return."""
        if os.getpid() == self._pid:
            return
        self._pid = os.getpid()
        for held in self._held.values():
            self._retired[held.lease.warrant_id] = self._closed_until(held.lease)
        self._held.clear()
        self._current = None
        self._blocked = None

    @staticmethod
    def _closed_until(lease: Lease) -> float:
        """How long a retired lease must stay closed: for as long as its signed
        warrant, or one delegated from it, could still authorize a call."""
        from tenuo.budget import _expiry

        signed = _expiry(lease.warrant)
        return max(lease.expires_at, signed) if signed else float("inf")

    def _retire(self, held: _Held) -> None:
        held.retired = True
        self._retired[held.lease.warrant_id] = self._closed_until(held.lease)

    def _usable(self, held: _Held) -> bool:
        lifetime = max(0.0, held.usable_until - held.taken_at)
        margin = min(self.renew_before, lifetime / 2)
        return not held.retired and held.usable_until - margin > self._clock()

    def _rotate(self, expected: Optional[_Held]) -> Lease:
        with self._renewing:
            with self._lock:
                closes = self._closes
                held = self._current
                if held is not expected and held is not None and self._usable(held):
                    return held.lease  # renewed while this thread waited
                if self._blocked is not None and self._mono() < self._blocked_until:
                    message, exhausted, retry_at = self._blocked
                    raise LeaseUnavailable(message, exhausted=exhausted, retry_at=retry_at)
                idle = False
                if held is not None and held.inflight == 0:
                    # Decided under the same lock enter() takes: from here on no
                    # call can start on this lease, so what it reports is final.
                    self._retire(held)
                    idle = True
            # Return the old lease first when nothing is running on it.
            if held is not None and idle and not self._return(held):
                with self._lock:
                    # Whether the issuer has the return is not known: it may
                    # have taken it and given the unused tokens to someone
                    # else. The lease stays closed and its return is retried.
                    self._retry_returns_at = self._mono() + self.recheck_after
            # Returns that failed earlier are tried again before asking for a
            # lease: what they free may be all the budget has left to give.
            self._return_idle()
            try:
                lease = self.source.acquire()
            except Exception as e:
                failure = e if isinstance(e, LeaseUnavailable) else LeaseUnavailable(f"no lease: {type(e).__name__}: {e}")
                with self._lock:
                    wait = self.recheck_after
                    if failure.retry_at is not None:
                        # Not sooner than a second: a time already past must not mean "ask on every call".
                        wait = min(wait, max(1.0, failure.retry_at - self._clock()))
                    self._blocked = (str(failure), failure.exhausted, failure.retry_at)
                    self._blocked_until = self._mono() + wait
                    if held is not None and held.retired:
                        self._current = None  # sent back, acknowledged or not: nothing more is spent under it
                if failure is e:
                    raise
                raise failure from e
            fresh = _Held(lease, self._clock(), self._mono())
            with self._lock:
                self._blocked = None
                if held is not None:
                    self._retire(held)  # returned when its last call ends
                self._held[lease.warrant_id] = fresh
                closed = self._closes != closes
                if closed:
                    # close() ran while the issuer was answering: this lease
                    # goes straight back, and nothing is left held after it.
                    self._retire(fresh)
                else:
                    self._current = fresh
                    self._closing = False  # in use again
                self._forget()
        self._return_idle(force=closed)
        if closed:
            raise LeaseUnavailable("the leases were closed while this call was waiting for one")
        return lease

    def _return_idle(self, force: bool = False) -> None:
        """Return retired leases nothing is running on, including ones a failed attempt left behind."""
        with self._lock:
            waiting = [h for h in self._held.values()
                       if h.retired and h.inflight == 0 and not h.returned and not h.returning]
            if not waiting:
                return
            # A lease whose return just failed is not retried on every call.
            if not force and self._mono() < self._retry_returns_at:
                return
        failed = False
        for held in waiting:
            failed = not self._return(held) or failed
        with self._lock:
            self._retry_returns_at = self._mono() + (self.recheck_after if failed else 0.0)

    def _return(self, held: _Held) -> bool:
        """Send a lease back. True once the issuer has acknowledged it."""
        with self._lock:
            if held.returned:
                return True
            if held.returning:
                return False  # another thread is sending it
            held.returning = True
            report = held.report()
        try:
            self.source.release(held.lease.warrant_id, report)
        except BaseException as e:
            # Including an interrupt in the middle of the request: the issuer
            # may or may not have it. The same report is sent again later.
            with self._lock:
                held.returning = False
            if not isinstance(e, Exception):
                raise
            logger.warning("Lease %s could not be returned; it stays charged in full until it is",
                           held.lease.warrant_id, exc_info=True)
            return False
        with self._lock:
            held.returning = False
            held.returned = True
        return True

    def _forget(self) -> None:
        now = self._clock()
        # A returned lease's bookkeeping can go; that it is retired is remembered until its warrant expires.
        for warrant_id in [w for w, h in self._held.items() if h.returned and h.inflight == 0]:
            del self._held[warrant_id]
        for warrant_id in [w for w, expires in self._retired.items() if expires + 60 < now and w not in self._held]:
            del self._retired[warrant_id]
