"""
Token budgets for model calls.

A warrant can carry a token budget as an ordinary constraint on the capability
that covers model calls::

    from tenuo import Warrant
    from tenuo.budget import llm_capability

    root = (Warrant.mint_builder()
        .capability("llm.chat", llm_capability(total_tokens=2_000_000,
                                               max_tokens=4096,
                                               models=["gpt-4o-mini"]))
        .holder(lead_key.public_key).ttl(86400).mint(issuer_key))

``total_tokens`` is a :class:`~tenuo.Range`. The core signs it with the rest of
the warrant, refuses a delegated warrant that widens or drops it, and checks it
on every call like any other argument. The one difference from other arguments
is who supplies the value: the caller does not. The enforcement point keeps a
running total per warrant in a :class:`BudgetStore` and passes *that* as the
argument, so the core decides and the store only counts.

Reserve / settle
----------------
Output tokens are known only after the call. :meth:`TokenMeter.begin` therefore
reserves the estimated input plus the most the call may generate, asks the core
whether the new total is allowed, and hands back a :class:`MeteredCall`. The
adapter writes ``call.max_output`` into the request, runs it, and calls
:meth:`MeteredCall.settle` with the usage the provider reported; the store is
corrected to the real figure. A call that never ran is given back with
:meth:`MeteredCall.release`. A crash in between leaves the reservation counted.

Delegation
----------
A call spends from its own warrant and from every warrant it was delegated
from. When the parents are presented (``warrant_chain``), each parent's total
is checked too, so workers that share a parent share its budget. Without the
parents only the leaf's own total can be enforced.

Periods
-------
``llm_capability(total_tokens=50_000, period="day")`` makes the total an
allowance for each hour, day, week or month instead of for the warrant's
lifetime. The period is signed with the warrant like the total, so a delegated
warrant cannot change it. The meter keeps one running total per warrant and
period and tells the core which period it counted by. A day, week or month
starts at midnight in ``timezone`` (UTC unless given); a week starts on Monday.

Scope: a total holds only where every call passes a meter on the same store.
The in-memory backend is per process and :class:`SqliteBudgetBackend` is per
host; several hosts need a shared :class:`BudgetBackend`. A process holding the
provider key can call the provider directly, so keep the key behind the meter.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import time
import weakref
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timedelta
from datetime import timezone as _timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple, Union, runtime_checkable

logger = logging.getLogger("tenuo.budget")

DEFAULT_TOOL = "llm.chat"
DEFAULT_FIELD = "total_tokens"
OUTPUT_FIELD = "max_tokens"
MODEL_FIELD = "model"
PERIOD_FIELD = "period"
ZONE_FIELD = "period_timezone"
PERIODS = ("hour", "day", "week", "month")

__all__ = [
    "BudgetBackend",
    "BudgetError",
    "BudgetExceeded",
    "BudgetLevel",
    "BudgetStore",
    "InMemoryBudgetBackend",
    "MeteredCall",
    "ModelCallDenied",
    "SqliteBudgetBackend",
    "TokenMeter",
    "estimate_input_tokens",
    "llm_capability",
    "usage_counts",
]


# ---------------------------------------------------------------------------
# Warrant side
# ---------------------------------------------------------------------------


def llm_capability(
    *,
    total_tokens: Optional[int] = None,
    max_tokens: Optional[int] = None,
    models: Optional[Sequence[str]] = None,
    period: Optional[str] = None,
    timezone: Optional[str] = None,
) -> Dict[str, Any]:
    """Constraints for a model-call capability.

    Args:
        total_tokens: Input plus output tokens the warrant, and everything
            delegated from it, may spend: in its lifetime, or in each
            ``period`` when one is given.
        max_tokens: Most output tokens one call may ask for.
        models: Models the warrant may call.
        period: ``"hour"``, ``"day"``, ``"week"`` or ``"month"`` to make
            ``total_tokens`` an allowance that starts again each period.
        timezone: IANA zone whose midnight starts a day, week or month
            (``"America/Vancouver"``). UTC when left out.
    """
    from tenuo import Exact, OneOf, Range

    out: Dict[str, Any] = {}
    if period is not None:
        if period not in PERIODS:
            raise ValueError(f"period must be one of {', '.join(PERIODS)}")
        if total_tokens is None:
            raise ValueError("a period needs total_tokens: it is the allowance for each period")
        out[PERIOD_FIELD] = Exact(period)
    if timezone is not None:
        if period is None:
            raise ValueError("timezone says where a period starts; give a period too")
        _zone(timezone)  # a zone this machine does not know is refused here, not on the first call
        out[ZONE_FIELD] = Exact(timezone)
    if models is not None:
        out[MODEL_FIELD] = OneOf(list(models))
    # Both ranges start at 0, not unbounded: a delegated warrant may only narrow
    # its parent's range, and a parent written as "0..N" (how Tenuo Cloud and
    # most hand-written policies put it) cannot be narrowed to a range with no
    # lower bound.
    if max_tokens is not None:
        out[OUTPUT_FIELD] = Range(min=0, max=_positive("max_tokens", max_tokens))
    if total_tokens is not None:
        out[DEFAULT_FIELD] = Range(min=0, max=_positive("total_tokens", total_tokens))
    return out


def _positive(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BudgetError(Exception):
    """Base class for budget errors."""


class BudgetExceeded(BudgetError):
    """The call would take a warrant past its token total.

    Attributes:
        warrant_id: The warrant whose total was reached.
        own: True when that is the caller's own warrant, False when it is one
            the caller's warrant was delegated from.
        limit: The total the warrant allows, when it is a plain upper bound.
        used: Tokens counted against the warrant before this call.
        needed: Fewest tokens this call would have added.
    """

    def __init__(self, *, warrant_id: str, own: bool, limit: Optional[int], used: int, needed: int,
                 period: Optional[str] = None, resets_at: Optional[float] = None) -> None:
        self.warrant_id = warrant_id
        self.own = own
        self.limit = limit
        self.used = used
        self.needed = needed
        self.period = period
        self.resets_at = resets_at
        whose = "this warrant" if own else "the warrant this one was delegated from"
        each = f" a {period}" if period else ""
        allows = f"allows {limit:,} tokens{each}" if limit is not None else "has a token total"
        again = ""
        if resets_at is not None:
            again = "; the next " + str(period) + " starts at " + datetime.fromtimestamp(
                resets_at, _timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        super().__init__(
            f"tenuo: token budget reached: {whose} {allows}, "
            f"{used:,} are used and this call needs at least {needed:,}{again}"
        )


class ModelCallDenied(BudgetError):
    """The warrant refused the model call for a reason other than the total.

    ``result`` is whatever the adapter's ``authorize`` callback returned, so the
    adapter can raise its own error type from it.
    """

    def __init__(self, result: Any) -> None:
        self.result = result
        super().__init__(getattr(result, "denial_reason", None) or "model call not authorized by warrant")


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------


@runtime_checkable
class BudgetBackend(Protocol):
    """Storage for running totals, one per warrant id.

    ``add`` is the only write. It must apply every delta and return the new
    totals as one atomic step, so two callers can never both read a total that
    omits the other's reservation. A total never goes below zero.
    """

    def add(self, deltas: Mapping[str, int], expires_at: Mapping[str, float]) -> Dict[str, int]:
        """Add ``deltas`` (negative to give tokens back) and return the new totals.

        ``expires_at`` gives, per key, the Unix time after which the row may be
        dropped.
        """
        ...

    def used(self, keys: Sequence[str]) -> Dict[str, int]:
        """Current total for each key; 0 for a key never seen."""
        ...


# Stores whose locks a forked child must not inherit as they were: one held by
# another thread at the fork would never open in the child.
_LOCKED: "weakref.WeakSet[Any]" = weakref.WeakSet()


def _reset_locks_in_child() -> None:
    for owner in list(_LOCKED):
        owner._reset_locks()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_locks_in_child)


class InMemoryBudgetBackend:
    """Thread-safe totals for one process."""

    def __init__(self) -> None:
        self._rows: Dict[str, List[float]] = {}  # key -> [used, expires_at]
        self._reset_locks()
        _LOCKED.add(self)

    def _reset_locks(self) -> None:
        self._lock = threading.Lock()

    def add(self, deltas: Mapping[str, int], expires_at: Mapping[str, float]) -> Dict[str, int]:
        with self._lock:
            self._evict(time.time())
            out: Dict[str, int] = {}
            for key, delta in deltas.items():
                row = self._rows.setdefault(key, [0, 0.0])
                row[0] = max(0, int(row[0]) + int(delta))
                row[1] = max(row[1], float(expires_at.get(key, 0.0)))
                out[key] = int(row[0])
            return out

    def used(self, keys: Sequence[str]) -> Dict[str, int]:
        with self._lock:
            return {k: int(self._rows[k][0]) if k in self._rows else 0 for k in keys}

    def _evict(self, now: float) -> None:
        for key in [k for k, row in self._rows.items() if row[1] and row[1] <= now]:
            del self._rows[key]


class SqliteBudgetBackend:
    """Totals in a SQLite file, shared by every process on the host that opens it.

    Each ``add`` is one ``BEGIN IMMEDIATE`` transaction. The file is put in WAL
    mode, so it must be on a local disk. A writer that finds the file busy
    waits and retries for up to ``timeout_seconds``; a file that still cannot
    be read or written raises, and the adapter then blocks the call.
    """

    def __init__(self, path: str, *, timeout_seconds: float = 30.0) -> None:
        self._path = str(path)
        self._timeout = timeout_seconds

        def create(conn: sqlite3.Connection) -> None:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS token_totals ("
                "key TEXT PRIMARY KEY, used INTEGER NOT NULL, expires_at REAL NOT NULL)"
            )

        self._run(create)

    def _connect(self) -> sqlite3.Connection:
        # A connection per operation: sqlite3 connections must not cross
        # threads, and the adapters call from worker threads and event loops.
        conn = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _run(self, work: Callable[[sqlite3.Connection], Any]) -> Any:
        """Run ``work`` on a fresh connection, retrying while the file is busy.

        SQLite's own wait is not fair between writers, so under contention one
        of them can be told the file is locked while others keep getting in.
        """
        deadline = time.monotonic() + self._timeout
        delay = 0.005
        while True:
            conn = None
            try:
                conn = self._connect()
                return work(conn)
            except sqlite3.OperationalError as e:
                busy = "locked" in str(e).lower() or "busy" in str(e).lower()
                if not busy or time.monotonic() >= deadline:
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.2)
            finally:
                if conn is not None:
                    conn.close()

    def add(self, deltas: Mapping[str, int], expires_at: Mapping[str, float]) -> Dict[str, int]:
        def work(conn: sqlite3.Connection) -> Dict[str, int]:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("DELETE FROM token_totals WHERE expires_at > 0 AND expires_at <= ?", (time.time(),))
                out: Dict[str, int] = {}
                for key, delta in deltas.items():
                    conn.execute(
                        "INSERT INTO token_totals (key, used, expires_at) VALUES (?, MAX(0, ?), ?) "
                        "ON CONFLICT(key) DO UPDATE SET "
                        "used = MAX(0, used + ?), expires_at = MAX(expires_at, excluded.expires_at)",
                        (key, int(delta), float(expires_at.get(key, 0.0)), int(delta)),
                    )
                    out[key] = int(conn.execute("SELECT used FROM token_totals WHERE key = ?", (key,)).fetchone()[0])
                conn.execute("COMMIT")
                return out
            except BaseException:
                # Nothing of a failed attempt stays: a retry starts from the stored totals.
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

        return self._run(work)

    def used(self, keys: Sequence[str]) -> Dict[str, int]:
        def work(conn: sqlite3.Connection) -> Dict[str, int]:
            out = {k: 0 for k in keys}
            for key in keys:
                row = conn.execute("SELECT used FROM token_totals WHERE key = ?", (key,)).fetchone()
                if row is not None:
                    out[key] = int(row[0])
            return out

        return self._run(work)


class BudgetStore:
    """Running token totals per warrant.

    ``BudgetStore()`` counts in memory, ``BudgetStore("budgets.db")`` in a
    SQLite file, and ``BudgetStore(backend=...)`` in any :class:`BudgetBackend`.

    Args:
        margin_seconds: How long a total is kept past its warrant's expiry, to
            cover clock differences between hosts.
    """

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        backend: Optional[BudgetBackend] = None,
        margin_seconds: int = 60,
    ) -> None:
        if path is not None and backend is not None:
            raise ValueError("pass a path or a backend, not both")
        if isinstance(margin_seconds, bool) or not isinstance(margin_seconds, int) or margin_seconds < 0:
            raise ValueError("margin_seconds must be a non-negative integer")
        if backend is not None:
            self._backend: BudgetBackend = backend
        elif path is not None:
            self._backend = SqliteBudgetBackend(path)
        else:
            self._backend = InMemoryBudgetBackend()
        self._margin = margin_seconds
        # Usage that could not be written (the backend failed after a call was
        # already billed). It rides along with the next write, so nothing more
        # is spent against these warrants until the total is right again.
        self._owed: Dict[str, int] = {}
        self._owed_expiries: Dict[str, float] = {}
        self._reset_locks()
        _LOCKED.add(self)

    def _reset_locks(self) -> None:
        self._owed_lock = threading.Lock()
        self._flush_lock = threading.Lock()  # one writer at a time carries the owed usage

    @property
    def blocking(self) -> bool:
        """False for the in-memory store, whose operations never wait on anything."""
        return not isinstance(self._backend, InMemoryBudgetBackend)

    def add(self, deltas: Mapping[str, int], expires_at: Optional[Mapping[str, float]] = None) -> Dict[str, int]:
        """Add tokens to each warrant id and return the new totals."""
        expiries = {k: (v + self._margin if v else 0.0) for k, v in (expires_at or {}).items()}
        with self._owed_lock:
            pending = bool(self._owed)
        if not pending:
            return self._with_owed(self._backend.add(deltas, expiries))
        # Reading what is owed, writing it and clearing it happen as one step,
        # so two writers cannot both carry the same owed usage.
        with self._flush_lock:
            with self._owed_lock:
                owed, owed_expiries = dict(self._owed), dict(self._owed_expiries)
            if not owed:
                return self._with_owed(self._backend.add(deltas, expiries))
            merged = dict(owed)
            for key, delta in deltas.items():
                merged[key] = merged.get(key, 0) + delta
            totals = self._backend.add(merged, {**owed_expiries, **expiries})
            with self._owed_lock:
                for key, amount in owed.items():
                    left = self._owed.get(key, 0) - amount
                    if left > 0:
                        self._owed[key] = left
                    else:
                        self._owed.pop(key, None)
                        self._owed_expiries.pop(key, None)
            return self._with_owed(totals)

    def _with_owed(self, totals: Dict[str, int]) -> Dict[str, int]:
        """Totals as ``used`` reports them: with usage that is owed and not yet written."""
        with self._owed_lock:
            if not self._owed:
                return totals
            return {key: total + self._owed.get(key, 0) for key, total in totals.items()}

    def owe(self, deltas: Mapping[str, int], expires_at: Optional[Mapping[str, float]] = None) -> None:
        """Remember usage a failed write left out, to be written with the next one."""
        with self._owed_lock:
            for key, delta in deltas.items():
                if delta > 0:
                    self._owed[key] = self._owed.get(key, 0) + delta
            for key, expiry in (expires_at or {}).items():
                if key in self._owed and expiry:
                    self._owed_expiries[key] = max(self._owed_expiries.get(key, 0.0), expiry + self._margin)

    def used(self, *warrant_ids: str) -> Dict[str, int]:
        """Tokens counted against each warrant id so far."""
        totals = self._backend.used(list(warrant_ids))
        with self._owed_lock:
            for key in warrant_ids:
                if key in self._owed:
                    totals[key] = totals.get(key, 0) + self._owed[key]
        return totals


# ---------------------------------------------------------------------------
# Usage and estimates
# ---------------------------------------------------------------------------

# Request fields that carry prompt text, across the wire formats.
_INPUT_KEYS = ("messages", "input", "prompt", "suffix", "instructions", "tools", "functions", "response_format",
               "text", "prediction")


# What one image is reserved at, whatever its size in bytes: providers bill an
# image by its dimensions, typically a few hundred to a couple of thousand tokens.
IMAGE_TOKEN_ESTIMATE = 1600
# Inline audio is reserved by its length: one token per this many base64 characters.
AUDIO_CHARS_PER_TOKEN = 1000

_IMAGE_PARTS = {"image_url": ("image_url",), "input_image": ("image_url", "file_id"), "image": ("source",)}
_BLOB_KEYS = ("inlineData", "inline_data", "fileData", "file_data")


def _audio_tokens(data: Any) -> int:
    return max(1, math.ceil(len(data) / AUDIO_CHARS_PER_TOKEN)) if isinstance(data, str) else 1


def _data_url_tokens(text: str) -> Optional[int]:
    head = text[:11].lower()
    if head.startswith("data:image/"):
        return IMAGE_TOKEN_ESTIMATE
    if head.startswith("data:audio/"):
        return _audio_tokens(text)
    return None


def _split_media(node: Any) -> Tuple[Any, int]:
    """A prompt without its image and audio parts, and the tokens to reserve for them.

    Their bytes say little about what they cost: a picture sent inline is
    megabytes of base64 and is billed as about a thousand tokens.
    """
    if isinstance(node, str):
        tokens = _data_url_tokens(node)
        return ("", tokens) if tokens is not None else (node, 0)
    if isinstance(node, Mapping):
        kind = node.get("type")
        if isinstance(kind, str):
            if any(key in node for key in _IMAGE_PARTS.get(kind, ())):
                return {"type": kind}, IMAGE_TOKEN_ESTIMATE
            if kind == "input_audio":
                audio = node.get("input_audio")
                data = audio.get("data") if isinstance(audio, Mapping) else node.get("data")
                return {"type": kind}, _audio_tokens(data)
        kept: Dict[str, Any] = {}
        total = 0
        for key, value in node.items():
            if key in _BLOB_KEYS and isinstance(value, Mapping):
                mime = str(value.get("mimeType") or value.get("mime_type") or "").lower()
                if mime.startswith("image/"):
                    total += IMAGE_TOKEN_ESTIMATE
                    continue
                if mime.startswith("audio/") and isinstance(value.get("data"), str):
                    total += _audio_tokens(value["data"])
                    continue
            kept[key], tokens = _split_media(value)
            total += tokens
        return kept, total
    if isinstance(node, (list, tuple)):
        items = [_split_media(item) for item in node]
        return [item for item, _ in items], sum(tokens for _, tokens in items)
    return node, 0


def estimate_input_tokens(request: Mapping[str, Any]) -> int:
    """Rough upper estimate of a request's input tokens, without a tokenizer.

    One token per three bytes of the JSON form of the prompt fields, which is
    on the high side for prose. An image counts as ``IMAGE_TOKEN_ESTIMATE``
    whether it is inline or linked, and inline audio by its length. It is only
    used to reserve before the call; the store is corrected to the provider's
    own count afterwards. Pass a tokenizer based function as
    ``TokenMeter(input_estimator=...)`` for a closer figure.
    """
    parts = {k: request[k] for k in _INPUT_KEYS if request.get(k) is not None}
    if not parts:
        return 0
    text, media = _split_media(parts)
    data = json.dumps(text, default=str, ensure_ascii=False)
    return math.ceil(len(data.encode("utf-8")) / 3) + 16 + media


def usage_counts(usage: Any) -> Optional[Dict[str, int]]:
    """Normalize a provider usage object to input, output and total tokens.

    Accepts the Chat Completions shape (``prompt_tokens`` /
    ``completion_tokens``), the Responses shape (``input_tokens`` /
    ``output_tokens``), objects or dicts. Returns None when there is no usable
    count, so the caller keeps the reservation as the charge.
    """
    if usage is None:
        return None

    impossible = []

    def read(*names: str) -> Optional[int]:
        for name in names:
            value = usage.get(name) if isinstance(usage, Mapping) else getattr(usage, name, None)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                if not math.isfinite(value) or value < 0:
                    impossible.append(name)
                    continue
                return int(value)
        return None

    inp = read("prompt_tokens", "input_tokens")
    out = read("completion_tokens", "output_tokens")
    total = read("total_tokens")
    if impossible:
        return None  # a count below zero, or not a finite number, is not a count: the reservation stands
    if total is None:
        if inp is None and out is None:
            return None
        total = (inp or 0) + (out or 0)
    inp, out = inp or 0, out or 0
    total = max(total, inp + out)  # a total below its own parts is not a total
    if total > inp + out:
        # Some providers leave thinking tokens out of the completion count but
        # bill them in the total. They are output.
        out = total - inp
    return {"input_tokens": inp, "output_tokens": out, "total_tokens": total}


# ---------------------------------------------------------------------------
# Metering
# ---------------------------------------------------------------------------


@dataclass
class BudgetLevel:
    """One warrant a call spends from: the caller's own, or one above it."""

    warrant: Any
    warrant_id: str
    own: bool
    constraint: Optional[Any]  # the signed total, when this warrant has one
    limit: Optional[int]  # its upper bound, when it is a plain Range
    expires_at: float  # when the row may be dropped: the warrant's end, or the period's
    used: int = 0  # filled in as the call proceeds
    key: str = ""  # where the store keeps this total: the warrant, or the warrant and period
    period: Optional[str] = None  # the signed period, when the total is per period
    zone: Optional[str] = None  # the signed time zone of that period, when one was given
    resets_at: Optional[float] = None  # when the current period ends
    problem: Optional[str] = None  # why a signed period cannot be counted by, if it cannot

    def __post_init__(self) -> None:
        if not self.key:
            self.key = self.warrant_id

    def snapshot(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"warrant_id": self.warrant_id, "used": self.used}
        if self.period is not None:
            out["period"] = self.period
            if self.resets_at is not None:
                out["resets_at"] = self.resets_at
        if self.limit is not None:
            out["limit"] = self.limit
        if not self.own:
            out["delegated_from"] = True
        return out


@dataclass
class MeteredCall:
    """A model call the meter has reserved tokens for.

    ``max_output`` is the output cap per choice the request must carry.
    """

    tool: str
    model: Optional[str]
    max_output: Optional[int]
    reserved: int
    input_estimate: int
    clamped: bool
    enforced: bool
    levels: List[BudgetLevel]
    _store: BudgetStore = dc_field(repr=False, default=None)  # type: ignore[assignment]
    _done: bool = dc_field(repr=False, default=False)
    _lock: threading.Lock = dc_field(repr=False, default_factory=threading.Lock)
    usage: Optional[Dict[str, Any]] = None
    # Scratch space for the adapter that runs the call (never read here).
    adapter_state: Dict[str, Any] = dc_field(repr=False, default_factory=dict)
    # True when the output cap is below what the call would otherwise have had,
    # because a budget in the chain is running out.
    lowered: bool = False

    @property
    def done(self) -> bool:
        return self._done

    def settle(self, usage: Any = None) -> Dict[str, Any]:
        """Replace the reservation with what the call really used.

        ``usage`` is the provider's usage object. When it is missing the
        reservation stands as the charge and the record says ``estimated``.
        Returns the usage record for audit. Only the first settle or release
        has an effect.
        """
        with self._lock:
            if self._done:
                return self.usage or {}
            self._done = True
        counts = usage_counts(usage)
        estimated = counts is None
        if counts is None:
            counts = {"input_tokens": self.input_estimate, "output_tokens": self.reserved - self.input_estimate,
                      "total_tokens": self.reserved}
        delta = counts["total_tokens"] - self.reserved
        try:
            totals = self._apply(delta)
        except Exception:
            if delta > 0:
                # The call used more than was reserved and the store could not
                # take the difference: it must not be forgotten.
                self._store.owe({lv.key: delta for lv in self.levels},
                                {lv.key: lv.expires_at for lv in self.levels})
            raise
        for level in self.levels:
            level.used = totals.get(level.key, level.used)
        record: Dict[str, Any] = dict(counts)
        if estimated:
            record["estimated"] = True
        if self.clamped:
            record["clamped"] = True
        over = [lv.warrant_id for lv in self.levels if lv.limit is not None and lv.used > lv.limit]
        if over:
            record["over_budget"] = over
        record["budget"] = [lv.snapshot() for lv in self.levels]
        self.usage = record
        return record

    def release(self) -> None:
        """The call did not run: give the reservation back."""
        with self._lock:
            if self._done:
                return
            self._done = True
        self._apply(-self.reserved)

    def _apply(self, delta: int) -> Dict[str, int]:
        keys = [lv.key for lv in self.levels]
        if delta == 0:
            return self._store.used(*keys)
        return self._store.add({k: delta for k in keys}, {lv.key: lv.expires_at for lv in self.levels})


class TokenMeter:
    """Meters model calls against the token totals in a warrant chain.

    Args:
        store: Where totals are kept. A path makes a SQLite store; None counts
            in memory.
        tool: Capability name that covers model calls.
        field: Constraint name that holds the total.
        enforce: False only records usage, and flags a passed total in the
            usage record. No call is refused and no output cap is set.
        default_max_output: Output cap used when neither the caller nor the
            warrant gives one.
        input_estimator: ``request -> tokens`` used for the reservation.
        clock: ``() -> Unix time`` that says which period a call falls in,
            for budgets signed with one. Rows are still dropped by real time.
    """

    def __init__(
        self,
        store: Union[BudgetStore, str, None] = None,
        *,
        tool: str = DEFAULT_TOOL,
        field: str = DEFAULT_FIELD,
        enforce: bool = True,
        default_max_output: int = 4096,
        input_estimator: Callable[[Mapping[str, Any]], int] = estimate_input_tokens,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.clock = clock  # says which period a call falls in
        self.store = store if isinstance(store, BudgetStore) else BudgetStore(store)
        self.tool = tool
        self.field = field
        self.enforce = enforce
        self.default_max_output = _positive("default_max_output", default_max_output)
        self._estimate = input_estimator

    @classmethod
    def coerce(cls, value: Any) -> Optional["TokenMeter"]:
        """Accept a meter, a store, or a SQLite path wherever a meter is expected."""
        if value is None or isinstance(value, TokenMeter):
            return value
        if isinstance(value, (BudgetStore, str)):
            return cls(value)
        raise TypeError("budget_store must be a TokenMeter, a BudgetStore or a path")

    # -- warrant reading ---------------------------------------------------

    def levels(self, warrant: Any, chain: Optional[Sequence[Any]] = None) -> List[BudgetLevel]:
        """The warrants a call spends from, root first, the caller's own last."""
        out: List[BudgetLevel] = []
        now = self.clock()
        for w in list(chain or []) + [warrant]:
            signed = self._constraints(w)
            constraint = signed.get(self.field)
            level = BudgetLevel(
                warrant=w,
                warrant_id=str(w.id),
                own=w is warrant,
                constraint=constraint,
                limit=_upper_bound(constraint),
                expires_at=_expiry(w),
            )
            if PERIOD_FIELD in signed or ZONE_FIELD in signed:
                # The total is for each period: one row per warrant and period, kept
                # until that period ends.
                level.period, level.zone = _signed_text(signed.get(PERIOD_FIELD)), _signed_text(signed.get(ZONE_FIELD))
                try:
                    label, level.resets_at = _period_bounds(level.period, level.zone, now)
                except ValueError as exc:
                    level.problem = str(exc)
                else:
                    level.key = f"{level.warrant_id}@{label}"
                    ends = [t for t in (level.expires_at, level.resets_at) if t]
                    level.expires_at = min(ends) if ends else 0.0
            out.append(level)
        return out

    def status(self, warrant: Any, chain: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
        """Where each warrant a call would spend from stands, root first.

        One entry per warrant: ``warrant_id``, ``used``, and for a warrant
        with a total, ``limit`` and ``remaining``. A total that is per period
        also has ``period`` and ``resets_at``, and ``used`` is for the current
        period. ``used`` includes the reservations of calls still running.
        """
        levels = self.levels(warrant, chain)
        used = self.store.used(*[lv.key for lv in levels])
        out = []
        for lv in levels:
            lv.used = used.get(lv.key, 0)
            entry = lv.snapshot()
            if lv.limit is not None:
                entry["remaining"] = max(0, lv.limit - lv.used)
            out.append(entry)
        return out

    def remaining(self, warrant: Any, chain: Optional[Sequence[Any]] = None) -> Optional[int]:
        """Tokens left before a call under this warrant is refused.

        The least room of any warrant in the chain, or None when none of them
        has a total.
        """
        rooms = [entry["remaining"] for entry in self.status(warrant, chain) if "remaining" in entry]
        return min(rooms) if rooms else None

    def model_allowed(self, warrant: Any, model: str) -> bool:
        """Whether the warrant's model constraint, if it has one, admits ``model``."""
        constraint = self._constraints(warrant).get(MODEL_FIELD)
        if constraint is None:
            return True
        from tenuo.core import check_constraint

        return bool(check_constraint(constraint, model))

    def _constraints(self, warrant: Any) -> Dict[str, Any]:
        # As the warrant check does: the tool's own capability, else the wildcard.
        caps = getattr(warrant, "capabilities", None) or {}
        if not isinstance(caps, Mapping):
            return {}
        found = caps.get(self.tool)
        if found is None:
            found = caps.get("*")
        return dict(found) if isinstance(found, Mapping) else {}

    # -- the call ----------------------------------------------------------

    def begin(
        self,
        warrant: Any,
        chain: Optional[Sequence[Any]],
        request: Mapping[str, Any],
        *,
        requested_output: Optional[int],
        choices: int = 1,
        authorize: Callable[[str, Dict[str, Any]], Any],
        as_sent: Optional[Callable[[int], Mapping[str, Any]]] = None,
    ) -> MeteredCall:
        """Reserve tokens for one model call and have the warrant authorize it.

        Args:
            warrant: The caller's warrant.
            chain: Its parents, root first, when presented.
            request: The request about to be sent (prompt fields are read for
                the estimate, and any field the warrant constrains is checked).
            requested_output: The output cap the caller asked for, if any.
            choices: Completions requested (``n``); each may use the cap.
            authorize: ``(tool, args) -> result`` run by the adapter for the
                caller's own warrant. ``result.allowed`` decides; on refusal
                ``result.constraint_violated`` names the field.
            as_sent: ``output cap -> request`` for an adapter that changes the
                request before sending it (the cap, for one). The warrant then
                checks the fields of what is sent, not of what was written.

        Raises:
            BudgetExceeded: A total in the chain would be passed.
            ModelCallDenied: The warrant refused for another reason.
        """
        levels = self.levels(warrant, chain)
        model = request.get(MODEL_FIELD)
        if self.enforce:
            for lv in levels:
                problem = lv.problem or _budget_problem(lv.constraint)
                if problem is not None:
                    # A budget the meter cannot count against is refused, not
                    # guessed at: the running total is checked as an upper bound.
                    raise ModelCallDenied(_Refusal(
                        f"the token budget of warrant {lv.warrant_id} is not usable: {problem}", self.field))
        if not self.enforce:
            return MeteredCall(self.tool, model, None, 0, 0, False, False, levels, self.store)

        choices = max(1, int(choices or 1))
        input_estimate = max(0, int(self._estimate(request)))
        before = self.store.used(*[lv.key for lv in levels])
        for lv in levels:
            lv.used = before.get(lv.key, 0)

        own = self._constraints(warrant)
        want = requested_output
        if want is None:
            want = self.default_max_output
            per_call = _upper_bound(own.get(OUTPUT_FIELD))
            if per_call is not None:
                want = min(want, per_call)
        rooms = [lv.limit - lv.used for lv in levels if lv.limit is not None]
        cap = want
        if rooms:
            # Never ask for more than is left. At least 1, so that when nothing
            # is left the request still reaches the core and the core refuses.
            cap = max(1, min(want, (min(rooms) - input_estimate) // choices))
        clamped = requested_output is not None and cap < requested_output
        reserved = input_estimate + cap * choices
        checked = as_sent(cap) if as_sent is not None else request

        call = MeteredCall(self.tool, model, cap, reserved, input_estimate, clamped, True, levels, self.store)
        call.lowered = cap < want
        totals = self.store.add(
            {lv.key: reserved for lv in levels}, {lv.key: lv.expires_at for lv in levels}
        )
        try:
            self._decide(call, own, checked, totals, before, input_estimate + choices, authorize)
        except BaseException:
            call.release()
            raise
        for lv in levels:
            lv.used = totals.get(lv.key, lv.used)
        return call

    def _decide(
        self,
        call: MeteredCall,
        own: Dict[str, Any],
        request: Mapping[str, Any],
        totals: Mapping[str, int],
        before: Mapping[str, int],
        needed: int,
        authorize: Callable[[str, Dict[str, Any]], Any],
    ) -> None:
        leaf = call.levels[-1]

        # Parents first: only their total is in question, since the core
        # already refused any child that is wider than its parent elsewhere.
        from tenuo.core import check_constraint

        for lv in call.levels[:-1]:
            if lv.constraint is not None and not check_constraint(lv.constraint, totals[lv.key]):
                raise BudgetExceeded(
                    warrant_id=lv.warrant_id, own=False, limit=lv.limit,
                    used=before.get(lv.key, 0), needed=needed,
                    period=lv.period, resets_at=lv.resets_at,
                )

        # The caller's own warrant goes through the adapter's full check
        # (chain, expiry, proof of possession), with the running total as the
        # value of the budget argument.
        args: Dict[str, Any] = {MODEL_FIELD: call.model, OUTPUT_FIELD: call.max_output}
        if own:
            # A capability with constraints is closed: pass exactly the
            # constrained fields. One the request lacks is left out, and the
            # core refuses it as missing.
            args = {k: v for k, v in args.items() if k in own}
            for name in own:
                if name not in args and not name.startswith("_") and name != self.field and name in request:
                    args[name] = request[name]
        # A total per period: the meter says which period it counted by, and the core
        # checks that against the signed one.
        if PERIOD_FIELD in own:
            args[PERIOD_FIELD] = leaf.period
        if ZONE_FIELD in own:
            args[ZONE_FIELD] = leaf.zone
        if not own or self.field in own:
            args[self.field] = totals[leaf.key]
        result = authorize(self.tool, args)
        if getattr(result, "allowed", False):
            return
        if getattr(result, "constraint_violated", None) == self.field:
            raise BudgetExceeded(
                warrant_id=leaf.warrant_id, own=True, limit=leaf.limit,
                used=before.get(leaf.key, 0), needed=needed,
                period=leaf.period, resets_at=leaf.resets_at,
            )
        raise ModelCallDenied(result)


class _Refusal:
    """A refusal the meter makes itself, shaped like an authorization result."""

    allowed = False
    error_type = "constraint_violation"

    def __init__(self, reason: str, field: str) -> None:
        self.denial_reason = reason
        self.constraint_violated = field


def _budget_problem(constraint: Any) -> Optional[str]:
    """Why a budget constraint cannot be metered, or None when it can.

    A budget is "at most N tokens": a range from 0 (or unbounded below) up to
    N. The meter authorizes each call with the total it could reach, so a range
    that starts above 0, or anything that is not a range with an upper bound,
    would be checked against a number that says nothing about it.
    """
    if constraint is None:
        return None
    upper = getattr(constraint, "max", None)
    if isinstance(upper, bool) or not isinstance(upper, (int, float)):
        return "it must be a range with an upper bound"
    lower = getattr(constraint, "min", None)
    if isinstance(lower, (int, float)) and not isinstance(lower, bool) and lower > 0:
        return "its range must start at 0"
    return None


def _signed_text(constraint: Any) -> Optional[str]:
    """The one value an Exact constraint allows, as text; None for anything else."""
    value = getattr(constraint, "value", None)
    return value if isinstance(value, str) else None


def _zone(name: Optional[str]) -> Any:
    """The time zone a period starts in: UTC when none is signed."""
    if not name or name == "UTC":
        return _timezone.utc
    from zoneinfo import ZoneInfo

    try:
        return ZoneInfo(name)
    except Exception as exc:
        raise ValueError(f"its period's time zone {name!r} is not one this machine knows") from exc


def _period_bounds(period: Optional[str], zone: Optional[str], now: float) -> Tuple[str, float]:
    """The period ``now`` falls in: a label that names it, and when it ends.

    Raises ValueError, worded to follow "the token budget ... is not usable:",
    for a period this meter cannot count by. A budget whose period is not
    understood is refused, never counted as if it had none.
    """
    if period not in PERIODS:
        raise ValueError(f"its period must be signed as one of {', '.join(PERIODS)}")
    at = datetime.fromtimestamp(now, _zone(zone))
    if period == "hour":
        start = at.replace(minute=0, second=0, microsecond=0)
        # By elapsed time, so the hour that repeats when clocks go back is two periods.
        return "hour:" + start.astimezone(_timezone.utc).strftime("%Y-%m-%dT%H"), start.timestamp() + 3600
    day = at.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
    if period == "day":
        first, following = day, day + timedelta(days=1)
    elif period == "week":
        first = day - timedelta(days=day.weekday())
        following = first + timedelta(days=7)
    else:
        first = day.replace(day=1)
        following = (first + timedelta(days=32)).replace(day=1)
    # Midnight on the wall clock of the zone, whatever the offset is on that date.
    end = following.replace(tzinfo=at.tzinfo).timestamp()
    return f"{period}:{first.strftime('%Y-%m-%d')}", end


def _upper_bound(constraint: Any) -> Optional[int]:
    """Upper bound of a Range constraint, or None for anything else."""
    if constraint is None:
        return None
    value = getattr(constraint, "max", None)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(math.floor(value))


def _expiry(warrant: Any) -> float:
    """Unix expiry of a warrant; 0 when it cannot be read (the row is then kept)."""
    try:
        raw = warrant.expires_at() if callable(getattr(warrant, "expires_at", None)) else warrant.expires_at
        if isinstance(raw, (int, float)):
            return float(raw)
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except Exception:
        logger.debug("could not read warrant expiry", exc_info=True)
        return 0.0
