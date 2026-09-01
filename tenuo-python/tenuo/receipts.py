"""Durable handoff for signed authorization receipts.

A receipt is evidence, and evidence that is dropped when a queue fills is not
evidence. Audit events are telemetry — losing one costs you a data point.
Losing a receipt costs you the ability to prove what happened, so receipts get
their own outlet with delivery semantics the host chooses rather than riding
the best-effort audit channel.

A sink must never deny a tool call: authorization has already been decided by
the time a receipt exists. Sink failures are therefore isolated, but unlike a
dropped audit event they are *reported* — a silent evidence gap is the failure
mode worth engineering against.

What qualifies a decision for a receipt
---------------------------------------

All three, or no receipt is produced:

1. **A sink is configured.** Receipts are opt-in.
2. **The decision was made over presented, parseable authority** — a warrant
   chain that decoded. Allows carry it as the verification result; denials as
   ``presented_chain``. Presented is not the same as *valid*: a chain from an
   untrusted root, an expired chain, a constraint miss — all qualify, and the
   receipt's own embedded chain then corroborates the refusal. What does not
   qualify is a call with no warrant at all, or bytes that would not decode:
   those were turned away at the door, not decided over authority, and there
   is nothing for a receipt to commit to. They stay in the audit stream.
3. **The trust context is known** — the client is bound to the authorizer
   that decided, automatically when the result carries it, or via
   ``bind_authorizer``. A sink configured with no way to bind warns once and
   emits nothing: an enforcement point that cannot say what it trusted has
   nothing worth signing.

Note the bar in (2) is a *parseable* warrant, which any caller can mint —
denial-receipt volume is therefore attacker-influenceable, like audit-event
volume. Unlike audit events, receipts do not drop under pressure by design;
bound your sink accordingly (``InMemoryReceiptSink`` counts what it evicts).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

__all__ = [
    "ReceiptSink",
    "InMemoryReceiptSink",
    "FileReceiptSink",
    "DeferredEmitter",
    "JournalEmitter",
    "deliver",
]


@runtime_checkable
class ReceiptSink(Protocol):
    """Where signed receipts go.

    ``handle`` receives the receipt as hex. Implementations should make
    delivery durable before returning; raising is preferred over returning
    early, because a raise is reported while a silent no-op is not.
    """

    def handle(self, receipt_hex: str) -> None: ...


class InMemoryReceiptSink:
    """Keeps receipts in a list. For tests and single-process inspection.

    Does not survive the process, so it is not an audit trail. ``max_receipts``
    bounds growth; once reached the oldest are dropped and ``dropped`` counts
    them, so a full buffer is visible rather than silent.
    """

    def __init__(self, max_receipts: int = 10_000) -> None:
        if max_receipts < 1:
            raise ValueError("max_receipts must be at least 1")
        self._max = max_receipts
        self._receipts: List[str] = []
        self._lock = threading.Lock()
        self.dropped = 0

    def handle(self, receipt_hex: str) -> None:
        with self._lock:
            self._receipts.append(receipt_hex)
            if len(self._receipts) > self._max:
                overflow = len(self._receipts) - self._max
                del self._receipts[:overflow]
                self.dropped += overflow

    @property
    def receipts(self) -> List[str]:
        with self._lock:
            return list(self._receipts)

    def __len__(self) -> int:
        with self._lock:
            return len(self._receipts)


class FileReceiptSink:
    """Appends receipts to a JSONL file, one object per line.

    Append-only so the file mirrors the receipt chain: entries are added, never
    rewritten. ``fsync`` defaults to True because the point of the file is to
    survive the crash that made you want the evidence; set it False only when
    you have another durability guarantee underneath.
    """

    def __init__(self, path: "str | Path", *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = fsync
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def handle(self, receipt_hex: str) -> None:
        line = json.dumps({"receipt": receipt_hex}, separators=(",", ":"))
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                if self._fsync:
                    os.fsync(handle.fileno())

    @property
    def path(self) -> Path:
        return self._path


def deliver(
    sink: Optional[ReceiptSink],
    receipt_hex: Optional[str],
    on_error: Optional[Callable[[BaseException], None]] = None,
) -> None:
    """Hand a receipt to a sink without letting failure reach the caller.

    Authorization is already decided by the time this runs, so a sink must not
    turn a permitted call into a denied one. The failure is reported rather
    than swallowed: an evidence gap nobody knows about is worse than one that
    shows up in the logs.
    """
    if sink is None or receipt_hex is None:
        return
    try:
        sink.handle(receipt_hex)
    except BaseException as exc:  # noqa: BLE001 - isolation is the point
        if on_error is not None:
            try:
                on_error(exc)
                return
            except BaseException:  # noqa: BLE001
                pass
        logger.warning("receipt sink failed; evidence for this decision was not stored", exc_info=exc)


# ── emission postures ────────────────────────────────────────────────────────
#
# The two postures differ in exactly one decision: when signing happens.
# The chain, the qualification rules, and the artifact are identical — a
# verifier cannot tell which posture produced a receipt. Only the loss
# contract differs, one line each:
#
#   DeferredEmitter  ~0.5 µs on the hot path (measured through
#                    ControlPlaneClient); a crash may take up to ``maxsize``
#                    receipts with it.
#   JournalEmitter   ~17 µs p50 on the hot path (measured through
#                    ControlPlaneClient; the Rust signing floor is ~13 µs);
#                    a process crash takes nothing — the append reaches the
#                    page cache before emit returns.


class DeferredEmitter:
    """Latency-strict posture: hand the decision to a worker, sign off-thread.

    The decision context is queued **by reference** — do not mutate the
    ``chain_result`` after emitting it.

    The hot path pays a blocking enqueue. A single worker signs in FIFO
    order — which is what preserves the receipt chain — and hands the wire
    to the sink. ``maxsize`` is the loss budget: a SIGKILL loses at most the
    queued decisions, and under sustained overload the enqueue blocks rather
    than sheds, because anonymous interior gaps are the one thing the chain
    cannot expose. Size it as ``rate × the longest outage to ride out``.

    ``maxsize`` is required to be positive. The unbounded configuration lost
    five million receipts in one measured crash and is not constructible.
    """

    def __init__(self, sink, maxsize: int = 256) -> None:
        if sink is None:
            raise ValueError("DeferredEmitter requires a sink")
        if not isinstance(maxsize, int) or maxsize <= 0:
            raise ValueError(
                "maxsize is the crash-loss budget and must be a positive int"
            )
        import queue as _queue

        self._sink = sink
        self._q: "_queue.Queue" = _queue.Queue(maxsize)
        self._inner = None
        self._on_error = None
        self._worker: Optional[threading.Thread] = None

    # Called by ControlPlaneClient: the emitter signs with the client's own
    # key so both postures share one identity and one chain.
    def _attach(self, inner, on_error) -> None:
        self._inner = inner
        self._on_error = on_error
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def emit_allow(self, chain_result, tool, allowed, ts, request_id, decision_code) -> None:
        self._q.put(("allow", chain_result, tool, allowed, ts, request_id, decision_code))

    def emit_denial(self, chain, tool, args, ts, request_id, decision_code, verified_pop) -> None:
        self._q.put(("deny", chain, tool, args, ts, request_id, decision_code, verified_pop))

    def qsize(self) -> int:
        return self._q.qsize()

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                self._q.task_done()
                return
            try:
                if item[0] == "allow":
                    _, chain_result, tool, allowed, ts, request_id, code = item
                    wire = self._inner.issue_receipt(
                        chain_result, tool, allowed, ts, request_id, code
                    )
                else:
                    _, chain, tool, args, ts, request_id, code, pop = item
                    wire = self._inner.issue_denial_receipt(
                        chain, tool, args, ts, request_id, code, pop
                    )
                deliver(self._sink, wire, self._on_error)
            except Exception as exc:  # noqa: BLE001 — one bad item must not kill the worker
                logger.warning("deferred receipt emission failed", exc_info=exc)
            finally:
                self._q.task_done()

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until everything enqueued so far is signed and delivered.

        Uses the queue's own unfinished-task accounting (the counter
        ``task_done`` maintains), which counts an item from ``put`` until its
        delivery completes — so an item the worker has popped but not finished
        still holds the flush. An emptiness poll cannot say that.
        """
        deadline = time.monotonic() + timeout
        with self._q.all_tasks_done:
            while self._q.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._q.all_tasks_done.wait(remaining)
        return True

    def close(self, timeout: float = 10.0) -> None:
        if self._worker is None:
            return
        self._q.put(None)
        self._worker.join(timeout)
        self._worker = None


class JournalEmitter:
    """Evidence-strict posture: sign and persist on the request thread.

    The receipt is appended (one hex line, readable by ``tenuo receipt
    chain``) and flushed into the page cache before the call returns, so a
    process crash loses nothing. The residual window is machine death, which
    the optional periodic fsync bounds — at a cost: fsync contends with the
    hot-path append on the same inode, and the measured worst co-stall was
    232 ms at full saturation. Segmented rotation removes that structurally
    and is the planned follow-up; until then, size ``fsync_interval_s``
    generously on write-heavy deployments.
    """

    def __init__(self, path: "str | Path", *, fsync_interval_s: Optional[float] = 0.5) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        self._inner = None
        self._on_error = None
        self._write_lock = threading.Lock()
        self._stop = threading.Event()
        if fsync_interval_s is not None:
            def _fsyncer() -> None:
                while not self._stop.wait(fsync_interval_s):
                    try:
                        os.fsync(self._fd)
                    except OSError:
                        pass
            threading.Thread(target=_fsyncer, daemon=True).start()

    def _attach(self, inner, on_error) -> None:
        self._inner = inner
        self._on_error = on_error

    @property
    def path(self) -> Path:
        return self._path

    def _append(self, wire: Optional[str]) -> None:
        if wire is None:
            return
        try:
            data = (wire + "\n").encode("ascii")
            # Serialized: concurrent appends of multi-KB lines interleave
            # without a lock, and os.write may return short — a torn line in
            # an evidence file is worse than a slightly slower one.
            with self._write_lock:
                view = memoryview(data)
                while view:
                    written = os.write(self._fd, view)
                    view = view[written:]
        except BaseException as exc:  # noqa: BLE001 — must not fail the tool call
            if self._on_error is not None:
                try:
                    self._on_error(exc)
                    return
                except BaseException:  # noqa: BLE001
                    pass
            logger.warning("journal append failed; evidence not stored", exc_info=exc)

    def emit_allow(self, chain_result, tool, allowed, ts, request_id, decision_code) -> None:
        self._append(self._inner.issue_receipt(
            chain_result, tool, allowed, ts, request_id, decision_code
        ))

    def emit_denial(self, chain, tool, args, ts, request_id, decision_code, verified_pop) -> None:
        self._append(self._inner.issue_denial_receipt(
            chain, tool, args, ts, request_id, decision_code, verified_pop
        ))

    def flush(self, timeout: float = 10.0) -> bool:  # noqa: ARG002 — nothing pending
        os.fsync(self._fd)
        return True

    def close(self, timeout: float = 10.0) -> None:  # noqa: ARG002
        self._stop.set()
        try:
            os.fsync(self._fd)
        finally:
            os.close(self._fd)
