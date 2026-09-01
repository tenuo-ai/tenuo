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
from pathlib import Path
from typing import Callable, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

__all__ = [
    "ReceiptSink",
    "InMemoryReceiptSink",
    "FileReceiptSink",
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
