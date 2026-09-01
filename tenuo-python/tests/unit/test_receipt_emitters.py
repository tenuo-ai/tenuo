"""The two emission postures behind one seam.

They differ in exactly one decision — when signing happens — so the artifact
and the chain must be posture-independent, and only the loss contract may
differ: deferred pays an enqueue and can lose up to maxsize on a crash;
journal pays the signing inline and is durable before emit returns.
"""

from __future__ import annotations

import time

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import Authorizer, Pattern, SigningKey, Warrant  # noqa: E402

from tenuo.control_plane import ControlPlaneClient  # noqa: E402
from tenuo.receipts import DeferredEmitter, InMemoryReceiptSink, JournalEmitter  # noqa: E402


@pytest.fixture
def decision():
    root, worker = SigningKey.generate(), SigningKey.generate()
    authorizer = Authorizer(trusted_roots=[root.public_key])
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(worker.public_key)
        .ttl(3600)
        .mint(root)
    )
    args = {"path": "/data/q3.pdf"}
    pop = warrant.sign(worker, "read_file", args, int(time.time()))
    result = authorizer.check_chain([warrant], "read_file", args, signature=pop)
    return authorizer, result


def _client(**kw):
    return ControlPlaneClient(
        url="http://127.0.0.1:1", api_key="k", authorizer_name="t", **kw
    )


def test_a_bare_sink_defaults_to_deferred_with_the_256_budget():
    sink = InMemoryReceiptSink()
    client = _client(receipt_sink=sink)

    emitter = client._receipt_emitter
    assert isinstance(emitter, DeferredEmitter)
    assert emitter._q.maxsize == 256


def test_the_unbounded_loss_budget_is_not_constructible():
    # The unbounded configuration lost five million receipts in one measured
    # crash; it must not exist.
    with pytest.raises(ValueError):
        DeferredEmitter(InMemoryReceiptSink(), maxsize=0)
    with pytest.raises(ValueError):
        DeferredEmitter(InMemoryReceiptSink(), maxsize=-1)


def test_deferred_signs_off_thread_and_flush_waits(decision):
    authorizer, result = decision
    sink = InMemoryReceiptSink()
    client = _client(receipt_sink=sink)
    client.bind_authorizer(authorizer)

    for i in range(20):
        client._emit_receipt(result, "read_file", True, f"req-{i}", None)
    assert client.flush_receipts()

    assert len(sink.receipts) == 20


def test_journal_is_durable_before_emit_returns(decision, tmp_path):
    authorizer, result = decision
    path = tmp_path / "receipts.wal"
    client = _client(receipt_emitter=JournalEmitter(path, fsync_interval_s=None))
    client.bind_authorizer(authorizer)

    client._emit_receipt(result, "read_file", True, "req-0", None)

    # No flush, no drain: the write reached the kernel inside emit. This is
    # the property that makes SIGKILL loss zero.
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert tenuo_core.verify_receipt(lines[0]).outcome == "allow"


@pytest.mark.parametrize("posture", ["deferred", "journal"])
def test_the_chain_is_posture_independent(decision, tmp_path, posture):
    """A verifier must not be able to tell which posture produced a receipt."""
    import hashlib

    authorizer, result = decision
    if posture == "deferred":
        sink = InMemoryReceiptSink()
        client = _client(receipt_sink=sink)
    else:
        client = _client(
            receipt_emitter=JournalEmitter(tmp_path / "r.wal", fsync_interval_s=None)
        )
    client.bind_authorizer(authorizer)

    for i in range(3):
        client._emit_receipt(result, "read_file", True, f"req-{i}", None)
    assert client.flush_receipts()

    wires = (
        sink.receipts
        if posture == "deferred"
        else (tmp_path / "r.wal").read_text().splitlines()
    )
    assert len(wires) == 3
    for prev, current in zip(wires, wires[1:]):
        payload = tenuo_core.verify_receipt(current)
        assert payload.prev_receipt_hash == hashlib.sha256(bytes.fromhex(prev)).hexdigest()
    assert tenuo_core.verify_receipt(wires[0]).prev_receipt_hash is None


def test_journal_output_feeds_the_chain_walker(decision, tmp_path):
    from tenuo.cli import verify_receipt_chain

    authorizer, result = decision
    path = tmp_path / "r.wal"
    client = _client(receipt_emitter=JournalEmitter(path, fsync_interval_s=None))
    client.bind_authorizer(authorizer)
    for i in range(3):
        client._emit_receipt(result, "read_file", True, f"req-{i}", None)

    assert verify_receipt_chain(str(path)) is True


def test_a_failing_delivery_does_not_kill_the_deferred_worker(decision):
    authorizer, result = decision

    class FlakySink:
        def __init__(self):
            self.receipts = []
            self.calls = 0

        def handle(self, wire):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("disk full")
            self.receipts.append(wire)

    seen = []
    sink = FlakySink()
    client = _client(
        receipt_emitter=DeferredEmitter(sink, maxsize=16),
        on_receipt_error=seen.append,
    )
    client.bind_authorizer(authorizer)

    for i in range(3):
        client._emit_receipt(result, "read_file", True, f"req-{i}", None)
    assert client.flush_receipts()

    # One receipt lost at delivery — reported, and chain-visible: the third
    # receipt's link dangles. The worker survived to sign it.
    assert len(sink.receipts) == 2
    assert len(seen) == 1


def test_shutdown_drains_the_deferred_queue(decision):
    authorizer, result = decision
    sink = InMemoryReceiptSink()
    client = _client(receipt_sink=sink)
    client.bind_authorizer(authorizer)

    for i in range(10):
        client._emit_receipt(result, "read_file", True, f"req-{i}", None)
    # Exercise the emitter's close directly: full client.shutdown() also calls
    # the Rust client's shutdown, which panics without a Tokio reactor in
    # standalone/offline mode — a pre-existing wart unrelated to draining.
    client._receipt_emitter.close(timeout=10.0)

    assert len(sink.receipts) == 10
