"""Runtime sessions, context isolation, and aggregate receipt outbox."""

from __future__ import annotations

import threading

import pytest
from tenuo_core import Pattern, SigningKey, Warrant

from tenuo import HolderIdentity, Runtime, get_runtime, guard
from tenuo._enforcement import enforce_tool_call
from tenuo.decorators import get_signing_key_context, get_warrant_context
from tenuo.exceptions import ConfigurationError
from tenuo.receipts import ReceiptBufferFull


@pytest.fixture
def pair():
    root = SigningKey.generate()
    holder = HolderIdentity.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(root)
    )
    runtime = Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
    )
    return root, holder, warrant, runtime


def test_session_from_wire_and_scope_isolation(pair):
    _root, holder, warrant, runtime = pair
    session = runtime.session_from_wire(warrant)
    assert get_runtime() is None
    assert get_warrant_context() is None

    with runtime.session_scope(session):
        assert get_runtime() is runtime
        assert get_warrant_context().id == warrant.id
        assert get_signing_key_context().public_key == holder.public_key

    assert get_runtime() is None
    assert get_warrant_context() is None


def test_session_from_wire_rejects_holder_mismatch(pair):
    _root, _holder, warrant, _runtime = pair
    other = Runtime(
        identity=HolderIdentity.generate(),
        trusted_roots=_runtime.trusted_roots,
    )
    with pytest.raises(ConfigurationError, match="holder"):
        other.session_from_wire(warrant)


def test_requires_trusted_roots():
    with pytest.raises(ConfigurationError, match="trusted root"):
        Runtime(identity=HolderIdentity.generate(), trusted_roots=[])


def test_collects_allow_and_deny(pair):
    root, holder, warrant, runtime = pair
    session = runtime.session_from_wire(warrant)
    with runtime.session_scope(session):
        allow = enforce_tool_call(
            "read_file",
            {"path": "/data/q3.pdf"},
            session.bound,
        )
        deny = enforce_tool_call(
            "read_file",
            {"path": "/etc/passwd"},
            session.bound,
        )
    assert allow.allowed
    assert not deny.allowed
    receipts = runtime.peek_receipts()
    assert len(receipts) == 2
    import tenuo_core

    assert tenuo_core.verify_receipt(receipts[0]).outcome == "allow"
    assert tenuo_core.verify_receipt(receipts[1]).outcome == "deny"
    assert runtime.drain_receipts() == receipts
    assert runtime.peek_receipts() == receipts
    assert runtime.acknowledge_receipts(2) == 2
    assert runtime.peek_receipts() == []


def test_aggregates_across_sessions_and_derived(pair):
    root, holder, warrant, runtime = pair
    other = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/other/*"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(root)
    )
    first = runtime.session_from_wire(warrant)
    second = runtime.session_from_wire(other)
    derived = first.derive(warrant)
    with runtime.session_scope(first):
        enforce_tool_call("read_file", {"path": "/data/a.pdf"}, first.bound)
    with runtime.session_scope(second):
        enforce_tool_call("read_file", {"path": "/data/other/b.pdf"}, second.bound)
    with runtime.session_scope(derived):
        enforce_tool_call("read_file", {"path": "/data/c.pdf"}, derived.bound)
    assert len(runtime.peek_receipts()) == 3


def test_guard_inside_session_scope(pair):
    _root, _holder, warrant, runtime = pair
    session = runtime.session_from_wire(warrant)

    @guard(tool="read_file")
    def read_file(path: str) -> str:
        return path

    with runtime.session_scope(session):
        assert read_file(path="/data/q3.pdf") == "/data/q3.pdf"
    assert len(runtime.peek_receipts()) == 1


def test_overflow_is_explicit(pair):
    root, holder, warrant, _runtime = pair
    runtime = Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
        receipt_maxsize=1,
    )
    session = runtime.session_from_wire(warrant)
    with runtime.session_scope(session):
        enforce_tool_call("read_file", {"path": "/data/a.pdf"}, session.bound)
        with pytest.raises(ReceiptBufferFull):
            enforce_tool_call("read_file", {"path": "/data/b.pdf"}, session.bound)
    assert len(runtime.peek_receipts()) == 1


def test_concurrent_producers_serialized_ack(pair):
    _root, _holder, warrant, runtime = pair
    session = runtime.session_from_wire(warrant)
    errors = []

    def produce():
        try:
            with runtime.session_scope(session):
                for _ in range(20):
                    enforce_tool_call(
                        "read_file", {"path": "/data/q3.pdf"}, session.bound
                    )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=produce) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    pending = runtime.peek_receipts()
    assert len(pending) == 80
    acked = 0

    def ack():
        nonlocal acked
        acked += runtime.acknowledge_receipts(10)

    ack_threads = [threading.Thread(target=ack) for _ in range(8)]
    for thread in ack_threads:
        thread.start()
    for thread in ack_threads:
        thread.join()
    assert acked == 80
    assert runtime.peek_receipts() == []


def test_shutdown_leaves_unacked_receipts(pair):
    _root, _holder, warrant, runtime = pair
    session = runtime.session_from_wire(warrant)
    with runtime.session_scope(session):
        enforce_tool_call("read_file", {"path": "/data/q3.pdf"}, session.bound)
    runtime.close()
    assert len(runtime.peek_receipts()) == 1
