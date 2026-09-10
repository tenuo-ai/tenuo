"""Runtime sessions, context isolation, and aggregate receipt outbox."""

from __future__ import annotations

import threading

import pytest
from tenuo_core import Pattern, SigningKey, Warrant, encode_warrant_stack

from tenuo import HolderIdentity, Runtime, bind_runtime, get_runtime, guard
from tenuo._enforcement import enforce_tool_call
from tenuo.decorators import chain_scope, get_signing_key_context, get_warrant_context
from tenuo.exceptions import ConfigurationError, UntrustedRoot


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


def test_install_is_process_default_without_session_scope(pair):
    _root, _holder, warrant, runtime = pair
    assert get_runtime() is None
    runtime.install()
    try:
        assert get_runtime() is runtime
        session = runtime.session_from_wire(warrant)
        result = enforce_tool_call(
            "read_file", {"path": "/data/q3.pdf"}, session.bound
        )
        assert result.allowed
        assert len(runtime.peek_receipts()) == 1
    finally:
        Runtime.uninstall()
    assert get_runtime() is None


def test_bind_overrides_process_default(pair):
    _root, _holder, warrant, runtime = pair
    other = Runtime(
        identity=HolderIdentity.generate(),
        trusted_roots=runtime.trusted_roots,
        receipts="collect",
    )
    runtime.install()
    try:
        with bind_runtime(other):
            assert get_runtime() is other
        assert get_runtime() is runtime
        with other.bind():
            assert get_runtime() is other
        assert get_runtime() is runtime
    finally:
        Runtime.uninstall()


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
    third = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/c.pdf"))
        .holder(holder.public_key)
        .ttl(3600)
        .mint(root)
    )
    first = runtime.session_from_wire(warrant)
    second = runtime.session_from_wire(other)
    third_session = runtime.session_from_wire(third)
    with runtime.session_scope(first):
        first_result = enforce_tool_call("read_file", {"path": "/data/a.pdf"}, first.bound)
    with runtime.session_scope(second):
        second_result = enforce_tool_call(
            "read_file", {"path": "/data/other/b.pdf"}, second.bound
        )
    with runtime.session_scope(third_session):
        third_result = enforce_tool_call(
            "read_file", {"path": "/data/c.pdf"}, third_session.bound
        )
    assert first_result.allowed
    assert second_result.allowed
    assert third_result.allowed
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


def test_overflow_does_not_deny_authorized_call(pair):
    root, holder, warrant, _runtime = pair
    runtime = Runtime(
        identity=holder,
        trusted_roots=[root.public_key],
        receipts="collect",
        receipt_maxsize=1,
    )
    session = runtime.session_from_wire(warrant)
    with runtime.session_scope(session):
        first = enforce_tool_call("read_file", {"path": "/data/a.pdf"}, session.bound)
        second = enforce_tool_call("read_file", {"path": "/data/b.pdf"}, session.bound)
    assert first.allowed
    assert second.allowed
    assert len(runtime.peek_receipts()) == 1
    assert runtime.receipt_overflows == 1


def _three_hop_stack(root_key: SigningKey, holder: HolderIdentity):
    mid = SigningKey.generate()
    worker = SigningKey.generate()
    root = (
        Warrant.mint_builder()
        .capability("read_file")
        .capability("list_dir")
        .holder(mid.public_key)
        .ttl(3600)
        .mint(root_key)
    )
    intermediate = (
        root.grant_builder()
        .capability("read_file")
        .capability("list_dir")
        .holder(worker.public_key)
        .ttl(1800)
        .grant(mid)
    )
    leaf = (
        intermediate.grant_builder()
        .capability("read_file")
        .holder(holder.public_key)
        .ttl(900)
        .grant(worker)
    )
    return root, intermediate, leaf


def test_session_scope_installs_parent_chain_for_guard(pair):
    root_key, holder, _warrant, _runtime = pair
    root, intermediate, leaf = _three_hop_stack(root_key, holder)
    runtime = Runtime(identity=holder, trusted_roots=[root_key.public_key], receipts="collect")
    session = runtime.session_from_wire([root, intermediate, leaf])
    assert [w.id for w in session._parents] == [root.id, intermediate.id]

    @guard(tool="read_file")
    def read_file() -> str:
        return "ok"

    with runtime.session_scope(session):
        parents = chain_scope()
        assert [w.id for w in parents] == [root.id, intermediate.id]
        assert read_file() == "ok"
        orphan = runtime.session_from_wire(leaf)
        with runtime.session_scope(orphan):
            assert chain_scope() == []
            with pytest.raises(UntrustedRoot):
                read_file()
        assert [w.id for w in chain_scope()] == [root.id, intermediate.id]
    assert chain_scope() is None


def test_session_context_manager_installs_parent_chain(pair):
    root_key, holder, _warrant, _runtime = pair
    root, intermediate, leaf = _three_hop_stack(root_key, holder)
    runtime = Runtime(identity=holder, trusted_roots=[root_key.public_key])
    session = runtime.session_from_wire(encode_warrant_stack([root, intermediate, leaf]))
    with session:
        result = enforce_tool_call("read_file", {}, session.bound)
    assert result.allowed
    orphan = runtime.session_from_wire(leaf)
    with orphan:
        denied = enforce_tool_call("read_file", {}, orphan.bound)
    assert not denied.allowed
    assert "root" in (denied.denial_reason or "").lower() or "issuer" in (
        denied.denial_reason or ""
    ).lower()


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
