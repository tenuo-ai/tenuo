"""The enforcement wiring that feeds denial receipts.

The producer (`issue_denial_receipt`) was tested; these pin the part that
feeds it — that `enforce_tool_call` denials actually carry the presented
chain, the authorizer, and the verified PoP, and that what reaches the
receipt is the truth about possession.
"""

from __future__ import annotations

import time

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import ControlPlaneClient, Pattern, SigningKey, Warrant  # noqa: E402

from tenuo._enforcement import enforce_tool_call  # noqa: E402


@pytest.fixture
def signing_key():
    return SigningKey.generate()


@pytest.fixture
def bound(signing_key):
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(signing_key.public_key)
        .ttl(3600)
        .mint(signing_key)
    )
    return warrant.bind(signing_key)


def test_a_constraint_denial_carries_the_verified_pop(bound, signing_key):
    """PoP verifies, then constraints fail — possession WAS established.

    Without verified_pop on this path, the receipt goes through
    deny_before_pop and claims possession was never established: the false
    claim the denial producer was explicitly built to avoid.
    """
    result = enforce_tool_call(
        "read_file",
        {"path": "/etc/passwd"},
        bound,
        trusted_roots=[signing_key.public_key],
    )

    assert not result.allowed
    assert result.error_type == "constraint_violation"
    assert result.presented_chain, "denial must carry the presented chain"
    assert result.authorizer is not None
    assert result.verified_pop is not None, (
        "constraint failures happen after PoP verification; the receipt must "
        "be able to say so"
    )


def test_a_wrong_tool_denial_still_carries_the_chain(bound, signing_key):
    result = enforce_tool_call(
        "delete_file",
        {"path": "/data/x"},
        bound,
        trusted_roots=[signing_key.public_key],
    )

    assert not result.allowed
    assert result.presented_chain


def test_the_denial_receipt_asserts_possession_when_it_was_proven(bound, signing_key):
    """End to end: enforcement denial → signed receipt with the PoP attached."""
    result = enforce_tool_call(
        "read_file",
        {"path": "/etc/passwd"},
        bound,
        trusted_roots=[signing_key.public_key],
    )

    client = ControlPlaneClient(url="http://127.0.0.1:1", api_key="k", authorizer_name="t")
    client.bind_authorizer(result.authorizer)
    wire = client.issue_denial_receipt(
        list(result.presented_chain),
        result.tool,
        result.arguments,
        int(time.time()),
        "req-1",
        "constraint-violation",
        bytes(result.verified_pop),
    )
    payload = tenuo_core.verify_receipt(wire)

    assert payload.outcome == "deny"
    assert payload.decision_code == "constraint-violation"
    # The whole point: an authenticated party was refused, and the receipt
    # says so instead of claiming possession was never established.
    assert payload.pop_signature is not None
    payload.check_conditional_requirements()


def test_key_10_uses_the_canonical_vocabulary():
    """Two runtimes disagreeing on key 10 makes it useless for correlation."""
    from tenuo.control_plane import _DECISION_CODE_BY_ERROR_TYPE

    assert _DECISION_CODE_BY_ERROR_TYPE["constraint_violation"] == "constraint-violation"
    assert _DECISION_CODE_BY_ERROR_TYPE["untrusted_issuer"] == "untrusted-root"
    assert _DECISION_CODE_BY_ERROR_TYPE["approval_gate_misconfigured"] == "approval-invalid"


def test_a_split_view_denial_commits_to_what_the_holder_signed(bound, signing_key):
    """Key 7 must hash the PoP view, not the host's original tool_args.

    Allows hash the pop_args view inside check_chain. A None-valued argument
    makes the stripped PoP view differ from tool_args, so hashing the wrong
    view here would produce a receipt that fails a later --args check against
    the wire payload — a genuine receipt, rejected.
    """
    from tenuo.receipts import InMemoryReceiptSink

    raw_args = {"path": "/etc/passwd", "note": None}
    result = enforce_tool_call(
        "read_file",
        raw_args,
        bound,
        trusted_roots=[signing_key.public_key],
    )
    assert not result.allowed
    assert result.pop_auth_args == {"path": "/etc/passwd"}, (
        "the denial must carry the stripped view the holder signed over"
    )

    from tenuo.control_plane import ControlPlaneClient as PyControlPlaneClient

    sink = InMemoryReceiptSink()
    client = PyControlPlaneClient(
        url="http://127.0.0.1:1",
        api_key="k",
        authorizer_name="t",
        receipt_sink=sink,
    )
    client.bind_authorizer(result.authorizer)
    client.emit_for_enforcement(result)

    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])

    leaf = result.presented_chain[-1]
    holder = leaf.authorized_holder() if callable(leaf.authorized_holder) else leaf.authorized_holder
    leaf_id = leaf.id() if callable(leaf.id) else leaf.id

    pop_view_hash = tenuo_core.py_compute_request_hash(
        leaf_id, "read_file", {"path": "/etc/passwd"}, holder
    ).hex()

    # The raw view is not even hashable — py_compute_request_hash rejects the
    # None value — which is its own proof that hashing result.arguments here
    # could never have matched what allows commit to.
    assert result.arguments != result.pop_auth_args
    assert payload.request_hash == pop_view_hash


# ── receipt qualification: which decisions get one at all ───────────────────
#
# The rule: a decision qualifies for a receipt iff a sink is configured, the
# decision was made over presented parseable authority (a decoded chain), and
# the trust context is known (bound, or the result carries the authorizer
# that decided). Presented is not the same as valid — an untrusted chain
# qualifies. No warrant, undecodable bytes, and envelope failures do not.


def _py_client(sink=None):
    from tenuo.control_plane import ControlPlaneClient as PyClient

    return PyClient(
        url="http://127.0.0.1:1", api_key="k", authorizer_name="t", receipt_sink=sink
    )


def test_no_sink_means_no_receipts_and_no_errors(bound, signing_key):
    """Receipts are opt-in: without a sink the deny path is a quiet no-op."""
    result = enforce_tool_call(
        "read_file", {"path": "/etc/passwd"}, bound,
        trusted_roots=[signing_key.public_key],
    )

    _py_client(sink=None).emit_for_enforcement(result)  # must not raise


def test_a_decision_without_presented_authority_is_not_receipted(bound, signing_key):
    """The shape MCP/FastAPI envelope failures produce: no chain, no receipt.

    A caller with no warrant was turned away at the door, not authorized
    against anything — there is no chain for a receipt to commit to.
    """
    from tenuo.receipts import InMemoryReceiptSink
    from tenuo._enforcement import EnforcementResult

    structural = EnforcementResult(
        allowed=False,
        tool="read_file",
        arguments={},
        denial_reason="missing warrant",
        error_type="invalid_pop",
    )

    sink = InMemoryReceiptSink()
    _py_client(sink=sink).emit_for_enforcement(structural)

    assert len(sink.receipts) == 0


def test_a_qualifying_denial_is_receipted_without_explicit_binding(bound, signing_key):
    """The result carries the authorizer that decided; binding is automatic."""
    from tenuo.receipts import InMemoryReceiptSink

    result = enforce_tool_call(
        "read_file", {"path": "/etc/passwd"}, bound,
        trusted_roots=[signing_key.public_key],
    )

    sink = InMemoryReceiptSink()
    client = _py_client(sink=sink)  # never bind_authorizer()ed
    client.emit_for_enforcement(result)

    assert len(sink.receipts) == 1
    assert tenuo_core.verify_receipt(sink.receipts[0]).outcome == "deny"


def test_unbound_with_no_authorizer_on_the_result_warns_once(caplog):
    """A sink with nothing to sign under is a misconfiguration worth one
    loud line — and exactly one, not one per decision."""
    import logging

    from tenuo.receipts import InMemoryReceiptSink
    from tenuo._enforcement import EnforcementResult

    bare = EnforcementResult(
        allowed=False, tool="t", arguments={}, denial_reason="x", error_type="expired"
    )
    sink = InMemoryReceiptSink()
    client = _py_client(sink=sink)

    with caplog.at_level(logging.WARNING):
        client.emit_for_enforcement(bare)
        client.emit_for_enforcement(bare)

    assert len(sink.receipts) == 0
    warnings = [r for r in caplog.records if "no authorizer was available" in r.message]
    assert len(warnings) == 1


def test_presented_but_untrusted_authority_still_qualifies(signing_key):
    """Presented is not valid. A parseable chain from a root the enforcement
    point does not trust is refused — and that refusal is a decision over
    presented authority, receipted like any other. The receipt's own chain
    check then corroborates the refusal for any verifier."""
    from tenuo.receipts import InMemoryReceiptSink

    stranger = SigningKey.generate()
    foreign_warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Pattern("/data/*"))
        .holder(stranger.public_key)
        .ttl(3600)
        .mint(stranger)
    )
    result = enforce_tool_call(
        "read_file",
        {"path": "/data/q3.pdf"},
        foreign_warrant.bind(stranger),
        trusted_roots=[signing_key.public_key],  # does not trust the stranger
    )
    assert not result.allowed
    assert result.presented_chain

    sink = InMemoryReceiptSink()
    _py_client(sink=sink).emit_for_enforcement(result)

    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])
    assert payload.outcome == "deny"
    # The refusal is receipted, and key 10 names the trust failure rather
    # than folding it into a PoP miss.
    assert payload.decision_code == "untrusted-root"
