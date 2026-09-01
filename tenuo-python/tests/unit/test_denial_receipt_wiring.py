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
