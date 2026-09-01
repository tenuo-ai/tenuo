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
