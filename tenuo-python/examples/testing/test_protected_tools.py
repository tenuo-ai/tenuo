"""Pytest recipe for application code protected by Tenuo.

The tests below use real warrants and the public ``tenuo.testing`` helpers.
They intentionally avoid ``allow_all()`` so authorization failures prove that a
protected function body did not run.
"""

from __future__ import annotations

import pytest

from tenuo import Exact, SigningKey, Warrant, guard, key_scope, warrant_scope
from tenuo.exceptions import ToolNotAuthorized
from tenuo.testing import (
    assert_authorized,
    assert_can_grant,
    assert_cannot_grant,
    assert_denied,
    deterministic_headers,
)


ALLOWED_RECORD_ID = "customer-123"
DENIED_RECORD_ID = "customer-999"


def mint_record_reader(record_id: str = ALLOWED_RECORD_ID) -> tuple[Warrant, SigningKey]:
    """Create a fresh warrant and holder key for each test."""
    key = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("read_record", record_id=Exact(record_id))
        .holder(key.public_key)
        .ttl(300)
        .mint(key)
    )
    return warrant, key


def protected_read_record(calls: list[str], issuer_key: SigningKey):
    """Return a guarded application function that records real executions."""

    @guard(tool="read_record", trusted_roots=[issuer_key.public_key])
    def read_record(record_id: str) -> dict[str, str]:
        calls.append(record_id)
        return {"record_id": record_id, "status": "ok"}

    return read_record


def test_allowed_record_executes_with_real_authorization():
    warrant, key = mint_record_reader()
    calls: list[str] = []
    read_record = protected_read_record(calls, key)

    with warrant_scope(warrant), key_scope(key):
        with assert_authorized():
            result = read_record(ALLOWED_RECORD_ID)

    assert result == {"record_id": ALLOWED_RECORD_ID, "status": "ok"}
    assert calls == [ALLOWED_RECORD_ID]


def test_denied_record_does_not_enter_function_body():
    warrant, key = mint_record_reader()
    calls: list[str] = []
    read_record = protected_read_record(calls, key)

    with warrant_scope(warrant), key_scope(key):
        with assert_denied(code="authorization_denied"):
            read_record(DENIED_RECORD_ID)

    assert calls == []


def test_missing_capability_uses_stable_error_code():
    warrant, key = mint_record_reader()
    calls: list[str] = []

    @guard(tool="delete_record", trusted_roots=[key.public_key])
    def delete_record(record_id: str) -> str:
        calls.append(record_id)
        return "deleted"

    with warrant_scope(warrant), key_scope(key):
        with pytest.raises(ToolNotAuthorized) as exc_info:
            delete_record(ALLOWED_RECORD_ID)

    assert exc_info.value.error_code == "tool_not_authorized"
    assert calls == []


def test_direct_warrant_assertions_cover_allowed_and_denied_args():
    warrant, key = mint_record_reader()

    with assert_authorized(warrant, key, "read_record", {"record_id": ALLOWED_RECORD_ID}):
        pass

    with assert_denied(warrant, key, "read_record", {"record_id": DENIED_RECORD_ID}):
        pass


def test_child_grant_can_narrow_but_cannot_widen_scope():
    warrant, key = mint_record_reader()

    child, child_key = assert_can_grant(
        warrant,
        key,
        child_tools=["read_record"],
        child_constraints={"record_id": Exact(ALLOWED_RECORD_ID)},
    )

    with assert_authorized(child, child_key, "read_record", {"record_id": ALLOWED_RECORD_ID}):
        pass

    assert_cannot_grant(
        warrant,
        key,
        child_tools=["read_record"],
        child_constraints={"record_id": Exact(DENIED_RECORD_ID)},
    )


def test_deterministic_headers_are_stable_for_regression_snapshots():
    warrant, key = mint_record_reader()
    args = {"record_id": ALLOWED_RECORD_ID}

    first = deterministic_headers(warrant, key, "read_record", args, timestamp=1_700_000_000)
    second = deterministic_headers(warrant, key, "read_record", args, timestamp=1_700_000_000)

    assert first == second
    assert "X-Tenuo-Warrant" in first
    assert "X-Tenuo-PoP" in first
