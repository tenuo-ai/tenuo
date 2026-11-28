"""Tests for Temporal downstream idempotency keys."""

from __future__ import annotations

import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import pytest

from tenuo.temporal import TenuoContextError, current_idempotency_key
from tenuo.temporal._idempotency import (
    _activity_idempotency_context,
    _derive_idempotency_key,
)


def _read_key_in_process() -> str:
    try:
        return current_idempotency_key()
    except TenuoContextError:
        return "<no-context>"


def test_key_is_retry_stable_and_opaque() -> None:
    first = _derive_idempotency_key("warrant-1", "run-1", "activity-1")
    retry = _derive_idempotency_key("warrant-1", "run-1", "activity-1")

    assert first == retry
    assert first.startswith("tnu_op_v1_")
    assert "warrant-1" not in first
    assert "run-1" not in first
    assert "activity-1" not in first


@pytest.mark.parametrize("field", [0, 1, 2])
def test_each_scope_component_changes_key(field: int) -> None:
    baseline = ["warrant-1", "run-1", "activity-1"]
    changed = baseline.copy()
    changed[field] += "-other"

    assert _derive_idempotency_key(*baseline) != _derive_idempotency_key(*changed)


def test_length_prefixing_prevents_component_ambiguity() -> None:
    assert _derive_idempotency_key("ab", "c", "d") != _derive_idempotency_key("a", "bc", "d")


def test_helper_fails_clearly_outside_authorized_activity() -> None:
    with pytest.raises(TenuoContextError, match="authorized Activity"):
        current_idempotency_key()


def test_context_is_reset_after_activity() -> None:
    with _activity_idempotency_context("warrant-1", "run-1", "activity-1") as key:
        assert current_idempotency_key() == key

    with pytest.raises(TenuoContextError):
        current_idempotency_key()


def test_nested_context_restores_outer_activity() -> None:
    with _activity_idempotency_context("warrant-1", "run-1", "activity-1") as outer:
        with _activity_idempotency_context("warrant-2", "run-2", "activity-2") as inner:
            assert current_idempotency_key() == inner
        assert current_idempotency_key() == outer


def test_concurrent_activities_are_context_isolated() -> None:
    async def read_key(activity_id: str) -> str:
        with _activity_idempotency_context("warrant-1", "run-1", activity_id):
            await asyncio.sleep(0)
            return current_idempotency_key()

    async def gather() -> tuple[str, str]:
        first, second = await asyncio.gather(read_key("a"), read_key("b"))
        return first, second

    first, second = asyncio.run(gather())
    assert first != second


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(),
    reason="requires the fork start method",
)
def test_forked_process_pool_never_reuses_parent_activity_key() -> None:
    fork_context = multiprocessing.get_context("fork")
    with ProcessPoolExecutor(max_workers=1, mp_context=fork_context) as pool:
        with _activity_idempotency_context("warrant-1", "run-1", "activity-1"):
            assert pool.submit(_read_key_in_process).result() == "<no-context>"
        with _activity_idempotency_context("warrant-2", "run-2", "activity-2"):
            assert pool.submit(_read_key_in_process).result() == "<no-context>"
