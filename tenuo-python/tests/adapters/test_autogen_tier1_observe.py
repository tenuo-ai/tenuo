"""AutoGen Tier 1 guards (no warrant) honor observe mode."""

import asyncio
import logging

import pytest

from tenuo.autogen import GuardBuilder
from tenuo.config import configure, reset_config
from tenuo.constraints import Pattern
from tenuo.exceptions import ConstraintViolation, ToolNotAuthorized


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def search(query: str) -> str:
    return f"found {query}"


def shell(cmd: str) -> str:
    return f"ran {cmd}"


async def asearch(query: str) -> str:
    return f"found {query}"


def _guard():
    return GuardBuilder().allow("search", query=Pattern("ok*")).allow("asearch", query=Pattern("ok*")).build()


def test_enforce_mode_blocks_tier1_denials():
    guard = _guard()
    with pytest.raises(ConstraintViolation):
        guard.guard_tool(search)(query="nope")
    with pytest.raises(ToolNotAuthorized):
        guard.guard_tool(shell)(cmd="ls")


def test_observe_mode_lets_tier1_denials_through_and_logs(caplog):
    configure(mode="observe", dev_mode=True)
    guard = _guard()
    with caplog.at_level(logging.WARNING, logger="tenuo.enforcement"):
        assert guard.guard_tool(search)(query="nope") == "found nope"
        assert guard.guard_tool(shell)(cmd="ls") == "ran ls"
    messages = [r.getMessage() for r in caplog.records]
    assert any(m.startswith("OBSERVE: would deny search") for m in messages)
    assert any(m.startswith("OBSERVE: would deny shell") for m in messages)


def test_observe_mode_async_tier1_denial_proceeds(caplog):
    configure(mode="observe", dev_mode=True)
    guard = _guard()
    with caplog.at_level(logging.WARNING, logger="tenuo.enforcement"):
        assert asyncio.run(guard.guard_tool(asearch)(query="nope")) == "found nope"
    assert any(r.getMessage().startswith("OBSERVE: would deny asearch") for r in caplog.records)
