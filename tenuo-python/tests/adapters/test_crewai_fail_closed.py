"""CrewAI hooks fail closed when driven by a real ``Crew.kickoff()``.

CrewAI's hook dispatcher swallows any exception a ``before_tool_call`` hook
raises and runs the tool, and never awaits a coroutine a hook returns. These
tests run real crews with a scripted LLM and assert that a tool body the
policy forbids never executes.
"""

import asyncio
import json
import os
import sys
import warnings
from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")

from crewai import Agent, Crew, Process, Task  # noqa: E402
from crewai.flow.flow import Flow, start  # noqa: E402
from crewai.hooks import (  # noqa: E402
    clear_before_tool_call_hooks,
    register_before_tool_call_hook,
)
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402
from tenuo_core import Range, SigningKey, Warrant  # noqa: E402

from tenuo.approval import cli_prompt  # noqa: E402
from tenuo.config import reset_config  # noqa: E402
from tenuo.crewai import (  # noqa: E402
    CrewAIConfigurationError,
    GuardBuilder,
    Pattern,
    Subpath,
    guarded_step,
)

EXECUTED: list = []


class ScriptedLLM(BaseLLM):
    """Returns one native tool call per scripted entry, then a final answer."""

    def __init__(self, calls, **kw):
        super().__init__(model="scripted", **kw)
        object.__setattr__(self, "_calls", list(calls))
        object.__setattr__(self, "_i", 0)

    def supports_function_calling(self) -> bool:
        return True

    def call(self, messages, tools=None, callbacks=None, available_functions=None, **kw):
        i = self._i
        object.__setattr__(self, "_i", i + 1)
        if i < len(self._calls):
            name, args = self._calls[i]
            return [{"id": f"call_{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]
        return "final answer"

    def supports_stop_words(self):
        return False

    def get_context_window_size(self):
        return 8192


def _crew(tools, calls, role="Researcher"):
    agent = Agent(
        role=role,
        goal="g",
        backstory="b",
        tools=tools,
        llm=ScriptedLLM(calls),
        max_iter=len(calls) + 2,
        verbose=False,
        allow_delegation=False,
    )
    task = Task(description="do it", expected_output="x", agent=agent)
    return Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)


@tool("transfer_funds")
def transfer_funds(amount: int) -> str:
    """Transfer funds."""
    EXECUTED.append(("transfer_funds", amount))
    return "TRANSFERRED"


@tool("delete_file")
def delete_file(path: str) -> str:
    """Delete a file."""
    EXECUTED.append(("delete_file", path))
    return "deleted"


@tool("read_file")
def read_file(path: str = "/etc/passwd") -> str:
    """Read a file."""
    EXECUTED.append(("read_file", path))
    return "contents"


@tool("search")
def search(query: str) -> str:
    """Search."""
    EXECUTED.append(("search", query))
    return "results"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    # Another test module replaces rich modules with mocks in sys.modules and
    # leaves them there; CrewAI's console output imports from rich lazily.
    for name, module in list(sys.modules.items()):
        if name.split(".")[0] == "rich" and isinstance(module, MagicMock):
            monkeypatch.delitem(sys.modules, name)
    reset_config()
    clear_before_tool_call_hooks()
    EXECUTED.clear()
    yield
    clear_before_tool_call_hooks()
    reset_config()


# -- approvals ---------------------------------------------------------------


def _approval_warrant():
    control, agent_key, approver_key = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .capability("transfer_funds", amount=Range(0, 100_000))
        .approval_gates({"transfer_funds": {"args": None, "message": "A human must confirm this transfer."}})
        .required_approvers([approver_key.public_key])
        .min_approvals(1)
        .holder(agent_key.public_key)
        .ttl(3600)
        .mint(control)
    )
    return control, agent_key, approver_key, warrant


def _approval_guard(control, agent_key, warrant, handler, audit=None):
    builder = (
        GuardBuilder()
        .allow("transfer_funds", amount=Range(0, 100_000))
        .with_warrant(warrant, agent_key)
        .with_trusted_roots([control.public_key])
    )
    if handler is not None:
        builder = builder.on_approval(handler)
    if audit is not None:
        builder = builder.audit(audit)
    return builder.build()


def test_refused_approval_blocks_tool(monkeypatch):
    control, agent_key, approver_key, warrant = _approval_warrant()
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    events = []
    guard = _approval_guard(control, agent_key, warrant, cli_prompt(approver_key=approver_key), events.append)
    guard.register()

    _crew([transfer_funds], [("transfer_funds", {"amount": 50000})]).kickoff()

    assert EXECUTED == []
    assert [(e.decision, e.error_code) for e in events] == [("DENY", "APPROVAL_DENIED")]


def test_missing_approval_handler_blocks_tool():
    control, agent_key, _, warrant = _approval_warrant()
    events = []
    _approval_guard(control, agent_key, warrant, None, events.append).register()

    _crew([transfer_funds], [("transfer_funds", {"amount": 50000})]).kickoff()

    assert EXECUTED == []
    assert [(e.decision, e.error_code) for e in events] == [("DENY", "APPROVAL_REQUIRED")]


def test_granted_approval_runs_tool(monkeypatch):
    control, agent_key, approver_key, warrant = _approval_warrant()
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    _approval_guard(control, agent_key, warrant, cli_prompt(approver_key=approver_key)).register()

    _crew([transfer_funds], [("transfer_funds", {"amount": 50000})]).kickoff()

    assert EXECUTED == [("transfer_funds", 50000)]


def test_unexpected_error_in_authorization_blocks_tool(monkeypatch):
    guard = GuardBuilder().allow("search", query=Pattern("*")).build()

    def boom(*_a, **_k):
        raise RuntimeError("bug")

    monkeypatch.setattr(guard, "_authorize", boom)
    guard.register()

    _crew([search], [("search", {"query": "x"})]).kickoff()

    assert EXECUTED == []


# -- async hook --------------------------------------------------------------


def test_as_async_hook_returns_a_blocking_sync_hook():
    guard = GuardBuilder().allow("search", query=Pattern("*")).build()
    with pytest.warns(DeprecationWarning):
        hook = guard.as_async_hook()
    assert not asyncio.iscoroutinefunction(hook)
    register_before_tool_call_hook(hook)

    _crew([delete_file], [("delete_file", {"path": "/x"})]).kickoff()

    assert EXECUTED == []


def test_as_async_hook_blocks_under_kickoff_async():
    guard = GuardBuilder().allow("search", query=Pattern("*")).build()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        register_before_tool_call_hook(guard.as_async_hook())

    asyncio.run(_crew([delete_file], [("delete_file", {"path": "/x"})]).kickoff_async())

    assert EXECUTED == []


# -- @guarded_step on Flow steps ---------------------------------------------


def _step_crew():
    return _crew([delete_file], [("delete_file", {"path": "/x"})], role="r")


def test_guarded_step_sync_flow_blocks_tool():
    class SyncFlow(Flow):
        @start()
        @guarded_step(allow={"read_file": {"path": Subpath("/data")}})
        def step(self):
            return _step_crew().kickoff()

    SyncFlow().kickoff()
    assert EXECUTED == []


def test_guarded_step_async_flow_blocks_tool():
    class AsyncFlow(Flow):
        @start()
        @guarded_step(allow={"read_file": {"path": Subpath("/data")}})
        async def step(self):
            return await _step_crew().kickoff_async()

    AsyncFlow().kickoff()
    assert EXECUTED == []


def test_guarded_step_async_allows_permitted_tool_and_unregisters():
    from crewai.hooks import get_before_tool_call_hooks

    @guarded_step(allow={"search": {"query": Pattern("*")}})
    async def step():
        assert len(get_before_tool_call_hooks()) == 1
        return await _crew([search], [("search", {"query": "ok"})]).kickoff_async()

    assert asyncio.iscoroutinefunction(step)
    asyncio.run(step())
    assert EXECUTED == [("search", "ok")]
    assert get_before_tool_call_hooks() == []


def test_guarded_step_rejects_sync_function_returning_awaitable():
    async def inner():
        return None

    @guarded_step(allow={"search": {"query": Pattern("*")}})
    def step():
        return inner()

    with pytest.raises(CrewAIConfigurationError):
        step()


# -- Tier 1 closed world -----------------------------------------------------


def test_omitted_constrained_argument_is_denied():
    GuardBuilder().allow("read_file", path=Subpath("/data")).build().register()

    _crew([read_file], [("read_file", {})]).kickoff()

    assert EXECUTED == []


def test_present_constrained_argument_still_allowed():
    GuardBuilder().allow("read_file", path=Subpath("/data")).build().register()

    _crew([read_file], [("read_file", {"path": "/data/a.txt"})]).kickoff()

    assert EXECUTED == [("read_file", "/data/a.txt")]


def test_explain_reports_missing_argument():
    guard = GuardBuilder().allow("read_file", path=Subpath("/data")).build()
    result = guard.explain("read_file", {})
    assert result.status == "DENIED"
    assert "path" in result.reason


# -- namespaced roles --------------------------------------------------------


@pytest.mark.parametrize("role", ["researcher", "Researcher", " RESEARCHER "])
def test_namespaced_policy_applies_regardless_of_role_case(role):
    (
        GuardBuilder()
        .allow("search", query=Pattern("*"))
        .allow("researcher::search", query=Pattern("arxiv:*"))
        .build()
        .register()
    )

    _crew([search], [("search", {"query": "secret"})], role=role).kickoff()

    assert EXECUTED == []


def test_namespaced_policy_allows_matching_value_for_capitalized_role():
    (
        GuardBuilder()
        .allow("search", query=Pattern("*"))
        .allow("researcher::search", query=Pattern("arxiv:*"))
        .build()
        .register()
    )

    _crew([search], [("search", {"query": "arxiv:1234"})], role="Researcher").kickoff()

    assert EXECUTED == [("search", "arxiv:1234")]


def test_role_keys_differing_only_in_case_are_rejected():
    with pytest.raises(CrewAIConfigurationError):
        (
            GuardBuilder()
            .allow("researcher::search", query=Pattern("arxiv:*"))
            .allow("Researcher::search", query=Pattern("*"))
            .build()
        )
