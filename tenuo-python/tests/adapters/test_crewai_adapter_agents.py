"""CrewAI agent adapters bypass tool hooks, so the guard refuses to cover them."""

import warnings
from unittest.mock import MagicMock

import pytest

pytest.importorskip("crewai")
adapters = pytest.importorskip("crewai.agents.agent_adapters.base_agent_adapter")

from tenuo import Wildcard  # noqa: E402
from tenuo.crewai import (  # noqa: E402
    CrewAIConfigurationError,
    GuardedCrew,
    _is_agent_adapter,
    guarded_step,
)


class _AdapterAgent(adapters.BaseAgentAdapter):
    """A stand-in adapter agent; never run."""


# The stand-in is only type-checked by the guard, so it needs no behaviour.
_AdapterAgent.__abstractmethods__ = frozenset()


def _adapter_agent(role: str):
    return _AdapterAgent.model_construct(role=role, goal="g", backstory="b")


def test_adapter_agents_are_recognised():
    assert _is_agent_adapter(_adapter_agent("researcher"))
    assert not _is_agent_adapter(MagicMock())


def test_guarded_crew_refuses_an_adapter_agent():
    crew = (
        GuardedCrew(agents=[_adapter_agent("researcher")], tasks=[MagicMock()])
        .policy({"researcher": ["search"]})
        .constraints({"researcher": {"search": {"query": Wildcard()}}})
        .build()
    )
    with pytest.raises(CrewAIConfigurationError, match="agent adapter"):
        crew.kickoff()


def test_strict_mode_says_what_it_does_not_detect():
    with pytest.warns(UserWarning, match="does not detect"):
        GuardedCrew(agents=[MagicMock()], tasks=[MagicMock()]).strict()
    with pytest.warns(UserWarning, match="does not detect"):
        guarded_step(allow={"search": {"query": Wildcard()}}, strict=True)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        GuardedCrew(agents=[MagicMock()], tasks=[MagicMock()]).strict(False)
        guarded_step(allow={"search": {"query": Wildcard()}})
