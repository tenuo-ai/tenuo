"""
AgentDojo benchmark integration for Tenuo.

Measures Tenuo's effectiveness at preventing prompt injection attacks
using the AgentDojo framework.
"""

# Core modules that don't require openai/agentdojo
from .tool_wrapper import TenuoToolWrapper, wrap_tools, AuthorizationMetrics
from .warrant_templates import (
    BANKING_CONSTRAINTS,
    TRAVEL_CONSTRAINTS,
    SLACK_CONSTRAINTS,
    WORKSPACE_CONSTRAINTS,
    get_constraints_for_suite,
    get_constraints_for_tool,
)

# Harness requires openai/agentdojo - import lazily
try:
    from .harness import TenuoAgentDojoHarness
except ImportError:
    TenuoAgentDojoHarness = None  # type: ignore

__all__ = [
    "TenuoAgentDojoHarness",
    "TenuoToolWrapper",
    "wrap_tools",
    "AuthorizationMetrics",
    "BANKING_CONSTRAINTS",
    "TRAVEL_CONSTRAINTS",
    "SLACK_CONSTRAINTS",
    "WORKSPACE_CONSTRAINTS",
    "get_constraints_for_suite",
    "get_constraints_for_tool",
]
