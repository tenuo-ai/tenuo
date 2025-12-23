"""
AgentDojo benchmark integration for Tenuo.

Measures Tenuo's effectiveness at preventing prompt injection attacks
using the AgentDojo framework.
"""

from .harness import TenuoAgentDojoHarness
from .tool_wrapper import TenuoToolWrapper, wrap_tools, AuthorizationMetrics
from .warrant_templates import (
    BANKING_CONSTRAINTS,
    TRAVEL_CONSTRAINTS,
    SLACK_CONSTRAINTS,
    WORKSPACE_CONSTRAINTS,
    get_constraints_for_suite,
    get_constraints_for_tool,
)

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
