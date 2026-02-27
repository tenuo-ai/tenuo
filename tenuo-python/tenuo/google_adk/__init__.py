"""
Tenuo Google ADK Integration

Provides authorization for Google ADK agents.

**Quick Start (Zero Config):**
    from google.adk import Agent
    from tenuo.google_adk import protect_agent

    # Wrap your agent - only allowed tools can run
    agent = protect_agent(
        Agent(tools=[search, read_file]),
        allow=["search", "read_file"]  # Explicit allowlist
    )

**With Constraints:**
    from tenuo.google_adk import GuardBuilder
    from tenuo.constraints import Subpath

    guard = (GuardBuilder()
        .allow("search")
        .allow("read_file", path=Subpath("/data"))  # Only /data/ allowed
        .build())

    agent = Agent(
        tools=[search, read_file],
        before_tool_callback=guard.before_tool,
    )

**With Warrants (Distributed Authorization):**
    from tenuo.google_adk import GuardBuilder

    guard = (GuardBuilder()
        .with_warrant(my_warrant, my_signing_key)
        .build())

    agent = Agent(
        tools=[search, read_file],
        before_tool_callback=guard.before_tool,
    )

DX Helpers:
    from tenuo.google_adk import (
        chain_callbacks,      # Compose multiple callbacks
        explain_denial,       # Rich denial explanations
        visualize_warrant,    # Display warrant capabilities
    )
"""

from .decorators import (
    extract_constraints,
    guard_tool,
    is_guarded,
)
from .guard import (
    GuardBuilder,
    MissingSigningKeyError,
    TenuoGuard,
    ToolAuthorizationError,
)
from .helpers import (
    chain_callbacks,
    explain_denial,
    generate_hints,
    protect_agent,
    scoped_warrant,
    suggest_skill_mapping,
    visualize_warrant,
)
from .plugin import (
    ScopedWarrant,
    TenuoPlugin,
)

__all__ = [
    # Zero-config entry point
    "protect_agent",
    # Core
    "TenuoGuard",
    "GuardBuilder",
    "ToolAuthorizationError",
    "MissingSigningKeyError",
    # Plugin
    "TenuoPlugin",
    "ScopedWarrant",
    # DX Helpers
    "chain_callbacks",
    "explain_denial",
    "visualize_warrant",
    "suggest_skill_mapping",
    "scoped_warrant",
    "generate_hints",
    # Decorators
    "guard_tool",
    "extract_constraints",
    "is_guarded",
]
