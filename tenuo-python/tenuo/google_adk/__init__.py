"""
Tenuo Google ADK Integration

Provides warrant-based authorization for Google ADK agents.

Usage (Tier 2 - Warrant with PoP):
    from tenuo.google_adk import GuardBuilder
    from tenuo import SigningKey, Warrant

    guard = (GuardBuilder()
        .with_warrant(my_warrant, agent_key)
        .map_skill("read_file_tool", "read_file", path="file_path")
        .on_denial("raise")
        .build())

    agent = Agent(
        tools=guard.filter_tools([read_file, search]),
        before_tool_callback=guard.before_tool,
    )

Usage (Tier 1 - Direct Constraints, no warrant):
    from tenuo.google_adk import GuardBuilder
    from tenuo.constraints import Subpath, UrlSafe

    guard = (GuardBuilder()
        .allow("read_file", path=Subpath("/data"))
        .allow("web_search", url=UrlSafe(allow_domains=["example.com"]))
        .build())

    # Note: "shell" is denied by default - only explicitly allowed tools work

    agent = Agent(
        tools=guard.filter_tools([read_file, search, shell]),
        before_tool_callback=guard.before_tool,
    )

DX Helpers:
    from tenuo.google_adk import (
        chain_callbacks,      # Compose multiple callbacks
        explain_denial,       # Rich denial explanations
        visualize_warrant,    # Display warrant capabilities
        suggest_skill_mapping,# Auto-suggest skill mappings
        scoped_warrant,       # Context manager for dynamic warrants
    )
"""

from .guard import (
    TenuoGuard,
    GuardBuilder,
    ToolAuthorizationError,
    MissingSigningKeyError,
)
from .plugin import (
    TenuoPlugin,
    ScopedWarrant,
)
from .helpers import (
    chain_callbacks,
    explain_denial,
    visualize_warrant,
    suggest_skill_mapping,
    scoped_warrant,
    generate_hints,
)
from .decorators import (
    guard_tool,
    extract_constraints,
    is_guarded,
)

__all__ = [
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
