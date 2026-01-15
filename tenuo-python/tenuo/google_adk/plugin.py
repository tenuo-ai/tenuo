"""
Tenuo Google ADK Plugin - Cross-Agent Authorization

Provides warrant-based authorization across all agents in an ADK Runner.

Usage:
    from google.adk.runners import InMemoryRunner
    from tenuo.google_adk import TenuoPlugin, ScopedWarrant

    plugin = TenuoPlugin(
        warrant=org_warrant,
        signing_key=agent_key,  # Required for PoP
        skill_map={...},
    )

    runner = InMemoryRunner(
        agent=coordinator_agent,
        plugins=[plugin],
    )

Multi-Tenant Safety:
    Use ScopedWarrant to prevent warrant leaks between agents:

    # Inject warrant scoped to specific agent
    session.state["tenuo_warrant"] = ScopedWarrant(warrant, "researcher")

    # If the warrant is accessed by a different agent, it will be rejected
"""

from __future__ import annotations

import logging
import time
from typing import Optional, Dict, Any, TYPE_CHECKING

logger = logging.getLogger(__name__)

try:
    from google.adk.plugins import BasePlugin  # type: ignore[import-not-found]
except ImportError:
    # Allow import even if google-adk not installed (for type checking)
    BasePlugin = object  # type: ignore[misc,assignment]

if TYPE_CHECKING:
    from google.adk.tools.tool_context import ToolContext  # type: ignore[import-not-found]
    from google.adk.tools.base_tool import BaseTool  # type: ignore[import-not-found]
    from google.adk.agents.callback_context import CallbackContext  # type: ignore[import-not-found]
    from tenuo_core import Warrant, SigningKey

from .guard import TenuoGuard  # noqa: E402


class ScopedWarrant:
    """
    Wrapper that binds a warrant to a specific agent.

    Prevents warrant leaks in multi-agent systems by ensuring
    a warrant injected for agent A cannot be used by agent B.

    Security: This is a proactive defense - the warrant is bound
    at injection time, not cleared reactively after potential leak.

    Usage:
        # Inject warrant scoped to specific agent
        session.state["__tenuo_warrant__"] = ScopedWarrant(warrant, "researcher")

        # If accessed by "writer" agent, before_agent_callback will reject it
    """

    # Use __slots__ to prevent 'warrant' and 'agent_name' from being shadowed
    # by delegated attributes from the wrapped warrant
    __slots__ = ("warrant", "agent_name")

    def __init__(self, warrant: "Warrant", agent_name: str):
        # Use object.__setattr__ to avoid triggering __getattr__
        object.__setattr__(self, "warrant", warrant)
        object.__setattr__(self, "agent_name", agent_name)

    def valid_for_agent(self, agent_name: str) -> bool:
        return self.agent_name == agent_name

    def __getattr__(self, name: str) -> Any:
        """
        Delegate unknown attributes to the wrapped warrant.

        Security: Using __slots__ ensures 'warrant' and 'agent_name' are
        never shadowed by delegated attributes from the wrapped warrant.
        """
        # Get warrant via object.__getattribute__ to avoid recursion
        warrant = object.__getattribute__(self, "warrant")
        return getattr(warrant, name)


class TenuoPlugin(BasePlugin):
    """
    ADK Plugin for warrant-based tool authorization.

    Applies to all agents managed by the Runner.
    Includes proactive state scoping to prevent leaks.

    Security Features:
        - Warrant validation at turn boundaries (before_agent_callback)
        - Proof-of-Possession verification (Tier 2)
        - Zero-trust argument checking
        - Scoped warrant support (ScopedWarrant)
        - Automatic expiry cleanup
    """

    def __init__(
        self,
        warrant: Optional["Warrant"] = None,
        signing_key: Optional["SigningKey"] = None,
        warrant_key: str = "__tenuo_warrant__",  # Must match TenuoGuard default
        skill_map: Optional[Dict[str, str]] = None,
        arg_map: Optional[Dict[str, Dict[str, str]]] = None,
        require_pop: bool = True,
    ):
        """
        Initialize TenuoPlugin.

        Args:
            warrant: Static warrant for all agents (or None for dynamic)
            signing_key: Signing key for Proof-of-Possession (required for Tier 2)
            warrant_key: Key to look up warrant in session state
            skill_map: Map ADK tool names to warrant skill names
            arg_map: Map tool argument names to constraint parameter names
            require_pop: If True (default), requires signing_key for Tier 2 authorization
        """
        self._guard = TenuoGuard(
            warrant=warrant,
            signing_key=signing_key,
            warrant_key=warrant_key,
            skill_map=skill_map,
            arg_map=arg_map,
            require_pop=require_pop,
        )
        self._warrant_key = warrant_key

    def before_agent_callback(  # type: ignore[override]
        self,
        callback_context: "CallbackContext",
        **kwargs: Any,  # Accept additional kwargs for API compatibility
    ) -> Optional[Any]:
        """
        Validate warrant scope at turn boundary.

        SECURITY: Proactive state scoping - warrant is bound to specific agent
        at injection time, not cleared reactively after potential leak.

        This callback:
            1. Validates ScopedWarrant matches the current agent
            2. Clears expired warrants from state
            3. Prevents cross-agent warrant access
        """
        # Check session_state (standard) then state (fallback)
        if hasattr(callback_context, 'session_state'):
            state = callback_context.session_state
        elif hasattr(callback_context, 'state'):
            state = callback_context.state
        else:
            return None  # No state available

        scoped_warrant = state.get(self._warrant_key)

        if scoped_warrant is None:
            return None  # No warrant, let before_tool handle it

        # Check if warrant is scoped (ScopedWarrant wrapper)
        if hasattr(scoped_warrant, "valid_for_agent"):
            if not scoped_warrant.valid_for_agent(callback_context.agent_name):
                # Warrant was scoped to different agent - reject
                # This catches the leak BEFORE it can be exploited
                logger.warning(
                    f"Removing warrant scoped for '{scoped_warrant.agent_name}' from agent '{callback_context.agent_name}'"
                )
                # Use pop() to avoid KeyError if already removed
                state.pop(self._warrant_key, None)
                return None  # Will fail in before_tool with "no warrant"

        # Check expiry
        warrant = getattr(scoped_warrant, "warrant", scoped_warrant)
        is_expired = self._check_warrant_expiry(warrant)
        if is_expired:
            # Use pop() to avoid KeyError if already removed
            state.pop(self._warrant_key, None)

        return None  # Continue with agent execution

    def _check_warrant_expiry(self, warrant: Any) -> bool:
        """Check if warrant is expired."""
        is_expired = getattr(warrant, "is_expired", None)

        # Handle method vs property
        if callable(is_expired):
            return is_expired()
        elif is_expired is not None:
            return bool(is_expired)

        # Fallback: check exp claim manually
        exp = getattr(warrant, "exp", None)
        if exp is not None:
            return time.time() > exp

        return False

    def before_tool_callback(  # type: ignore[override]
        self,
        tool: "BaseTool",
        args: Dict[str, Any],
        tool_context: "ToolContext",
        **kwargs: Any,  # Accept additional kwargs for API compatibility
    ) -> Optional[Dict[str, Any]]:
        """Plugin hook - called for all tool invocations."""
        return self._guard.before_tool(tool, args, tool_context)

    def after_tool_callback(  # type: ignore[override]
        self,
        tool: "BaseTool",
        args: Dict[str, Any],
        tool_context: "ToolContext",
        result: Any,
        **kwargs: Any,  # Accept additional kwargs for API compatibility
    ) -> Optional[Any]:
        """Plugin hook - called after all tool invocations."""
        return self._guard.after_tool(tool, args, tool_context, result)
