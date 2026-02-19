"""
Tenuo LangChain Integration

Primary API:
    guard_tools()  - Wrap tools (you manage mint/grant context)
    guard_agent()  - Wrap entire executor (built-in context)
    guard()        - Unified smart wrapper (auto-detects type)

Example:
    from tenuo import configure, mint_sync, SigningKey, Capability, Pattern
    from tenuo.langchain import guard_tools, guard_agent

    kp = SigningKey.generate()
    configure(issuer_key=kp, dev_mode=True)

    # Option 1: Wrap tools (manage context yourself)
    tools = guard_tools([search_tool, file_tool])
    with mint_sync(Capability("search")):
        result = executor.invoke({"input": "search"})

    # Option 2: Wrap entire agent (built-in context)
    protected = guard_agent(
        executor,
        issuer_key=kp,
        capabilities=[Capability("search")],
    )
    result = protected.invoke({"input": "search"})  # No context needed!

For multi-agent graphs with automatic delegation, see tenuo.langgraph.
"""

from typing import Any, Dict, List, Optional
import asyncio
import inspect
import logging

from .config import allow_passthrough
from .decorators import warrant_scope, key_scope, get_allowed_tools_context
from .exceptions import (
    ToolNotAuthorized,
    ConstraintViolation,
    ConfigurationError,
)
from .schemas import ToolSchema, TOOL_SCHEMAS, _get_tool_name
from .audit import log_authorization_success

# Check version compatibility on import (warns, doesn't fail)
from tenuo._version_compat import check_langchain_compat  # noqa: E402

check_langchain_compat()

# Optional LangChain import
try:
    from langchain_core.tools import BaseTool, StructuredTool
    from pydantic import BaseModel

    LANGCHAIN_AVAILABLE = True
except (ImportError, TypeError):
    LANGCHAIN_AVAILABLE = False
    BaseTool = object  # type: ignore
    StructuredTool = object  # type: ignore
    BaseModel = object  # type: ignore

# Module logger
logger = logging.getLogger("tenuo.langchain")


# =============================================================================
# Core: TenuoTool wrapper
# =============================================================================


class TenuoTool(BaseTool):  # type: ignore[misc]
    """
    LangChain tool wrapper that enforces Tenuo authorization.

    This tool wraps another LangChain tool and checks authorization
    from context before each invocation.

    Attributes:
        wrapped: The original LangChain tool
        strict: If True, require constraints for require_at_least_one tools
    """

    name: str = ""
    description: str = ""
    wrapped: Any = None
    strict: bool = False
    _schemas: Dict[str, ToolSchema] = {}
    _bound_warrant: Optional[Any] = None

    def __init__(
        self,
        wrapped: Any,
        strict: bool = False,
        schemas: Optional[Dict[str, ToolSchema]] = None,
        bound_warrant: Optional[Any] = None,
        **kwargs: Any,
    ):
        """
        Create a TenuoTool wrapper.

        Args:
            wrapped: The LangChain tool to wrap
            strict: Enforce constraints for require_at_least_one tools
            schemas: Tool schemas for risk level checking
            bound_warrant: Explicit BoundWarrant to use (optional, overrides context)
        """
        # Get tool name and description
        tool_name = _get_tool_name(wrapped)
        tool_desc = getattr(wrapped, "description", f"Protected tool: {tool_name}")

        # Initialize with name and description
        super().__init__(name=tool_name, description=tool_desc, **kwargs)

        # Store wrapped tool and settings
        object.__setattr__(self, "wrapped", wrapped)
        object.__setattr__(self, "strict", strict)
        object.__setattr__(self, "_schemas", schemas or TOOL_SCHEMAS)
        object.__setattr__(self, "_bound_warrant", bound_warrant)

        # Copy args_schema if present
        if hasattr(wrapped, "args_schema"):
            object.__setattr__(self, "args_schema", wrapped.args_schema)

    def _check_authorization(self, tool_input: Dict[str, Any]) -> None:
        """Check authorization before tool execution."""
        # Use explicit bound_warrant if provided, else context
        bound_warrant = getattr(self, "_bound_warrant", None)

        if bound_warrant:
            warrant = bound_warrant
        else:
            warrant = warrant_scope()

        schema = self._schemas.get(self.name)

        if warrant is None:
            if allow_passthrough():
                logger.warning(f"PASSTHROUGH: Tool '{self.name}' executed without warrant")
                return
            raise ToolNotAuthorized(tool=self.name)

        # scoped_task's allowed_tools takes precedence over warrant.tools
        allowed_tools = get_allowed_tools_context()
        if allowed_tools is not None:
            if self.name not in allowed_tools:
                raise ToolNotAuthorized(
                    tool=self.name,
                    authorized_tools=allowed_tools,
                )
        # Fall back to warrant's tool allowlist
        elif warrant.tools and self.name not in warrant.tools:
            raise ToolNotAuthorized(
                tool=self.name,
                authorized_tools=warrant.tools if warrant.tools else None,
            )

        if schema and schema.risk_level == "critical":
            constraints = _get_constraints_dict(warrant)
            has_relevant = any(c in constraints for c in schema.recommended_constraints)
            if not has_relevant and not constraints:
                raise ConfigurationError(
                    f"Critical tool '{self.name}' requires at least one constraint. "
                    f"Recommended: {schema.recommended_constraints}."
                )

        if self.strict and schema and schema.require_at_least_one:
            constraints = _get_constraints_dict(warrant)
            if not constraints:
                raise ConfigurationError(f"Strict mode: tool '{self.name}' requires at least one constraint.")

        # Build args dict for authorization
        constraint_args = {k: v for k, v in tool_input.items()}

        try:
            # Detect if we have a BoundWarrant (has .authorize without signature param)
            # or a plain Warrant (requires explicit signature)
            is_bound = hasattr(warrant, "warrant") and hasattr(warrant, "_key")

            if is_bound:
                # BoundWarrant - handles PoP signing internally
                authorized = warrant.validate(self.name, constraint_args)
            else:
                # Plain Warrant - need to sign with key from context
                import time
                signing_key = key_scope()
                if signing_key:
                    pop_signature = bytes(warrant.sign(signing_key, self.name, constraint_args, int(time.time())))
                    authorized = warrant.authorize(self.name, constraint_args, pop_signature)
                else:
                    # No key context - cannot authorize
                    # Rust core expects pop_signature, so we can't authorize without a key
                    authorized = False

            if not authorized:
                raise ToolNotAuthorized(tool=self.name)

            log_authorization_success(warrant, self.name, tool_input)

        except (ToolNotAuthorized, ConstraintViolation, ConfigurationError):
            raise
        except Exception as e:
            raise ConstraintViolation(
                field="unknown",
                reason=f"Authorization error: {str(e)}",
                value=None,
            ) from e

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous tool execution with authorization."""
        tool_input = self._build_tool_input(args, kwargs)
        self._check_authorization(tool_input)

        # Prefer func over _run for @tool decorated functions
        if hasattr(self.wrapped, "func") and self.wrapped.func is not None:
            return self.wrapped.func(*args, **kwargs)
        elif hasattr(self.wrapped, "_run"):
            # Pass through config if present in kwargs
            return self.wrapped._run(*args, **kwargs)
        else:
            return self.wrapped(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronous tool execution with authorization."""
        tool_input = self._build_tool_input(args, kwargs)
        self._check_authorization(tool_input)

        if hasattr(self.wrapped, "coroutine") and self.wrapped.coroutine is not None:
            return await self.wrapped.coroutine(*args, **kwargs)
        elif hasattr(self.wrapped, "func") and self.wrapped.func is not None:
            result = self.wrapped.func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
        elif hasattr(self.wrapped, "_arun"):
            return await self.wrapped._arun(*args, **kwargs)
        elif hasattr(self.wrapped, "_run"):
            return self.wrapped._run(*args, **kwargs)
        else:
            result = self.wrapped(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result

    def _build_tool_input(self, args: tuple, kwargs: dict) -> Dict[str, Any]:
        """Build tool input dict from args and kwargs."""
        tool_input = dict(kwargs)

        # Try to get parameter names from wrapped tool
        if hasattr(self.wrapped, "func"):
            func = self.wrapped.func
        elif hasattr(self.wrapped, "_run"):
            func = self.wrapped._run
        elif callable(self.wrapped):
            func = self.wrapped
        else:
            return tool_input

        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            # Skip 'self' if present
            if params and params[0] == "self":
                params = params[1:]
            for i, arg in enumerate(args):
                if i < len(params):
                    tool_input[params[i]] = arg
        except (ValueError, TypeError):
            pass

        return tool_input


def _get_constraints_dict(warrant: Any) -> Dict[str, Any]:
    """Safely get constraints dict from warrant.

    Extracts all constraint field names across all tools in the warrant.
    Used by guard() to verify critical tools have constraints configured.
    """
    # Try extracting from capabilities (works for both Warrant and BoundWarrant)
    # capabilities returns {tool: {field: constraint, ...}, ...}
    if hasattr(warrant, "capabilities"):
        try:
            caps = warrant.capabilities
            if caps:
                # Flatten all constraint fields across all tools
                all_constraints = {}
                for tool_name, constraints in caps.items():
                    if constraints:
                        all_constraints.update(constraints)
                if all_constraints:
                    return all_constraints
        except Exception:
            pass

    return {}


# =============================================================================
# DX: guard_tools() - Wrap tools with authorization
# =============================================================================


def guard_tools(
    tools: List[Any],
    *,
    issuer_key: Optional[Any] = None,
    strict: bool = False,
    warn_on_missing_warrant: bool = True,
    schemas: Optional[Dict[str, ToolSchema]] = None,
) -> List[Any]:
    """
    Wrap LangChain tools with Tenuo authorization.

    This wraps individual tools with protection. Use `guard_agent()` to wrap
    an entire AgentExecutor with built-in authorization context.

    Args:
        tools: List of LangChain BaseTool objects to protect
        issuer_key: SigningKey for issuing warrants (enables dev_mode if provided)
        strict: If True, fail on any missing warrant (default: False)
        warn_on_missing_warrant: If True, log warnings for unprotected calls (default: True)
        schemas: Optional custom tool schemas for risk level checking

    Returns:
        List of protected TenuoTool objects

    Example:
        from tenuo import SigningKey, mint_sync, Capability
        from tenuo.langchain import guard_tools
        from langchain.agents import create_openai_tools_agent, AgentExecutor

        # Wrap tools with protection
        key = SigningKey.generate()
        protected = guard_tools([search, calculator], issuer_key=key)

        # Create agent as normal
        agent = create_openai_tools_agent(llm, protected, prompt)
        executor = AgentExecutor(agent=agent, tools=protected)

        # Run with authorization context
        with mint_sync(Capability("search"), Capability("calculator")):
            result = executor.invoke({"input": "What is 2+2?"})

    See Also:
        guard_agent: Wraps entire executor with built-in authorization
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError("LangChain is required for guard_tools(). Install with: uv pip install langchain-core")

    if issuer_key is not None:
        from .config import configure, is_configured

        if not is_configured():
            configure(
                issuer_key=issuer_key,
                dev_mode=True,  # Auto-enable dev mode for one-liner usage
                strict_mode=strict,
                warn_on_missing_warrant=warn_on_missing_warrant,
            )
        else:
            from .config import get_config

            config = get_config()
            if config:
                object.__setattr__(config, "strict_mode", strict)
                object.__setattr__(config, "warn_on_missing_warrant", warn_on_missing_warrant)

    merged_schemas = {**TOOL_SCHEMAS, **(schemas or {})}
    return [TenuoTool(t, strict=strict, schemas=merged_schemas) for t in tools]


# =============================================================================
# Unified guard() - Smart Type Detection
# =============================================================================


def guard(
    tools: List[Any],
    bound: Optional[Any] = None,
    *,
    strict: bool = False,
) -> List[Any]:
    """
    Guard tools with Tenuo authorization (unified API).

    Smart-detects input type and returns TenuoTool wrappers.

    Args:
        tools: List of tools (functions or BaseTools)
        bound: Optional BoundWarrant for explicit auth.
               If None, uses context.
        strict: Require constraints for critical tools

    Returns:
        List of guarded TenuoTool wrappers

    Example:
        # Context-based:
        tools = guard([search, calculator])
        with mint_sync(Capability("search")):
            agent.invoke(...)

        # Explicit bound warrant:
        bound = warrant.bind(key)
        tools = guard([search, calculator], bound)
    """
    if not tools:
        return []

    return [TenuoTool(t, strict=strict, bound_warrant=bound) for t in tools]


# =============================================================================
# DX: guard_agent() - Wrap entire agent with authorization
# =============================================================================


def guard_agent(
    agent_or_executor: Any,
    *,
    issuer_key: Optional[Any] = None,
    capabilities: Optional[List[Any]] = None,
    strict: bool = False,
    warn_on_missing: bool = True,
) -> Any:
    """
    Wrap an entire LangChain agent/executor with Tenuo authorization.

    This is the ultimate one-liner for LangChain users. It:
    1. Configures Tenuo (if key provided)
    2. Extracts and wraps all tools from the agent
    3. Creates a new executor with protected tools
    4. Optionally scopes to specific capabilities (built-in context)

    Args:
        agent_or_executor: AgentExecutor, RunnableAgent, or agent with tools
        issuer_key: SigningKey for issuing warrants (optional, auto dev_mode)
        capabilities: List of Capability objects to scope the agent to (optional)
        strict: If True, require constraints for critical tools
        warn_on_missing: If True, log warnings for missing warrants

    Returns:
        A wrapped agent/executor that enforces authorization

    Example:
        from tenuo.langchain import guard_agent
        from tenuo import SigningKey, Capability, Pattern
        from langchain.agents import create_openai_tools_agent, AgentExecutor

        # Create your agent as normal
        agent = create_openai_tools_agent(llm, tools, prompt)
        executor = AgentExecutor(agent=agent, tools=tools)

        # One line to add Tenuo protection
        key = SigningKey.generate()
        protected = guard_agent(
            executor,
            issuer_key=key,
            capabilities=[
                Capability("search"),
                Capability("read_file", path=Pattern("/data/*")),
            ],
        )

        # Now run - authorization is automatic!
        result = protected.invoke({"input": "Search for reports"})

        # Or use context managers for dynamic scoping
        from tenuo import mint
        async with mint(Capability("calculator")) as w:
            result = protected.invoke({"input": "What is 2+2?"})

    See Also:
        guard_tools: Wraps individual tools (you manage context)

    Advanced: Wrapping LangGraph agents
        For LangGraph StateGraph agents, use tenuo.langgraph.TenuoToolNode instead.
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError("LangChain is required for guard_agent(). Install with: uv pip install langchain-core")

    # Configure if key provided
    if issuer_key is not None:
        from .config import configure, is_configured

        if not is_configured():
            configure(
                issuer_key=issuer_key,
                dev_mode=True,
                allow_self_signed=True,
                strict_mode=strict,
                warn_on_missing_warrant=warn_on_missing,
            )

    # Extract tools from agent
    tools = _extract_tools(agent_or_executor)
    if not tools:
        logger.warning("guard_agent: No tools found in agent. Make sure agent has 'tools' attribute.")
        return agent_or_executor

    # Wrap tools
    protected_tools = [TenuoTool(t, strict=strict) for t in tools]

    # Create protected executor
    return _rebuild_executor(agent_or_executor, protected_tools, capabilities)


def _extract_tools(agent_or_executor: Any) -> List[Any]:
    """Extract tools from various agent types."""
    # AgentExecutor
    if hasattr(agent_or_executor, "tools"):
        return list(agent_or_executor.tools)

    # RunnableAgent or similar
    if hasattr(agent_or_executor, "agent") and hasattr(agent_or_executor.agent, "tools"):
        return list(agent_or_executor.agent.tools)

    # Tool list directly
    if isinstance(agent_or_executor, list):
        return agent_or_executor

    return []


def _rebuild_executor(
    original: Any,
    protected_tools: List[Any],
    capabilities: Optional[List[Any]] = None,
) -> Any:
    """Rebuild the executor with protected tools."""
    try:
        from langchain.agents import AgentExecutor  # type: ignore[import-not-found,attr-defined]
    except ImportError:
        # Fallback: just return a simple wrapper
        return _SimpleProtectedAgent(original, protected_tools, capabilities)

    # If it's an AgentExecutor, create a new one with protected tools
    if isinstance(original, AgentExecutor):
        # Create wrapper that sets up context before each invoke
        return _TenuoAgentExecutor(
            agent=original.agent,
            tools=protected_tools,
            capabilities=capabilities,
            # Copy settings from original
            verbose=getattr(original, "verbose", False),
            max_iterations=getattr(original, "max_iterations", 15),
            handle_parsing_errors=getattr(original, "handle_parsing_errors", True),
        )

    # For other types, return a simple wrapper
    return _SimpleProtectedAgent(original, protected_tools, capabilities)


class _TenuoAgentExecutor:
    """
    Wrapper around AgentExecutor that sets up Tenuo context.

    This allows capabilities to be set once at agent creation time,
    then automatically applied on each invocation.
    """

    def __init__(
        self,
        agent: Any,
        tools: List[Any],
        capabilities: Optional[List[Any]] = None,
        **kwargs: Any,
    ):
        try:
            from langchain.agents import AgentExecutor  # type: ignore[import-not-found,attr-defined]
        except ImportError:
            raise ImportError("langchain is required for _TenuoAgentExecutor")

        self._inner = AgentExecutor(agent=agent, tools=tools, **kwargs)
        self._capabilities = capabilities
        self._tools = tools

    @property
    def tools(self) -> List[Any]:
        return self._tools

    def invoke(self, input_data: Any, **kwargs: Any) -> Any:
        """Invoke with Tenuo context."""
        if self._capabilities:
            from .scoped import mint_sync

            with mint_sync(*self._capabilities):
                return self._inner.invoke(input_data, **kwargs)
        else:
            return self._inner.invoke(input_data, **kwargs)

    async def ainvoke(self, input_data: Any, **kwargs: Any) -> Any:
        """Async invoke with Tenuo context."""
        if self._capabilities:
            from .scoped import mint

            async with mint(*self._capabilities):
                return await self._inner.ainvoke(input_data, **kwargs)
        else:
            return await self._inner.ainvoke(input_data, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Delegate to inner executor."""
        return getattr(self._inner, name)


class _SimpleProtectedAgent:
    """Simple wrapper for non-AgentExecutor agents."""

    def __init__(
        self,
        original: Any,
        tools: List[Any],
        capabilities: Optional[List[Any]] = None,
    ):
        self._original = original
        self._tools = tools
        self._capabilities = capabilities

    @property
    def tools(self) -> List[Any]:
        return self._tools

    def invoke(self, input_data: Any, **kwargs: Any) -> Any:
        if self._capabilities:
            from .scoped import mint_sync

            with mint_sync(*self._capabilities):
                return self._original.invoke(input_data, **kwargs)
        else:
            return self._original.invoke(input_data, **kwargs)

    async def ainvoke(self, input_data: Any, **kwargs: Any) -> Any:
        if self._capabilities:
            from .scoped import mint

            async with mint(*self._capabilities):
                return await self._original.ainvoke(input_data, **kwargs)
        else:
            return await self._original.ainvoke(input_data, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._original, name)


# =============================================================================
# auto_protect: Zero-config protection with audit mode default
# =============================================================================


def auto_protect(
    agent_or_tools: Any,
    *,
    mode: str = "audit",  # "audit" (log only), "enforce" (block), "permissive" (warn)
    infer_schemas: bool = True,
) -> Any:
    """
    Zero-config protection with sensible defaults.

    SECURITY: Defaults to AUDIT mode (log only, don't block).
    This lets you deploy without breaking anything, then analyze logs
    to understand what capabilities you need.

    Args:
        agent_or_tools: AgentExecutor, list of tools, or single tool
        mode: "audit" (log only), "enforce" (block violations), "permissive" (warn only)
        infer_schemas: If True, infer tool schemas from type hints

    Returns:
        Protected version of the input

    Example:
        # Deploy in audit mode first
        executor = auto_protect(executor)  # Logs all tool calls

        # After analyzing logs, switch to enforce
        executor = auto_protect(executor, mode="enforce")
    """
    from .config import configure, EnforcementMode, is_configured, get_config

    # Map mode string to enum
    mode_map = {
        "audit": EnforcementMode.AUDIT,
        "enforce": EnforcementMode.ENFORCE,
        "permissive": EnforcementMode.PERMISSIVE,
    }
    enforcement_mode = mode_map.get(mode, EnforcementMode.AUDIT)

    # Auto-configure if not already configured
    if not is_configured():
        from tenuo_core import SigningKey

        configure(
            issuer_key=SigningKey.generate(),
            mode=enforcement_mode.value,  # type: ignore[arg-type]
            dev_mode=True,
            warn_on_missing_warrant=True,
        )
    else:
        # Update mode on existing config
        config = get_config()
        config.mode = enforcement_mode

    # Detect type and protect
    if hasattr(agent_or_tools, "invoke") and hasattr(agent_or_tools, "tools"):
        # AgentExecutor-like
        return guard_agent(agent_or_tools)
    elif isinstance(agent_or_tools, list):
        # List of tools
        return guard_tools(agent_or_tools)
    elif hasattr(agent_or_tools, "name") and hasattr(agent_or_tools, "invoke"):
        # Single tool
        return guard_tools([agent_or_tools])[0]
    else:
        raise TypeError(
            f"auto_protect expects AgentExecutor, list of tools, or single tool. Got: {type(agent_or_tools).__name__}"
        )


# =============================================================================
# SecureAgentExecutor: Drop-in replacement for AgentExecutor
# =============================================================================


class SecureAgentExecutor:
    """
    Drop-in replacement for LangChain AgentExecutor with Tenuo protection.

    All tools are automatically protected. Use with mint() context.

    Example:
        from tenuo.langchain import SecureAgentExecutor

        executor = SecureAgentExecutor(agent=agent, tools=tools)

        async with mint(Capability("search")):
            result = await executor.ainvoke({"input": "search"})
    """

    def __init__(
        self,
        agent: Any,
        tools: List[Any],
        *,
        strict: bool = False,
        warn_on_missing_warrant: bool = True,
        schemas: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain not installed. Run: uv pip install langchain-core")

        from langchain.agents import AgentExecutor  # type: ignore[import-not-found,attr-defined]

        # Wrap tools with Tenuo configuration
        protected_tools = guard_tools(
            tools, strict=strict, warn_on_missing_warrant=warn_on_missing_warrant, schemas=schemas
        )

        # Create underlying executor
        self._executor = AgentExecutor(agent=agent, tools=protected_tools, **kwargs)

    def invoke(self, input_data: Any, **kwargs: Any) -> Any:
        return self._executor.invoke(input_data, **kwargs)

    async def ainvoke(self, input_data: Any, **kwargs: Any) -> Any:
        return await self._executor.ainvoke(input_data, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._executor, name)


__all__ = [
    # Primary API
    "guard",  # Unified smart wrapper
    "guard_tools",  # Wrap tools (you manage context)
    "guard_agent",  # Wrap executor (built-in context)
    "auto_protect",  # Zero-config with audit mode default
    "SecureAgentExecutor",  # Drop-in AgentExecutor replacement
    "TenuoTool",  # LangChain BaseTool wrapper
    # Feature flag
    "LANGCHAIN_AVAILABLE",
]
