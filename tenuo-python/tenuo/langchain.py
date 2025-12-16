"""
Tenuo LangChain Integration

This module provides two patterns for protecting LangChain tools with Tenuo:

1. **Tier 1 API (Recommended)** - Uses context from root_task/scoped_task:
    ```python
    from tenuo import configure, root_task_sync, Keypair
    from tenuo.langchain import protect_langchain_tools
    
    kp = Keypair.generate()
    configure(issuer_key=kp, dev_mode=True)
    
    # Wrap LangChain tools
    tools = protect_langchain_tools([search_tool, file_tool])
    
    # Tools automatically use warrant from context
    with root_task_sync(tools=["search", "read_file"], path="/data/*"):
        agent = create_openai_tools_agent(llm, tools)
        result = executor.invoke({"input": "search for reports"})
    ```

2. **Tier 2 API (Explicit)** - Pass warrant/keypair explicitly:
    ```python
    from tenuo.langchain import protect_tools
    
    # Wrap with explicit warrant
    tools = protect_tools(
        tools=[search, read_file],
        warrant=root_warrant,
        keypair=keypair,
    )
    ```

For multi-agent graphs with automatic delegation, see tenuo.langgraph.
"""

from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Union
import asyncio
import inspect
import logging

import yaml

from .config import allow_passthrough
from .decorators import get_warrant_context, get_keypair_context, get_allowed_tools_context
from .exceptions import (
    TenuoError,
    ToolNotAuthorized,
    ConstraintViolation,
    ConfigurationError,
)
from .schemas import ToolSchema, TOOL_SCHEMAS, _get_tool_name
from .audit import log_authorization_success

# Optional LangChain import
try:
    from langchain_core.tools import BaseTool, StructuredTool
    from pydantic import BaseModel
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    BaseTool = object  # type: ignore
    StructuredTool = object  # type: ignore
    BaseModel = object  # type: ignore

# Module logger
logger = logging.getLogger("tenuo.langchain")


# =============================================================================
# Tier 1 API: Context-based protection
# =============================================================================

def protect_langchain_tools(
    tools: List[Any],
    *,
    strict: bool = False,
    schemas: Optional[Dict[str, ToolSchema]] = None,
) -> List[Any]:
    """
    Wrap LangChain tools with Tenuo authorization (Tier 1 API).
    
    This function wraps LangChain tools to enforce authorization using
    warrants from context (set by root_task/scoped_task).
    
    Args:
        tools: List of LangChain BaseTool objects
        strict: If True, fail on tools with require_at_least_one but no constraints
        schemas: Optional custom tool schemas
    
    Returns:
        List of TenuoTool wrapped tools
    
    Example:
        from tenuo import configure, root_task_sync, Keypair
        from tenuo.langchain import protect_langchain_tools
        
        kp = Keypair.generate()
        configure(issuer_key=kp, dev_mode=True)
        
        tools = protect_langchain_tools([search_tool, file_tool])
        
        with root_task_sync(tools=["search", "read_file"], path="/data/*"):
            result = tools[0].invoke({"query": "Q3 reports"})
    
    Raises:
        ImportError: If langchain is not installed
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LangChain is required for protect_langchain_tools(). "
            "Install with: pip install langchain-core"
        )
    
    merged_schemas = {**TOOL_SCHEMAS, **(schemas or {})}
    return [TenuoTool(t, strict=strict, schemas=merged_schemas) for t in tools]


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
    
    def __init__(
        self,
        wrapped: Any,
        strict: bool = False,
        schemas: Optional[Dict[str, ToolSchema]] = None,
        **kwargs: Any,
    ):
        """
        Create a TenuoTool wrapper.
        
        Args:
            wrapped: The LangChain tool to wrap
            strict: Enforce constraints for require_at_least_one tools
            schemas: Tool schemas for risk level checking
        """
        # Get tool name and description
        tool_name = _get_tool_name(wrapped)
        tool_desc = getattr(wrapped, 'description', f"Protected tool: {tool_name}")
        
        # Initialize with name and description
        super().__init__(name=tool_name, description=tool_desc, **kwargs)
        
        # Store wrapped tool and settings
        object.__setattr__(self, 'wrapped', wrapped)
        object.__setattr__(self, 'strict', strict)
        object.__setattr__(self, '_schemas', schemas or TOOL_SCHEMAS)
        
        # Copy args_schema if present
        if hasattr(wrapped, 'args_schema'):
            object.__setattr__(self, 'args_schema', wrapped.args_schema)
    
    def _check_authorization(self, tool_input: Dict[str, Any]) -> None:
        """Check authorization before tool execution."""
        warrant = get_warrant_context()
        schema = self._schemas.get(self.name)
        
        # No warrant in context
        if warrant is None:
            if allow_passthrough():
                logger.warning(
                    f"PASSTHROUGH: Tool '{self.name}' executed without warrant"
                )
                return
            raise ToolNotAuthorized(tool=self.name)
        
        # Check allowed tools from scoped_task context (takes precedence)
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
        
        # Critical tools require constraints
        if schema and schema.risk_level == "critical":
            constraints = _get_constraints_dict(warrant)
            has_relevant = any(
                c in constraints for c in schema.recommended_constraints
            )
            if not has_relevant and not constraints:
                raise ConfigurationError(
                    f"Critical tool '{self.name}' requires at least one constraint. "
                    f"Recommended: {schema.recommended_constraints}."
                )
        
        # Strict mode
        if self.strict and schema and schema.require_at_least_one:
            constraints = _get_constraints_dict(warrant)
            if not constraints:
                raise ConfigurationError(
                    f"Strict mode: tool '{self.name}' requires at least one constraint."
                )
        
        # Check constraints
        constraints = _get_constraints_dict(warrant)
        for key, constraint in constraints.items():
            if key in tool_input:
                value = tool_input[key]
                if hasattr(constraint, 'check'):
                    try:
                        constraint.check(value)
                    except Exception as e:
                        raise ConstraintViolation(
                            field=key,
                            reason=str(e),
                            value=value,
                        ) from e
        
        # Audit success
        log_authorization_success(warrant, self.name, tool_input)
    
    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous tool execution with authorization."""
        # Build tool input from args/kwargs
        tool_input = self._build_tool_input(args, kwargs)
        
        # Check authorization
        self._check_authorization(tool_input)
        
        # Execute wrapped tool - prefer func over _run for @tool decorated functions
        if hasattr(self.wrapped, 'func') and self.wrapped.func is not None:
            return self.wrapped.func(*args, **kwargs)
        elif hasattr(self.wrapped, '_run'):
            # Pass through config if present in kwargs
            return self.wrapped._run(*args, **kwargs)
        else:
            return self.wrapped(*args, **kwargs)
    
    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronous tool execution with authorization."""
        # Build tool input from args/kwargs
        tool_input = self._build_tool_input(args, kwargs)
        
        # Check authorization
        self._check_authorization(tool_input)
        
        # Execute wrapped tool - prefer func over _arun for @tool decorated functions
        if hasattr(self.wrapped, 'coroutine') and self.wrapped.coroutine is not None:
            return await self.wrapped.coroutine(*args, **kwargs)
        elif hasattr(self.wrapped, 'func') and self.wrapped.func is not None:
            result = self.wrapped.func(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
        elif hasattr(self.wrapped, '_arun'):
            return await self.wrapped._arun(*args, **kwargs)
        elif hasattr(self.wrapped, '_run'):
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
        if hasattr(self.wrapped, 'func'):
            func = self.wrapped.func
        elif hasattr(self.wrapped, '_run'):
            func = self.wrapped._run
        elif callable(self.wrapped):
            func = self.wrapped
        else:
            return tool_input
        
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            # Skip 'self' if present
            if params and params[0] == 'self':
                params = params[1:]
            for i, arg in enumerate(args):
                if i < len(params):
                    tool_input[params[i]] = arg
        except (ValueError, TypeError):
            pass
        
        return tool_input


def _get_constraints_dict(warrant: Any) -> Dict[str, Any]:
    """Safely get constraints dict from warrant."""
    if hasattr(warrant, 'constraints_dict'):
        result = warrant.constraints_dict()
        if result is not None:
            return dict(result)
    return {}


# =============================================================================
# Tier 2 API: Explicit warrant/keypair (preserved for compatibility)
# =============================================================================

@dataclass
class ToolConfig:
    """Configuration for a single tool."""
    name: str
    constraints: Dict[str, Any] = field(default_factory=dict)
    extract_args: Optional[Callable] = None


@dataclass  
class LangChainConfig:
    """
    Configuration for protect_tools().
    
    Config file format (tenuo.yaml):
        version: "1"
        tools:
          search:
            constraints:
              query:
                pattern: "*"
          read_file:
            constraints:
              path:
                pattern: "/data/*"
    """
    version: str = "1"
    tools: Dict[str, ToolConfig] = field(default_factory=dict)
    
    @classmethod
    def from_file(cls, path: str) -> "LangChainConfig":
        """Load config from YAML file."""
        with open(path) as f:
            raw = yaml.safe_load(f)
        return cls.from_dict(raw)
    
    @classmethod
    def from_dict(cls, raw: dict) -> "LangChainConfig":
        """Parse config from dictionary."""
        tools = {}
        for name, tool_raw in raw.get("tools", {}).items():
            tools[name] = ToolConfig(
                name=name,
                constraints=tool_raw.get("constraints", {}),
            )
        return cls(
            version=raw.get("version", "1"),
            tools=tools,
        )


def protect_tool(
    tool: Any,
    name: Optional[str] = None, 
    extract_args: Optional[Callable[..., dict]] = None,
    warrant: Optional[Any] = None,
    keypair: Optional[Any] = None,
) -> Callable:
    """
    Wrap a tool function to enforce Tenuo authorization (Tier 2 API).
    
    If warrant/keypair are provided, they are used directly.
    If not, they are retrieved from context.
    
    Args:
        tool: The tool function or LangChain BaseTool to wrap.
        name: Tool name (defaults to tool.name or function name).
        extract_args: Function to extract authorization args from tool call.
        warrant: Explicit warrant to use (optional).
        keypair: Explicit keypair to use (optional).
    
    Returns:
        Wrapped function that enforces authorization before execution.
    """
    from .audit import audit_logger, AuditEvent, AuditEventType
    from .exceptions import ScopeViolation as AuthorizationError
    
    tool_name = name or _get_tool_name(tool)
    
    # Get the callable
    if hasattr(tool, 'func') and tool.func is not None:
        callable_func = tool.func
    elif hasattr(tool, '_run'):
        callable_func = tool._run
    else:
        callable_func = tool
    
    @wraps(callable_func)
    def protected_tool(*args: Any, **kwargs: Any) -> Any:
        # Get context (or use provided)
        current_warrant = warrant or get_warrant_context()
        current_keypair = keypair or get_keypair_context()
        
        if not current_warrant:
            raise AuthorizationError(
                f"No warrant found for tool '{tool_name}'. "
                "Either pass warrant explicitly or set it in context."
            )
        
        if not current_keypair:
            raise AuthorizationError(
                f"No keypair found for tool '{tool_name}'. "
                "Either pass keypair explicitly or set it in context."
            )
        
        # Check warrant expiry
        if current_warrant.is_expired():
            expires_at = current_warrant.expires_at() if hasattr(current_warrant, 'expires_at') else "unknown"
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.WARRANT_EXPIRED,
                warrant_id=current_warrant.id,
                tool=tool_name,
                action="denied",
                error_code="warrant_expired",
                details=f"Warrant expired at {expires_at}",
            ))
            raise AuthorizationError(
                f"Warrant has expired (at {expires_at}). "
                f"Cannot authorize tool '{tool_name}'."
            )
            
        # Extract args for auth check
        if extract_args:
            sig = inspect.signature(callable_func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            auth_args = extract_args(**bound.arguments)
        else:
            sig = inspect.signature(callable_func)
            params = list(sig.parameters.keys())
            auth_args = dict(kwargs)
            for i, arg_val in enumerate(args):
                if i < len(params):
                    auth_args[params[i]] = arg_val
            
        # Create PoP signature
        signature = current_warrant.create_pop_signature(
            current_keypair, tool_name, auth_args
        )
            
        # Authorize
        if not current_warrant.authorize(tool_name, auth_args, bytes(signature)):
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.AUTHORIZATION_FAILURE,
                warrant_id=current_warrant.id,
                tool=tool_name,
                action="denied",
                trace_id=current_warrant.session_id,
                constraints=auth_args,
                error_code="constraint_not_satisfied",
                details=f"Warrant does not authorize tool '{tool_name}' with provided args",
            ))
            raise AuthorizationError(
                f"Warrant does not authorize tool '{tool_name}' with args {auth_args}"
            )
            
        # Audit log the success
        audit_logger.log(AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_SUCCESS,
            warrant_id=current_warrant.id,
            tool=tool_name,
            action="authorized",
            trace_id=current_warrant.session_id,
            constraints=auth_args,
            details=f"Authorization successful for tool '{tool_name}'",
        ))
            
        # Execute original
        logger.debug(f"Authorized access to '{tool_name}' with args {auth_args}")
        return callable_func(*args, **kwargs)
    
    # Preserve metadata
    protected_tool.__name__ = getattr(callable_func, '__name__', tool_name)
    protected_tool.__doc__ = getattr(callable_func, '__doc__', None)
    
    # Preserve LangChain attributes
    for attr in ('name', 'description', 'args_schema', 'return_direct'):
        if hasattr(tool, attr):
            setattr(protected_tool, attr, getattr(tool, attr))
    
    return protected_tool


def protect_tools(
    tools: List[Any],
    warrant: Any,
    keypair: Any,
    config: Optional[Union[str, dict, LangChainConfig]] = None,
) -> List[Callable]:
    """
    Wrap tools for Single Agent use with Tenuo authorization (Tier 2 API).
    
    This is the Tier 2 entry point requiring explicit warrant/keypair.
    For Tier 1 (context-based), use protect_langchain_tools().
    
    Args:
        tools: List of tool functions to protect.
        warrant: Root warrant to enforce.
        keypair: Keypair for PoP.
        config: Optional config for per-tool constraints.
    
    Returns:
        List of protected tool functions.
    """
    from .config_utils import build_constraint
    
    # Load config if provided
    parsed_config: Optional[LangChainConfig] = None
    if config is not None:
        if isinstance(config, LangChainConfig):
            parsed_config = config
        elif isinstance(config, str):
            parsed_config = LangChainConfig.from_file(config)
        elif isinstance(config, dict):
            parsed_config = LangChainConfig.from_dict(config)
        else:
            raise TypeError(f"Invalid config type: {type(config)}")
    
    protected = []
    for tool in tools:
        tool_name = _get_tool_name(tool)
        
        # Get tool-specific config if available
        tool_config = parsed_config.tools.get(tool_name) if parsed_config else None
        
        if tool_config and tool_config.constraints:
            # Attenuate warrant for this specific tool
            constraints = {}
            for constraint_name, constraint_value in tool_config.constraints.items():
                constraints[constraint_name] = build_constraint(constraint_value)
            
            tool_warrant = warrant.attenuate(
                constraints=constraints,
                keypair=keypair,
            )
            logger.debug(
                f"Attenuated warrant for tool '{tool_name}': {tool_warrant.id}"
            )
        else:
            tool_warrant = warrant
        
        protected.append(
            protect_tool(
                tool,
                name=tool_name,
                warrant=tool_warrant,
                keypair=keypair,
                extract_args=tool_config.extract_args if tool_config else None,
            )
        )
    
    return protected


# =============================================================================
# DX: One-liner secure_agent()
# =============================================================================

def secure_agent(
    tools: List[Any],
    *,
    issuer_keypair: Optional[Any] = None,
    strict_mode: bool = False,
    warn_on_missing_warrant: bool = True,
    schemas: Optional[Dict[str, ToolSchema]] = None,
) -> List[Any]:
    """
    One-liner to secure LangChain tools with Tenuo authorization.
    
    This is the recommended entry point for LangChain users. It:
    1. Configures Tenuo globally (if issuer_keypair provided)
    2. Wraps tools with protection
    3. Sets up warnings for missing warrants by default
    
    Args:
        tools: List of LangChain BaseTool objects to protect
        issuer_keypair: Keypair for issuing warrants (enables dev_mode if provided)
        strict_mode: If True, fail on any missing warrant (default: False)
        warn_on_missing_warrant: If True, log warnings for unprotected calls (default: True)
        schemas: Optional custom tool schemas for risk level checking
    
    Returns:
        List of protected TenuoTool objects
    
    Example:
        from tenuo import Keypair, root_task_sync
        from tenuo.langchain import secure_agent
        from langchain.agents import create_openai_tools_agent, AgentExecutor
        
        # One line to secure your tools
        kp = Keypair.generate()
        tools = secure_agent([search, calculator], issuer_keypair=kp)
        
        # Create agent as normal
        agent = create_openai_tools_agent(llm, tools, prompt)
        executor = AgentExecutor(agent=agent, tools=tools)
        
        # Run with authorization
        with root_task_sync(tools=["search", "calculator"]):
            result = executor.invoke({"input": "What is 2+2?"})
    
    Note:
        This function is idempotent - calling it multiple times with the same
        issuer_keypair will not reconfigure Tenuo.
    """
    if not LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LangChain is required for secure_agent(). "
            "Install with: pip install langchain-core"
        )
    
    # Configure Tenuo if keypair provided
    if issuer_keypair is not None:
        from .config import configure, is_configured
        if not is_configured():
            configure(
                issuer_key=issuer_keypair,
                dev_mode=True,  # Auto-enable dev mode for one-liner usage
                strict_mode=strict_mode,
                warn_on_missing_warrant=warn_on_missing_warrant,
            )
        else:
            # Update mode settings even if already configured
            from .config import get_config
            config = get_config()
            if config:
                object.__setattr__(config, 'strict_mode', strict_mode)
                object.__setattr__(config, 'warn_on_missing_warrant', warn_on_missing_warrant)
    
    # Protect tools
    merged_schemas = {**TOOL_SCHEMAS, **(schemas or {})}
    return [TenuoTool(t, strict=strict_mode, schemas=merged_schemas) for t in tools]


__all__ = [
    # DX: One-liner entry point
    "secure_agent",
    # Tier 1 API (context-based)
    "protect_langchain_tools",
    "TenuoTool",
    # Tier 2 API (explicit)
    "protect_tool",
    "protect_tools",
    "ToolConfig",
    "LangChainConfig",
    # Feature flag
    "LANGCHAIN_AVAILABLE",
]
