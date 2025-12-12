"""
Tenuo LangChain Integration

This module provides tools to wrap LangChain tools with Tenuo authorization.

Usage patterns:

1. Single Agent with Config (Recommended):
    ```python
    from tenuo.langchain import protect_tools
    
    # Your tools - NO TENUO IMPORTS needed
    @tool
    def search(query: str) -> str: ...
    
    @tool  
    def read_file(path: str) -> str: ...
    
    # Wrap at setup time
    secure_tools = protect_tools(
        tools=[search, read_file],
        warrant=root_warrant,
        keypair=keypair,
        config="tenuo.yaml",  # Per-tool constraints
    )
    
    agent = AgentExecutor(agent=base_agent, tools=secure_tools)
    ```

2. Single Agent without Config:
    ```python
    secure_tools = protect_tools(
        tools=[search, read_file],
        warrant=root_warrant,
        keypair=keypair,
    )
    ```

3. Multi-Agent (use SecureGraph from tenuo.langgraph instead)
"""

from typing import List, Callable, Optional, Union, Any, Dict
from dataclasses import dataclass, field
from functools import wraps
import yaml
import logging

from tenuo import Warrant, Keypair, AuthorizationError
from tenuo.decorators import get_warrant_context, get_keypair_context
from tenuo.audit import audit_logger, AuditEvent, AuditEventType
from tenuo.config_utils import build_constraint

# Module logger
logger = logging.getLogger("tenuo.langchain")


# =============================================================================
# Config Classes
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
              max_results:
                max: 100
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


# =============================================================================
# Constraint Building (imported from config_utils)
# =============================================================================
# build_constraint() is imported from tenuo.config_utils


# =============================================================================
# Core Functions
# =============================================================================

def _get_tool_name(tool: Any) -> str:
    """
    Get the name of a tool, handling both functions and LangChain BaseTool.
    
    LangChain tools (StructuredTool, BaseTool) have a 'name' attribute.
    Regular functions have __name__.
    """
    return getattr(tool, 'name', getattr(tool, '__name__', str(tool)))


def _get_callable(tool: Any) -> Callable:
    """
    Get the callable from a tool, handling both functions and LangChain BaseTool.
    
    LangChain BaseTool has a 'func' attribute or can be called directly.
    """
    if hasattr(tool, 'func') and tool.func is not None:
        return tool.func
    if hasattr(tool, '_run'):
        return tool._run
    return tool


def protect_tool(
    tool: Any,  # Callable or LangChain BaseTool
    name: Optional[str] = None, 
    extract_args: Optional[Callable[..., dict]] = None,
    warrant: Optional[Warrant] = None,
    keypair: Optional[Keypair] = None
) -> Callable:
    """
    Wrap a tool function to enforce Tenuo authorization.
    
    If warrant/keypair are provided, they are used (Single Agent mode).
    If not, they are retrieved from context (SecureGraph mode).
    
    IMPORTANT: PoP is MANDATORY
    ---------------------------
    Keypair must always be available (either provided or in context) because
    Proof-of-Possession is mandatory. This ensures leaked warrants are useless
    without the corresponding private key.
    
    Args:
        tool: The tool function or LangChain BaseTool to wrap.
        name: Tool name (defaults to tool.name or function name).
        extract_args: Function to extract authorization args from tool call.
        warrant: Explicit warrant to use (optional, falls back to context).
        keypair: Explicit keypair to use (optional, falls back to context).
    
    Returns:
        Wrapped function that enforces authorization before execution.
    """
    # Handle both functions and LangChain BaseTool objects
    tool_name = name or _get_tool_name(tool)
    callable_func = _get_callable(tool)
    
    @wraps(callable_func)
    def protected_tool(*args, **kwargs):
        # 1. Get context (or use provided)
        current_warrant = warrant or get_warrant_context()
        current_keypair = keypair or get_keypair_context()
        
        if not current_warrant:
            raise AuthorizationError(
                f"No warrant found for tool '{tool_name}'. "
                "Either pass warrant explicitly or set it in context."
            )
        
        # PoP is MANDATORY - keypair must always be available
        if not current_keypair:
            raise AuthorizationError(
                f"No keypair found for tool '{tool_name}'. "
                "Proof-of-Possession is mandatory - keypair is required. "
                "Either pass keypair explicitly or set it in context using set_keypair_context()."
            )
        
        # 2. Check warrant expiry BEFORE any further processing
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
            
        # 3. Extract args for auth check
        if extract_args:
            # Bind args to signature to handle positional/keyword mix
            import inspect
            sig = inspect.signature(callable_func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            auth_args = extract_args(**bound.arguments)
        else:
            # Default: use all kwargs + positional args mapped to param names
            import inspect
            sig = inspect.signature(callable_func)
            params = list(sig.parameters.keys())
            auth_args = dict(kwargs)
            for i, arg_val in enumerate(args):
                if i < len(params):
                    auth_args[params[i]] = arg_val
            
        # 4. Create PoP signature (ALWAYS - PoP is mandatory)
        # Keypair is guaranteed to be present (validated above)
        signature = current_warrant.create_pop_signature(
            current_keypair, tool_name, auth_args
        )
            
        # 5. Authorize
        if not current_warrant.authorize(tool_name, auth_args, bytes(signature)):
            # Audit log the failure
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
            
        # 6. Execute original
        logger.debug(f"Authorized access to '{tool_name}' with args {auth_args}")
        return callable_func(*args, **kwargs)
    
    # Preserve original function/tool metadata for LangChain
    protected_tool.__name__ = getattr(callable_func, '__name__', tool_name)
    protected_tool.__doc__ = getattr(callable_func, '__doc__', None)
    
    # Preserve LangChain-specific attributes if present
    for attr in ('name', 'description', 'args_schema', 'return_direct', 
                 'verbose', 'handle_tool_error', 'handle_validation_error'):
        if hasattr(tool, attr):
            setattr(protected_tool, attr, getattr(tool, attr))
    
    return protected_tool


def protect_tools(
    tools: List[Callable],
    warrant: Warrant,
    keypair: Keypair,  # REQUIRED - PoP is mandatory
    config: Optional[Union[str, dict, LangChainConfig]] = None
) -> List[Callable]:
    """
    Wrap a list of tools for Single Agent use with Tenuo authorization.
    
    This is the main entry point for protecting LangChain tools. Each tool
    will be wrapped to check authorization before execution.
    
    IMPORTANT: PoP is MANDATORY
    ---------------------------
    The keypair parameter is required because Proof-of-Possession (PoP) is
    mandatory. This ensures that leaked warrants are useless without the
    corresponding private key.
    
    IMPORTANT: Static vs Dynamic Constraints
    ----------------------------------------
    Constraints are evaluated at SETUP TIME when protect_tools() is called.
    This means ${state.*} interpolation is NOT supported here.
    
    For dynamic constraints that depend on runtime state, use SecureGraph:
    
        from tenuo.langgraph import SecureGraph
        
        # Dynamic constraints work in SecureGraph
        config = {
            "nodes": {
                "file_reader": {
                    "attenuate": {
                        "tools": ["read_file"],
                        "constraints": {
                            "path": {"pattern": "/uploads/${state.user_id}/*"}
                        }
                    }
                }
            }
        }
        secure = SecureGraph(graph=graph, config=config, ...)
    
    Args:
        tools: List of tool functions to protect.
        warrant: Root warrant to enforce.
        keypair: Keypair for PoP (REQUIRED - Proof-of-Possession is mandatory).
        config: Optional config for per-tool constraints. Can be:
                - Path to YAML config file
                - Dict with config
                - LangChainConfig object
    
    Returns:
        List of protected tool functions.
    
    Example config (tenuo.yaml):
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
    
    With config, each tool gets its own attenuated warrant based on the
    constraints specified. Without config, all tools use the root warrant.
    """
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
            # Use root warrant as-is
            tool_warrant = warrant
        
        # Wrap the tool
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
