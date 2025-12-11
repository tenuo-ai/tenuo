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

from tenuo import Warrant, Keypair, AuthorizationError, Pattern, Exact, OneOf, Range
from tenuo.decorators import get_warrant_context, get_keypair_context

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
# Constraint Building
# =============================================================================

def _build_constraint(raw: Any) -> Any:
    """
    Convert config constraint to Tenuo constraint type.
    
    Supported formats:
        exact: "value"           -> Exact("value")
        pattern: "/path/*"       -> Pattern("/path/*")
        enum: ["a", "b", "c"]    -> OneOf(["a", "b", "c"])
        min: 0, max: 100         -> Range(0, 100)
    """
    if not isinstance(raw, dict):
        # Raw value = exact match
        return Exact(raw)
    
    if "exact" in raw:
        return Exact(raw["exact"])
    if "pattern" in raw:
        return Pattern(raw["pattern"])
    if "enum" in raw:
        return OneOf(raw["enum"])
    if "min" in raw or "max" in raw:
        return Range(min_val=raw.get("min"), max_val=raw.get("max"))
    
    raise ValueError(f"Unknown constraint format: {raw}")


# =============================================================================
# Core Functions
# =============================================================================

def protect_tool(
    tool: Callable, 
    name: Optional[str] = None, 
    extract_args: Optional[Callable] = None,
    warrant: Optional[Warrant] = None,
    keypair: Optional[Keypair] = None
) -> Callable:
    """
    Wrap a tool function to enforce Tenuo authorization.
    
    If warrant/keypair are provided, they are used (Single Agent mode).
    If not, they are retrieved from context (SecureGraph mode).
    
    Args:
        tool: The tool function to wrap.
        name: Tool name (defaults to function name).
        extract_args: Function to extract authorization args from tool call.
        warrant: Explicit warrant to use (optional).
        keypair: Explicit keypair to use (optional).
    
    Returns:
        Wrapped function that enforces authorization before execution.
    """
    tool_name = name or tool.__name__
    
    @wraps(tool)
    def protected_tool(*args, **kwargs):
        # 1. Get context (or use provided)
        current_warrant = warrant or get_warrant_context()
        current_keypair = keypair or get_keypair_context()
        
        if not current_warrant:
            raise AuthorizationError(
                f"No warrant found for tool '{tool_name}'. "
                "Either pass warrant explicitly or set it in context."
            )
            
        # 2. Extract args for auth check
        if extract_args:
            # Bind args to signature to handle positional/keyword mix
            import inspect
            sig = inspect.signature(tool)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            auth_args = extract_args(**bound.arguments)
        else:
            # Default: use all kwargs + positional args mapped to param names
            import inspect
            sig = inspect.signature(tool)
            params = list(sig.parameters.keys())
            auth_args = dict(kwargs)
            for i, arg_val in enumerate(args):
                if i < len(params):
                    auth_args[params[i]] = arg_val
            
        # 3. Create PoP signature if needed
        signature = None
        if current_warrant.requires_pop:
            if not current_keypair:
                raise AuthorizationError(
                    f"Warrant requires Proof-of-Possession for tool '{tool_name}', "
                    "but no keypair is available."
                )
            signature = current_warrant.create_pop_signature(
                current_keypair, tool_name, auth_args
            )
            
        # 4. Authorize
        if not current_warrant.authorize(tool_name, auth_args, signature):
            raise AuthorizationError(
                f"Warrant does not authorize tool '{tool_name}' with args {auth_args}"
            )
            
        # 5. Execute original
        logger.debug(f"Authorized access to '{tool_name}' with args {auth_args}")
        return tool(*args, **kwargs)
    
    # Preserve original function metadata for LangChain
    protected_tool.__name__ = tool.__name__
    protected_tool.__doc__ = tool.__doc__
    
    return protected_tool


def protect_tools(
    tools: List[Callable],
    warrant: Warrant,
    keypair: Optional[Keypair] = None,
    config: Optional[Union[str, dict, LangChainConfig]] = None
) -> List[Callable]:
    """
    Wrap a list of tools for Single Agent use with Tenuo authorization.
    
    This is the main entry point for protecting LangChain tools. Each tool
    will be wrapped to check authorization before execution.
    
    Args:
        tools: List of tool functions to protect.
        warrant: Root warrant to enforce.
        keypair: Keypair for PoP (if warrant requires it).
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
        tool_name = tool.__name__
        
        # Get tool-specific config if available
        tool_config = parsed_config.tools.get(tool_name) if parsed_config else None
        
        if tool_config and tool_config.constraints:
            # Attenuate warrant for this specific tool
            constraints = {}
            for constraint_name, constraint_value in tool_config.constraints.items():
                constraints[constraint_name] = _build_constraint(constraint_value)
            
            tool_warrant = warrant.attenuate(
                tool=tool_name,
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
