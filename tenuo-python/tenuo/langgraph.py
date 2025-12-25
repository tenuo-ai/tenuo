"""
Tenuo LangGraph Integration

This module provides tools for securing LangGraph agents with Tenuo.
It solves the key management problem by keeping private keys out of the graph state.

Recommended Pattern:
    1. Auto-load keys from env vars OR register manually
    2. Pass warrant in state (it attenuates dynamically)
    3. Pass key_id via LangGraph config (infrastructure concern)
    4. Use guard() wrapper OR @tenuo_node decorator

Usage:
    from tenuo import KeyRegistry, SigningKey
    from tenuo.langgraph import guard, TenuoToolNode, load_tenuo_keys
    
    # Option 1: Auto-load keys from TENUO_KEY_* env vars
    load_tenuo_keys()  # Loads TENUO_KEY_DEFAULT, TENUO_KEY_WORKER_1, etc.
    
    # Option 2: Manual registration
    KeyRegistry.get_instance().register("worker", SigningKey.generate())
    
    # Define State (only warrant - key_id goes in config)
    class State(TypedDict):
        messages: List[BaseMessage]
        warrant: Warrant
    
    # Option A: guard() wrapper (keeps node pure)
    def my_agent(state: State) -> dict:
        return {"messages": [...]}
    
    graph.add_node("agent", guard(my_agent))
    
    # Option B: @tenuo_node decorator (explicit access to bound_warrant)
    @tenuo_node
    def my_agent(state: State, bound_warrant: BoundWarrant) -> dict:
        if bound_warrant.allows("search"):
        ...
        return {"messages": [...]}
        
    # Invoke with key_id in config
    graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})
"""

from typing import Any, Callable, Dict, List, Optional, Union, TypeVar
from functools import wraps
import logging
import os

from .exceptions import ConfigurationError
from .bound_warrant import BoundWarrant
from .keys import KeyRegistry, load_signing_key_from_env
from tenuo_core import Warrant

# Optional LangGraph imports
try:
    from langgraph.prebuilt import ToolNode  # type: ignore
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool
    from langchain_core.runnables import RunnableConfig
    LANGGRAPH_AVAILABLE = True
except (ImportError, TypeError):
    # TypeError can happen on Python 3.9 with old typing/Pydantic interactions in langchain
    LANGGRAPH_AVAILABLE = False
    ToolNode = object  # type: ignore
    BaseTool = object  # type: ignore
    RunnableConfig = dict  # type: ignore

logger = logging.getLogger("tenuo.langgraph")

F = TypeVar('F', bound=Callable)


# =============================================================================
# Key Auto-Loading (Convention over Configuration)
# =============================================================================

def load_tenuo_keys(prefix: str = "TENUO_KEY_") -> int:
    """
    Auto-load signing keys from environment variables.
    
    Scans for env vars matching the prefix and registers them in KeyRegistry.
    
    Naming convention:
        TENUO_KEY_DEFAULT -> key_id="default"
        TENUO_KEY_WORKER_1 -> key_id="worker-1"
        TENUO_KEY_MY_SERVICE -> key_id="my-service"
    
    Args:
        prefix: Environment variable prefix (default: "TENUO_KEY_")
        
    Returns:
        Number of keys loaded
        
    Example:
        # Set env vars:
        # TENUO_KEY_DEFAULT=base64...
        # TENUO_KEY_WORKER=base64...
        
        count = load_tenuo_keys()
        print(f"Loaded {count} keys")
    """
    registry = KeyRegistry.get_instance()
    loaded = 0
    
    for name, value in os.environ.items():
        if name.startswith(prefix) and value:
            # Convert TENUO_KEY_WORKER_1 -> worker-1
            key_id = name[len(prefix):].lower().replace("_", "-")
            if not key_id:
                key_id = "default"
            
            try:
                key = load_signing_key_from_env(name)
                registry.register(key_id, key)
                logger.info(f"Auto-loaded key '{key_id}' from {name}")
                loaded += 1
            except Exception as e:
                logger.warning(f"Failed to load key from {name}: {e}")
    
    return loaded


# =============================================================================
# Core: Get BoundWarrant from State + Config
# =============================================================================

def _get_key_id_from_config(config: Optional[Dict[str, Any]]) -> str:
    """Extract key_id from LangGraph config, with fallback to 'default'."""
    if config is None:
        return "default"
    
    # LangGraph stores custom config in "configurable"
    configurable = config.get("configurable", {})
    return configurable.get("tenuo_key_id", "default")


def _get_bound_warrant(
    state: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    *,
    key_id: Optional[str] = None,
) -> BoundWarrant:
    """
    Get BoundWarrant from state warrant + key from registry.
    
    Key resolution order:
    1. Explicit key_id parameter
    2. config["configurable"]["tenuo_key_id"]
    3. "default"
    
    Args:
        state: Graph state containing 'warrant'
        config: LangGraph config (optional)
        key_id: Explicit key_id override (optional)
    
    Returns:
        BoundWarrant
        
    Raises:
        ConfigurationError: If warrant missing or key not found
    """
    # Get warrant from state
    warrant = state.get("warrant")
    if not warrant:
        raise ConfigurationError(
            "State is missing 'warrant' field. "
            "Ensure your State TypedDict includes 'warrant: Warrant'."
        )
    
    # Auto-inflate from string (Base64) if needed (for serialization safety)
    if isinstance(warrant, str):
        try:
            warrant = Warrant.from_base64(warrant)
        except Exception as e:
            raise ConfigurationError(f"Failed to decode warrant from string token: {e}")
    
    if key_id is None:
        # Try config first
        resolved_key_id = _get_key_id_from_config(config)
    else:
        resolved_key_id = key_id
    
    # Get key from registry
    registry = KeyRegistry.get_instance()
    try:
        key = registry.get(resolved_key_id)
    except KeyError:
        raise ConfigurationError(
            f"Key '{resolved_key_id}' not found in KeyRegistry. "
            f"Either register it manually or use load_tenuo_keys() to load from env vars."
        )
        
    # Bind key to warrant
    if isinstance(warrant, BoundWarrant):
        # Already bound - use as-is (rare in state)
        return warrant
    elif hasattr(warrant, 'bind'):
        return warrant.bind(key)
        
    raise ConfigurationError(f"Invalid warrant type in state: {type(warrant)}")


# =============================================================================
# guard() - Wrapper for Pure Nodes
# =============================================================================

def guard(
    node: Callable,
    *,
    key_id: Optional[str] = None,
    inject_warrant: bool = False,
) -> Callable:
    """
    Wrap a LangGraph node with Tenuo authorization.
    
    This keeps the node function pure (standard LangGraph signature).
    Authorization context is set up before the node runs.
    
    Args:
        node: The node function (state) -> dict
        key_id: Explicit key_id (default: from config or "default")
        inject_warrant: If True, pass bound_warrant as kwarg
        
    Returns:
        Wrapped node function
        
    Example:
        def my_agent(state: State) -> dict:
            # Pure domain logic - no Tenuo imports needed
            return {"messages": [...]}
        
        # Wrap at graph construction:
        graph.add_node("agent", guard(my_agent))
        graph.add_node("worker", guard(worker_node, key_id="worker"))
    """
    @wraps(node)
    def wrapper(
        state: Union[Dict[str, Any], Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        # print(f"DEBUG: wrapper called. config type: {type(config)}. kwargs: {kwargs.keys()}")
        if config is None and 'config' in kwargs:
             config = kwargs['config']
             
        state_dict = state if isinstance(state, dict) else vars(state)
        
        try:
            bw = _get_bound_warrant(state_dict, config, key_id=key_id)
        except Exception as e:
            raise ConfigurationError(
                f"Authorization failed in node '{node.__name__}': {e}"
            ) from e
        
        if inject_warrant:
            kwargs['bound_warrant'] = bw
        
        # For now, we just validate the warrant exists and is bound
        # The actual tool authorization happens in TenuoTool or guard()
        # This wrapper primarily ensures the key binding works
        
        # Check if wrapped function accepts config parameter
        import inspect
        sig = inspect.signature(node)
        accepts_config = 'config' in sig.parameters or any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        )
        
        if config and accepts_config:
            return node(state, config=config, **kwargs)
        else:
            return node(state, **kwargs)
    
    return wrapper


# =============================================================================
# @tenuo_node - Decorator with Explicit Access
# =============================================================================

def tenuo_node(func: F) -> F:
    """
    Decorator for LangGraph nodes that need explicit BoundWarrant access.
    
    Injects `bound_warrant` as a keyword argument. Use this when you need
    to check permissions, delegate, or attenuate within the node.
    
    For simple authorization (just ensuring the warrant is valid), prefer
    the `guard()` wrapper which keeps nodes pure.
    
    Args:
        func: Node function with signature (state, bound_warrant=...) -> dict
        
    Returns:
        Wrapped function
        
    Example:
        @tenuo_node
        def my_agent(state: State, bound_warrant: BoundWarrant) -> dict:
            # Check permissions before expensive operation
            if not bound_warrant.allows("search"):
                return {"messages": ["Not authorized for search"]}
            
            # Delegate to sub-agent
            child_warrant = bound_warrant.grant(
                to=worker_pubkey,
                allow=["search"],
                ttl=60
            )
            return {"messages": [...], "warrant": child_warrant}
    """
    @wraps(func)
    def wrapper(
        state: Union[Dict[str, Any], Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        state_dict = state if isinstance(state, dict) else vars(state)
        
        try:
            bw = _get_bound_warrant(state_dict, config)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to bind warrant in node '{func.__name__}': {e}"
            ) from e
            
        kwargs['bound_warrant'] = bw
        
        return func(state, **kwargs)
        
    return wrapper  # type: ignore


# =============================================================================
# require_warrant - Manual Helper
# =============================================================================

def require_warrant(
    state: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> BoundWarrant:
    """
    Manually get BoundWarrant from state + config.
    
    Use this if you can't use decorators/wrappers.
    
    Example:
        def my_node(state, config=None):
            bw = require_warrant(state, config)
            if bw.authorize("search", {"query": "test"}):
                ...
    """
    return _get_bound_warrant(state, config)


# =============================================================================
# TenuoToolNode - Secure ToolNode
# =============================================================================

class TenuoToolNode(ToolNode if LANGGRAPH_AVAILABLE else object):  # type: ignore
    """
    A Secure ToolNode that authorizes tool calls using warrant from state.
    
    Drop-in replacement for LangGraph's ToolNode with automatic Tenuo protection.
    
    Usage:
        from tenuo.langgraph import TenuoToolNode
        
        tools = [search, calculator]
        tool_node = TenuoToolNode(tools)
        
        graph.add_node("tools", tool_node)
        
        # Invoke with key_id in config
        graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})
    """
    
    def __init__(self, tools: List[BaseTool], **kwargs: Any):
        if not LANGGRAPH_AVAILABLE:
            raise ImportError(
                "LangGraph is required for TenuoToolNode. "
                "Install with: pip install langgraph"
            )
        super().__init__(tools, **kwargs)
        
    def _run_with_auth(
        self,
        input: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute tools with authorization from state warrant."""
        from .langchain import TenuoTool
        
        # Get BoundWarrant from state + config
        try:
            bw = _get_bound_warrant(input, config)
        except Exception as e:
            import uuid
            request_id = str(uuid.uuid4())[:8]
            logger.warning(f"[{request_id}] Failed to get BoundWarrant: {e}")
            return {
                "messages": [
                    ToolMessage(
                        content=f"Security configuration error (ref: {request_id})",
                        tool_call_id="unknown",
                        status="error"
                    )
                ]
            }
            
        # Wrap tools with authorization
        protected_map = {
            name: TenuoTool(tool, bound_warrant=bw)
            for name, tool in self.tools_by_name.items()
        }
        
        # Dispatch tool calls
        messages = input.get("messages", [])
        if not messages:
            return {"messages": []}
            
        last_message = messages[-1]
        if not hasattr(last_message, "tool_calls"):
            return {"messages": []}
            
        results = []
        for call in last_message.tool_calls:
            tool_name = call["name"]
            tool_args = call["args"]
            tool_id = call["id"]
            
            if tool_name not in protected_map:
                results.append(ToolMessage(
                        content=f"Error: Tool '{tool_name}' not found.",
                        tool_call_id=tool_id,
                        status="error"
                ))
                continue
                
            tool = protected_map[tool_name]
            
            try:
                output = tool.invoke(tool_args, config=config)  # type: ignore[arg-type]
                results.append(ToolMessage(
                    content=str(output),
                       tool_call_id=tool_id,
                       name=tool_name
                ))
            except Exception as e:
                # Generate request ID for log correlation
                import uuid
                request_id = str(uuid.uuid4())[:8]
                
                # Log detailed error for operators (never exposed to LLM)
                logger.warning(
                    f"[{request_id}] Tool '{tool_name}' authorization failed: {e}"
                )
                
                # Return opaque error to LLM (prevents constraint probing)
                results.append(ToolMessage(
                    content=f"Authorization denied (ref: {request_id})",
                        tool_call_id=tool_id,
                        status="error"
                ))
                
        return {"messages": results}

    def __call__(
        self,
        input: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute as callable."""
        return self._run_with_auth(input, config=config, **kwargs)
         
    def invoke(
        self,
        input: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute via invoke()."""
        return self._run_with_auth(input, config=config, **kwargs)


__all__ = [
    # Key loading
    "load_tenuo_keys",
    # Wrappers
    "guard",
    "tenuo_node",
    "require_warrant",
    # ToolNode
    "TenuoToolNode",
    # Flags
    "LANGGRAPH_AVAILABLE",
]
