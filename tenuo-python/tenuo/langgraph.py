"""
Tenuo LangGraph Integration

This module provides middleware for securing LangGraph agents with Tenuo.
It solves the key management problem by keeping private keys out of graph state.

Recommended Pattern (Middleware):
    Use TenuoMiddleware with LangGraph's create_agent() for the cleanest integration.
    The middleware intercepts tool calls and enforces authorization automatically.

    from langchain.agents import create_agent
    from tenuo import SigningKey
    from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

    # Auto-load keys from TENUO_KEY_* env vars
    load_tenuo_keys()

    # Create middleware - handles all authorization
    tenuo = TenuoMiddleware()

    # Build agent with middleware
    agent = create_agent(
        model="gpt-4.1",
        tools=[search_tool, file_tool],
        middleware=[tenuo],
    )

    # Invoke with warrant in state
    result = agent.invoke({
        "messages": [HumanMessage("search for AI papers")],
        "warrant": root_warrant,  # Or warrant.to_base64() for serialization
    })

Security Model (Local vs Remote PEP):
    This middleware acts as a **Local Policy Enforcement Point (PEP)**. It protects
    the agent from unauthorized tool usage *before* execution.

    However, for complete security (Defense-in-Depth), the tools themselves
    (or the APIs they call) must also verify authorization. Use `bound_warrant.token`
    to pass the signed warrant to remote services.

Alternative Patterns:
    TenuoToolNode  - Drop-in replacement for ToolNode (legacy graphs)
    guard_node()   - Wrapper for custom node functions
    @tenuo_node    - Decorator for explicit BoundWarrant access

See docs: https://tenuo.dev/langgraph
"""

from typing import Any, Callable, Dict, List, Optional, Union, TypeVar
from functools import wraps
import logging
import os
import uuid

from .exceptions import ConfigurationError
from .bound_warrant import BoundWarrant
from .keys import KeyRegistry, load_signing_key_from_env
from ._enforcement import enforce_tool_call, filter_tools_by_warrant
from tenuo_core import Warrant

# Check version compatibility on import (warns, doesn't fail)
from tenuo._version_compat import check_langgraph_compat  # noqa: E402

check_langgraph_compat()

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

# Optional middleware imports (langchain 1.0+)
try:
    from langchain.agents.middleware import (  # type: ignore
        AgentMiddleware,
        ModelRequest,
        ModelResponse,
    )
    from langchain.tools.tool_node import ToolCallRequest  # type: ignore

    MIDDLEWARE_AVAILABLE = True
except ImportError:
    MIDDLEWARE_AVAILABLE = False
    AgentMiddleware = object  # type: ignore
    ModelRequest = object  # type: ignore
    ModelResponse = object  # type: ignore
    ToolCallRequest = object  # type: ignore

logger = logging.getLogger("tenuo.langgraph")

F = TypeVar("F", bound=Callable)


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
            key_id = name[len(prefix) :].lower().replace("_", "-")
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
# TenuoMiddleware - Primary Integration (LangChain 1.0+)
# =============================================================================


class TenuoMiddleware(AgentMiddleware if MIDDLEWARE_AVAILABLE else object):  # type: ignore
    """
    Middleware for securing LangGraph agents with Tenuo authorization.

    This is the recommended way to integrate Tenuo with LangGraph. The middleware
    intercepts all tool calls and model requests, enforcing authorization based
    on the warrant in state.

    Features:
        - Automatic tool call authorization with PoP signing
        - Optional tool filtering (only show authorized tools to the LLM)
        - Opaque error messages (prevents constraint probing)
        - Audit logging for compliance

    Usage:
        from langchain.agents import create_agent
        from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

        load_tenuo_keys()  # Auto-load TENUO_KEY_* env vars

        agent = create_agent(
            model="gpt-4.1",
            tools=[search_tool, file_tool],
            middleware=[TenuoMiddleware()],
        )

        # Invoke with warrant in state
        result = agent.invoke({
            "messages": [HumanMessage("search for AI papers")],
            "warrant": root_warrant,
        })

    Configuration:
        key_id: Which signing key to use (default: from config or "default")
        filter_tools: If True, only show authorized tools to LLM (default: True)
        require_constraints: Require constraints for sensitive tools (default: False)
    """

    def __init__(
        self,
        *,
        key_id: Optional[str] = None,
        filter_tools: bool = True,
        require_constraints: bool = False,
        debug: bool = False,
    ):
        """
        Initialize TenuoMiddleware.

        Args:
            key_id: Explicit key_id to use (overrides config["tenuo_key_id"])
            filter_tools: Filter tools presented to LLM based on warrant
            require_constraints: Require constraints for sensitive tools
            debug: If True, returns detailed error messages to the LLM (DEV ONLY)
        """
        if not MIDDLEWARE_AVAILABLE:
            raise ImportError(
                "LangChain middleware requires langchain>=1.0. "
                "Install with: uv pip install 'langchain>=1.0'"
            )
        super().__init__()
        self._key_id = key_id
        self._filter_tools = filter_tools
        self._require_constraints = require_constraints
        self._debug = debug

    def _get_bound_warrant_from_request(
        self,
        state: Any,
        runtime: Any,
    ) -> BoundWarrant:
        """Extract and bind warrant from agent state."""
        # Use runtime.config for key_id if available
        config = getattr(runtime, "config", None) or {}
        return _get_bound_warrant(state, config, key_id=self._key_id)

    def wrap_model_call(
        self,
        request: "ModelRequest",
        handler: Callable[["ModelRequest"], "ModelResponse"],
    ) -> "ModelResponse":
        """
        Filter tools presented to the LLM based on warrant.

        This prevents the LLM from even attempting unauthorized tool calls,
        improving accuracy and reducing friction.
        """
        if not self._filter_tools:
            return handler(request)

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            # Filter tools to only those allowed by warrant
            if hasattr(request, "tools") and request.tools:
                filtered = filter_tools_by_warrant(
                    list(request.tools),
                    bw,
                    get_name=lambda t: getattr(t, "name", str(t)),
                )
                return handler(request.override(tools=filtered))

        except Exception as e:
            # Log but don't fail - let tool call handle auth
            logger.debug(f"Tool filtering skipped: {e}")

        return handler(request)

    def wrap_tool_call(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """
        Authorize each tool call against the warrant.

        Returns opaque error messages to prevent constraint probing attacks.
        """
        request_id = str(uuid.uuid4())[:8]
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            # Use shared enforcement logic
            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
            )

            if not result.allowed:
                # Log detailed reason for operators
                logger.warning(
                    f"[{request_id}] Tool '{tool_name}' denied: {result.denial_reason}"
                )

                # In debug mode, tell the LLM exactly why
                error_msg = (
                    f"Authorization denied: {result.denial_reason}"
                    if self._debug
                    else f"Authorization denied (ref: {request_id})"
                )

                return ToolMessage(
                    content=error_msg,
                    tool_call_id=tool_call.get("id", "unknown"),
                    status="error",
                )

            # Tool authorized - proceed with execution
            logger.debug(f"[{request_id}] Tool '{tool_name}' authorized")
            return handler(request)

        except ConfigurationError as e:
            logger.warning(f"[{request_id}] Configuration error: {e}")

            error_msg = (
                f"Configuration error: {e}"
                if self._debug
                else f"Security configuration error (ref: {request_id})"
            )

            return ToolMessage(
                content=error_msg,
                tool_call_id=tool_call.get("id", "unknown"),
                status="error",
            )
        except Exception as e:
            logger.error(f"[{request_id}] Unexpected error in authorization: {e}")

            error_msg = (
                f"Unexpected error: {e}"
                if self._debug
                else f"Authorization error (ref: {request_id})"
            )

            return ToolMessage(
                content=error_msg,
                tool_call_id=tool_call.get("id", "unknown"),
                status="error",
            )


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
            "State is missing 'warrant' field. Ensure your State TypedDict includes 'warrant: Warrant'."
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
    elif hasattr(warrant, "bind"):
        return warrant.bind(key)

    raise ConfigurationError(f"Invalid warrant type in state: {type(warrant)}")


# =============================================================================
# guard_node() - Wrapper for Pure Nodes
# =============================================================================


def guard_node(
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
        graph.add_node("agent", guard_node(my_agent))
        graph.add_node("worker", guard_node(worker_node, key_id="worker"))
    """

    @wraps(node)
    def wrapper(
        state: Union[Dict[str, Any], Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        if config is None and "config" in kwargs:
            config = kwargs["config"]

        state_dict = state if isinstance(state, dict) else vars(state)

        try:
            bw = _get_bound_warrant(state_dict, config, key_id=key_id)
        except Exception as e:
            raise ConfigurationError(f"Authorization failed in node '{node.__name__}': {e}") from e

        if inject_warrant:
            kwargs["bound_warrant"] = bw

        # For now, we just validate the warrant exists and is bound
        # The actual tool authorization happens in TenuoTool or guard()
        # This wrapper primarily ensures the key binding works

        # Check if wrapped function accepts config parameter
        import inspect

        sig = inspect.signature(node)
        accepts_config = "config" in sig.parameters or any(
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
            raise ConfigurationError(f"Failed to bind warrant in node '{func.__name__}': {e}") from e

        kwargs["bound_warrant"] = bw

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

    **Note**: For new projects, prefer TenuoMiddleware with create_agent().
    TenuoToolNode is provided for compatibility with existing graphs that
    use the ToolNode pattern.

    Drop-in replacement for LangGraph's ToolNode with automatic Tenuo protection.

    Usage:
        from tenuo.langgraph import TenuoToolNode

        tools = [search, calculator]
        tool_node = TenuoToolNode(tools)

        graph.add_node("tools", tool_node)

        # Invoke with key_id in config
        graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})
    """

    def __init__(
        self,
        tools: List[BaseTool],
        *,
        require_constraints: bool = False,
        **kwargs: Any,
    ):
        """
        Initialize TenuoToolNode.

        Args:
            tools: List of tools to make available
            require_constraints: Require constraints for sensitive tools
        """
        if not LANGGRAPH_AVAILABLE:
            raise ImportError(
                "LangGraph is required for TenuoToolNode. "
                "Install with: uv pip install langgraph"
            )
        super().__init__(tools, **kwargs)
        self._require_constraints = require_constraints

    def _run_with_auth(
        self,
        input: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute tools with authorization from state warrant."""
        # Get BoundWarrant from state + config
        try:
            bw = _get_bound_warrant(input, config)
        except Exception as e:
            request_id = str(uuid.uuid4())[:8]
            logger.warning(f"[{request_id}] Failed to get BoundWarrant: {e}")
            return {
                "messages": [
                    ToolMessage(
                        content=f"Security configuration error (ref: {request_id})",
                        tool_call_id="unknown",
                        status="error",
                    )
                ]
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

            if tool_name not in self.tools_by_name:
                results.append(
                    ToolMessage(
                        content=f"Error: Tool '{tool_name}' not found.",
                        tool_call_id=tool_id,
                        status="error",
                    )
                )
                continue

            # Use shared enforcement logic
            request_id = str(uuid.uuid4())[:8]
            enforcement_result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
            )

            if not enforcement_result.allowed:
                # Log detailed reason for operators
                logger.warning(
                    f"[{request_id}] Tool '{tool_name}' denied: "
                    f"{enforcement_result.denial_reason}"
                )
                # Return opaque error to LLM
                results.append(
                    ToolMessage(
                        content=f"Authorization denied (ref: {request_id})",
                        tool_call_id=tool_id,
                        status="error",
                    )
                )
                continue

            # Tool authorized - execute it
            tool = self.tools_by_name[tool_name]
            try:
                output = tool.invoke(tool_args, config=config)
                results.append(
                    ToolMessage(
                        content=str(output),
                        tool_call_id=tool_id,
                        name=tool_name,
                    )
                )
            except Exception as e:
                logger.warning(f"[{request_id}] Tool '{tool_name}' execution failed: {e}")
                results.append(
                    ToolMessage(
                        content=f"Tool execution error (ref: {request_id})",
                        tool_call_id=tool_id,
                        status="error",
                    )
                )

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
    # Primary API (Middleware)
    "TenuoMiddleware",
    # Key loading
    "load_tenuo_keys",
    # Node wrappers (alternative patterns)
    "guard_node",
    "tenuo_node",
    "require_warrant",
    # Legacy ToolNode (for existing graphs)
    "TenuoToolNode",
    # Flags
    "LANGGRAPH_AVAILABLE",
    "MIDDLEWARE_AVAILABLE",
]
