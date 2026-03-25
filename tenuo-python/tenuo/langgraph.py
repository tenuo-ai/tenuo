"""
Tenuo LangGraph Integration

This module provides middleware for securing LangGraph agents with Tenuo.
It solves the key management problem by keeping private keys out of graph state.

Production Pattern (TenuoToolNode):
    Use TenuoToolNode as a drop-in replacement for LangGraph's ToolNode.
    This is the stable, recommended path for production graphs — including
    multi-agent supervisor patterns.

    from tenuo.langgraph import TenuoToolNode, guard_node, load_tenuo_keys

    load_tenuo_keys()  # reads TENUO_KEY_* env vars into KeyRegistry

    # Supervisor node validates warrant covers the tools it will dispatch to
    def supervisor(state: State) -> dict:
        ...

    # Tool node enforces per-call authorization (tool name + argument constraints)
    tool_node = TenuoToolNode([search_tool, write_tool])

    graph.add_node("supervisor", guard_node(supervisor, required_tools=["search"]))
    graph.add_node("tools", tool_node)

Multi-Agent Delegation Pattern:
    Each agent holds an *attenuated* copy of the root warrant in graph state.
    Downstream nodes and tool-nodes only see the narrowed capability set.

    # Supervisor attenuates warrant for sub-agent and stores it in state
    @tenuo_node
    def supervisor(state: State, bound_warrant: BoundWarrant) -> dict:
        researcher_warrant = bound_warrant.warrant.attenuate(
            signing_key=supervisor_key,
            holder=researcher_pubkey,
            capabilities={"search": {}, "read": {}},
            ttl_seconds=300,
        )
        return {"warrant": researcher_warrant}

    # Researcher's TenuoToolNode can only call search/read — not write
    researcher_tools = TenuoToolNode([search_tool, read_tool, write_tool])

Experimental Pattern (TenuoMiddleware):
    TenuoMiddleware integrates with the LangChain 1.0+ agent middleware API
    (langchain>=1.2).  It intercepts both model calls (tool filtering) and
    tool calls (authorization).  The middleware API is stable in langchain 1.x
    but is newer than TenuoToolNode — prefer TenuoToolNode if you need maximum
    compatibility across LangChain versions.

    from langchain.agents import create_agent
    from tenuo.langgraph import TenuoMiddleware, load_tenuo_keys

    load_tenuo_keys()

    agent = create_agent(
        model="gpt-4.1",
        tools=[search_tool, file_tool],
        middleware=[TenuoMiddleware()],
    )

    result = agent.invoke({
        "messages": [HumanMessage("search for AI papers")],
        "warrant": root_warrant,
    })

Security Model (Local vs Remote PEP):
    This middleware acts as a **Local Policy Enforcement Point (PEP)**. It protects
    the agent from unauthorized tool usage *before* execution.

    However, for complete security (Defense-in-Depth), the tools themselves
    (or the APIs they call) must also verify authorization. Use `bound_warrant.token`
    to pass the signed warrant to remote services.

See docs: https://tenuo.ai/langgraph
"""

import logging
import os
import uuid
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from tenuo_core import Warrant

# Check version compatibility on import (warns, doesn't fail)
from tenuo._version_compat import check_langgraph_compat  # noqa: E402

from ._enforcement import enforce_tool_call, filter_tools_by_warrant
from .bound_warrant import BoundWarrant
from .exceptions import ConfigurationError
from .keys import KeyRegistry, load_signing_key_from_env

check_langgraph_compat()

# Optional LangGraph imports
try:
    from langchain_core.messages import ToolMessage
    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import ToolNode  # type: ignore

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


def _warrant_stack_from_bound(bw: "BoundWarrant") -> Optional[str]:
    """Encode the bound warrant as a single-element base64 CBOR WarrantStack.

    LangGraph operates on single delegated warrants (no multi-hop chain object
    in Python state), so chain_length=1 and warrant_stack contains just the
    leaf warrant.  This gives the control plane enough context to reconstruct
    the issuer and warrant ID even without a full ChainVerificationResult.
    Returns None on any failure so callers always degrade gracefully.
    """
    try:
        from tenuo_core import encode_warrant_stack
        w = getattr(bw, "warrant", None)
        if w is not None:
            return encode_warrant_stack([w])
    except Exception:
        pass
    return None


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
        approval_policy: Optional[Any] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[Any] = None,
        control_plane: Optional[Any] = None,
    ):
        """
        Initialize TenuoMiddleware.

        Args:
            key_id: Explicit key_id to use (overrides config["tenuo_key_id"])
            filter_tools: Filter tools presented to LLM based on warrant
            require_constraints: Require constraints for sensitive tools
            debug: If True, returns detailed error messages to the LLM (DEV ONLY)
            approval_policy: Optional ApprovalPolicy for human-in-the-loop (Tier 2 only)
            approval_handler: Handler invoked when approval policy triggers
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
        self._approval_policy = approval_policy
        self._approval_handler = approval_handler
        self._approvals = approvals
        self._control_plane = control_plane

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

    async def awrap_model_call(
        self,
        request: "ModelRequest",
        handler: Callable[["ModelRequest"], Any],
    ) -> "ModelResponse":
        """Async version of wrap_model_call — filters tools for async agents."""
        if not self._filter_tools:
            return await handler(request)

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            if hasattr(request, "tools") and request.tools:
                filtered = filter_tools_by_warrant(
                    list(request.tools),
                    bw,
                    get_name=lambda t: getattr(t, "name", str(t)),
                )
                return await handler(request.override(tools=filtered))

        except Exception as e:
            logger.debug(f"Tool filtering skipped: {e}")

        return await handler(request)

    def wrap_tool_call(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """
        Authorize each tool call against the warrant.

        Returns opaque error messages to prevent constraint probing attacks.
        """
        return self._authorize_and_run(request, handler, is_async=False)

    async def awrap_tool_call(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """Async version of wrap_tool_call — authorizes tool calls for async agents."""
        return await self._authorize_and_run_async(request, handler)

    def _authorize_and_run(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
        *,
        is_async: bool = False,
    ) -> Any:
        """Shared authorization logic for sync tool calls."""
        import time

        request_id = str(uuid.uuid4())[:8]
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            start_ns = time.perf_counter_ns()

            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
                approval_policy=self._approval_policy,
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    result, latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )

            if not result.allowed:
                logger.warning(
                    f"[{request_id}] Tool '{tool_name}' denied: {result.denial_reason}"
                )
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

    async def _authorize_and_run_async(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """Shared authorization logic for async tool calls."""
        import time

        request_id = str(uuid.uuid4())[:8]
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            start_ns = time.perf_counter_ns()

            result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
                approval_policy=self._approval_policy,
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    result, latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )

            if not result.allowed:
                logger.warning(
                    f"[{request_id}] Tool '{tool_name}' denied: {result.denial_reason}"
                )
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

            logger.debug(f"[{request_id}] Tool '{tool_name}' authorized")
            return await handler(request)

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
    required_tools: Optional[List[str]] = None,
) -> Callable:
    """
    Wrap a LangGraph node with Tenuo authorization.

    Validates that:
    1. The ``warrant`` field is present in state and can be bound to a key.
    2. If ``required_tools`` is provided, the warrant covers *all* of those
       tools — use this on supervisor nodes to fail fast before any sub-graph
       work begins, rather than discovering a missing capability mid-execution.

    Per-argument constraint enforcement (e.g. checking ``query`` matches a
    pattern) happens at ``TenuoToolNode`` time, not here.  This wrapper is
    the warrant-presence and key-binding check only.

    Args:
        node: The node function (state) -> dict
        key_id: Explicit key_id (default: from config or "default")
        inject_warrant: If True, pass bound_warrant as kwarg to the node
        required_tools: Optional list of tool names the warrant must cover.
            Raises ConfigurationError if the warrant does not grant all of
            them, blocking the node from running at all.

    Returns:
        Wrapped node function

    Example::

        def researcher(state: State) -> dict:
            return {"messages": [...]}

        # Validate warrant covers both tools before the node runs:
        graph.add_node("researcher", guard_node(researcher, required_tools=["search", "read"]))
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

        # Optional: check that the warrant covers all required tools up-front
        # so the node fails fast instead of discovering missing capabilities later.
        if required_tools:
            from ._enforcement import enforce_tool_call
            for tool_name in required_tools:
                result = enforce_tool_call(tool_name=tool_name, tool_args={}, bound_warrant=bw)
                if not result.allowed:
                    raise ConfigurationError(
                        f"Node '{node.__name__}': warrant does not cover required tool "
                        f"'{tool_name}': {result.denial_reason}"
                    )

        if inject_warrant:
            kwargs["bound_warrant"] = bw

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
        approval_policy: Optional[Any] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[Any] = None,
        control_plane: Optional[Any] = None,
        **kwargs: Any,
    ):
        """
        Initialize TenuoToolNode.

        Args:
            tools: List of tools to make available
            require_constraints: Require constraints for sensitive tools
            approval_policy: Optional ApprovalPolicy for human-in-the-loop (Tier 2 only)
            approval_handler: Handler invoked when approval policy triggers
        """
        if not LANGGRAPH_AVAILABLE:
            raise ImportError(
                "LangGraph is required for TenuoToolNode. "
                "Install with: uv pip install langgraph"
            )
        super().__init__(tools, **kwargs)
        self._require_constraints = require_constraints
        self._approval_policy = approval_policy
        self._approval_handler = approval_handler
        self._approvals = approvals
        self._control_plane = control_plane

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
            import time
            start_ns = time.perf_counter_ns()

            enforcement_result = enforce_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
                approval_policy=self._approval_policy,
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    enforcement_result, latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
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
                from tenuo.approval import ApprovalRequired, ApprovalDenied
                if isinstance(e, (ApprovalRequired, ApprovalDenied)):
                    status = "required" if isinstance(e, ApprovalRequired) else "denied"
                    logger.info(f"[{request_id}] Tool '{tool_name}' approval {status}")
                    results.append(
                        ToolMessage(
                            content=f"Approval {status} (ref: {request_id})",
                            tool_call_id=tool_id,
                            status="error",
                        )
                    )
                    continue
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

    async def ainvoke(
        self,
        input: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Execute asynchronously via ainvoke().

        Runs _run_with_auth in a thread-pool executor so blocking tool calls
        don't stall the event loop. LangGraph calls ainvoke() on async graphs.
        """
        import asyncio
        import functools

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(self._run_with_auth, input, config=config, **kwargs),
        )


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
