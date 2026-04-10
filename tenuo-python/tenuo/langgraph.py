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

from ._enforcement import enforce_tool_call, enforce_tool_call_async, filter_tools_by_warrant
from .bound_warrant import BoundWarrant
from .config import resolve_trusted_roots
from .approval import ApprovalDenied, ApprovalRequired, ApprovalVerificationError
from .exceptions import ApprovalGateTriggered, ConfigurationError
from .keys import KeyRegistry, load_signing_key_from_env

check_langgraph_compat()

# Optional LangGraph imports
try:
    from langchain_core.messages import ToolMessage
    from langchain_core.runnables import RunnableConfig
    from langchain_core.tools import BaseTool
    from langgraph.prebuilt import ToolNode  # type: ignore[import-not-found]

    LANGGRAPH_AVAILABLE = True
except (ImportError, TypeError):
    # TypeError can happen on Python 3.9 with old typing/Pydantic interactions in langchain
    LANGGRAPH_AVAILABLE = False
    ToolNode = object  # type: ignore
    BaseTool = object  # type: ignore
    RunnableConfig = dict  # type: ignore

# wrap_tool_call / awrap_tool_call were added in LangGraph 0.3+ (requires Python 3.10+).
# On Python 3.9, uv/pip resolves to LangGraph 0.2.x which lacks this API.
# TenuoToolNode requires this hook to enforce authorization; construction raises RuntimeError
# when unsupported. This flag lets callers and tests detect support ahead of time.
if LANGGRAPH_AVAILABLE:
    import inspect as _inspect
    WRAP_TOOL_CALL_SUPPORTED = "wrap_tool_call" in _inspect.signature(ToolNode.__init__).parameters
    del _inspect
else:
    WRAP_TOOL_CALL_SUPPORTED = False

# Optional middleware imports (langchain 1.0+)
try:
    from langchain.agents.middleware import (  # type: ignore[import-not-found]
        AgentMiddleware,
        ModelRequest,
        ModelResponse,
    )
    from langchain.tools.tool_node import ToolCallRequest  # type: ignore[import-not-found]

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
        trusted_roots: Optional[List[Any]] = None,
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
            trusted_roots: List of trusted issuer public keys (tenuo_core.PublicKey).
                Warrant issuers are verified against these roots via
                Authorizer.authorize_one() — closes the self-signed trust gap.
                Always supply in production. Emits SecurityWarning when omitted.
            approval_handler: Handler for warrant approval gates (e.g. ``cli_prompt``)
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
        self._trusted_roots = trusted_roots
        self._approval_handler = approval_handler
        self._approvals = approvals
        if control_plane is None:
            from .control_plane import get_or_create
            control_plane = get_or_create()
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
            # Fail closed: if warrant/filter resolution fails, show no tools to
            # the model so it cannot attempt any tool call.  The subsequent
            # wrap_tool_call will surface the auth error with a proper message.
            logger.warning(f"Tool filtering failed, hiding all tools from model: {e}")
            if hasattr(request, "tools") and request.tools:
                return handler(request.override(tools=[]))

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
            logger.warning(f"Tool filtering failed, hiding all tools from model: {e}")
            if hasattr(request, "tools") and request.tools:
                return await handler(request.override(tools=[]))

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

        request_id = str(uuid.uuid4())
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
                trusted_roots=resolve_trusted_roots(self._trusted_roots),
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    result, chain_result=result.chain_result,
                    latency_us=latency_us, request_id=request_id,
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

        except (ApprovalGateTriggered, ApprovalRequired) as gate:
            if self._control_plane:
                from ._enforcement import EnforcementResult
                gate_result = EnforcementResult(
                    allowed=False,
                    tool=tool_name,
                    arguments=tool_args,
                    denial_reason=str(gate),
                    error_type="approval_required",
                )
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    gate_result, latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )
            raise
        except (ApprovalDenied, ApprovalVerificationError) as e:
            logger.warning(f"[{request_id}] Approval verification failed for '{tool_name}': {e}")
            raise
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

        request_id = str(uuid.uuid4())
        tool_call = request.tool_call
        tool_name = tool_call.get("name", "unknown")
        tool_args = tool_call.get("args", {})

        try:
            bw = self._get_bound_warrant_from_request(request.state, request.runtime)

            start_ns = time.perf_counter_ns()

            result = await enforce_tool_call_async(
                tool_name=tool_name,
                tool_args=tool_args,
                bound_warrant=bw,
                require_constraints=self._require_constraints,
                trusted_roots=resolve_trusted_roots(self._trusted_roots),
                approval_handler=self._approval_handler,
                approvals=self._approvals,
            )

            if self._control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    result, chain_result=result.chain_result,
                    latency_us=latency_us, request_id=request_id,
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

        except (ApprovalGateTriggered, ApprovalRequired) as gate:
            if self._control_plane:
                from ._enforcement import EnforcementResult
                gate_result = EnforcementResult(
                    allowed=False,
                    tool=tool_name,
                    arguments=tool_args,
                    denial_reason=str(gate),
                    error_type="approval_required",
                )
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                self._control_plane.emit_for_enforcement(
                    gate_result, latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )
            raise
        except (ApprovalDenied, ApprovalVerificationError) as e:
            logger.warning(f"[{request_id}] Approval verification failed for '{tool_name}': {e}")
            raise
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
        _MAX_WARRANT_B64 = 64 * 1024
        if len(warrant) > _MAX_WARRANT_B64:
            raise ConfigurationError(
                f"Warrant string is {len(warrant)} bytes, exceeding the "
                f"{_MAX_WARRANT_B64} byte safety limit. Possible corruption or attack."
            )
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
    trusted_roots: Optional[List[Any]] = None,
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
                result = enforce_tool_call(tool_name=tool_name, tool_args={}, bound_warrant=bw, trusted_roots=trusted_roots)
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
    A drop-in replacement for LangGraph's ToolNode with Tenuo authorization.

    Authorization is wired through ToolNode's own ``wrap_tool_call`` /
    ``awrap_tool_call`` hook parameters, so the parent handles all execution
    details — streaming, parallel dispatch, error handling, state injection,
    ``Command`` routing — without any reimplementation.

    Usage::

        from tenuo.langgraph import TenuoToolNode, load_tenuo_keys

        load_tenuo_keys()  # reads TENUO_KEY_* env vars

        tool_node = TenuoToolNode([search_tool, write_tool])
        graph.add_node("tools", tool_node)
        graph.invoke(state, config={"configurable": {"tenuo_key_id": "worker"}})

    Multi-agent pattern::

        researcher_node = TenuoToolNode([search_tool])
        executor_node   = TenuoToolNode([write_tool])
        # Each node enforces the warrant currently in state independently.
    """

    def __init__(
        self,
        tools: List[BaseTool],
        *,
        require_constraints: bool = False,
        trusted_roots: Optional[List[Any]] = None,
        approval_handler: Optional[Any] = None,
        approvals: Optional[Any] = None,
        control_plane: Optional[Any] = None,
        key_id: Optional[str] = None,
        **kwargs: Any,
    ):
        if not LANGGRAPH_AVAILABLE:
            raise ImportError(
                "LangGraph is required for TenuoToolNode. "
                "Install with: uv pip install langgraph"
            )

        # Capture auth config in closure so the wrappers are self-contained.
        _require_constraints = require_constraints
        _trusted_roots = trusted_roots
        _approval_handler = approval_handler
        _approvals = approvals
        _control_plane = control_plane
        _key_id = key_id

        def _make_bound_warrant(request: Any) -> Any:
            """Extract BoundWarrant from the tool call request."""
            state = request.state
            state_dict = state if isinstance(state, dict) else vars(state)
            config = getattr(request.runtime, "config", None)
            return _get_bound_warrant(state_dict, config, key_id=_key_id)

        def _auth_wrap(request: Any, handler: Callable[..., Any]) -> Any:
            """Sync authorization wrapper passed to ToolNode."""
            import time

            request_id = str(uuid.uuid4())
            tool_call = request.tool_call
            tool_name = tool_call.get("name", "unknown")
            tool_args = tool_call.get("args", {})

            try:
                bw = _make_bound_warrant(request)
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to get BoundWarrant: {e}")
                return ToolMessage(
                    content=f"Security configuration error (ref: {request_id})",
                    tool_call_id=tool_call.get("id", "unknown"),
                    status="error",
                )

            start_ns = time.perf_counter_ns()
            try:
                result = enforce_tool_call(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    bound_warrant=bw,
                    require_constraints=_require_constraints,
                    trusted_roots=_trusted_roots,
                    approval_handler=_approval_handler,
                    approvals=_approvals,
                )
            except (ApprovalGateTriggered, ApprovalRequired, ApprovalDenied, ApprovalVerificationError):
                raise

            if _control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                _control_plane.emit_for_enforcement(
                    result, chain_result=result.chain_result,
                    latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )

            if not result.allowed:
                logger.warning(f"[{request_id}] Tool '{tool_name}' denied: {result.denial_reason}")
                return ToolMessage(
                    content=f"Authorization denied (ref: {request_id})",
                    tool_call_id=tool_call.get("id", "unknown"),
                    status="error",
                )

            logger.debug(f"[{request_id}] Tool '{tool_name}' authorized")
            return handler(request)

        async def _auth_awrap(request: Any, handler: Callable[..., Any]) -> Any:
            """Async authorization wrapper passed to ToolNode."""
            import time

            request_id = str(uuid.uuid4())
            tool_call = request.tool_call
            tool_name = tool_call.get("name", "unknown")
            tool_args = tool_call.get("args", {})

            try:
                bw = _make_bound_warrant(request)
            except Exception as e:
                logger.warning(f"[{request_id}] Failed to get BoundWarrant: {e}")
                return ToolMessage(
                    content=f"Security configuration error (ref: {request_id})",
                    tool_call_id=tool_call.get("id", "unknown"),
                    status="error",
                )

            start_ns = time.perf_counter_ns()
            try:
                result = await enforce_tool_call_async(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    bound_warrant=bw,
                    require_constraints=_require_constraints,
                    trusted_roots=_trusted_roots,
                    approval_handler=_approval_handler,
                    approvals=_approvals,
                )
            except (ApprovalGateTriggered, ApprovalRequired, ApprovalDenied, ApprovalVerificationError):
                raise

            if _control_plane:
                latency_us = (time.perf_counter_ns() - start_ns) // 1000
                _control_plane.emit_for_enforcement(
                    result, chain_result=result.chain_result,
                    latency_us=latency_us, request_id=request_id,
                    warrant_stack_override=_warrant_stack_from_bound(bw),
                )

            if not result.allowed:
                logger.warning(f"[{request_id}] Tool '{tool_name}' denied: {result.denial_reason}")
                return ToolMessage(
                    content=f"Authorization denied (ref: {request_id})",
                    tool_call_id=tool_call.get("id", "unknown"),
                    status="error",
                )

            logger.debug(f"[{request_id}] Tool '{tool_name}' authorized")
            return await handler(request)

        try:
            super().__init__(
                tools,
                wrap_tool_call=_auth_wrap,
                awrap_tool_call=_auth_awrap,
                **kwargs,
            )
            self._tenuo_hooks_active = True
        except TypeError as exc:
            raise RuntimeError(
                "TenuoToolNode requires LangGraph >= 0.2.35 (wrap_tool_call support). "
                "Authorization enforcement cannot be applied on this version. "
                "Upgrade langgraph or use TenuoMiddleware instead."
            ) from exc
        # Store for test introspection / approval param checks
        self._require_constraints = require_constraints
        self._approval_handler = approval_handler
        self._approvals = approvals
        if control_plane is None:
            from .control_plane import get_or_create
            control_plane = get_or_create()
        self._control_plane = control_plane
        self._key_id = key_id


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
