"""
Tenuo LangGraph Integration

Provides the tenuo_node decorator for scoping authority in LangGraph nodes.

Usage:
    from tenuo.langgraph import tenuo_node
    
    @tenuo_node(tools=["search"], query="*")
    async def researcher(state):
        # Automatically scoped to search tool with query constraint
        return await search_tool.invoke(state["query"])
    
    graph.add_node("researcher", researcher)

For the full SecureGraph with automatic attenuation, see the design spec
in docs/langgraph-spec.md.
"""

import asyncio
from functools import wraps
from typing import Any, Callable, List, Optional, TypeVar

from .scoped import scoped_task
from .decorators import get_warrant_context

# Type variable for node functions
F = TypeVar('F', bound=Callable)


def tenuo_node(
    *,
    tools: Optional[List[str]] = None,
    ttl: Optional[int] = None,
    **constraints: Any,
) -> Callable[[F], F]:
    """
    Decorator to scope authority for a LangGraph node.
    
    This decorator wraps a node function with scoped_task(), automatically
    narrowing the warrant scope for the duration of the node execution.
    
    Args:
        tools: List of tools this node is allowed to use
        ttl: Optional TTL override for the scoped warrant
        **constraints: Constraint key-value pairs
    
    Returns:
        Decorated function with automatic scope narrowing
    
    Example:
        @tenuo_node(tools=["search", "read_file"], path="/data/*")
        async def researcher(state):
            # Only search and read_file are allowed here
            # path must match /data/*
            results = await search_tool.invoke(state["query"])
            return {"results": results}
        
        graph.add_node("researcher", researcher)
    
    Note:
        The decorator requires a parent warrant in context. Use root_task()
        before invoking the graph:
        
        with root_task_sync(tools=["search", "read_file", "write_file"]):
            result = graph.invoke({"query": "Q3 reports"})
    
    Important:
        - If the decorated function is async, use it in async context
        - If the decorated function is sync, use it in sync context
        - Do NOT mix async functions with sync invocation or vice versa
    """
    def decorator(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):
            # Async function → async wrapper (strict)
            @wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                async with scoped_task(tools=tools, ttl=ttl, **constraints):
                    return await fn(*args, **kwargs)
            return async_wrapper  # type: ignore
        else:
            # Sync function → sync wrapper (strict)
            @wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                with scoped_task(tools=tools, ttl=ttl, **constraints):
                    return fn(*args, **kwargs)
            return sync_wrapper  # type: ignore
    
    return decorator


def require_warrant(fn: F) -> F:
    """
    Decorator to require a warrant in context before executing.
    
    Use this for nodes that should only run with authorization,
    but don't need to narrow scope.
    
    Example:
        @require_warrant
        async def sensitive_node(state):
            # Only runs if warrant is in context
            ...
    
    Important:
        - If the decorated function is async, use it in async context
        - If the decorated function is sync, use it in sync context
    """
    if asyncio.iscoroutinefunction(fn):
        @wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            warrant = get_warrant_context()
            if warrant is None:
                from .exceptions import ScopeViolation
                raise ScopeViolation(
                    "Node requires warrant in context. "
                    "Use root_task() before invoking the graph."
                )
            return await fn(*args, **kwargs)
        return async_wrapper  # type: ignore
    else:
        @wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            warrant = get_warrant_context()
            if warrant is None:
                from .exceptions import ScopeViolation
                raise ScopeViolation(
                    "Node requires warrant in context. "
                    "Use root_task() before invoking the graph."
                )
            return fn(*args, **kwargs)
        return sync_wrapper  # type: ignore


# =============================================================================
# DX: TenuoToolNode - Drop-in ToolNode replacement
# =============================================================================

# Try to import ToolNode from langgraph
try:
    from langgraph.prebuilt import ToolNode  # type: ignore[import-not-found]
    LANGGRAPH_TOOLNODE_AVAILABLE = True
except ImportError:
    ToolNode = object  # type: ignore[assignment]
    LANGGRAPH_TOOLNODE_AVAILABLE = False


class TenuoToolNode:
    """
    Drop-in replacement for LangGraph's ToolNode with automatic Tenuo protection.
    
    This is the recommended way to use tools in LangGraph with Tenuo.
    It automatically wraps tools with authorization checks.
    
    Example:
        from tenuo.langgraph import TenuoToolNode
        from tenuo import root_task_sync
        
        # Before (manual protection):
        # tools = [search, calculator]
        # protected = protect_langchain_tools(tools)
        # tool_node = ToolNode(protected)
        
        # After (automatic protection):
        tool_node = TenuoToolNode([search, calculator])
        
        # Build graph as normal
        graph.add_node("tools", tool_node)
        
        # Run with authorization
        with root_task_sync(tools=["search", "calculator"]):
            result = graph.invoke(...)
    
    Args:
        tools: List of LangChain BaseTool objects
        strict: If True, require constraints for high-risk tools
        **kwargs: Additional arguments passed to ToolNode
    
    Raises:
        ImportError: If langgraph is not installed
    """
    
    def __init__(
        self,
        tools: list,
        *,
        strict: bool = False,
        **kwargs: Any,
    ):
        if not LANGGRAPH_TOOLNODE_AVAILABLE:
            raise ImportError(
                "LangGraph is required for TenuoToolNode. "
                "Install with: pip install langgraph"
            )
        
        # Import and wrap tools
        from .langchain import protect_langchain_tools, LANGCHAIN_AVAILABLE
        if not LANGCHAIN_AVAILABLE:
            raise ImportError(
                "LangChain is required for TenuoToolNode. "
                "Install with: pip install langchain-core"
            )
        
        # Wrap tools with Tenuo protection
        protected_tools = protect_langchain_tools(tools, strict=strict)
        
        # Create the underlying ToolNode
        self._tool_node = ToolNode(protected_tools, **kwargs)
        
        # Store for introspection
        self._tools = tools
        self._protected_tools = protected_tools
        self._strict = strict
    
    def __call__(self, state: Any, config: Any = None) -> Any:
        """Execute the tool node (delegates to underlying ToolNode)."""
        if config is not None:
            return self._tool_node(state, config)
        return self._tool_node(state)
    
    async def __acall__(self, state: Any, config: Any = None) -> Any:
        """Async execution (delegates to underlying ToolNode)."""
        if hasattr(self._tool_node, '__acall__'):
            if config is not None:
                return await self._tool_node.__acall__(state, config)
            return await self._tool_node.__acall__(state)
        # Fallback to sync
        return self(state, config)
    
    @property
    def tools(self) -> list:
        """Get the protected tools."""
        return self._protected_tools
    
    @property
    def original_tools(self) -> list:
        """Get the original unprotected tools."""
        return self._tools


__all__ = [
    "tenuo_node",
    "require_warrant",
    # DX: Drop-in ToolNode replacement
    "TenuoToolNode",
    "LANGGRAPH_TOOLNODE_AVAILABLE",
]
