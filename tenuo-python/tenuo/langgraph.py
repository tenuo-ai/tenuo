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


__all__ = [
    "tenuo_node",
    "require_warrant",
]
