"""
Decorator-based tool protection for Google ADK.

Provides syntactic sugar for attaching constraints to tool functions.

⚠️  IMPORTANT: Decorators are best for simple, static scenarios.
    For production systems with dynamic authorization or Tier 2 (warrants),
    use GuardBuilder directly. See tenuo/google_adk/guard.py.

Usage:
    from tenuo.google_adk import guard_tool, GuardBuilder
    from tenuo.constraints import Subpath, Pattern

    @guard_tool(path=Subpath("/data"))
    def read_file(path: str) -> str:
        with open(path) as f:
            return f.read()

    @guard_tool(query=Pattern("*"))
    def web_search(query: str) -> str:
        return search_api(query)

    # Extract constraints from decorated tools
    guard = GuardBuilder.from_tools([read_file, web_search]).build()

    agent = Agent(
        tools=[read_file, web_search],
        before_tool_callback=guard.before_tool,
    )
"""

from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


def guard_tool(**constraints) -> Callable[[F], F]:
    """
    Attach Tenuo constraints to a tool function.

    This decorator stores constraint metadata on the function object,
    which can later be extracted by GuardBuilder.from_tools().

    Args:
        **constraints: Constraint objects for each parameter.
                      Use _allow_unknown=True to opt out of Zero Trust.

    Returns:
        Decorated function with __tenuo_constraints__ metadata.

    Example:
        @guard_tool(path=Subpath("/data"), _allow_unknown=False)
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()

    Warning:
        - Decorators are static. Use GuardBuilder for dynamic authorization.
        - Not suitable for Tier 2 (warrants). Use .with_warrant() instead.
        - Can't be used on third-party functions you don't control.
    """

    def decorator(func: F) -> F:
        # Store constraints as metadata on the function
        if not hasattr(func, "__tenuo_constraints__"):
            setattr(func, "__tenuo_constraints__", {})
        getattr(func, "__tenuo_constraints__").update(constraints)

        # Mark as Tenuo-protected for introspection
        setattr(func, "__tenuo_protected__", True)

        return func

    return decorator


def extract_constraints(tool: Callable) -> dict:
    """
    Extract Tenuo constraints from a decorated tool function.

    Args:
        tool: Function to extract constraints from.

    Returns:
        Dict of constraints, or empty dict if tool is not decorated.

    Example:
        constraints = extract_constraints(read_file)
        # {"path": Subpath("/data")}
    """
    return getattr(tool, "__tenuo_constraints__", {})


def is_guarded(tool: Callable) -> bool:
    """
    Check if a tool has Tenuo constraints attached.

    Args:
        tool: Function to check.

    Returns:
        True if tool has @guard_tool decorator, False otherwise.

    Example:
        if is_guarded(read_file):
            print("Tool has constraints")
    """
    return getattr(tool, "__tenuo_protected__", False)
