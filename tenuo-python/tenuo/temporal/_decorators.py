"""Decorators and tool-name resolution for Tenuo-Temporal activities."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar

if TYPE_CHECKING:
    from tenuo.temporal._config import TenuoPluginConfig

F = TypeVar("F", bound=Callable[..., Any])


def unprotected(func: F) -> F:
    """Mark an activity as unprotected - safe for local execution.

    Protected activities (default) require Tenuo authorization and
    cannot be used as local activities because local activities bypass
    worker interceptors.

    Use this decorator when:
    - The activity only accesses internal/trusted resources
    - The activity doesn't need per-invocation authorization
    - You want to run the activity as a local activity

    Example:
        @activity.defn
        @unprotected
        async def get_config_value(key: str) -> str:
            '''Internal config lookup - no Tenuo needed.'''
            return config[key]

        # Can now be called as local activity:
        await workflow.execute_local_activity(
            get_config_value,
            args=["database_url"],
            ...
        )
    """
    func._tenuo_unprotected = True  # type: ignore
    return func


def is_unprotected(func: Any) -> bool:
    """Check if an activity is marked as unprotected."""
    return getattr(func, "_tenuo_unprotected", False)


def tool(name: str) -> Callable[[F], F]:
    """Map an activity to a specific Tenuo tool name.

    By default, activities are authorized using their function name
    as the tool name. Use this decorator when the activity name
    differs from the warrant tool name.

    Args:
        name: The tool name in the warrant (e.g., "read_file")

    Example:
        @activity.defn
        @tool("read_file")
        async def fetch_document(doc_id: str) -> str:
            '''Fetches document - authorized via 'read_file' capability.'''
            return await storage.get(doc_id)

        # Warrant needs: capability("read_file", {...})
        # Activity is called: fetch_document(doc_id)
    """

    def decorator(func: F) -> F:
        func._tenuo_tool_name = name  # type: ignore
        return func

    return decorator


def get_tool_name(func: Any, default: str) -> str:
    """Get the Tenuo tool name for an activity.

    Returns the @tool() name if set, otherwise the default.
    """
    return getattr(func, "_tenuo_tool_name", default)


def _warrant_tool_name_for_activity_type(
    config_or_input: Any,
    activity_type_or_config: Any = None,
    activity_fn: Optional[Any] = None,
) -> str:
    """Map Temporal activity type to warrant / PoP tool name (inbound + outbound must agree).

    Accepts two call signatures:
      - Legacy: (config, activity_type: str, activity_fn)
      - Input-based: (input, config) where input.fn may be None (dynamic activity)
        and input.activity holds the runtime activity-type string.
    """
    # Detect input-based call: first arg has an 'activity' attribute (not a config or str)
    if hasattr(config_or_input, "activity") and not isinstance(config_or_input, str):
        # input-based call: (input, config)
        _input = config_or_input
        config: Optional["TenuoPluginConfig"] = activity_type_or_config
        activity_type: str = getattr(_input, "activity", None) or ""
        activity_fn = getattr(_input, "fn", None)
    else:
        # legacy call: (config, activity_type, activity_fn)
        config = config_or_input
        activity_type = activity_type_or_config or ""

    default_tool = activity_type
    if activity_fn is not None:
        resolved = get_tool_name(activity_fn, activity_type)
        if resolved:
            default_tool = resolved

    if config is None:
        return default_tool
    return config.tool_mappings.get(activity_type, default_tool)
