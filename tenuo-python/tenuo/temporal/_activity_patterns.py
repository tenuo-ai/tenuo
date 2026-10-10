"""Anchored glob matching for activity-name allow/skip patterns.

Backs ``TenuoPluginConfig.unwarranted_activities`` and
``TenuoPluginConfig.mcp_call_tool_activities``. A pattern matches the ENTIRE
activity name — ``*`` stands for any run of characters (including none); no
other glob syntax (``?``, ``[seq]``) is supported, so a pattern never matches
more than its author wrote. Matching is always whole-string, never substring:
the pattern ``"foo"`` matches only the literal name ``"foo"``, never
``"foo-effect"`` or ``"prefix-foo"``. Substring matching on activity names is
exactly how an internal-activity allowlist would accidentally swallow a
same-substring effect activity, so it is not offered.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Sequence, Tuple

_WILDCARD = "*"


def _pattern_to_regex(pattern: str) -> "re.Pattern[str]":
    parts = pattern.split(_WILDCARD)
    escaped = ".*".join(re.escape(part) for part in parts)
    return re.compile(f"^{escaped}$")


def activity_name_matches(name: str, pattern: str) -> bool:
    """Whole-string match of ``name`` against ``pattern`` (``*`` = any run of chars)."""
    return _pattern_to_regex(pattern).fullmatch(name) is not None


def activity_name_matches_any(name: str, patterns: Sequence[str]) -> bool:
    """True if ``name`` whole-string-matches any pattern in ``patterns``."""
    return any(activity_name_matches(name, pattern) for pattern in patterns)


# Canonical MCP tool-call effect-activity names an ``unwarranted_activities``
# pattern must never match. Checked against every configured pattern in
# ``TenuoPluginConfig.__post_init__`` so a careless glob (or a bare ``"*"``)
# cannot silently exempt real tool-call effects from authorization. These are
# representative shapes of the harness's ``<server>[-stateless|-stateful]
# -call-tool-v2`` activities (see ``tenuo.temporal.harness``), not an
# exhaustive list — the probe set only needs to be broad enough to catch
# patterns that are unintentionally too permissive.
FORBIDDEN_UNWARRANTED_PROBES: Tuple[str, ...] = (
    "probe-stateless-call-tool-v2",
    "probe-stateful-call-tool-v2",
    "probe-call-tool-v2",
    "call-tool-v2",
)


def validate_unwarranted_activities(patterns: Sequence[str]) -> None:
    """Raise ``ConfigurationError`` if any pattern would match an MCP effect probe."""
    from tenuo.exceptions import ConfigurationError

    for pattern in patterns:
        for probe in FORBIDDEN_UNWARRANTED_PROBES:
            if activity_name_matches(probe, pattern):
                raise ConfigurationError(
                    "TenuoPluginConfig.unwarranted_activities pattern "
                    f"{pattern!r} matches {probe!r}, a name shaped like an MCP "
                    "call-tool effect activity. Effect activities must stay "
                    "protected; narrow the pattern to an exact activity name "
                    "or a suffix/prefix pattern that cannot match "
                    "'*-call-tool-v2'."
                )


# ---------------------------------------------------------------------------
# MCP call-tool-v2 unwrapping — TenuoPluginConfig.mcp_call_tool_activities
# ---------------------------------------------------------------------------
# A wrapper activity takes exactly one argument shaped like
# ``{tool_name, arguments, meta}``. We unwrap it into the (tool_name,
# arguments) pair a warrant should actually authorize, and we never read
# ``meta`` — it is transport metadata, not authority.


def is_mcp_call_tool_activity(activity_type: str, patterns: Sequence[str]) -> bool:
    """True if *activity_type* matches one of ``mcp_call_tool_activities``."""
    if not patterns:
        return False
    return activity_name_matches_any(activity_type, patterns)


def _wrapper_field(wrapper: Any, name: str) -> Any:
    """Read *name* off a wrapper that may be a ``dict``, dataclass, or plain object."""
    if isinstance(wrapper, Mapping):
        return wrapper.get(name)
    return getattr(wrapper, name, None)


def unwrap_mcp_call_tool(
    activity_type: str,
    args_dict: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    """Unwrap an MCP call-tool-v2 wrapper's single argument into ``(tool_name, arguments)``.

    ``args_dict`` is the wrapper activity's own args dict (one entry: its
    single wrapper parameter). Raises ``TenuoActivityMappingError`` — fail
    closed, never a best-effort guess — when the shape doesn't match: not
    exactly one argument, a missing/non-string ``tool_name``, or a
    non-dict/non-``None`` ``arguments``. ``meta`` (or anything else on the
    wrapper) is never inspected: it carries no authority.
    """
    from tenuo.temporal.exceptions import TenuoActivityMappingError

    if len(args_dict) != 1:
        raise TenuoActivityMappingError(
            f"MCP call-tool activity {activity_type!r} matched "
            "mcp_call_tool_activities but does not take exactly one "
            f"argument (got {len(args_dict)})."
        )
    (wrapper,) = args_dict.values()

    tool_name = _wrapper_field(wrapper, "tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        raise TenuoActivityMappingError(
            f"MCP call-tool activity {activity_type!r} wrapper is missing a "
            f"valid string 'tool_name' (got {tool_name!r})."
        )

    arguments = _wrapper_field(wrapper, "arguments")
    if arguments is None:
        arguments = {}
    elif not isinstance(arguments, dict):
        raise TenuoActivityMappingError(
            f"MCP call-tool activity {activity_type!r} wrapper 'arguments' "
            f"must be a dict or None, got {type(arguments).__name__}."
        )
    return tool_name, dict(arguments)
