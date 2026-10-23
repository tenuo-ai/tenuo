"""Anchored glob matching for activity-name allow/skip patterns.

Backs ``TenuoPluginConfig.unwarranted_activities``. A pattern matches the ENTIRE
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
from typing import Sequence

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


# MCP tool-call effect activities are named ``<server>[-stateless|-stateful]
# -call-tool-v2`` (see ``tenuo.temporal.harness``), with any server name. An
# ``unwarranted_activities`` pattern must not be able to match that shape for
# ANY server, so the check is structural rather than a list of sample names:
# ``payments-*`` and ``payments-call-tool-v2`` are refused as well as ``*``.
MCP_EFFECT_SUFFIX = "call-tool-v2"


def could_match_mcp_effect(pattern: str) -> bool:
    """True if some ``*-call-tool-v2`` activity name would match ``pattern``.

    A pattern ending in ``*`` can be completed with the suffix. Otherwise the
    text after its last ``*`` (or the whole pattern, without one) must end the
    name, so it matches a call-tool name iff it and the suffix overlap at the
    end.
    """
    if _WILDCARD not in pattern:
        return pattern.endswith(MCP_EFFECT_SUFFIX)
    tail = pattern.rsplit(_WILDCARD, 1)[1]
    return tail == "" or MCP_EFFECT_SUFFIX.endswith(tail) or tail.endswith(MCP_EFFECT_SUFFIX)


def validate_unwarranted_activities(patterns: Sequence[str]) -> None:
    """Raise ``ConfigurationError`` if any pattern could match an MCP effect activity."""
    from tenuo.exceptions import ConfigurationError

    for pattern in patterns:
        if could_match_mcp_effect(pattern):
            raise ConfigurationError(
                "TenuoPluginConfig.unwarranted_activities pattern "
                f"{pattern!r} could match an MCP call-tool effect activity "
                "('<server>-call-tool-v2'). Effect activities must stay "
                "protected; use exact internal activity names, or a pattern "
                "that ends in fixed text other than '-call-tool-v2'."
            )
