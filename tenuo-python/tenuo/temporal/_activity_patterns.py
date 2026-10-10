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
from typing import Sequence, Tuple

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
