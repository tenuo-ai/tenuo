"""Parse tool-argument JSON without collapsing duplicate keys."""

from __future__ import annotations

from typing import Any


def parse_strict_json(text: str) -> Any:
    """Parse JSON text, rejecting a repeated key in any object.

    A dict that a framework has already parsed cannot be checked: the
    duplicate is gone. Call this while the text is still available.
    Nested objects are checked too.

    Raises:
        ValueError: The text is not a single JSON value, or an object repeats a key.
    """
    from tenuo_core import parse_strict_json as _parse

    return _parse(text)
