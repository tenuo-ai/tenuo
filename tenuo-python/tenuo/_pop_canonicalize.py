"""Canonicalize tool-call argument dicts before they cross the Rust FFI boundary.

The Rust core's ``py_to_constraint_value`` accepts ``str``/``int``/``float``/
``bool``/``list`` but **not** ``None``. Many real-world tool signatures declare
optional arguments with ``None`` defaults (``encoding: Optional[str] = None``),
and those ``None`` values routinely show up in MCP wire-args dicts as explicit
nulls. Without canonicalization, ``warrant.sign()`` and ``Authorizer.authorize*``
crash with ``ValueError: value must be str, int, float, bool, or list``.

This module provides a single helper, :func:`strip_none_values`, that both the
MCP client signing path and the MCP server verification path use to produce a
matching canonical view. The rule is intentionally minimal and identical on
both sides:

* Drop any top-level key whose value is ``None``.
* Recurse into list values to drop ``None`` elements.
* Never copy unnecessarily — return the input dict when no changes are needed.

Both sides of the handshake must apply the exact same canonicalization for the
PoP bytes to match, so keep this function simple and deterministic. Any
semantic changes here are a signed-bytes-format change.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _clean_list(value: List[Any]) -> List[Any]:
    """Drop ``None`` elements from a list, recursing into nested lists.

    Keeps any non-``None`` / non-list element as-is. Lists nested at any
    depth are cleaned in place of being passed through verbatim so the
    final structure is guaranteed ``None``-free end to end.
    """
    cleaned: List[Any] = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, list):
            cleaned.append(_clean_list(item))
        else:
            cleaned.append(item)
    return cleaned


def strip_none_values(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``args`` with ``None``-valued keys dropped.

    List-valued entries have their ``None`` elements dropped recursively
    at any depth. Non-mapping, non-list values pass through unchanged.

    We do not recurse into nested **dicts** because tool arg dicts are
    flat key → scalar/list mappings at the Rust FFI boundary and the
    Rust ``ConstraintValue`` enum has no dict variant. A property-based
    fuzzer (``tests/property/test_pop_ffi_fuzzer.py``) pins the invariant
    that the returned structure is recursively ``None``-free for any
    reachable input, and that both client and server derive byte-
    identical PoP canonicalizations from it.

    Args:
        args: Tool-call argument dict (e.g., MCP ``params.arguments``).

    Returns:
        A new dict with ``None`` values removed. The input is not modified.
    """
    out: Dict[str, Any] = {}
    for key, value in args.items():
        if value is None:
            continue
        if isinstance(value, list):
            out[key] = _clean_list(value)
        else:
            out[key] = value
    return out


__all__ = ["strip_none_values"]
