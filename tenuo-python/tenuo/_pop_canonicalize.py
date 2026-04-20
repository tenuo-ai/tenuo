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


def strip_none_values(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``args`` with ``None``-valued keys dropped.

    List-valued entries have their ``None`` elements dropped recursively.
    Non-mapping, non-list values pass through unchanged.

    This is intentionally shallow in structure: we do not recurse into nested
    dicts because tool arg dicts are flat key → scalar/list mappings at the
    Rust FFI boundary.

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
            cleaned: List[Any] = [item for item in value if item is not None]
            out[key] = cleaned
        else:
            out[key] = value
    return out


__all__ = ["strip_none_values"]
