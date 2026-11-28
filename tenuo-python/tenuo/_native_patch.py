"""Install Python-side extensions on the shared ``tenuo_core`` (PyO3) classes.

``tenuo_core`` is a native extension, so its classes (``Warrant``,
``SigningKey``, ...) exist once per process. The pure-Python ``tenuo``
package, however, can be imported more than once: Temporal's workflow sandbox
re-imports every non-passthrough module (including ``tenuo``) in a fresh
``sys.modules`` for each workflow it validates or runs. If each copy blindly
re-assigned its own functions onto the native classes, the last sandbox to
import ``tenuo`` would replace the host's methods process-wide. Host code then
calls methods whose globals belong to the sandbox copy, e.g. ``Warrant.bind``
returns the sandbox's ``BoundWarrant`` class and ``isinstance`` checks against
the host's ``BoundWarrant`` fail.

:func:`patch_native` records which attributes Tenuo installed. A copy of
``tenuo`` imported inside a Temporal workflow sandbox never replaces an
attribute that an earlier copy already installed. Imports outside the sandbox
(the first import, or a deliberate re-import) still install their own.
"""

from __future__ import annotations

import sys
from typing import Any

_REGISTRY_ATTR = "_tenuo_native_patches"


def _in_workflow_sandbox() -> bool:
    """Return True when running on a Temporal workflow sandbox thread."""
    wf = sys.modules.get("temporalio.workflow")
    if wf is None:
        # Inside the sandbox ``sys.modules`` is a fresh per-sandbox dict that
        # may not contain temporalio yet; temporalio is always passed through,
        # so importing it here returns the host's module. Only reached when a
        # second copy of tenuo is being imported (see patch_native).
        try:
            import importlib

            wf = importlib.import_module("temporalio.workflow")
        except Exception:
            return False
    try:
        return bool(wf.unsafe.in_sandbox())
    except Exception:
        return False


def _registry(cls: Any) -> dict:
    reg = cls.__dict__.get(_REGISTRY_ATTR)
    if reg is None:
        reg = {}
        setattr(cls, _REGISTRY_ATTR, reg)
    return reg


def patch_native(cls: Any, name: str, value: Any, *, if_missing: bool = False) -> None:
    """Set ``cls.<name> = value`` on a shared native class.

    Args:
        cls: The native class to extend.
        name: Attribute name.
        value: Function, property or descriptor to install.
        if_missing: Only install when the class does not already provide
            ``name`` natively (Tenuo-installed attributes may be replaced).
    """
    reg = _registry(cls)
    if name in reg:
        if _in_workflow_sandbox():
            return
    else:
        if if_missing and hasattr(cls, name):
            return
        reg[name] = getattr(cls, name, None)
    setattr(cls, name, value)


def native_original(cls: Any, name: str) -> Any:
    """Return ``cls.<name>`` as it was before Tenuo first patched it."""
    reg = cls.__dict__.get(_REGISTRY_ATTR) or {}
    if name in reg:
        return reg[name]
    return getattr(cls, name, None)


__all__ = ["native_original", "patch_native"]
