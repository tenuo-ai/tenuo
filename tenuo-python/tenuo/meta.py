"""Translate a host value into the core ``_meta.tenuo`` envelope.

``sign_meta`` and ``decode_meta`` in the core are the only producer and
consumer of that object. This module turns a host dict into the argument
JSON text those functions sign. It does not choose a base64 alphabet, frame
a warrant stack, or drop ``None``.

A dict the framework has already parsed is a lossy input. The original
argument text is what a cross-language vector signs. When only the dict
remains, ``argument_json`` is the translation and the core parses that text.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Dict

from tenuo_core import args_from_json


def argument_json(args: Mapping[str, Any]) -> str:
    """Host dict to the argument JSON text the core signs.

    Key order is sorted so two hosts with the same values produce the same
    text. ``None`` is JSON null and stays in the text.
    """
    return json.dumps(
        args,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def signed_arguments(args: Mapping[str, Any]) -> Dict[str, Any]:
    """The core's reading of ``argument_json(args)``, as a host dict.

    JSON null comes back as ``None``. Proof checks use this map, not a
    second pass that drops ``None``.
    """
    return args_from_json(argument_json(args))


__all__ = ["argument_json", "signed_arguments"]
