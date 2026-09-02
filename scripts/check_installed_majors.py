#!/usr/bin/env python3
"""Fail unless installed distributions match the expected major versions.

Usage::

    python scripts/check_installed_majors.py mcp=1 fastmcp=3

Each argument is ``<distribution>=<major>``. Used by CI lanes that pin a
dependency line (FastMCP 3 + MCP SDK 1.x, FastMCP 4 + MCP SDK 2.x) so a
resolver that quietly picks the other major fails the job instead of running
the tests against the wrong line.
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    failures: list[str] = []
    for spec in argv:
        dist, sep, major = spec.partition("=")
        if not sep or not dist or not major:
            failures.append(f"malformed spec {spec!r} (want <distribution>=<major>)")
            continue
        try:
            installed = version(dist)
        except PackageNotFoundError:
            failures.append(f"{dist} is not installed (expected {major}.x)")
            continue
        print(f"{dist}={installed}")
        if not installed.startswith(f"{major}."):
            failures.append(f"expected {dist} {major}.x, got {installed}")
    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
