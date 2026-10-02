"""Helpers for optional-integration ImportError messages.

Keep installation hints aligned with extras declared in pyproject.toml.
Do not encode Python-version policy here; that lives on the extras themselves.
"""

from __future__ import annotations


def extra_install_command(extra: str) -> str:
    """Return the canonical pip command for a Tenuo optional extra."""
    return f'pip install "tenuo[{extra}]"'


def missing_optional_dependency(integration: str, extra: str) -> str:
    """Build a consistent missing-optional-dependency ImportError message."""
    return (
        f"{integration} is required. "
        f"Install with: {extra_install_command(extra)}"
    )
