"""Shared configuration for Hypothesis property-based tests.

Select a profile with HYPOTHESIS_PROFILE (dev, ci, thorough). Default: dev.
"""

import os

import pytest

collect_ignore_glob = []

try:
    from hypothesis import settings

    # No deadline in CI: shared Windows and 3.9 runners are slow enough that
    # per-example timing would make failures depend on the runner.
    settings.register_profile("ci", max_examples=200, derandomize=True, deadline=None)
    settings.register_profile("dev", max_examples=50)
    settings.register_profile("thorough", max_examples=5000)
    settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
except ModuleNotFoundError:
    collect_ignore_glob = ["test_*.py"]


def pytest_collection_modifyitems(items):
    for item in items:
        if "property" in str(item.fspath):
            item.add_marker(pytest.mark.hypothesis)
