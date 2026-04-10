"""Shared configuration for Hypothesis property-based tests."""

import pytest

collect_ignore_glob = []

try:
    from hypothesis import settings

    settings.register_profile("ci", max_examples=200, derandomize=True)
    settings.register_profile("dev", max_examples=50)
    settings.register_profile("thorough", max_examples=5000)
    settings.load_profile("dev")
except ModuleNotFoundError:
    collect_ignore_glob = ["test_*.py"]


def pytest_collection_modifyitems(items):
    for item in items:
        if "property" in str(item.fspath):
            item.add_marker(pytest.mark.hypothesis)
