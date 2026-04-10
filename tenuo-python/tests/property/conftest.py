"""Shared configuration for Hypothesis property-based tests."""

import pytest
from hypothesis import settings

# CI profile: fast, reproducible
settings.register_profile("ci", max_examples=200, derandomize=True)
# Dev profile: quick feedback
settings.register_profile("dev", max_examples=50)
# Thorough profile: nightly / release
settings.register_profile("thorough", max_examples=5000)

settings.load_profile("dev")


def pytest_collection_modifyitems(items):
    for item in items:
        if "property" in str(item.fspath):
            item.add_marker(pytest.mark.hypothesis)
