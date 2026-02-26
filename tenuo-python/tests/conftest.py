"""
Shared pytest configuration for the test suite.
"""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Auto-skip temporal_live tests unless explicitly opted in.

    The live tests require an in-process Temporal server and must run in
    their own pytest process to avoid pollution from mock-based test files.
    They run in the dedicated ``temporal-integration`` CI job with
    ``TEMPORAL_LIVE_TESTS=1``, or locally via:

        TEMPORAL_LIVE_TESTS=1 pytest tests/test_temporal_live.py -v

    Running them directly (without the full suite) also works:

        pytest tests/test_temporal_live.py -v
    """
    # If only live test files were selected, don't skip
    all_files = {str(item.fspath) for item in items}
    if all(f.endswith("test_temporal_live.py") for f in all_files):
        return

    if os.environ.get("TEMPORAL_LIVE_TESTS"):
        return

    skip = pytest.mark.skip(
        reason="Skipped in full suite (process isolation required). "
        "Run with: TEMPORAL_LIVE_TESTS=1 pytest tests/test_temporal_live.py"
    )
    for item in items:
        if "temporal_live" in item.keywords:
            item.add_marker(skip)
