"""
Shared pytest configuration for the test suite.
"""

import os
from pathlib import Path

import pytest

_TEMPORAL_E2E_FILES = frozenset({"test_temporal_live.py", "test_temporal_replay.py"})


def pytest_collection_modifyitems(config, items):
    """Auto-skip temporal_live tests unless explicitly opted in.

    The live tests require an in-process Temporal server and must run in
    their own pytest process to avoid pollution from mock-based test files.
    They run in the dedicated ``temporal-integration`` CI job with
    ``TEMPORAL_LIVE_TESTS=1``, or locally via:

        TEMPORAL_LIVE_TESTS=1 pytest tests/e2e/test_temporal_live.py -v

    Running only Temporal e2e files (live or replay) also opts in:

        pytest tests/e2e/test_temporal_live.py -v
        pytest tests/e2e/test_temporal_replay.py -v
    """
    # If only Temporal e2e files were selected, don't skip
    all_files = {str(item.fspath) for item in items}
    basenames = {Path(f).name for f in all_files}
    if basenames and basenames <= _TEMPORAL_E2E_FILES:
        return

    if os.environ.get("TEMPORAL_LIVE_TESTS"):
        return

    skip = pytest.mark.skip(
        reason="Skipped in full suite (process isolation required). "
        "Run with: TEMPORAL_LIVE_TESTS=1 pytest tests/e2e/test_temporal_live.py "
        "or run only tests/e2e/test_temporal_live.py / test_temporal_replay.py"
    )
    for item in items:
        if "temporal_live" in item.keywords:
            item.add_marker(skip)
