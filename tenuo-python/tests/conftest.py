"""
Shared pytest configuration for the test suite.
"""

_TEMPORAL_E2E_FILES = frozenset({"test_temporal_live.py", "test_temporal_replay.py"})


def pytest_collection_modifyitems(config, items):
    pass
