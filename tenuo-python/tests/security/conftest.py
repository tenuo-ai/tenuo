"""
Pytest configuration for security tests.
"""

import pytest


def pytest_configure(config):
    """Register custom markers for security tests.

    Markers are declared in pyproject.toml [tool.pytest.ini_options]; this
    hook is kept for backwards-compatibility with direct `pytest tests/security/`
    invocations where pyproject.toml is the root config.
    """


@pytest.fixture
def keypair():
    """Generate a fresh keypair for testing."""
    from tenuo import SigningKey

    return SigningKey.generate()


@pytest.fixture
def attacker_keypair():
    """Generate a keypair representing an attacker."""
    from tenuo import SigningKey

    return SigningKey.generate()
