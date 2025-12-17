"""
Pytest configuration for security tests.
"""

import pytest


def pytest_configure(config):
    """Register custom markers for security tests."""
    config.addinivalue_line(
        "markers", "security: security/red team tests"
    )
    config.addinivalue_line(
        "markers", "integration_responsibility: tests documenting application responsibilities (not Tenuo bugs)"
    )
    config.addinivalue_line(
        "markers", "signature: tests for signature and trust verification"
    )
    config.addinivalue_line(
        "markers", "monotonicity: tests for capability attenuation rules"
    )
    config.addinivalue_line(
        "markers", "pop: tests for Proof-of-Possession binding"
    )
    config.addinivalue_line(
        "markers", "delegation: tests for delegation depth and chain limits"
    )
    config.addinivalue_line(
        "markers", "implementation: tests for implementation-level bypasses"
    )


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
