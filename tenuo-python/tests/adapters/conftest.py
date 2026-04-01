"""Shared fixtures for adapter tests."""
import pytest


@pytest.fixture
def root_key():
    """A fresh SigningKey acting as the trust root / control plane."""
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def holder_key():
    """A fresh SigningKey acting as the agent warrant holder."""
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def attacker_key():
    """A fresh SigningKey representing an untrusted attacker."""
    from tenuo import SigningKey
    return SigningKey.generate()
