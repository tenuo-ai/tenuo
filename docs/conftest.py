"""Pytest fixtures for documentation code blocks.

These fixtures are automatically available to all code blocks
when running `pytest --markdown-docs docs/`.
"""

import pytest


@pytest.fixture(autouse=True)
def doc_test_setup():
    """Set up Tenuo in dev mode for all doc examples."""
    from tenuo import configure, SigningKey
    
    # Configure with a fresh key for each test
    configure(
        issuer_key=SigningKey.generate(),
        dev_mode=True,
        audit_log=False,
    )
    yield


@pytest.fixture
def key():
    """Provide a SigningKey for examples."""
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def worker_key():
    """Provide a worker SigningKey."""
    from tenuo import SigningKey
    return SigningKey.generate()


@pytest.fixture
def control_key():
    """Provide a control plane SigningKey."""
    from tenuo import SigningKey
    return SigningKey.generate()


# Mock functions that appear in examples
def receive_warrant_from_orchestrator():
    """Mock function for examples."""
    from tenuo import Warrant, SigningKey, Capability, Pattern
    
    key = SigningKey.generate()
    warrant = (Warrant.mint_builder()
        .capability("search", query=Pattern("*"))
        .capability("read_file", path=Pattern("/data/*"))
        .holder(key.public_key)
        .ttl(3600)
        .mint(key))
    return warrant


def receive_warrant():
    """Alias for receive_warrant_from_orchestrator."""
    return receive_warrant_from_orchestrator()


# Make these available as builtins for code blocks
@pytest.fixture(autouse=True)
def inject_mocks(monkeypatch):
    """Inject mock functions into builtins for code blocks."""
    import builtins
    monkeypatch.setattr(builtins, 'receive_warrant_from_orchestrator', receive_warrant_from_orchestrator)
    monkeypatch.setattr(builtins, 'receive_warrant', receive_warrant)

