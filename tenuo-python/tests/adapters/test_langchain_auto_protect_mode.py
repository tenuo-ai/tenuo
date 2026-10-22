"""auto_protect() never silently weakens enforcement."""

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool  # noqa: E402
from tenuo_core import SigningKey  # noqa: E402

from tenuo.config import EnforcementMode, configure, get_config, reset_config  # noqa: E402
from tenuo.exceptions import ConfigurationError  # noqa: E402
from tenuo.langchain import auto_protect  # noqa: E402


@tool
def search(query: str) -> str:
    """Search."""
    return query


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


def test_unconfigured_defaults_to_observe():
    auto_protect([search])
    assert get_config().mode == EnforcementMode.OBSERVE


def test_keeps_configured_enforce_mode():
    root = SigningKey.generate()
    configure(trusted_roots=[root.public_key], mode="enforce")
    auto_protect([search])
    assert get_config().mode == EnforcementMode.ENFORCE


def test_explicit_mode_is_applied():
    root = SigningKey.generate()
    configure(trusted_roots=[root.public_key], mode="enforce")
    auto_protect([search], mode="observe")
    assert get_config().mode == EnforcementMode.OBSERVE


def test_audit_alias_accepted():
    auto_protect([search], mode="audit")
    assert get_config().mode == EnforcementMode.OBSERVE


def test_unknown_mode_raises_instead_of_observing():
    with pytest.raises(ConfigurationError):
        auto_protect([search], mode="enforced")


def test_observe_mode_warns(caplog):
    with caplog.at_level("WARNING"):
        auto_protect([search])
    assert any("observe mode is active process-wide" in r.getMessage() for r in caplog.records)


def test_keeps_verifier_only_trusted_roots():
    root = SigningKey.generate()
    configure(trusted_roots=[root.public_key], mode="enforce")
    auto_protect([search])
    config = get_config()
    assert not config.dev_mode
    assert [k.to_bytes() for k in config.trusted_roots] == [root.public_key.to_bytes()]
