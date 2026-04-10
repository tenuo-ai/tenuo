"""
Tests for LangChain delegation support.

Covers:
- Attenuated warrant allows narrower tools
- Attenuated warrant blocks dropped tools
- Monotonic attenuation enforced at creation
"""

import pytest

from tenuo import (
    LANGCHAIN_AVAILABLE,
    SigningKey,
    Warrant,
    chain_scope,
    configure,
    key_scope,
    reset_config,
    warrant_scope,
)
from tenuo.exceptions import ToolNotAuthorized

pytestmark = pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")


@pytest.fixture(autouse=True)
def _reset():
    reset_config()
    yield
    reset_config()


if LANGCHAIN_AVAILABLE:
    try:
        from langchain_core.tools import tool
        from tenuo.langchain import guard_tools

        @tool
        def search(query: str) -> str:
            """Search for information."""
            return f"Results for: {query}"

        @tool
        def read_file(path: str) -> str:
            """Read a file from disk."""
            return f"Contents of: {path}"

        @tool
        def delete_file(path: str) -> str:
            """Delete a file from disk."""
            return f"Deleted: {path}"
    except Exception:
        pass


class TestLangChainDelegation:
    def test_attenuated_warrant_allows_child_tools(self):
        issuer = SigningKey.generate()
        orch = SigningKey.generate()
        worker = SigningKey.generate()
        configure(issuer_key=issuer, dev_mode=True)

        root = (
            Warrant.mint_builder()
            .capability("search")
            .capability("read_file")
            .capability("delete_file")
            .holder(orch.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        child = (
            root.grant_builder()
            .capability("search")
            .capability("read_file")
            .holder(worker.public_key)
            .ttl(1800)
            .grant(orch)
        )

        tools = guard_tools([search, read_file, delete_file])

        with chain_scope([root]):
            with warrant_scope(child):
                with key_scope(worker):
                    result = tools[0].invoke({"query": "test"})
                    assert "Results for: test" in result

                    result2 = tools[1].invoke({"path": "/data/x"})
                    assert "Contents of:" in result2

    def test_attenuated_warrant_blocks_dropped_tools(self):
        issuer = SigningKey.generate()
        orch = SigningKey.generate()
        worker = SigningKey.generate()
        configure(issuer_key=issuer, dev_mode=True)

        root = (
            Warrant.mint_builder()
            .capability("search")
            .capability("read_file")
            .capability("delete_file")
            .holder(orch.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        child = (
            root.grant_builder()
            .capability("search")
            .holder(worker.public_key)
            .ttl(1800)
            .grant(orch)
        )

        tools = guard_tools([search, read_file, delete_file])

        with chain_scope([root]):
            with warrant_scope(child):
                with key_scope(worker):
                    result = tools[0].invoke({"query": "test"})
                    assert result is not None

                    with pytest.raises(ToolNotAuthorized):
                        tools[1].invoke({"path": "/data/x"})

                    with pytest.raises(ToolNotAuthorized):
                        tools[2].invoke({"path": "/data/x"})

    def test_cannot_escalate_via_grant_builder(self):
        issuer = SigningKey.generate()
        orch = SigningKey.generate()
        worker = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("search")
            .holder(orch.public_key)
            .ttl(3600)
            .mint(issuer)
        )

        with pytest.raises(Exception):
            root.grant_builder() \
                .capability("search") \
                .capability("delete_file") \
                .holder(worker.public_key) \
                .ttl(1800) \
                .grant(orch)
