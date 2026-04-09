"""
Tests for chain_scope context variable.

Covers:
- Getter returns None when not set
- Context manager sets and resets
- Nesting preserves outer scope on exit
- Works with warrant_scope / key_scope together
"""

import pytest

from tenuo import SigningKey, Warrant, chain_scope, key_scope, warrant_scope
from tenuo.decorators import ChainContext


@pytest.fixture
def issuer_key():
    return SigningKey.generate()


@pytest.fixture
def worker_key():
    return SigningKey.generate()


@pytest.fixture
def root_warrant(issuer_key, worker_key):
    return (
        Warrant.mint_builder()
        .capability("read_file")
        .holder(worker_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


class TestChainScopeBasics:
    def test_getter_returns_none_by_default(self):
        assert chain_scope() is None

    def test_context_manager_sets_and_resets(self, root_warrant):
        assert chain_scope() is None
        with chain_scope([root_warrant]):
            parents = chain_scope()
            assert parents is not None
            assert len(parents) == 1
            assert parents[0].id == root_warrant.id
        assert chain_scope() is None

    def test_empty_list_is_truthy_context(self):
        with chain_scope([]):
            assert chain_scope() == []

    def test_nested_scopes(self, issuer_key, worker_key):
        k2 = SigningKey.generate()
        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .holder(worker_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )
        child = (
            root.grant_builder()
            .capability("read_file")
            .holder(k2.public_key)
            .ttl(1800)
            .grant(worker_key)
        )

        with chain_scope([root]):
            assert len(chain_scope()) == 1
            with chain_scope([root, child]):
                assert len(chain_scope()) == 2
            assert len(chain_scope()) == 1
        assert chain_scope() is None


class TestChainScopeWithWarrantAndKey:
    def test_all_three_scopes_together(self, issuer_key, worker_key, root_warrant):
        child_key = SigningKey.generate()
        child = (
            root_warrant.grant_builder()
            .capability("read_file")
            .holder(child_key.public_key)
            .ttl(1800)
            .grant(worker_key)
        )

        with chain_scope([root_warrant]):
            with warrant_scope(child):
                with key_scope(child_key):
                    assert chain_scope() is not None
                    assert len(chain_scope()) == 1
                    assert warrant_scope().id == child.id
                    assert key_scope() is not None

        assert chain_scope() is None
        assert warrant_scope() is None
        assert key_scope() is None
