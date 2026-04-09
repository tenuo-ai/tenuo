"""
Tests for OpenAI adapter delegation support.

Covers:
- Delegated warrant exposes only child tools
- Delegated warrant has correct depth
- Monotonic attenuation enforced at creation
- Wrong signer rejected
"""

import pytest

from tenuo import SigningKey, Warrant


@pytest.fixture
def issuer_key():
    return SigningKey.generate()


@pytest.fixture
def orch_key():
    return SigningKey.generate()


@pytest.fixture
def worker_key():
    return SigningKey.generate()


@pytest.fixture
def root_warrant(issuer_key, orch_key):
    return (
        Warrant.mint_builder()
        .capability("search")
        .capability("read_file")
        .capability("delete_file")
        .holder(orch_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


@pytest.fixture
def child_warrant(root_warrant, orch_key, worker_key):
    return (
        root_warrant.grant_builder()
        .capability("search")
        .capability("read_file")
        .holder(worker_key.public_key)
        .ttl(1800)
        .grant(orch_key)
    )


class TestOpenAIDelegation:
    def test_attenuated_warrant_tools(self, child_warrant):
        """Child warrant exposes only granted tools."""
        tools = child_warrant.tools
        assert "search" in tools
        assert "read_file" in tools
        assert "delete_file" not in tools

    def test_attenuated_depth(self, root_warrant, child_warrant):
        """Root has depth 0, child has depth 1."""
        assert root_warrant.depth == 0
        assert child_warrant.depth == 1

    def test_three_level_depth(self, issuer_key, orch_key, worker_key):
        sub_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("search")
            .capability("read_file")
            .holder(orch_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        mid = (
            root.grant_builder()
            .capability("search")
            .capability("read_file")
            .holder(worker_key.public_key)
            .ttl(1800)
            .grant(orch_key)
        )

        leaf = (
            mid.grant_builder()
            .capability("search")
            .holder(sub_key.public_key)
            .ttl(900)
            .grant(worker_key)
        )

        assert root.depth == 0
        assert mid.depth == 1
        assert leaf.depth == 2

    def test_ttl_attenuation(self, root_warrant, child_warrant):
        """Child TTL must not exceed parent TTL."""
        assert child_warrant.ttl <= root_warrant.ttl

    def test_cannot_escalate_via_grant_builder(self, root_warrant, orch_key, worker_key):
        """Cannot add tools the parent doesn't have."""
        with pytest.raises(Exception):
            root_warrant.grant_builder() \
                .capability("search") \
                .capability("launch_missiles") \
                .holder(worker_key.public_key) \
                .ttl(1800) \
                .grant(orch_key)

    def test_wrong_signer_rejected(self, root_warrant, worker_key):
        """Signing with a key that doesn't hold the parent fails."""
        imposter = SigningKey.generate()
        with pytest.raises(Exception):
            root_warrant.grant_builder() \
                .capability("search") \
                .holder(worker_key.public_key) \
                .ttl(1800) \
                .grant(imposter)

    def test_child_parent_hash_linked(self, root_warrant, child_warrant):
        """Child warrant has a parent_hash linking to root."""
        assert child_warrant.parent_hash is not None
        assert root_warrant.parent_hash is None
