"""
Tests for Temporal delegation support.

Covers:
- grant_builder creates valid attenuated warrant
- check_chain verifies delegation chain
- Orphaned child rejected by check_chain
- Chain header round-trip via encode/decode
"""

import time

import pytest

pytest.importorskip("temporalio")

from tenuo import Authorizer, SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack  # noqa: E402


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
def authorizer(issuer_key):
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def root_warrant(issuer_key, orch_key):
    return (
        Warrant.mint_builder()
        .capability("process_order")
        .capability("send_email")
        .capability("refund")
        .holder(orch_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


@pytest.fixture
def child_warrant(root_warrant, orch_key, worker_key):
    return (
        root_warrant.grant_builder()
        .capability("process_order")
        .capability("send_email")
        .holder(worker_key.public_key)
        .ttl(1800)
        .grant(orch_key)
    )


class TestTemporalDelegationChain:
    def test_check_chain_allows_child_tool(self, authorizer, root_warrant, child_warrant, worker_key):
        chain = [root_warrant, child_warrant]
        pop = child_warrant.sign(worker_key, "process_order", {"id": "123"}, int(time.time()))
        result = authorizer.check_chain(
            chain, "process_order", {"id": "123"}, signature=bytes(pop)
        )
        assert result.chain_length == 2

    def test_check_chain_denies_dropped_tool(self, authorizer, root_warrant, child_warrant, worker_key):
        chain = [root_warrant, child_warrant]
        pop = child_warrant.sign(worker_key, "refund", {"id": "123"}, int(time.time()))
        with pytest.raises(Exception):
            authorizer.check_chain(
                chain, "refund", {"id": "123"}, signature=bytes(pop)
            )

    def test_orphaned_child_rejected(self, authorizer, child_warrant, worker_key):
        pop = child_warrant.sign(worker_key, "process_order", {"id": "123"}, int(time.time()))
        with pytest.raises(Exception, match="(?i)(issuer|root|trust)"):
            authorizer.check_chain(
                [child_warrant], "process_order", {"id": "123"}, signature=bytes(pop)
            )

    def test_warrant_stack_round_trip(self, root_warrant, child_warrant):
        encoded = encode_warrant_stack([root_warrant, child_warrant])
        decoded = decode_warrant_stack_base64(encoded)
        assert len(decoded) == 2
        assert decoded[0].id == root_warrant.id
        assert decoded[-1].id == child_warrant.id

    def test_three_level_chain(self, issuer_key, orch_key, worker_key, authorizer):
        sub_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("process_order")
            .capability("send_email")
            .holder(orch_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        mid = (
            root.grant_builder()
            .capability("process_order")
            .capability("send_email")
            .holder(worker_key.public_key)
            .ttl(1800)
            .grant(orch_key)
        )

        leaf = (
            mid.grant_builder()
            .capability("process_order")
            .holder(sub_key.public_key)
            .ttl(900)
            .grant(worker_key)
        )

        chain = [root, mid, leaf]
        pop = leaf.sign(sub_key, "process_order", {"id": "x"}, int(time.time()))
        result = authorizer.check_chain(
            chain, "process_order", {"id": "x"}, signature=bytes(pop)
        )
        assert result.chain_length == 3

    def test_cannot_escalate_at_creation(self, root_warrant, orch_key, worker_key):
        with pytest.raises(Exception):
            root_warrant.grant_builder() \
                .capability("process_order") \
                .capability("transfer_funds") \
                .holder(worker_key.public_key) \
                .ttl(1800) \
                .grant(orch_key)
