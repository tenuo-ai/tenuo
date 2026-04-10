"""
Tests for MCP delegation chain support (WarrantStack + check_chain).

Covers:
- MCPVerifier decodes WarrantStack from _meta.tenuo.warrant
- MCPVerifier uses check_chain for multi-warrant chains
- MCPVerifier falls back to authorize_one for single warrants
- Orphaned child warrant (no chain) rejected
- Attenuated tool denied even with valid chain
- Backward compatibility with single root warrant
- chain_scope context var integration with SecureMCPClient
"""

from __future__ import annotations

import base64
import time

import pytest
from tenuo import (
    Authorizer,
    SigningKey,
    Warrant,
    decode_warrant_stack_base64,
    encode_warrant_stack,
)

from tenuo.mcp.server import MCPVerifier


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def orchestrator_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def worker_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def verifier(authorizer: Authorizer) -> MCPVerifier:
    return MCPVerifier(authorizer=authorizer)


@pytest.fixture
def root_warrant(issuer_key, orchestrator_key) -> Warrant:
    return (
        Warrant.mint_builder()
        .capability("read_file")
        .capability("write_file")
        .capability("delete_file")
        .holder(orchestrator_key.public_key)
        .ttl(3600)
        .mint(issuer_key)
    )


@pytest.fixture
def child_warrant(root_warrant, orchestrator_key, worker_key) -> Warrant:
    return (
        root_warrant.grant_builder()
        .capability("read_file")
        .holder(worker_key.public_key)
        .ttl(1800)
        .grant(orchestrator_key)
    )


@pytest.fixture
def stack_b64(root_warrant, child_warrant) -> str:
    return encode_warrant_stack([root_warrant, child_warrant])


def _make_meta(warrant_b64: str, warrant, signing_key, tool: str, args: dict) -> dict:
    pop = warrant.sign(signing_key, tool, args, int(time.time()))
    return {
        "tenuo": {
            "warrant": warrant_b64,
            "signature": base64.b64encode(bytes(pop)).decode(),
        }
    }


# ---------------------------------------------------------------------------
# WarrantStack decode + check_chain
# ---------------------------------------------------------------------------


class TestMCPVerifierWarrantStack:
    """MCPVerifier correctly decodes WarrantStack and uses check_chain."""

    def test_chain_allowed_for_child_tool(self, verifier, stack_b64, child_warrant, worker_key):
        meta = _make_meta(stack_b64, child_warrant, worker_key, "read_file", {"path": "/x"})
        result = verifier.verify("read_file", {"path": "/x"}, meta=meta)
        assert result.allowed is True

    def test_chain_denied_for_dropped_tool(self, verifier, stack_b64, child_warrant, worker_key):
        meta = _make_meta(stack_b64, child_warrant, worker_key, "write_file", {"path": "/x"})
        result = verifier.verify("write_file", {"path": "/x"}, meta=meta)
        assert result.allowed is False
        assert result.denial_reason is not None

    def test_chain_denied_for_absent_tool(self, verifier, stack_b64, child_warrant, worker_key):
        meta = _make_meta(stack_b64, child_warrant, worker_key, "delete_file", {"path": "/x"})
        result = verifier.verify("delete_file", {"path": "/x"}, meta=meta)
        assert result.allowed is False

    def test_stack_roundtrip_preserves_chain(self, root_warrant, child_warrant):
        encoded = encode_warrant_stack([root_warrant, child_warrant])
        decoded = decode_warrant_stack_base64(encoded)
        assert len(decoded) == 2
        assert decoded[0].id == root_warrant.id
        assert decoded[-1].id == child_warrant.id


class TestMCPVerifierOrphanedChild:
    """Orphaned child warrant (sent without parent chain) must be rejected."""

    def test_orphaned_child_rejected(self, verifier, child_warrant, worker_key):
        single_b64 = child_warrant.to_base64()
        meta = _make_meta(single_b64, child_warrant, worker_key, "read_file", {"path": "/x"})
        result = verifier.verify("read_file", {"path": "/x"}, meta=meta)
        assert result.allowed is False
        assert "issuer" in (result.denial_reason or "").lower() or "root" in (result.denial_reason or "").lower()


class TestMCPVerifierSingleWarrantBackcompat:
    """Single root warrant (no chain) still works via authorize_one."""

    def test_root_warrant_allowed(self, verifier, issuer_key, orchestrator_key):
        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )
        single_b64 = root.to_base64()
        meta = _make_meta(single_b64, root, orchestrator_key, "read_file", {"path": "/x"})
        result = verifier.verify("read_file", {"path": "/x"}, meta=meta)
        assert result.allowed is True

    def test_root_warrant_denied_wrong_tool(self, verifier, issuer_key, orchestrator_key):
        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )
        single_b64 = root.to_base64()
        meta = _make_meta(single_b64, root, orchestrator_key, "delete_file", {"path": "/x"})
        result = verifier.verify("delete_file", {"path": "/x"}, meta=meta)
        assert result.allowed is False


class TestMCPVerifierDeepChain:
    """Three-level delegation chain: issuer → orchestrator → worker → sub-agent."""

    def test_three_level_chain_allowed(self, issuer_key, orchestrator_key, worker_key, verifier):
        sub_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .capability("list_dir")
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        mid = (
            root.grant_builder()
            .capability("read_file")
            .capability("list_dir")
            .holder(worker_key.public_key)
            .ttl(1800)
            .grant(orchestrator_key)
        )

        leaf = (
            mid.grant_builder()
            .capability("read_file")
            .holder(sub_key.public_key)
            .ttl(900)
            .grant(worker_key)
        )

        stack = encode_warrant_stack([root, mid, leaf])
        meta = _make_meta(stack, leaf, sub_key, "read_file", {"path": "/data"})
        result = verifier.verify("read_file", {"path": "/data"}, meta=meta)
        assert result.allowed is True

    def test_three_level_chain_denied_escalation(self, issuer_key, orchestrator_key, worker_key, verifier):
        sub_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .capability("list_dir")
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        mid = (
            root.grant_builder()
            .capability("read_file")
            .holder(worker_key.public_key)
            .ttl(1800)
            .grant(orchestrator_key)
        )

        leaf = (
            mid.grant_builder()
            .capability("read_file")
            .holder(sub_key.public_key)
            .ttl(900)
            .grant(worker_key)
        )

        stack = encode_warrant_stack([root, mid, leaf])
        meta = _make_meta(stack, leaf, sub_key, "list_dir", {"path": "/data"})
        result = verifier.verify("list_dir", {"path": "/data"}, meta=meta)
        assert result.allowed is False


class TestMCPVerifierCorruptedStack:
    """Corrupted WarrantStack must not silently fall back to single-warrant decode."""

    def test_truncated_cbor_stack_rejected(self, verifier, worker_key):
        """A truncated CBOR array must not silently parse as a single warrant."""
        import base64

        valid_key = SigningKey.generate()
        w = Warrant.mint_builder().capability("read_file").holder(worker_key.public_key).ttl(3600).mint(valid_key)
        stack_b64 = encode_warrant_stack([w])
        raw = base64.urlsafe_b64decode(stack_b64 + "==")
        # Corrupt: chop off last 10 bytes of the CBOR to break structure
        corrupted = base64.urlsafe_b64encode(raw[:-10]).decode().rstrip("=")

        meta = {"tenuo": {
            "warrant": corrupted,
            "signature": base64.b64encode(b"\x00" * 64).decode(),
        }}
        result = verifier.verify("read_file", {"path": "/data/x.txt"}, meta=meta)
        assert result.allowed is False
        assert "malformed" in (result.denial_reason or "").lower()

    def test_garbage_bytes_rejected(self, verifier):
        """Random garbage that isn't CBOR or single warrant must be rejected."""
        import base64

        garbage = base64.urlsafe_b64encode(b"not-a-warrant-at-all").decode().rstrip("=")
        meta = {"tenuo": {
            "warrant": garbage,
            "signature": base64.b64encode(b"\x00" * 64).decode(),
        }}
        result = verifier.verify("read_file", {"path": "/data/x.txt"}, meta=meta)
        assert result.allowed is False
        assert "malformed" in (result.denial_reason or "").lower()


class TestMCPVerifierChainWithWrongSigner:
    """Chain where the child is signed by the wrong key must be rejected."""

    def test_wrong_signer_rejected(self, issuer_key, orchestrator_key, worker_key, verifier):
        imposter_key = SigningKey.generate()

        root = (
            Warrant.mint_builder()
            .capability("read_file")
            .holder(orchestrator_key.public_key)
            .ttl(3600)
            .mint(issuer_key)
        )

        with pytest.raises(Exception):
            root.grant_builder() \
                .capability("read_file") \
                .holder(worker_key.public_key) \
                .ttl(1800) \
                .grant(imposter_key)
