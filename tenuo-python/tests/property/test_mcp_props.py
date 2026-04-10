"""Property tests for MCP integration (server.py).

Verifies:
- MCPVerifier.verify never crashes for arbitrary meta envelopes
- Payload size limits are enforced at exact boundaries
- Valid warrants are accepted, garbage is rejected cleanly
- WarrantStack vs single warrant decode paths both work
"""

from __future__ import annotations

import base64
import time

from hypothesis import given, settings
from hypothesis import strategies as st

from tenuo import Authorizer, SigningKey, Warrant
from tenuo.mcp.server import (
    MAX_APPROVALS_COUNT,
    MAX_SIGNATURE_B64_BYTES,
    MAX_WARRANT_B64_BYTES,
    MCPVerificationResult,
    MCPVerifier,
)

from .strategies import (
    st_args_dict,
    st_mcp_meta,
    st_tool_name,
    st_valid_mcp_envelope,
    st_warrant_bundle,
)


def _make_verifier(key):
    auth = Authorizer(trusted_roots=[key.public_key])
    return MCPVerifier(authorizer=auth, control_plane=None, nonce_store=None)


# ---------------------------------------------------------------------------
# Robustness: arbitrary meta envelopes never crash
# ---------------------------------------------------------------------------


class TestMCPVerifierRobustness:
    @given(tool=st_tool_name, args=st_args_dict, meta=st_mcp_meta)
    @settings(max_examples=100)
    def test_verify_never_crashes(self, tool, args, meta):
        """MCPVerifier.verify returns MCPVerificationResult for any meta shape."""
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        result = verifier.verify(tool, args, meta=meta)
        assert isinstance(result, MCPVerificationResult)
        assert isinstance(result.allowed, bool)

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=30)
    def test_verify_none_meta_returns_denial(self, tool, args):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        result = verifier.verify(tool, args, meta=None)
        assert result.allowed is False
        assert result.jsonrpc_error_code == -32001

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=30)
    def test_verify_empty_meta_returns_denial(self, tool, args):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        result = verifier.verify(tool, args, meta={})
        assert result.allowed is False

    @given(
        tool=st_tool_name,
        args=st_args_dict,
        garbage=st.binary(min_size=1, max_size=200),
    )
    @settings(max_examples=30)
    def test_garbage_warrant_denied_cleanly(self, tool, args, garbage):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        meta = {
            "tenuo": {
                "warrant": base64.b64encode(garbage).decode(),
                "signature": base64.b64encode(b"garbage").decode(),
            }
        }
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is False
        assert result.jsonrpc_error_code is not None


# ---------------------------------------------------------------------------
# Payload size limits
# ---------------------------------------------------------------------------


class TestPayloadSizeLimits:
    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=10)
    def test_oversized_warrant_rejected(self, tool, args):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        oversized = "A" * (MAX_WARRANT_B64_BYTES + 1)
        meta = {"tenuo": {"warrant": oversized, "signature": "dGVzdA=="}}
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is False
        assert result.jsonrpc_error_code == -32602
        assert "too large" in result.denial_reason.lower()

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=10)
    def test_oversized_signature_rejected(self, tool, args):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        warrant = Warrant.issue(
            keypair=key, capabilities={tool: {}},
            ttl_seconds=3600, holder=key.public_key,
        )
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": "A" * (MAX_SIGNATURE_B64_BYTES + 1),
            }
        }
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is False
        assert result.jsonrpc_error_code == -32602

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=10)
    def test_too_many_approvals_rejected(self, tool, args):
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        warrant = Warrant.issue(
            keypair=key, capabilities={tool: {}},
            ttl_seconds=3600, holder=key.public_key,
        )
        meta = {
            "tenuo": {
                "warrant": warrant.to_base64(),
                "signature": base64.b64encode(b"sig").decode(),
                "approvals": ["dGVzdA=="] * (MAX_APPROVALS_COUNT + 1),
            }
        }
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is False
        assert result.jsonrpc_error_code == -32602

    @given(tool=st_tool_name, args=st_args_dict)
    @settings(max_examples=10)
    def test_exactly_at_limit_not_rejected(self, tool, args):
        """Warrant exactly at size limit is not rejected by size check."""
        key = SigningKey.generate()
        verifier = _make_verifier(key)
        meta = {
            "tenuo": {
                "warrant": "A" * MAX_WARRANT_B64_BYTES,
                "signature": "A" * MAX_SIGNATURE_B64_BYTES,
            }
        }
        result = verifier.verify(tool, args, meta=meta)
        # Should fail for decode reasons, NOT size limit reasons
        assert result.allowed is False
        assert "too large" not in (result.denial_reason or "").lower()


# ---------------------------------------------------------------------------
# Valid warrants are accepted (FFI actually executes)
# ---------------------------------------------------------------------------


class TestMCPVerifierAcceptsValidWarrant:
    @given(data=st_valid_mcp_envelope())
    @settings(max_examples=20)
    def test_valid_warrant_accepted(self, data):
        """A properly signed warrant with correct PoP is accepted."""
        meta, warrant, key, tool, args = data
        verifier = _make_verifier(key)
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is True
        assert result.tool == tool


# ---------------------------------------------------------------------------
# WarrantStack decode path
# ---------------------------------------------------------------------------


class TestWarrantStackDecode:
    @given(data=st_warrant_bundle())
    @settings(max_examples=20)
    def test_single_warrant_stack_accepted(self, data):
        """A single-element WarrantStack is correctly decoded and authorized."""
        warrant, key, tool, args = data
        from tenuo import encode_warrant_stack

        pop = _make_pop(warrant, key, tool, args)
        stack_b64 = encode_warrant_stack([warrant])
        meta = {
            "tenuo": {
                "warrant": stack_b64,
                "signature": base64.b64encode(pop).decode(),
            }
        }
        verifier = _make_verifier(key)
        result = verifier.verify(tool, args, meta=meta)
        assert result.allowed is True


def _make_pop(warrant, key, tool, args):
    return bytes(warrant.sign(key, tool, args, int(time.time())))
