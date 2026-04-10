"""
Tests for tenuo.mcp.server — server-side MCP warrant verification.

All tests use real warrants / authorizers so we exercise the full
cryptographic stack, not mocks.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict

import pytest
from tenuo_core import Authorizer, SignedApproval, SigningKey, Warrant
from tenuo_core import py_compute_request_hash as compute_request_hash

from tenuo.mcp.server import (
    MCPAuthorizationError,
    MCPVerificationResult,
    MCPVerifier,
    verify_mcp_call,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def issuer_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def agent_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key: SigningKey) -> Authorizer:
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def simple_warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    """Root warrant: allows read_file on /data/*."""
    from tenuo import Pattern

    return Warrant.issue(
        issuer_key,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=agent_key.public_key,
    )


@pytest.fixture
def multi_tool_warrant(issuer_key: SigningKey, agent_key: SigningKey) -> Warrant:
    """Warrant covering two tools."""
    return Warrant.issue(
        issuer_key,
        capabilities={"read_file": {}, "list_dir": {}},
        holder=agent_key.public_key,
    )


def _encode_warrant(warrant: Warrant) -> str:
    return warrant.to_base64()


def _encode_pop(warrant: Warrant, key: SigningKey, tool: str, args: dict) -> str:
    import time

    sig = warrant.sign(key, tool, args, int(time.time()))
    return base64.b64encode(bytes(sig)).decode()


def _make_arguments(
    warrant: Warrant,
    key: SigningKey,
    tool: str,
    tool_args: Dict[str, Any],
    approvals: list | None = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Return (tool_args, meta) where meta = {"tenuo": {...}} for params._meta."""
    tenuo: Dict[str, Any] = {
        "warrant": _encode_warrant(warrant),
        "signature": _encode_pop(warrant, key, tool, tool_args),
    }
    if approvals:
        tenuo["approvals"] = [
            base64.b64encode(a.to_bytes()).decode() for a in approvals
        ]
    return dict(tool_args), {"tenuo": tenuo}


# ---------------------------------------------------------------------------
# MCPVerificationResult unit tests
# ---------------------------------------------------------------------------


class TestMCPVerificationResult:
    def test_raise_if_denied_raises_on_denial(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            denial_reason="Access denied",
            jsonrpc_error_code=-32001,
        )
        with pytest.raises(MCPAuthorizationError) as exc_info:
            result.raise_if_denied()
        assert exc_info.value.result is result

    def test_raise_if_denied_returns_self_on_success(self):
        result = MCPVerificationResult(
            allowed=True,
            tool="read_file",
            clean_arguments={"path": "/data/f.txt"},
            constraints={"path": "/data/f.txt"},
        )
        assert result.raise_if_denied() is result

    def test_to_jsonrpc_error_format(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            denial_reason="Expired",
            jsonrpc_error_code=-32001,
        )
        err = result.to_jsonrpc_error()
        assert err == {"code": -32001, "message": "Expired"}

    def test_to_jsonrpc_error_defaults_to_minus_32001(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
        )
        assert result.to_jsonrpc_error()["code"] == -32001

    def test_is_approval_required_true(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32002,
        )
        assert result.is_approval_required is True

    def test_is_approval_required_false(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32001,
        )
        assert result.is_approval_required is False

    def test_request_hash_field_defaults_to_none(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
        )
        assert result.request_hash is None

    def test_request_hash_in_to_jsonrpc_error(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32002,
            request_hash="abcd1234",
        )
        err = result.to_jsonrpc_error()
        assert err["code"] == -32002
        assert err["data"]["request_hash"] == "abcd1234"

    def test_to_jsonrpc_error_no_data_when_no_hash(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32001,
        )
        err = result.to_jsonrpc_error()
        assert "data" not in err


class TestMCPAuthorizationError:
    def test_carries_result(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            denial_reason="Denied",
            jsonrpc_error_code=-32001,
        )
        exc = MCPAuthorizationError(result)
        assert exc.result is result
        assert exc.jsonrpc_error_code == -32001
        assert exc.to_jsonrpc_error()["code"] == -32001

    def test_message_from_denial_reason(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            denial_reason="Warrant expired",
        )
        exc = MCPAuthorizationError(result)
        assert "Warrant expired" in str(exc)


# ---------------------------------------------------------------------------
# MCPVerifier — require_warrant semantics
# ---------------------------------------------------------------------------


class TestRequireWarrant:
    def test_no_tenuo_denied_by_default(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", {"path": "/data/f.txt"})
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
        dr = result.denial_reason or ""
        assert "No warrant" in dr
        assert "TenuoMiddleware" in dr
        assert "SecureMCPClient" in dr and "inject_warrant" in dr

    def test_missing_signature_includes_signature_hint(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
    ):
        meta = {"tenuo": {"warrant": simple_warrant.to_base64()}}
        result = MCPVerifier(authorizer=authorizer).verify(
            "read_file", {"path": "/data/f.txt"}, meta=meta
        )
        assert not result.allowed
        assert "_meta.tenuo.signature" in (result.denial_reason or "")

    def test_no_tenuo_allowed_when_require_warrant_false(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer, require_warrant=False)
        result = verifier.verify("read_file", {"path": "/data/f.txt"})
        assert result.allowed
        assert result.clean_arguments == {"path": "/data/f.txt"}

    def test_require_warrant_false_emits_to_control_plane(self, authorizer: Authorizer):
        """Unauthenticated calls with require_warrant=False must still emit
        to the control plane for audit."""

        class _Recorder:
            def __init__(self):
                self.calls: list = []

            def emit_for_enforcement(self, result, chain_result=None, latency_us=0, **kw):
                self.calls.append(
                    {"result": result, "chain_result": chain_result, "latency_us": latency_us}
                )

        cp = _Recorder()
        verifier = MCPVerifier(
            authorizer=authorizer, require_warrant=False, control_plane=cp
        )
        result = verifier.verify("read_file", {"path": "/data/f.txt"})
        assert result.allowed
        assert len(cp.calls) == 1
        assert cp.calls[0]["result"].allowed is True
        assert cp.calls[0]["chain_result"] is None

    def test_none_arguments_treated_as_empty(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", None)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_tenuo_not_dict_in_meta_treated_as_missing(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", {"path": "/x"}, meta={"tenuo": "not-a-dict"})
        assert not result.allowed
        assert "No warrant" in (result.denial_reason or "")


# ---------------------------------------------------------------------------
# MCPVerifier — successful authorization
# ---------------------------------------------------------------------------


class TestSuccessfulVerification:
    def test_valid_warrant_and_pop(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/data/log.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", arguments, meta=meta)

        assert result.allowed
        assert result.tool == "read_file"
        assert "_tenuo" not in result.clean_arguments
        assert result.clean_arguments == tool_args

    def test_clean_arguments_never_contains_tenuo(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        arguments, meta = _make_arguments(
            simple_warrant, agent_key, "read_file", {"path": "/data/f.txt"}
        )
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)
        assert "_tenuo" not in result.clean_arguments
        assert "_tenuo" not in result.constraints

    def test_warrant_id_extracted(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        arguments, meta = _make_arguments(
            simple_warrant, agent_key, "read_file", {"path": "/data/f.txt"}
        )
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)
        assert result.warrant_id is not None

    def test_verify_or_raise_returns_clean_arguments(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/data/file.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        clean = MCPVerifier(authorizer=authorizer).verify_or_raise("read_file", arguments, meta=meta)
        assert clean == tool_args

    def test_warrant_with_pop_passes(
        self,
        issuer_key: SigningKey,
    ):
        """Warrants with a PoP signature pass verification."""
        agent_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])
        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {}},
            holder=agent_key.public_key,
        )
        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(warrant, agent_key, "read_file", tool_args)
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)
        assert result.allowed


# ---------------------------------------------------------------------------
# MCPVerifier — denial scenarios
# ---------------------------------------------------------------------------


class TestDenialScenarios:
    def test_constraint_violation(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        # Warrant allows /data/*, but call uses /etc/passwd
        tool_args = {"path": "/etc/passwd"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_wrong_tool(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        # Warrant covers read_file, but caller claims list_dir
        tool_args = {"path": "/data/"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "list_dir", tool_args)

        result = MCPVerifier(authorizer=authorizer).verify("list_dir", arguments, meta=meta)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_malformed_warrant_base64(self, authorizer: Authorizer):
        meta = {"tenuo": {"warrant": "not-valid-base64!!!"}}
        result = MCPVerifier(authorizer=authorizer).verify("read_file", {"path": "/x"}, meta=meta)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
        assert "Malformed warrant" in (result.denial_reason or "")

    def test_malformed_signature_base64(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
    ):
        meta = {
            "tenuo": {
                "warrant": simple_warrant.to_base64(),
                "signature": "!!!not-base64!!!",
            }
        }
        result = MCPVerifier(authorizer=authorizer).verify("read_file", {"path": "/data/f.txt"}, meta=meta)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
        assert "Malformed signature" in (result.denial_reason or "")

    def test_malformed_approval_base64(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        meta["tenuo"]["approvals"] = ["!!!bad!!!"]

        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)
        assert not result.allowed
        assert "Malformed approval" in (result.denial_reason or "")

    def test_untrusted_issuer(self, agent_key: SigningKey):
        # Authorizer trusts key_A, but warrant is signed by key_B
        trusted_key = SigningKey.generate()
        untrusted_issuer = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[trusted_key.public_key])

        warrant = Warrant.issue(
            untrusted_issuer,
            capabilities={"read_file": {}},
            holder=agent_key.public_key,
        )
        arguments, meta = _make_arguments(warrant, agent_key, "read_file", {"path": "/x"})
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments, meta=meta)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_verify_or_raise_raises_on_denial(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/etc/shadow"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        with pytest.raises(MCPAuthorizationError) as exc_info:
            MCPVerifier(authorizer=authorizer).verify_or_raise("read_file", arguments, meta=meta)
        assert exc_info.value.jsonrpc_error_code == -32001


# ---------------------------------------------------------------------------
# MCPVerifier — approval gate triggered
# ---------------------------------------------------------------------------


class TestApprovalGateTriggered:
    def test_gate_fires_returns_minus_32002(
        self,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        approver_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"transfer": {}},
            holder=agent_key.public_key,
            approval_gates={"transfer": None},  # whole-tool gate
            required_approvers=[approver_key.public_key],
            min_approvals=1,
        )
        arguments, meta = _make_arguments(warrant, agent_key, "transfer", {"amount": 100})

        result = MCPVerifier(authorizer=authorizer).verify("transfer", arguments, meta=meta)

        assert not result.allowed
        assert result.is_approval_required
        assert result.jsonrpc_error_code == -32002
        assert "approvals" in (result.denial_reason or "").lower()
        assert result.request_hash is not None, "request_hash must be populated from Rust"
        assert len(result.request_hash) > 0

    def test_gate_request_hash_in_jsonrpc_error(
        self,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        approver_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"transfer": {}},
            holder=agent_key.public_key,
            approval_gates={"transfer": None},
            required_approvers=[approver_key.public_key],
            min_approvals=1,
        )
        arguments, meta = _make_arguments(warrant, agent_key, "transfer", {"amount": 100})

        result = MCPVerifier(authorizer=authorizer).verify("transfer", arguments, meta=meta)
        err = result.to_jsonrpc_error()
        assert err["code"] == -32002
        assert "data" in err
        assert err["data"]["request_hash"] == result.request_hash

    def test_gate_satisfied_with_valid_approval(
        self,
        issuer_key: SigningKey,
        agent_key: SigningKey,
    ):
        approver_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[issuer_key.public_key])

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"transfer": {}},
            holder=agent_key.public_key,
            approval_gates={"transfer": None},
            required_approvers=[approver_key.public_key],
            min_approvals=1,
        )

        tool_args: Dict[str, Any] = {"amount": 100}

        # Build a real SignedApproval for this call using py_compute_request_hash
        from tenuo_core import ApprovalPayload

        request_hash = compute_request_hash(
            warrant.id, "transfer", tool_args, agent_key.public_key
        )
        now = int(time.time())
        payload = ApprovalPayload(
            request_hash=request_hash,
            nonce=os.urandom(16),
            external_id="test-approver",
            approved_at=now,
            expires_at=now + 300,
        )
        approval = SignedApproval.create(payload, approver_key)

        arguments, meta = _make_arguments(
            warrant, agent_key, "transfer", tool_args, approvals=[approval]
        )

        result = MCPVerifier(authorizer=authorizer).verify("transfer", arguments, meta=meta)

        assert result.allowed
        assert not result.is_approval_required


# ---------------------------------------------------------------------------
# MCPVerifier — with CompiledMcpConfig
# ---------------------------------------------------------------------------


class TestWithExtractionConfig:
    @pytest.fixture
    def mcp_config(self, tmp_path):
        """Write a minimal mcp-config.yaml and compile it."""
        from tenuo_core import CompiledMcpConfig, McpConfig

        yaml = tmp_path / "mcp.yaml"
        yaml.write_text(
            """
version: "1"
tools:
  read_file:
    description: "Read a file"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
"""
        )
        return CompiledMcpConfig.compile(McpConfig.from_file(str(yaml)))

    def test_extraction_maps_field_names(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config,
    ):
        from tenuo import Pattern

        from tenuo import Range

        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {"path": Pattern("/data/*"), "max_size": Range(max=10 * 1024 * 1024)}},
            holder=agent_key.public_key,
        )
        # When using CompiledMcpConfig, the client computes PoP over the
        # extracted (renamed) constraints — both sides share the config.
        # The extracted constraints use "max_size" (mapped from "maxSize").
        extracted_constraints = {"path": "/data/log.txt", "max_size": 2048}
        pop_sig = _encode_pop(warrant, agent_key, "read_file", extracted_constraints)

        raw_body = {"path": "/data/log.txt", "maxSize": 2048}
        meta = {"tenuo": {"warrant": warrant.to_base64(), "signature": pop_sig}}

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", raw_body, meta=meta
        )

        assert result.allowed
        # constraints should use the mapped name ("max_size" not "maxSize")
        assert "max_size" in result.constraints or "path" in result.constraints

    def test_extraction_error_returns_minus_32602(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config,
    ):
        warrant = Warrant.issue(
            issuer_key,
            capabilities={"read_file": {}},
            holder=agent_key.public_key,
        )
        # Missing required 'path' field
        arguments, meta = _make_arguments(warrant, agent_key, "read_file", {"maxSize": 1024})

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", arguments, meta=meta
        )

        assert not result.allowed
        assert result.jsonrpc_error_code == -32602

    def test_unknown_tool_in_config_returns_minus_32602(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config,
    ):
        warrant = Warrant.issue(
            issuer_key,
            capabilities={"unknown_tool": {}},
            holder=agent_key.public_key,
        )
        arguments, meta = _make_arguments(
            warrant, agent_key, "unknown_tool", {"path": "/x"}
        )

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "unknown_tool", arguments, meta=meta
        )

        assert not result.allowed
        assert result.jsonrpc_error_code == -32602

    def test_pop_signed_over_raw_body_not_extracted_hints_config_sync(
        self,
        authorizer: Authorizer,
        issuer_key: SigningKey,
        agent_key: SigningKey,
        mcp_config,
    ):
        from tenuo import Pattern, Range

        warrant = Warrant.issue(
            issuer_key,
            capabilities={
                "read_file": {
                    "path": Pattern("/data/*"),
                    "max_size": Range(max=5000),
                }
            },
            holder=agent_key.public_key,
        )
        # Correct server-side extraction uses max_size; PoP must sign that dict.
        # Sign over wrong (camelCase) shape → denial with CompiledMcpConfig hint.
        wrong_for_pop = {"path": "/data/log.txt", "maxSize": 2048}
        pop_sig = _encode_pop(warrant, agent_key, "read_file", wrong_for_pop)
        raw_body = {"path": "/data/log.txt", "maxSize": 2048}
        meta = {"tenuo": {"warrant": warrant.to_base64(), "signature": pop_sig}}

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", raw_body, meta=meta
        )

        assert not result.allowed
        dr = result.denial_reason or ""
        assert "CompiledMcpConfig" in dr


# ---------------------------------------------------------------------------
# verify_mcp_call standalone function
# ---------------------------------------------------------------------------


class TestVerifyMcpCall:
    def test_standalone_authorized(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        result = verify_mcp_call("read_file", arguments, authorizer=authorizer, meta=meta)
        assert result.allowed

    def test_standalone_denied(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/etc/shadow"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        result = verify_mcp_call("read_file", arguments, authorizer=authorizer, meta=meta)
        assert not result.allowed

    def test_standalone_no_warrant(self, authorizer: Authorizer):
        result = verify_mcp_call("read_file", {"path": "/x"}, authorizer=authorizer)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001


# ---------------------------------------------------------------------------
# Unmapped-argument warning tests
# ---------------------------------------------------------------------------


class TestUnmappedArgumentWarning:
    """Verify that MCPVerifier warns when tool args are not mapped to constraints."""

    def test_warns_on_unmapped_args(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
        caplog: pytest.LogCaptureFixture,
    ):
        """Args not present in extraction.constraints trigger a warning."""
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_extraction = MagicMock()
        mock_extraction.constraints = {"path": "/data/f.txt"}
        mock_config.extract_constraints.return_value = mock_extraction

        verifier = MCPVerifier(authorizer=authorizer, config=mock_config)

        constraint_args = {"path": "/data/f.txt"}
        tool_args = {"path": "/data/f.txt", "dry_run": True, "format": "json"}
        _, meta = _make_arguments(simple_warrant, agent_key, "read_file", constraint_args)

        import logging
        with caplog.at_level(logging.WARNING, logger="tenuo.mcp.server"):
            verifier.verify("read_file", tool_args, meta=meta)

        assert any("unauthenticated" in r.message.lower() for r in caplog.records)
        assert any("dry_run" in r.message for r in caplog.records)
        assert any("format" in r.message for r in caplog.records)

    def test_no_warning_when_all_args_mapped(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
        caplog: pytest.LogCaptureFixture,
    ):
        """No warning when every arg has a corresponding constraint."""
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_extraction = MagicMock()
        mock_extraction.constraints = {"path": "/data/f.txt"}
        mock_config.extract_constraints.return_value = mock_extraction

        verifier = MCPVerifier(authorizer=authorizer, config=mock_config)

        tool_args = {"path": "/data/f.txt"}
        _, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        import logging
        with caplog.at_level(logging.WARNING, logger="tenuo.mcp.server"):
            verifier.verify("read_file", tool_args, meta=meta)

        assert not any("unauthenticated" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# Nonce / replay-prevention tests
# ---------------------------------------------------------------------------


class TestNonceReplayPrevention:
    """Verify that MCPVerifier rejects replayed PoP signatures."""

    def test_replay_rejected_with_explicit_nonce_store(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        """Second call with the exact same PoP bytes is rejected."""
        from tenuo.nonce import NonceStore

        ns = NonceStore(ttl_seconds=120)
        verifier = MCPVerifier(authorizer=authorizer, nonce_store=ns)

        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        result1 = verifier.verify("read_file", arguments, meta=meta)
        assert result1.allowed

        result2 = verifier.verify("read_file", arguments, meta=meta)
        assert not result2.allowed
        assert "replay" in (result2.denial_reason or "").lower()
        assert result2.jsonrpc_error_code == -32001

    def test_no_replay_check_without_nonce_store(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Without a nonce store, duplicate PoPs are accepted (stateless mode)."""
        from tenuo import nonce as nonce_mod
        monkeypatch.setattr(nonce_mod, "_default_store", None)

        verifier = MCPVerifier(authorizer=authorizer)

        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        result1 = verifier.verify("read_file", arguments, meta=meta)
        assert result1.allowed

        result2 = verifier.verify("read_file", arguments, meta=meta)
        assert result2.allowed

    def test_distinct_pops_both_admitted(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        """Two calls with different args produce distinct PoPs — both pass."""
        from tenuo.nonce import NonceStore

        ns = NonceStore(ttl_seconds=120)
        verifier = MCPVerifier(authorizer=authorizer, nonce_store=ns)

        args1 = {"path": "/data/a.txt"}
        arguments1, meta1 = _make_arguments(simple_warrant, agent_key, "read_file", args1)

        args2 = {"path": "/data/b.txt"}
        arguments2, meta2 = _make_arguments(simple_warrant, agent_key, "read_file", args2)

        result1 = verifier.verify("read_file", arguments1, meta=meta1)
        assert result1.allowed

        result2 = verifier.verify("read_file", arguments2, meta=meta2)
        assert result2.allowed

    def test_default_nonce_store_used_when_enabled(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """When enable_default_nonce_store() was called, MCPVerifier picks it up."""
        from tenuo.nonce import NonceStore
        from tenuo import nonce as nonce_mod

        default_ns = NonceStore(ttl_seconds=120)
        monkeypatch.setattr(nonce_mod, "_default_store", default_ns)

        verifier = MCPVerifier(authorizer=authorizer)

        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        result1 = verifier.verify("read_file", arguments, meta=meta)
        assert result1.allowed

        result2 = verifier.verify("read_file", arguments, meta=meta)
        assert not result2.allowed
        assert "replay" in (result2.denial_reason or "").lower()


# ---------------------------------------------------------------------------
# Control plane emission coverage tests
# ---------------------------------------------------------------------------


class TestControlPlaneEmissions:
    """Verify that MCPVerifier emits to the control plane on all paths."""

    def test_extraction_error_emits(self, authorizer: Authorizer):
        """Extraction failure (step 1) emits a deny event."""
        from unittest.mock import MagicMock

        mock_config = MagicMock()
        mock_config.extract_constraints.side_effect = ValueError("missing field 'path'")
        mock_cp = MagicMock()

        verifier = MCPVerifier(authorizer=authorizer, config=mock_config, control_plane=mock_cp)
        result = verifier.verify("read_file", {"path": "/x"}, meta={"tenuo": {}})

        assert not result.allowed
        mock_cp.emit_for_enforcement.assert_called_once()
        emitted = mock_cp.emit_for_enforcement.call_args
        assert emitted[0][0].allowed is False

    def test_missing_warrant_strict_emits(self, authorizer: Authorizer):
        """Missing warrant with require_warrant=True emits a deny event."""
        from unittest.mock import MagicMock

        mock_cp = MagicMock()
        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        result = verifier.verify("read_file", {"path": "/x"})

        assert not result.allowed
        mock_cp.emit_for_enforcement.assert_called_once()

    def test_malformed_warrant_emits(self, authorizer: Authorizer):
        """Malformed warrant base64 emits a deny event."""
        from unittest.mock import MagicMock

        mock_cp = MagicMock()
        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)
        result = verifier.verify(
            "read_file", {"path": "/x"},
            meta={"tenuo": {"warrant": "not-valid-base64!!!", "signature": "abc"}},
        )

        assert not result.allowed
        mock_cp.emit_for_enforcement.assert_called_once()

    def test_authorized_call_emits_allow(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        """Successful authorization emits an allow event with chain_result."""
        from unittest.mock import MagicMock

        mock_cp = MagicMock()
        verifier = MCPVerifier(authorizer=authorizer, control_plane=mock_cp)

        tool_args = {"path": "/data/f.txt"}
        arguments, meta = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        result = verifier.verify("read_file", arguments, meta=meta)

        assert result.allowed
        mock_cp.emit_for_enforcement.assert_called_once()
        emitted = mock_cp.emit_for_enforcement.call_args
        assert emitted[0][0].allowed is True
        assert emitted[1].get("chain_result") is not None

    def test_mcp_result_clean_arguments_in_emission(
        self,
        authorizer: Authorizer,
    ):
        """emit_for_enforcement resolves clean_arguments for MCPVerificationResult."""
        from unittest.mock import MagicMock

        from tenuo.control_plane import ControlPlaneClient

        mcp_result = MCPVerificationResult(
            allowed=True,
            tool="read_file",
            clean_arguments={"path": "/data/f.txt"},
            constraints={"path": "/data/f.txt"},
        )

        mock_inner = MagicMock()
        client = ControlPlaneClient.__new__(ControlPlaneClient)
        client._inner = mock_inner

        client.emit_for_enforcement(mcp_result)

        mock_inner.emit_allow.assert_called_once()
        call_args = mock_inner.emit_allow.call_args
        arguments_json = call_args[0][7]
        assert arguments_json is not None
        assert "/data/f.txt" in arguments_json
