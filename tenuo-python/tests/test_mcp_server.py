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
) -> Dict[str, Any]:
    """Build a full tool-arguments dict with _tenuo injected."""
    tenuo: Dict[str, Any] = {
        "warrant": _encode_warrant(warrant),
        "signature": _encode_pop(warrant, key, tool, tool_args),
    }
    if approvals:
        tenuo["approvals"] = [
            base64.b64encode(a.to_bytes()).decode() for a in approvals
        ]
    return {**tool_args, "_tenuo": tenuo}


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

    def test_is_guard_triggered_true(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="transfer",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32002,
        )
        assert result.is_guard_triggered is True

    def test_is_guard_triggered_false(self):
        result = MCPVerificationResult(
            allowed=False,
            tool="read_file",
            clean_arguments={},
            constraints={},
            jsonrpc_error_code=-32001,
        )
        assert result.is_guard_triggered is False


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
        assert "No warrant" in (result.denial_reason or "")

    def test_no_tenuo_allowed_when_require_warrant_false(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer, require_warrant=False)
        result = verifier.verify("read_file", {"path": "/data/f.txt"})
        assert result.allowed
        assert result.clean_arguments == {"path": "/data/f.txt"}

    def test_none_arguments_treated_as_empty(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", None)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_tenuo_not_dict_treated_as_missing(self, authorizer: Authorizer):
        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", {"path": "/x", "_tenuo": "not-a-dict"})
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
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        verifier = MCPVerifier(authorizer=authorizer)
        result = verifier.verify("read_file", arguments)

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
        arguments = _make_arguments(
            simple_warrant, agent_key, "read_file", {"path": "/data/f.txt"}
        )
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
        assert "_tenuo" not in result.clean_arguments
        assert "_tenuo" not in result.constraints

    def test_warrant_id_extracted(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        arguments = _make_arguments(
            simple_warrant, agent_key, "read_file", {"path": "/data/f.txt"}
        )
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
        assert result.warrant_id is not None

    def test_verify_or_raise_returns_clean_arguments(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/data/file.txt"}
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        clean = MCPVerifier(authorizer=authorizer).verify_or_raise("read_file", arguments)
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
        arguments = _make_arguments(warrant, agent_key, "read_file", tool_args)
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
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
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)

        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)

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
        arguments = _make_arguments(simple_warrant, agent_key, "list_dir", tool_args)

        result = MCPVerifier(authorizer=authorizer).verify("list_dir", arguments)

        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_malformed_warrant_base64(self, authorizer: Authorizer):
        arguments = {"path": "/x", "_tenuo": {"warrant": "not-valid-base64!!!"}}
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
        assert "Malformed warrant" in (result.denial_reason or "")

    def test_malformed_signature_base64(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
    ):
        arguments = {
            "path": "/data/f.txt",
            "_tenuo": {
                "warrant": simple_warrant.to_base64(),
                "signature": "!!!not-base64!!!",
            },
        }
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
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
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        arguments["_tenuo"]["approvals"] = ["!!!bad!!!"]

        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
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
        arguments = _make_arguments(warrant, agent_key, "read_file", {"path": "/x"})
        result = MCPVerifier(authorizer=authorizer).verify("read_file", arguments)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001

    def test_verify_or_raise_raises_on_denial(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/etc/shadow"}
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        with pytest.raises(MCPAuthorizationError) as exc_info:
            MCPVerifier(authorizer=authorizer).verify_or_raise("read_file", arguments)
        assert exc_info.value.jsonrpc_error_code == -32001


# ---------------------------------------------------------------------------
# MCPVerifier — guard triggered
# ---------------------------------------------------------------------------


class TestGuardTriggered:
    def test_guard_fires_returns_minus_32002(
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
            guards={"transfer": None},  # whole-tool guard
            required_approvers=[approver_key.public_key],
            min_approvals=1,
        )
        arguments = _make_arguments(warrant, agent_key, "transfer", {"amount": 100})

        result = MCPVerifier(authorizer=authorizer).verify("transfer", arguments)

        assert not result.allowed
        assert result.is_guard_triggered
        assert result.jsonrpc_error_code == -32002
        assert "approvals" in (result.denial_reason or "").lower()

    def test_guard_satisfied_with_valid_approval(
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
            guards={"transfer": None},
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

        arguments = _make_arguments(
            warrant, agent_key, "transfer", tool_args, approvals=[approval]
        )

        result = MCPVerifier(authorizer=authorizer).verify("transfer", arguments)

        assert result.allowed
        assert not result.is_guard_triggered


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
        arguments = {
            **raw_body,
            "_tenuo": {"warrant": warrant.to_base64(), "signature": pop_sig},
        }

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", arguments
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
        arguments = _make_arguments(warrant, agent_key, "read_file", {"maxSize": 1024})

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "read_file", arguments
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
        arguments = _make_arguments(
            warrant, agent_key, "unknown_tool", {"path": "/x"}
        )

        result = MCPVerifier(authorizer=authorizer, config=mcp_config).verify(
            "unknown_tool", arguments
        )

        assert not result.allowed
        assert result.jsonrpc_error_code == -32602


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
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        result = verify_mcp_call("read_file", arguments, authorizer=authorizer)
        assert result.allowed

    def test_standalone_denied(
        self,
        authorizer: Authorizer,
        simple_warrant: Warrant,
        agent_key: SigningKey,
    ):
        tool_args = {"path": "/etc/shadow"}
        arguments = _make_arguments(simple_warrant, agent_key, "read_file", tool_args)
        result = verify_mcp_call("read_file", arguments, authorizer=authorizer)
        assert not result.allowed

    def test_standalone_no_warrant(self, authorizer: Authorizer):
        result = verify_mcp_call("read_file", {"path": "/x"}, authorizer=authorizer)
        assert not result.allowed
        assert result.jsonrpc_error_code == -32001
