"""MCPVerifier denials carry a presented chain and emit a signed receipt."""

from __future__ import annotations

import pytest

tenuo_core = pytest.importorskip("tenuo_core")

from tenuo import Pattern
from tenuo.mcp import (
    MCPVerifier,
    TENUO_CONSTRAINT_VIOLATION,
    TENUO_TOOL_NOT_AUTHORIZED,
)
from tenuo.receipts import InMemoryReceiptSink, ReceiptSigner
from tenuo_core import Authorizer, SigningKey, Warrant


@pytest.fixture
def issuer_key():
    return SigningKey.generate()


@pytest.fixture
def agent_key():
    return SigningKey.generate()


@pytest.fixture
def authorizer(issuer_key):
    return Authorizer(trusted_roots=[issuer_key.public_key])


@pytest.fixture
def warrant(issuer_key, agent_key):
    return Warrant.issue(
        issuer_key,
        capabilities={"read_file": {"path": Pattern("/data/*")}},
        holder=agent_key.public_key,
    )


def _meta(warrant, key, tool, args):
    import base64
    import time

    sig = warrant.sign(key, tool, args, int(time.time()))
    return {
        "tenuo": {
            "warrant": warrant.to_base64(),
            "signature": base64.b64encode(bytes(sig)).decode(),
        }
    }


def test_constraint_denial_carries_chain_and_tenuo_code(authorizer, warrant, agent_key):
    verifier = MCPVerifier(authorizer=authorizer, control_plane=False)
    args = {"path": "/etc/passwd"}
    result = verifier.verify("read_file", args, meta=_meta(warrant, agent_key, "read_file", args))

    assert not result.allowed
    assert result.error_type == "constraint_violation"
    assert result.error_code == TENUO_CONSTRAINT_VIOLATION
    assert result.presented_chain
    assert result.authorizer is not None
    assert result.verified_pop is not None
    assert result.to_jsonrpc_error()["data"]["code"] == TENUO_CONSTRAINT_VIOLATION


def test_wrong_tool_denial_carries_chain(authorizer, warrant, agent_key):
    verifier = MCPVerifier(authorizer=authorizer, control_plane=False)
    args = {"path": "/data/x"}
    result = verifier.verify("delete_file", args, meta=_meta(warrant, agent_key, "delete_file", args))

    assert not result.allowed
    assert result.error_code == TENUO_TOOL_NOT_AUTHORIZED
    assert result.presented_chain


def test_no_warrant_is_not_receipted(authorizer, issuer_key):
    sink = InMemoryReceiptSink()
    signer = ReceiptSigner(issuer_key, sink, authorizer=authorizer)
    verifier = MCPVerifier(authorizer=authorizer, control_plane=signer)
    result = verifier.verify("read_file", {"path": "/data/x"}, meta={})

    assert not result.allowed
    assert result.presented_chain is None
    signer.flush()
    assert len(sink.receipts) == 0


def test_constraint_denial_emits_a_signed_receipt(authorizer, warrant, agent_key, issuer_key):
    sink = InMemoryReceiptSink()
    signer = ReceiptSigner(issuer_key, sink, authorizer=authorizer)
    verifier = MCPVerifier(authorizer=authorizer, control_plane=signer)
    args = {"path": "/etc/passwd"}
    result = verifier.verify("read_file", args, meta=_meta(warrant, agent_key, "read_file", args))

    assert not result.allowed
    assert signer.flush()
    assert len(sink.receipts) == 1
    payload = tenuo_core.verify_receipt(sink.receipts[0])
    assert payload.outcome == "deny"
    assert payload.decision_code == "constraint-violation"
    assert payload.pop_signature is not None
