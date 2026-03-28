"""Tests for @guard(verify_mode='verify') — server-side PoP verification.

These tests cover the scenario where a client has already computed a
Proof-of-Possession signature and sends it alongside the request.  The server
uses @guard(verify_mode='verify') to verify the pre-computed signature without
needing the private key.
"""

import time

import pytest

from tenuo import Authorizer, Pattern, SigningKey, Warrant, configure, guard, warrant_scope
from tenuo.config import reset_config
from tenuo.constraints import Constraints
from tenuo.exceptions import (
    ConfigurationError,
    MissingSignature,
    SignatureInvalid,
    ScopeViolation,
)


@pytest.fixture(autouse=True)
def reset_tenuo_config():
    reset_config()
    yield
    reset_config()


@pytest.fixture
def issuer_kp():
    return SigningKey.generate()


@pytest.fixture
def holder_kp():
    return SigningKey.generate()


@pytest.fixture
def simple_warrant(issuer_kp, holder_kp):
    return Warrant.mint(
        keypair=issuer_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=holder_kp.public_key,
        ttl_seconds=300,
    )


# ============================================================================
# Basic verify path
# ============================================================================


def test_verify_mode_allows_valid_presigned_request(issuer_kp, holder_kp, simple_warrant):
    """Server-side: pre-computed PoP signature is accepted when valid."""

    sig = simple_warrant.sign(holder_kp, "read_file", {"path": "/data/report.csv"}, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        result = read_file(path="/data/report.csv", _pop=bytes(sig))

    assert result == "content of /data/report.csv"


def test_verify_mode_rejects_wrong_signature(issuer_kp, holder_kp, simple_warrant):
    """Server-side: PoP signature from a different key is rejected."""

    wrong_kp = SigningKey.generate()
    bad_sig = simple_warrant.sign(wrong_kp, "read_file", {"path": "/data/report.csv"}, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        with pytest.raises(SignatureInvalid):
            read_file(path="/data/report.csv", _pop=bytes(bad_sig))


def test_verify_mode_rejects_wrong_tool_in_signature(issuer_kp, holder_kp, simple_warrant):
    """Server-side: PoP signed for a different tool is rejected."""

    # Sign for 'delete_file' but call as 'read_file'
    wrong_tool_sig = simple_warrant.sign(holder_kp, "delete_file", {"path": "/data/report.csv"}, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        with pytest.raises((SignatureInvalid, ScopeViolation)):
            read_file(path="/data/report.csv", _pop=bytes(wrong_tool_sig))


def test_verify_mode_requires_extract_signature(issuer_kp, simple_warrant):
    """verify_mode without extract_signature raises MissingSignature."""

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        # No extract_signature provided — returns None
    )
    def read_file(path: str) -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        with pytest.raises(MissingSignature):
            read_file(path="/data/report.csv")


def test_verify_mode_requires_authorizer_or_trusted_roots(simple_warrant):
    """verify_mode without authorizer= or trusted_roots= raises ConfigurationError."""

    @guard(
        tool="read_file",
        verify_mode="verify",
        # Neither trusted_roots nor authorizer provided
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        with pytest.raises(ConfigurationError):
            read_file(path="/data/report.csv", _pop=b"\x00" * 64)


def test_verify_mode_accepts_explicit_authorizer(issuer_kp, holder_kp, simple_warrant):
    """verify_mode with an explicit Authorizer= works without trusted_roots on decorator."""

    sig = simple_warrant.sign(holder_kp, "read_file", {"path": "/data/x"}, int(time.time()))
    auth = Authorizer(trusted_roots=[issuer_kp.public_key])

    @guard(
        tool="read_file",
        verify_mode="verify",
        authorizer=auth,
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        result = read_file(path="/data/x", _pop=bytes(sig))

    assert result == "content of /data/x"


def test_verify_mode_uses_global_configure_trusted_roots(issuer_kp, holder_kp, simple_warrant):
    """verify_mode falls back to configure(trusted_roots=[...]) when no explicit roots given."""

    configure(trusted_roots=[issuer_kp.public_key])
    sig = simple_warrant.sign(holder_kp, "read_file", {"path": "/data/y"}, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
    )
    def read_file(path: str, _pop: bytes = b"") -> str:
        return f"content of {path}"

    with warrant_scope(simple_warrant):
        result = read_file(path="/data/y", _pop=bytes(sig))

    assert result == "content of /data/y"


# ============================================================================
# Delegation chain verification
# ============================================================================


def test_verify_mode_with_delegation_chain(issuer_kp, holder_kp):
    """verify_mode check_chain path validates a two-level delegation chain."""

    root = Warrant.mint(
        keypair=issuer_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=issuer_kp.public_key,
        ttl_seconds=300,
    )
    child = root.attenuate(
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/reports/*")}),
        signing_key=issuer_kp,
        holder=holder_kp.public_key,
        ttl_seconds=60,
    )

    args = {"path": "/data/reports/q3.pdf"}
    sig = child.sign(holder_kp, "read_file", args, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
        extract_chain=lambda *a, **kw: kw.get("_chain"),
    )
    def read_file(path: str, _pop: bytes = b"", _chain: list = None) -> str:
        return f"content of {path}"

    with warrant_scope(child):
        result = read_file(path="/data/reports/q3.pdf", _pop=bytes(sig), _chain=[root])

    assert result == "content of /data/reports/q3.pdf"


def test_verify_mode_chain_rejects_unauthorized_path(issuer_kp, holder_kp):
    """verify_mode chain: child warrant constraint is enforced (path not in child scope)."""

    root = Warrant.mint(
        keypair=issuer_kp,
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/*")}),
        holder=issuer_kp.public_key,
        ttl_seconds=300,
    )
    child = root.attenuate(
        capabilities=Constraints.for_tool("read_file", {"path": Pattern("/data/reports/*")}),
        signing_key=issuer_kp,
        holder=holder_kp.public_key,
        ttl_seconds=60,
    )

    # Sign for a path outside the child's allowed scope
    forbidden_args = {"path": "/data/other/secret.txt"}
    sig = child.sign(holder_kp, "read_file", forbidden_args, int(time.time()))

    @guard(
        tool="read_file",
        verify_mode="verify",
        trusted_roots=[issuer_kp.public_key],
        extract_signature=lambda *a, **kw: kw.get("_pop"),
        extract_args=lambda *a, **kw: {k: v for k, v in kw.items() if not k.startswith("_")},
        extract_chain=lambda *a, **kw: kw.get("_chain"),
    )
    def read_file(path: str, _pop: bytes = b"", _chain: list = None) -> str:
        return f"content of {path}"

    with warrant_scope(child):
        with pytest.raises((ScopeViolation, SignatureInvalid)):
            read_file(path="/data/other/secret.txt", _pop=bytes(sig), _chain=[root])
