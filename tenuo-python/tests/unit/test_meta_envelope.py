"""The core `_meta.tenuo` vector is the same string in Python as in Rust."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tenuo.meta import argument_json
from tenuo.mcp.server import MCPVerifier
from tenuo_core import Authorizer, SigningKey, Warrant, args_from_json, decode_meta, sign_meta, verify_meta

_VECTOR = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "tenuo-meta.json").read_text()
)


def test_python_matches_core_meta_vector():
    holder = SigningKey.from_bytes(bytes.fromhex(_VECTOR["holder_seed_hex"]))
    decoded = decode_meta(_VECTOR["warrant"], _VECTOR["signature"])
    signed = sign_meta(
        decoded["warrants"],
        holder,
        _VECTOR["tool"],
        _VECTOR["args_json"],
        _VECTOR["timestamp"],
    )

    assert signed["warrant"] == _VECTOR["warrant"]
    assert signed["signature"] == _VECTOR["signature"]
    assert verify_meta(
        _VECTOR["warrant"],
        _VECTOR["signature"],
        _VECTOR["tool"],
        _VECTOR["args_json"],
        _VECTOR["timestamp"],
    )
    assert not verify_meta(
        _VECTOR["warrant"],
        _VECTOR["signature"],
        _VECTOR["tool"],
        _VECTOR["rejected_args_json"],
        _VECTOR["timestamp"],
    )
    signed_args = args_from_json(_VECTOR["args_json"])
    assert "note" in signed_args
    assert signed_args["note"] is None

    float_signed = sign_meta(
        decoded["warrants"],
        holder,
        _VECTOR["tool"],
        _VECTOR["float_args_json"],
        _VECTOR["timestamp"],
    )
    assert float_signed["signature"] == _VECTOR["float_signature"]
    assert argument_json({"limit": 1.0, "note": None, "path": "/data/ok"}) == (
        '{"limit":1,"note":null,"path":"/data/ok"}'
    )
    assert args_from_json('{"n":1.0}') == args_from_json('{"n":1}')


@pytest.mark.parametrize("value", [0.9384646938271072, 0.9384646938271073, 0.5862090086938249])
def test_core_preserves_host_float(value):
    assert args_from_json(argument_json({"n": value}))["n"] == value


@pytest.mark.parametrize(
    ("original", "changed"),
    [
        ({}, {"target": None}),
        ({"items": [1, 2]}, {"items": [None, 1, 2]}),
        ({"items": [[1, 2]]}, {"items": [[1, None, 2]]}),
        ({"target": None}, {}),
        ({"n": 0.9384646938271072}, {"n": 0.9384646938271073}),
    ],
)
def test_mcp_rejects_argument_tampering(original, changed):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.issue(issuer, capabilities={"test": {}}, holder=holder.public_key)
    timestamp = int(time.time())
    envelope = sign_meta([warrant], holder, "test", argument_json(original), timestamp)
    assert not verify_meta(
        envelope["warrant"], envelope["signature"], "test", argument_json(changed), timestamp
    )
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[issuer.public_key]))
    assert verifier.verify("test", original, meta={"tenuo": envelope}).allowed
    denied = verifier.verify("test", changed, meta={"tenuo": envelope})
    assert not denied.allowed
    assert denied.jsonrpc_error_code == -32001
