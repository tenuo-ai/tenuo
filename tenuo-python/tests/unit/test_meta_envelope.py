"""The core `_meta.tenuo` vector is the same string in Python as in Rust."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tenuo.meta import argument_json
from tenuo.exceptions import ValidationError
from tenuo.mcp.server import MCPVerifier
from tenuo_core import Authorizer, SigningKey, Warrant, args_from_json, decode_meta, sign_meta, verify_meta, verify_meta_pop

_VECTOR = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "tenuo-meta.json").read_text()
)
_SUITE = json.loads(
    (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "tenuo-meta-conformance.json").read_text()
)


def test_delegated_approval_vector():
    vector = _SUITE["delegated"]
    holder = SigningKey.from_bytes(bytes.fromhex(vector["holder_seed_hex"]))
    decoded = decode_meta(vector["warrant"], vector["signature"], vector["approvals"])
    assert len(decoded["warrants"]) == 2
    assert len(decoded["approvals"]) == 1
    decoded["approvals"][0].verify()
    signed = sign_meta(decoded["warrants"], holder, vector["tool"], vector["args_json"], vector["timestamp"], decoded["approvals"])
    assert signed == {key: vector[key] for key in ("warrant", "signature", "approvals")}
    assert verify_meta_pop(vector["warrant"], vector["signature"], vector["tool"], vector["args_json"], vector["timestamp"])


@pytest.mark.parametrize("case", _SUITE["valid"])
def test_shared_argument_conformance(case):
    holder = SigningKey.from_bytes(bytes.fromhex(_VECTOR["holder_seed_hex"]))
    decoded = decode_meta(_VECTOR["warrant"], _VECTOR["signature"])
    meta = sign_meta(decoded["warrants"], holder, _VECTOR["tool"], case["args"], _VECTOR["timestamp"])
    assert verify_meta_pop(meta["warrant"], meta["signature"], _VECTOR["tool"], case["equivalent"], _VECTOR["timestamp"])
    assert not verify_meta_pop(meta["warrant"], meta["signature"], _VECTOR["tool"], case["tampered"], _VECTOR["timestamp"])


@pytest.mark.parametrize("text", _SUITE["invalid_arguments"])
def test_shared_invalid_arguments(text):
    with pytest.raises(ValueError) as caught:
        args_from_json(text)
    assert caught.value.code == "invalid_arguments"


@pytest.mark.parametrize("case", _SUITE["invalid_envelopes"])
def test_shared_invalid_envelopes(case):
    envelope = {**_SUITE["delegated"], **case}
    with pytest.raises((ValueError, TypeError, ValidationError)):
        decode_meta(envelope["warrant"], envelope["signature"], envelope["approvals"])


@pytest.mark.parametrize("args,code", [
    ({"n": float("nan")}, "invalid_arguments"),
    ({1: "a", "1": "b"}, "invalid_arguments"),
    ({"n": 2**64 + 1}, "invalid_arguments"),
    ({"n": -(2**63) - 1}, "invalid_arguments"),
    ({"secret": "x" * 262145}, "payload_too_large"),
    ({"rows": [[0] * 256] * 17}, "payload_too_large"),
    ({"rows": ["x" * 8192] * 9}, "payload_too_large"),
    ({"content": "x" * (64 * 1024 + 1)}, "payload_too_large"),
])
def test_invalid_arguments_are_audited_denials(args, code):
    from types import SimpleNamespace
    emitted = []
    control = SimpleNamespace(emit_for_enforcement=lambda result, **kwargs: emitted.append(result))
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[]), control_plane=control)
    result = verifier.verify("test", args)
    assert not result.allowed
    assert result.error_type == code
    assert result.jsonrpc_error_code == -32602
    assert result.clean_arguments == {}
    assert "secret" not in result.denial_reason
    assert emitted == [result]


def test_large_single_string_argument_is_accepted():
    # A file-sized string (well over the old 8 KiB per-string cap) is within
    # the 64 KiB string budget, so a signed call with it verifies.
    import time
    from tenuo_core import sign_meta
    from tenuo import SigningKey, Warrant
    from tenuo.mcp.client import argument_json
    key = SigningKey.generate()
    warrant = Warrant.mint_builder().capability("write_file").holder(key.public_key).ttl(60).mint(key)
    args = {"content": "x" * (48 * 1024)}
    meta = {"tenuo": sign_meta([warrant], key, "write_file", argument_json(args), int(time.time()), None)}
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=[key.public_key]))
    result = verifier.verify("write_file", args, meta=meta)
    assert result.allowed, result.denial_reason


def test_argument_snapshot_does_not_share_nested_caller_data():
    from tenuo.meta import _capture_arguments
    original = {"nested": {"path": "/data/ok"}}
    snapshot = _capture_arguments(original)
    original["nested"]["path"] = "/etc/passwd"
    assert snapshot.execution_args == {"nested": {"path": "/data/ok"}}
    assert snapshot.pop_args == snapshot.execution_args


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
