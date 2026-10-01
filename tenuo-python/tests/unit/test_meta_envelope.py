"""The core `_meta.tenuo` vector is the same string in Python as in Rust."""

from __future__ import annotations

import json
from pathlib import Path

from tenuo.meta import argument_json
from tenuo_core import SigningKey, args_from_json, decode_meta, sign_meta, verify_meta

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
