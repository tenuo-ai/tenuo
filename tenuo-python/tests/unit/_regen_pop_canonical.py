"""Regenerate the cross-language PoP canonicalization fixture.

The fixture pins the exact Ed25519 signature bytes produced by
``Warrant::sign_with_timestamp`` for a curated set of (tool, args, key,
warrant, timestamp) tuples. Two tests load that fixture and assert their
``sign`` path reproduces the same bytes exactly:

* ``tenuo-core/tests/pop_canonical_fixture.rs``  — Rust
* ``tenuo-python/tests/unit/test_pop_canonical_fixture.py`` — Python (PyO3)

Any change to the PoP canonicalization on either side that diverges from
the other will break one of those two tests. The fix is never "regenerate
the fixture to paper over the break" — the fix is to restore parity
first, then regenerate intentionally as part of a bytes-format change.

## Regenerating

Run from ``tenuo-python/`` with the project venv active::

    python tests/unit/_regen_pop_canonical.py

This overwrites ``../tenuo-core/tests/fixtures/pop_canonical.json`` in
place. Commit the regenerated file alongside the canonicalization change
and explain the bytes-level break in the PR description.

## Why Python as the generator?

Either language would work — the fixture just needs to be produced once
and then read back on both sides. Python is more convenient for scripting
the issuance loop, and the PyO3 bindings we use here go through the exact
same ``sign_with_timestamp`` as the Rust test, so the fixture generator
and the Rust consumer cannot disagree about canonicalization by
construction.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from tenuo_core import SigningKey, Warrant
from tenuo._pop_canonicalize import strip_none_values


# Fixed 32-byte seeds for deterministic key material. Values are
# cryptographically uninteresting — these keys never sign anything but
# test fixtures.
ISSUER_SEED = bytes(range(32))                    # 00 01 02 ... 1f
HOLDER_SEED = bytes(range(32, 64))                # 20 21 22 ... 3f

# Fixed timestamp and TTL chosen to avoid overlap with the current time
# at test runtime. The window bucketing is independent of "now" because
# we pass an explicit timestamp.
FIXED_TIMESTAMP = 1_700_000_000  # 2023-11-14T22:13:20Z

# Maximum TTL the protocol accepts (90 days). The warrant's
# ``issued_at`` is the moment you run the regenerator — that's fine
# because it's stored verbatim in the fixture and both tests load the
# exact same encoded bytes. The tests exercise ``sign`` (PoP) not
# ``authorize``, so warrant-TTL expiry doesn't gate them.
TTL_SECS = 90 * 24 * 3600

# Each case is a pair of (case_name, tool_name, capabilities_for_tool,
# args_to_sign). The capabilities dict is empty for most cases so the
# warrant accepts any args — we're exercising PoP canonicalization, not
# constraint matching.
CASES: List[Dict[str, Any]] = [
    {
        "name": "empty_args",
        "tool": "noop",
        "args": {},
    },
    {
        "name": "single_string",
        "tool": "read_file",
        "args": {"path": "/data/log.txt"},
    },
    {
        "name": "string_and_int",
        "tool": "read_file",
        "args": {"path": "/data/log.txt", "max_size": 2048},
    },
    {
        "name": "sort_order_probe",
        "tool": "query",
        # Keys deliberately out of lexicographic order so the fixture
        # pins that both sides sort identically before CBOR-encoding.
        "args": {"zebra": 1, "apple": 2, "mango": 3},
    },
    {
        "name": "booleans_and_floats",
        "tool": "configure",
        "args": {"enabled": True, "ratio": 0.5, "count": 0},
    },
    {
        "name": "bool_only_true",
        "tool": "configure",
        "args": {"enabled": True},
    },
    {
        "name": "list_of_strings",
        "tool": "tag",
        "args": {"tags": ["prod", "us-east", "tier-1"]},
    },
    {
        "name": "unicode_keys_and_values",
        "tool": "translate",
        "args": {"texte": "caf\u00e9 chaud", "\u4e2d\u6587": "ok"},
    },
    {
        "name": "large_int_within_i64",
        "tool": "offset",
        "args": {"offset": 9_000_000_000},
    },
    {
        "name": "negative_int",
        "tool": "offset",
        "args": {"offset": -42},
    },
    {
        "name": "none_optional_is_stripped",
        "tool": "read_file",
        # Raw wire shape we actually see in MCP calls.
        "raw_args": {"path": "/data/log.txt", "max_size": None},
        # Canonical signing shape (what strip_none_values must produce).
        "args": {"path": "/data/log.txt"},
    },
]


def _issue_warrant(issuer: SigningKey, holder: SigningKey, tool: str) -> Warrant:
    # Wildcard capability so every case's args are accepted regardless of
    # constraint shape — this fixture only exercises PoP, not matches().
    return Warrant.issue(
        issuer,
        capabilities={tool: {}},
        ttl_seconds=TTL_SECS,
        holder=holder.public_key,
    )


def _fixture_path() -> Path:
    here = Path(__file__).resolve()
    # tenuo-python/tests/unit/_regen_pop_canonical.py
    #   → repo_root/tenuo-core/tests/fixtures/pop_canonical.json
    repo_root = here.parents[3]
    return repo_root / "tenuo-core" / "tests" / "fixtures" / "pop_canonical.json"


def generate() -> Dict[str, Any]:
    issuer = SigningKey.from_bytes(ISSUER_SEED)
    holder = SigningKey.from_bytes(HOLDER_SEED)

    cases_out: List[Dict[str, Any]] = []
    for case in CASES:
        warrant = _issue_warrant(issuer, holder, case["tool"])
        raw_args = case.get("raw_args", case["args"])
        canonical_args = strip_none_values(raw_args)
        assert canonical_args == case["args"], (
            f"{case['name']}: expected canonical args {case['args']}, "
            f"got {canonical_args} from raw_args={raw_args}"
        )
        sig = warrant.sign(holder, case["tool"], canonical_args, FIXED_TIMESTAMP)
        sig_bytes = bytes(sig)
        assert len(sig_bytes) == 64, f"expected 64-byte Ed25519 sig, got {len(sig_bytes)}"
        out_case = {
            "name": case["name"],
            "tool": case["tool"],
            "args": canonical_args,
            "warrant_b64": warrant.to_base64(),
            "timestamp": FIXED_TIMESTAMP,
            "expected_signature_hex": sig_bytes.hex(),
        }
        if "raw_args" in case:
            out_case["raw_args"] = case["raw_args"]
        cases_out.append(out_case)

    return {
        "version": 1,
        "note": (
            "Deterministic PoP canonicalization fixture. Regenerate with "
            "tenuo-python/tests/unit/_regen_pop_canonical.py. Do NOT edit by hand."
        ),
        "issuer_priv_hex": ISSUER_SEED.hex(),
        "holder_priv_hex": HOLDER_SEED.hex(),
        "cases": cases_out,
    }


def main() -> None:
    data = generate()
    path = _fixture_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    print(f"wrote {len(data['cases'])} cases to {path}")


if __name__ == "__main__":
    main()
