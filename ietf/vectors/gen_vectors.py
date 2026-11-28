#!/usr/bin/env python3
"""
Generate byte-exact JWS test vectors for draft-niyikiza-oauth-attenuating-agent-tokens-02.

Design choices (recorded in the emitted document):
  * Keys are Ed25519 from the same 32-byte seeds as docs/spec/test-vectors.md
    (Control Plane / Orchestrator / Worker / Worker2 / Attacker), so each JWS
    vector is the twin of an existing CBOR vector where a twin exists. A second
    Control Plane key (seed 32 x 0x05), which that suite does not use, is the
    key of the second trust anchor.
  * AAT and PoP payloads are JCS-canonical (RFC 8785) except where a vector
    deliberately carries other bytes: an inadmissible number, number syntax JCS
    would rewrite, duplicate members, or a non-canonical layout. Each token
    records that status. Verifiers must accept the bytes as presented and must
    not re-canonicalize before verifying a signature.
  * Headers carry explicit typing: {"alg":"Ed25519","typ":"aat+jwt"} for
    AATs and {"alg":"Ed25519","typ":"aat-pop+jwt"} for PoP JWTs (RFC 8725 §3.11).
  * aat_aud is OPTIONAL on the PoP; when present it MUST identify this
    enforcement point (7d). Every chain token that carries `aud` must name
    this enforcement point (6c). A PoP `nonce` is checked when the vector's
    policy says the enforcement point requires one (7h).
  * `all` subsumption: every parent clause is subsumed by at least one derived
    clause; a derived clause MAY cover several parent clauses.
  * Verification clock: now = 1704067500 (2024-01-01T00:05:00Z).
    MAX_IAT_SKEW = 30, MAX_TOKEN_LIFETIME = 90 days, MAX_DELEGATION_DEPTH = 8,
    MAX_CONSTRAINT_DEPTH = 32, MAX_TOKEN_SIZE = 65536, MAX_CHAIN_SIZE = 262144
    (the draft's recommended values; a vector's `params` can override them),
    PoP window = ±30 s, this enforcement point is "https://tools.example.com";
    audience and nonce are required only where a vector's policy says so.

Every vector is checked by the self-checking §8 verifier in this file before it
is written. A vector whose actual verdict or step differs from its expected one
aborts generation. `--mutation-check` then disables each check of that verifier
in turn and fails unless some vector changes verdict (see CHECKS, UNREACHABLE).

Importing this module builds the vectors in memory and writes nothing, so other
tests can use verify_chain() as a reference Section 8 verifier.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
import sys
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

OUT = Path(__file__).parent
# Machine-readable suite lives with the other cross-language vectors
# (tests/vectors/, consumed by the Rust, Python and TypeScript test suites);
# the readable Markdown stays next to the draft. Both are overridable so the
# validation script can regenerate into a temporary directory.
_ap = argparse.ArgumentParser(description="Generate AAT JWS test vectors")
_ap.add_argument("--json-out", type=Path, default=OUT.parent.parent / "tests" / "vectors" / "aat-jws-vectors.json")
_ap.add_argument("--md-out", type=Path, default=OUT / "aat-jws-vectors.md")
_ap.add_argument("--mutation-check", action="store_true",
                 help="after generating, disable each verifier check in turn and require a vector to notice")
_ap.add_argument("--fault-chains", action="store_true",
                 help="print, for every DENY vector, each check that fails once the earlier ones are disabled")
ARGS = _ap.parse_args(None if __name__ == "__main__" else [])  # an importer's argv is not ours

# ---------------------------------------------------------------------------
# Fixed parameters
# ---------------------------------------------------------------------------
NOW = 1704067500  # 2024-01-01T00:05:00Z
MAX_IAT_SKEW = 30
MAX_TOKEN_LIFETIME = 90 * 24 * 3600
MAX_DELEGATION_DEPTH = 8
MAX_CONSTRAINT_DEPTH = 32
MAX_TOKEN_SIZE = 65536  # the draft's RECOMMENDED values (Section 4.3.1); J.23.2 and J.23.3 set smaller ones
MAX_CHAIN_SIZE = 262144
POP_WINDOW = 30
AUDIENCE = "https://tools.example.com"
ROOT_ISS = "https://auth.example.com"
ROOT_ISS2 = "https://auth.example.org"  # issuer of the second trust anchor

IAT_ROOT = 1704067200  # 2024-01-01T00:00:00Z
EXP_ROOT = 1704070800  # 2024-01-01T01:00:00Z

SEEDS = {
    "control_plane": bytes([0x01] * 32),
    "control_plane2": bytes([0x05] * 32),
    "orchestrator": bytes([0x02] * 32),
    "worker": bytes([0x03] * 32),
    "worker2": bytes([0x04] * 32),
    "attacker": bytes([0xFF] * 32),
}
# Public keys as listed in docs/spec/test-vectors.md; asserted below. control_plane2 is not in that suite.
EXPECTED_PUB_HEX = {
    "control_plane": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "orchestrator": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    "worker": "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
    "worker2": "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c",
    "attacker": "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
}


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sha_b64u(signing_input: str) -> str:
    """base64url-nopad(SHA-256(signing input)), as for par_hash and aat_hash (Section 4.6)."""
    return b64u(hashlib.sha256(signing_input.encode("ascii")).digest())


# ---------------------------------------------------------------------------
# JSON numbers (Section 3.4) and JCS (RFC 8785)
# ---------------------------------------------------------------------------
def _is_num(v) -> bool:
    return isinstance(v, (int, Decimal)) and not isinstance(v, bool)


def _is_int(v) -> bool:
    """Section 3.2: a JSON number written with no fraction or exponent part. _loads
    keeps every other number syntax as Decimal, so only int qualifies."""
    return isinstance(v, int) and not isinstance(v, bool)


def _es_number(f: float) -> str:
    """ECMAScript Number::toString(f), the number serialization of RFC 8785 Section 3.2.2.3.

    repr() yields the shortest digit string that rounds to f, and the closest such
    string when there are several, which is what ECMAScript requires; only the
    layout (plain digits or exponent form) differs."""
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity have no JSON form")
    if f == 0:
        return "0"
    _, digits, exp = Decimal(repr(abs(f))).as_tuple()
    s = "".join(map(str, digits)).rstrip("0")
    exp += len(digits) - len(s)
    k, n = len(s), exp + len(s)  # |f| = 0.s * 10^n
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + s
    else:
        out = s[0] + ("." + s[1:] if k > 1 else "") + ("e+" if n > 0 else "e-") + str(abs(n - 1))
    return ("-" if f < 0 else "") + out


def _admissible(x) -> bool:
    """Section 3.4: a number is admissible when the JCS serialization of its double
    denotes the same mathematical value. x is an int or Decimal holding the number
    exactly as written. Exactness of the double is not the test: 2**60 has an exact
    double, but JCS prints it as 1152921504606847000, so it is not admissible, while
    1152921504606847000 rounds to that double and is printed unchanged, so it is."""
    try:
        return Decimal(_es_number(float(x))) == Decimal(x)
    except (OverflowError, ValueError):
        return False  # beyond the double range: JCS cannot serialize it at all


def _inadmissible(v) -> bool:
    """True if any number anywhere in v is not admissible (Section 3.4)."""
    if _is_num(v):
        return not _admissible(v)
    if isinstance(v, list):
        return any(_inadmissible(x) for x in v)
    if isinstance(v, dict):
        return any(_inadmissible(x) for x in v.values())
    return False


# RFC 8785 Appendix B, plus the Section 3.4 examples.
for _bits, _want in (
        ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
        ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
        ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
        ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
        ("43143ff3c1cb0959", "1424953923781206.2")):
    assert _es_number(struct.unpack(">d", bytes.fromhex(_bits))[0]) == _want, _bits
assert all(_admissible(Decimal(x)) for x in ("0.1", "1e20", "9007199254740994", "1152921504606847000"))
assert not any(_admissible(Decimal(x)) for x in ("9007199254740993", "1.00000000000000001", "1152921504606846976"))


def _check_safe(v):
    """The vectors avoid every JCS case that is not trivially portable."""
    if isinstance(v, float):
        raise ValueError("write a non-integer as Decimal or as raw JSON text, never as a float")
    if isinstance(v, str) and not v.isascii():
        raise ValueError("non-ASCII strings are deliberately excluded")
    if isinstance(v, list):
        for x in v:
            _check_safe(x)
    if isinstance(v, dict):
        for k, x in v.items():
            if not (isinstance(k, str) and k.isascii()):
                raise ValueError("non-ASCII keys are deliberately excluded")
            _check_safe(x)


def _ser(v, num) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if _is_num(v):
        return num(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(x, num) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _ser(v[k], num) for k in sorted(v)) + "}"
    raise TypeError(type(v))


def jcs(v) -> bytes:
    """RFC 8785: members sorted, no whitespace, every number written as ECMAScript
    writes its IEEE 754 double, so an inadmissible number comes out as another
    value (9007199254740993 as 9007199254740992). Sorting by code point equals
    JCS's UTF-16 order because every key in the suite is ASCII."""
    return _ser(v, lambda x: _es_number(float(x))).encode()


def dumps_exact(v) -> str:
    """Compact JSON with members sorted and every integer written with its exact
    digits. It is the JCS form whenever every number is admissible and below 1e21;
    _is_jcs records, per token, whether that holds."""
    _check_safe(v)
    return _ser(v, lambda x: str(x) if isinstance(x, int) else _es_number(float(x)))


def _loads(text):
    """Parse JSON as a verifier must (Sections 3.2, 3.4, 8): every number keeps its
    exact value, and a number written with a fraction or exponent part stays a
    Decimal, so 1.0 and 1e0 remain distinguishable from 1. Returns the value and
    whether any object repeats a member name."""
    dup = False

    def pairs(ps):
        nonlocal dup
        dup = dup or len({k for k, _ in ps}) != len(ps)
        return dict(ps)

    def no_constant(name):
        raise ValueError(f"{name} is not JSON")

    return json.loads(text, object_pairs_hook=pairs, parse_float=Decimal, parse_constant=no_constant), dup


def _is_jcs(text: str) -> bool:
    """True if text is exactly the JCS serialization of the JSON it encodes."""
    try:
        value, dup = _loads(text)
        return not dup and jcs(value).decode() == text
    except (ValueError, OverflowError):
        return False


class Key:
    def __init__(self, name: str, seed: bytes):
        self.name = name
        self.priv = Ed25519PrivateKey.from_private_bytes(seed)
        self.pub = self.priv.public_key()
        self.pub_raw = self.pub.public_bytes_raw()
        self.seed = seed

    @property
    def jwk(self) -> dict:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(self.pub_raw)}

    @property
    def thumbprint(self) -> str:
        # RFC 7638: required members in lexicographic order, no whitespace.
        return b64u(hashlib.sha256(jcs({"crv": "Ed25519", "kty": "OKP", "x": self.jwk["x"]})).digest())

    @property
    def thumbprint_uri(self) -> str:
        return f"urn:ietf:params:oauth:jwk-thumbprint:sha-256:{self.thumbprint}"

    def sign(self, msg: bytes) -> bytes:
        return self.priv.sign(msg)


KEYS = {n: Key(n, s) for n, s in SEEDS.items()}
for n, pub_hex in EXPECTED_PUB_HEX.items():
    assert KEYS[n].pub_raw.hex() == pub_hex, n

# -02 proposal (agreed 2026-09-13): explicit typing per RFC 8725 §3.11, DPoP-style.
HEADER = {"alg": "Ed25519", "typ": "aat+jwt"}
POP_HEADER = {"alg": "Ed25519", "typ": "aat-pop+jwt"}
AAT_TYPE = "attenuating_agent_token"


def _jws(payload_json: str, payload, signer: Key, header: dict) -> dict:
    h = b64u(jcs(header))
    p = b64u(payload_json.encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = signer.sign(signing_input)
    return {
        "header": header,
        "payload": payload,
        "payload_json": payload_json,
        "payload_jcs_canonical": _is_jcs(payload_json),
        "header_b64": h,
        "payload_b64": p,
        "signing_input": signing_input.decode("ascii"),
        "signing_input_sha256_b64u": b64u(hashlib.sha256(signing_input).digest()),
        "signature_b64": b64u(sig),
        "compact": f"{h}.{p}.{b64u(sig)}",
        "signer": signer.name,
    }


def jws_sign(payload: dict, signer: Key, header: dict = HEADER) -> dict:
    return _jws(dumps_exact(payload), payload, signer, header)


def jws_sign_raw(payload_json: str, signer: Key, header: dict = HEADER) -> dict:
    """Sign exact JSON text: duplicate members, number syntax that JCS would
    rewrite, or a layout that is not JCS. `payload` is then only a convenience
    parse (Python's: last duplicate wins, fraction and exponent become floats)."""
    return _jws(payload_json, json.loads(payload_json), signer, header)


def par_hash_of(tok: dict) -> str:
    return _sha_b64u(tok["signing_input"])


def uuid7ish(n: int) -> str:
    # Twin of the CBOR IDs tnu_wrt_019471f8000070008000000000000001 etc.
    return f"019471f8-0000-7000-8000-{n:012x}"


def aat(tools: dict) -> list:
    return [{"type": AAT_TYPE, "tools": tools}]


# ---------------------------------------------------------------------------
# Self-checking §8 verifier (fail-closed)
# ---------------------------------------------------------------------------
class Deny(Exception):
    def __init__(self, step: str, why: str = "", check: str | None = None):
        super().__init__(f"{step}: {why}")
        self.step = step
        self.why = why
        self.check = check


# Every check verify_chain makes, named "<step>:<what>". The wf:, check: and sub:
# entries are the Section 3.4 and 4.5 rules that steps 3n/4o, 6b and 4p4 apply;
# norm: and aat: are the empty-map normalization (Section 3.3) and the
# attenuating_agent_token type filter (steps 3m, 4n, 6a). 3b:anchors is trying the
# root signature against every trust anchor's key; switched off, only the first
# trust anchor's key is tried. 3k:verifying is the part of 3k:anchor that ties iss
# to the trust anchor whose key verified the signature; switched off, the issuer
# of any trust anchor is accepted. `--mutation-check` switches each off in turn and
# requires some vector to change verdict.
CHECKS = (
    "1:empty", "2a:token-size", "2b:chain-size", "2c:extract", "2c:unique",
    "3a:alg", "3a:typ", "3a:crit", "3b:sig", "3b:anchors", "3b:dup", "3b:numericdate", "3c:depth", "3d:par_hash",
    "3e:exp", "3f:iat", "3g:exp-iat", "3h:lifetime", "3i:integer", "3i:bound", "3j:jti", "3k:uri",
    "3k:anchor", "3k:verifying", "3l:jwk", "3l:private", "3m:array", "3m:one", "3m:tools", "3m:maps", "3n:walk",
    "4a:alg", "4a:typ", "4a:crit", "4b:sig", "4b:dup", "4b1:jti", "4b2:jwk", "4b2:private", "4b3:array",
    "4b4:integer", "4b5:strings", "4b5:numericdate", "4c:iss", "4d:depth", "4e:parent-max", "4f:max",
    "4g:max-depth", "4h:exp", "4i:exp", "4j:iat", "4k:iat", "4l:exp-iat", "4m:depth",
    "4n:one", "4n:tools", "4n:maps", "4o:walk", "4p1:tool", "4p2:named", "4p2:omit-required",
    "4p2:omit-star", "4p2:star", "4p3:required", "4p4:subsumes", "4q:par_hash", "5:length",
    "6a:one", "6b:tool", "6b:dup", "6b:numbers", "6b:check", "6b:star", "6b:closed", "6b:required",
    "6c:type", "6c:aud", "6c:required",
    "7a:alg", "7a:typ", "7a:crit", "7b:sig", "7b:dup", "7c:jti", "7c:strings", "7c:iat", "7c:hta",
    "7c:aat_id", "7c:aat_hash", "7d:aud", "7d:required", "7e:tool", "7f:numbers", "7f:hta", "7g:past", "7g:future",
    "7h:nonce", "7i:replay",
    "wf:object", "wf:depth", "wf:type", "wf:members", "wf:exact-value", "wf:composite-array",
    "wf:empty-composite", "wf:one_of-values", "wf:set-arrays", "wf:range-types", "wf:range-inclusive",
    "wf:range-order", "wf:numbers", "wf:optional-bool", "wf:optional-nested", "wf:star-wildcard",
    "wf:star-optional",
    "check:exact", "check:one_of", "check:not_one_of", "check:contains", "check:contains-array",
    "check:subset", "check:subset-array", "check:range-number", "check:range-min", "check:range-max",
    "check:range-min-exclusive", "check:range-max-exclusive", "check:all", "check:any",
    "sub:wildcard-child", "sub:exact-exact", "sub:exact-one_of", "sub:exact-range", "sub:one_of",
    "sub:range-min", "sub:range-max", "sub:range-unbounded", "sub:range-min-exclusive",
    "sub:range-max-exclusive", "sub:not_one_of", "sub:contains", "sub:subset", "sub:all", "sub:any",
    "sub:undeclared",
    "norm:parent", "norm:child", "norm:leaf", "aat:type",
)
# Checks that can never be the only thing wrong with a presentation: whenever one
# of them fails, the check named in its reason fails too. No vector can depend on
# them alone, so the mutation check requires that disabling them flips nothing.
UNREACHABLE = {
    "1:empty": "an empty chain has no root, so no later step can reach PERMIT",
    "2c:extract": "a jti that is not a string also fails 3j (root) or 4b1 (derived)",
    "3k:uri": "the trust anchor's issuer is a URI, so a root iss that is not one also fails 3k:anchor",
    "3l:jwk": "without a cnf.jwk the next signature check (4b or 7b) fails",
    "3m:array": "without the array there is no attenuating_agent_token entry, which fails 3m:one",
    "3m:tools": "an entry without a tools object authorizes no tool, so 6b fails",
    "4b2:jwk": "without a cnf.jwk the next signature check (4b or 7b) fails",
    "4b3:array": "a token without the array has no attenuating_agent_token entry, which fails 4n:one",
    "4b5:strings": "a missing or non-string iss fails 4c, and a missing or non-string par_hash fails 4q",
    "4e:parent-max": "child.del_depth > parent.del_max_depth means 4g or 4m fails as well",
    "4f:max": "del_depth <= del_max_depth <= the root's del_max_depth <= MAX_DELEGATION_DEPTH (4m, 4g, 3i)",
    "4n:tools": "an entry without a tools object authorizes no tool, so 4p1 or 6b fails below it",
    "5:length": "3c and 4d already make len(chain) equal leaf.del_depth + 1",
    "6a:one": "3m and 4n already require exactly one entry in every token, the leaf included",
    "6b:star": "the * constraint is always a wildcard (3n, 4o), which accepts every value",
    "7c:strings": "aat_id and aat_hash are compared with the leaf (7c) and aat_tool with the tool (7e)",
    "7c:hta": "the invocation's args are an object, so a missing or non-object hta fails 7f",
    "wf:object": "a constraint that is not an object cannot be evaluated by any later step",
}
assert set(UNREACHABLE) <= set(CHECKS) and len(set(CHECKS)) == len(CHECKS)
_DISABLED: set[str] = set()  # mutation testing only; empty while vectors are generated


def _chk(cid: str, failed: bool, why: str, step: str | None = None):
    """Deny when `failed`, unless mutation testing has disabled check `cid`."""
    assert cid in CHECKS, cid
    if failed and cid not in _DISABLED:
        raise Deny(step or cid.split(":")[0], why, cid)


def _off(cid: str) -> bool:
    """True when mutation testing has disabled rule `cid` of check() or subsumes()."""
    assert cid in CHECKS, cid
    return cid in _DISABLED


_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def _sig_ok(jwk, signing_input: str, sig_b64: str) -> bool:
    """Ed25519 verification under a trust anchor's key or a cnf.jwk; never a header key.
    Every key the verifier accepts is an OKP Ed25519 key, so alg Ed25519 (3a, 4a, 7a)
    is consistent with it; a key that does not decode simply fails to verify."""
    if not _is_jwk(jwk):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"])).verify(b64u_dec(sig_b64),
                                                                     signing_input.encode("ascii"))
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False


def _verify_jws(compact: str, jwk, hstep: str, sstep: str, typ: str) -> dict:
    """Header checks (3a, 4a, 7a), then the signature and claim parsing (3b, 4b, 7b)."""
    parts = compact.split(".")
    if len(parts) != 3:
        raise Deny(hstep, "not a JWS Compact Serialization")
    h, p, s = parts
    try:
        header = json.loads(b64u_dec(h))
    except ValueError:
        raise Deny(hstep, "protected header is not JSON")
    if not isinstance(header, dict):
        raise Deny(hstep, "protected header is not a JSON object")
    _chk(f"{hstep}:alg", header.get("alg") != "Ed25519" or not _is_jwk(jwk),
         f"alg {header.get('alg')!r} is not permitted or is inconsistent with the verification key")
    _chk(f"{hstep}:typ", header.get("typ") != typ, f"typ {header.get('typ')!r}, expected {typ!r}")
    crit = header.get("crit")
    # This verifier understands no extension header parameter. Any valid, non-empty
    # crit list therefore names an unsupported parameter; an empty or malformed list
    # is itself invalid under RFC 7515 Section 4.1.11.
    _chk(f"{hstep}:crit", crit is not None,
         f"crit is invalid or lists parameters this verifier does not understand: {crit!r}")
    _chk(f"{sstep}:sig", not _sig_ok(jwk, f"{h}.{p}", s), "signature does not verify")
    try:
        claims, dup = _loads(b64u_dec(p))
    except ValueError:
        raise Deny(sstep, "payload is not JSON")
    if not isinstance(claims, dict):
        raise Deny(sstep, "payload is not a JSON object")
    _chk(f"{sstep}:dup", dup, "duplicate JSON member name")
    return claims


def _jwk_of(claims: dict):
    cnf = claims.get("cnf")
    return cnf.get("jwk") if isinstance(cnf, dict) else None


def _is_jwk(jwk) -> bool:
    """True for a structurally valid public Ed25519 JWK (optional members allowed)."""
    if not (isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"
            and isinstance(jwk.get("x"), str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", jwk["x"])):
        return False
    try:
        raw = b64u_dec(jwk["x"])
        return len(raw) == 32 and b64u(raw) == jwk["x"]
    except (ValueError, TypeError):
        return False


def _thumb_uri(jwk: dict) -> str:
    return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + b64u(
        hashlib.sha256(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})).digest()
    )


def _extract_jti(compact: str):
    """Step 2c: the jti of an unverified payload, or None if no string jti can be extracted."""
    try:
        claims = json.loads(b64u_dec(compact.split(".")[1]))
    except (ValueError, IndexError):
        return None
    jti = claims.get("jti") if isinstance(claims, dict) else None
    return jti if isinstance(jti, str) else None


def _aat_entries(claims: dict) -> list:
    """The authorization_details entries of type attenuating_agent_token; this
    algorithm ignores entries of other types (Section 3.3, steps 4n and 6a)."""
    ad = claims.get("authorization_details")
    if not isinstance(ad, list):
        return []
    return [e for e in ad if isinstance(e, dict) and (e.get("type") == AAT_TYPE or _off("aat:type"))]


def _entry_tools(entry, step: str) -> dict:
    """The tools object of one attenuating_agent_token entry, after the shape checks of 3m and 4n."""
    if entry is None:
        return {}  # no entry: reachable only when 3m or 4n is switched off
    tools = entry.get("tools")
    _chk(f"{step}:tools", not isinstance(tools, dict), "the attenuating_agent_token entry has no tools object")
    if not isinstance(tools, dict):
        return {}
    _chk(f"{step}:maps", not all(isinstance(m, dict) for m in tools.values()),
         "a tools value is not a constraint-map object")
    return tools


CORE_TYPES = ("exact", "range", "one_of", "not_one_of", "contains", "subset", "wildcard", "all", "any")
# §3.4: the members each core type may carry besides constraint_type and optional.
MEMBERS = {"exact": {"value"}, "range": {"min", "max", "min_inclusive", "max_inclusive"},
           "one_of": {"values"}, "not_one_of": {"excluded"}, "contains": {"required"},
           "subset": {"allowed"}, "wildcard": set(), "all": {"constraints"}, "any": {"constraints"}}
SET_MEMBER = {"not_one_of": "excluded", "contains": "required", "subset": "allowed"}
WILDCARD = {"constraint_type": "wildcard"}


def _clauses(c: dict) -> list:
    cs = c.get("constraints")
    return cs if c.get("constraint_type") in ("all", "any") and isinstance(cs, list) else []


def _check_map(cmap, step: str):
    """§3.4 well-formedness of every constraint in one constraint map (steps 3n, 4o)."""
    for k, c in (cmap.items() if isinstance(cmap, dict) else ()):
        if isinstance(c, dict):
            _chk("wf:optional-bool", "optional" in c and not isinstance(c["optional"], bool),
                 f"{k}: optional is not a boolean", step)
            if k == "*":
                _chk("wf:star-wildcard", c.get("constraint_type") != "wildcard",
                     "the * entry is not a wildcard constraint", step)
                _chk("wf:star-optional", "optional" in c, "the * entry carries optional", step)
        _walk(c, step, 1)


def _walk(c, step: str, depth: int):
    _chk("wf:object", not isinstance(c, dict), "a constraint is not a JSON object", step)
    if not isinstance(c, dict):
        return
    _chk("wf:depth", depth > MAX_CONSTRAINT_DEPTH, "constraint tree deeper than MAX_CONSTRAINT_DEPTH", step)
    _chk("wf:optional-nested", depth > 1 and "optional" in c, "optional appears inside all/any", step)
    t = c.get("constraint_type")
    _chk("wf:type", t not in CORE_TYPES, f"unrecognized constraint_type {t!r} (fail-closed)", step)
    _chk("wf:members", bool(set(c) - {"constraint_type", "optional"} - MEMBERS.get(t, set())),
         "constraint has a member its type does not define", step)
    if t == "exact":
        v = c.get("value")
        _chk("wf:exact-value", "value" not in c or not (v is None or isinstance(v, (str, bool)) or _is_num(v)),
             "exact.value is not a string, number, boolean, or null", step)
    if t in ("all", "any"):
        cs = c.get("constraints")
        _chk("wf:composite-array", not isinstance(cs, list), f"{t}.constraints is not an array", step)
        _chk("wf:empty-composite", cs == [], f"{t} with an empty constraints array", step)
    if t == "one_of":
        _chk("wf:one_of-values", not (isinstance(c.get("values"), list) and c["values"]),
             "one_of.values is not a non-empty array", step)
    if t in SET_MEMBER:
        _chk("wf:set-arrays", not isinstance(c.get(SET_MEMBER[t]), list), f"{t}.{SET_MEMBER[t]} is not an array", step)
    if t == "range":
        _chk("wf:range-types", any(k in c and not _is_num(c[k]) for k in ("min", "max")),
             "range bound is not a number", step)
        _chk("wf:range-inclusive", any(f"{k}_inclusive" in c and (k not in c or not isinstance(c[f"{k}_inclusive"], bool))
                                       for k in ("min", "max")),
             "range inclusivity flag is not a boolean or has no bound", step)
        lo, hi = c.get("min"), c.get("max")
        _chk("wf:range-order", _is_num(lo) and _is_num(hi) and lo > hi, "range min is greater than max", step)
    _chk("wf:numbers", _inadmissible(c), "constraint contains a number that is not admissible", step)
    for clause in _clauses(c):
        _walk(clause, step, depth + 1)


def _norm(cmap, cid: str) -> dict:
    """§3.3: an empty constraint map is {"*": wildcard}. A map that is not an object
    (only possible when a shape check is disabled) has no members."""
    m = cmap if isinstance(cmap, dict) else {}
    return {"*": WILDCARD} if not m and not _off(cid) else m


def _req(c) -> bool:
    """§3.3: an entry is required unless it carries `optional: true`."""
    return not (isinstance(c, dict) and c.get("optional", False))


def _eq(a, b) -> bool:
    """Value equality per §3.4: identical JCS serializations."""
    return jcs(a) == jcs(b)


def _in(v, xs) -> bool:
    return any(_eq(v, x) for x in xs)


def check(c: dict, v) -> bool:
    """§3.4 check predicate. An unrecognized constraint_type fails closed."""
    t = c.get("constraint_type")
    if t == "wildcard":
        return True
    if t == "exact":
        return _off("check:exact") or _eq(v, c["value"])
    if t == "one_of":
        return _off("check:one_of") or _in(v, c["values"])
    if t == "not_one_of":
        return _off("check:not_one_of") or not _in(v, c["excluded"])
    if t in ("contains", "subset"):  # array arguments, compared as sets
        if not isinstance(v, list):
            return _off(f"check:{t}-array")
        if t == "contains":
            return _off("check:contains") or all(_in(r, v) for r in c["required"])
        return _off("check:subset") or all(_in(x, c["allowed"]) for x in v)
    if t == "range":
        if not _is_num(v):
            return _off("check:range-number")
        for side, outside in (("min", lambda b: v < b), ("max", lambda b: v > b)):
            bound = c.get(side)
            if bound is None:
                continue
            if outside(bound) and not _off(f"check:range-{side}"):
                return False
            if v == bound and not c.get(f"{side}_inclusive", True) and not _off(f"check:range-{side}-exclusive"):
                return False
        return True
    if t == "all":
        return (any if _off("check:all") else all)(check(s, v) for s in _clauses(c))
    if t == "any":
        return (all if _off("check:any") else any)(check(s, v) for s in _clauses(c))
    return False


def _range_tighter(child: dict, parent: dict) -> bool:
    """§4.5 range rule: each parent bound is matched by a derived bound at least as tight."""
    for side, looser in (("min", lambda c, p: c < p), ("max", lambda c, p: c > p)):
        pb, cb = parent.get(side), child.get(side)
        if pb is None:
            continue  # a missing parent bound is unbounded
        if cb is None:
            if not _off("sub:range-unbounded"):
                return False
            continue
        if looser(cb, pb) and not _off(f"sub:range-{side}"):
            return False
        if (cb == pb and parent.get(f"{side}_inclusive", True) is False and child.get(f"{side}_inclusive", True)
                and not _off(f"sub:range-{side}-exclusive")):
            return False
    return True


def subsumes(child: dict, parent: dict) -> bool:
    """True iff child ⊑ parent under the §4.5 table; every pair the table does not
    list is invalid.

    `all` uses the -02 rule (Section 4.5): every parent clause must subsume at
    least one derived clause; a derived clause MAY cover several parent clauses;
    extra derived clauses are permitted. This drops draft-01's one-to-one
    requirement (Warden NOTES entry 12). An empty `all` or `any` never reaches
    this function: steps 3n and 4o reject it.
    """
    ct, pt = child.get("constraint_type"), parent.get("constraint_type")
    if pt == "wildcard":
        return True
    if ct == "wildcard":
        return _off("sub:wildcard-child")
    if ct == pt == "all":
        return all(any(subsumes(cd, cp) for cd in _clauses(child)) for cp in _clauses(parent)) or _off("sub:all")
    if ct == pt == "any":
        return all(any(subsumes(cd, cp) for cp in _clauses(parent)) for cd in _clauses(child)) or _off("sub:any")
    if ct == "exact" and pt == "exact":
        return _off("sub:exact-exact") or _eq(child["value"], parent["value"])
    if ct == "exact" and pt == "one_of":
        return _off("sub:exact-one_of") or _in(child["value"], parent["values"])
    if ct == "exact" and pt == "range":
        return _off("sub:exact-range") or (_is_num(child["value"]) and check(parent, child["value"]))
    if ct == pt == "one_of":
        return _off("sub:one_of") or all(_in(x, parent["values"]) for x in child["values"])
    if ct == pt == "range":
        return _range_tighter(child, parent)
    if ct == pt == "not_one_of":
        return _off("sub:not_one_of") or all(_in(x, child["excluded"]) for x in parent["excluded"])
    if ct == pt == "contains":
        return _off("sub:contains") or all(_in(x, child["required"]) for x in parent["required"])
    if ct == pt == "subset":
        return _off("sub:subset") or all(_in(x, parent["allowed"]) for x in child["allowed"])
    return _off("sub:undeclared")


def _attenuates(parent_tools: dict, child_tools: dict):
    """Step 4p: capability monotonicity (§4.5)."""
    for name, cmap in child_tools.items():
        if name not in parent_tools:
            _chk("4p1:tool", True, f"tool {name!r} is not in the parent")
            continue
        pm, cm = _norm(parent_tools[name], "norm:parent"), _norm(cmap, "norm:child")
        # 4p2: the key rules of §4.5. "*" names no argument.
        for k in cm:
            if k != "*":
                _chk("4p2:named", k not in pm and "*" not in pm,
                     f"{name}: child names {k!r}, which the parent neither names nor admits via *")
        for k in pm:
            if k != "*" and k not in cm:
                _chk("4p2:omit-required", _req(pm[k]), f"{name}: child omits {k!r}, which the parent requires")
                _chk("4p2:omit-star", "*" in cm, f"{name}: child omits {k!r} but keeps *, which would readmit it")
        _chk("4p2:star", "*" in cm and "*" not in pm, f"{name}: child contains * but the parent does not")
        # 4p3: a required argument stays required.
        for k in cm:
            if k != "*" and k in pm:
                _chk("4p3:required", _req(pm[k]) and not _req(cm[k]),
                     f"{name}.{k}: child makes a required argument optional")
        # 4p4: each child constraint attenuates the parent's, or the parent's * for a key it does not name.
        for k, c in cm.items():
            pc = pm[k] if k in pm else pm.get("*")
            if pc is not None:
                _chk("4p4:subsumes", not subsumes(c, pc), f"{name}.{k} does not attenuate the parent constraint")


def verify_chain(chain: list[str], trust_anchors: list[tuple[str, dict]], tool: str, args: dict,
                 pop_jwt: str, now: int = NOW, audience: str = AUDIENCE,
                 max_token_size: int = MAX_TOKEN_SIZE, max_chain_size: int = MAX_CHAIN_SIZE,
                 require_pop_aud: bool = False, require_chain_aud: bool = False,
                 nonce: str | None = None, track_pop_jti: bool = False,
                 accepted_pop_jtis: set[str] | None = None, args_dup: bool = False) -> str:
    """Returns 'PERMIT' or raises Deny(step). `args` must come from _loads so that
    numbers keep the exact value written in the invocation."""
    # 1, 2
    _chk("1:empty", not chain, "empty chain")
    sizes = [len(t.encode("ascii")) for t in chain]
    _chk("2a:token-size", any(s > max_token_size for s in sizes), "a token exceeds MAX_TOKEN_SIZE")
    _chk("2b:chain-size", sum(sizes) > max_chain_size, "chain exceeds MAX_CHAIN_SIZE")
    jtis = [_extract_jti(t) for t in chain]  # untrusted until each signature verifies
    _chk("2c:extract", None in jtis, "a string-valued jti cannot be extracted")
    seen = [j for j in jtis if j is not None]
    _chk("2c:unique", len(set(seen)) != len(seen), "duplicate jti in chain")

    # 3: root
    root, anchor_iss, err = None, None, None
    anchors = trust_anchors[:1] if _off("3b:anchors") else trust_anchors
    for ta_iss, ta_jwk in anchors:
        try:
            root = _verify_jws(chain[0], ta_jwk, "3a", "3b", "aat+jwt")
            anchor_iss = ta_iss
            break
        except Deny as e:
            err = e
    if root is None:
        raise err
    iat, exp = root.get("iat"), root.get("exp")
    _chk("3b:numericdate", not (_is_int(iat) and _is_int(exp)), "root iat/exp missing or not NumericDate")
    dd = root.get("del_depth")
    _chk("3c:depth", not (_is_int(dd) and dd == 0), "root del_depth is not the integer 0")
    _chk("3d:par_hash", "par_hash" in root, "root carries par_hash")
    _chk("3e:exp", not exp > now, "root expired")
    _chk("3f:iat", iat > now + MAX_IAT_SKEW, "root iat beyond now + MAX_IAT_SKEW")
    _chk("3g:exp-iat", not exp > iat, "root exp <= iat")
    _chk("3h:lifetime", exp > iat + MAX_TOKEN_LIFETIME, "root lifetime exceeds MAX_TOKEN_LIFETIME")
    dmd = root.get("del_max_depth")
    _chk("3i:integer", not (_is_int(dmd) and dmd >= 0), "root del_max_depth missing or not a non-negative integer")
    _chk("3i:bound", _is_num(dmd) and dmd > MAX_DELEGATION_DEPTH, "root del_max_depth exceeds MAX_DELEGATION_DEPTH")
    jti = root.get("jti")
    _chk("3j:jti", not (isinstance(jti, str) and jti), "root jti missing or not a non-empty string")
    iss = root.get("iss")
    _chk("3k:uri", not (isinstance(iss, str) and _URI.match(iss)), "root iss is not a URI")
    any_anchor = _off("3k:verifying") and iss in [ta_iss for ta_iss, _ in trust_anchors]
    _chk("3k:anchor", iss != anchor_iss and not any_anchor, "root iss does not match the verifying trust anchor")
    jwk = _jwk_of(root)
    _chk("3l:jwk", not _is_jwk(jwk), "root cnf.jwk missing")
    _chk("3l:private", isinstance(jwk, dict) and "d" in jwk, "root cnf.jwk contains the private key parameter d")
    ad = root.get("authorization_details")
    _chk("3m:array", not (isinstance(ad, list) and ad), "root authorization_details is not a non-empty array")
    ents = _aat_entries(root)
    _chk("3m:one", len(ents) != 1, f"root has {len(ents)} attenuating_agent_token entries")
    root_tools = _entry_tools(ents[0] if ents else None, "3m")
    if not _off("3n:walk"):
        for cmap in root_tools.values():
            _check_map(cmap, "3n")

    # 4: adjacent pairs
    toks = [(root, root_tools)]
    for i in range(1, len(chain)):
        parent, parent_tools = toks[-1]
        pjwk = _jwk_of(parent)
        child = _verify_jws(chain[i], pjwk, "4a", "4b", "aat+jwt")
        jti = child.get("jti")
        _chk("4b1:jti", not (isinstance(jti, str) and jti), "jti missing or not a non-empty string")
        cjwk = _jwk_of(child)
        _chk("4b2:jwk", not _is_jwk(cjwk), "cnf.jwk missing")
        _chk("4b2:private", isinstance(cjwk, dict) and "d" in cjwk, "cnf.jwk contains the private key parameter d")
        _chk("4b3:array", not isinstance(child.get("authorization_details"), list),
             "authorization_details missing or not an array")
        dd, dmd = child.get("del_depth"), child.get("del_max_depth")
        _chk("4b4:integer", not all(_is_int(x) and x >= 0 for x in (dd, dmd)),
             "del_depth/del_max_depth missing or not non-negative integers")
        _chk("4b5:strings", not (isinstance(child.get("iss"), str) and isinstance(child.get("par_hash"), str)),
             "iss/par_hash missing or not strings")
        ciat, cexp = child.get("iat"), child.get("exp")
        _chk("4b5:numericdate", not (_is_int(ciat) and _is_int(cexp)), "iat/exp missing or not NumericDate")
        _chk("4c:iss", child.get("iss") != _thumb_uri(pjwk), "iss != thumbprint URI of parent.cnf.jwk")
        _chk("4d:depth", dd != parent["del_depth"] + 1, "del_depth is not parent.del_depth + 1")
        _chk("4e:parent-max", dd > parent["del_max_depth"], "del_depth > parent.del_max_depth")
        _chk("4f:max", dd > MAX_DELEGATION_DEPTH, "del_depth > MAX_DELEGATION_DEPTH")
        _chk("4g:max-depth", dmd > parent["del_max_depth"], "del_max_depth > parent.del_max_depth")
        _chk("4h:exp", cexp > parent["exp"], "exp > parent.exp")
        _chk("4i:exp", not cexp > now, "expired")
        _chk("4j:iat", ciat < parent["iat"], "iat < parent.iat")
        _chk("4k:iat", ciat > now + MAX_IAT_SKEW, "iat beyond now + MAX_IAT_SKEW")
        _chk("4l:exp-iat", not cexp > ciat, "exp <= iat")
        _chk("4m:depth", dd > dmd, "del_depth > del_max_depth")
        ents = _aat_entries(child)
        _chk("4n:one", len(ents) != 1, f"{len(ents)} attenuating_agent_token entries, not exactly one")
        child_tools = _entry_tools(ents[0] if ents else None, "4n")
        if not _off("4o:walk"):
            for cmap in child_tools.values():
                _check_map(cmap, "4o")
        _attenuates(parent_tools, child_tools)
        h, p = chain[i - 1].split(".")[:2]
        _chk("4q:par_hash", child.get("par_hash") != _sha_b64u(f"{h}.{p}"), "par_hash mismatch")
        toks.append((child, child_tools))

    # 5, 6: leaf
    leaf, leaf_tools = toks[-1]
    _chk("5:length", len(chain) != leaf["del_depth"] + 1, "len(chain) != leaf.del_depth + 1")
    _chk("6a:one", len(_aat_entries(leaf)) != 1, "leaf does not have exactly one attenuating_agent_token entry")
    _chk("6b:tool", tool not in leaf_tools, f"tool {tool!r} not authorized")
    _chk("6b:dup", args_dup, "invocation arguments contain a duplicate JSON member name")
    _chk("6b:numbers", _inadmissible(args), "an argument number is not admissible (§3.4)")
    m = _norm(leaf_tools.get(tool, {}), "norm:leaf")
    for a, v in args.items():
        if a != "*" and a in m:
            _chk("6b:check", not check(m[a], v), f"argument {a!r} violates its constraint")
        elif "*" in m:
            _chk("6b:star", not check(m["*"], v), f"argument {a!r} violates the * constraint")
        else:
            _chk("6b:closed", True, f"argument {a!r} not in the closed-world map")
    for a, c in m.items():
        if a != "*":
            _chk("6b:required", _req(c) and a not in args, f"required argument {a!r} absent")
    # 6c: chain audience. Every token that carries aud must name this enforcement
    # point (RFC 7519 §4.1.3 applied per token); a derived token can add or narrow
    # the restriction but never remove one.
    for i, (c, _) in enumerate(toks):
        if "aud" in c:
            aud = c["aud"]
            valid_aud = isinstance(aud, str) or (isinstance(aud, list) and all(isinstance(v, str) for v in aud))
            _chk("6c:type", not valid_aud, f"token {i} aud is not a string or array of strings")
            vals = aud if isinstance(aud, list) else [aud]
            _chk("6c:aud", audience not in vals, f"token {i} aud does not identify this enforcement point")
    _chk("6c:required", require_chain_aud and not any("aud" in c for c, _ in toks),
         "chain audience required by policy but no token carries aud")

    # 7: PoP
    pop = _verify_jws(pop_jwt, _jwk_of(leaf), "7a", "7b", "aat-pop+jwt")
    _chk("7c:jti", not (isinstance(pop.get("jti"), str) and pop["jti"]), "PoP jti missing or not a non-empty string")
    _chk("7c:strings", not all(isinstance(pop.get(k), str) and pop[k] for k in ("aat_id", "aat_hash", "aat_tool")),
         "PoP aat_id/aat_hash/aat_tool missing or not non-empty strings")
    _chk("7c:iat", not _is_int(pop.get("iat")), "PoP iat missing or not a NumericDate")
    _chk("7c:hta", not isinstance(pop.get("hta"), dict), "PoP hta missing or not an object")
    _chk("7c:aat_id", pop.get("aat_id") != leaf.get("jti"), "aat_id != leaf.jti")
    _chk("7c:aat_hash", pop.get("aat_hash") != _sha_b64u(".".join(chain[-1].split(".")[:2])),
         "aat_hash does not match the presented leaf")
    pop_aud = pop.get("aat_aud")
    _chk("7d:aud", pop_aud is not None and pop_aud != audience, "aat_aud does not identify this enforcement point")
    _chk("7d:required", pop_aud is None and require_pop_aud, "aat_aud required by policy but absent")
    _chk("7e:tool", pop.get("aat_tool") != tool, "aat_tool != tool")
    _chk("7f:numbers", _inadmissible(pop.get("hta")), "a number in the PoP hta is not admissible (§3.4)")
    _chk("7f:hta", jcs(pop.get("hta")) != jcs(args), "hta != args (JCS)")
    _chk("7g:past", pop["iat"] < now - POP_WINDOW, "PoP iat is older than the clock window")
    _chk("7g:future", pop["iat"] > now + POP_WINDOW, "PoP iat is further in the future than the clock window")
    _chk("7h:nonce", nonce is not None and pop.get("nonce") != nonce,
         "nonce required by policy but absent or not issued by this enforcement point")
    if track_pop_jti:
        if accepted_pop_jtis is None:
            raise ValueError("accepted_pop_jtis state is required when track_pop_jti is true")
        _chk("7i:replay", pop["jti"] in accepted_pop_jtis, "PoP jti was already accepted within the tolerance window")
        accepted_pop_jtis.add(pop["jti"])
    return "PERMIT"


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------
CP, ORCH, WK, WK2, ATK = (KEYS[n] for n in ("control_plane", "orchestrator", "worker", "worker2", "attacker"))
CP2 = KEYS["control_plane2"]
TRUST = [(ROOT_ISS, CP.jwk), (ROOT_ISS2, CP2.jwk)]

Q3, Q4 = "/data/q3-report.pdf", "/data/q4-report.pdf"


def root_claims(jti: str, tools: dict, holder: Key, iat=IAT_ROOT, exp=EXP_ROOT, dmd=3, **extra) -> dict:
    claims = {
        "jti": jti, "iss": ROOT_ISS, "iat": iat, "exp": exp,
        "del_depth": 0, "del_max_depth": dmd,
        "cnf": {"jwk": holder.jwk},
        "authorization_details": aat(tools),
    }
    claims.update(extra)
    return claims


def derived_claims(jti: str, parent_tok: dict, signer: Key, holder: Key, tools: dict,
                   iat: int, exp: int, dmd: int, depth: int | None = None, par_hash: str | None = None) -> dict:
    pc = parent_tok["payload"]
    return {
        "jti": jti,
        "iss": signer.thumbprint_uri,
        "iat": iat, "exp": exp,
        "del_depth": pc["del_depth"] + 1 if depth is None else depth,
        "del_max_depth": dmd,
        "par_hash": par_hash_of(parent_tok) if par_hash is None else par_hash,
        "cnf": {"jwk": holder.jwk},
        "authorization_details": aat(tools),
    }


def pop_sign(payload: dict, signer: Key, header: dict = POP_HEADER) -> dict:
    return jws_sign(payload, signer, header)


def pop_claims(jti: str, leaf_tok: dict, tool: str, hta: dict, iat=NOW, aud=AUDIENCE,
               nonce: str | None = None) -> dict:
    c = {"jti": jti, "iat": iat, "aat_id": leaf_tok["payload"]["jti"], "aat_hash": par_hash_of(leaf_tok),
         "aat_tool": tool, "hta": hta}
    if aud is not None:
        c["aat_aud"] = aud
    if nonce is not None:
        c["nonce"] = nonce
    return c


VECTORS: list[dict] = []


def _verdict(run: dict, replay_state: set[str] | None):
    """Verify one recorded presentation. Returns (verdict, step, check)."""
    try:
        args, args_dup = _loads(run["args_json"])
        return verify_chain(run["chain"], TRUST, run["tool"], args, run["pop"],
                            now=run["now"], accepted_pop_jtis=replay_state, args_dup=args_dup,
                            **run["policy"], **run["params"]), None, None
    except Deny as e:
        return "DENY", e.step, e.check


def add(vid: str, title: str, twin: str | None, desc: str, chain: list[dict], pop: dict, tool: str,
        args: dict | None, expect: str, expect_step: str | None = None, now: int = NOW,
        notes: list[str] | None = None, policy: dict | None = None, replay_state: set[str] | None = None,
        params: dict | None = None, args_json: str | None = None):
    """`policy` is what this enforcement point requires beyond the base algorithm:
    require_pop_aud, require_chain_aud, nonce (the value it issued), track_pop_jti.
    `params` overrides suite parameters for this vector (max_token_size,
    max_chain_size). `args_json` is the invocation's exact JSON text when it is
    not dumps_exact(args), for instance a number written with an exponent."""
    policy, params = policy or {}, params or {}
    args_json = dumps_exact(args) if args_json is None else args_json
    run = {"chain": [t["compact"] for t in chain], "tool": tool, "args_json": args_json, "pop": pop["compact"],
           "now": now, "policy": policy, "params": params,
           "replay": sorted(replay_state) if replay_state is not None else None}
    verdict, step, _ = _verdict(run, replay_state)
    ok = verdict == expect and (expect == "PERMIT" or step == expect_step)
    if not ok:
        print(f"!! {vid}: expected {expect} {expect_step or ''}, got {verdict} {step or ''}", file=sys.stderr)
        sys.exit(1)
    VECTORS.append({
        "id": vid, "title": title, "cbor_twin": twin, "description": desc, "notes": notes or [],
        "verification_time": now, "tool": tool, "args": json.loads(args_json), "args_json": args_json,
        "policy": policy, "params": params,
        "replay_state": ({"before": run["replay"], "after": sorted(replay_state)}
                         if replay_state is not None else None),
        "chain": chain, "pop": pop,
        "expected": {"verdict": expect, "step": expect_step},
        "_run": run,
    })
    if __name__ == "__main__":
        print(f"ok {vid}: {verdict} {step or ''}")


# --- J.1 minimal root, single-token chain (twin of A.1) ----------------------
j1_root = jws_sign(root_claims(uuid7ish(1), {"read_file": {"path": {"constraint_type": "wildcard"}}}, ORCH), CP)
j1_pop = pop_sign(pop_claims(uuid7ish(0xA01), j1_root, "read_file", {"path": Q3}), ORCH)
add("J.1", "Minimal valid root token, single-token chain", "A.1",
    "Root issued by the trust anchor to the Orchestrator; read_file with a wildcard path. "
    "Presented alone (root = leaf) with a PoP from the Orchestrator.",
    [j1_root], j1_pop, "read_file", {"path": Q3}, "PERMIT")

# --- J.3 valid 3-level chain (twin of A.3) -----------------------------------
ROOT_TOOLS = {
    "read_file": {"path": {"constraint_type": "one_of", "values": [Q3, Q4]}},
    "search_index": {"query": {"constraint_type": "wildcard"},
                     "limit": {"constraint_type": "range", "max": 100}},
}
L1_TOOLS = {
    "read_file": {"path": {"constraint_type": "one_of", "values": [Q3]}},
    "search_index": {"query": {"constraint_type": "exact", "value": "public filings"},
                     "limit": {"constraint_type": "range", "max": 20}},
}
L2_TOOLS = {"read_file": {"path": {"constraint_type": "exact", "value": Q3}}}

L0 = jws_sign(root_claims(uuid7ish(0x10), ROOT_TOOLS, ORCH), CP)
L1 = jws_sign(derived_claims(uuid7ish(0x11), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
L2 = jws_sign(derived_claims(uuid7ish(0x12), L1, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 2), WK)
POP3 = pop_sign(pop_claims(uuid7ish(0xA03), L2, "read_file", {"path": Q3}), WK2)
add("J.3", "Valid 3-level chain", "A.3",
    "Root (Control Plane -> Orchestrator, del_max_depth 3) -> L1 (Orchestrator -> Worker, one_of narrowed, "
    "range max 100 -> 20, wildcard -> exact, del_max_depth 2) -> L2 (Worker -> Worker2, one_of -> exact, "
    "search_index dropped, terminal: del_depth == del_max_depth == 2).",
    [L0, L1, L2], POP3, "read_file", {"path": Q3}, "PERMIT")

# --- J.6 PoP variants on the valid chain -------------------------------------
add("J.6.1", "PoP without aat_aud, enforcement point requires audience", "A.6",
    "Same chain as J.3; the PoP omits aat_aud and this enforcement point's policy requires it (step 7d, "
    "third sentence).",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA04), L2, "read_file", {"path": Q3}, aud=None), WK2),
    "read_file", {"path": Q3}, "DENY", "7d", policy={"require_pop_aud": True},
    notes=["aat_aud is OPTIONAL in -02; this vector's policy requires it. Compare J.6.3, the same PoP under "
           "a policy that does not (Warden NOTES entry 8)."])
add("J.6.2", "PoP aat_aud does not identify this enforcement point", "A.6",
    "Same chain as J.3; aat_aud is present but names https://evil.example.com. A present aat_aud MUST identify "
    "the receiving enforcement point regardless of policy (step 7d, first sentence).",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA05), L2, "read_file", {"path": Q3},
                                     aud="https://evil.example.com"), WK2),
    "read_file", {"path": Q3}, "DENY", "7d", policy={"require_pop_aud": True})
add("J.6.3", "PoP without aat_aud, enforcement point does not require audience", None,
    "Same chain as J.3; the PoP omits aat_aud and this enforcement point has no audience policy. "
    "aat_aud is OPTIONAL (§7.2).",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA06), L2, "read_file", {"path": Q3}, aud=None), WK2),
    "read_file", {"path": Q3}, "PERMIT")
add("J.6.4", "PoP aat_aud mismatch is fatal even without an audience policy", None,
    "Same chain as J.3; aat_aud names https://evil.example.com and this enforcement point has no audience "
    "policy. Presence is optional; a present value MUST identify the receiver (step 7d).",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA07), L2, "read_file", {"path": Q3},
                                     aud="https://evil.example.com"), WK2),
    "read_file", {"path": Q3}, "DENY", "7d")

# --- J.6.5-7 enforcement-point nonce (§7.2 nonce, step 7h; DPoP RFC 9449 §9 pattern) -----
NONCE = "e1c8a7f4-3b2d-4c5e-9f6a-7b8c9d0e1f2a"
STALE_NONCE = "0f0e0d0c-0b0a-4908-8706-050403020100"
add("J.6.5", "Nonce required, PoP omits nonce", None,
    "Same chain as J.3; this enforcement point issued nonce " + NONCE + " and requires it. The PoP carries none.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA08), L2, "read_file", {"path": Q3}), WK2),
    "read_file", {"path": Q3}, "DENY", "7h", policy={"nonce": NONCE})
add("J.6.6", "Nonce required, PoP carries the issued nonce", None,
    "Same chain as J.3; the PoP carries the nonce this enforcement point issued. The holder never names "
    "the enforcement point; the nonce binds the proof to it.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA09), L2, "read_file", {"path": Q3}, nonce=NONCE), WK2),
    "read_file", {"path": Q3}, "PERMIT", policy={"nonce": NONCE})
add("J.6.7", "Nonce required, PoP carries a nonce this enforcement point did not issue", None,
    "Same chain as J.3; the PoP carries a nonce from another enforcement point or an expired one.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA0A), L2, "read_file", {"path": Q3}, nonce=STALE_NONCE), WK2),
    "read_file", {"path": Q3}, "DENY", "7h", policy={"nonce": NONCE})

# --- J.6.8-10 chain audience (§3.2 aud, step 6c; Macaroon caveat / RFC 8707 pattern) ------
AUD_ROOT = jws_sign(root_claims(uuid7ish(0x20), ROOT_TOOLS, ORCH, aud=AUDIENCE), CP)
AUD_L1 = jws_sign(derived_claims(uuid7ish(0x21), AUD_ROOT, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.6.8", "Root aud names this enforcement point", None,
    "J.3 root and L1 with aud on the root set to this enforcement point by the issuer. L1 carries no aud; "
    "the root's restriction still applies to every token below it (step 6c).",
    [AUD_ROOT, AUD_L1], pop_sign(pop_claims(uuid7ish(0xA0B), AUD_L1, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "PERMIT")
OTHER_ROOT = jws_sign(root_claims(uuid7ish(0x22), ROOT_TOOLS, ORCH, aud="https://other.example.com"), CP)
OTHER_L1 = jws_sign(derived_claims(uuid7ish(0x23), OTHER_ROOT, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.6.9", "Root aud names another enforcement point", None,
    "Same as J.6.8 with the root's aud set to https://other.example.com. The chain is valid but was not "
    "issued for this enforcement point; the presentation audience on the PoP does not override the chain (step 6c).",
    [OTHER_ROOT, OTHER_L1], pop_sign(pop_claims(uuid7ish(0xA0C), OTHER_L1, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "6c")
add("J.6.10", "Chain audience required, no token carries aud", None,
    "Same chain as J.3, which carries no aud anywhere; this enforcement point's policy requires chain audience "
    "restriction (step 6c, last sentence).",
    [L0, L1, L2], POP3, "read_file", {"path": Q3}, "DENY", "6c", policy={"require_chain_aud": True})
MIXED_AUD_ROOT = jws_sign(root_claims(uuid7ish(0x24), ROOT_TOOLS, ORCH, aud=[AUDIENCE, 7]), CP)
add("J.6.11", "Chain audience array contains a non-string value", None,
    "The root aud array contains this enforcement point and the number 7. RFC 7519 permits a string or an array "
    "of strings, so membership alone is insufficient (step 6c).",
    [MIXED_AUD_ROOT], pop_sign(pop_claims(uuid7ish(0xA0D), MIXED_AUD_ROOT, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "6c")

# --- J.7 explicit typing (-02 proposal, RFC 8725 §3.11) ----------------------
add("J.7.1", "PoP JWT missing typ", None,
    "PoP is otherwise valid but its header is {\"alg\":\"Ed25519\"} with no typ.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAE1), L2, "read_file", {"path": Q3}), WK2, header={"alg": "Ed25519"}),
    "read_file", {"path": Q3}, "DENY", "7a")
add("J.7.2", "AAT presented where a PoP is expected (type confusion)", None,
    "The PoP slot carries a token with typ aat+jwt, signed by Worker2 with aat_* claims present. "
    "Explicit typing rejects it before the claims are examined.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAE2), L2, "read_file", {"path": Q3}), WK2, header=HEADER),
    "read_file", {"path": Q3}, "DENY", "7a")
j73_root = jws_sign(root_claims(uuid7ish(0x7E), ROOT_TOOLS, ORCH), CP, header=POP_HEADER)
add("J.7.3", "AAT with typ aat-pop+jwt in the chain", None,
    "The root token is signed by the trust anchor but typed as a PoP.",
    [j73_root],
    pop_sign(pop_claims(uuid7ish(0xAE3), j73_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")
j74_root = jws_sign(root_claims(uuid7ish(0x7F), ROOT_TOOLS, ORCH), CP, header={"alg": "Ed25519"})
add("J.7.4", "AAT missing typ", None,
    "Root is otherwise valid but its header is {\"alg\":\"Ed25519\"} with no typ.",
    [j74_root],
    pop_sign(pop_claims(uuid7ish(0xAE4), j74_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")
j75_root = jws_sign(root_claims(uuid7ish(0x80), ROOT_TOOLS, ORCH), CP, header={"alg": "EdDSA", "typ": "aat+jwt"})
add("J.7.5", "AAT with the deprecated polymorphic alg EdDSA", None,
    "Root is typed aat+jwt and signed with the Control Plane Ed25519 key, but its header names "
    "alg EdDSA, which RFC 9864 deprecates in favour of Ed25519 (Section 9.11).",
    [j75_root],
    pop_sign(pop_claims(uuid7ish(0xAE5), j75_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")

# --- J.4 I1 violation (twin of A.4) ------------------------------------------
bad_l1 = jws_sign(derived_claims(uuid7ish(0x41), L0, ATK, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ATK)
add("J.4", "I1 violation: derived token signed by a key that does not hold the parent", "A.4",
    "L1 is signed by the Attacker and honestly sets iss to the Attacker's thumbprint URI. "
    "Signature verification under parent.cnf.jwk fails before the iss comparison is reached.",
    [L0, bad_l1], pop_sign(pop_claims(uuid7ish(0xA41), bad_l1, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4b")

forged_iss = derived_claims(uuid7ish(0x42), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2)
bad_l1b = jws_sign(forged_iss, ATK)  # claims Orchestrator's iss, signed by Attacker
add("J.4.b", "I1 violation: iss claims the parent holder but signature is the Attacker's", "A.4",
    "Same as J.4 but iss is forged to the Orchestrator's thumbprint URI. Still fails at 4b.",
    [L0, bad_l1b], pop_sign(pop_claims(uuid7ish(0xA42), bad_l1b, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4b")
wrong_iss = derived_claims(uuid7ish(0x43), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2)
wrong_iss["iss"] = ATK.thumbprint_uri
bad_l1c = jws_sign(wrong_iss, ORCH)
add("J.4.c", "I1 violation: signature verifies, iss is not the parent holder thumbprint", "A.4",
    "L1 is signed by the Orchestrator (parent holder) so 4b passes; iss is the Attacker's thumbprint URI.",
    [L0, bad_l1c], pop_sign(pop_claims(uuid7ish(0xA43), bad_l1c, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4c")

# --- J.5 expired root (twin of A.5) ------------------------------------------
exp_root = jws_sign(root_claims(uuid7ish(0x50), ROOT_TOOLS, ORCH, iat=IAT_ROOT, exp=1704067400), CP)
add("J.5", "Expired root token", "A.5",
    "Root exp = 1704067400, verification time = 1704067500.",
    [exp_root], pop_sign(pop_claims(uuid7ish(0xA50), exp_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3e")

# --- J.10 I2 violations (twin of A.10) ---------------------------------------
skip = jws_sign(derived_claims(uuid7ish(0x61), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2, depth=2), ORCH)
add("J.10", "I2 violation: del_depth skips a level", "A.10",
    "L1 declares del_depth 2 under a root at depth 0.",
    [L0, skip], pop_sign(pop_claims(uuid7ish(0xA61), skip, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4d")
raise_dmd = jws_sign(derived_claims(uuid7ish(0x62), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 4), ORCH)
add("J.10.b", "I2 violation: del_max_depth raised above parent", "A.10",
    "L1 declares del_max_depth 4 under a root with del_max_depth 3.",
    [L0, raise_dmd], pop_sign(pop_claims(uuid7ish(0xA62), raise_dmd, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4g")
# derive from a terminal token
L3 = jws_sign(derived_claims(uuid7ish(0x63), L2, WK2, ATK, L2_TOOLS, IAT_ROOT + 180, 1704068400, 2), WK2)
add("J.10.c", "I2 violation: derivation from a terminal token", "A.9.1",
    "L2 in J.3 is terminal (del_depth == del_max_depth == 2). L3 is a correctly signed child of it.",
    [L0, L1, L2, L3], pop_sign(pop_claims(uuid7ish(0xA63), L3, "read_file", {"path": Q3}), ATK),
    "read_file", {"path": Q3}, "DENY", "4e")

# --- J.11 I4 violations (twin of A.11) ---------------------------------------
widen = dict(L1_TOOLS); widen = {**L1_TOOLS, "read_file": {"path": {"constraint_type": "one_of", "values": [Q3, Q4, "/data/secret.pdf"]}}}
w1 = jws_sign(derived_claims(uuid7ish(0x71), L0, ORCH, WK, widen, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.11", "I4 violation: one_of widened", "A.11",
    "L1 adds /data/secret.pdf to read_file.path.",
    [L0, w1], pop_sign(pop_claims(uuid7ish(0xA71), w1, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4p4")
newtool = {**L1_TOOLS, "delete_file": {}}
w2 = jws_sign(derived_claims(uuid7ish(0x72), L0, ORCH, WK, newtool, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.11.b", "I4 violation: tool not present in parent", "A.11",
    "L1 adds delete_file, which the root never authorized.",
    [L0, w2], pop_sign(pop_claims(uuid7ish(0xA72), w2, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4p1")
dropkey = {**L1_TOOLS, "search_index": {"query": {"constraint_type": "exact", "value": "public filings"}}}
w3 = jws_sign(derived_claims(uuid7ish(0x73), L0, ORCH, WK, dropkey, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.11.c", "I4 violation: constraint key dropped from a closed-world map", "A.11",
    "L1 drops search_index.limit, which the parent requires; a required key stays required (§4.5, step 4p2).",
    [L0, w3], pop_sign(pop_claims(uuid7ish(0xA73), w3, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4p2")
towild = {**L1_TOOLS, "read_file": {"path": {"constraint_type": "wildcard"}}}
w4 = jws_sign(derived_claims(uuid7ish(0x74), L0, ORCH, WK, towild, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.11.d", "I4 violation: one_of relaxed to wildcard", "A.11",
    "A derived wildcard is valid only under a parent wildcard.",
    [L0, w4], pop_sign(pop_claims(uuid7ish(0xA74), w4, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4p4")

# --- J.12 I5 violation (twin of A.12) ----------------------------------------
ph = jws_sign(derived_claims(uuid7ish(0x81), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2,
                             par_hash=par_hash_of(j1_root)), ORCH)
add("J.12", "I5 violation: par_hash over a different parent", "A.12",
    "L1 is a valid child of the J.3 root in every respect except par_hash, which is SHA-256 of the J.1 root's "
    "signing input. Both roots have the same holder key, so only I5 catches the splice.",
    [L0, ph], pop_sign(pop_claims(uuid7ish(0xA81), ph, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4q")
ph2 = jws_sign(derived_claims(uuid7ish(0x82), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2,
                              par_hash=b64u(hashlib.sha256(L0["payload_b64"].encode()).digest())), ORCH)
add("J.12.b", "I5 violation: par_hash over the payload segment only", "A.12",
    "par_hash is SHA-256 of BASE64URL(payload) instead of the full JWS Signing Input "
    "(header || '.' || payload). A common implementation mistake.",
    [L0, ph2], pop_sign(pop_claims(uuid7ish(0xA82), ph2, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4q")

# --- J.13 I3 violation (twin of A.13) ----------------------------------------
ttl = jws_sign(derived_claims(uuid7ish(0x91), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, EXP_ROOT + 3600, 2), ORCH)
add("J.13", "I3 violation: derived exp beyond parent exp", "A.13",
    "L1 exp = root exp + 3600.",
    [L0, ttl], pop_sign(pop_claims(uuid7ish(0xA91), ttl, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4h")
early = jws_sign(derived_claims(uuid7ish(0x92), L0, ORCH, WK, L1_TOOLS, IAT_ROOT - 1, 1704069000, 2), ORCH)
add("J.13.b", "I3 violation: derived iat earlier than parent iat", "A.13",
    "L1 iat = root iat - 1.",
    [L0, early], pop_sign(pop_claims(uuid7ish(0xA92), early, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4j")

# --- J.14 invalid signature (twin of A.14) -----------------------------------
sig = bytearray(b64u_dec(L0["signature_b64"])); sig[0] ^= 0x01
flipped = {**L0, "signature_b64": b64u(bytes(sig)), "compact": f"{L0['header_b64']}.{L0['payload_b64']}.{b64u(bytes(sig))}",
           "signer": "control_plane (signature byte 0 XOR 0x01)"}
add("J.14", "Invalid signature: one bit flipped in the root signature", "A.14",
    "Header and payload are byte-identical to the J.3 root.",
    [flipped], pop_sign(pop_claims(uuid7ish(0xAA1), flipped, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3b")
none_root = {**L0}
NONE_HEADER = {"alg": "none", "typ": "aat+jwt"}
none_hdr = b64u(jcs(NONE_HEADER))
none_root.update({"header": NONE_HEADER, "header_b64": none_hdr, "signature_b64": "",
                  "signing_input": f"{none_hdr}.{L0['payload_b64']}", "compact": f"{none_hdr}.{L0['payload_b64']}.",
                  "signing_input_sha256_b64u": b64u(hashlib.sha256(f"{none_hdr}.{L0['payload_b64']}".encode()).digest()),
                  "signer": "(unsigned)"})
add("J.14.b", "alg: none rejected unconditionally", "A.14",
    "Same payload as the J.3 root with header {\"alg\":\"none\",\"typ\":\"aat+jwt\"} and an empty "
    "signature (§9.11). The header is typed correctly, so alg is its only fault; a verifier that let alg "
    "choose the verification method would accept the unsigned token.",
    [none_root], pop_sign(pop_claims(uuid7ish(0xAA2), none_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")
crit_root = jws_sign(root_claims(uuid7ish(0x82), ROOT_TOOLS, ORCH), CP,
                     header={"alg": "Ed25519", "typ": "aat+jwt", "crit": ["urn:example:unknown"],
                             "urn:example:unknown": True})
add("J.7.6", "crit lists a header parameter the enforcement point does not understand", None,
    "Root is correctly typed and signed by the root issuer, but its crit header names an extension "
    "parameter the enforcement point does not understand (RFC 7515 Section 4.1.11, step 3a).",
    [crit_root], pop_sign(pop_claims(uuid7ish(0xAE6), crit_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")
empty_crit_root = jws_sign(root_claims(uuid7ish(0x83), ROOT_TOOLS, ORCH), CP,
                           header={"alg": "Ed25519", "typ": "aat+jwt", "crit": []})
add("J.7.15", "crit is an empty array", None,
    "The root is otherwise valid, but its crit is an empty array. RFC 7515 Section 4.1.11 forbids producers to "
    "send one, and step 3a rejects a crit that is not a non-empty array of strings.",
    [empty_crit_root], pop_sign(pop_claims(uuid7ish(0xAE7), empty_crit_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")
hdr_key_root = jws_sign(root_claims(uuid7ish(0x81), ROOT_TOOLS, ORCH), ATK,
                        header={"alg": "Ed25519", "typ": "aat+jwt", "jwk": ATK.jwk})
add("J.14.c", "Header-supplied key is not used", None,
    "Root signed by the Attacker, whose public key is embedded in the JWS header as jwk. Keys come only "
    "from trust anchors or cnf.jwk (Section 3.5), so the signature is checked against the root issuer's "
    "key and fails.",
    [hdr_key_root], pop_sign(pop_claims(uuid7ish(0xAA3), hdr_key_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3b")

# --- J.20 PoP failures (twin of A.20) ----------------------------------------
add("J.20.1", "PoP signed by the wrong holder key", "A.20.1",
    "Valid J.3 chain; PoP signed by the Attacker instead of Worker2.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAB1), L2, "read_file", {"path": Q3}), ATK),
    "read_file", {"path": Q3}, "DENY", "7b")
add("J.20.2", "PoP aat_id references a different token", "A.20",
    "PoP signed correctly by Worker2 but aat_id is the L1 jti.",
    [L0, L1, L2], pop_sign({**pop_claims(uuid7ish(0xAB2), L2, "read_file", {"path": Q3}), "aat_id": L1["payload"]["jti"]}, WK2),
    "read_file", {"path": Q3}, "DENY", "7c")
add("J.20.3", "Leaf exact rejects invocation args before PoP hta is compared", "A.20",
    "PoP commits to {path: q3}; the invocation presents {path: q4}. Denied at 6b because q4 fails the L2 "
    "exact constraint. Step 7f is not reached. J.20.5 is the actual hta-mismatch case.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAB3), L2, "read_file", {"path": Q3}), WK2),
    "read_file", {"path": Q4}, "DENY", "6b")
add("J.20.4", "PoP iat outside the clock window", "A.20",
    "PoP iat = now - 31 with a ±30 s window.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAB4), L2, "read_file", {"path": Q3}, iat=NOW - 31), WK2),
    "read_file", {"path": Q3}, "DENY", "7g")
add("J.20.5", "PoP hta does not match invocation args", "A.20",
    "Leaf is the J.3 root (read_file.path is one_of[q3, q4]). Invocation path is q3, which passes step 6b. "
    "PoP hta commits to q4, so 7f fails.",
    [L0], pop_sign(pop_claims(uuid7ish(0xAB5), L0, "read_file", {"path": Q4}), ORCH),
    "read_file", {"path": Q3}, "DENY", "7f")
add("J.20.6", "PoP aat_tool does not match the invocation tool", "A.20",
    "Prefix [L0, L1] authorizes both read_file and search_index. Invocation is search_index with valid args; "
    "PoP aat_tool is read_file. Step 6b passes; 7e fails. hta matches the invocation so 7f is not the cause.",
    [L0, L1], pop_sign(pop_claims(uuid7ish(0xAB6), L1, "read_file",
                                 {"query": "public filings", "limit": 5}), WK),
    "search_index", {"query": "public filings", "limit": 5}, "DENY", "7e")
L2_sibling = jws_sign({**derived_claims(uuid7ish(0x12), L1, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 2),
                       "exp": 1704068700}, WK)
add("J.20.7", "PoP replayed on a sibling leaf with the same jti", None,
    "The Worker re-derives a sibling of the J.3 L2 with the same jti and holder but a different exp, and "
    "presents it with the PoP Worker2 made for L2. aat_id matches; aat_hash does not (step 7c).",
    [L0, L1, L2_sibling], POP3, "read_file", {"path": Q3}, "DENY", "7c")
EMPTY_ROOT = jws_sign(root_claims(uuid7ish(0xB10), {"read_file": {}}, ORCH), CP)
no_hta = {k: v for k, v in pop_claims(uuid7ish(0xAB8), EMPTY_ROOT, "read_file", {}).items() if k != "hta"}
add("J.20.8", "PoP without hta", None,
    "Single-token chain: the J.8.1 root, whose read_file has an empty constraint map, invoked with no arguments. "
    "The PoP omits hta. Step 7c requires hta to be present and an object; because the invocation's args are "
    "{}, an implementation that defaulted a missing hta to {} would pass step 7f and accept.",
    [EMPTY_ROOT], pop_sign(no_hta, ORCH), "read_file", {}, "DENY", "7c")

# Stateful replay checks. Each vector records the cache before and after the
# presentation so a harness can run it independently or as the sequence below.
tracked_pop = pop_sign(pop_claims(uuid7ish(0xAB9), L2, "read_file", {"path": Q3}), WK2)
replay_cache: set[str] = set()
add("J.20.9", "Tracked PoP jti accepted for the first time", None,
    "The enforcement point tracks PoP jti values for read_file. The cache is empty, so this otherwise valid "
    "presentation is accepted and its jti is recorded only after all authorization checks pass.",
    [L0, L1, L2], tracked_pop, "read_file", {"path": Q3}, "PERMIT",
    policy={"track_pop_jti": True}, replay_state=replay_cache)
add("J.20.10", "Tracked PoP jti replay is denied", None,
    "The same proof is presented with its jti already in the enforcement point's acceptance cache. "
    "All preceding checks pass; step 7i denies the replay.",
    [L0, L1, L2], tracked_pop, "read_file", {"path": Q3}, "DENY", "7i",
    policy={"track_pop_jti": True}, replay_state=replay_cache)
bad_before_record = pop_sign(pop_claims(uuid7ish(0xABA), L0, "read_file", {"path": Q4}), ORCH)
empty_replay_cache: set[str] = set()
add("J.20.11", "Rejected PoP is not entered in the replay cache", None,
    "The invocation passes the root's one_of constraint, but hta commits to different arguments. Step 7f "
    "denies before step 7i; the recorded replay-state transition remains empty to empty.",
    [L0], bad_before_record, "read_file", {"path": Q3}, "DENY", "7f",
    policy={"track_pop_jti": True}, replay_state=empty_replay_cache)

# --- J.9 closed-world enforcement at the leaf (§3.3, step 6b) ----------------
add("J.9.1", "Closed-world: unconstrained extra argument", None,
    "Leaf constrains only path; invocation adds mode.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAC1), L2, "read_file", {"path": Q3, "mode": "r"}), WK2),
    "read_file", {"path": Q3, "mode": "r"}, "DENY", "6b")
add("J.9.2", "Closed-world: constrained argument absent", None,
    "Leaf constrains path; invocation omits it.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAC2), L2, "read_file", {}), WK2),
    "read_file", {}, "DENY", "6b")
add("J.9.3", "Tool dropped at L2 cannot be invoked", None,
    "search_index is authorized at L0 and L1 but was dropped at L2.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAC3), L2, "search_index", {"query": "public filings", "limit": 5}), WK2),
    "search_index", {"query": "public filings", "limit": 5}, "DENY", "6b")
add("J.9.4", "Prefix presentation of a valid chain", None,
    "Only [L0, L1] of the J.3 chain is presented, with a PoP from the Worker (L1 holder) on search_index. "
    "This is a valid chain in its own right; the leaf is L1.",
    [L0, L1], pop_sign(pop_claims(uuid7ish(0xAC4), L1, "search_index", {"query": "public filings", "limit": 5}), WK),
    "search_index", {"query": "public filings", "limit": 5}, "PERMIT",
    notes=["NOTES entry 6 in the Warden repo: prefix presentation is permitted and relies entirely on PoP."])
dup_args_json = f'{{"path":"{Q4}","path":"{Q3}"}}'
add("J.9.5", "Invocation arguments repeat a member name", None,
    "The invocation names path twice, first q4 and then q3. A parser that keeps the last value sees arguments "
    "that satisfy the leaf and match the PoP hta; step 6b rejects the duplicate before either comparison matters.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAC5), L2, "read_file", {"path": Q3}), WK2),
    "read_file", {"path": Q3}, "DENY", "6b", args_json=dup_args_json)

# --- J.2 cycle detection -----------------------------------------------------
dup = jws_sign(derived_claims(uuid7ish(0x10), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.2", "Duplicate jti in chain (cycle detection, step 2c)", "A.9",
    "L1 reuses the root's jti. Detected before any signature is verified.",
    [L0, dup], pop_sign(pop_claims(uuid7ish(0xAD1), dup, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "2c")

# --- J.23 presentation and parsing boundaries -------------------------------
add("J.23.1", "Empty chain", None,
    "The presentation contains no AAT. Verification stops before the PoP is examined.",
    [], j1_pop, "read_file", {"path": Q3}, "DENY", "1")

oversized_claims = root_claims(uuid7ish(0x2302), {"read_file": {"path": WILDCARD}}, ORCH)
oversized_claims["padding"] = "x" * 1400
oversized_root = jws_sign(oversized_claims, CP)
SMALL_LIMITS = {"max_token_size": 2048, "max_chain_size": 4096}
add("J.23.2", "Token exceeds MAX_TOKEN_SIZE", None,
    f"The root's compact serialization is {len(oversized_root['compact'])} bytes; this vector sets MAX_TOKEN_SIZE "
    f"to {SMALL_LIMITS['max_token_size']} and MAX_CHAIN_SIZE to {SMALL_LIMITS['max_chain_size']}, so only the "
    "per-token limit is exceeded. The signed padding claim is otherwise ignored.",
    [oversized_root], pop_sign(pop_claims(uuid7ish(0x23A2), oversized_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "2a", params=SMALL_LIMITS)

J3_LIMITS = {"max_token_size": 1024, "max_chain_size": 2048}
add("J.23.3", "Chain exceeds MAX_CHAIN_SIZE", None,
    f"The J.3 chain and PoP, unchanged. Its tokens are {', '.join(str(len(t['compact'])) for t in (L0, L1, L2))} "
    f"bytes, each within this vector's MAX_TOKEN_SIZE ({J3_LIMITS['max_token_size']}), but together "
    f"{sum(len(t['compact']) for t in (L0, L1, L2))} bytes, more than its MAX_CHAIN_SIZE "
    f"({J3_LIMITS['max_chain_size']}). Nothing else is wrong with the presentation.",
    [L0, L1, L2], POP3, "read_file", {"path": Q3}, "DENY", "2b", params=J3_LIMITS)

dup_claims = root_claims(uuid7ish(0x2304), {"read_file": {"path": WILDCARD}}, ORCH)
dup_payload = jcs(dup_claims).decode()
dup_member = f'"jti":"{dup_claims["jti"]}"'
dup_payload = dup_payload.replace(dup_member, f"{dup_member},{dup_member}")
duplicate_member_root = jws_sign_raw(dup_payload, CP)
add("J.23.4", "Signed claims object contains a duplicate member name", None,
    "The root signature is valid and both jti members have the same value, allowing minimal step-2c extraction. "
    "Full parsing after signature verification rejects the duplicate member at step 3b.",
    [duplicate_member_root],
    pop_sign(pop_claims(uuid7ish(0x23A4), duplicate_member_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3b")


# --- J.15 / J.16 composite constraints (all / any) ---------------------------
# Tool "export" with args format (any) and limit (all). Root -> one derived link.
def rng(**kw):
    return {"constraint_type": "range", **kw}


def ex(v):
    return {"constraint_type": "exact", "value": v}


def ALL(*cs):
    return {"constraint_type": "all", "constraints": list(cs)}


def ANY(*cs):
    return {"constraint_type": "any", "constraints": list(cs)}


WILD = {"constraint_type": "wildcard"}
EXPORT_ROOT = {"export": {"format": ANY(ex("pdf"), ex("csv"), ex("xlsx")), "limit": ALL(rng(max=100), rng(min=0))}}
XR = jws_sign(root_claims(uuid7ish(0xF0), EXPORT_ROOT, ORCH), CP)


def composite(vid, title, desc, derived_tools, expect, step=None, args=None, notes=None, n=0):
    d = jws_sign(derived_claims(uuid7ish(0xF10 + n), XR, ORCH, WK, derived_tools, IAT_ROOT + 60, 1704069000, 2), ORCH)
    a = args or {"format": "pdf", "limit": 10}
    add(vid, title, None, desc, [XR, d], pop_sign(pop_claims(uuid7ish(0xAF0 + n), d, "export", a), WK),
        "export", a, expect, step, notes=notes)


composite("J.15.1", "all: derived adds a clause", "limit: all[max 100, min 0] -> all[max 100, min 0, min 1].",
          {"export": {"format": ANY(ex("pdf")), "limit": ALL(rng(max=100), rng(min=0), rng(min=1))}}, "PERMIT", n=1)
composite("J.15.2", "all: derived drops a parent clause", "limit: all[max 100, min 0] -> all[max 100]. Dropping widens.",
          {"export": {"format": ANY(ex("pdf")), "limit": ALL(rng(max=100))}}, "DENY", "4p4", n=2)
composite("J.15.3", "all: one derived clause covers two parent clauses",
          "limit: all[max 100, min 0] -> all[min 10 max 50]. The single derived range is narrower than both parent "
          "clauses. PERMIT under the -02 rule (Section 4.5); draft-01's one-to-one text would DENY.",
          {"export": {"format": ANY(ex("pdf")), "limit": ALL(rng(min=10, max=50))}}, "PERMIT", n=3,
          notes=["Warden interop case all-clause-reuse-two-parents-one-derived. Soundness: C_d ⊑ C_p1 and C_d ⊑ C_p2 "
                 "implies C_d ⊑ C_p1 ∧ C_p2, so no one-to-one assignment is needed."])
# J.15.4 needs its own root because the parent shape differs.
WR = jws_sign(root_claims(uuid7ish(0xF1), {"export": {"format": WILD, "limit": ALL(WILD, WILD)}}, ORCH), CP)
wd = jws_sign(derived_claims(uuid7ish(0xF14), WR, ORCH, WK, {"export": {"format": WILD, "limit": ALL(ex(5))}},
                             IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.15.4", "all: one exact covers two parent wildcards", None,
    "limit: all[wildcard, wildcard] -> all[exact 5]. Minimal shape of the clause-reuse rule.",
    [WR, wd], pop_sign(pop_claims(uuid7ish(0xAF4), wd, "export", {"format": "pdf", "limit": 5}), WK),
    "export", {"format": "pdf", "limit": 5}, "PERMIT",
    notes=["Warden interop case all-clause-reuse-wildcards."])
composite("J.15.5", "all: a derived clause fails subsumption", "limit: all[max 100, min 0] -> all[max 200, min 0].",
          {"export": {"format": ANY(ex("pdf")), "limit": ALL(rng(max=200), rng(min=0))}}, "DENY", "4p4", n=5)
composite("J.15.6", "all: leaf check evaluates every clause", "Valid derivation; invocation limit 0 fails min 1.",
          {"export": {"format": ANY(ex("pdf")), "limit": ALL(rng(max=100), rng(min=0), rng(min=1))}}, "DENY", "6b",
          args={"format": "pdf", "limit": 0}, n=6)

composite("J.16.1", "any: derived removes alternatives", "format: any[pdf, csv, xlsx] -> any[pdf, csv].",
          {"export": {"format": ANY(ex("pdf"), ex("csv")), "limit": ALL(rng(max=100), rng(min=0))}}, "PERMIT", n=7)
composite("J.16.2", "any: derived adds an alternative", "format: any[pdf, csv, xlsx] -> any[pdf, docx]. §4.5 example.",
          {"export": {"format": ANY(ex("pdf"), ex("docx")), "limit": ALL(rng(max=100), rng(min=0))}}, "DENY", "4p4", n=8)
XR2 = jws_sign(root_claims(uuid7ish(0xF3), {**EXPORT_ROOT, "read_file": {"path": WILD}}, ORCH), CP)
x2_child = jws_sign(derived_claims(uuid7ish(0xF19), XR2, ORCH, WK,
                                  {"export": {"format": ANY(), "limit": ALL(rng(max=100), rng(min=0))},
                                   "read_file": {"path": WILD}}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.16.3", "any: empty derived any", None,
    "The root carries the J.15 export tool plus read_file; the derived token keeps both and narrows export.format "
    "from any[pdf, csv, xlsx] to any[]. An empty any is invalid in any position (§4.5, §3.4); the invocation is "
    "read_file, so nothing but the walk of the derived token's constraint trees (step 4o) can catch it. Read as a "
    "set, any[] is vacuously narrower than its parent, so a verifier that skips 4o would accept.",
    [XR2, x2_child], pop_sign(pop_claims(uuid7ish(0xAF9), x2_child, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "4o")
composite("J.16.4", "any: leaf check accepts a listed alternative", "Valid any[pdf, csv]; invocation format csv.",
          {"export": {"format": ANY(ex("pdf"), ex("csv")), "limit": ALL(rng(max=100), rng(min=0))}}, "PERMIT",
          args={"format": "csv", "limit": 10}, n=10)
composite("J.16.5", "any: leaf check rejects a removed alternative", "Valid any[pdf, csv]; invocation format xlsx.",
          {"export": {"format": ANY(ex("pdf"), ex("csv")), "limit": ALL(rng(max=100), rng(min=0))}}, "DENY", "6b",
          args={"format": "xlsx", "limit": 10}, n=11)
# cross-type inside any: parent any[one_of[pdf,csv], exact xlsx] -> derived any[exact pdf]
CR = jws_sign(root_claims(uuid7ish(0xF2), {"export": {"format": ANY({"constraint_type": "one_of", "values": ["pdf", "csv"]}, ex("xlsx")), "limit": WILD}}, ORCH), CP)
cd_ = jws_sign(derived_claims(uuid7ish(0xF16), CR, ORCH, WK, {"export": {"format": ANY(ex("pdf")), "limit": WILD}},
                              IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.16.6", "any: cross-type clause subsumption", None,
    "format: any[one_of[pdf, csv], exact xlsx] -> any[exact pdf]. exact pdf ⊑ one_of[pdf, csv] per the cross-type rules.",
    [CR, cd_], pop_sign(pop_claims(uuid7ish(0xAF6), cd_, "export", {"format": "pdf", "limit": 3}), WK),
    "export", {"format": "pdf", "limit": 3}, "PERMIT")
# split: parent any[one_of[pdf, csv]] -> derived any[exact pdf, exact csv]
SR = jws_sign(root_claims(uuid7ish(0xF4), {"export": {"format": ANY({"constraint_type": "one_of", "values": ["pdf", "csv"]}), "limit": WILD}}, ORCH), CP)
sd_ = jws_sign(derived_claims(uuid7ish(0xF1A), SR, ORCH, WK, {"export": {"format": ANY(ex("pdf"), ex("csv")), "limit": WILD}},
                              IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.16.7", "any: one parent clause split into two derived clauses", None,
    "format: any[one_of[pdf, csv]] -> any[exact pdf, exact csv]. The derived any has more clauses than its parent, "
    "and each is subsumed by the one parent clause (§4.5). A verifier that rejects added clauses, or that matches "
    "derived clauses to parent clauses one to one, would DENY.",
    [SR, sd_], pop_sign(pop_claims(uuid7ish(0xAFA), sd_, "export", {"format": "csv", "limit": 3}), WK),
    "export", {"format": "csv", "limit": 3}, "PERMIT")
# union: parent any[range 0..10, range 5..20] -> derived any[range 0..20]
UR = jws_sign(root_claims(uuid7ish(0xF5), {"export": {"format": WILD, "limit": ANY(rng(min=0, max=10), rng(min=5, max=20))}}, ORCH), CP)
ud_ = jws_sign(derived_claims(uuid7ish(0xF1B), UR, ORCH, WK, {"export": {"format": WILD, "limit": ANY(rng(min=0, max=20))}},
                              IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.16.8", "any: derived clause covered only by the union of parent clauses", None,
    "limit: any[range 0..10, range 5..20] -> any[range 0..20]. The parent's clauses together accept every value "
    "range 0..20 accepts, but no single parent clause subsumes it, so the clause-wise rule of §4.5 denies at step 4p4. "
    "A verifier that compares accepted values instead of clauses would PERMIT.",
    [UR, ud_], pop_sign(pop_claims(uuid7ish(0xAFB), ud_, "export", {"format": "pdf", "limit": 15}), WK),
    "export", {"format": "pdf", "limit": 15}, "DENY", "4p4")


# --- J.8 empty maps, unknown types, flatten ----------------------------------
empty_child = jws_sign(derived_claims(uuid7ish(0xB11), EMPTY_ROOT, ORCH, WK,
                                     {"read_file": {"path": ex(Q3)}}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.8.1", "Empty parent map: derived introduces constraint keys (step 4p2)", None,
    "Root authorizes read_file with an empty constraint map. L1 introduces path:exact. "
    "§4.5 / step 4p2 permits adding keys when the parent map is empty (an empty map is *).",
    [EMPTY_ROOT, empty_child], pop_sign(pop_claims(uuid7ish(0xB01), empty_child, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "PERMIT")
add("J.8.2", "Empty tool map at the leaf: extra arguments are permitted", None,
    "Root = leaf, read_file has an empty constraint map. An empty map is {\"*\": wildcard}, so extra args PERMIT.",
    [EMPTY_ROOT], pop_sign(pop_claims(uuid7ish(0xB02), EMPTY_ROOT, "read_file", {"path": Q3, "mode": "r"}), ORCH),
    "read_file", {"path": Q3, "mode": "r"}, "PERMIT")
unk_root = jws_sign(root_claims(uuid7ish(0xB13), {"read_file": {"path": {"constraint_type": "no_such_type"}}}, ORCH), CP)
add("J.8.3", "Unknown constraint_type is fail-closed at the leaf", "A.9.2",
    "Root carries path:{constraint_type: no_such_type}. Step 3n rejects constraint types the enforcement "
    "point does not implement when it walks the root's constraint trees.",
    [unk_root], pop_sign(pop_claims(uuid7ish(0xB03), unk_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")
unk_other = jws_sign(root_claims(uuid7ish(0xB16), {"read_file": {"path": WILD},
                                                   "export": {"format": {"constraint_type": "no_such_type"}}}, ORCH), CP)
add("J.8.5", "Unknown constraint_type on a tool that is not invoked", None,
    "Root authorizes read_file (wildcard path) and export, whose format constraint has an unknown type. "
    "The invocation is read_file. The chain is still rejected at step 3n: the unknown type is found when "
    "the root's constraint trees are walked, not only when the constrained tool is invoked.",
    [unk_other], pop_sign(pop_claims(uuid7ish(0xB05), unk_other, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")
bad_range = jws_sign(root_claims(uuid7ish(0xB17), {"read_file": {"path": WILD},
                                                   "export": {"limit": {"constraint_type": "range", "min": 10, "max": 5}}},
                                 ORCH), CP)
add("J.8.6", "Malformed range (min greater than max)", None,
    "Root carries export.limit = range(min 10, max 5), which is not well-formed (Section 3.4). The invocation "
    "is read_file; the chain is rejected at step 3n.",
    [bad_range], pop_sign(pop_claims(uuid7ish(0xB06), bad_range, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")
BIG = 2**53 + 1
big_root = jws_sign(root_claims(uuid7ish(0xB18), {"get_account": {"id": WILD}}, ORCH), CP)
add("J.8.7", "Argument number that does not survive the JCS round trip", None,
    "Root authorizes get_account with a wildcard id. The invocation passes id = 2^53 + 1, which rounds to the "
    "double 2^53; JCS prints that as 9007199254740992, a different value, so the number is not admissible "
    "(Section 3.4). Denied at step 6b.",
    [big_root], pop_sign(pop_claims(uuid7ish(0xB07), big_root, "get_account", {"id": 2**53}), ORCH),
    "get_account", {"id": BIG}, "DENY", "6b",
    notes=["The PoP's hta carries 9007199254740992, the JCS form of the argument, so the PoP is admissible and "
           "matches at step 7f; the argument's admissibility (step 6b) is the only fault. J.20.17 is the "
           "mirror case."])
add("J.8.8", "Argument above 2^53 that survives the JCS round trip", None,
    "The invocation passes id = 2^53 + 2. JCS prints its double as 9007199254740994, the same value, so it is "
    "admissible. PERMIT: the rule is what JCS prints, not a magnitude limit (compare J.8.10 and J.8.11).",
    [big_root], pop_sign(pop_claims(uuid7ish(0xB08), big_root, "get_account", {"id": 2**53 + 2}), ORCH),
    "get_account", {"id": 2**53 + 2}, "PERMIT")
big_lit = jws_sign(root_claims(uuid7ish(0xB19), {"read_file": {"path": WILD},
                                                 "get_account": {"id": {"constraint_type": "range", "max": BIG}}},
                               ORCH), CP)
add("J.8.9", "Constraint literal that does not survive the JCS round trip", None,
    "Root carries get_account.id = range(max 2^53 + 1). The invocation is read_file, but the chain is "
    "rejected at step 3n: constraint values are checked when the chain is verified, not only when used.",
    [big_lit], pop_sign(pop_claims(uuid7ish(0xB09), big_lit, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")
FLAT_ROOT = jws_sign(root_claims(uuid7ish(0xB14), {"export": {"limit": ALL(rng(min=0), rng(max=100))}}, ORCH), CP)
flat_child = jws_sign(derived_claims(uuid7ish(0xB15), FLAT_ROOT, ORCH, WK,
                                    {"export": {"limit": rng(min=10, max=50)}}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.8.4", "Flatten all to a bare range is rejected even when the range is narrower", None,
    "Parent limit is all[min 0, max 100]. Derived is range(min 10, max 50), not wrapped in all. "
    "Same-type wrapping is required; undeclared (all, range) is invalid.",
    [FLAT_ROOT, flat_child], pop_sign(pop_claims(uuid7ish(0xB04), flat_child, "export", {"limit": 20}), WK),
    "export", {"limit": 20}, "DENY", "4p4",
    notes=["Conservative by design: the derived range is semantically narrower, but (all, range) is an undeclared "
           "pair and §4.5 rejects every undeclared pair. tenuo-core agrees (IncompatibleConstraintTypes)."])


# --- J.17 remaining core types -----------------------------------------------
def n1of(*xs):
    return {"constraint_type": "not_one_of", "excluded": list(xs)}


def reqd(*xs):
    return {"constraint_type": "contains", "required": list(xs)}


def sub(*xs):
    return {"constraint_type": "subset", "allowed": list(xs)}


CORE_ROOT = jws_sign(root_claims(uuid7ish(0xC0), {
    "publish": {
        "label": n1of("secret", "internal"),
        "tags": reqd("public"),
        "roles": sub("reader", "editor", "admin"),
        "limit": rng(min=0, max=100),
    }
}, ORCH), CP)


def core(vid, title, desc, tools, expect, step=None, args=None, n=0):
    d = jws_sign(derived_claims(uuid7ish(0xC10 + n), CORE_ROOT, ORCH, WK, tools, IAT_ROOT + 60, 1704069000, 2), ORCH)
    a = args or {"label": "public", "tags": ["public"], "roles": ["reader"], "limit": 10}
    add(vid, title, None, desc, [CORE_ROOT, d], pop_sign(pop_claims(uuid7ish(0xC80 + n), d, "publish", a), WK),
        "publish", a, expect, step)


core("J.17.1", "not_one_of: derived adds an exclusion",
     "label: not_one_of[secret, internal] -> not_one_of[secret, internal, embargoed].",
     {"publish": {"label": n1of("secret", "internal", "embargoed"), "tags": reqd("public"),
                  "roles": sub("reader", "editor", "admin"), "limit": rng(min=0, max=100)}},
     "PERMIT", n=1)
core("J.17.2", "not_one_of: derived drops an exclusion",
     "label: not_one_of[secret, internal] -> not_one_of[secret]. Removing an exclusion widens.",
     {"publish": {"label": n1of("secret"), "tags": reqd("public"),
                  "roles": sub("reader", "editor", "admin"), "limit": rng(min=0, max=100)}},
     "DENY", "4p4", n=2)
core("J.17.3", "contains: derived adds a required element",
     "tags: contains[public] -> contains[public, reviewed].",
     {"publish": {"label": n1of("secret", "internal"), "tags": reqd("public", "reviewed"),
                  "roles": sub("reader", "editor", "admin"), "limit": rng(min=0, max=100)}},
     "PERMIT", args={"label": "public", "tags": ["public", "reviewed"], "roles": ["reader"], "limit": 10}, n=3)
core("J.17.4", "contains: derived drops a required element",
     "tags: contains[public] -> contains[]. Removing a required element widens.",
     {"publish": {"label": n1of("secret", "internal"), "tags": reqd(),
                  "roles": sub("reader", "editor", "admin"), "limit": rng(min=0, max=100)}},
     "DENY", "4p4", n=4)
core("J.17.5", "subset: derived shrinks the allowed set",
     "roles: subset[reader, editor, admin] -> subset[reader, editor].",
     {"publish": {"label": n1of("secret", "internal"), "tags": reqd("public"),
                  "roles": sub("reader", "editor"), "limit": rng(min=0, max=100)}},
     "PERMIT", n=5)
core("J.17.6", "subset: derived adds an allowed element",
     "roles: subset[reader, editor, admin] -> subset[reader, editor, admin, owner]. Adding widens.",
     {"publish": {"label": n1of("secret", "internal"), "tags": reqd("public"),
                  "roles": sub("reader", "editor", "admin", "owner"), "limit": rng(min=0, max=100)}},
     "DENY", "4p4", n=6)
core("J.17.7", "range: exclusive derived bound at the same min is tighter",
     "limit: range[0, 100] inclusive -> range[0, 100] with min_inclusive false.",
     {"publish": {"label": n1of("secret", "internal"), "tags": reqd("public"),
                  "roles": sub("reader", "editor", "admin"),
                  "limit": rng(min=0, max=100, min_inclusive=False)}},
     "PERMIT", n=7)

EXCL_ROOT = jws_sign(root_claims(uuid7ish(0xC1), {
    "publish": {
        "label": n1of("secret", "internal"),
        "tags": reqd("public"),
        "roles": sub("reader", "editor", "admin"),
        "limit": rng(min=0, max=100, min_inclusive=False),
    }
}, ORCH), CP)
excl_child = jws_sign(derived_claims(uuid7ish(0xC18), EXCL_ROOT, ORCH, WK, {
    "publish": {
        "label": n1of("secret", "internal"),
        "tags": reqd("public"),
        "roles": sub("reader", "editor", "admin"),
        "limit": rng(min=0, max=100),
    }
}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.17.8", "range: inclusive derived bound under an exclusive parent widens", None,
    "Parent limit is range[0, 100] with min_inclusive false. Derived uses the default inclusive min=0.",
    [EXCL_ROOT, excl_child],
    pop_sign(pop_claims(uuid7ish(0xC88), excl_child, "publish",
                        {"label": "public", "tags": ["public"], "roles": ["reader"], "limit": 10}), WK),
    "publish", {"label": "public", "tags": ["public"], "roles": ["reader"], "limit": 10}, "DENY", "4p4")


# --- J.18 composite cross-kind -----------------------------------------------
cross_child = jws_sign(derived_claims(uuid7ish(0xD1), XR, ORCH, WK, {
    "export": {"format": ALL(ex("pdf")), "limit": ALL(rng(max=100), rng(min=0))}
}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.18.1", "derived all under parent any is rejected", None,
    "format: any[pdf, csv, xlsx] -> all[exact pdf]. (all, any) is an undeclared pair.",
    [XR, cross_child], pop_sign(pop_claims(uuid7ish(0xD81), cross_child, "export", {"format": "pdf", "limit": 10}), WK),
    "export", {"format": "pdf", "limit": 10}, "DENY", "4p4",
    notes=["Conservative by design: all[exact pdf] is semantically narrower than the parent any, but the pair is "
           "undeclared. tenuo-core agrees (IncompatibleConstraintTypes)."])
NEST_ROOT = jws_sign(root_claims(uuid7ish(0xD0), {
    "export": {"format": ALL(ANY(ex("pdf"), ex("csv"), ex("xlsx"))), "limit": WILD}
}, ORCH), CP)
nest_child = jws_sign(derived_claims(uuid7ish(0xD2), NEST_ROOT, ORCH, WK, {
    "export": {"format": ALL(ANY(ex("pdf"))), "limit": WILD}
}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.18.2", "nested all[any[...]]: derived removes an alternative", None,
    "format: all[any[pdf, csv, xlsx]] -> all[any[pdf]]. Inner any narrows; outer all is preserved.",
    [NEST_ROOT, nest_child], pop_sign(pop_claims(uuid7ish(0xD82), nest_child, "export", {"format": "pdf", "limit": 3}), WK),
    "export", {"format": "pdf", "limit": 3}, "PERMIT")


# --- J.21 structural root checks ---------------------------------------------
ph_root = jws_sign(root_claims(uuid7ish(0xE1), {"read_file": {"path": WILD}}, ORCH,
                              par_hash="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), CP)
add("J.21.1", "Root token carries par_hash", None,
    "A root MUST NOT contain par_hash (step 3d).",
    [ph_root], pop_sign(pop_claims(uuid7ish(0xE81), ph_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3d")
depth_root = jws_sign(root_claims(uuid7ish(0xE2), {"read_file": {"path": WILD}}, ORCH, del_depth=1), CP)
add("J.21.2", "Root token del_depth is not 0", None,
    "A root MUST have del_depth == 0 (step 3c).",
    [depth_root], pop_sign(pop_claims(uuid7ish(0xE82), depth_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3c")
priv_claims = root_claims(uuid7ish(0xE3), {"read_file": {"path": WILD}}, ORCH)
priv_claims["cnf"] = {"jwk": {**ORCH.jwk, "d": b64u(ORCH.seed)}}
priv_root = jws_sign(priv_claims, CP)
add("J.21.3", "cnf.jwk contains private key material", None,
    "Root cnf.jwk includes the Ed25519 d parameter. Step 3l requires a public key.",
    [priv_root], pop_sign(pop_claims(uuid7ish(0xE83), priv_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3l",
    notes=["The d value is the Orchestrator's published test seed (32 x 0x02), not a secret."])
future_root = jws_sign(root_claims(uuid7ish(0xE4), {"read_file": {"path": WILD}}, ORCH, iat=NOW + 31), CP)
add("J.21.4", "Root iat is more than MAX_IAT_SKEW in the future", None,
    "iat = now + 31, MAX_IAT_SKEW = 30 (step 3f).",
    [future_root], pop_sign(pop_claims(uuid7ish(0xE84), future_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3f")
long_root = jws_sign(root_claims(uuid7ish(0xE5), {"read_file": {"path": WILD}}, ORCH,
                                iat=IAT_ROOT, exp=IAT_ROOT + MAX_TOKEN_LIFETIME + 1), CP)
add("J.21.5", "Root lifetime exceeds MAX_TOKEN_LIFETIME", None,
    "exp = iat + 90 days + 1 (step 3h).",
    [long_root], pop_sign(pop_claims(uuid7ish(0xE85), long_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3h")
no_tools = jws_sign({**root_claims(uuid7ish(0xE7F), {}, ORCH),
                     "authorization_details": [{"type": "attenuating_agent_token"}]}, CP)
add("J.21.8", "AAT entry without a tools member", None,
    "The root's attenuating_agent_token entry has no tools member (step 3m).",
    [no_tools], pop_sign(pop_claims(uuid7ish(0xE8F), no_tools, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3m")
bad_map = jws_sign(root_claims(uuid7ish(0xE7D), {"read_file": ["path"]}, ORCH), CP)
add("J.21.10", "A tools value that is not a constraint-map object", None,
    "read_file maps to an array instead of a constraint map (step 3m).",
    [bad_map], pop_sign(pop_claims(uuid7ish(0xE8D), bad_map, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3m")
bad_all = jws_sign(root_claims(uuid7ish(0xE7C), {"read_file": {"path": {"constraint_type": "all",
                                                                         "constraints": WILD}}}, ORCH), CP)
add("J.21.11", "all whose constraints member is not an array", None,
    "The constraints member of all is an object, not an array; the constraint is not well-formed (step 3n).",
    [bad_all], pop_sign(pop_claims(uuid7ish(0xE8C), bad_all, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")
typo_range = jws_sign(root_claims(uuid7ish(0xE7B), {"read_file": {
    "path": WILD, "limit": {"constraint_type": "range", "maximum": 10}}}, ORCH), CP)
add("J.21.12", "range with an undefined member", None,
    "limit is constrained by a range whose bound is spelled maximum instead of max. Read as a range with "
    "no bounds, it would admit limit 1000; a member its type does not define makes the constraint not "
    "well-formed (step 3n).",
    [typo_range], pop_sign(pop_claims(uuid7ish(0xE8B), typo_range, "read_file", {"path": Q3, "limit": 1000}), ORCH),
    "read_file", {"path": Q3, "limit": 1000}, "DENY", "3n")
bool_depth = jws_sign(root_claims(uuid7ish(0xE7E), {"read_file": {"path": WILD}}, ORCH, del_depth=False), CP)
add("J.21.9", "Root del_depth is false rather than the integer 0", None,
    "del_depth must be an integer (Section 3.2); false is not 0 (step 3c).",
    [bool_depth], pop_sign(pop_claims(uuid7ish(0xE8E), bool_depth, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3c")
iss_root = jws_sign(root_claims(uuid7ish(0xE6), {"read_file": {"path": WILD}}, ORCH,
                               iss="https://other-issuer.example.com"), CP)
add("J.21.6", "Root iss does not match the verifying trust anchor", None,
    "Signed by the Control Plane key, whose trust anchor issuer is https://auth.example.com, but iss is "
    "https://other-issuer.example.com, which is not the issuer of any trust anchor (step 3k, RFC 8725 Section 3.8). "
    "Compare J.21.22, whose iss is the issuer of a trust anchor other than the one that verified it.",
    [iss_root], pop_sign(pop_claims(uuid7ish(0xE86), iss_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3k")
empty_all_root = jws_sign(root_claims(uuid7ish(0xE7), {"read_file": {"path": {"constraint_type": "all",
                                                                              "constraints": []}}}, ORCH), CP)
add("J.21.7", "Root carries an empty all constraint", None,
    "Single-token chain whose root constrains path with all([]). An empty conjunction would accept every "
    "value; it is rejected when the root's constraint trees are walked (step 3n).",
    [empty_all_root], pop_sign(pop_claims(uuid7ish(0xE87), empty_all_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3n")


# --- J.22 optional and unnamed arguments (§3.3, §4.5, steps 4p and 6b) ---------
RT = "read_text_file"
P = "/srv/api/README.md"
EXP = {"constraint_type": "exact", "value": P}


def lines(mx, optional=True):
    c = {"constraint_type": "range", "max": mx}
    if optional:
        c["optional"] = True
    return c


OPEN_MAP = {"path": EXP, "head": lines(200), "tail": lines(200), "*": WILDCARD}
CLOSED_MAP = {"path": EXP, "head": lines(200)}
OR = jws_sign(root_claims(uuid7ish(0x2200), {RT: OPEN_MAP}, ORCH), CP)
CR = jws_sign(root_claims(uuid7ish(0x2201), {RT: CLOSED_MAP}, ORCH), CP)


def leaf_case(vid, title, desc, root, args, expect, step=None, n=0):
    add(vid, title, None, desc, [root],
        pop_sign(pop_claims(uuid7ish(0x2280 + n), root, RT, args), ORCH), RT, args, expect, step)


def derive_case(vid, title, desc, root, child_map, args, expect, step=None, n=0):
    d = jws_sign(derived_claims(uuid7ish(0x2240 + n), root, ORCH, WK, {RT: child_map},
                                IAT_ROOT + 60, 1704069000, 2), ORCH)
    add(vid, title, None, desc, [root, d],
        pop_sign(pop_claims(uuid7ish(0x22C0 + n), d, RT, args), WK), RT, args, expect, step)


leaf_case("J.22.1", "Optional arguments may be omitted",
          "path is required; head and tail are optional; the invocation carries only path.",
          OR, {"path": P}, "PERMIT", n=1)
leaf_case("J.22.2", "A present optional argument is constrained",
          "head is optional with max 200; the invocation sets head to 100.",
          OR, {"path": P, "head": 100}, "PERMIT", n=2)
leaf_case("J.22.3", "A present optional argument that violates its constraint",
          "head is optional with max 200; the invocation sets head to 500.",
          OR, {"path": P, "head": 500}, "DENY", "6b", n=3)
leaf_case("J.22.4", "The * entry admits an unnamed argument",
          "The map carries *; the invocation adds encoding, which the map does not name.",
          OR, {"path": P, "encoding": "utf-8"}, "PERMIT", n=4)
leaf_case("J.22.5", "A required argument is still required",
          "path is required; the invocation carries only head.",
          OR, {"head": 10}, "DENY", "6b", n=5)
leaf_case("J.22.6", "Without *, an unnamed argument is rejected",
          "The map has path and optional head but no *; the invocation adds encoding.",
          CR, {"path": P, "encoding": "utf-8"}, "DENY", "6b", n=6)
derive_case("J.22.7", "Derived token makes an optional argument required",
            "Parent head is optional (max 200); child head is required (max 100). Required narrows.",
            CR, {"path": EXP, "head": lines(100, optional=False)}, {"path": P, "head": 50}, "PERMIT", n=7)
derive_case("J.22.8", "Derived token makes a required argument optional",
            "Parent path is required; child marks it optional, admitting invocations that omit it.",
            CR, {"path": {**EXP, "optional": True}, "head": lines(200)}, {"path": P}, "DENY", "4p3", n=8)
derive_case("J.22.9", "Derived token omits an optional argument, which forbids it",
            "Parent head is optional and the parent has no *; child omits head. The chain is valid, and "
            "an invocation that carries head is now rejected as unnamed.",
            CR, {"path": EXP}, {"path": P, "head": 10}, "DENY", "6b", n=9)
derive_case("J.22.10", "Derived token omits an optional argument; invocation without it",
            "Same derivation as J.22.9; the invocation carries only path.",
            CR, {"path": EXP}, {"path": P}, "PERMIT", n=10)
derive_case("J.22.11", "Derived token omits a required argument",
            "Parent path is required; the child omits it.",
            CR, {"head": lines(200)}, {"head": 10}, "DENY", "4p2", n=11)
derive_case("J.22.12", "Derived token constrains an argument the parent admitted via *",
            "Parent has *; child keeps * and adds encoding = exact utf-8. The invocation passes latin-1.",
            OR, {**OPEN_MAP, "encoding": {"constraint_type": "exact", "value": "utf-8"}},
            {"path": P, "encoding": "latin-1"}, "DENY", "6b", n=12)
derive_case("J.22.13", "Derived token constrains an argument the parent admitted via *; value allowed",
            "Same derivation as J.22.12; the invocation passes utf-8.",
            OR, {**OPEN_MAP, "encoding": {"constraint_type": "exact", "value": "utf-8"}},
            {"path": P, "encoding": "utf-8"}, "PERMIT", n=13)
derive_case("J.22.14", "Derived token adds * when the parent has none",
            "Parent map has no *; the child adds one, admitting arguments the parent forbids.",
            CR, {**CLOSED_MAP, "*": WILDCARD}, {"path": P}, "DENY", "4p2", n=14)
derive_case("J.22.15", "Derived token names an argument the parent neither names nor admits",
            "Parent map has no *; the child adds encoding as a required wildcard. The invocation passes encoding, "
            "so it satisfies the child's map and only the derivation (step 4p2) is at fault.",
            CR, {**CLOSED_MAP, "encoding": WILDCARD}, {"path": P, "encoding": "utf-8"}, "DENY", "4p2", n=15)
derive_case("J.22.16", "Derived token omits an optional argument but keeps *",
            "Parent has * and optional head; the child omits head and keeps *, so head would come back "
            "under * with any value.",
            OR, {"path": EXP, "tail": lines(200), "*": WILDCARD}, {"path": P}, "DENY", "4p2", n=16)
EMPTY_RT = jws_sign(root_claims(uuid7ish(0x2202), {RT: {}}, ORCH), CP)
derive_case("J.22.17", "Empty parent map is equivalent to *",
            "Parent map is empty; the child pins path and keeps *. Normalization treats the parent as {*: wildcard}.",
            EMPTY_RT, {"path": EXP, "*": WILDCARD}, {"path": P, "head": 5}, "PERMIT", n=17)
BAD_NEST = jws_sign(root_claims(uuid7ish(0x2203), {RT: {"path": {"constraint_type": "all", "constraints": [
    {**EXP, "optional": True}]}}}, ORCH), CP)
leaf_case("J.22.18", "optional inside all is not well-formed",
          "The optional member may appear only on a top-level constraint-map entry.",
          BAD_NEST, {"path": P}, "DENY", "3n", n=18)
derive_case("J.22.20", "Derived token names a new optional argument under the parent's *",
            "Parent has *; the child keeps * and adds encoding as an optional exact utf-8. The invocation omits it.",
            OR, {**OPEN_MAP, "encoding": {"constraint_type": "exact", "value": "utf-8", "optional": True}},
            {"path": P}, "PERMIT", n=20)
derive_case("J.22.21", "Derived token drops *",
            "Parent has *; the child keeps every named key and drops *. An invocation using only named arguments.",
            OR, {"path": EXP, "head": lines(200), "tail": lines(200)}, {"path": P, "tail": 20}, "PERMIT", n=21)
derive_case("J.22.22", "Derived token drops *; unnamed argument rejected",
            "Same derivation as J.22.21; the invocation adds encoding, which the child no longer admits.",
            OR, {"path": EXP, "head": lines(200), "tail": lines(200)}, {"path": P, "encoding": "utf-8"},
            "DENY", "6b", n=22)
BAD_STAR_OPT = jws_sign(root_claims(uuid7ish(0x2205), {RT: {"path": EXP, "*": {**WILDCARD, "optional": True}}},
                                    ORCH), CP)
leaf_case("J.22.23", "A * entry carrying optional is not well-formed",
          "The * entry must be a wildcard constraint without an optional member.",
          BAD_STAR_OPT, {"path": P}, "DENY", "3n", n=23)
BAD_STAR = jws_sign(root_claims(uuid7ish(0x2204), {RT: {"path": EXP, "*": {"constraint_type": "range", "max": 5}}},
                                ORCH), CP)
leaf_case("J.22.19", "A * entry that is not a wildcard is not well-formed",
          "In this specification the * entry must be a wildcard constraint.",
          BAD_STAR, {"path": P}, "DENY", "3n", n=19)


# ===========================================================================
# Vectors that pin the remaining -02 checks (added 2026-10). Each DENY vector
# differs from a valid presentation by one fault; `--fault-chains` lists the
# checks that catch it, and `--mutation-check` shows which vector each check
# depends on. Token and PoP jti values come from T() and P(), one block of 256
# per vector group.
# ===========================================================================
def T(group: int, k: int) -> str:
    return uuid7ish(0x30000 + (group << 8) + k)


def P(group: int, k: int) -> str:
    return uuid7ish(0x38000 + (group << 8) + k)


def pop_of(leaf: dict, holder: Key, tool: str, hta: dict, jti: str, header: dict = POP_HEADER, **kw) -> dict:
    return pop_sign(pop_claims(jti, leaf, tool, hta, **kw), holder, header)


def raw_json(obj, **texts) -> str:
    """dumps_exact(obj) with each "@@name@@" string replaced by the raw JSON text `name`."""
    out = dumps_exact(obj)
    for name, text in texts.items():
        marker = f'"@@{name}@@"'
        assert out.count(marker) == 1, name
        out = out.replace(marker, text)
    return out


def child_of_l0(k: int, tools: dict = L1_TOOLS, holder: Key = WK, iat: int = IAT_ROOT + 60, exp: int = 1704069000,
                dmd: int = 2, **changes) -> dict:
    """Claims for a child of the J.3 root, for the Orchestrator to sign, with `changes` applied (a value of
    None removes the member)."""
    c = derived_claims(T(24, k) if "jti" not in changes else changes["jti"], L0, ORCH, holder, tools, iat, exp, dmd)
    for name, value in changes.items():
        if value is None:
            c.pop(name, None)
        else:
            c[name] = value
    return c


READ_Q3 = {"path": Q3}
WILD_READ = {"read_file": {"path": WILD}}


def solo(vid: str, title: str, desc: str, root: dict, tool: str, args: dict, expect: str, step: str | None,
         pop_jti: str, **kw):
    """A single-token chain: `root` is presented as the leaf, with a PoP from the Orchestrator."""
    add(vid, title, None, desc, [root], pop_of(root, ORCH, tool, args, pop_jti), tool, args, expect, step, **kw)


# --- J.7.7-J.7.14 headers of derived tokens and PoP JWTs (steps 4a, 7a; Section 3.5) ---
for vid, k, header, title, desc in (
        ("J.7.7", 1, {"alg": "Ed25519"}, "Derived token missing typ",
         "The J.3 L1, correctly signed by the Orchestrator, with header {\"alg\":\"Ed25519\"}. Explicit typing "
         "applies to every token in the chain, not only the root (step 4a)."),
        ("J.7.8", 2, {"alg": "EdDSA", "typ": "aat+jwt"}, "Derived token with the deprecated polymorphic alg EdDSA",
         "The J.3 L1 with header alg EdDSA. The signature is a valid Ed25519 signature, so only the allowlist "
         "(Section 9.11, RFC 9864) rejects it; the allowlist applies to each token independently (step 4a)."),
        ("J.7.9", 3, {"alg": "Ed25519", "typ": "aat+jwt", "crit": ["urn:example:unknown"], "urn:example:unknown": True},
         "Derived token crit lists a parameter the enforcement point does not understand",
         "The J.3 L1 with a crit header naming an extension parameter (RFC 7515 Section 4.1.11, step 4a).")):
    tok = jws_sign(derived_claims(T(7, k), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH, header)
    add(vid, title, None, desc, [L0, tok], pop_of(tok, WK, "read_file", READ_Q3, P(7, k)),
        "read_file", READ_Q3, "DENY", "4a")
add("J.7.10", "PoP JWT with the deprecated polymorphic alg EdDSA", None,
    "Valid J.3 chain; the PoP is a valid Ed25519 signature by Worker2 but its header names alg EdDSA (step 7a).",
    [L0, L1, L2], pop_of(L2, WK2, "read_file", READ_Q3, P(7, 4), {"alg": "EdDSA", "typ": "aat-pop+jwt"}),
    "read_file", READ_Q3, "DENY", "7a")
add("J.7.11", "PoP JWT crit lists a parameter the enforcement point does not understand", None,
    "Valid J.3 chain; the PoP header carries crit [urn:example:unknown] (RFC 7515 Section 4.1.11, step 7a).",
    [L0, L1, L2], pop_of(L2, WK2, "read_file", READ_Q3, P(7, 5),
                         {**POP_HEADER, "crit": ["urn:example:unknown"], "urn:example:unknown": True}),
    "read_file", READ_Q3, "DENY", "7a")
TRACE = {"urn:example:trace": "t-7f3a"}
tr_root = jws_sign(root_claims(T(7, 6), ROOT_TOOLS, ORCH), CP, {**HEADER, **TRACE})
tr_l1 = jws_sign(derived_claims(T(7, 7), tr_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH,
                 {**HEADER, **TRACE})
add("J.7.12", "Unrecognized header parameters are ignored", None,
    "The J.3 root and L1 shape, each with an extra header parameter urn:example:trace that is not listed in crit, "
    "and a PoP whose header carries it too. Enforcement points MUST ignore header parameters they do not "
    "recognize (Section 3.5). PERMIT.",
    [tr_root, tr_l1], pop_of(tr_l1, WK, "read_file", READ_Q3, P(7, 6), {**POP_HEADER, **TRACE}),
    "read_file", READ_Q3, "PERMIT")
jwk_root = jws_sign(root_claims(T(7, 8), WILD_READ, ORCH), CP, {**HEADER, "jwk": ATK.jwk})
add("J.7.13", "A header jwk on an AAT is ignored", None,
    "A valid root signed by the Control Plane whose header also carries a jwk: the Attacker's public key. A token "
    "carrying a header key is verified as if it were absent (Section 3.5), so this is PERMIT; a verifier that took "
    "the key from the header would check the signature against the wrong key and deny. Compare J.14.c.",
    [jwk_root], pop_of(jwk_root, ORCH, "read_file", READ_Q3, P(7, 8)), "read_file", READ_Q3, "PERMIT")
add("J.7.14", "A header jwk on the PoP JWT is ignored", None,
    "Valid J.3 chain; the PoP, signed by Worker2, carries the Attacker's public key as a header jwk, as a DPoP "
    "proof would carry its own key. The PoP key is always leaf.cnf.jwk (Section 3.5, step 7b). PERMIT.",
    [L0, L1, L2], pop_of(L2, WK2, "read_file", READ_Q3, P(7, 9), {**POP_HEADER, "jwk": ATK.jwk}),
    "read_file", READ_Q3, "PERMIT")

# --- J.8.10-J.8.14 number admissibility (Section 3.4, step 6b) -------------
NUM_NOTE = ("Read the invocation from args_json with a parser that keeps every number's exact value; a parser that "
            "rounds to doubles cannot tell admissible from inadmissible numbers.")
add("J.8.10", "Argument whose double is exact but whose JCS form is another number", None,
    "id = 2^60 = 1152921504606846976. The double is exact, but JCS prints it with the shortest round-trip digits, "
    "1152921504606847000, which denotes a different value, so the number is not admissible (Section 3.4). DENY at "
    "step 6b; exactness of the double is not the test. The PoP's hta carries the JCS form, 1152921504606847000, "
    "so step 6b is the only fault.",
    [big_root], pop_of(big_root, ORCH, "get_account", {"id": 1152921504606847000}, P(8, 10)), "get_account",
    {"id": 2**60},
    "DENY", "6b", notes=[NUM_NOTE])
add("J.8.11", "Argument whose double is inexact but whose JCS form is the same number", None,
    "id = 1152921504606847000. It rounds to the double 2^60, which JCS prints as 1152921504606847000: the input's "
    "own value, so the number is admissible. PERMIT. Together with J.8.10 this separates the Section 3.4 rule "
    "from a test of whether the double is exact.",
    [big_root], pop_of(big_root, ORCH, "get_account", {"id": 1152921504606847000}, P(8, 11)),
    "get_account", {"id": 1152921504606847000}, "PERMIT", notes=[NUM_NOTE])
add("J.8.12", "Argument written with an exponent", None,
    "args_json writes id as 1e20, one of the Section 3.4 examples of an admissible number. The PoP's hta carries "
    "its JCS form, 100000000000000000000; step 7f compares JCS forms, so the two match. PERMIT.",
    [big_root], pop_of(big_root, ORCH, "get_account", {"id": 10**20}, P(8, 12)), "get_account", None,
    "PERMIT", args_json='{"id":1e20}', notes=[NUM_NOTE])
add("J.8.13", "Argument with a fraction", None,
    "args_json writes id as 0.1, a Section 3.4 example of an admissible number: its double is not exactly 0.1, "
    "but JCS prints it as 0.1. PERMIT.",
    [big_root], pop_of(big_root, ORCH, "get_account", {"id": Decimal("0.1")}, P(8, 13)), "get_account", None,
    "PERMIT", args_json='{"id":0.1}', notes=[NUM_NOTE])
add("J.8.14", "Argument with more precision than a double holds", None,
    "args_json writes id as 1.00000000000000001, the Section 3.4 example of an inadmissible number: JCS prints its "
    "double as 1. DENY at step 6b. The PoP's hta carries the JCS form, 1, so step 6b is the only fault.",
    [big_root], pop_of(big_root, ORCH, "get_account", {"id": 1}, P(8, 14)), "get_account", None, "DENY", "6b",
    args_json='{"id":1.00000000000000001}', notes=[NUM_NOTE])


# --- J.8.15-J.8.24 constraint well-formedness (Section 3.4, steps 3n, 4o) -----
def nested(depth: int) -> dict:
    """A constraint tree exactly `depth` levels deep: alternating all/any around exact 5."""
    c = ex(5)
    for i in range(depth - 1):
        c = (ALL if i % 2 == 0 else ANY)(c)
    return c


deep32 = jws_sign(root_claims(T(8, 15), {"set_level": {"level": nested(MAX_CONSTRAINT_DEPTH)}}, ORCH), CP)
solo("J.8.15", "Constraint tree exactly MAX_CONSTRAINT_DEPTH deep",
     "set_level.level is 31 alternating all/any constraints around exact 5: depth 32, the RECOMMENDED "
     "MAX_CONSTRAINT_DEPTH (Section 3.4). The invocation sets level 5. PERMIT.",
     deep32, "set_level", {"level": 5}, "PERMIT", None, P(8, 15))
deep33 = jws_sign(root_claims(T(8, 16), {"set_level": {"level": nested(MAX_CONSTRAINT_DEPTH + 1)}}, ORCH), CP)
solo("J.8.16", "Constraint tree one level deeper than MAX_CONSTRAINT_DEPTH",
     "As J.8.15 with one more all: depth 33 (step 3n). Evaluated, it would still accept level 5.",
     deep33, "set_level", {"level": 5}, "DENY", "3n", P(8, 16))
for vid, k, bad, title, desc in (
        ("J.8.17", 17, {"constraint_type": "one_of", "values": []}, "one_of with an empty values array",
         "one_of.values must be a non-empty array (Section 3.4); to authorize no value, the issuer omits the tool."),
        ("J.8.18", 18, {"constraint_type": "exact", "value": ["pdf", "csv"]}, "exact whose value is an array",
         "exact.value must be a string, number, boolean, or null (Section 3.4)."),
        ("J.8.19", 19, {"constraint_type": "not_one_of", "excluded": "secret"}, "not_one_of whose excluded is a string",
         "excluded must be an array (Section 3.4)."),
        ("J.8.20", 20, {"constraint_type": "range", "max": "100"}, "range whose bound is a string",
         "min and max must be numbers (Section 3.4)."),
        ("J.8.21", 21, {"constraint_type": "range", "max": 10, "min_inclusive": False},
         "range with min_inclusive but no min",
         "min_inclusive may appear only with min (Section 3.4).")):
    tok = jws_sign(root_claims(T(8, k), {**WILD_READ, "export": {"format": bad}}, ORCH), CP)
    solo(vid, title, f"Root authorizes read_file (wildcard path) and export, whose format constraint is malformed. "
                     f"{desc} The invocation is read_file; the chain is rejected when the root's constraint trees "
                     f"are walked (step 3n).",
         tok, "read_file", READ_Q3, "DENY", "3n", P(8, k))
incl = jws_sign(root_claims(T(8, 22), {"set_level": {"level": rng(min=0, max=10, min_inclusive="false")}}, ORCH), CP)
solo("J.8.22", "range inclusivity flag that is a string",
     "level is range(min 0, max 10) with min_inclusive \"false\", a string. The issuer meant to exclude 0, but a "
     "string is truthy, so a verifier that read it loosely would admit level 0. min_inclusive must be a boolean "
     "(Section 3.4, step 3n).",
     incl, "set_level", {"level": 0}, "DENY", "3n", P(8, 22))
opt = jws_sign(root_claims(T(8, 23), {RT: {"path": {**EXP, "optional": "false"}}}, ORCH), CP)
solo("J.8.23", "optional that is a string",
     "read_text_file.path is exact with optional \"false\", a string. The issuer meant path to be required, but a "
     "truthy reading makes it optional, and the invocation omits it. optional must be a boolean (Section 3.4, "
     "step 3n).",
     opt, RT, {}, "DENY", "3n", P(8, 23))
bad_l1 = jws_sign(child_of_l0(0, tools={"read_file": L1_TOOLS["read_file"],
                                       "search_index": {"query": ex("public filings"), "limit": rng(min=50, max=20)}},
                              jti=T(8, 24)), ORCH)
add("J.8.24", "Malformed constraint in a derived token, on a tool that is not invoked", None,
    "L1 of the J.3 chain with search_index.limit = range(min 50, max 20), which is not well-formed (min greater "
    "than max). Its max still lies within the parent's range max 100, so step 4p would accept it. The "
    "invocation is read_file; the chain is rejected when the child's constraint trees are walked (step 4o).",
    [L0, bad_l1], pop_of(bad_l1, WK, "read_file", READ_Q3, P(8, 24)), "read_file", READ_Q3, "DENY", "4o")

# --- J.9.6 a grant-shaped claim outside authorization_details (Section 3.3, step 6b) ---
scope_l1 = jws_sign(child_of_l0(6, scope="read_file search_index delete_file", jti=T(9, 6)), ORCH)
add("J.9.6", "A tool named only by a scope claim in a derived token", None,
    "L1 of the J.3 chain carries a scope claim (RFC 8693 Section 4.2), \"read_file search_index delete_file\", "
    "which names delete_file; neither L1's attenuating_agent_token entry nor the root grants it. The invocation is "
    "delete_file. Only the leaf's attenuating_agent_token entry authorizes a tool (step 6b), and claims this "
    "specification does not define carry no authority in a derived token (Section 3.3); a verifier that read scope "
    "as a grant would accept.",
    [L0, scope_l1], pop_of(scope_l1, WK, "delete_file", READ_Q3, P(9, 6)), "delete_file", READ_Q3, "DENY", "6b")

# --- J.10.d-J.10.f delegation depth (I2, steps 4d, 4m) -----------------------
dm = jws_sign(derived_claims(T(10, 4), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 0), ORCH)
add("J.10.d", "I2 violation: derived del_max_depth below its del_depth", None,
    "L1 has del_depth 1 and del_max_depth 0. It is within the parent's ceiling (4e, 4g) but below its own depth "
    "(step 4m).",
    [L0, dm], pop_of(dm, WK, "read_file", READ_Q3, P(10, 4)), "read_file", READ_Q3, "DENY", "4m")
skip_a = jws_sign(derived_claims(T(10, 5), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 3, depth=2), ORCH)
skip_b = jws_sign(derived_claims(T(10, 6), skip_a, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 3, depth=2), WK)
add("J.10.e", "I2 violation: depth skips a level and then repeats", None,
    "Root (depth 0) -> A (depth 2) -> B (depth 2), every del_max_depth 3. The leaf's depth plus one equals the "
    "chain length, so step 5 passes; only the per-link check (step 4d) catches the chain. A verifier that checks "
    "only that depth increases would also miss A.",
    [L0, skip_a, skip_b], pop_of(skip_b, WK2, "read_file", READ_Q3, P(10, 6)), "read_file", READ_Q3, "DENY", "4d")
deep_chain = [jws_sign(root_claims(T(10, 0x10), {"read_file": {"path": {"constraint_type": "one_of", "values": [Q3, Q4]}}},
                                   ORCH, dmd=MAX_DELEGATION_DEPTH), CP)]
HOLDERS = (ORCH, WK, WK2)
for d in range(1, MAX_DELEGATION_DEPTH + 1):
    deep_chain.append(jws_sign(derived_claims(T(10, 0x10 + d), deep_chain[-1], HOLDERS[(d - 1) % 3], HOLDERS[d % 3],
                                              L2_TOOLS, IAT_ROOT + 10 * d, EXP_ROOT - 60 * d, MAX_DELEGATION_DEPTH),
                               HOLDERS[(d - 1) % 3]))
add("J.10.f", "Chain at MAX_DELEGATION_DEPTH", None,
    f"A root with del_max_depth {MAX_DELEGATION_DEPTH} and {MAX_DELEGATION_DEPTH} derivations, holders cycling "
    "Orchestrator -> Worker -> Worker2. The leaf has del_depth 8, the minimum MAX_DELEGATION_DEPTH an "
    f"implementation may choose (Section 4.3), so every conforming verifier accepts it. The chain is "
    f"{sum(len(t['compact']) for t in deep_chain)} bytes. PERMIT.",
    deep_chain, pop_of(deep_chain[-1], HOLDERS[MAX_DELEGATION_DEPTH % 3], "read_file", READ_Q3, P(10, 0x10)),
    "read_file", READ_Q3, "PERMIT")

# --- J.13.c-J.13.f derived-token lifetimes (I3, steps 4h-4l) -----------------
for vid, k, iat, exp, step, title, desc in (
        ("J.13.c", 3, IAT_ROOT + 60, NOW, "4i", "I3 violation: derived token expired while its parent is valid",
         "L1 exp = now; exp must be strictly greater than now (step 4i). The root is still valid."),
        ("J.13.d", 4, NOW + MAX_IAT_SKEW + 1, 1704069000, "4k", "I3 violation: derived iat beyond MAX_IAT_SKEW",
         "L1 iat = now + 31 with MAX_IAT_SKEW 30 (step 4k)."),
        ("J.13.e", 5, NOW + 10, NOW + 10, "4l", "I3 violation: derived exp equal to its iat",
         "L1 iat = exp = now + 10: not expired and within the skew, but exp must be strictly greater than iat "
         "(step 4l).")):
    tok = jws_sign(derived_claims(T(13, k), L0, ORCH, WK, L1_TOOLS, iat, exp, 2), ORCH)
    add(vid, title, None, desc, [L0, tok], pop_of(tok, WK, "read_file", READ_Q3, P(13, k)),
        "read_file", READ_Q3, "DENY", step)
edge_root = jws_sign(root_claims(T(13, 6), ROOT_TOOLS, ORCH, iat=NOW + MAX_IAT_SKEW), CP)
edge_l1 = jws_sign(derived_claims(T(13, 7), edge_root, ORCH, WK, L1_TOOLS, NOW + MAX_IAT_SKEW, EXP_ROOT, 2), ORCH)
add("J.13.f", "Every inclusive lifetime bound at its limit", None,
    "Root iat = now + 30 (MAX_IAT_SKEW, step 3f); L1 iat = root iat (4j) = now + 30 (4k) and L1 exp = root exp "
    "(4h). Each of these relations is <= or >=, so the chain is valid. PERMIT.",
    [edge_root, edge_l1], pop_of(edge_l1, WK, "read_file", READ_Q3, P(13, 7)), "read_file", READ_Q3, "PERMIT")


# --- J.19 the Section 4.5 subsumption table ----------------------------------
def pair(vid: str, title: str, desc: str, parent_c: dict, child_c: dict, value, expect: str, k: int,
         notes: list[str] | None = None):
    """Root pick.v = parent_c; the derived token narrows it to child_c; the invocation passes v = value,
    which satisfies child_c, so only the derivation can be at fault."""
    r = jws_sign(root_claims(T(19, 2 * k), {"pick": {"v": parent_c}}, ORCH), CP)
    c = jws_sign(derived_claims(T(19, 2 * k + 1), r, ORCH, WK, {"pick": {"v": child_c}},
                                IAT_ROOT + 60, 1704069000, 2), ORCH)
    add(vid, title, None, desc, [r, c], pop_of(c, WK, "pick", {"v": value}, P(19, k)), "pick", {"v": value},
        expect, None if expect == "PERMIT" else "4p4", notes=notes)


def one_of(*xs):
    return {"constraint_type": "one_of", "values": list(xs)}


CONSERVATIVE = ("Conservative by design: the derived constraint is semantically narrower, but §4.5 rejects every "
                "pair its table does not list.")
pair("J.19.1", "exact under any is rejected",
     "pick.v: any[exact pdf, exact csv] -> exact pdf. Section 4.1 names this pair as semantically valid but "
     "structurally rejected; a derived any[exact pdf] would be accepted.",
     ANY(ex("pdf"), ex("csv")), ex("pdf"), "pdf", "DENY", 1, notes=[CONSERVATIVE])
pair("J.19.2", "not_one_of under one_of is rejected",
     "pick.v: one_of[pdf, csv, xlsx] -> not_one_of[xlsx]. The derived constraint admits values outside the "
     "parent's set (§4.5 names this pair).",
     one_of("pdf", "csv", "xlsx"), n1of("xlsx"), "pdf", "DENY", 2)
pair("J.19.3", "one_of to exact with a value outside the set",
     "pick.v: one_of[pdf, csv] -> exact xlsx. The invocation passes xlsx, which the derived token allows and "
     "the root never did.",
     one_of("pdf", "csv"), ex("xlsx"), "xlsx", "DENY", 3)
pair("J.19.4", "exact under not_one_of is rejected",
     "pick.v: not_one_of[secret] -> exact public. (not_one_of, exact) is not in the table.",
     n1of("secret"), ex("public"), "public", "DENY", 4, notes=[CONSERVATIVE])
pair("J.19.5", "one_of under not_one_of is rejected",
     "pick.v: not_one_of[secret] -> one_of[public, internal]. (not_one_of, one_of) is not in the table.",
     n1of("secret"), one_of("public", "internal"), "public", "DENY", 5, notes=[CONSERVATIVE])
pair("J.19.6", "one_of under exact is rejected",
     "pick.v: exact pdf -> one_of[pdf]. The two accept the same value, but (exact, one_of) is not in the table.",
     ex("pdf"), one_of("pdf"), "pdf", "DENY", 6, notes=[CONSERVATIVE])
pair("J.19.7", "one_of under range is rejected",
     "pick.v: range[0, 100] -> one_of[10, 20]. (range, one_of) is not in the table; exact is the only "
     "non-range type a range parent accepts.",
     rng(min=0, max=100), one_of(10, 20), 10, "DENY", 7, notes=[CONSERVATIVE])
pair("J.19.8", "range to exact inside the range",
     "pick.v: range[0, 100] -> exact 50. Valid: exact whose value is a number the parent range accepts.",
     rng(min=0, max=100), ex(50), 50, "PERMIT", 8)
pair("J.19.9", "range to exact outside the range",
     "pick.v: range[0, 100] -> exact 150.",
     rng(min=0, max=100), ex(150), 150, "DENY", 9)
pair("J.19.10", "exact to a different exact",
     "pick.v: exact pdf -> exact csv.",
     ex("pdf"), ex("csv"), "csv", "DENY", 10)
pair("J.19.11", "range: derived min below the parent's",
     "pick.v: range[10, 100] -> range[5, 100].",
     rng(min=10, max=100), rng(min=5, max=100), 50, "DENY", 11)
pair("J.19.12", "range: derived drops a bound the parent has",
     "pick.v: range[max 100] -> range[min 0]. A missing derived bound is valid only if the parent bound is "
     "missing too.",
     rng(max=100), rng(min=0), 50, "DENY", 12)
pair("J.19.13", "range: inclusive derived max under an exclusive parent max",
     "pick.v: range[max 100, max_inclusive false] -> range[max 100]. The derived range admits 100.",
     rng(max=100, max_inclusive=False), rng(max=100), 50, "DENY", 13)
EVERY = {"a": (ex("x"), "x"), "b": (rng(min=0, max=10), 5), "c": (one_of("x", "y"), "y"),
         "d": (n1of("z"), "x"), "e": (reqd("x"), ["x", "y"]), "f": (sub("x", "y"), ["x"]),
         "g": (ALL(rng(min=0), rng(max=10)), 5), "h": (ANY(ex("x"), ex("y")), "x"), "i": (WILD, "anything")}
w_root = jws_sign(root_claims(T(19, 40), {"pick": {a: WILD for a in EVERY}}, ORCH), CP)
w_child = jws_sign(derived_claims(T(19, 41), w_root, ORCH, WK, {"pick": {a: c for a, (c, _) in EVERY.items()}},
                                  IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.19.14", "A wildcard parent subsumes every core type", None,
    "Root pick has nine wildcard arguments a-i; the derived token constrains them with exact, range, one_of, "
    "not_one_of, contains, subset, all, any, and wildcard respectively. Every (wildcard, T) pair is valid. "
    "PERMIT.",
    [w_root, w_child], pop_of(w_child, WK, "pick", {a: v for a, (_, v) in EVERY.items()}, P(19, 20)),
    "pick", {a: v for a, (_, v) in EVERY.items()}, "PERMIT")
opt_root = jws_sign(root_claims(T(19, 42), {RT: {"head": lines(200), "tail": lines(200)}}, ORCH), CP)
opt_child = jws_sign(derived_claims(T(19, 43), opt_root, ORCH, WK, {RT: {}}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.19.15", "Derived empty map under a closed parent", None,
    "Root read_text_file has only the optional head and tail (max 200) and no *; the derived token's map is "
    "empty. Normalized, the empty map is {\"*\": wildcard}, which the parent does not have and which would "
    "readmit head and tail with any value (step 4p2). A verifier that normalized only at step 6b would accept "
    "the invocation head = 500.",
    [opt_root, opt_child], pop_of(opt_child, WK, RT, {"head": 500}, P(19, 21)), RT, {"head": 500}, "DENY", "4p2")

# --- J.20.12-J.20.16 PoP claims (steps 7b, 7c, 7g) ---------------------------
dup_hta = raw_json(pop_claims(P(20, 12), L2, "read_file", "@@hta@@"), hta=f'{{"path":"{Q4}","path":"{Q3}"}}')
add("J.20.12", "PoP hta repeats a member with different values", None,
    "Valid J.3 chain; the PoP's hta is {\"path\": q4, \"path\": q3}. A parser that keeps the last member sees "
    "args that match the invocation; one that keeps the first sees a mismatch. Step 7b rejects the duplicate "
    "before either reading matters.",
    [L0, L1, L2], jws_sign_raw(dup_hta, WK2, POP_HEADER), "read_file", READ_Q3, "DENY", "7b")
add("J.20.13", "PoP jti is an empty string", None,
    "Valid J.3 chain; the PoP's jti is \"\". It must be a non-empty string (step 7c) even where no jti "
    "tracking is deployed.",
    [L0, L1, L2], pop_sign({**pop_claims(P(20, 13), L2, "read_file", READ_Q3), "jti": ""}, WK2),
    "read_file", READ_Q3, "DENY", "7c")
pop_frac = raw_json({**pop_claims(P(20, 14), L2, "read_file", READ_Q3), "iat": "@@iat@@"}, iat=f"{NOW}.0")
add("J.20.14", "PoP iat written with a fraction", None,
    f"Valid J.3 chain; the PoP's iat is written {NOW}.0. Its value is now, but a NumericDate in a PoP JWT has no "
    "fraction or exponent part (Section 3.2, step 7c).",
    [L0, L1, L2], jws_sign_raw(pop_frac, WK2, POP_HEADER), "read_file", READ_Q3, "DENY", "7c")
add("J.20.15", "PoP iat beyond the clock window in the future", None,
    "Valid J.3 chain; PoP iat = now + 31 with a ±30 s window. The window is bilateral (step 7g, Section 9.9).",
    [L0, L1, L2], pop_of(L2, WK2, "read_file", READ_Q3, P(20, 15), iat=NOW + POP_WINDOW + 1),
    "read_file", READ_Q3, "DENY", "7g")
add("J.20.16", "PoP iat in the future, inside the clock window", None,
    "Valid J.3 chain; PoP iat = now + 20, inside the ±30 s window. PERMIT.",
    [L0, L1, L2], pop_of(L2, WK2, "read_file", READ_Q3, P(20, 16), iat=NOW + 20), "read_file", READ_Q3, "PERMIT")
POP_HTA_BIG = raw_json(pop_claims(P(20, 17), big_root, "get_account", {"id": "@@id@@"}), id=str(2**53 + 1))
add("J.20.17", "PoP hta number that does not survive the JCS round trip", None,
    "The invocation passes id = 9007199254740992 (2^53), which is admissible. The PoP's hta writes id as "
    "9007199254740993 (2^53 + 1), which rounds to the same double and so has the same JCS form; the canonical "
    "forms match, but the signed number is not admissible (Section 3.4), so step 7f denies.",
    [big_root], jws_sign_raw(POP_HTA_BIG, ORCH, POP_HEADER), "get_account", None, "DENY", "7f",
    args_json='{"id":9007199254740992}', notes=[NUM_NOTE])

# --- J.21.13-J.21.23 root claims (steps 3b, 3g, 3i-3l) ----------------------
solo("J.21.13", "Root exp written with an exponent",
     "Root exp is written 1.7040708e9, the value 1704070800 in exponent form. NumericDate values have no fraction "
     "or exponent part (Section 3.2, step 3b).",
     jws_sign_raw(raw_json({**root_claims(T(21, 13), WILD_READ, ORCH), "exp": "@@exp@@"}, exp="1.7040708e9"), CP),
     "read_file", READ_Q3, "DENY", "3b", P(21, 13))
solo("J.21.14", "Root exp equal to its iat",
     "Root iat = exp = now + 10: not expired and within the skew, but exp must be strictly greater than iat "
     "(step 3g).",
     jws_sign(root_claims(T(21, 14), WILD_READ, ORCH, iat=NOW + 10, exp=NOW + 10), CP),
     "read_file", READ_Q3, "DENY", "3g", P(21, 14))
for vid, k, text, title, desc in (
        ("J.21.15", 15, "9", "Root del_max_depth above MAX_DELEGATION_DEPTH",
         "del_max_depth 9 with MAX_DELEGATION_DEPTH 8. The chain is a single token, so no depth is ever used; the "
         "root's ceiling is still checked (step 3i)."),
        ("J.21.16", 16, "3.0", "Root del_max_depth written with a fraction",
         "del_max_depth is written 3.0. Its value is 3, but del_max_depth is an integer with no fraction part "
         "(Section 3.2, step 3i)."),
        ("J.21.17", 17, "3e0", "Root del_max_depth written with an exponent",
         "del_max_depth is written 3e0 (Section 3.2, step 3i)."),
        ("J.21.18", 18, None, "Root without del_max_depth",
         "del_max_depth is absent. It is REQUIRED and has no default (step 3i).")):
    claims = root_claims(T(21, k), WILD_READ, ORCH)
    if text is None:
        del claims["del_max_depth"]
        tok = jws_sign(claims, CP)
    else:
        tok = jws_sign_raw(raw_json({**claims, "del_max_depth": "@@dmd@@"}, dmd=text), CP)
    solo(vid, title, desc, tok, "read_file", READ_Q3, "DENY", "3i", P(21, k))
solo("J.21.19", "Root del_max_depth equal to MAX_DELEGATION_DEPTH",
     "del_max_depth 8 = MAX_DELEGATION_DEPTH. Not exceeding is <= (step 3i). PERMIT.",
     jws_sign(root_claims(T(21, 19), WILD_READ, ORCH, dmd=MAX_DELEGATION_DEPTH), CP),
     "read_file", READ_Q3, "PERMIT", None, P(21, 19))
empty_jti_root = jws_sign(root_claims("", ROOT_TOOLS, ORCH), CP)
ej_l1 = jws_sign(derived_claims(T(21, 21), empty_jti_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.21.20", "Root jti is an empty string", None,
    "The J.3 root with jti \"\", and a valid L1 under it. Step 2c extracts \"\" as a string; step 3j requires a "
    "non-empty one. The leaf's jti is ordinary, so the PoP is unaffected.",
    [empty_jti_root, ej_l1], pop_of(ej_l1, WK, "read_file", READ_Q3, P(21, 20)), "read_file", READ_Q3,
    "DENY", "3j")
wrong_kty_claims = root_claims(T(21, 22), WILD_READ, ORCH)
wrong_kty_claims["cnf"] = {"jwk": {**ORCH.jwk, "kty": "RSA"}}
wrong_kty_root = jws_sign(wrong_kty_claims, CP)
solo("J.21.21", "Root cnf.jwk has a key type inconsistent with Ed25519",
     "The JWK declares kty RSA while retaining a valid Ed25519 crv and x. A verifier that uses x alone would "
     "accept the PoP; step 3l rejects the invalid public JWK.",
     wrong_kty_root, "read_file", READ_Q3, "DENY", "3l", P(21, 21))
cross_root = jws_sign(root_claims(T(21, 23), WILD_READ, ORCH), CP2)  # iss is ROOT_ISS, the first anchor's issuer
solo("J.21.22", "Root iss names another trust anchor's issuer",
     f"The suite's second trust anchor pairs the control_plane2 key with issuer {ROOT_ISS2}. This root is signed "
     f"by that key, but its iss is {ROOT_ISS}, the first trust anchor's issuer. Step 3k compares iss with the "
     "issuer of the anchor whose key verified the signature (RFC 8725 Section 3.8); a verifier that accepted the "
     f"issuer of any trust anchor would accept. Compare J.21.23, a root signed by the same key with iss {ROOT_ISS2}, "
     "and J.21.6, whose iss is not the issuer of any trust anchor.",
     cross_root, "read_file", READ_Q3, "DENY", "3k", P(21, 22))
second_root = jws_sign(root_claims(T(21, 24), WILD_READ, ORCH, iss=ROOT_ISS2), CP2)
solo("J.21.23", "Root signed by the second trust anchor's key",
     f"A root signed by the control_plane2 key with iss {ROOT_ISS2}: the key and issuer of the suite's second "
     "trust anchor. Step 3b verifies the signature against the public key of a trust anchor, here the second one, "
     "and step 3k compares iss with that anchor's issuer. A verifier that tried only the first trust anchor would "
     "deny. PERMIT. Compare J.21.22, a root signed by the same key with the first trust anchor's issuer.",
     second_root, "read_file", READ_Q3, "PERMIT", None, P(21, 23))

# --- J.24 derived-token claims (steps 2c, 4b) ---------------------------------
num_jti_root = jws_sign(root_claims(2401, ROOT_TOOLS, ORCH), CP)
nj_l1 = jws_sign(derived_claims(T(24, 1), num_jti_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.24.1", "A jti that is not a string", None,
    "The J.3 root with jti 2401, a number, and a valid L1 under it. Step 2c cannot extract a string-valued jti "
    "and denies before any signature is verified; step 3j would deny it too.",
    [num_jti_root, nj_l1], pop_of(nj_l1, WK, "read_file", READ_Q3, P(24, 1)), "read_file", READ_Q3, "DENY", "2c")
mid = jws_sign(child_of_l0(2, jti=""), ORCH)
mid_leaf = jws_sign(derived_claims(T(24, 3), mid, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 2), WK)
add("J.24.2", "Intermediate token jti is an empty string", None,
    "The J.3 chain with L1's jti set to \"\" (L2 re-derived over it). The leaf's jti is ordinary, so only step "
    "4b1 applies.",
    [L0, mid, mid_leaf], pop_of(mid_leaf, WK2, "read_file", READ_Q3, P(24, 2)), "read_file", READ_Q3, "DENY", "4b1")
priv_l1 = jws_sign(child_of_l0(4, cnf={"jwk": {**WK.jwk, "d": b64u(WK.seed)}}), ORCH)
add("J.24.3", "Derived cnf.jwk contains private key material", None,
    "L1's cnf.jwk carries the Worker's d parameter alongside x (step 4b2). The public part is still the Worker's "
    "key, so the PoP verifies.",
    [L0, priv_l1], pop_of(priv_l1, WK, "read_file", READ_Q3, P(24, 4)), "read_file", READ_Q3, "DENY", "4b2",
    notes=["The d value is the Worker's published test seed (32 x 0x03), not a secret."])
dd_frac = jws_sign_raw(raw_json({**child_of_l0(5), "del_depth": "@@dd@@"}, dd="1.0"), ORCH)
add("J.24.4", "Derived del_depth written with a fraction", None,
    "L1's del_depth is written 1.0: the right value, but not an integer in the Section 3.2 sense (step 4b4).",
    [L0, dd_frac], pop_of(dd_frac, WK, "read_file", READ_Q3, P(24, 5)), "read_file", READ_Q3, "DENY", "4b4")
dd_exp = jws_sign_raw(raw_json({**derived_claims(T(24, 6), L1, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 2),
                                "del_depth": "@@dd@@"}, dd="2e0"), WK)
add("J.24.5", "Derived del_depth written with an exponent", None,
    "The J.3 chain with L2's del_depth written 2e0 (step 4b4).",
    [L0, L1, dd_exp], pop_of(dd_exp, WK2, "read_file", READ_Q3, P(24, 6)), "read_file", READ_Q3, "DENY", "4b4")
iat_frac = jws_sign_raw(raw_json({**child_of_l0(7), "iat": "@@iat@@"}, iat=f"{IAT_ROOT + 60}.5"), ORCH)
add("J.24.6", "Derived iat with a fraction", None,
    f"L1's iat is {IAT_ROOT + 60}.5. RFC 7519 allows fractional NumericDates, but this profile does not (Section "
    "3.2, step 4b5).",
    [L0, iat_frac], pop_of(iat_frac, WK, "read_file", READ_Q3, P(24, 7)), "read_file", READ_Q3, "DENY", "4b5")
no_iss = jws_sign(child_of_l0(8, iss=None), ORCH)
add("J.24.7", "Derived token without iss", None,
    "L1 omits iss (step 4b5; step 4c would also fail).",
    [L0, no_iss], pop_of(no_iss, WK, "read_file", READ_Q3, P(24, 8)), "read_file", READ_Q3, "DENY", "4b5")
no_ph = jws_sign(child_of_l0(9, par_hash=None), ORCH)
add("J.24.8", "Derived token without par_hash", None,
    "L1 omits par_hash (step 4b5; step 4q would also fail).",
    [L0, no_ph], pop_of(no_ph, WK, "read_file", READ_Q3, P(24, 9)), "read_file", READ_Q3, "DENY", "4b5")
DUP_TOOLS = (f'{{"read_file":{{"path":{{"constraint_type":"exact","value":"{Q3}"}}}},'
             f'"read_file":{{"path":{{"constraint_type":"exact","value":"{Q4}"}}}}}}')
dup_tool = jws_sign_raw(raw_json(child_of_l0(10, tools="@@tools@@"), tools=DUP_TOOLS), ORCH)
add("J.24.9", "Derived token repeats a tool identifier", None,
    "L1's tools object names read_file twice, first exact q3 and then exact q4; both narrow the root's one_of. "
    "Duplicate tool identifiers are malformed (Section 3.3.1) and duplicate member names are rejected when the "
    "claims are parsed (step 4b). The invocation reads q4: a last-member parser would accept, a first-member "
    "parser would deny at 6b.",
    [L0, dup_tool], pop_of(dup_tool, WK, "read_file", {"path": Q4}, P(24, 10)), "read_file", {"path": Q4},
    "DENY", "4b")
wrong_crv_l1 = jws_sign(child_of_l0(11, cnf={"jwk": {**WK.jwk, "crv": "X25519"}}), ORCH)
add("J.24.10", "Derived cnf.jwk has the wrong curve", None,
    "L1's JWK declares X25519 while retaining the Worker's Ed25519 x. An X25519 key cannot verify an Ed25519 "
    "signature: this generator rejects it at step 4b2, and a verifier that accepts any public key there denies "
    "at step 7a, where alg must be consistent with the key.",
    [L0, wrong_crv_l1], pop_of(wrong_crv_l1, WK, "read_file", READ_Q3, P(24, 11)),
    "read_file", READ_Q3, "DENY", "4b2")
short_x_l1 = jws_sign(child_of_l0(12, cnf={"jwk": {**WK.jwk, "x": b64u(WK.pub_raw[:-1])}}), ORCH)
add("J.24.11", "Derived cnf.jwk has a short public-key value", None,
    "L1's x decodes to 31 bytes rather than the 32 bytes required for Ed25519. Step 4b2 rejects the malformed JWK.",
    [L0, short_x_l1], pop_of(short_x_l1, WK, "read_file", READ_Q3, P(24, 12)),
    "read_file", READ_Q3, "DENY", "4b2")

# --- J.25 authorization_details entries (steps 3m, 4b3, 4n) ------------------
OTHER = {"type": "https://example.com/tool_access", "tools": {"delete_file": {}}}
mixed_root = jws_sign({**root_claims(T(25, 1), {}, ORCH),
                       "authorization_details": aat(WILD_READ) + [OTHER]}, CP)
solo("J.25.1", "Root with an entry of another type alongside its AAT entry",
     "authorization_details holds the AAT entry (read_file) and an entry of type https://example.com/tool_access "
     "that also has a tools member. Exactly one entry has the AAT type, so step 3m passes; the other entry is "
     "ignored (Section 3.3). The invocation is read_file. PERMIT.",
     mixed_root, "read_file", READ_Q3, "PERMIT", None, P(25, 1))
solo("J.25.2", "A tool granted only by an entry of another type",
     "Same root as J.25.1; the invocation is delete_file, which only the other entry names. Only the AAT entry "
     "grants authority (Section 3.3), so step 6b denies.",
     mixed_root, "delete_file", {}, "DENY", "6b", P(25, 2))
other_leaf = jws_sign(child_of_l0(3, authorization_details=[{**OTHER, "tools": L2_TOOLS}], jti=T(25, 3)), ORCH)
add("J.25.3", "Leaf whose only entry has another type", None,
    "L1's authorization_details holds one entry, of type https://example.com/tool_access, whose tools would be a "
    "valid attenuation of the root. Other entries carry no authority (Section 3.3), and every token must "
    "carry exactly one AAT entry (step 4n).",
    [L0, other_leaf], pop_of(other_leaf, WK, "read_file", READ_Q3, P(25, 3)), "read_file", READ_Q3, "DENY", "4n")
empty_mid = jws_sign(child_of_l0(4, authorization_details=[], jti=T(25, 4)), ORCH)
empty_leaf = jws_sign({**derived_claims(T(25, 5), empty_mid, WK, WK2, {}, IAT_ROOT + 120, 1704068400, 2)}, WK)
add("J.25.4", "Intermediate token with no AAT entry", None,
    "L1 carries an empty authorization_details array and has a child. Every token, not only the root and the "
    "leaf, must carry exactly one AAT entry (Section 3.3), so step 4n denies at L1.",
    [L0, empty_mid, empty_leaf], pop_of(empty_leaf, WK2, "read_file", READ_Q3, P(25, 5)), "read_file", READ_Q3,
    "DENY", "4n")
empty_l1 = jws_sign(child_of_l0(6, authorization_details=[], jti=T(25, 6)), ORCH)
add("J.25.5", "Leaf with no AAT entry", None,
    "L1 carries an empty authorization_details array and is presented as the leaf. Every token must carry "
    "exactly one AAT entry (step 4n).",
    [L0, empty_l1], pop_of(empty_l1, WK, "read_file", READ_Q3, P(25, 6)), "read_file", READ_Q3, "DENY", "4n")
two_mid = jws_sign(child_of_l0(7, authorization_details=aat(L1_TOOLS) + aat({"read_file": {"path": ex(Q4)}}),
                               jti=T(25, 7)), ORCH)
two_leaf = jws_sign(derived_claims(T(25, 8), two_mid, WK, WK2, L2_TOOLS, IAT_ROOT + 120, 1704068400, 2), WK)
add("J.25.6", "Intermediate token with two AAT entries", None,
    "L1 carries two attenuating_agent_token entries, each a valid attenuation of the root (step 4n). The leaf "
    "attenuates the first.",
    [L0, two_mid, two_leaf], pop_of(two_leaf, WK2, "read_file", READ_Q3, P(25, 8)), "read_file", READ_Q3,
    "DENY", "4n")
two_root = jws_sign({**root_claims(T(25, 9), {}, ORCH),
                     "authorization_details": aat(ROOT_TOOLS) + aat({"delete_file": {}})}, CP)
tr_child = jws_sign(derived_claims(T(25, 10), two_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.25.7", "Root with two AAT entries", None,
    "The root carries two attenuating_agent_token entries (step 3m). Its child attenuates the first.",
    [two_root, tr_child], pop_of(tr_child, WK, "read_file", READ_Q3, P(25, 10)), "read_file", READ_Q3,
    "DENY", "3m")
arr_child = jws_sign(derived_claims(T(25, 11), EMPTY_ROOT, ORCH, WK, {"read_file": []}, IAT_ROOT + 60,
                                    1704069000, 2), ORCH)
add("J.25.8", "Derived tools value that is an array", None,
    "Root read_file has an empty constraint map; L1 maps read_file to [] instead of an object (step 4n). A "
    "verifier that read [] as an empty map would treat it as {\"*\": wildcard} and accept any arguments.",
    [EMPTY_ROOT, arr_child], pop_of(arr_child, WK, "read_file", {"path": Q3, "mode": "w"}, P(25, 11)),
    "read_file", {"path": Q3, "mode": "w"}, "DENY", "4n")
solo("J.25.9", "Root tools value that is an empty array",
     "read_file maps to [] instead of a constraint map (step 3m). Compare J.21.10, whose array is not empty.",
     jws_sign(root_claims(T(25, 12), {"read_file": []}, ORCH), CP), "read_file", {"path": Q3, "mode": "w"},
     "DENY", "3m", P(25, 12))
obj_ad = jws_sign(child_of_l0(13, authorization_details=aat(L1_TOOLS)[0], jti=T(25, 13)), ORCH)
add("J.25.10", "Derived authorization_details that is an object", None,
    "L1's authorization_details is its AAT entry itself, not an array containing it (step 4b3).",
    [L0, obj_ad], pop_of(obj_ad, WK, "read_file", READ_Q3, P(25, 13)), "read_file", READ_Q3, "DENY", "4b3")

# --- J.26 leaf check predicates (step 6b) ------------------------------------
LEAF_ROOT = jws_sign(root_claims(T(26, 0), {"publish": {
    "label": n1of("secret", "internal"),
    "tags": reqd("public", "reviewed"),
    "roles": sub("reader", "editor"),
    "format": one_of("pdf", "csv"),
    "limit": rng(min=0, max=100, min_inclusive=False),
    "size": rng(min=1, max=10, max_inclusive=False),
}}, ORCH), CP)
GOOD = {"label": "public", "tags": ["public", "reviewed"], "roles": ["reader"], "format": "pdf", "limit": 50, "size": 5}
LEAF_DESC = ("Single-token chain; the root's publish tool constrains label (not_one_of[secret, internal]), tags "
             "(contains[public, reviewed]), roles (subset[reader, editor]), format (one_of[pdf, csv]), limit "
             "(range, min 0 exclusive, max 100) and size (range, min 1, max 10 exclusive). ")
for vid, k, change, expect, title, desc in (
        ("J.26.1", 1, {"format": "docx"}, "DENY", "one_of rejects a value outside the set", "format = docx."),
        ("J.26.2", 2, {"label": "secret"}, "DENY", "not_one_of rejects an excluded value", "label = secret."),
        ("J.26.3", 3, {"tags": ["public"]}, "DENY", "contains rejects an array missing a required element",
         "tags = [public]."),
        ("J.26.4", 4, {"tags": "public reviewed"}, "DENY", "contains rejects a value that is not an array",
         "tags is the string \"public reviewed\"."),
        ("J.26.5", 5, {"roles": ["reader", "admin"]}, "DENY", "subset rejects an element outside the allowed set",
         "roles = [reader, admin]."),
        ("J.26.6", 6, {"roles": "reader"}, "DENY", "subset rejects a value that is not an array",
         "roles is the string \"reader\"."),
        ("J.26.7", 7, {"limit": "50"}, "DENY", "range rejects a value that is not a number",
         "limit is the string \"50\"."),
        ("J.26.8", 8, {"limit": 0}, "DENY", "range rejects its exclusive min", "limit = 0, the exclusive min."),
        ("J.26.9", 9, {"size": 10}, "DENY", "range rejects its exclusive max", "size = 10, the exclusive max."),
        ("J.26.10", 10, {"limit": 100, "size": 1}, "PERMIT", "range accepts its inclusive bounds",
         "limit = 100 (inclusive max) and size = 1 (inclusive min). PERMIT."),
        ("J.26.11", 11, {"tags": ["reviewed", "public", "public"]}, "PERMIT", "contains compares as sets",
         "tags = [reviewed, public, public]: another order and a duplicate (Section 3.4). PERMIT."),
        ("J.26.12", 12, {"roles": ["editor", "reader", "editor"]}, "PERMIT", "subset compares as sets",
         "roles = [editor, reader, editor]: another order and a duplicate (Section 3.4). PERMIT.")):
    a = {**GOOD, **change}
    solo(vid, title, LEAF_DESC + desc + ("" if expect == "PERMIT" else " Denied at step 6b."), LEAF_ROOT,
         "publish", a, expect, None if expect == "PERMIT" else "6b", P(26, k))

# --- J.27 inputs a verifier must accept, and one it must not ------------------
claims = root_claims(T(27, 1), ROOT_TOOLS, ORCH)
claims["urn:example:tenant"] = "acme"
xc_root = jws_sign(claims, CP)
xc_l1 = jws_sign({**derived_claims(T(27, 2), xc_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2),
                  "urn:example:trace": "t-1"}, ORCH)
add("J.27.1", "Unrecognized claims are ignored", None,
    "The J.3 root and L1 shape with an extra claim on each (urn:example:tenant, urn:example:trace). A token MUST "
    "NOT be rejected for carrying claims outside this specification (Section 3.4); in a derived token they carry "
    "no authority (Section 3.3). PERMIT.",
    [xc_root, xc_l1], pop_of(xc_l1, WK, "read_file", READ_Q3, P(27, 1)), "read_file", READ_Q3, "PERMIT")
ncj_root = jws_sign_raw(json.dumps(root_claims(T(27, 3), ROOT_TOOLS, ORCH), indent=2), CP)
ncj_l1 = jws_sign_raw(json.dumps(derived_claims(T(27, 4), ncj_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2),
                                 separators=(", ", ": ")), ORCH)
add("J.27.2", "Payloads that are not JCS", None,
    "The J.3 root and L1 shape, the root's payload indented with its members in issue order and L1's with spaces "
    "after separators. Signatures, par_hash and aat_hash cover the presented bytes; a verifier that "
    "re-serialized a payload first would compute different values (Section 3.5). PERMIT.",
    [ncj_root, ncj_l1], pop_of(ncj_l1, WK, "read_file", READ_Q3, P(27, 2)), "read_file", READ_Q3, "PERMIT")
self_l1 = jws_sign(derived_claims(T(27, 5), L0, ORCH, ORCH, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.27.3", "Derivation to the same holder key", None,
    "L1 is derived by the Orchestrator for itself: its cnf.jwk equals the root's. Same-key derivation is valid "
    "(Section 6.2); only delivery across a process or trust boundary requires a new key, and that is not "
    "verifiable. PERMIT.",
    [L0, self_l1], pop_of(self_l1, ORCH, "read_file", READ_Q3, P(27, 3)), "read_file", READ_Q3, "PERMIT")
arr_root = jws_sign(root_claims(T(27, 6), ROOT_TOOLS, ORCH, aud=["https://other.example.com", AUDIENCE]), CP)
arr_l1 = jws_sign(derived_claims(T(27, 7), arr_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.27.4", "Root aud is an array that includes this enforcement point", None,
    "Root aud = [https://other.example.com, https://tools.example.com]; one of its values identifies this "
    "enforcement point (step 6c, RFC 7519 Section 4.1.3). PERMIT.",
    [arr_root, arr_l1], pop_of(arr_l1, WK, "read_file", READ_Q3, P(27, 4)), "read_file", READ_Q3, "PERMIT")
aud_l1 = jws_sign(child_of_l0(8, aud="https://other.example.com", jti=T(27, 8)), ORCH)
add("J.27.5", "Derived token aud names another enforcement point", None,
    "The root carries no aud; L1 restricts itself to https://other.example.com. Every aud in the chain is "
    "checked, so a derived token can add a restriction (step 6c). A verifier that checked only the root's aud "
    "would accept.",
    [L0, aud_l1], pop_of(aud_l1, WK, "read_file", READ_Q3, P(27, 5)), "read_file", READ_Q3, "DENY", "6c")
kid_jwk = {**ORCH.jwk, "kid": "orchestrator-2024", "use": "sig", "alg": "Ed25519"}
kid_root = jws_sign({**root_claims(T(27, 9), ROOT_TOOLS, ORCH), "cnf": {"jwk": kid_jwk}}, CP)
kid_l1 = jws_sign(derived_claims(T(27, 10), kid_root, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.27.6", "Holder JWK with optional members", None,
    "The root's cnf.jwk adds kid, use and alg to the Orchestrator's key. L1's iss is the RFC 7638 thumbprint, "
    "which covers only the required members crv, kty and x (step 4c). PERMIT.",
    [kid_root, kid_l1], pop_of(kid_l1, WK, "read_file", READ_Q3, P(27, 6)), "read_file", READ_Q3, "PERMIT")


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
def tok_md(label: str, t: dict) -> str:
    out = [f"**{label}** (signed by `{t['signer']}`)", "",
           "Protected header (JCS):", "```json", jcs(t["header"]).decode(), "```",
           ("Payload (JCS; this exact byte string is base64url-encoded):"
            if t["payload_jcs_canonical"] else
            "Payload (exact JSON, intentionally not JCS-canonical; this exact byte string is base64url-encoded):"),
           "```json", t["payload_json"], "```",
           "| Field | Value |", "|---|---|",
           f"| header_b64 | `{t['header_b64']}` |",
           f"| payload_b64 | `{t['payload_b64']}` |",
           f"| SHA-256(signing input), base64url | `{t['signing_input_sha256_b64u']}` |",
           f"| signature_b64 | `{t['signature_b64'] or '(empty)'}` |",
           "", "Compact JWS:", "```", t["compact"], "```", ""]
    return "\n".join(out)


# The id of a vector is J.<group>[.<n>]; the group is its topic.
GROUPS = {
    1: "Minimal single-token chain", 2: "Token-instance cycle detection (2c)", 3: "Valid three-level chain",
    4: "I1 delegation authority (4b, 4c)", 5: "Expired root (3e)",
    6: "PoP audience, nonce and chain audience (6c, 7d, 7h)",
    7: "Explicit typing and header parameters (3a, 4a, 7a)",
    8: "Constraint maps, well-formedness and number admissibility (3n, 4o, 6b)", 9: "Closed-world leaf checks (6b)",
    10: "I2 delegation depth (4d-4m)", 11: "I4 capability monotonicity (4p)", 12: "I5 cryptographic linkage (4q)",
    13: "I3 lifetimes (4h-4l)", 14: "Signatures and header keys (3a, 3b)", 15: "all subsumption",
    16: "any subsumption", 17: "not_one_of, contains, subset and range attenuation",
    18: "Composites across kinds", 19: "The Section 4.5 subsumption table (4p2, 4p4)",
    20: "PoP JWT failures and replay (7b-7i)", 21: "Root token claims (3b-3n)",
    22: "Optional and unnamed arguments (4p2, 4p3, 6b)", 23: "Presentation size and parsing (1, 2a-2c, 3b)",
    24: "Derived token claims (2c, 4b)", 25: "authorization_details entries (3m, 4b3, 4n)",
    26: "Leaf check predicates (6b)", 27: "Inputs a verifier must accept, and a derived aud (6c)",
}


def _id_key(vid: str):
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in vid.split(".")[1:]]


def _step_key(step: str):
    m = re.fullmatch(r"(\d+)([a-z]?)(\d*)", step)
    return int(m[1]), m[2], int(m[3] or 0)


VECTORS.sort(key=lambda v: _id_key(v["id"]))
assert len({v["id"] for v in VECTORS}) == len(VECTORS)
assert {int(v["id"].split(".")[1]) for v in VECTORS} == set(GROUPS)
TWINS = sum(1 for v in VECTORS if v["cbor_twin"])
DEFAULT_PARAMS = {"max_token_size": MAX_TOKEN_SIZE, "max_chain_size": MAX_CHAIN_SIZE}

md = []
md.append("# AAT JWS Test Vectors (draft-niyikiza-oauth-attenuating-agent-tokens-02)\n")
md.append("Generated by `gen_vectors.py`; do not edit by hand. "
          "every expected verdict below was reproduced by the self-checking §8 verifier in that file. "
          "These vectors follow the -02 text. Tokens use `alg` `Ed25519` (RFC 9864) rather than -01's "
          "`EdDSA`, so an unmodified -01 verifier rejects nearly every vector; Appendix F of the draft lists the "
          "other verdict changes.\n")
md.append("## Vector ids\n")
md.append("A vector's id is `J.<group>[.<n>]`, where the group is its topic (below). `cbor_twin`, where set, names "
          "the vector `A.x` in Tenuo's CBOR suite (`docs/spec/test-vectors.md`) that encodes the same scenario, "
          "with the same key seeds and timestamps. "
          f"{TWINS} of the {len(VECTORS)} vectors have a twin; otherwise group numbers have no relation to the CBOR "
          "suite's section numbers.\n")
md.append("| Group | Topic | Vectors |\n|---|---|---|")
for g, topic in GROUPS.items():
    md.append(f"| J.{g} | {topic} | {sum(1 for v in VECTORS if int(v['id'].split('.')[1]) == g)} |")
md.append("")
md.append("## Conventions\n")
md.append("- Signature algorithm: Ed25519, JWS `alg` = `Ed25519` (RFC 9864).")
md.append("- AAT headers carry `typ` = `aat+jwt` and PoP headers carry `typ` = `aat-pop+jwt` (RFC 8725 §3.11, "
          "as DPoP uses `dpop+jwt`). Verifiers reject a missing or mismatched `typ` at the header step "
          "(3a, 4a, 7a). Draft-01 defines no `typ`.")
md.append("- `aat_aud` is OPTIONAL in the PoP; when present it MUST identify the receiving "
          "enforcement point (step 7d). AATs MAY carry `aud`, checked for every token in the chain (step 6c). "
          "PoP JWTs MAY carry an enforcement-point `nonce` (step 7h). Each vector states which of these its "
          "enforcement point requires under **Policy**. Draft-01 leaves audience to deployment policy without "
          "defining the value.")
md.append("- In `all` subsumption, every parent clause must subsume at least one derived clause; "
          "a derived clause MAY cover several parent clauses; extra derived clauses are permitted. Draft-01's one-to-one "
          "assignment is dropped (it adds backtracking without adding soundness).")
md.append("- AAT and PoP payloads are JCS-canonical (RFC 8785) except where a vector deliberately carries other "
          "bytes: an inadmissible number, number syntax that JCS would rewrite, a duplicate member, or a "
          "non-canonical layout (J.27.2). Each token records `payload_jcs_canonical`; a verifier MUST verify the "
          "presented bytes and MUST NOT re-canonicalize before checking a signature.")
md.append("- `par_hash` = base64url-nopad(SHA-256(parent JWS Signing Input)), where the signing input is the ASCII "
          "string `BASE64URL(header) || '.' || BASE64URL(payload)` (§4.6). J.12.b shows the wrong (payload-only) form.")
md.append("- Derived `iss` = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 thumbprint of the signing key>`.")
md.append("- `jti` values follow the CBOR vector IDs: `tnu_wrt_019471f8...0001` becomes `019471f8-0000-7000-8000-000000000001`.")
md.append("- No non-ASCII strings or escaped characters appear anywhere. Numbers with a fraction or "
          "exponent appear only where a vector tests them: in invocation arguments (J.8.12-J.8.14) and in claims "
          "whose syntax §3.2 restricts (J.20.14, J.21.13, J.21.16, J.21.17, J.24.4-J.24.6). Number admissibility "
          "(§3.4) is covered by J.8.7-J.8.14. A harness must read `args_json` and each `payload_json` with a parser "
          "that keeps a number's exact value and whether it was written with a fraction or exponent; a parser that "
          "converts to doubles cannot detect either.")
md.append("- The expected verdict follows the -02 text. The expected step is the first failing step in §8's "
          "order; an implementation that orders independent steps differently can report another step for the "
          "same vector, so harnesses compare verdicts.")
md.append("")
md.append("## Verification parameters\n")
md.append("These apply to every vector; a vector whose **Parameters** line names other values uses those instead "
          "(in the JSON, a vector's `params` override the suite's).\n")
md.append("| Parameter | Value |\n|---|---|")
md.append(f"| now (verification time) | `{NOW}` (2024-01-01T00:05:00Z) |")
md.append(f"| MAX_IAT_SKEW | {MAX_IAT_SKEW} s |")
md.append(f"| MAX_TOKEN_LIFETIME | {MAX_TOKEN_LIFETIME} s (90 days) |")
md.append(f"| MAX_DELEGATION_DEPTH | {MAX_DELEGATION_DEPTH} |")
md.append(f"| MAX_CONSTRAINT_DEPTH | {MAX_CONSTRAINT_DEPTH} |")
md.append(f"| MAX_TOKEN_SIZE | {MAX_TOKEN_SIZE} bytes (J.23.2 and J.23.3 use smaller limits) |")
md.append(f"| MAX_CHAIN_SIZE | {MAX_CHAIN_SIZE} bytes (J.23.2 and J.23.3 use smaller limits) |")
md.append(f"| PoP clock window | ±{POP_WINDOW} s |")
md.append(f"| This enforcement point's audience identifier | `{AUDIENCE}`. A chain `aud`, a PoP `aat_aud`, or a "
          "nonce is required only where a vector's **Policy** says so. |")
md.append(f"| Trust anchors | `control_plane` public key, bound to issuer `{ROOT_ISS}`; `control_plane2` public key, "
          f"bound to issuer `{ROOT_ISS2}` |")
md.append("")
md.append("## Key material\n")
md.append("Same seeds as `docs/spec/test-vectors.md`, plus `control_plane2`, the second trust anchor's key, which "
          "that suite does not use.\n")
md.append("| Role | Seed (hex) | Public key (hex) | JWK `x` | RFC 7638 thumbprint |\n|---|---|---|---|---|")
for n, k in KEYS.items():
    md.append(f"| {n} | `{k.seed.hex()}` | `{k.pub_raw.hex()}` | `{k.jwk['x']}` | `{k.thumbprint}` |")
md.append("")
md.append("Thumbprint input is the JCS form of the JWK's required members, e.g. for the Orchestrator:\n")
md.append("```json\n" + jcs({"crv": "Ed25519", "kty": "OKP", "x": ORCH.jwk["x"]}).decode() + "\n```\n")
md.append("Thumbprint URIs used as derived-token `iss`:\n")
md.append("| Signer | `iss` |\n|---|---|")
for n in ("orchestrator", "worker", "worker2", "attacker"):
    md.append(f"| {n} | `{KEYS[n].thumbprint_uri}` |")
md.append("")
md.append("## Coverage of Section 8\n")
md.append("Each DENY vector differs from a valid presentation by one fault. `gen_vectors.py --mutation-check` "
          "disables each check of the generator's verifier in turn (the lettered steps, the §3.4 well-formedness "
          "rules, each `check` predicate and §4.5 subsumption rule, and the empty-map and entry-type "
          "normalizations) and requires at least one vector to change verdict. The checks below cannot be the only "
          "fault in a presentation, because another check always fails with them; no vector depends on them alone. "
          "4f and 5 are among them.\n")
md.append("| Check | Why it is never the only fault |\n|---|---|")
for cid, why in UNREACHABLE.items():
    md.append(f"| `{cid}` | {why} |")
md.append("")
md.append("Vectors by expected step:\n")
md.append("| Step | Vectors |\n|---|---|")
by_step: dict[str, list[str]] = {}
for v in VECTORS:
    by_step.setdefault(v["expected"]["step"] or "PERMIT", []).append(v["id"])
for step in sorted((k for k in by_step if k != "PERMIT"), key=_step_key) + ["PERMIT"]:
    md.append(f"| {step} | {', '.join(by_step[step])} |")
md.append("")
md.append("## Index\n")
md.append("| ID | Title | CBOR twin | Expected |\n|---|---|---|---|")
for v in VECTORS:
    e = v["expected"]
    md.append(f"| {v['id']} | {v['title']} | {v['cbor_twin'] or 'none'} | {e['verdict']}{' at step ' + e['step'] if e['step'] else ''} |")
md.append("")

for v in VECTORS:
    e = v["expected"]
    md.append(f"## {v['id']} {v['title']}\n")
    if v["cbor_twin"]:
        md.append(f"CBOR twin: {v['cbor_twin']}.\n")
    md.append(v["description"] + "\n")
    if v["policy"]:
        md.append("**Policy:** " + ", ".join(f"`{k}`=`{val}`" for k, val in v["policy"].items()) + "\n")
    if v["params"]:
        md.append("**Parameters:** " + ", ".join(f"`{k}`=`{val}` (suite: {DEFAULT_PARAMS[k]})"
                                                 for k, val in v["params"].items()) + "\n")
    for n in v["notes"]:
        md.append(f"> {n}\n")
    md.append(f"**Invocation:** tool `{v['tool']}`, args `{v['args_json']}`, now = `{v['verification_time']}`")
    md.append(f"**Expected:** **{e['verdict']}**" + (f" at step {e['step']}" if e["step"] else "") + "\n")
    if v["replay_state"] is not None:
        md.append("**Replay state:** accepted PoP `jti` values before = "
                  f"`{json.dumps(v['replay_state']['before'])}`; after = "
                  f"`{json.dumps(v['replay_state']['after'])}`\n")
    for i, t in enumerate(v["chain"]):
        md.append(tok_md(f"Chain[{i}] (del_depth {t['payload'].get('del_depth')})", t))
    md.append(tok_md("PoP JWT", v["pop"]))
    md.append("---\n")


def tok_json(t: dict) -> dict:
    return {k: t[k] for k in ("header", "payload", "payload_json", "payload_jcs_canonical",
                              "header_b64", "payload_b64", "signing_input",
                              "signing_input_sha256_b64u", "signature_b64", "compact", "signer")}


json_out = {
    "spec": "draft-niyikiza-oauth-attenuating-agent-tokens-02",
    "conventions": {
        "header": HEADER, "pop_header": POP_HEADER,
        "payload_jcs": "per token; see payload_jcs_canonical (false where a vector deliberately carries other bytes)",
        "numbers": "read args_json and payload_json losslessly: exact values, and whether a number has a fraction "
                   "or exponent part",
        "params": "suite defaults; a vector's params override them",
        "steps": "expected.step is the first failing Section 8 step in order; verdicts are normative",
        "aat_aud": "optional; when present it must identify the enforcement point (7d)",
        "chain_aud": "every chain token that carries aud must identify the enforcement point (6c)",
        "pop_nonce": "checked when the vector policy names the nonce the enforcement point issued (7h)",
        "all_subsumption": "every parent clause subsumes at least one derived clause; reuse permitted",
        "par_hash": "base64url-nopad(SHA-256(parent JWS Signing Input))",
    },
    "params": {"now": NOW, "max_iat_skew": MAX_IAT_SKEW, "max_token_lifetime": MAX_TOKEN_LIFETIME,
               "max_delegation_depth": MAX_DELEGATION_DEPTH, "max_constraint_depth": MAX_CONSTRAINT_DEPTH,
               "max_token_size": MAX_TOKEN_SIZE, "max_chain_size": MAX_CHAIN_SIZE,
               "pop_window": POP_WINDOW, "audience": AUDIENCE},
    "keys": {n: {"seed_hex": k.seed.hex(), "public_hex": k.pub_raw.hex(), "jwk": k.jwk,
                 "thumbprint": k.thumbprint, "thumbprint_uri": k.thumbprint_uri} for n, k in KEYS.items()},
    "trust_anchors": [{"iss": iss, "jwk": jwk} for iss, jwk in TRUST],
    "vectors": [{
        "id": v["id"], "title": v["title"], "cbor_twin": v["cbor_twin"], "description": v["description"],
        "notes": v["notes"], "now": v["verification_time"], "tool": v["tool"], "args": v["args"],
        "args_json": v["args_json"], "policy": v["policy"], "params": v["params"], "replay_state": v["replay_state"],
        "chain": [tok_json(t) for t in v["chain"]], "chain_compact": [t["compact"] for t in v["chain"]],
        "pop": tok_json(v["pop"]),
        "presentation": {"aat_chain": [t["compact"] for t in v["chain"]], "aat_pop": v["pop"]["compact"]},
        "expected": v["expected"],
    } for v in VECTORS],
}
# `payload` is a convenience view; a Decimal in it (J.8.13's hta) is shown as the
# nearest double, while payload_json keeps the exact text.
if __name__ == "__main__":
    ARGS.md_out.write_text("\n".join(md))
    ARGS.json_out.write_text(json.dumps(json_out, indent=2, default=float) + "\n")
    print(f"\nwrote {len(VECTORS)} vectors: {ARGS.json_out} and {ARGS.md_out}")


# ---------------------------------------------------------------------------
# Mutation check: is every check pinned by some vector?
# ---------------------------------------------------------------------------
def _outcome(v: dict) -> str:
    run = v["_run"]
    try:
        return _verdict(run, set(run["replay"]) if run["replay"] is not None else None)[0]
    except Exception:  # a disabled check let malformed input reach code that cannot handle it
        return "ERROR"


def mutation_check() -> int:
    """Disable each check in turn and re-verify every vector. A check must change
    the verdict of at least one vector unless UNREACHABLE explains why it cannot
    be the only fault; a check listed there must change none."""
    problems, rows = [], []
    for cid in CHECKS:
        _DISABLED.clear()
        _DISABLED.add(cid)
        outcomes = [(v["id"], _outcome(v), v["expected"]["verdict"]) for v in VECTORS]
        flips = [vid for vid, got, want in outcomes if got not in (want, "ERROR")]
        errors = [vid for vid, got, _ in outcomes if got == "ERROR"]
        rows.append((cid, flips, errors))
        if cid in UNREACHABLE and flips:
            problems.append(f"{cid} is listed as unreachable but disabling it flips {', '.join(flips)}")
        if cid not in UNREACHABLE and not flips:
            problems.append(f"{cid}: no vector changes verdict when this check is disabled")
    _DISABLED.clear()
    for cid, flips, errors in rows:
        shown = ", ".join(flips[:6]) + (" ..." if len(flips) > 6 else "")
        note = f"unreachable: {UNREACHABLE[cid]}" if cid in UNREACHABLE else shown
        print(f"  {cid:28} {len(flips):3} flipped {len(errors):3} errored  {note}")
    reachable = len(CHECKS) - len(UNREACHABLE)
    print(f"mutation check: {reachable} reachable checks, {len(UNREACHABLE)} unreachable as a sole fault, "
          f"{len(VECTORS)} vectors, {len(problems)} problems")
    for p in problems:
        print(f"!! {p}")  # stdout, so a combined log keeps each line whole
    return 1 if problems else 0


def fault_chains():
    """For each DENY vector, the checks that fail in turn as each earlier one is
    disabled. A single-fault vector stops at one check, or at the checks that
    UNREACHABLE says always fail with it."""
    for v in VECTORS:
        if v["expected"]["verdict"] != "DENY":
            continue
        found = []
        while True:
            _DISABLED.clear()
            _DISABLED.update(found)
            run = v["_run"]
            try:
                verdict, _, cid = _verdict(run, set(run["replay"]) if run["replay"] is not None else None)
            except Exception as e:
                found.append(f"ERROR({type(e).__name__})")
                break
            if verdict == "PERMIT" or cid is None:
                break
            found.append(cid)
        _DISABLED.clear()
        print(f"  {v['id']:10} {' -> '.join(found)}")


if ARGS.fault_chains:
    fault_chains()
if ARGS.mutation_check:
    sys.exit(mutation_check())
