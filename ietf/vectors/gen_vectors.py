#!/usr/bin/env python3
"""
Generate byte-exact JWS test vectors for draft-niyikiza-oauth-attenuating-agent-tokens-02.

Design choices (recorded in the emitted document):
  * Keys are Ed25519 from the same 32-byte seeds as docs/spec/test-vectors.md
    (Control Plane / Orchestrator / Worker / Worker2 / Attacker), so each JWS
    vector is the twin of an existing CBOR vector where a twin exists.
  * AAT payloads are JCS-canonical (RFC 8785). The draft only *requires* JCS
    for the PoP payload (§5.2); for AATs it is a vector choice that makes the
    signing input reproducible. Verifiers must accept the bytes as presented,
    they must not re-canonicalize an AAT before verifying its signature.
  * Headers carry explicit typing: {"alg":"EdDSA","typ":"aat+jwt"} for
    AATs and {"alg":"EdDSA","typ":"aat-pop+jwt"} for PoP JWTs (RFC 8725 §3.11).
  * aat_aud is REQUIRED on the PoP and MUST match the configured audience.
  * `all` subsumption: every parent clause is subsumed by at least one derived
    clause; a derived clause MAY cover several parent clauses.
  * Verification clock: now = 1704067500 (2024-01-01T00:05:00Z).
    MAX_IAT_SKEW = 30, MAX_TOKEN_LIFETIME = 90 days, MAX_DELEGATION_DEPTH = 8,
    PoP window = ±30 s, audience "https://tools.example.com" required.

Every vector is checked by the independent §7 verifier in this file before it
is written. A vector whose actual verdict differs from its expected verdict
aborts generation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

OUT = Path(__file__).parent

# ---------------------------------------------------------------------------
# Fixed parameters
# ---------------------------------------------------------------------------
NOW = 1704067500  # 2024-01-01T00:05:00Z
MAX_IAT_SKEW = 30
MAX_TOKEN_LIFETIME = 90 * 24 * 3600
MAX_DELEGATION_DEPTH = 8
MAX_CONSTRAINT_DEPTH = 32
POP_WINDOW = 30
AUDIENCE = "https://tools.example.com"
ROOT_ISS = "https://auth.example.com"

IAT_ROOT = 1704067200  # 2024-01-01T00:00:00Z
EXP_ROOT = 1704070800  # 2024-01-01T01:00:00Z

SEEDS = {
    "control_plane": bytes([0x01] * 32),
    "orchestrator": bytes([0x02] * 32),
    "worker": bytes([0x03] * 32),
    "worker2": bytes([0x04] * 32),
    "attacker": bytes([0xFF] * 32),
}
# Public keys as listed in docs/spec/test-vectors.md; asserted below.
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


def _check_jcs_safe(v):
    """The vectors avoid every JCS case that is not trivially portable."""
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return
    if isinstance(v, float):
        raise ValueError("floats are deliberately excluded from these vectors")
    if isinstance(v, str):
        if not v.isascii():
            raise ValueError("non-ASCII strings are deliberately excluded")
        return
    if isinstance(v, list):
        for x in v:
            _check_jcs_safe(x)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not (isinstance(k, str) and k.isascii()):
                raise ValueError("non-ASCII keys are deliberately excluded")
            _check_jcs_safe(x)
        return
    raise TypeError(type(v))


def jcs(obj) -> bytes:
    """RFC 8785 for the ASCII, integer-only subset used here.

    With that subset, JCS == sorted keys, no whitespace, no escaping beyond
    what JSON requires. Python's sort on ASCII keys equals UTF-16 code-unit
    order, so the output is byte-exact JCS.
    """
    _check_jcs_safe(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


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
for n, k in KEYS.items():
    assert k.pub_raw.hex() == EXPECTED_PUB_HEX[n], n

# -02 proposal (agreed 2026-09-13): explicit typing per RFC 8725 §3.11, DPoP-style.
HEADER = {"alg": "EdDSA", "typ": "aat+jwt"}
POP_HEADER = {"alg": "EdDSA", "typ": "aat-pop+jwt"}


def jws_sign(payload: dict, signer: Key, header: dict = HEADER) -> dict:
    h = b64u(jcs(header))
    p = b64u(jcs(payload))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = signer.sign(signing_input)
    return {
        "header": header,
        "payload": payload,
        "header_b64": h,
        "payload_b64": p,
        "signing_input": signing_input.decode("ascii"),
        "signing_input_sha256_b64u": b64u(hashlib.sha256(signing_input).digest()),
        "signature_b64": b64u(sig),
        "compact": f"{h}.{p}.{b64u(sig)}",
        "signer": signer.name,
    }


def par_hash_of(tok: dict) -> str:
    return b64u(hashlib.sha256(tok["signing_input"].encode("ascii")).digest())


def uuid7ish(n: int) -> str:
    # Twin of the CBOR IDs tnu_wrt_019471f8000070008000000000000001 etc.
    return f"019471f8-0000-7000-8000-{n:012x}"


def aat(tools: dict) -> list:
    return [{"type": "attenuating_agent_token", "tools": tools}]


# ---------------------------------------------------------------------------
# Independent §7 verifier (subset sufficient for the vectors; fail-closed)
# ---------------------------------------------------------------------------
class Deny(Exception):
    def __init__(self, step: str, why: str = ""):
        super().__init__(f"{step}: {why}")
        self.step = step
        self.why = why


def _split(compact: str):
    parts = compact.split(".")
    if len(parts) != 3:
        raise Deny("2", "not compact JWS")
    return parts


def _verify_jws(compact: str, pub: Ed25519PublicKey, step_alg: str, step_sig: str,
                expected_typ: str = "aat+jwt") -> dict:
    h, p, s = _split(compact)
    try:
        header = json.loads(b64u_dec(h))
    except Exception:
        raise Deny(step_alg, "unparseable header")
    if header.get("alg") != "EdDSA":
        raise Deny(step_alg, f"alg={header.get('alg')!r} not on allowlist")
    if header.get("typ") != expected_typ:
        raise Deny(step_alg, f"typ={header.get('typ')!r}, expected {expected_typ!r}")
    try:
        pub.verify(b64u_dec(s), f"{h}.{p}".encode("ascii"))
    except InvalidSignature:
        raise Deny(step_sig, "signature does not verify")
    return json.loads(b64u_dec(p))


def _jwk_pub(jwk: dict, step: str = "3l") -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" in jwk:
        raise Deny(step, "cnf.jwk not an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))


def _thumb_uri(jwk: dict) -> str:
    return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + b64u(
        hashlib.sha256(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})).digest()
    )


def _aat_entry(claims: dict, step: str, exactly_one: bool):
    ad = claims.get("authorization_details")
    if not isinstance(ad, list):
        raise Deny(step, "authorization_details missing")
    ents = [e for e in ad if isinstance(e, dict) and e.get("type") == "attenuating_agent_token"]
    if exactly_one and len(ents) != 1:
        raise Deny(step, f"{len(ents)} attenuating_agent_token entries")
    if len(ents) > 1:
        raise Deny(step, "more than one attenuating_agent_token entry")
    return ents[0] if ents else {"type": "attenuating_agent_token", "tools": {}}


def _cdepth(c, d=1):
    if d > MAX_CONSTRAINT_DEPTH:
        raise Deny("3n/4o", "constraint tree too deep")
    for sub in c.get("constraints", []) if c.get("constraint_type") in ("all", "any") else []:
        _cdepth(sub, d + 1)


def check(c: dict, v) -> bool:
    t = c.get("constraint_type")
    if t == "wildcard":
        return True
    if t == "exact":
        return v == c["value"] and type(v) is type(c["value"])
    if t == "one_of":
        return any(v == x and type(v) is type(x) for x in c["values"])
    if t == "range":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return False
        lo, hi = c.get("min"), c.get("max")
        if lo is not None and (v < lo or (v == lo and not c.get("min_inclusive", True))):
            return False
        if hi is not None and (v > hi or (v == hi and not c.get("max_inclusive", True))):
            return False
        return True
    if t == "not_one_of":
        return all(v != x or type(v) is not type(x) for x in c["excluded"])
    if t == "contains":
        if not isinstance(v, list):
            return False
        return all(any(x == r and type(x) is type(r) for x in v) for r in c["required"])
    if t == "subset":
        if not isinstance(v, list):
            return False
        return all(any(x == a and type(x) is type(a) for a in c["allowed"]) for x in v)
    if t == "all":
        return all(check(s, v) for s in c["constraints"])
    if t == "any":
        return any(check(s, v) for s in c["constraints"])
    raise Deny("6b", f"unrecognized constraint_type {t!r} (fail-closed)")


def subsumes(child: dict, parent: dict) -> bool:
    """True iff child ⊑ parent under §4.5 for the types the vectors use.

    `all` uses the agreed -02 rule (Tenuo's): every parent clause must be
    subsumed by at least one derived clause; a derived clause MAY cover
    several parent clauses; extra derived clauses are permitted. This drops
    draft-01's one-to-one requirement (Warden NOTES entry 12).
    """
    ct, pt = child.get("constraint_type"), parent.get("constraint_type")
    if ct == "wildcard":
        return pt == "wildcard"
    if pt == "wildcard":
        return ct in ("exact", "range", "one_of", "not_one_of", "contains", "subset", "all", "any")
    if ct == "all" and pt == "all":
        return all(any(subsumes(cd, cp) for cd in child["constraints"]) for cp in parent["constraints"])
    if ct == "any" and pt == "any":
        if not child["constraints"]:
            return False
        return all(any(subsumes(cd, cp) for cp in parent["constraints"]) for cd in child["constraints"])
    if ct == "exact":
        if pt == "exact":
            return child["value"] == parent["value"]
        if pt == "one_of":
            return child["value"] in parent["values"]
        if pt == "range":
            return isinstance(child["value"], (int, float)) and not isinstance(child["value"], bool) and check(parent, child["value"])
        return False
    if ct == "one_of" and pt == "one_of":
        return all(x in parent["values"] for x in child["values"])
    if ct == "range" and pt == "range":
        pmin, pmax = parent.get("min"), parent.get("max")
        cmin, cmax = child.get("min"), child.get("max")
        if pmin is not None:
            if cmin is None or cmin < pmin:
                return False
            if cmin == pmin and parent.get("min_inclusive", True) is False and child.get("min_inclusive", True):
                return False
        if pmax is not None:
            if cmax is None or cmax > pmax:
                return False
            if cmax == pmax and parent.get("max_inclusive", True) is False and child.get("max_inclusive", True):
                return False
        return True
    if ct == "not_one_of" and pt == "not_one_of":
        return all(x in child["excluded"] for x in parent["excluded"])
    if ct == "contains" and pt == "contains":
        return all(x in child["required"] for x in parent["required"])
    if ct == "subset" and pt == "subset":
        return all(x in parent["allowed"] for x in child["allowed"])
    return False  # every undeclared pair is invalid


def verify_chain(chain: list[str], trust_anchors: list[Ed25519PublicKey], tool: str, args: dict,
                 pop_jwt: str, now: int = NOW, audience: str | None = AUDIENCE) -> str:
    """Returns 'PERMIT' or raises Deny(step)."""
    if not chain:
        raise Deny("1", "empty chain")
    # 2c: jti cycle detection on unverified payloads
    jtis = []
    for t in chain:
        try:
            c = json.loads(b64u_dec(_split(t)[1]))
        except Exception:
            raise Deny("2c", "payload not JSON")
        if not isinstance(c.get("jti"), str):
            raise Deny("2c", "jti missing")
        jtis.append(c["jti"])
    if len(set(jtis)) != len(jtis):
        raise Deny("2c", "duplicate jti in chain")

    # 3: root
    root = None
    last_err = None
    for ta in trust_anchors:
        try:
            root = _verify_jws(chain[0], ta, "3a", "3b")
            break
        except Deny as e:
            last_err = e
    if root is None:
        raise last_err
    if root.get("del_depth") != 0:
        raise Deny("3c", "root del_depth != 0")
    if "par_hash" in root:
        raise Deny("3d", "root has par_hash")
    if not (root["exp"] > now):
        raise Deny("3e", "root expired")
    if not (root["iat"] <= now + MAX_IAT_SKEW):
        raise Deny("3f", "root iat in future")
    if not (root["exp"] > root["iat"]):
        raise Deny("3g", "exp <= iat")
    if not (root["exp"] <= root["iat"] + MAX_TOKEN_LIFETIME):
        raise Deny("3h", "lifetime too long")
    dmd = root.get("del_max_depth")
    if not (isinstance(dmd, int) and not isinstance(dmd, bool) and 0 <= dmd <= MAX_DELEGATION_DEPTH):
        raise Deny("3i", "bad del_max_depth")
    if not (isinstance(root.get("jti"), str) and root["jti"]):
        raise Deny("3j", "jti")
    if not (isinstance(root.get("iss"), str) and ":" in root["iss"]):
        raise Deny("3k", "iss not URI")
    _jwk_pub(root.get("cnf", {}).get("jwk", {}), "3l")
    root_aat = _aat_entry(root, "3m", exactly_one=True)
    for cm in root_aat["tools"].values():
        for c in cm.values():
            _cdepth(c)

    # 4: adjacent pairs
    claims = [root]
    for i in range(1, len(chain)):
        parent = claims[-1]
        child = _verify_jws(chain[i], _jwk_pub(parent["cnf"]["jwk"], "4b2"), "4a", "4b")
        for f, step in (("jti", "4b1"), ("cnf", "4b2"), ("authorization_details", "4b3"),
                        ("del_depth", "4b4"), ("del_max_depth", "4b4"),
                        ("iss", "4b5"), ("iat", "4b5"), ("exp", "4b5"), ("par_hash", "4b5")):
            if f not in child:
                raise Deny(step, f"{f} missing")
        _jwk_pub(child["cnf"].get("jwk", {}), "4b2")
        if child["iss"] != _thumb_uri(parent["cnf"]["jwk"]):
            raise Deny("4c", "iss != thumbprint(parent.cnf.jwk)")
        if child["del_depth"] != parent["del_depth"] + 1:
            raise Deny("4d", "del_depth not parent+1")
        if not (child["del_depth"] <= parent["del_max_depth"]):
            raise Deny("4e", "del_depth > parent.del_max_depth")
        if not (child["del_depth"] <= MAX_DELEGATION_DEPTH):
            raise Deny("4f", "del_depth > MAX")
        if not (child["del_max_depth"] <= parent["del_max_depth"]):
            raise Deny("4g", "del_max_depth raised")
        if not (child["exp"] <= parent["exp"]):
            raise Deny("4h", "exp > parent.exp")
        if not (child["exp"] > now):
            raise Deny("4i", "expired")
        if not (child["iat"] >= parent["iat"]):
            raise Deny("4j", "iat < parent.iat")
        if not (child["iat"] <= now + MAX_IAT_SKEW):
            raise Deny("4k", "iat in future")
        if not (child["exp"] > child["iat"]):
            raise Deny("4l", "exp <= iat")
        if not (child["del_depth"] <= child["del_max_depth"]):
            raise Deny("4m", "del_depth > del_max_depth")
        child_aat = _aat_entry(child, "4n", exactly_one=False)
        parent_aat = _aat_entry(parent, "4n", exactly_one=False)
        for cm in child_aat["tools"].values():
            for c in cm.values():
                _cdepth(c)
        for tname, cmap in child_aat["tools"].items():
            if tname not in parent_aat["tools"]:
                raise Deny("4p1", f"tool {tname!r} not in parent")
            pmap = parent_aat["tools"][tname]
            if pmap and set(pmap) != set(cmap):
                raise Deny("4p2", f"constraint keys differ for {tname!r}")
            for k in set(pmap) & set(cmap):
                if not subsumes(cmap[k], pmap[k]):
                    raise Deny("4p4", f"{tname}.{k} does not subsume")
        h, p, _ = _split(chain[i - 1])
        if child["par_hash"] != b64u(hashlib.sha256(f"{h}.{p}".encode("ascii")).digest()):
            raise Deny("4q", "par_hash mismatch")
        claims.append(child)

    leaf = claims[-1]
    if len(chain) != leaf["del_depth"] + 1:
        raise Deny("5", "chain length != leaf.del_depth+1")
    leaf_aat = _aat_entry(leaf, "6a", exactly_one=True)
    if tool not in leaf_aat["tools"]:
        raise Deny("6b", f"tool {tool!r} not authorized")
    cmap = leaf_aat["tools"][tool]
    if cmap:
        for a in args:
            if a not in cmap:
                raise Deny("6b", f"argument {a!r} not in closed-world map")
        for a in cmap:
            if a not in args:
                raise Deny("6b", f"constrained argument {a!r} absent")
        for a, c in cmap.items():
            if not check(c, args[a]):
                raise Deny("6b", f"argument {a!r} violates constraint")

    pop = _verify_jws(pop_jwt, _jwk_pub(leaf["cnf"]["jwk"], "7b"), "7a", "7b", expected_typ="aat-pop+jwt")
    if pop.get("aat_id") != leaf["jti"]:
        raise Deny("7c", "aat_id != leaf.jti")
    if audience is not None and pop.get("aat_aud") != audience:
        raise Deny("7d", "aat_aud mismatch")
    if pop.get("aat_tool") != tool:
        raise Deny("7e", "aat_tool != tool")
    if jcs(pop.get("hta")) != jcs(args):
        raise Deny("7f", "hta != args (JCS)")
    if abs(pop["iat"] - now) > POP_WINDOW:
        raise Deny("7g", "PoP iat outside window")
    return "PERMIT"


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------
CP, ORCH, WK, WK2, ATK = (KEYS[n] for n in ("control_plane", "orchestrator", "worker", "worker2", "attacker"))
TRUST = [CP.pub]

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


def pop_claims(jti: str, leaf_tok: dict, tool: str, hta: dict, iat=NOW, aud=AUDIENCE) -> dict:
    c = {"jti": jti, "iat": iat, "aat_id": leaf_tok["payload"]["jti"], "aat_tool": tool, "hta": hta}
    if aud is not None:
        c["aat_aud"] = aud
    return c


VECTORS: list[dict] = []


def add(vid: str, title: str, twin: str | None, desc: str, chain: list[dict], pop: dict, tool: str,
        args: dict, expect: str, expect_step: str | None = None, now: int = NOW, notes: list[str] | None = None):
    compact = [t["compact"] for t in chain]
    try:
        verdict, step = verify_chain(compact, TRUST, tool, args, pop["compact"], now=now), None
    except Deny as e:
        verdict, step = "DENY", e.step
    ok = verdict == expect and (expect == "PERMIT" or step == expect_step)
    if not ok:
        print(f"!! {vid}: expected {expect} {expect_step or ''}, got {verdict} {step or ''}", file=sys.stderr)
        sys.exit(1)
    VECTORS.append({
        "id": vid, "title": title, "cbor_twin": twin, "description": desc, "notes": notes or [],
        "verification_time": now, "tool": tool, "args": args,
        "chain": chain, "pop": pop,
        "expected": {"verdict": expect, "step": expect_step},
    })
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
add("J.6.1", "PoP without aat_aud, verifier requires audience", "A.6",
    "Same chain as J.3; the PoP omits aat_aud. The vector's deployment policy requires audience binding.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA04), L2, "read_file", {"path": Q3}, aud=None), WK2),
    "read_file", {"path": Q3}, "DENY", "7d",
    notes=["-02: aat_aud is REQUIRED. Under draft-01 text a verifier with no audience policy would PERMIT "
           "(Warden NOTES entry 8)."])
add("J.6.2", "PoP aat_aud does not identify this enforcement point", "A.6",
    "Same chain as J.3; aat_aud is present but names https://evil.example.com.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xA05), L2, "read_file", {"path": Q3},
                                     aud="https://evil.example.com"), WK2),
    "read_file", {"path": Q3}, "DENY", "7d")

# --- J.7 explicit typing (-02 proposal, RFC 8725 §3.11) ----------------------
add("J.7.1", "PoP JWT missing typ", None,
    "PoP is otherwise valid but its header is {\"alg\":\"EdDSA\"} with no typ.",
    [L0, L1, L2], pop_sign(pop_claims(uuid7ish(0xAE1), L2, "read_file", {"path": Q3}), WK2, header={"alg": "EdDSA"}),
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
j74_root = jws_sign(root_claims(uuid7ish(0x7F), ROOT_TOOLS, ORCH), CP, header={"alg": "EdDSA"})
add("J.7.4", "AAT missing typ", None,
    "Root is otherwise valid but its header is {\"alg\":\"EdDSA\"} with no typ.",
    [j74_root],
    pop_sign(pop_claims(uuid7ish(0xAE4), j74_root, "read_file", {"path": Q3}), ORCH),
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
    "L1 drops search_index.limit. §4.5 requires the exact same key set when the parent map is non-empty.",
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
none_hdr = b64u(jcs({"alg": "none"}))
none_root.update({"header": {"alg": "none"}, "header_b64": none_hdr, "signature_b64": "",
                  "signing_input": f"{none_hdr}.{L0['payload_b64']}", "compact": f"{none_hdr}.{L0['payload_b64']}.",
                  "signing_input_sha256_b64u": b64u(hashlib.sha256(f"{none_hdr}.{L0['payload_b64']}".encode()).digest()),
                  "signer": "(unsigned)"})
add("J.14.b", "alg: none rejected unconditionally", "A.14",
    "Same payload as the J.3 root with header {\"alg\":\"none\"} and an empty signature (§8.13).",
    [none_root], pop_sign(pop_claims(uuid7ish(0xAA2), none_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "3a")

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

# --- J.2 cycle detection -----------------------------------------------------
dup = jws_sign(derived_claims(uuid7ish(0x10), L0, ORCH, WK, L1_TOOLS, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.2", "Duplicate jti in chain (cycle detection, step 2c)", "A.9",
    "L1 reuses the root's jti. Detected before any signature is verified.",
    [L0, dup], pop_sign(pop_claims(uuid7ish(0xAD1), dup, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "DENY", "2c")


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
          "clauses. PERMIT under the agreed -02 rule (Tenuo's); draft-01's one-to-one text would DENY.",
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
composite("J.16.3", "any: empty derived any", "format: any[...] -> any[]. §4.5: derived any MUST contain at least one clause.",
          {"export": {"format": ANY(), "limit": ALL(rng(max=100), rng(min=0))}}, "DENY", "4p4", n=9)
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


# --- J.8 empty maps, unknown types, flatten ----------------------------------
EMPTY_ROOT = jws_sign(root_claims(uuid7ish(0xB10), {"read_file": {}}, ORCH), CP)
empty_child = jws_sign(derived_claims(uuid7ish(0xB11), EMPTY_ROOT, ORCH, WK,
                                     {"read_file": {"path": ex(Q3)}}, IAT_ROOT + 60, 1704069000, 2), ORCH)
add("J.8.1", "Empty parent map: derived introduces constraint keys (step 4p3)", None,
    "Root authorizes read_file with an empty constraint map. L1 introduces path:exact. "
    "§4.5 / step 4p3 permits adding keys when the parent map is empty.",
    [EMPTY_ROOT, empty_child], pop_sign(pop_claims(uuid7ish(0xB01), empty_child, "read_file", {"path": Q3}), WK),
    "read_file", {"path": Q3}, "PERMIT")
add("J.8.2", "Empty tool map at the leaf: extra arguments are permitted", None,
    "Root = leaf, read_file has an empty constraint map. Closed-world mode is off, so extra args PERMIT.",
    [EMPTY_ROOT], pop_sign(pop_claims(uuid7ish(0xB02), EMPTY_ROOT, "read_file", {"path": Q3, "mode": "r"}), ORCH),
    "read_file", {"path": Q3, "mode": "r"}, "PERMIT")
unk_root = jws_sign(root_claims(uuid7ish(0xB13), {"read_file": {"path": {"constraint_type": "no_such_type"}}}, ORCH), CP)
add("J.8.3", "Unknown constraint_type is fail-closed at the leaf", "A.9.2",
    "Root carries path:{constraint_type: no_such_type}. Step 6b denies unrecognized types.",
    [unk_root], pop_sign(pop_claims(uuid7ish(0xB03), unk_root, "read_file", {"path": Q3}), ORCH),
    "read_file", {"path": Q3}, "DENY", "6b",
    notes=["The draft fixes the outcome, not the step: a verifier that validates constraint types while "
           "walking the tree at step 3n will report 3n instead of 6b. Both are conformant."])
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


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
def tok_md(label: str, t: dict) -> str:
    out = [f"**{label}** (signed by `{t['signer']}`)", "",
           "Protected header (JCS):", "```json", jcs(t["header"]).decode(), "```",
           "Payload (JCS, this exact byte string is what is base64url-encoded):", "```json",
           jcs(t["payload"]).decode() if t["signer"] != "(unsigned)" else jcs(t["payload"]).decode(), "```",
           "Pretty payload:", "```json", json.dumps(t["payload"], indent=2), "```",
           "| Field | Value |", "|---|---|",
           f"| header_b64 | `{t['header_b64']}` |",
           f"| payload_b64 | `{t['payload_b64']}` |",
           f"| SHA-256(signing input), base64url | `{t['signing_input_sha256_b64u']}` |",
           f"| signature_b64 | `{t['signature_b64'] or '(empty)'}` |",
           "", "Compact JWS:", "```", t["compact"], "```", ""]
    return "\n".join(out)


md = []
md.append("# AAT JWS Test Vectors (draft-niyikiza-oauth-attenuating-agent-tokens-02)\n")
md.append("**Status:** generated by `gen_vectors.py`, do not edit by hand; "
          "every expected verdict below was reproduced by the independent §7 verifier in that file. "
          "These vectors are for the -02 text. A draft-01 implementation will disagree on `typ`, "
          "required `aat_aud`, and `all` clause-reuse (`J.15.3`, `J.15.4`).\n")
md.append("## Conventions\n")
md.append("- Signature algorithm: Ed25519, JWS `alg` = `EdDSA`.")
md.append("- **Explicit typing.** AAT header carries `typ` = `aat+jwt` and PoP header carries `typ` = `aat-pop+jwt` "
          "(RFC 8725 §3.11, cf. DPoP `dpop+jwt`). Verifiers reject a missing or mismatched `typ` at the header step "
          "(3a, 4a, 7a). Draft-01 defines no `typ`.")
md.append("- **Audience.** `aat_aud` is REQUIRED in the PoP and MUST match a configured audience. "
          "Draft-01 leaves this to deployment policy.")
md.append("- **`all` subsumption.** Every parent clause must be subsumed by at least one derived clause; "
          "a derived clause MAY cover several parent clauses; extra derived clauses are permitted. Draft-01's one-to-one "
          "assignment is dropped (it adds backtracking without adding soundness).")
md.append("- AAT payloads are JCS-canonical (RFC 8785). The draft requires JCS only for the PoP payload (§5.2). "
          "Canonicalizing AAT payloads is a vector choice so the signing input is reproducible; a verifier MUST "
          "verify the presented bytes and MUST NOT re-canonicalize before checking a signature.")
md.append("- `par_hash` = base64url-nopad(SHA-256(parent JWS Signing Input)), where the signing input is the ASCII "
          "string `BASE64URL(header) || '.' || BASE64URL(payload)` (§4.6). J.12.b shows the wrong (payload-only) form.")
md.append("- Derived `iss` = `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<RFC 7638 thumbprint of the signing key>`.")
md.append("- `jti` values follow the CBOR vector IDs: `tnu_wrt_019471f8...0001` becomes `019471f8-0000-7000-8000-000000000001`.")
md.append("- No floats, no non-ASCII strings, no escaped characters appear anywhere. That keeps JCS trivially portable "
          "and sidesteps the binary64 canonicalization issue (Warden NOTES entry 7), which needs its own vectors.")
md.append("")
md.append("## Verification parameters\n")
md.append("| Parameter | Value |\n|---|---|")
md.append(f"| now (verification time) | `{NOW}` (2024-01-01T00:05:00Z) |")
md.append(f"| MAX_IAT_SKEW | {MAX_IAT_SKEW} s |")
md.append(f"| MAX_TOKEN_LIFETIME | {MAX_TOKEN_LIFETIME} s (90 days) |")
md.append(f"| MAX_DELEGATION_DEPTH | {MAX_DELEGATION_DEPTH} |")
md.append(f"| MAX_CONSTRAINT_DEPTH | {MAX_CONSTRAINT_DEPTH} |")
md.append(f"| PoP clock window | ±{POP_WINDOW} s |")
md.append(f"| Required PoP audience | `{AUDIENCE}` (deployment policy for these vectors) |")
md.append(f"| Trust anchors | Control Plane public key only |")
md.append("")
md.append("## Key material\n")
md.append("Same seeds as `docs/spec/test-vectors.md`.\n")
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
md.append("## Index\n")
md.append("| ID | Title | CBOR twin | Expected |\n|---|---|---|---|")
for v in VECTORS:
    e = v["expected"]
    md.append(f"| {v['id']} | {v['title']} | {v['cbor_twin'] or '—'} | {e['verdict']}{' at step ' + e['step'] if e['step'] else ''} |")
md.append("")

for v in VECTORS:
    e = v["expected"]
    md.append(f"## {v['id']} {v['title']}\n")
    if v["cbor_twin"]:
        md.append(f"CBOR twin: {v['cbor_twin']}.  ")
    md.append(v["description"] + "\n")
    for n in v["notes"]:
        md.append(f"> {n}\n")
    md.append(f"**Invocation:** tool `{v['tool']}`, args `{jcs(v['args']).decode()}`, now = `{v['verification_time']}`  ")
    md.append(f"**Expected:** **{e['verdict']}**" + (f" at step {e['step']}" if e["step"] else "") + "\n")
    for i, t in enumerate(v["chain"]):
        md.append(tok_md(f"Chain[{i}] (del_depth {t['payload']['del_depth']})", t))
    md.append(tok_md("PoP JWT", v["pop"]))
    md.append("---\n")

(OUT / "aat-jws-vectors.md").write_text("\n".join(md))


def tok_json(t: dict) -> dict:
    return {k: t[k] for k in ("header", "payload", "header_b64", "payload_b64", "signing_input",
                              "signing_input_sha256_b64u", "signature_b64", "compact", "signer")}


json_out = {
    "spec": "draft-niyikiza-oauth-attenuating-agent-tokens-02",
    "conventions": {
        "header": HEADER, "pop_header": POP_HEADER,
        "aat_payload_jcs": True, "pop_payload_jcs": True,
        "aat_aud_required": True,
        "all_subsumption": "every parent clause subsumed by at least one derived clause; reuse permitted",
        "par_hash": "base64url-nopad(SHA-256(parent JWS Signing Input))",
    },
    "params": {"now": NOW, "max_iat_skew": MAX_IAT_SKEW, "max_token_lifetime": MAX_TOKEN_LIFETIME,
               "max_delegation_depth": MAX_DELEGATION_DEPTH, "pop_window": POP_WINDOW, "audience": AUDIENCE},
    "keys": {n: {"seed_hex": k.seed.hex(), "public_hex": k.pub_raw.hex(), "jwk": k.jwk,
                 "thumbprint": k.thumbprint, "thumbprint_uri": k.thumbprint_uri} for n, k in KEYS.items()},
    "trust_anchors": [CP.jwk],
    "vectors": [{
        "id": v["id"], "title": v["title"], "cbor_twin": v["cbor_twin"], "description": v["description"],
        "notes": v["notes"], "now": v["verification_time"], "tool": v["tool"], "args": v["args"],
        "chain": [tok_json(t) for t in v["chain"]], "chain_compact": [t["compact"] for t in v["chain"]],
        "pop": tok_json(v["pop"]), "expected": v["expected"],
    } for v in VECTORS],
}
(OUT / "aat-jws-vectors.json").write_text(json.dumps(json_out, indent=2) + "\n")
print(f"\nwrote {len(VECTORS)} vectors to {OUT}")
