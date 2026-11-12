"""Check the aat entries of cases.json against the AAT -02 reference verifier.

usage: python3 -I check_aat_column.py <dir holding gen_vectors.py> <cases.json>

For every case it builds a real chain with the suite's own helpers, presents it
with a PoP, and requires verify_chain to return the recorded result and step.
It also checks that each cited suite vector exists and has the same result.
It writes nothing.
"""
import json
import sys

sys.path.insert(0, sys.argv[1])
import gen_vectors as gv  # noqa: E402

TOOL = "export"
HOLD = (gv.ORCH, gv.WK, gv.WK2)
FMT = {"format": {"constraint_type": "one_of", "values": ["pdf", "csv"]}}
_n = [0xCC0000]


def jti():
    _n[0] += 1
    return gv.uuid7ish(_n[0])


def root(cmap, dmd=3):
    return gv.jws_sign(gv.root_claims(jti(), {TOOL: cmap}, gv.ORCH, dmd=dmd), gv.CP)


def derive(parent, cmap, dmd=3, cmap_text=None):
    depth = parent["payload"]["del_depth"] + 1
    signer, holder = HOLD[(depth - 1) % 3], HOLD[depth % 3]
    mark = {"@@": 1}
    claims = gv.derived_claims(jti(), parent, signer, holder, {TOOL: mark if cmap_text else cmap},
                               gv.IAT_ROOT + 10 * depth, gv.EXP_ROOT - 60 * depth, dmd)
    if cmap_text:
        text = gv.dumps_exact(claims)
        assert text.count('{"@@":1}') == 1
        return gv.jws_sign_raw(text.replace('{"@@":1}', cmap_text), signer)
    return gv.jws_sign(claims, signer)


def present(chain, args):
    holder = HOLD[(len(chain) - 1) % 3]
    args_json = gv.dumps_exact(args)
    parsed, dup = gv._loads(args_json)
    pop = gv.pop_sign(gv.pop_claims(jti(), chain[-1], TOOL, args), holder)
    try:
        return gv.verify_chain([t["compact"] for t in chain], gv.TRUST, TOOL, parsed, pop["compact"], args_dup=dup), None
    except gv.Deny as e:
        return "DENY", e.step


doc = json.load(open(sys.argv[2]))
bad = 0
for c in doc["cases"]:
    a = c["aat"]
    if "chain" in a:
        pairs = a["chain"]
        assert pairs[0][0] == 0
        chain = [root(FMT, dmd=pairs[0][1])]
        for depth, dmd in pairs[1:]:
            chain.append(derive(chain[-1], FMT, dmd=dmd))
            assert chain[-1]["payload"]["del_depth"] == depth
        args = {"format": "pdf"}
    else:
        chain = [root(a["parent"])]
        if "child" in a or "child_text" in a:
            chain.append(derive(chain[0], a.get("child"), cmap_text=a.get("child_text")))
            if "child_text" in a:
                assert a["child_text"] in chain[-1]["payload_json"]
        args = a["request"]
    verdict, step = present(chain, args)
    ok = verdict == a["result"] and step == a["step"]
    sv = a.get("suite_vector")
    if sv:
        v = next((x for x in gv.VECTORS if x["id"] == sv), None)
        same = v is not None and v["expected"]["verdict"] == a["result"] and v["expected"]["step"] == a["step"]
        ok = ok and same
        sv = f'{sv} {"same" if same else "DIFFERS"}'
    bad += not ok
    print(f'{"ok" if ok else "!!"} {c["id"]:6} {verdict:6} {step or "":4} recorded {a["result"]:6} {a["step"] or "":4} {sv or "":14} {c["title"]}')
print(f"\n{len(doc['cases'])} cases, {bad} mismatches; suite sha256 unchanged: nothing was written")
sys.exit(1 if bad else 0)
