#!/usr/bin/env python3
"""Compare an implementation's verdicts with the AAT JWS vector suite.

Usage:

    python3 ietf/vectors/compare_results.py RESULTS.json [--suite PATH] [--steps] [--json]

RESULTS.json maps each vector id to a verdict, or to an object with a
"verdict" and an optional "step":

    {"J.1": "PERMIT", "J.2": {"verdict": "DENY", "step": "2c"}}

A list of {"id": ..., "verdict": ..., "step": ...} objects is accepted too.
Verdicts are "PERMIT" or "DENY", in any case. Mark a vector the
implementation does not support as "SKIP", optionally with a "reason"; skipped
vectors are listed separately and are not disagreements.

Only verdicts are compared. Section 8 permits some reordering, so a different
failing step is not a disagreement; --steps lists those differences for
information.

The suite's SHA-256 is printed so that a report names the exact bytes it was
run against. Exit status: 0 if every reported verdict matches, 1 if any
differs, 2 for a usage or input error. Standard library only.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

DEFAULT_SUITE = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "aat-jws-vectors.json"
VERDICTS = {"PERMIT", "DENY", "SKIP"}


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def load_results(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        fail(f"cannot read results {path}: {e}")
    if isinstance(raw, list):
        items = []
        for entry in raw:
            if not isinstance(entry, dict) or "id" not in entry:
                fail("a results list must hold objects with an 'id'")
            items.append((entry["id"], entry))
    elif isinstance(raw, dict):
        items = list(raw.items())
    else:
        fail("results must be a JSON object or array")
    results = {}
    for vid, value in items:
        entry = value if isinstance(value, dict) else {"verdict": value}
        verdict = entry.get("verdict")
        if not isinstance(verdict, str) or verdict.upper() not in VERDICTS:
            fail(f"{vid}: verdict must be PERMIT, DENY or SKIP, got {verdict!r}")
        if vid in results:
            fail(f"{vid}: reported more than once")
        results[vid] = {"verdict": verdict.upper(), "step": entry.get("step"), "reason": entry.get("reason")}
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare an implementation's verdicts with the AAT JWS vectors.")
    ap.add_argument("results", type=Path, help="JSON file of verdicts by vector id")
    ap.add_argument("--suite", type=Path, default=DEFAULT_SUITE, help="vector suite (default: %(default)s)")
    ap.add_argument("--steps", action="store_true", help="also list DENY vectors whose step differs")
    ap.add_argument("--json", action="store_true", help="print a machine-readable summary instead")
    args = ap.parse_args()

    try:
        suite_bytes = args.suite.read_bytes()
        suite = json.loads(suite_bytes)
    except (OSError, ValueError) as e:
        fail(f"cannot read suite {args.suite}: {e}")
    vectors = {v["id"]: v for v in suite["vectors"]}
    results = load_results(args.results)

    unknown = sorted(set(results) - set(vectors))
    if unknown:
        fail(f"ids not in the suite: {', '.join(unknown)}")

    agree, differ, skipped, step_diff = [], [], [], []
    for vid, v in vectors.items():
        got = results.get(vid)
        if got is None:
            continue
        exp = v["expected"]
        if got["verdict"] == "SKIP":
            skipped.append((vid, got["reason"]))
        elif got["verdict"] != exp["verdict"]:
            differ.append((vid, exp, got, v["title"]))
        else:
            agree.append(vid)
            if exp["verdict"] == "DENY" and got["step"] and got["step"] != exp["step"]:
                step_diff.append((vid, exp["step"], got["step"], v["title"]))
    missing = [vid for vid in vectors if vid not in results]

    summary = {
        "suite": args.suite.name, "suite_sha256": hashlib.sha256(suite_bytes).hexdigest(),
        "spec": suite.get("spec"), "vectors": len(vectors), "reported": len(results),
        "agree": len(agree), "differ": len(differ), "skipped": len(skipped), "missing": len(missing),
        "disagreements": [{"id": vid, "expected": exp["verdict"], "expected_step": exp["step"],
                           "got": got["verdict"], "got_step": got["step"], "title": title}
                          for vid, exp, got, title in differ],
        "skipped_ids": [{"id": vid, "reason": reason} for vid, reason in skipped],
        "missing_ids": missing,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"suite:  {args.suite.name}")
        print(f"sha256: {summary['suite_sha256']}  ({summary['spec']}, {len(vectors)} vectors)")
        print(f"agree {len(agree)}, differ {len(differ)}, skipped {len(skipped)}, missing {len(missing)}")
        for vid, exp, got, title in differ:
            exp_s = exp["verdict"] + (f" at {exp['step']}" if exp["step"] else "")
            got_s = got["verdict"] + (f" at {got['step']}" if got["step"] else "")
            print(f"  DIFFER {vid}: expected {exp_s}, got {got_s}  ({title})")
        for vid, reason in skipped:
            print(f"  skip   {vid}" + (f": {reason}" if reason else ""))
        if missing:
            print(f"  missing: {', '.join(missing)}")
        if args.steps:
            for vid, exp_step, got_step, title in step_diff:
                print(f"  step   {vid}: expected {exp_step}, got {got_step}  ({title})")
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    main()
