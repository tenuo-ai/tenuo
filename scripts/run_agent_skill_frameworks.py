#!/usr/bin/env python3
"""Run real framework dispatch regressions and retain versioned evidence.

Dependencies are installed separately. Missing dependencies, skips, failures and
zero collected tests do not produce passing evidence. This never calls a model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "tests/agent-skills/tenuo-agent-authorization"
SUITES = ("openai", "langgraph", "temporal", "mcp")


def fingerprint(root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return digest.hexdigest()


def implementation_fingerprint(source: Path) -> str:
    paths = list((source / "tenuo-python/tenuo").rglob("*.py"))
    paths += list((source / "tenuo-core/src").rglob("*.rs"))
    paths += list((source / "tenuo-python/src").rglob("*.rs"))
    paths += [path for path in (
        source / "tenuo-python/Cargo.lock", source / "tenuo-core/Cargo.lock",
        source / "tenuo-python/build.rs", source / "tenuo-core/build.rs",
    ) if path.is_file()]
    paths += [
        source / "tenuo-python/pyproject.toml",
        source / "tenuo-python/Cargo.toml",
        source / "tenuo-core/Cargo.toml",
    ]
    return fingerprint(source, paths)


def harness_fingerprint(suite: str) -> str:
    return fingerprint(
        ROOT,
        [
            EVAL / f"frameworks/test_{suite}.py",
            EVAL / "frameworks/mcp_effect_server.py",
            Path(__file__).resolve(),
        ],
    )


def junit_counts(path: Path) -> dict:
    if not path.exists():
        return {"tests": 0, "failures": 0, "errors": 1, "skipped": 0}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    return {
        key: sum(int(s.get(key, 0)) for s in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }


def is_green(counts: dict, returncode: int) -> bool:
    return (
        returncode == 0
        and counts["tests"] > 0
        and all(counts[k] == 0 for k in ("failures", "errors", "skipped"))
    )


def matching_native_build(build: object, implementation: str, runtime: dict) -> bool:
    """A distribution URL proves location, not what compiled the extension."""
    return bool(
        isinstance(build, dict)
        and build.get("result") == "pass"
        and build.get("implementation_fingerprint") == implementation
        and build.get("native_sha256") == runtime.get("native_sha256")
        and isinstance(build.get("native_sha256"), str)
        and len(build["native_sha256"]) == 64
        and build.get("command")
        and build.get("generated_at")
    )


PROBE = r"""
import hashlib, importlib.metadata as m, json, tenuo, tenuo_core, sys
from pathlib import Path
packages = {}
for name in ['tenuo','openai-agents','langchain','langchain-core','langgraph','langgraph-prebuilt','temporalio','mcp','fastmcp']:
    try: packages[name] = m.version(name)
    except m.PackageNotFoundError: pass
native = Path(tenuo_core.__file__)
if native.suffix == '.py':
    candidates = list(native.parent.glob('*.so')) + list(native.parent.glob('*.pyd'))
    if len(candidates) != 1: raise RuntimeError('cannot identify native extension')
    native = candidates[0]
try:
    from agents.mcp import MCPServerStdio
    agents_mcp_hook = hasattr(MCPServerStdio(params={'command':'unused'}), 'tool_input_guardrails')
except ImportError:
    agents_mcp_hook = None
print(json.dumps(dict(python=sys.version, packages=packages, tenuo_path=tenuo.__file__, native_path=str(native), native_sha256=hashlib.sha256(native.read_bytes()).hexdigest(), direct_url=m.distribution('tenuo').read_text('direct_url.json'), agents_mcp_hook=agents_mcp_hook)))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument(
        "--source",
        type=Path,
        default=ROOT,
        help="exact checkout to exercise, never inferred from package version",
    )
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument(
        "--rebuild-native", action="store_true",
        help="force an exact-source native rebuild before tests; otherwise reuse a matching build record from --output",
    )
    parser.add_argument(
        "--lane",
        required=True,
        help="e.g. main-mcp1 or pr883-temporal; preserves other lanes",
    )
    parser.add_argument(
        "--output", type=Path, default=EVAL / "framework-regression-results.json"
    )
    args = parser.parse_args()
    source = args.source.resolve()
    implementation = implementation_fingerprint(source)
    report = (
        json.loads(args.output.read_text())
        if args.output.exists()
        else {"schema_version": 1, "runs": []}
    )
    build_command = [
        str(args.python), "-m", "pip", "install", "--no-deps",
        "--force-reinstall", "-e", str(source / "tenuo-python"),
    ]
    if args.rebuild_native:
        subprocess.run(build_command, cwd=source, check=True)
        if implementation_fingerprint(source) != implementation:
            raise RuntimeError("SDK source changed during native build")
    env = {
        **os.environ,
        "PYTHONPATH": str(source / "tenuo-python"),
        "OPENAI_AGENTS_DISABLE_TRACING": "1",
    }
    probe = json.loads(
        subprocess.check_output(
            [str(args.python), "-c", PROBE], env=env, cwd=source, text=True
        )
    )
    if not Path(probe["tenuo_path"]).resolve().is_relative_to(source):
        raise RuntimeError("imported Tenuo does not belong to --source")
    direct = json.loads(probe["direct_url"] or "{}")
    from urllib.parse import unquote, urlsplit

    installed_source = Path(unquote(urlsplit(direct.get("url", "")).path)).resolve()
    if installed_source != source / "tenuo-python":
        raise RuntimeError("native distribution was not built/installed from --source")
    if args.rebuild_native:
        native_build = {
            "result": "pass", "command": build_command,
            "implementation_fingerprint": implementation,
            "native_sha256": probe["native_sha256"],
            "generated_at": datetime.now(UTC).isoformat(),
        }
    else:
        native_build = next(
            (r.get("native_build") for r in reversed(report["runs"])
             if matching_native_build(r.get("native_build"), implementation, probe)),
            None,
        )
        if native_build is None:
            raise RuntimeError(
                "no matching native build record; rerun with --rebuild-native "
                "(an editable install URL alone does not prove source freshness)"
            )
    with tempfile.TemporaryDirectory(prefix="tenuo-framework-") as directory:
        junit = Path(directory) / "junit.xml"
        command = [
            str(args.python),
            "-m",
            "pytest",
            str(EVAL / f"frameworks/test_{args.suite}.py"),
            "-q",
            f"--junitxml={junit}",
        ]
        run = subprocess.run(
            command,
            check=False,
            cwd=source,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        print(run.stdout)
        counts = junit_counts(junit)
    sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source, text=True
    ).strip()
    if implementation_fingerprint(source) != implementation:
        raise RuntimeError("SDK source changed during framework tests")
    evidence = {
        "lane": args.lane,
        "suite": args.suite,
        "source_sha": sha,
        "implementation_fingerprint": implementation,
        "native_build": native_build,
        "harness_fingerprint": harness_fingerprint(args.suite),
        "generated_at": datetime.now(UTC).isoformat(),
        "runtime": probe,
        "counts": counts,
        "returncode": run.returncode,
        "result": "pass" if is_green(counts, run.returncode) else "fail",
        "output": run.stdout,
        "scope": "Real dispatch and effect counters for the enumerated cases only. No whole-agent or cross-version certification.",
    }
    report["runs"] = sorted(
        [r for r in report["runs"] if r["lane"] != args.lane] + [evidence],
        key=lambda r: r["lane"],
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
