#!/usr/bin/env python3
"""Inventory evidence for native agent tools and their authorization path.

This helper is read-only and heuristic. It identifies files that deserve
inspection; it does not prove complete mediation or certify an integration.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


IGNORED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}

TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".rs",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}

PATTERNS = {
    "native_tool": re.compile(
        r"@(?:\w+\.)?(?:function_tool|tool)\b|\bFunctionTool\s*\(|"
        r"\bStructuredTool\.from_function\s*\(|\bToolNode\s*\(|"
        r"\b(?:defineTool|createTool)\s*\(|\btool\s*\(\s*\{|\bDynamicStructuredTool\s*\(|"
        r"\btenuo\.tool\s*\(|\bimpl\s+Tool\s+for\b|\brig::tool\b"
    ),
    "tool_registration": re.compile(
        r"\btools\s*=\s*\[|\.bind_tools\s*\(|\btools\s*:\s*\[|\btools\s*:\s*{"
    ),
    "builtin_execution": re.compile(
        r"\b(?:ShellTool|LocalShellTool|ComputerTool|ApplyPatchTool|CodeInterpreterTool)\s*\(|"
        r"\bsubprocess\.(?:run|Popen|call)\s*\(|\bos\.system\s*\(|"
        r"\bchild_process\.(?:exec|spawn)\s*\(|\b(?:execSync|spawnSync|execFile)\s*\(|"
        r"\bstd::process\b|\bCommand::new\s*\("
    ),
    "handoff": re.compile(
        r"\.as_tool\s*\(|\bhandoff\s*\(|\bhandoffs\s*=|\bsubagents?\s*=|"
        r"\bdelegate\s*\("
    ),
    "interceptor": re.compile(
        r"\btool_input_guardrails\b|\bbefore_tool_call\b|\bpreToolUse\b|"
        r"\bTenuoToolNode\b|\bTenuoMiddleware\b|\bcreate_tier[12]_guardrail\b|"
        r"\bguard_tools?\s*\(|\b_authorize\s*\(|"
        r"\btenuo\.tool\s*\(|\bwithSession\s*\(|\bguardTools\s*\(|"
        r"\bGuard::\w+\s*\(|\bTenuoGuard\b|\bbefore_tool\w*\b|\bpre_tool\w*\b"
    ),
    # Python, TypeScript, and Rust spellings of the same roles.
    "issuer": re.compile(
        r"\bWarrant\.mint_builder\s*\(|\bmint_sync\s*\(|\bmint\s*\(|"
        r"fire_trigger\s*\(|/triggers/[^\s]+/fire|"
        r"\bcreateTenuo\s*\(|\.session\s*\(|\bdevRoot\s*\(|\bissuerKeyFrom\w*\s*\(|"
        r"\bWarrant::builder\s*\(|\bWarrantBuilder\b|\bSigningKey::generate\s*\("
    ),
    "holder": re.compile(
        r"\.holder\s*\(|\bkey_scope\s*\(|\bholder_key\b|\bagent_key\b|"
        r"\bholder\s*:|\bpublicKeyFromHex\s*\(|\bholderKey\b|\bLocalSigner\b|\bHolderKey\b"
    ),
    "verifier": re.compile(
        r"\bAuthorizer\s*\(|\bMCPVerifier\s*\(|\bcheck_sync\s*\(|"
        r"\bauthoriz(?:e|er)\.(?:check|verify)\s*\(|"
        r"\btenuo\.verify\s*\(|\btenuo\.mcp\.verify\s*\(|\bcontext\.authorize\s*\(|"
        r"\bAuthorizer::(?:new|builder)\s*\(|\bcheck_chain\w*\s*\(|\bverify_pop\w*\s*\("
    ),
    "trusted_roots": re.compile(
        r"\btrusted_roots\s*[=(]|TENUO_TRUSTED_ROOTS|\btrustedRoots\s*:|"
        r"\bwith_trusted_roots\s*\(|\bTrustStore\b"
    ),
    "effect": re.compile(
        r"\b(?:subprocess\.(?:run|Popen|call)|shutil\.rmtree|"
        r"os\.(?:remove|unlink|rename|replace)|"
        r"requests\.(?:post|put|patch|delete)|httpx\.(?:post|put|patch|delete)|"
        r"\w+\.(?:write|delete|remove|unlink|insert|update|commit|publish|send|deploy)\s*\(|"
        r"(?:delete|remove|deploy|send|publish|create|update|write)_\w+\s*\(|"
        r"\bfs\.(?:writeFile|writeFileSync|rm|rmSync|unlink|rename)\w*\s*\(|"
        r"\baxios\.(?:post|put|patch|delete)\s*\(|"
        r"method\s*:\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"']|"
        r"\bstd::fs::(?:write|remove_\w+|rename)\s*\(|\bCommand::new\s*\(|"
        r"\breqwest\b.*\.(?:post|put|patch|delete)\s*\()",
        re.IGNORECASE,
    ),
    "test": re.compile(
        r"\bpytest\b|\bunittest\b|\bassert\b|\bMock\s*\(|"
        r"\bvitest\b|\bjest\b|\bdescribe\s*\(|\bexpect\s*\(|"
        r"#\[(?:tokio::)?test\]|\bassert(?:_eq|_ne)?!\s*\("
    ),
}


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int
    excerpt: str


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def inspect(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        relative = str(path.relative_to(root))
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                continue
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(
                        Finding(kind=kind, path=relative, line=number, excerpt=stripped[:180])
                    )
    return findings


def summarize(findings: list[Finding], max_per_kind: int) -> dict[str, object]:
    by_kind: dict[str, list[Finding]] = {kind: [] for kind in PATTERNS}
    for finding in findings:
        by_kind[finding.kind].append(finding)

    required = ("native_tool", "issuer", "holder", "verifier", "trusted_roots", "effect")
    gaps = [kind for kind in required if not by_kind[kind]]
    warnings: list[str] = []
    if by_kind["native_tool"] and not by_kind["verifier"]:
        warnings.append("Native tool evidence exists, but no verifier path was found.")
    if by_kind["verifier"] and not by_kind["issuer"]:
        warnings.append("Verifier evidence exists, but no warrant minting path was found.")
    if by_kind["builtin_execution"]:
        warnings.append(
            "Built-in or direct execution exists; confirm the selected framework hook covers it or verify downstream."
        )
    if by_kind["issuer"] and by_kind["verifier"]:
        issuer_files = {item.path for item in by_kind["issuer"]}
        verifier_files = {item.path for item in by_kind["verifier"]}
        if issuer_files & verifier_files:
            warnings.append(
                "Issuance and verification appear in the same file; confirm the agent cannot control the issuer."
            )

    return {
        "counts": {kind: len(items) for kind, items in by_kind.items()},
        "evidence": {
            kind: [asdict(item) for item in items[:max_per_kind]]
            for kind, items in by_kind.items()
            if items
        },
        "truncated": {
            kind: len(items) - max_per_kind
            for kind, items in by_kind.items()
            if len(items) > max_per_kind
        },
        "gaps": gaps,
        "warnings": warnings,
        "note": "Heuristic inventory only; confirm hook coverage, trust ownership, and denial-before-effect manually.",
    }


def print_human(summary: dict[str, object]) -> None:
    evidence = summary["evidence"]
    counts = summary["counts"]
    assert isinstance(evidence, dict)
    assert isinstance(counts, dict)
    print("Tenuo native agent tool inventory")
    print()
    for kind in PATTERNS:
        items = evidence.get(kind, [])
        label = kind.replace("_", " ").title()
        if not items:
            print(f"{label}: not found")
            continue
        print(f"{label}:")
        for item in items:
            print(f"  - {item['path']}:{item['line']}  {item['excerpt']}")
        omitted = counts[kind] - len(items)
        if omitted:
            print(f"  - ... {omitted} more")
    print()
    gaps = summary["gaps"]
    print("Gaps: " + (", ".join(gaps) if gaps else "none detected"))
    for warning in summary["warnings"]:
        print(f"Warning: {warning}")
    print(f"Note: {summary['note']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="project root")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--max-per-kind",
        type=int,
        default=8,
        help="maximum evidence entries emitted for each category (default: 8)",
    )
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"not a directory: {root}")
    if args.max_per_kind < 1:
        parser.error("--max-per-kind must be at least 1")

    summary = summarize(inspect(root), args.max_per_kind)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_human(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
