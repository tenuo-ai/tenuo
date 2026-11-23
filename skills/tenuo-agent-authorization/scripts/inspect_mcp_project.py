#!/usr/bin/env python3
"""Inventory evidence for an end-to-end Tenuo MCP authorization path.

This helper is read-only and heuristic. It identifies files that deserve
inspection; it does not certify that an integration is secure.
"""

from __future__ import annotations

import argparse
import json
import os
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
    "framework": re.compile(
        r"\b(?:from|import)\s+(?:agents|openai|langchain\w*|langgraph\w*|crewai|temporalio|"
        r"tenuo\.(?:openai|langchain|langgraph|crewai|autogen|google_adk|temporal|fastapi|a2a)|mcp|fastmcp)\b|"
        r"from\s+[\"'](?:@langchain/|@openai/agents|@modelcontextprotocol/)"
    ),
    "mcp_server": re.compile(
        r"\bFastMCP\s*\(|\bServer\s*\(|@\w*\.tool\s*\(|"
        r"\bMcpServer\s*\(|\.registerTool\s*\(|\bserver\.tool\s*\(|\bguardTools\s*\(|"
        r"\brmcp::|#\[tool\b|\btenuo::mcp\b"
    ),
    "mcp_client": re.compile(
        r"\bSecureMCPClient\b|\bClientSession\b|\.call_tool\s*\(|"
        r"\.callTool\s*\(|\btenuo\.mcp\.attach\s*\(|\bMcpMeta\b"
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
    "propagation": re.compile(
        r"inject_warrant\s*=|_meta[\"']?\s*[:.]\s*[\"']?tenuo|"
        r"[\"']_tenuo[\"']|\bwarrant_chain\b|\bencode_warrant_stack\b|\bchain_scope\s*\(|"
        r"\btenuo\.mcp\.attach\s*\(|\btenuo\.present\s*\(|\bmcp_meta\b|\bpresent\s*\("
    ),
    "verifier": re.compile(
        r"\bMCPVerifier\s*\(|\bTenuoServerMiddleware\s*\(|\bTenuoMiddleware\s*\(|"
        r"\btenuo\.mcp\.(?:verify|handler)\s*\(|\btenuo\.verify\s*\(|\bguardTools\s*\(|"
        r"\bAuthorizer::(?:new|builder)\s*\(|\bGuard::\w+\s*\(|\bcheck_chain\w*\s*\("
    ),
    "trusted_roots": re.compile(
        r"\btrusted_roots\s*[=(]|TENUO_TRUSTED_ROOTS|\btrustedRoots\s*:|"
        r"\bwith_trusted_roots\s*\(|\bTrustStore\b"
    ),
    # Only the Python MCPVerifier exposes an optional-warrant switch
    # (require_warrant). The TypeScript and Rust verifiers have no such
    # option and fail closed unless a wrapper makes authorization optional.
    "fail_closed": re.compile(r"\brequire_warrant\s*=\s*True\b"),
    "effect": re.compile(
        r"\b(?:subprocess\.(?:run|Popen|call)|shutil\.rmtree|"
        r"os\.(?:remove|unlink|rename|replace)|"
        r"requests\.(?:post|put|patch|delete)|httpx\.(?:post|put|patch|delete)|"
        r"\w+\.(?:write|delete|remove|unlink|insert|update|commit|publish|send|deploy)\s*\(|"
        r"(?:delete|remove|deploy|send|publish|create|update|write|refund|charge|pay|transfer)_\w+\s*\(|"
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
    # Prune before descent: filtering rglob results still traverses dependency
    # trees. A copied skill and an alternatively named virtualenv are not target
    # application evidence. Keep other agent configuration directories visible.
    installed_skill = Path(__file__).resolve().parents[1]
    for directory, directories, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        directories[:] = [
            name for name in directories
            if name not in IGNORED_DIRS
            and not (parent / name).is_symlink()
            and (parent / name).resolve() != installed_skill
            and not (parent / name / "pyvenv.cfg").is_file()
        ]
        for name in files:
            path = parent / name
            if (
                path.suffix.lower() in TEXT_SUFFIXES
                and path.is_file()
                and path.resolve().is_relative_to(root.resolve())
            ):
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
            # Rust attributes are executable metadata, not hash comments.
            comment_prefixes = ("//", "/*", "*") if path.suffix.lower() == ".rs" else ("#", "//", "/*", "*")
            if not stripped or stripped.startswith(comment_prefixes):
                continue
            for kind, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(Finding(kind=kind, path=relative, line=number, excerpt=stripped[:180]))
    return findings


def summarize(findings: list[Finding], max_per_kind: int) -> dict[str, object]:
    by_kind: dict[str, list[Finding]] = {kind: [] for kind in PATTERNS}
    for finding in findings:
        by_kind[finding.kind].append(finding)

    # The advertised path is issuer -> holder-bound warrant -> PoP-signed MCP
    # call -> verifier -> effect, so an MCP endpoint and an effect are as
    # required as the authority roles. A repository with none of them has
    # nothing to protect yet and must not read as gap-free.
    required = ("issuer", "holder", "propagation", "verifier", "trusted_roots", "effect")
    gaps = [kind for kind in required if not by_kind[kind]]
    if not by_kind["mcp_server"] and not by_kind["mcp_client"]:
        gaps.insert(0, "mcp_endpoint")
    warnings: list[str] = []
    if not by_kind["test"]:
        warnings.append("No test evidence was found; denial-before-effect tests are required.")
    if by_kind["verifier"] and not by_kind["issuer"]:
        warnings.append("Verifier evidence exists, but no warrant minting path was found.")
    if by_kind["issuer"] and by_kind["verifier"]:
        issuer_files = {item.path for item in by_kind["issuer"]}
        verifier_files = {item.path for item in by_kind["verifier"]}
        if issuer_files & verifier_files:
            warnings.append(
                "Issuance and verification appear in the same file; confirm the agent cannot control the issuer."
            )
    verifier_suffixes = {Path(item.path).suffix.lower() for item in by_kind["verifier"]}
    if verifier_suffixes & {".py", ".pyi"} and not by_kind["fail_closed"]:
        warnings.append(
            "Python verifier evidence exists, but require_warrant=True was not found; "
            "an MCPVerifier with require_warrant=False lets unauthenticated callers through."
        )
    if verifier_suffixes & {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".rs"}:
        warnings.append(
            "TypeScript and Rust verifiers have no optional-warrant switch; confirm manually that "
            "no wrapper, observe-only mode, or fallback route makes authorization optional."
        )

    # Nested evidence shares each kind's --max-per-kind budget, so "truncated" covers it too.
    shown = {id(item) for items in by_kind.values() for item in items[:max_per_kind]}
    candidates = []
    for path in sorted({item.path for item in findings}):
        items = [item for item in findings if item.path == path]
        evidence_text = "\n".join(item.excerpt for item in items)
        frameworks = [
            label
            for label, pattern in {
                "OpenAI Agents": r"agents|function_tool|tool_input_guardrails|tenuo\.openai",
                "LangChain/LangGraph": r"langchain|langgraph|TenuoToolNode|TenuoMiddleware|tenuo_node|guard_node",
                "Temporal": r"temporal|TenuoTemporalPlugin|TenuoWorkerInterceptor",
                "CrewAI": r"crewai|GuardedCrew|guarded_step|before_tool_call",
                "Google ADK": r"google_adk|TenuoPlugin|before_tool_callback",
                "FastAPI": r"fastapi|SecureAPIRouter",
                "MCP": r"MCP|McpServer|call_tool|callTool",
            }.items()
            if re.search(pattern, evidence_text, re.I)
        ]
        candidates.append(
            {
                "path": path,
                "framework_candidates": frameworks,
                "tool_types": sorted(
                    {
                        item.kind
                        for item in items
                        if item.kind in {"native_tool", "builtin_execution", "handoff", "mcp_server", "mcp_client"}
                    }
                ),
                "effects": [asdict(item) for item in items if item.kind == "effect" and id(item) in shown],
                "existing_interception": [
                    asdict(item) for item in items if item.kind in {"interceptor", "verifier"} and id(item) in shown
                ],
                "possible_bypass": "Unverified: trace original handlers, alternate dispatch and direct effect clients in source.",
            }
        )

    return {
        "certified": False,
        "candidate_boundaries": candidates,
        "counts": {kind: len(items) for kind, items in by_kind.items()},
        "evidence": {kind: [asdict(item) for item in items[:max_per_kind]] for kind, items in by_kind.items() if items},
        "truncated": {kind: len(items) - max_per_kind for kind, items in by_kind.items() if len(items) > max_per_kind},
        "gaps": gaps,
        "warnings": warnings,
        "note": "Heuristic inventory only; confirm trust ownership and denial-before-effect behavior manually.",
    }


def print_human(summary: dict[str, object]) -> None:
    evidence = summary["evidence"]
    counts = summary["counts"]
    assert isinstance(evidence, dict)
    assert isinstance(counts, dict)
    print("Tenuo MCP integration inventory")
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
    print("Gaps: " + (", ".join(gaps) if gaps else "no missing symbols; coverage still unverified"))
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
