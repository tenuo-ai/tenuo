"""Offline structural checks and an explicit, strict promotion report.

Normal CI remains deterministic and does not invoke GitHub or a hosted model.
An online horizon --check is a separate maintenance check.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .refresh_agent_skill_horizon import (
        AUTHORS,
        CATEGORIES,
        render,
        render_frameworks,
        refresh_policy,
        matches_refresh_pr,
        source_fingerprint,
    )
    from .run_agent_skill_frameworks import (
        harness_fingerprint,
        implementation_fingerprint,
        is_green,
        matching_native_build,
    )
else:
    from refresh_agent_skill_horizon import (
        AUTHORS,
        CATEGORIES,
        render,
        render_frameworks,
        refresh_policy,
        matches_refresh_pr,
        source_fingerprint,
    )
    from run_agent_skill_frameworks import (
        harness_fingerprint,
        implementation_fingerprint,
        is_green,
        matching_native_build,
    )

MAX_AGE_DAYS = 7
FRAMEWORKS = {
    "MCP",
    "LangChain",
    "LangGraph",
    "OpenAI Agents",
    "Temporal",
    "CrewAI",
    "Google ADK",
    "AutoGen",
    "FastAPI",
    "A2A",
    "Hermes",
}


def age_problem(value: str, now: datetime) -> str | None:
    try:
        stamp = datetime.fromisoformat(value)
        age = (now - stamp).total_seconds()
    except (ValueError, TypeError):
        return "missing or invalid timezone-aware timestamp"
    if age < -300:
        return "timestamp is in the future"
    if age > MAX_AGE_DAYS * 86400:
        return f"older than {MAX_AGE_DAYS} days"
    return None


def horizon_checks(
    root: Path, skill: Path, release: dict, now: datetime | None = None
) -> tuple[list[str], list[str]]:
    errors, freshness = [], []
    now = now or datetime.now(UTC)
    try:
        snapshot = json.loads((skill / "unreleased.json").read_text())
        reviews = json.loads((skill / "unreleased-reviews.json").read_text())
        status = json.loads((skill / "framework-status.json").read_text())
        if (
            snapshot["schema_version"] != 1
            or snapshot["repository"] != "tenuo-ai/tenuo"
            or not snapshot["complete"]
        ):
            errors.append("unreleased overlay: invalid provenance/completeness")
        if sorted(snapshot["authors"]) != sorted(AUTHORS):
            errors.append("unreleased overlay must query both required authors")
        age = age_problem(snapshot["generated_at"], now)
        if age:
            freshness.append("open-PR snapshot " + age)
        prs = snapshot["pull_requests"]
        numbers = [p["number"] for p in prs]
        if len(numbers) != len(set(numbers)):
            errors.append("duplicate PRs in overlay")
        if snapshot["counts"] != {
            a: sum(p["author"] == a for p in prs) for a in AUTHORS
        }:
            errors.append("open-PR author counts contradict inventory")
        heads = {p["head"]: p["number"] for p in prs}
        policy = refresh_policy(root / "scripts/agent_skill_refresh_pr.json")
        for p in prs:
            n = p["number"]
            identity = p.get("refresh_identity")
            if identity and (
                not matches_refresh_pr(p, policy)
                or identity.get("policy") != policy
                or identity.get("method") != "full-head-tree-excluding-horizon-outputs-and-own-review-v1"
                or not isinstance(identity.get("tree_fingerprint"), str)
                or len(identity["tree_fingerprint"]) != 64
                or any(c not in "0123456789abcdef" for c in identity["tree_fingerprint"])
            ):
                errors.append(f"PR #{n}: invalid self-refresh identity exception")
            if p["author"] not in AUTHORS or p[
                "source_fingerprint"
            ] != source_fingerprint(p):
                errors.append(f"PR #{n}: source provenance/fingerprint mismatch")
            r = p["review"]
            if p["stack_parent"] != heads.get(p["base"]):
                errors.append(f"PR #{n}: incorrect stack parent")
            expected_deps = sorted(
                set(
                    ([p["stack_parent"]] if p["stack_parent"] else [])
                    + r.get("depends_on", [])
                )
            )
            if p["depends_on"] != expected_deps:
                errors.append(f"PR #{n}: dependency graph contradicts review/branch")
            if p["review_status"] != "reviewed":
                freshness.append(f"PR #{n}: pending review")
                continue
            if (
                r != reviews.get(str(n))
                or r["source_fingerprint"] != p["source_fingerprint"]
            ):
                errors.append(f"PR #{n}: review does not match source snapshot")
            cats = r["category"]
            if (
                not cats
                or set(cats) - set(CATEGORIES)
                or ("I" in cats and len(cats) != 1)
            ):
                errors.append(f"PR #{n}: invalid classification")
            if not r["summary"] or not all(
                isinstance(r.get(k), bool)
                for k in ("security_relevance", "api_relevance", "docs_relevance")
            ):
                errors.append(f"PR #{n}: missing impact review")
        graph = {p["number"]: p["depends_on"] for p in prs}
        visited, active = set(), set()

        def visit(n):
            if n in active:
                raise ValueError(f"cyclic PR dependency at #{n}")
            if n in visited or n not in graph:
                return  # closed/external prerequisites remain recorded in reviews
            active.add(n)
            for parent in graph[n]:
                visit(parent)
            active.remove(n)
            visited.add(n)

        for n in graph:
            visit(n)
        if (skill / "references/unreleased.md").read_text() != render(snapshot):
            errors.append("generated unreleased.md is out of sync")
        if (skill / "references/framework-status.md").read_text() != render_frameworks(
            status, snapshot
        ):
            errors.append("generated framework-status.md is out of sync")
        if {f["name"] for f in status["frameworks"]} != FRAMEWORKS:
            errors.append("framework status is missing required surfaces")
        if status.get("reviewed_main_source_fingerprint") != snapshot.get(
            "main_source_fingerprint"
        ) or not snapshot.get("main_source_fingerprint"):
            freshness.append("framework facts need review for changed main SDK sources")
        if status["reviewed_release_tag"] != release.get("repository_tag"):
            freshness.append("framework facts need review for re-pinned release")
        guidance_paths = [skill / "SKILL.md"] + [
            p
            for p in (skill / "references").glob("*.md")
            if p.name not in {"unreleased.md", "framework-status.md"}
        ]
        from hashlib import sha256

        guidance = sha256()
        for path in sorted(guidance_paths):
            guidance.update(path.relative_to(skill).as_posix().encode() + b"\0")
            guidance.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
        review = status.get("guidance_review", {})
        if (
            review.get("fingerprint") != guidance.hexdigest()
            or review.get("consistent_with_known_gaps") is not True
        ):
            freshness.append("skill guidance needs review against known framework gaps")
        for f in status["frameworks"]:
            for path in f["source_paths"] + f["existing_test_paths"]:
                if not (root / path).is_file():
                    errors.append(f"framework status: missing evidence path {path}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"invalid horizon/framework artifacts: {exc}")
    return errors, freshness


def promotion_checks(
    root: Path, skill: Path, release: dict, structural_errors: list[str]
) -> dict[str, list[str]]:
    if __package__:
        from .validate_agent_skills import (
            behavioral_eval_fingerprint,
            validate_behavioral_eval_result,
        )
    else:
        from validate_agent_skills import (
            behavioral_eval_fingerprint,
            validate_behavioral_eval_result,
        )

    errors, freshness = horizon_checks(root, skill, release)
    checks = {
        "structural and release contract": list(structural_errors),
        "reviewed open-PR snapshot and framework facts": errors + freshness,
        "framework regression matrix": [],
        "generic payment-boundary coding-agent eval": [],
        "framework coding-agent eval": [],
        "project onboarding coding-agent eval": [],
    }
    evidence_dir = root / "tests/agent-skills/tenuo-agent-authorization"
    try:
        runs = json.loads(
            (evidence_dir / "framework-regression-results.json").read_text()
        )["runs"]
        implementation = implementation_fingerprint(root)
        for suite, major in (
            ("openai", None),
            ("langgraph", None),
            ("temporal", None),
            ("mcp", "1"),
            ("mcp", "2"),
        ):
            current = [
                r for r in runs
                if r["suite"] == suite
                and r["implementation_fingerprint"] == implementation
                and r["harness_fingerprint"] == harness_fingerprint(suite)
                and (major is None or r["runtime"]["packages"].get("mcp", "").split(".")[0] == major)
            ]
            for r in current:
                if r["result"] != "pass" or not is_green(r["counts"], r["returncode"]):
                    checks["framework regression matrix"].append(
                        f"current {suite} lane {r.get('lane', 'unnamed')} failed; "
                        "another green lane cannot override it"
                    )
            matches = [
                r
                for r in current
                if matching_native_build(r.get("native_build"), implementation, r["runtime"])
                and r["result"] == "pass"
                and is_green(r["counts"], r["returncode"])
                and not age_problem(r["generated_at"], datetime.now(UTC))
                and (
                    major is None
                    or r["runtime"]["packages"].get("mcp", "").split(".")[0] == major
                )
            ]
            if not matches:
                checks["framework regression matrix"].append(
                    f"missing current green {suite}"
                    + (f" / MCP {major}" if major else "")
                )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        checks["framework regression matrix"].append(
            f"missing/invalid regression evidence: {exc}"
        )
    for scenario, label in (
        ("payment-boundary", "generic payment-boundary coding-agent eval"),
        ("framework-boundary", "framework coding-agent eval"),
        ("project-onboarding", "project onboarding coding-agent eval"),
    ):
        for language in (
            ("python", "typescript", "rust")
            if scenario == "payment-boundary"
            else ("python",)
        ):
            path = evidence_dir / f"{scenario}-result.{language}.json"
            issues, warnings = [], []
            try:
                result = json.loads(path.read_text())
                if not isinstance(result, dict):
                    raise ValueError("coding-agent evidence must be an object")
                inputs = validate_behavioral_eval_result(
                    result,
                    issues,
                    str(path),
                    language,
                    warnings,
                    skill_dir=skill,
                    scenario=scenario + "-eval.md",
                )
                if (
                    issues
                    or warnings
                    or result.get("result") != "pass"
                    or result.get("evidence_kind") != "fresh"
                    or not inputs
                ):
                    raise ValueError(
                        "missing fresh passing implementation and reporting evidence"
                    )
                if any(
                    result.get("evidence", {}).get(k) != "passed"
                    for k in ("critical_items", "required_reporting")
                ):
                    raise ValueError("implementation/reporting not both passed")
                if result["skill_fingerprint"] != behavioral_eval_fingerprint(
                    inputs, skill
                ):
                    raise ValueError("stale skill input fingerprint")
                if scenario == "framework-boundary":
                    for issue in framework_case_checks(result, evidence_dir, skill):
                        checks[label].append(issue)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                checks[label].append(f"{language}: {exc}")
    return checks


def framework_case_checks(result: dict, evidence_dir: Path, skill: Path) -> list[str]:
    """An aggregate pass is not evidence that every required dispatcher ran."""
    if __package__:
        from .validate_agent_skills import validate_behavioral_eval_result
    else:
        from validate_agent_skills import validate_behavioral_eval_result

    problems = []
    cases = result.get("cases")
    if not isinstance(cases, dict):
        return ["missing per-case coding-agent evidence"]
    for name in ("openai", "langgraph", "temporal", "mcp1", "mcp2"):
        case = cases.get(name)
        issues, warnings = [], []
        if not isinstance(case, dict):
            problems.append(f"{name}: missing coding-agent case")
            continue
        try:
            inputs = validate_behavioral_eval_result(
                case, issues, f"framework case {name}", "python", warnings,
                skill_dir=skill, scenario="framework-boundary-eval.md",
            )
            if (
                issues or warnings or not inputs
                or case.get("result") != "pass"
                or case.get("evidence_kind") != "fresh"
                or any(case.get("evidence", {}).get(key) != "passed"
                       for key in ("critical_items", "required_reporting"))
            ):
                raise ValueError("needs current passing implementation and reporting evidence")
            artifacts = case.get("artifacts")
            if not isinstance(artifacts, list) or not artifacts:
                raise ValueError("missing preserved case artifacts")
            for artifact in artifacts:
                if not isinstance(artifact, str):
                    raise ValueError("artifact paths must be strings")
                path = evidence_dir / artifact
                if (Path(artifact).is_absolute() or ".." in Path(artifact).parts
                    or not path.resolve().is_relative_to(evidence_dir.resolve())
                    or not path.is_file()):
                    raise ValueError(f"missing or non-contained artifact: {artifact}")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            problems.append(f"{name}: {exc}")
    return problems


def render_promotion(checks: dict[str, list[str]]) -> str:
    ready = not any(checks.values())
    lines = [
        "## Distribution readiness",
        "",
        "READY" if ready else "NOT READY — promotion blockers remain",
        "",
        (
            "This offline report does not query GitHub or run a hosted model. Run the online horizon --check before promotion. "
            "Structural success alone does not establish behavioral correctness."
        ),
        "",
    ]
    for label, issues in checks.items():
        lines.append(f"- {'BLOCKED' if issues else 'PASS'}: {label}")
        lines.extend(f"  - {issue}" for issue in issues)
    return "\n".join(lines) + "\n"
