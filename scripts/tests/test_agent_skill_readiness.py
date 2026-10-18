import copy
import json
import shutil
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.agent_skill_readiness import age_problem, framework_case_checks, horizon_checks, promotion_checks
from scripts.refresh_agent_skill_horizon import (
    build_snapshot,
    fetch_live,
    normalize,
    render,
    render_frameworks,
    comparable_snapshot,
    refresh_tree_fingerprint,
)
from scripts.run_agent_skill_frameworks import is_green, junit_counts, matching_native_build, implementation_fingerprint
from scripts.validate_agent_skills import INTEGRATION_SKILL, ROOT, behavioral_eval_fingerprint


def pr(number=1, head="feature", base="main"):
    return {
        "number": number,
        "author": {"login": "d8joseph"},
        "title": "Test",
        "url": f"https://github.com/tenuo-ai/tenuo/pull/{number}",
        "body": "Related #9, not necessarily a dependency.",
        "baseRefName": base,
        "headRefName": head,
        "headRefOid": "a" * 40,
        "files": [{"path": "tenuo-python/tenuo/openai.py"}],
    }


class HorizonTests(unittest.TestCase):
    def review(self, p):
        return {
            str(p["number"]): {
                "source_fingerprint": normalize(p)["source_fingerprint"],
                "category": ["A"],
                "summary": "Authorization change reviewed.",
                "security_relevance": True,
                "api_relevance": False,
                "docs_relevance": False,
            }
        }

    def test_new_or_changed_code_cannot_reuse_review(self):
        p = pr()
        review = self.review(p)
        current = build_snapshot([p], "b" * 40, review, "2026-10-17T00:00:00+00:00")
        self.assertEqual(current["pull_requests"][0]["review_status"], "reviewed")
        for field, value in [
            ("headRefOid", "c" * 40),
            ("body", "New security semantics"),
            ("baseRefName", "different"),
            ("files", [{"path": "other.py"}]),
        ]:
            changed = {**p, field: value}
            item = build_snapshot([changed], "b" * 40, review, current["generated_at"])[
                "pull_requests"
            ][0]
            self.assertEqual(item["review_status"], "pending")
            self.assertEqual(item["review"], {})

    def test_stacks_are_not_flattened_and_mentions_are_not_edges(self):
        parent, child = pr(), pr(2, "leaf", "feature")
        s = build_snapshot([parent, child], "b" * 40, {}, "2026-10-17T00:00:00+00:00")
        self.assertEqual(s["pull_requests"][1]["depends_on"], [1])
        self.assertEqual(s["pull_requests"][1]["mentioned_local_numbers"], [9])
        self.assertEqual(s["pull_requests"][0]["depends_on"], [])

    def test_self_refresh_ignores_only_its_generated_cycle(self):
        entries = [
            {"path": "skills/tenuo-agent-authorization/unreleased.json", "sha": "generated", "type": "blob"},
            {"path": "skills/tenuo-agent-authorization/SKILL.md", "sha": "guidance", "type": "blob"},
            {"path": "scripts/refresh_agent_skill_horizon.py", "sha": "code", "type": "blob"},
        ]
        reviews = {"955": {"source_fingerprint": "self"}, "916": {"summary": "sandbox gap"}}
        first = refresh_tree_fingerprint(entries, reviews, 955)
        entries[0]["sha"] = "new generated output"
        reviews["955"]["source_fingerprint"] = "new self review"
        self.assertEqual(first, refresh_tree_fingerprint(entries, reviews, 955))
        for entry in entries[1:]:
            original = entry["sha"]
            entry["sha"] = "modified"
            self.assertNotEqual(first, refresh_tree_fingerprint(entries, reviews, 955))
            entry["sha"] = original
        reviews["916"]["summary"] = "wrongly removed gap"
        self.assertNotEqual(first, refresh_tree_fingerprint(entries, reviews, 955))

    def test_self_refresh_does_not_exempt_another_pr_or_payload_change(self):
        p = pr()
        p["refresh_identity"] = {"tree_fingerprint": "a" * 64}
        before = build_snapshot([p], "main", {}, "now")
        changed_head = build_snapshot([{**p, "headRefOid": "b" * 40}], "main", {}, "now")
        self.assertEqual(comparable_snapshot(before), comparable_snapshot(changed_head))
        for mutation in (
            {"body": "new API"},
            {"files": [{"path": "new.py"}]},
            {"refresh_identity": {"tree_fingerprint": "c" * 64}},
        ):
            changed = build_snapshot([{**p, **mutation}], "main", {}, "now")
            self.assertNotEqual(comparable_snapshot(before), comparable_snapshot(changed))
        ordinary = pr(2)
        before = build_snapshot([ordinary], "main", {}, "now")
        after = build_snapshot([{**ordinary, "headRefOid": "b" * 40}], "main", {}, "now")
        self.assertNotEqual(comparable_snapshot(before), comparable_snapshot(after))

    def test_human_horizon_is_stable_for_metadata_but_changes_with_hazards(self):
        p = pr(955, "skill/authorization-readiness")
        p["refresh_identity"] = {"tree_fingerprint": "a" * 64}
        snapshot = build_snapshot([p], "main-before", self.review(p), "before")
        baseline = render(snapshot)
        refreshed = copy.deepcopy(snapshot)
        refreshed["generated_at"] = "after"
        refreshed["main_sha"] = "main-after"
        refreshed["main_source_fingerprint"] = "changed-source-review-metadata"
        item = refreshed["pull_requests"][0]
        item["head_sha"] = "captured-after"
        item["refresh_identity"]["tree_fingerprint"] = "b" * 64
        # A reviewed source-only change can retain identical human implications;
        # exact provenance remains in JSON and is validated independently.
        item["source_fingerprint"] = "c" * 64
        item["review"]["source_fingerprint"] = "c" * 64
        self.assertEqual(render(refreshed), baseline)
        for mutation in (
            {"summary": "Known hook bypass; enforce at receiving service."},
            {"category": ["C", "A"]},
            {"merge_notes": "Requires parent-chain fix first."},
        ):
            changed = copy.deepcopy(refreshed)
            changed["pull_requests"][0]["review"].update(mutation)
            self.assertNotEqual(render(changed), baseline)
        changed = copy.deepcopy(refreshed)
        changed["pull_requests"][0]["review"] = {}
        changed["pull_requests"][0]["review_status"] = "pending"
        self.assertIn("PENDING REVIEW", render(changed))
        self.assertNotEqual(render(changed), baseline)
        changed = copy.deepcopy(refreshed)
        changed["pull_requests"][0]["depends_on"] = [916]
        self.assertNotEqual(render(changed), baseline)
        self.assertIn("../unreleased.json", baseline)
        self.assertNotIn("main-before", baseline)
        self.assertNotIn("a" * 64, baseline)

    def test_human_framework_facts_are_stable_for_review_metadata(self):
        status = json.loads((INTEGRATION_SKILL / "framework-status.json").read_text())
        snapshot = build_snapshot([pr()], "main-before", {}, "before")
        baseline = render_frameworks(status, snapshot)
        changed_status = copy.deepcopy(status)
        changed_status["reviewed_main_sha"] = "main-after"
        changed_status["reviewed_main_source_fingerprint"] = "new-fingerprint"
        changed_status["guidance_review"] = {"fingerprint": "new-review"}
        changed_snapshot = copy.deepcopy(snapshot)
        changed_snapshot["generated_at"] = "after"
        changed_snapshot["main_sha"] = "main-after"
        self.assertEqual(render_frameworks(changed_status, changed_snapshot), baseline)
        changed_status["frameworks"][0]["known_bypasses"] = "New bypass found."
        self.assertNotEqual(render_frameworks(changed_status, changed_snapshot), baseline)
        changed_status = copy.deepcopy(status)
        changed_status["reviewed_release_tag"] = "v99.0.0"
        self.assertNotEqual(render_frameworks(changed_status, snapshot), baseline)
        self.assertIn("../framework-status.json", baseline)
        self.assertNotIn(status["reviewed_main_sha"], baseline)

    def test_refresh_cannot_silently_truncate_files(self):
        p = {**pr(), "changedFiles": 2}
        with (
            patch(
                "scripts.refresh_agent_skill_horizon.gh",
                side_effect=[{"sha": "b" * 40}, [p], [[{"filename": "only-one"}]]],
            ),
            self.assertRaisesRegex(ValueError, "incomplete files"),
        ):
            fetch_live()

    def test_refresh_repairs_graphql_file_truncation(self):
        p = {**pr(), "changedFiles": 2}
        with patch(
            "scripts.refresh_agent_skill_horizon.gh",
            side_effect=[
                {"sha": "b" * 40},
                [p],
                [[{"filename": "a"}, {"filename": "b"}]],
                [],
            ],
        ):
            found, _ = fetch_live()
        self.assertEqual([f["path"] for f in found[0]["files"]], ["a", "b"])

    def test_dates_expire_and_future_or_naive_dates_cannot_pass(self):
        now = datetime.now(UTC)
        self.assertIsNone(age_problem(now.isoformat(), now))
        for stamp in [
            (now - timedelta(days=8)).isoformat(),
            (now + timedelta(days=1)).isoformat(),
            "2026-10-17T00:00:00",
            "bad",
        ]:
            self.assertIsNotNone(age_problem(stamp, now))

    def test_snapshot_tampering_and_cycles_are_rejected(self):
        snapshot = json.loads((INTEGRATION_SKILL / "unreleased.json").read_text())
        reviews = json.loads(
            (INTEGRATION_SKILL / "unreleased-reviews.json").read_text()
        )
        status = json.loads((INTEGRATION_SKILL / "framework-status.json").read_text())
        release = json.loads((INTEGRATION_SKILL / "release.json").read_text())
        with TemporaryDirectory() as directory:
            skill = Path(directory)
            shutil.copytree(INTEGRATION_SKILL, skill, dirs_exist_ok=True)

            def write():
                (skill / "unreleased.json").write_text(json.dumps(snapshot))
                (skill / "unreleased-reviews.json").write_text(json.dumps(reviews))
                (skill / "framework-status.json").write_text(json.dumps(status))
                (skill / "references/unreleased.md").write_text(render(snapshot))
                (skill / "references/framework-status.md").write_text(
                    render_frameworks(status, snapshot)
                )

            write()
            errors, _ = horizon_checks(ROOT, skill, release)
            self.assertEqual(errors, [])
            original = (skill / "SKILL.md").read_text()
            (skill / "SKILL.md").write_text(original + "\nChanged recommendation\n")
            _, freshness = horizon_checks(ROOT, skill, release)
            self.assertTrue(
                any("guidance needs review" in issue for issue in freshness)
            )
            (skill / "SKILL.md").write_text(original)
            snapshot["pull_requests"][0]["body"] = "Changed after review"
            write()
            errors, _ = horizon_checks(ROOT, skill, release)
            self.assertTrue(any("fingerprint mismatch" in e for e in errors))
            snapshot["pull_requests"][0]["depends_on"] = [
                snapshot["pull_requests"][0]["number"]
            ]
            write()
            errors, _ = horizon_checks(ROOT, skill, release)
            self.assertTrue(any("cyclic" in e for e in errors))

    def test_structural_success_is_not_promotion(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            checks = promotion_checks(root, root, {}, [])
        self.assertEqual(checks["structural and release contract"], [])
        self.assertTrue(checks["framework regression matrix"])
        self.assertTrue(checks["generic payment-boundary coding-agent eval"])
        self.assertTrue(checks["framework coding-agent eval"])
        self.assertTrue(checks["project onboarding coding-agent eval"])


class FrameworkEvidenceTests(unittest.TestCase):
    def test_skips_zero_collection_and_errors_never_count_as_green(self):
        good = {"tests": 7, "failures": 0, "errors": 0, "skipped": 0}
        self.assertTrue(is_green(good, 0))
        for key in ["failures", "errors", "skipped"]:
            self.assertFalse(is_green({**good, key: 1}, 0))
        self.assertFalse(is_green({**good, "tests": 0}, 0))
        self.assertFalse(is_green(good, 1))

    def test_green_lane_does_not_hide_known_current_framework_failure(self):
        runtime = {"native_sha256": "a" * 64, "packages": {"mcp": "1.30.0"}}
        run = {
            "suite": "openai", "lane": "working-version",
            "implementation_fingerprint": "source", "harness_fingerprint": "harness",
            "runtime": runtime, "generated_at": datetime.now(UTC).isoformat(),
            "counts": {"tests": 7, "failures": 0, "errors": 0, "skipped": 0},
            "returncode": 0, "result": "pass",
            "native_build": {"result": "pass", "implementation_fingerprint": "source",
                             "native_sha256": "a" * 64, "command": ["build"], "generated_at": "today"},
        }
        with TemporaryDirectory() as directory, patch(
            "scripts.agent_skill_readiness.horizon_checks", return_value=([], [])
        ), patch("scripts.agent_skill_readiness.implementation_fingerprint", return_value="source"), patch(
            "scripts.agent_skill_readiness.harness_fingerprint", return_value="harness"
        ):
            root = Path(directory)
            evidence = root / "tests/agent-skills/tenuo-agent-authorization"
            evidence.mkdir(parents=True)
            path = evidence / "framework-regression-results.json"
            path.write_text(json.dumps({"runs": [run]}))
            checks = promotion_checks(root, INTEGRATION_SKILL, {}, [])
            self.assertFalse(any("openai" in issue for issue in checks["framework regression matrix"]))
            path.write_text(json.dumps({"runs": [run, {
                **run, "lane": "broken-version", "returncode": 1, "result": "fail",
            }]}))
            checks = promotion_checks(root, INTEGRATION_SKILL, {}, [])
            self.assertTrue(any("broken-version failed" in issue for issue in checks["framework regression matrix"]))

    def test_native_binding_and_lock_changes_invalidate_source_evidence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("tenuo-python/pyproject.toml", "tenuo-python/Cargo.toml",
                         "tenuo-core/Cargo.toml", "tenuo-python/src/lib.rs",
                         "tenuo-python/Cargo.lock"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("original")
            original = implementation_fingerprint(root)
            for name in ("tenuo-python/src/lib.rs", "tenuo-python/Cargo.lock"):
                path = root / name
                path.write_text("changed")
                self.assertNotEqual(implementation_fingerprint(root), original)
                path.write_text("original")

    def test_editable_url_or_stale_native_build_is_not_provenance(self):
        runtime = {"native_sha256": "a" * 64}
        build = {
            "result": "pass", "implementation_fingerprint": "source",
            "native_sha256": "a" * 64, "command": ["python", "-m", "pip", "install"],
            "generated_at": datetime.now(UTC).isoformat(),
        }
        self.assertTrue(matching_native_build(build, "source", runtime))
        self.assertFalse(matching_native_build(None, "source", runtime))
        self.assertFalse(matching_native_build(build, "changed source", runtime))
        self.assertFalse(matching_native_build(build, "source", {"native_sha256": "b" * 64}))

    def test_aggregate_framework_pass_cannot_hide_missing_stale_or_escaped_cases(self):
        names = ("openai", "langgraph", "temporal", "mcp1", "mcp2")
        inputs = ["SKILL.md", "references/python.md"]
        case = {
            "language": "python", "result": "pass", "evidence_kind": "fresh",
            "inputs": inputs,
            "skill_fingerprint": behavioral_eval_fingerprint(inputs),
            "evidence": {"critical_items": "passed", "required_reporting": "passed"},
            "artifacts": ["report.md"],
        }
        with TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / "report.md").write_text("Preserved independent review")
            result = {"result": "pass", "cases": {name: dict(case) for name in names}}
            self.assertEqual(framework_case_checks(result, evidence, INTEGRATION_SKILL), [])
            del result["cases"]["mcp2"]
            self.assertIn("mcp2", str(framework_case_checks(result, evidence, INTEGRATION_SKILL)))
            result["cases"]["mcp2"] = {**case, "skill_fingerprint": "0" * 64}
            self.assertIn("mcp2", str(framework_case_checks(result, evidence, INTEGRATION_SKILL)))
            result["cases"]["mcp2"] = {**case, "artifacts": ["../outside.md"]}
            self.assertIn("non-contained", str(framework_case_checks(result, evidence, INTEGRATION_SKILL)))
            result["cases"]["mcp2"] = {**case, "artifacts": ["missing.md"]}
            self.assertIn("missing", str(framework_case_checks(result, evidence, INTEGRATION_SKILL)))

    def test_junit_aggregates_all_suites(self):
        with TemporaryDirectory() as directory:
            p = Path(directory) / "report.xml"
            p.write_text(
                '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0"/><testsuite tests="1" failures="1" errors="0" skipped="0"/></testsuites>'
            )
            self.assertEqual(
                junit_counts(p), {"tests": 3, "failures": 1, "errors": 0, "skipped": 0}
            )
