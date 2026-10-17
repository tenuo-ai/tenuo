import json
import shutil
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.agent_skill_readiness import age_problem, horizon_checks, promotion_checks
from scripts.refresh_agent_skill_horizon import (
    build_snapshot,
    fetch_live,
    normalize,
    render,
    render_frameworks,
)
from scripts.run_agent_skill_frameworks import is_green, junit_counts
from scripts.validate_agent_skills import INTEGRATION_SKILL, ROOT


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


class FrameworkEvidenceTests(unittest.TestCase):
    def test_skips_zero_collection_and_errors_never_count_as_green(self):
        good = {"tests": 7, "failures": 0, "errors": 0, "skipped": 0}
        self.assertTrue(is_green(good, 0))
        for key in ["failures", "errors", "skipped"]:
            self.assertFalse(is_green({**good, key: 1}, 0))
        self.assertFalse(is_green({**good, "tests": 0}, 0))
        self.assertFalse(is_green(good, 1))

    def test_junit_aggregates_all_suites(self):
        with TemporaryDirectory() as directory:
            p = Path(directory) / "report.xml"
            p.write_text(
                '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="0"/><testsuite tests="1" failures="1" errors="0" skipped="0"/></testsuites>'
            )
            self.assertEqual(
                junit_counts(p), {"tests": 3, "failures": 1, "errors": 0, "skipped": 0}
            )
