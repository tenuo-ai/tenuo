import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
    SPEC = importlib.util.spec_from_file_location(
        "retry_chart", SCRIPTS / "retry_helm_chart.py"
    )
    retry_chart = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(retry_chart)


PUBLISHERS = [
    "Publish to crates.io",
    "Publish to PyPI",
    "Publish TypeScript packages to npm",
    "Docker Authorizer (manifest)",
    "Docker Control (manifest)",
]


class RetryChartTests(unittest.TestCase):
    def test_only_chart_failure_is_retryable(self):
        good = [
            {"name": name, "conclusion": "success", "id": i + 20}
            for i, name in enumerate(PUBLISHERS)
        ] + [{"name": "Publish Helm chart / publish", "conclusion": "failure", "id": 2}]
        self.assertEqual(retry_chart.retryable_chart_job(good), 2)
        for jobs in [
            [],
            good[:-1],
            [*good, good[-1]],
            good[1:],
            [{**good[0], "conclusion": "failure"}, *good[1:]],
            [{**good[0], "conclusion": "cancelled"}, *good[1:]],
            [{**good[0], "conclusion": "skipped"}, *good[1:]],
            [*good[:-1], {**good[-1], "conclusion": "success"}],
        ]:
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                retry_chart.retryable_chart_job(jobs)

    def mock_api(self, path, method="GET"):
        if method == "POST":
            self.assertEqual(path, "repos/tenuo-ai/tenuo/actions/jobs/12/rerun")
            return None
        if "/releases/tags/" in path:
            return {"draft": False, "prerelease": False, "tag_name": "v0.3.6"}
        if "/git/ref/" in path:
            return {"object": {"type": "tag", "sha": "b" * 40}}
        if "/git/tags/" in path:
            return {"object": {"type": "commit", "sha": "a" * 40}}
        if "/jobs?" in path:
            return {
                "jobs": [
                    *[
                        {"id": i + 20, "name": name, "conclusion": "success"}
                        for i, name in enumerate(PUBLISHERS)
                    ],
                    {
                        "id": 12,
                        "name": "Publish Helm chart / publish",
                        "conclusion": "failure",
                    },
                ]
            }
        return {"workflow_runs": [self.run]}

    def setUp(self):
        self.run = {
            "id": 4,
            "head_sha": "a" * 40,
            "head_branch": "v0.3.6",
            "event": "release",
            "head_repository": {"full_name": "tenuo-ai/tenuo"},
            "status": "completed",
            "conclusion": "failure",
            "html_url": "https://github.com/tenuo-ai/tenuo/actions/runs/4",
        }

    def test_retry_uses_original_release_commit_and_only_failed_chart(self):
        with patch.object(retry_chart, "api", side_effect=self.mock_api) as api:
            self.assertEqual(
                retry_chart.retry("tenuo-ai/tenuo", "v0.3.6"), self.run["html_url"]
            )
            posts = [c for c in api.call_args_list if c.kwargs.get("method") == "POST"]
            self.assertEqual(len(posts), 1)

    def test_tag_move_after_readiness_cannot_rerun(self):
        with (
            patch.object(retry_chart, "api", side_effect=self.mock_api) as api,
            patch.object(
                retry_chart, "release_commit", side_effect=["a" * 40, "b" * 40]
            ),
        ):
            with self.assertRaisesRegex(ValueError, "tag moved"):
                retry_chart.retry("tenuo-ai/tenuo", "v0.3.6")
            self.assertFalse(
                any(c.kwargs.get("method") == "POST" for c in api.call_args_list)
            )

    def test_wrong_commit_event_repository_and_incomplete_runs_are_refused(self):
        for change in [
            {"head_sha": "b" * 40},
            {"event": "workflow_dispatch"},
            {"head_branch": "v0.3.5"},
            {"head_repository": {"full_name": "other/fork"}},
            {"status": "in_progress"},
            {"conclusion": "success"},
        ]:
            with (
                self.subTest(change=change),
                patch.object(retry_chart, "api", side_effect=self.mock_api) as api,
            ):
                self.run.update(change)
                with self.assertRaises(ValueError):
                    retry_chart.retry("tenuo-ai/tenuo", "v0.3.6")
                self.assertFalse(
                    any(c.kwargs.get("method") == "POST" for c in api.call_args_list)
                )
                self.setUp()


if __name__ == "__main__":
    unittest.main()
