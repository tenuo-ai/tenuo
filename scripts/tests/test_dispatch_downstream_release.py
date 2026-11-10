import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "downstream", Path(__file__).resolve().parents[1] / "dispatch_downstream_release.py"
)
downstream = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(downstream)


class DownstreamReleaseTests(unittest.TestCase):
    def setUp(self):
        self.run = {
            "conclusion": "success",
            "event": "release",
            "name": "Release",
            "head_repository": {"full_name": "tenuo-ai/tenuo"},
            "head_branch": "v0.3.6",
            "head_sha": "a" * 40,
        }

    def mock_api(self, path):
        if "/actions/workflows/release.yml/" in path:
            return {"workflow_runs": [self.run]}
        if "/git/ref/" in path:
            return {"object": {"type": "tag", "sha": "b" * 40}}
        if "/git/tags/" in path:
            return {"object": {"type": "commit", "sha": "a" * 40}}
        return {"tag_name": "v0.3.6", "draft": False, "prerelease": False}

    def test_successful_publisher_is_bound_to_the_release_commit(self):
        with patch.object(downstream, "api", side_effect=self.mock_api):
            result = downstream.prepare(
                "tenuo-ai/tenuo", "workflow_run", {"workflow_run": self.run}
            )
        self.assertEqual(result["tag"], "v0.3.6")
        self.assertEqual(result["source_sha"], "a" * 40)

    def test_failures_forks_manual_builds_and_unrelated_workflows_are_ignored(self):
        for change in [
            {"conclusion": "failure"},
            {"event": "pull_request"},
            {"event": "workflow_dispatch"},
            {"name": "CI"},
            {"head_repository": {"full_name": "other/fork"}},
            {"head_branch": "v0.4.0-rc.1"},
        ]:
            with self.subTest(change=change), patch.object(downstream, "api") as api:
                self.assertIsNone(
                    downstream.prepare(
                        "tenuo-ai/tenuo",
                        "workflow_run",
                        {"workflow_run": {**self.run, **change}},
                    )
                )
                api.assert_not_called()

    def test_moved_tags_cannot_substitute_a_different_source_commit(self):
        with (
            patch.object(downstream, "api", side_effect=self.mock_api),
            self.assertRaises(ValueError),
        ):
            downstream.prepare(
                "tenuo-ai/tenuo",
                "workflow_run",
                {"workflow_run": {**self.run, "head_sha": "c" * 40}},
            )

    def test_manual_replay_resolves_latest_and_rejects_shell_input(self):
        with patch.object(downstream, "api", side_effect=self.mock_api):
            self.assertEqual(
                downstream.prepare("tenuo-ai/tenuo", "workflow_dispatch", {})["tag"],
                "v0.3.6",
            )
            with self.assertRaises(ValueError):
                downstream.prepare(
                    "tenuo-ai/tenuo", "workflow_dispatch", {}, "v0.3.6; echo injected"
                )

    def test_draft_and_prerelease_metadata_are_not_propagated(self):
        for field in ["draft", "prerelease"]:
            with patch.object(
                downstream,
                "api",
                return_value={"draft": False, "prerelease": False, field: True},
            ):
                self.assertIsNone(
                    downstream.prepare(
                        "tenuo-ai/tenuo", "workflow_run", {"workflow_run": self.run}
                    )
                )

    def test_dispatch_uses_a_structured_payload_and_only_the_same_organization(self):
        with patch.object(downstream, "api") as api:
            downstream.dispatch(
                "tenuo-ai/tenuo", "tenuo-ai/controller", "v0.3.6", "a" * 40
            )
            path, payload = api.call_args.args
            self.assertEqual(path, "repos/tenuo-ai/controller/dispatches")
            self.assertEqual(payload["event_type"], "tenuo-release")
            with self.assertRaises(ValueError):
                downstream.dispatch(
                    "tenuo-ai/tenuo", "other/controller", "v0.3.6", "a" * 40
                )

    def test_binaries_wait_for_the_package_publisher_to_succeed(self):
        def pending(path):
            if "/actions/workflows/release.yml/" in path:
                return {"workflow_runs": [{"head_sha": "a" * 40, "conclusion": None}]}
            return self.mock_api(path)

        with patch.object(downstream, "api", side_effect=pending):
            self.assertIsNone(
                downstream.prepare(
                    "tenuo-ai/tenuo",
                    "workflow_run",
                    {"workflow_run": {**self.run, "name": "Authorizer Binaries"}},
                )
            )

    def test_successful_manual_runs_and_other_tags_do_not_prove_publication(self):
        for change in [
            {"event": "workflow_dispatch"},
            {"head_branch": "v0.3.5"},
            {"conclusion": "failure"},
        ]:

            def incomplete(path, change=change):
                if "/actions/workflows/release.yml/" in path:
                    return {"workflow_runs": [{**self.run, **change}]}
                return self.mock_api(path)

            with (
                self.subTest(change=change),
                patch.object(downstream, "api", side_effect=incomplete),
            ):
                self.assertIsNone(
                    downstream.prepare(
                        "tenuo-ai/tenuo",
                        "workflow_run",
                        {"workflow_run": {**self.run, "name": "Authorizer Binaries"}},
                    )
                )
                self.assertIsNone(
                    downstream.prepare(
                        "tenuo-ai/tenuo", "workflow_dispatch", {}, "v0.3.6"
                    )
                )


if __name__ == "__main__":
    unittest.main()
