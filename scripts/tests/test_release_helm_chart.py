import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "chart_release", Path(__file__).resolve().parents[1] / "release_helm_chart.py"
)
chart = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(chart)
DIGEST = "sha256:" + "a" * 64


class ChartReleaseTests(unittest.TestCase):
    def test_only_stable_tags(self):
        for tag in ["main", "v1.2.3-rc.1", "v01.2.3", "v1.2.3\n", "v1.2.3;echo bad"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                chart.version_from_tag(tag)
        self.assertEqual(chart.version_from_tag("v0.3.6"), "0.3.6")

    def test_prerelease_packaging_checks_are_allowed_without_publication(self):
        self.assertEqual(
            chart.version_from_tag("v0.4.0-rc.1", stable_only=False), "0.4.0-rc.1"
        )
        with self.assertRaises(ValueError):
            chart.version_from_tag("v0.4.0-rc.01", stable_only=False)
        with self.assertRaises(ValueError):
            chart.version_from_tag("v0.4.0-rc.1")

    def test_digest_must_be_complete_and_unique(self):
        self.assertEqual(chart.digest_from_output(f"Digest: {DIGEST}\n"), DIGEST)
        for value in [
            "",
            "Digest: sha256:abc",
            f"Digest: {DIGEST}\nDigest: sha256:{'b' * 64}",
        ]:
            with self.assertRaises(ValueError):
                chart.digest_from_output(value)

    def test_chart_versions_must_both_match_release(self):
        for metadata in [
            "version: 0.3.5\nappVersion: 0.3.6\n",
            "version: 0.3.6\nappVersion: 0.3.5\n",
        ]:
            with (
                patch("sys.argv", ["release_helm_chart.py", "--tag", "v0.3.6"]),
                patch.object(chart.Path, "read_text", return_value=metadata),
                patch.object(
                    chart.tomllib,
                    "load",
                    return_value={"package": {"version": "0.3.6"}},
                ),
                patch.object(chart, "run") as command,
            ):
                with self.assertRaises(ValueError):
                    chart.main()
                command.assert_not_called()

    def test_core_version_mismatch_is_rejected_before_helm(self):
        with (
            patch("sys.argv", ["release_helm_chart.py", "--tag", "v0.3.6"]),
            patch.object(
                chart.tomllib, "load", return_value={"package": {"version": "0.3.7"}}
            ),
            patch.object(chart, "run") as command,
        ):
            with self.assertRaisesRegex(ValueError, "Core version"):
                chart.main()
            command.assert_not_called()

    @unittest.skipUnless(
        shutil.which("helm"), "Helm is required for package integration"
    )
    def test_publication_retries_and_public_access(self):
        real_run = subprocess.run
        version = chart.version_from_tag(
            "v"
            + next(
                line.split(":", 1)[1].strip()
                for line in Path("charts/tenuo-authorizer/Chart.yaml")
                .read_text()
                .splitlines()
                if line.startswith("version:")
            )
        )
        for mode in [
            "new",
            "existing",
            "denied",
            "unavailable",
            "private",
            "different",
        ]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                package = output / f"tenuo-authorizer-{version}.tgz"
                pushes = []
                public_pulls = []

                def fake_run(
                    args,
                    *,
                    mode=mode,
                    package=package,
                    pushes=pushes,
                    public_pulls=public_pulls,
                    **kwargs,
                ):
                    args = list(args)
                    result = subprocess.CompletedProcess(args, 0, "", "")
                    if args[:3] == ["docker", "buildx", "imagetools"]:
                        return result
                    if args[:3] == ["helm", "registry", "login"]:
                        self.assertEqual(kwargs["input"], "fake-token")
                        return result
                    if args[:2] == ["helm", "push"]:
                        pushes.append(args)
                        result.stderr = f"Digest: {DIGEST}\n"
                        return result
                    if args[:2] == ["helm", "pull"]:
                        public = "@sha256:" in args[2]
                        if not public and mode in [
                            "new",
                            "private",
                            "denied",
                            "unavailable",
                        ]:
                            result.returncode = 1
                            result.stderr = {
                                "denied": "403 denied",
                                "unavailable": "503 unavailable",
                            }.get(mode, "404 not found")
                            return result
                        if public:
                            public_pulls.append(args)
                            env = kwargs["env"]
                            self.assertFalse(Path(env["HELM_CACHE_HOME"]).exists())
                            self.assertFalse(Path(env["HELM_CONFIG_HOME"]).exists())
                            self.assertEqual(
                                Path(env["HELM_REGISTRY_CONFIG"]).read_text(),
                                '{"auths": {}}',
                            )
                            self.assertEqual(
                                Path(env["DOCKER_CONFIG"], "config.json").read_text(),
                                '{"auths": {}}',
                            )
                            if mode == "private":
                                result.returncode, result.stderr = 1, "401 unauthorized"
                                return result
                        destination = Path(args[args.index("--destination") + 1])
                        shutil.copyfile(package, destination / package.name)
                        result.stderr = f"Digest: {DIGEST}\n"
                        return result
                    return real_run(args, **kwargs)

                real_files = chart.chart_files

                def files(path, mode=mode, real_files=real_files):
                    return (
                        {"different": "contents"}
                        if mode == "different" and "existing" in str(path)
                        else real_files(path)
                    )

                with (
                    patch.dict(
                        os.environ,
                        {
                            "GITHUB_REPOSITORY_OWNER": "tenuo-ai",
                            "GITHUB_ACTOR": "test",
                            "GH_TOKEN": "fake-token",
                            "GITHUB_STEP_SUMMARY": str(Path(tmp) / "test-summary.md"),
                        },
                    ),
                    patch(
                        "sys.argv",
                        [
                            "release_helm_chart.py",
                            "--tag",
                            f"v{version}",
                            "--publish",
                            "--output",
                            str(output),
                        ],
                    ),
                    patch.object(chart.subprocess, "run", side_effect=fake_run),
                    patch.object(chart, "chart_files", side_effect=files),
                ):
                    if mode in ["denied", "unavailable", "private", "different"]:
                        with self.assertRaises((RuntimeError, ValueError)):
                            chart.main()
                        self.assertFalse((output / "chart-reference.txt").exists())
                    else:
                        chart.main()
                        self.assertIn(
                            DIGEST, (output / "chart-reference.txt").read_text()
                        )
                        self.assertEqual(len(public_pulls), 1)
                self.assertEqual(len(pushes), int(mode in ["new", "private"]))


if __name__ == "__main__":
    unittest.main()
