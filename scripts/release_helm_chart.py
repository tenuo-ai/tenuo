"""Package, validate, and optionally publish the authorizer chart."""

import argparse
import hashlib
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


def run(*args, env=None, input=None):
    result = subprocess.run(
        args, check=False, text=True, capture_output=True, env=env, input=input
    )
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr}")
    return result


def version_from_tag(tag):
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if not match:
        raise ValueError("Expected a stable release tag vX.Y.Z")
    return tag[1:]


def chart_files(package):
    files = {}
    with tarfile.open(package, "r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile() or member.name in files:
                raise ValueError("Chart archive contains unexpected members")
            files[member.name] = hashlib.sha256(
                archive.extractfile(member).read()
            ).hexdigest()
    return files


def digest_from_output(output):
    matches = re.findall(r"^Digest:\s+(sha256:[0-9a-f]{64})\s*$", output, re.MULTILINE)
    if len(set(matches)) != 1:
        raise ValueError("Registry did not report a unique chart digest")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("helm-release"))
    args = parser.parse_args()
    version = version_from_tag(args.tag)
    chart = Path("charts/tenuo-authorizer")
    metadata = (chart / "Chart.yaml").read_text()
    for field in ["version", "appVersion"]:
        match = re.search(
            rf'^{field}:\s*["\']?([^\s"\']+)["\']?\s*$', metadata, re.MULTILINE
        )
        if not match or match[1] != version:
            raise ValueError(f"Chart {field} must match {args.tag}")
    run("helm", "lint", "--strict", str(chart))
    args.output.mkdir(parents=True, exist_ok=True)
    run("helm", "package", str(chart), "--destination", str(args.output))
    package = args.output / f"tenuo-authorizer-{version}.tgz"
    rendered = run("helm", "template", "release-smoke", str(package)).stdout
    if f'image: "tenuo/authorizer:{version}"' not in rendered:
        raise ValueError("Packaged chart must use the released authorizer image")
    (args.output / "rendered.yaml").write_text(rendered)
    if not args.publish:
        print(f"Chart {version}: lint, package, and render passed")
        return
    owner = os.environ["GITHUB_REPOSITORY_OWNER"].lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", owner):
        raise ValueError("Invalid registry owner")
    repository = f"oci://ghcr.io/{owner}/charts"
    reference = f"{repository}/tenuo-authorizer"
    # Verify image publication independently, including manual chart-only retries.
    run("docker", "buildx", "imagetools", "inspect", f"tenuo/authorizer:{version}")
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, HELM_REGISTRY_CONFIG=f"{tmp}/credentials.json")
        run(
            "helm",
            "registry",
            "login",
            "ghcr.io",
            "--username",
            os.environ["GITHUB_ACTOR"],
            "--password-stdin",
            input=os.environ["GH_TOKEN"],
            env=env,
        )
        existing = Path(tmp) / "existing"
        existing.mkdir()
        probe = subprocess.run(
            [
                "helm",
                "pull",
                reference,
                "--version",
                version,
                "--destination",
                str(existing),
            ],
            check=False,
            text=True,
            capture_output=True,
            env=env,
        )
        if probe.returncode == 0:
            if chart_files(existing / package.name) != chart_files(package):
                raise ValueError(
                    "Published chart differs from this release; refusing to overwrite"
                )
            digest = digest_from_output(probe.stdout + probe.stderr)
        else:
            error = probe.stdout + probe.stderr
            if not re.search(
                r"(?i)(404|manifest_unknown|: not found)", error
            ) or re.search(r"(?i)(401|403|unauthorized|denied)", error):
                raise RuntimeError(
                    "Could not check existing chart publication: " + error
                )
            pushed = run("helm", "push", str(package), repository, env=env)
            digest = digest_from_output(pushed.stdout + pushed.stderr)
        immutable = f"{reference}@{digest}"
        # Use empty Helm and Docker credential stores to prove public installability.
        public = Path(tmp) / "public"
        public.mkdir()
        public_env = dict(
            os.environ,
            HELM_REGISTRY_CONFIG=f"{public}/credentials.json",
            DOCKER_CONFIG=str(public),
        )
        (public / "credentials.json").write_text('{"auths": {}}')
        (public / "config.json").write_text('{"auths": {}}')
        run("helm", "pull", immutable, "--destination", str(public), env=public_env)
        if chart_files(public / package.name) != chart_files(package):
            raise ValueError("Public chart does not match the packaged release")
        run(
            "helm",
            "template",
            "release-smoke",
            str(public / package.name),
            env=public_env,
        )
    record = f"Helm chart: {immutable}\nAuthorizer image: tenuo/authorizer:{version}\n"
    (args.output / "chart-reference.txt").write_text(record)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(f"### Published Helm chart\n\n```text\n{record}```\n")
    print(record)


if __name__ == "__main__":
    main()
