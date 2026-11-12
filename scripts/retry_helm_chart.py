"""Retry only a failed chart job after every other release job succeeds."""

import argparse
import json
import os
import subprocess
from urllib.parse import quote

from release_helm_chart import version_from_tag


def api(path, method="GET"):
    result = subprocess.run(
        ["gh", "api", "--method", method, path],
        check=True,
        text=True,
        capture_output=True,
    )
    return json.loads(result.stdout) if result.stdout.strip() else None


def retryable_chart_job(jobs):
    required = {
        "Publish to crates.io",
        "Publish to PyPI",
        "Publish TypeScript packages to npm",
        "Docker Authorizer (manifest)",
        "Docker Control (manifest)",
    }
    if not required.issubset({job["name"] for job in jobs}):
        raise ValueError("Release publisher jobs are missing")
    charts = [j for j in jobs if j["name"] == "Publish Helm chart / publish"]
    if len(charts) != 1 or charts[0]["conclusion"] != "failure":
        raise ValueError("Expected exactly one failed chart publisher job")
    if any(j["conclusion"] != "success" for j in jobs if j is not charts[0]):
        raise ValueError("All other release jobs must succeed before chart-only retry")
    return charts[0]["id"]


def retry(repository, tag):
    version_from_tag(tag)
    release = api(f"repos/{repository}/releases/tags/{quote(tag, safe='')}")
    if release["draft"] or release["prerelease"] or release["tag_name"] != tag:
        raise ValueError("Expected the published stable release")
    ref = api(f"repos/{repository}/git/ref/tags/{quote(tag, safe='')}")["object"]
    while ref["type"] == "tag":
        ref = api(f"repos/{repository}/git/tags/{ref['sha']}")["object"]
    if ref["type"] != "commit":
        raise ValueError("Release tag must resolve to a commit")
    runs = api(
        f"repos/{repository}/actions/workflows/release.yml/runs?event=release&head_sha={ref['sha']}&per_page=100"
    )["workflow_runs"]
    runs = [
        r
        for r in runs
        if r["event"] == "release"
        and r["head_sha"] == ref["sha"]
        and r["head_repository"]["full_name"] == repository
        and r["head_branch"] == tag
    ]
    if not runs:
        raise ValueError("No original Release run exists for this tag and commit")
    latest = max(runs, key=lambda r: r["id"])
    if latest["status"] != "completed" or latest["conclusion"] != "failure":
        raise ValueError("Latest original Release run must be completed and failed")
    jobs = []
    page = 1
    while True:
        batch = api(
            f"repos/{repository}/actions/runs/{latest['id']}/jobs?filter=latest&per_page=100&page={page}"
        )["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    job_id = retryable_chart_job(jobs)
    api(f"repos/{repository}/actions/jobs/{job_id}/rerun", method="POST")
    return latest["html_url"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    print("Retry requested:", retry(os.environ["GITHUB_REPOSITORY"], args.tag))
