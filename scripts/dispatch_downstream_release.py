#!/usr/bin/env python3
"""Notify a configured downstream controller after a stable release succeeds."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
PUBLISHERS = {"Release", "Authorizer Binaries"}


def api(path, payload=None):
    command = ["gh", "api", "--method", "POST" if payload is not None else "GET", path]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(
        command,
        input=json.dumps(payload) if payload is not None else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"GitHub request failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def prepare(source, event_name, event, manual_tag=""):
    if not REPOSITORY.fullmatch(source):
        raise ValueError("invalid source repository")
    run = None
    if event_name == "workflow_run":
        run = event["workflow_run"]
        if (
            run["conclusion"] != "success"
            or run["event"] != "release"
            or run["name"] not in PUBLISHERS
            or run["head_repository"]["full_name"] != source
        ):
            return None
        tag = run["head_branch"]
    elif event_name == "workflow_dispatch":
        tag = manual_tag or api(f"repos/{source}/releases/latest")["tag_name"]
    else:
        raise ValueError("unsupported event")
    if not TAG.fullmatch(tag):
        if run is not None:
            return None
        raise ValueError("release tag must be a stable vX.Y.Z tag")
    release = api(f"repos/{source}/releases/tags/{tag}")
    if release["draft"] or release["prerelease"]:
        return None
    ref = api(f"repos/{source}/git/ref/tags/{tag}")["object"]
    for _ in range(5):
        if ref["type"] == "commit":
            break
        if ref["type"] != "tag":
            raise ValueError("release tag must point to a commit")
        ref = api(f"repos/{source}/git/tags/{ref['sha']}")["object"]
    else:
        raise ValueError("release tag nesting limit exceeded")
    if not SHA.fullmatch(ref["sha"]):
        raise ValueError("invalid source commit")
    if run is not None and run["head_sha"] != ref["sha"]:
        raise ValueError("publisher commit does not match the immutable release tag")
    if run is not None and run["name"] == "Authorizer Binaries":
        publishers = api(
            f"repos/{source}/actions/workflows/release.yml/runs?head_sha={ref['sha']}&per_page=30"
        )
        if not any(
            publisher["head_sha"] == ref["sha"] and publisher["conclusion"] == "success"
            for publisher in publishers["workflow_runs"]
        ):
            return None
    return {"source_repository": source, "tag": tag, "source_sha": ref["sha"]}


def dispatch(source, controller, tag, sha):
    if not REPOSITORY.fullmatch(source) or not REPOSITORY.fullmatch(controller):
        raise ValueError("invalid source or controller repository")
    if source.split("/")[0] != controller.split("/")[0] or source == controller:
        raise ValueError(
            "controller must be a different repository in the source organization"
        )
    if not TAG.fullmatch(tag) or not SHA.fullmatch(sha):
        raise ValueError("invalid release coordinates")
    api(
        f"repos/{controller}/dispatches",
        {
            "event_type": "tenuo-release",
            "client_payload": {
                "source_repository": source,
                "tag": tag,
                "source_sha": sha,
            },
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "dispatch"])
    parser.add_argument("--tag", default="")
    parser.add_argument("--sha", default="")
    parser.add_argument("--controller", default="")
    args = parser.parse_args()
    source = os.environ["GITHUB_REPOSITORY"]
    if (
        not REPOSITORY.fullmatch(args.controller)
        or args.controller.split("/")[0] != source.split("/")[0]
        or args.controller == source
    ):
        raise ValueError(
            "configure a different controller repository in the source organization"
        )
    if args.command == "dispatch":
        dispatch(source, args.controller, args.tag, args.sha)
        print(f"Downstream update event sent for {args.tag}.")
        return
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    result = prepare(source, os.environ["GITHUB_EVENT_NAME"], event, args.tag)
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write("eligible=" + ("true" if result else "false") + "\n")
        if result:
            stream.write(f"tag={result['tag']}\nsha={result['source_sha']}\n")
    print(
        f"Stable release ready: {result['tag']}"
        if result
        else "No eligible stable release to propagate."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError) as error:
        raise SystemExit(str(error)) from None
