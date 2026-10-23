"""tenuo.process: the warrant check covers exactly the process that runs."""

import os
import shutil
import subprocess

import pytest

from tenuo import OneOf, SigningKey, Subpath, Subset, Warrant
from tenuo.exceptions import AuthorizationDenied
from tenuo.process import GIT, Program, run, run_command

pytestmark = pytest.mark.skipif(os.name != "posix" or shutil.which("git") is None, reason="POSIX with git only")

ROOT, AGENT, REVIEWER = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args], check=True)


@pytest.fixture
def repo(tmp_path):
    repo = (tmp_path / "repo").resolve()
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app.py").write_text("print('hi')\n")
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def capability(repo, subcommands=("status", "diff", "log", "add", "commit")):
    return dict(
        subcommand=OneOf(list(subcommands)),
        flags=Subset(["--short", "--stat", "--oneline"]),
        paths=Subset([".", "app.py"]),
        cwd=Subpath(str(repo)),
    )


@pytest.fixture
def warrant(repo):
    return Warrant.mint_builder().capability("git", **capability(repo)).holder(AGENT.public_key).ttl(600).mint(ROOT)


def git_run(warrant, repo, key=AGENT, **call):
    call.setdefault("cwd", str(repo))
    return run(warrant.bind(key), GIT, trusted_roots=[ROOT.public_key], **call)


def test_allowed_call_runs(warrant, repo):
    (repo / "app.py").write_text("print('bye')\n")
    out = git_run(warrant, repo, subcommand="status", flags=["--short"])
    assert out.returncode == 0
    assert out.stdout.decode().strip() == "M app.py"
    assert git_run(warrant, repo, subcommand="log", flags=["--oneline"]).stdout.decode().endswith("init\n")


@pytest.mark.parametrize(
    "call",
    [
        dict(subcommand="push"),
        dict(subcommand="reset", flags=["--hard"]),
        dict(subcommand="diff", flags=["--output=/tmp/x"]),
        dict(subcommand="diff", paths=["/etc/passwd"]),
        dict(subcommand="status", cwd="/"),
    ],
)
def test_calls_outside_the_warrant_are_denied(warrant, repo, call):
    with pytest.raises(AuthorizationDenied):
        git_run(warrant, repo, **call)


def test_cwd_is_checked_after_resolving_symlinks(warrant, repo):
    (repo / "escape").symlink_to("/")
    with pytest.raises(AuthorizationDenied):
        git_run(warrant, repo, subcommand="status", cwd=str(repo / "escape"))


@pytest.mark.parametrize(
    "call",
    [
        dict(subcommand="diff", paths=["--output=/tmp/x"]),
        dict(subcommand="status", flags=["status"]),
        dict(subcommand="--version"),
        dict(subcommand=None),
    ],
)
def test_malformed_requests_are_denied(warrant, repo, call):
    with pytest.raises(AuthorizationDenied):
        git_run(warrant, repo, **call)


def test_wrong_holder_cannot_run(warrant, repo):
    with pytest.raises(Exception):
        git_run(warrant, repo, key=REVIEWER, subcommand="status")


def test_delegated_warrant_is_narrower_and_cannot_widen(warrant, repo):
    child = (
        warrant.grant_builder()
        .capability("git", **capability(repo, subcommands=("status", "diff")))
        .holder(REVIEWER.public_key)
        .ttl(300)
        .grant(AGENT)
    )
    out = run(
        child.bind(REVIEWER),
        GIT,
        cwd=str(repo),
        subcommand="diff",
        flags=["--stat"],
        trusted_roots=[ROOT.public_key],
        warrant_chain=[warrant],
    )
    assert out.returncode == 0
    with pytest.raises(AuthorizationDenied):
        run(
            child.bind(REVIEWER),
            GIT,
            cwd=str(repo),
            subcommand="commit",
            trusted_roots=[ROOT.public_key],
            warrant_chain=[warrant],
        )
    with pytest.raises(Exception):
        child.grant_builder().capability("git", **capability(repo)).holder(AGENT.public_key).grant(REVIEWER)


@pytest.mark.parametrize(
    "command",
    [
        "git status && rm -rf ~",
        "git status; touch pwned",
        "git log {--output=pwned,-1}",
        "git -c core.pager=sh log",
        "bash -c 'git status'",
        "git status 'unclosed",
        "git push origin main",
    ],
)
def test_command_strings_never_reach_a_shell(warrant, repo, command):
    with pytest.raises(AuthorizationDenied):
        run_command(warrant.bind(AGENT), GIT, command, cwd=str(repo), trusted_roots=[ROOT.public_key])
    assert not (repo / "pwned").exists()


def test_command_string_runs_the_parsed_call(warrant, repo):
    out = run_command(
        warrant.bind(AGENT), GIT, "git log --oneline -- app.py", cwd=str(repo), trusted_roots=[ROOT.public_key]
    )
    assert out.returncode == 0 and out.stdout.decode().endswith("init\n")


def test_repository_config_cannot_run_programs(warrant, repo):
    marker = repo.parent / "ran"
    git(repo, "config", "core.fsmonitor", f"touch {marker}.fsmonitor; false")
    git(repo, "config", "core.pager", f"touch {marker}.pager; cat")
    git(repo, "config", "diff.x.textconv", f"touch {marker}.textconv; cat")
    git(repo, "config", "filter.y.clean", f"touch {marker}.clean; cat")
    (repo / ".gitattributes").write_text("*.py diff=x filter=y\n")
    (repo / "app.py").write_text("print('changed')\n")

    for subcommand in ("status", "diff", "log"):
        assert git_run(warrant, repo, subcommand=subcommand).returncode == 0
    assert sorted(p.name for p in repo.parent.glob("ran.*")) == []

    # Control: the same repository runs the planted fsmonitor under a plain git call.
    subprocess.run(["git", "status"], cwd=repo, capture_output=True, check=False)
    assert (repo.parent / "ran.fsmonitor").exists()


def test_program_without_subcommands(tmp_path):
    (tmp_path / "a.txt").write_text("")
    ls = Program(name="ls")
    w = (
        Warrant.mint_builder()
        .capability("ls", flags=Subset(["-1"]), paths=Subset(["a.txt", "-rf"]), cwd=Subpath(str(tmp_path)))
        .holder(AGENT.public_key)
        .ttl(60)
        .mint(ROOT)
    )
    out = run(w.bind(AGENT), ls, cwd=str(tmp_path), flags=["-1"], paths=["a.txt"], trusted_roots=[ROOT.public_key])
    assert out.stdout.decode() == "a.txt\n"
    with pytest.raises(AuthorizationDenied):
        run(w.bind(AGENT), ls, cwd=str(tmp_path), subcommand="x", trusted_roots=[ROOT.public_key])
    with pytest.raises(AuthorizationDenied):
        run(w.bind(AGENT), ls, cwd=str(tmp_path), paths=["-rf"], trusted_roots=[ROOT.public_key])
