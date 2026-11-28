"""tenuo.process: the warrant check covers exactly the process that runs."""

import os
import shutil
import subprocess
from dataclasses import replace
from unittest.mock import patch

import pytest

from tenuo import OneOf, SigningKey, Subpath, Subset, Warrant
from tenuo.approval import ApprovalRequest, sign_approval
from tenuo_core import py_compute_request_hash
from tenuo.exceptions import AuthorizationDenied, ConfigurationError
from tenuo.process import GIT, Program, run, run_command

pytestmark = pytest.mark.skipif(os.name != "posix" or shutil.which("git") is None, reason="POSIX with git only")

ROOT, AGENT, REVIEWER = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args], check=True)


@pytest.fixture(params=["sha1", "sha256"])
def repo(tmp_path, request):
    repo = (tmp_path / "repo").resolve()
    repo.mkdir()
    git(repo, "init", "-q", f"--object-format={request.param}")
    (repo / "app.py").write_text("print('hi')\n")
    git(repo, "add", "app.py")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def capability(repo, subcommands=("status", "diff", "log", "add", "commit"), paths=None):
    return dict(
        subcommand=OneOf(list(subcommands)),
        flags=Subset(["--short", "--stat", "--oneline"]),
        paths=paths if paths is not None else Subpath(str(repo)),
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


@pytest.mark.parametrize("command_string", [False, True])
def test_approval_is_verified_for_the_exact_resolved_call(repo, command_string):
    approver = SigningKey.generate()
    gated = Warrant.issue(
        keypair=ROOT,
        capabilities={"git": capability(repo)},
        holder=AGENT.public_key,
        ttl_seconds=600,
        approval_gates={"git": None},
        required_approvers=[approver.public_key],
        min_approvals=1,
    )
    args = {"subcommand": "status", "flags": ["--short"], "paths": [str(repo)], "cwd": str(repo)}
    request = ApprovalRequest(
        tool="git",
        arguments=args,
        warrant_id=gated.id,
        request_hash=py_compute_request_hash(gated.id, "git", args, AGENT.public_key),
    )
    signed = sign_approval(request, approver)

    def call(approvals, flags=("--short",)):
        options = dict(cwd=str(repo), trusted_roots=[ROOT.public_key], approvals=approvals)
        if command_string:
            return run_command(gated.bind(AGENT), GIT, "git status " + " ".join(flags), **options)
        return run(gated.bind(AGENT), GIT, subcommand="status", flags=flags, **options)

    with pytest.raises(AuthorizationDenied):
        call(None)
    assert call([signed]).returncode == 0
    with pytest.raises(AuthorizationDenied):
        call([signed], flags=())


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


def test_paths_are_checked_after_resolving_symlinks(warrant, repo):
    outside = repo.parent / "secret.txt"
    outside.write_text("secret\n")
    (repo / "leak.py").symlink_to(outside)
    with pytest.raises(AuthorizationDenied):
        git_run(warrant, repo, subcommand="diff", paths=["leak.py"])
    with pytest.raises(AuthorizationDenied):
        git_run(warrant, repo, subcommand="diff", paths=["../secret.txt"])


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
        .capability(
            "git",
            **capability(
                repo,
                subcommands=("status", "diff"),
                paths=Subset([str(repo / "app.py")]),
            ),
        )
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
        paths=["app.py"],
        trusted_roots=[ROOT.public_key],
        warrant_chain=[warrant],
    )
    assert out.returncode == 0
    # Omitting `paths` defaults to `"."` (`[str(repo)]`), which is outside the narrowed Subset.
    with pytest.raises(AuthorizationDenied):
        run(
            child.bind(REVIEWER),
            GIT,
            cwd=str(repo),
            subcommand="diff",
            trusted_roots=[ROOT.public_key],
            warrant_chain=[warrant],
        )
    with pytest.raises(AuthorizationDenied):
        run(
            child.bind(REVIEWER),
            GIT,
            cwd=str(repo),
            subcommand="diff",
            paths=["other.py"],
            trusted_roots=[ROOT.public_key],
            warrant_chain=[warrant],
        )
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
    alt_attr = repo / "alt.attributes"
    alt_attr.write_text("*.py diff=x filter=y\n")
    gpg_helper = repo.parent / "gpg_helper.sh"
    gpg_helper.write_text(f"#!/bin/sh\ntouch {marker}.gpg\nexit 1\n")
    gpg_helper.chmod(0o755)
    # Write a commit carrying a forged gpgsig header before planting config hooks.
    tree = subprocess.run(
        ["git", "-C", str(repo), "write-tree"], capture_output=True, text=True, check=True
    ).stdout.strip()
    signature_header = "gpgsig-sha256" if len(tree) == 64 else "gpgsig"
    raw_commit = (
        f"tree {tree}\n"
        "author t <t@t> 1700000000 +0000\n"
        "committer t <t@t> 1700000000 +0000\n"
        f"{signature_header} -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\n"
        "signed\n"
    ).encode()
    commit_oid = (
        subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
            input=raw_commit,
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    git(repo, "update-ref", "HEAD", commit_oid)

    git(repo, "config", "core.fsmonitor", f"touch {marker}.fsmonitor; false")
    git(repo, "config", "core.pager", f"touch {marker}.pager; cat")
    git(repo, "config", "core.attributesFile", str(alt_attr))
    git(repo, "config", "diff.x.textconv", f"touch {marker}.textconv; cat")
    git(repo, "config", "diff.external", f"touch {marker}.extdiff; cat")
    git(repo, "config", "filter.y.clean", f"touch {marker}.clean; cat")
    git(repo, "config", "log.showSignature", "true")
    git(repo, "config", "format.pretty", "%G? %s")
    for key in ("gpg.program", "gpg.openpgp.program", "gpg.x509.program", "gpg.ssh.program"):
        git(repo, "config", key, str(gpg_helper))
    git(repo, "config", "protocol.file.allow", "always")
    (repo / ".gitattributes").write_text("*.py diff=x filter=y\n")
    (repo / "app.py").write_text("print('changed')\n")

    for subcommand in ("status", "diff", "log"):
        assert git_run(warrant, repo, subcommand=subcommand).returncode == 0

    # Forced flags (--no-ext-diff, --no-textconv) come after caller flags, so
    # even a warrant that permits --ext-diff or --textconv cannot re-enable them.
    w_driver_flags = (
        Warrant.mint_builder()
        .capability(
            "git",
            subcommand=OneOf(["diff"]),
            flags=Subset(["--ext-diff", "--textconv"]),
            paths=Subpath(str(repo)),
            cwd=Subpath(str(repo)),
        )
        .holder(AGENT.public_key)
        .ttl(60)
        .mint(ROOT)
    )
    assert (
        run(
            w_driver_flags.bind(AGENT),
            GIT,
            cwd=str(repo),
            subcommand="diff",
            flags=["--ext-diff", "--textconv"],
            trusted_roots=[ROOT.public_key],
        ).returncode
        == 0
    )
    assert sorted(p.name for p in repo.parent.glob("ran.*")) == []

    # Control: the same repository runs the planted fsmonitor and gpg helper under plain git calls.
    subprocess.run(["git", "status"], cwd=repo, capture_output=True, check=False)
    subprocess.run(["git", "--no-pager", "log", "-1"], cwd=repo, capture_output=True, check=False)
    assert (repo.parent / "ran.fsmonitor").exists()
    assert (repo.parent / "ran.gpg").exists()


def test_literal_pathspecs_and_backslash_rejection(repo):
    (repo / "app.py").write_text("print('changed')\n")
    w = (
        Warrant.mint_builder()
        .capability(
            "git",
            subcommand=OneOf(["diff"]),
            flags=Subset(["--name-only"]),
            paths=Subset([str(repo / "a*.py")]),
            cwd=Subpath(str(repo)),
        )
        .holder(AGENT.public_key)
        .ttl(60)
        .mint(ROOT)
    )
    # GIT_LITERAL_PATHSPECS=1 prevents `a*.py` from matching `app.py`.
    out = run(
        w.bind(AGENT),
        GIT,
        cwd=str(repo),
        subcommand="diff",
        flags=["--name-only"],
        paths=["a*.py"],
        trusted_roots=[ROOT.public_key],
    )
    assert out.stdout.decode().strip() == ""

    with pytest.raises(AuthorizationDenied):
        run(w.bind(AGENT), GIT, cwd=str(repo), subcommand="diff", paths=["a\\b.py"], trusted_roots=[ROOT.public_key])


def test_min_version_check_fails_closed(tmp_path):
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\necho 'git version 2.40.0'\n")
    fake_git.chmod(0o755)
    old_git = replace(GIT, binary=str(fake_git))
    with pytest.raises(ConfigurationError, match="2.41"):
        old_git.resolve()


def test_profile_rejects_an_unsupported_operation_even_with_authority(warrant, repo):
    assert warrant.allows(
        "git",
        {
            "subcommand": "add",
            "flags": [],
            "paths": [str(repo)],
            "cwd": str(repo),
        },
    )
    with pytest.raises(AuthorizationDenied, match="does not support"):
        git_run(warrant, repo, subcommand="add")


def test_command_uses_the_core_tokens_for_the_authorized_argv(warrant, repo):
    profile = Program(name="git", binary=shutil.which("git"), subcommands=True)
    with (
        patch("shlex.split", side_effect=AssertionError("second parser")),
        patch("tenuo.process.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as execute,
    ):
        run_command(
            warrant.bind(AGENT),
            profile,
            "git diff --stat -- 'a; b.txt'",
            cwd=str(repo),
            trusted_roots=[ROOT.public_key],
        )
    assert execute.call_args.args[0] == [
        profile.resolve(),
        "diff",
        "--stat",
        "--",
        str(repo / "a; b.txt"),
    ]


def test_command_globs_and_braces_are_literal_paths(warrant, repo):
    out = run_command(
        warrant.bind(AGENT),
        GIT,
        "git diff --stat -- 'a*.py' '{app.py,other.py}'",
        cwd=str(repo),
        trusted_roots=[ROOT.public_key],
    )
    assert out.returncode == 0 and out.stdout == b""


def test_profile_pins_binary_resolution_and_copies_configuration():
    env = {"SETTING": "fixed"}
    profile = Program(name="git", env=env)
    env["SETTING"] = "changed"
    assert profile.env["SETTING"] == "fixed"
    with pytest.raises(TypeError):
        profile.env["SETTING"] = "changed"
    with patch("shutil.which", side_effect=["/usr/bin/git", "/untrusted/git"]):
        assert profile.resolve() == profile.resolve() == os.path.realpath("/usr/bin/git")


def test_program_without_subcommands(tmp_path):
    tmp_path = tmp_path.resolve()
    target = tmp_path / "a.txt"
    target.write_text("")
    ls = Program(name="ls")
    w = (
        Warrant.mint_builder()
        .capability("ls", flags=Subset(["-1"]), paths=Subpath(str(tmp_path)), cwd=Subpath(str(tmp_path)))
        .holder(AGENT.public_key)
        .ttl(60)
        .mint(ROOT)
    )
    out = run(w.bind(AGENT), ls, cwd=str(tmp_path), flags=["-1"], paths=["a.txt"], trusted_roots=[ROOT.public_key])
    assert out.stdout.decode() == f"{target}\n"
    with pytest.raises(AuthorizationDenied):
        run(w.bind(AGENT), ls, cwd=str(tmp_path), subcommand="x", trusted_roots=[ROOT.public_key])
    with pytest.raises(AuthorizationDenied):
        run(w.bind(AGENT), ls, cwd=str(tmp_path), paths=["-rf"], trusted_roots=[ROOT.public_key])
