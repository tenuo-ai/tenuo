"""
Run a program exactly as a warrant authorizes it.

A warrant check on a command string does not decide what runs: the shell
expands braces, globs and ``~`` after the check, and the program reads its own
config. ``run`` closes that gap for one program at a time:

1. The request is structured: ``subcommand``, ``flags``, ``paths`` and ``cwd``.
2. ``cwd`` and each entry of ``paths`` (joined to ``cwd``, defaulting to
   ``"."`` when omitted) are resolved with ``realpath`` before the check, so a
   symlink inside an allowed directory cannot point the process elsewhere.
   Because ``realpath`` resolves paths before ``execve`` rather than pinning
   file descriptors, the directory ancestry of ``cwd`` and ``paths`` must not
   be writable by concurrent untrusted processes during execution.
3. The warrant is checked against those values with ordinary constraints.
4. Exactly those resolved values become argv, executed without a shell, with a
   fixed environment. Program-forced safety flags are placed after caller flags,
   and paths go after ``--`` so they are never read as options.

Example::

    from tenuo import OneOf, Subpath, Subset, Warrant
    from tenuo.process import GIT, run

    warrant = (Warrant.mint_builder()
        .capability("git",
            subcommand=OneOf(["status", "diff", "log"]),
            flags=Subset(["--short", "--stat", "--oneline"]),
            paths=Subpath("/workspace/repo"),
            cwd=Subpath("/workspace/repo"))
        .holder(agent_key.public_key).ttl(1800).mint(issuer_key))

    run(warrant.bind(agent_key), GIT, subcommand="status", flags=["--short"],
        cwd="/workspace/repo")          # runs
    run(warrant.bind(agent_key), GIT, subcommand="push",
        cwd="/workspace/repo")          # raises AuthorizationDenied

Delegation narrows each field the usual way: ``OneOf`` to a smaller ``OneOf``,
``Subset`` to a smaller ``Subset``, ``Subpath`` to a deeper root.

POSIX only. On Windows each program parses its own command line, so argv
cannot be passed through exactly.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .exceptions import AuthorizationDenied, ConfigurationError

__all__ = ["GIT", "Program", "run", "run_command"]


@functools.lru_cache(maxsize=16)
def _check_version(binary: str, min_version: Tuple[int, int]) -> None:
    try:
        out = subprocess.run(
            [binary, "--version"],
            env={},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=True,
        ).stdout.decode("utf-8", errors="replace")
    except Exception as exc:
        raise ConfigurationError(f"failed to check version of {binary!r}: {exc}") from None
    match = re.search(r"(\d+)\.(\d+)", out)
    if not match or (int(match.group(1)), int(match.group(2))) < min_version:
        req = f"{min_version[0]}.{min_version[1]}"
        raise ConfigurationError(f"{binary!r} must be version {req} or newer (got {out.strip()!r})")


@dataclass(frozen=True)
class Program:
    """A program the warrant can authorize, and how to run it safely.

    Args:
        name: The word the agent uses for it (``"git"``). Also the default tool
            name checked against the warrant.
        binary: Absolute path. Defaults to ``name`` looked up on ``PATH`` when
            first run, then resolved with ``realpath``.
        env: The complete environment for the process. Nothing is inherited.
        subcommands: Whether the first word after the program is a subcommand.
        forced_flags: Flags always added after caller flags for a subcommand,
            for options that turn off code-running features of that subcommand.
        supported_subcommands: The operations this executor understands. This
            is a grammar limit; the warrant must separately authorize the call.
        min_version: Minimum ``(major, minor)`` version required by the profile.
    """

    name: str
    binary: Optional[str] = None
    env: Mapping[str, str] = field(default_factory=dict)
    subcommands: bool = False
    forced_flags: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    min_version: Optional[Tuple[int, int]] = None
    supported_subcommands: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        # Profiles are trusted executor configuration, not mutable agent input.
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        object.__setattr__(
            self,
            "forced_flags",
            MappingProxyType({name: tuple(flags) for name, flags in self.forced_flags.items()}),
        )
        if self.supported_subcommands is not None:
            if not self.subcommands:
                raise ConfigurationError("supported_subcommands requires subcommands=True")
            object.__setattr__(self, "supported_subcommands", tuple(self.supported_subcommands))

    def resolve(self) -> str:
        return self._resolved_binary

    def _execution_env(self, binary: str, cwd: str) -> Dict[str, str]:
        return dict(self.env)

    @functools.cached_property
    def _resolved_binary(self) -> str:
        path = self.binary or shutil.which(self.name)
        if not path or not os.path.isabs(path):
            raise ConfigurationError(f"{self.name}: no absolute binary path (found {path!r})")
        real = os.path.realpath(path)
        if self.min_version is not None:
            _check_version(real, self.min_version)
        return real


# Repository config and attributes can make read-only git commands run
# programs: core.fsmonitor on status, core.pager and diff.external on log and
# diff, textconv and clean filters on diff. Command-line config wins over the
# repository's, and an empty tree as the attribute source ignores the
# worktree's .gitattributes (git 2.41+). Settings in .git/ itself (such as
# .git/info/attributes) still apply, so keep .git/ out of the agent's file tools.
# Network transports are off: this profile is for local repository commands.
_GIT_CONFIG = {
    "core.fsmonitor": "false",
    "core.hooksPath": "/dev/null",
    "core.attributesFile": "/dev/null",
    "core.pager": "cat",
    "core.sshCommand": "false",
    "core.editor": "false",
    "diff.external": "",
    "log.showSignature": "false",
    "gpg.program": "false",
    "gpg.openpgp.program": "false",
    "gpg.x509.program": "false",
    "gpg.ssh.program": "false",
    "protocol.allow": "never",
}
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_NO_DRIVERS = ("--no-ext-diff", "--no-textconv")


class _GitProgram(Program):
    def _execution_env(self, binary: str, cwd: str) -> Dict[str, str]:
        env = dict(self.env)
        # This read-only builtin computes the empty-tree ID using this repo's
        # object format. Never assume SHA-1 or read attributes from the worktree.
        try:
            result = subprocess.run(
                [binary, "hash-object", "-t", "tree", "--stdin"],
                cwd=cwd,
                env=env,
                input=b"",
                capture_output=True,
                timeout=10,
                check=True,
            )
            tree = result.stdout.decode("ascii").strip()
            if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree) is None:
                raise ValueError("invalid empty-tree ID")
        except Exception as exc:
            raise ConfigurationError(f"cannot determine Git attribute source: {exc}") from None
        env["GIT_ATTR_SOURCE"] = tree
        return env


GIT = _GitProgram(
    name="git",
    subcommands=True,
    min_version=(2, 41),
    supported_subcommands=("status", "diff", "log"),
    env={
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_SOURCE": _EMPTY_TREE,
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": str(len(_GIT_CONFIG)),
        **{f"GIT_CONFIG_KEY_{i}": key for i, key in enumerate(_GIT_CONFIG)},
        **{f"GIT_CONFIG_VALUE_{i}": value for i, value in enumerate(_GIT_CONFIG.values())},
    },
    forced_flags={"diff": _NO_DRIVERS, "log": _NO_DRIVERS, "show": _NO_DRIVERS},
)


def _deny(tool: str, reason: str) -> AuthorizationDenied:
    return AuthorizationDenied(tool, reason=reason)


def run(
    bound_warrant: Any,
    program: Program,
    *,
    cwd: str,
    subcommand: Optional[str] = None,
    flags: Sequence[str] = (),
    paths: Sequence[str] = (),
    tool: Optional[str] = None,
    trusted_roots: Optional[List[Any]] = None,
    warrant_chain: Optional[List[Any]] = None,
    approvals: Optional[List[Any]] = None,
    timeout: float = 60,
) -> "subprocess.CompletedProcess[bytes]":
    """Check the warrant against this exact call, then run it.

    The warrant's capability for ``tool`` (default: ``program.name``) is
    checked with arguments ``subcommand`` (only when ``program.subcommands``),
    ``flags``, ``paths`` and ``cwd``. Constrain all of them; unnamed arguments
    are denied.

    Pass collected SignedApproval objects via ``approvals`` when the warrant
    requires approval. They are verified against this exact resolved request.

    Returns the completed process with captured stdout and stderr. A non-zero
    exit is returned, not raised.

    Raises:
        AuthorizationDenied: The warrant does not allow this call, or the
            request is malformed.
    """
    tool = tool or program.name
    if os.name != "posix":
        raise ConfigurationError("tenuo.process runs on POSIX systems only")
    flags, paths = list(flags), list(paths) or ["."]

    words = [subcommand or "", *flags, *paths, cwd]
    if any(not isinstance(w, str) or "\0" in w or "\\" in w for w in words):
        raise _deny(tool, "arguments must be strings without NUL bytes or backslashes")
    if any(not f.startswith("-") or f == "--" for f in flags):
        raise _deny(tool, "flags must start with '-'")
    if any(p.startswith("-") for p in paths):
        raise _deny(tool, "paths cannot start with '-'")
    if program.subcommands:
        if not subcommand or subcommand.startswith("-"):
            raise _deny(tool, f"{program.name} needs a subcommand")
        if program.supported_subcommands is not None and subcommand not in program.supported_subcommands:
            raise _deny(tool, f"{program.name} profile does not support subcommand {subcommand!r}")
    elif subcommand is not None:
        raise _deny(tool, f"{program.name} takes no subcommand")

    real_cwd = os.path.realpath(cwd)
    real_paths = [os.path.realpath(os.path.join(real_cwd, p)) for p in paths]
    if "\\" in real_cwd or any("\\" in p for p in real_paths):
        raise _deny(tool, "resolved paths must not contain backslashes")
    request: Dict[str, Any] = {"flags": flags, "paths": real_paths, "cwd": real_cwd}
    if program.subcommands:
        request["subcommand"] = subcommand

    result = bound_warrant.validate(
        tool, request, approvals=approvals, trusted_roots=trusted_roots, warrant_chain=warrant_chain
    )
    if not result:
        raise _deny(tool, result.reason or "not authorized")

    head = [subcommand] if subcommand else []
    forced = list(program.forced_flags.get(subcommand, ())) if subcommand else []
    binary = program.resolve()
    env = program._execution_env(binary, real_cwd)
    argv = [binary, *head, *flags, *forced, "--", *real_paths]
    return subprocess.run(
        argv,
        cwd=real_cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def run_command(
    bound_warrant: Any,
    program: Program,
    command: str,
    *,
    cwd: str,
    **kwargs: Any,
) -> "subprocess.CompletedProcess[bytes]":
    """``run`` for tools that take one command string, such as ``shell(command)``.

    The string is split once with POSIX quoting rules and that split is what
    runs; it never reaches a shell, so operators and expansions are plain
    words. It must start with ``program.name``. Words starting with ``-`` are
    flags and the rest are paths, so pass option values joined
    (``--max-count=5``, not ``-n 5``).
    """
    tool = kwargs.get("tool") or program.name
    from .constraints import Shlex

    decision = Shlex(allow=[program.name]).check(command)
    if not decision["allowed"]:
        raise _deny(tool, "command rejected by Shlex syntax check")
    words = decision["tokens"]
    if not words or words[0] != program.name:
        raise _deny(tool, f"command must start with {program.name!r}")
    words = words[1:]
    subcommand = None
    if program.subcommands:
        if not words or words[0].startswith("-"):
            raise _deny(tool, f"{program.name} needs a subcommand first")
        subcommand, words = words[0], words[1:]
    flags: List[str] = []
    paths: List[str] = []
    for i, word in enumerate(words):
        if word == "--":
            paths += words[i + 1 :]
            break
        (flags if word.startswith("-") else paths).append(word)
    if any(p.startswith("-") for p in paths):
        raise _deny(tool, "paths cannot start with '-'")
    return run(bound_warrant, program, cwd=cwd, subcommand=subcommand, flags=flags, paths=paths, **kwargs)
