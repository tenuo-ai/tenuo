"""
Run a program exactly as a warrant authorizes it.

A warrant check on a command string does not decide what runs: the shell
expands braces, globs and ``~`` after the check, and the program reads its own
config. ``run`` closes that gap for one program at a time:

1. The request is structured: ``subcommand``, ``flags``, ``paths`` and ``cwd``.
2. ``cwd`` is resolved with ``realpath`` before the check, so a symlink inside
   an allowed directory cannot point the process elsewhere.
3. The warrant is checked against those values with ordinary constraints.
4. Exactly those values become argv, executed without a shell, with a fixed
   environment. Paths go after ``--`` so they are never read as options.

Example::

    from tenuo import OneOf, Subpath, Subset, Warrant
    from tenuo.process import GIT, run

    warrant = (Warrant.mint_builder()
        .capability("git",
            subcommand=OneOf(["status", "diff", "log"]),
            flags=Subset(["--short", "--stat", "--oneline"]),
            paths=Subset(["."]),
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

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .exceptions import AuthorizationDenied, ConfigurationError

__all__ = ["GIT", "Program", "run", "run_command"]


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
        forced_flags: Flags always added after a subcommand, for options that
            turn off code-running features of that subcommand.
    """

    name: str
    binary: Optional[str] = None
    env: Mapping[str, str] = field(default_factory=dict)
    subcommands: bool = False
    forced_flags: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    def resolve(self) -> str:
        path = self.binary or shutil.which(self.name)
        if not path or not os.path.isabs(path):
            raise ConfigurationError(f"{self.name}: no absolute binary path (found {path!r})")
        return os.path.realpath(path)


# Repository config and attributes can make read-only git commands run
# programs: core.fsmonitor on status, core.pager and diff.external on log and
# diff, textconv and clean filters on diff. Command-line config wins over the
# repository's, and an empty tree as the attribute source ignores the
# worktree's .gitattributes (git 2.40+). Settings in .git/ itself (such as
# .git/info/attributes) still apply, so keep .git/ out of the agent's file tools.
# Network transports are off: this profile is for local repository commands.
_GIT_CONFIG = {
    "core.fsmonitor": "false",
    "core.hooksPath": "/dev/null",
    "core.pager": "cat",
    "core.sshCommand": "false",
    "core.editor": "false",
    "diff.external": "",
    "protocol.allow": "never",
}
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_NO_DRIVERS = ("--no-ext-diff", "--no-textconv")

GIT = Program(
    name="git",
    subcommands=True,
    env={
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_ATTR_SOURCE": _EMPTY_TREE,
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
    timeout: float = 60,
) -> "subprocess.CompletedProcess[bytes]":
    """Check the warrant against this exact call, then run it.

    The warrant's capability for ``tool`` (default: ``program.name``) is
    checked with arguments ``subcommand`` (only when ``program.subcommands``),
    ``flags``, ``paths`` and ``cwd``. Constrain all of them; unnamed arguments
    are denied.

    Returns the completed process with captured stdout and stderr. A non-zero
    exit is returned, not raised.

    Raises:
        AuthorizationDenied: The warrant does not allow this call, or the
            request is malformed.
    """
    tool = tool or program.name
    if os.name != "posix":
        raise ConfigurationError("tenuo.process runs on POSIX systems only")
    flags, paths = list(flags), list(paths)

    words = [subcommand or "", *flags, *paths, cwd]
    if any(not isinstance(w, str) or "\0" in w for w in words):
        raise _deny(tool, "arguments must be strings without NUL bytes")
    if any(not f.startswith("-") or f == "--" for f in flags):
        raise _deny(tool, "flags must start with '-'")
    if any(p.startswith("-") for p in paths):
        raise _deny(tool, "paths cannot start with '-'")
    if program.subcommands:
        if not subcommand or subcommand.startswith("-"):
            raise _deny(tool, f"{program.name} needs a subcommand")
    elif subcommand is not None:
        raise _deny(tool, f"{program.name} takes no subcommand")

    request: Dict[str, Any] = {"flags": flags, "paths": paths, "cwd": os.path.realpath(cwd)}
    if program.subcommands:
        request["subcommand"] = subcommand

    result = bound_warrant.validate(tool, request, trusted_roots=trusted_roots, warrant_chain=warrant_chain)
    if not result:
        raise _deny(tool, result.reason or "not authorized")

    head = [subcommand, *program.forced_flags.get(subcommand, ())] if subcommand else []
    argv = [program.resolve(), *head, *flags, "--", *paths]
    return subprocess.run(
        argv,
        cwd=request["cwd"],
        env=dict(program.env),
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
    try:
        words = shlex.split(command)
    except ValueError as exc:
        raise _deny(tool, f"cannot parse command: {exc}") from None
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
