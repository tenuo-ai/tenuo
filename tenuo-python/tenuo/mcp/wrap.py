"""Run an existing FastMCP server with Tenuo checking every tool call.

    python -m tenuo.mcp.wrap --home ~/.tenuo mcp-atlassian --transport stdio
    TENUO_TRUSTED_ROOT=<hex public key> python -m tenuo.mcp.wrap mcp-atlassian --transport stdio

With ``--home``, trust, revocations and the mode come from a ``tenuo-cli``
workspace and are reread on every call: in ``mode: observe`` every call runs
and is recorded to the workspace's observations.jsonl, under the server's name
as the step, for drafting a warrant. ``tenuo-cli mode enforce`` turns the check
on without restarting the server.

The first argument is the server's console script (``mcp-atlassian``) or a
``module:function`` entrypoint; everything after it is passed to the server
unchanged. Whichever FastMCP server the entrypoint starts gets
:class:`TenuoMiddleware` at the front of its middleware, so every
``tools/call`` must carry a warrant chain rooted in a trusted key and a
holder signature, or the tool doesn't run.

The check is installed where every MCP session starts (the SDK's low-level
``Server.run``), over stdio and HTTP alike. A server that isn't built on
FastMCP is refused instead of started unguarded.
"""

from __future__ import annotations

import argparse
import functools
import importlib
import os
import sys
from importlib.metadata import entry_points
from typing import Any, Callable, List, Optional, Sequence

__all__ = ["guard_fastmcp_servers", "main"]

_ENV_ROOT = "TENUO_TRUSTED_ROOT"


class WrapError(RuntimeError):
    """The server can't be started with the Tenuo check in place."""


def _parse_roots(values: Sequence[str]) -> List[Any]:
    from tenuo_core import PublicKey

    roots = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                roots.append(PublicKey.from_bytes(bytes.fromhex(part)))
            except Exception as exc:
                raise WrapError(f"invalid trusted root {part!r}: expected a hex-encoded public key") from exc
    return roots


def guard_fastmcp_servers(verifier: Any) -> None:
    """Install ``TenuoMiddleware(verifier)`` on every FastMCP server this process runs.

    Patches the MCP SDK's low-level ``Server.run`` (and FastMCP's subclass, where
    it overrides ``run``). Each session's server is mapped back to its FastMCP
    instance and the middleware is inserted first. A server with a TenuoMiddleware
    of its own raises :class:`WrapError` rather than run two verifiers. A
    low-level server with no FastMCP instance behind it raises :class:`WrapError`.
    """
    from fastmcp import FastMCP
    from fastmcp.server.low_level import LowLevelServer
    from mcp.server.lowlevel.server import Server

    from .fastmcp_middleware import TenuoMiddleware

    def ensure_guarded(lowlevel: Any) -> None:
        server = getattr(lowlevel, "fastmcp", None)
        if not isinstance(server, FastMCP):
            raise WrapError(
                "tenuo.mcp.wrap: this server isn't built on FastMCP, so Tenuo can't check its "
                "tool calls; refusing to start it unguarded. Put it behind an MCP proxy with a "
                "Tenuo check instead."
            )
        guards = [m for m in server.middleware if isinstance(m, TenuoMiddleware)]
        if any(m._verifier is not verifier for m in guards):
            # Two verifiers with different roots would each reject the other's warrants.
            raise WrapError(
                "tenuo.mcp.wrap: this server already checks calls with its own TenuoMiddleware; "
                "run it directly instead of under tenuo.mcp.wrap."
            )
        if not guards:
            server.middleware.insert(0, TenuoMiddleware(verifier))

    def patch(cls: type) -> None:
        original: Callable[..., Any] = cls.__dict__["run"]
        if getattr(original, "_tenuo_guarded", False):
            return

        @functools.wraps(original)
        async def run(self: Any, *args: Any, **kwargs: Any) -> Any:
            ensure_guarded(self)
            return await original(self, *args, **kwargs)

        run._tenuo_guarded = True  # type: ignore[attr-defined]
        setattr(cls, "run", run)

    for cls in (Server, LowLevelServer):
        if "run" in cls.__dict__:
            patch(cls)


def _find_wrap_error(exc: BaseException) -> Optional[WrapError]:
    """Find a WrapError raised inside the server's task groups."""
    if isinstance(exc, WrapError):
        return exc
    for inner in getattr(exc, "exceptions", ()):
        found = _find_wrap_error(inner)
        if found is not None:
            return found
    cause = exc.__cause__ or exc.__context__
    return _find_wrap_error(cause) if cause is not None else None


def _resolve_entrypoint(target: str) -> Callable[..., Any]:
    if ":" in target:
        module_name, _, attr = target.partition(":")
        obj: Any = importlib.import_module(module_name)
        for part in attr.split("."):
            obj = getattr(obj, part)
        return obj
    matches = entry_points(group="console_scripts", name=target)
    for ep in matches:
        return ep.load()
    raise WrapError(
        f"no console script named {target!r} in this environment; install the server here, "
        "or pass its entrypoint as module:function"
    )


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tenuo.mcp.wrap",
        description="Run an existing FastMCP server with Tenuo checking every tool call.",
    )
    parser.add_argument(
        "--home",
        metavar="DIR",
        help="tenuo-cli workspace for trust, revocations and enforce/observe mode (default: none)",
    )
    parser.add_argument("--step", help="with --home, the step observed calls are recorded under (default: SERVER)")
    parser.add_argument("--key", help="with --home, a server identity in the workspace that signs receipts")
    parser.add_argument(
        "--trusted-root",
        action="append",
        default=[],
        metavar="HEX",
        help=f"public key that warrants must chain to (repeatable; default: ${_ENV_ROOT}, comma-separated)",
    )
    parser.add_argument("server", help="the server's console script, or module:function")
    parser.add_argument("server_args", nargs=argparse.REMAINDER, help="arguments passed to the server")
    args = parser.parse_args(argv)

    try:
        from .server import MCPVerifier

        if args.home:
            if args.trusted_root:
                raise WrapError("--home reads trust from the workspace; drop --trusted-root")
            step = args.step or args.server.rpartition(":")[0] or args.server
            verifier = MCPVerifier.local(path=args.home, key=args.key, step=step)
        else:
            if args.step or args.key:
                raise WrapError("--step and --key need --home")
            roots = _parse_roots(args.trusted_root or [os.environ.get(_ENV_ROOT, "")])
            if not roots:
                raise WrapError(
                    f"no trust configured: pass --home with a tenuo-cli workspace, or --trusted-root / {_ENV_ROOT}"
                )

            from tenuo_core import Authorizer

            verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=roots), require_warrant=True)
        guard_fastmcp_servers(verifier)
        server_args = list(args.server_args)
        if server_args[:1] == ["--"]:
            server_args = server_args[1:]
        # Before the import: a server may parse its arguments at import time.
        sys.argv = [args.server, *server_args]
        entrypoint = _resolve_entrypoint(args.server)
    except WrapError as exc:
        parser.exit(2, f"tenuo.mcp.wrap: {exc}\n")

    try:
        result = entrypoint()
    except BaseException as exc:
        refused = _find_wrap_error(exc)
        if refused is None:
            raise
        parser.exit(2, f"{refused}\n")
    sys.exit(result if isinstance(result, int) else 0)


if __name__ == "__main__":
    main()
