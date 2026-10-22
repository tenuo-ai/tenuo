"""
``python -m tenuo.mcp.wrap``: an unmodified FastMCP server, run with Tenuo checking every call.

The wrapper patches the MCP SDK process-wide, so everything that starts a
server runs in a subprocess.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastmcp")

from tenuo import Capability, Exact, SigningKey, Wildcard, configure, mint  # noqa: E402
from tenuo.mcp import SecureMCPClient  # noqa: E402
from tenuo.mcp.wrap import WrapError, _find_wrap_error, _parse_roots  # noqa: E402

from .._mcp_sdk_support import (  # noqa: E402
    FASTMCP_SERVER_AVAILABLE,
    FASTMCP_SERVER_SKIP_REASON,
)

if sys.version_info >= (3, 11):
    from builtins import BaseExceptionGroup
else:  # pragma: no cover
    from exceptiongroup import BaseExceptionGroup

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def _reset_global_config():
    # Some tests call configure(); later tests elsewhere must not inherit their roots.
    from tenuo.config import reset_config

    yield
    reset_config()
REPO = Path(__file__).resolve().parent.parent.parent


def _env(**extra: str) -> dict:
    existing = os.environ.get("PYTHONPATH", "")
    path = os.pathsep.join(p for p in (str(REPO), str(FIXTURES), existing) if p)
    return {**os.environ, "PYTHONPATH": path, **extra}


def _wrap(*args: str, env: dict, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tenuo.mcp.wrap", *args],
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
    )


INITIALIZE = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
    '"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}\n'
)


@pytest.mark.skipif(not FASTMCP_SERVER_AVAILABLE, reason=FASTMCP_SERVER_SKIP_REASON)
@pytest.mark.asyncio
async def test_wrapped_server_runs_only_what_the_warrant_allows(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    log.touch()
    key = SigningKey.generate()
    configure(issuer_key=key, trusted_roots=[key.public_key])
    env = _env(TENUO_TRUSTED_ROOT=key.public_key.to_bytes().hex(), WRAP_TEST_LOG=str(log))

    async with SecureMCPClient(
        command=sys.executable,
        args=["-m", "tenuo.mcp.wrap", "fastmcp_wrap_server:main"],
        env=env,
        inject_warrant=True,
    ) as client:
        async with mint(Capability("comment", issue_key=Exact("OPS-12"), body=Wildcard())):
            await client.tools["comment"](issue_key="OPS-12", body="fixed")
            # Skip the client's own check so the wrapped server is what refuses it.
            with pytest.raises(Exception, match="issue_key"):
                await client.call_tool(
                    "comment", {"issue_key": "OPS-40", "body": "closing"}, warrant_context=False, inject_warrant=True
                )

        with pytest.raises(Exception, match="No warrant provided"):
            await client.call_tool(
                "comment", {"issue_key": "OPS-12", "body": "x"}, warrant_context=False, inject_warrant=False
            )

    assert log.read_text().splitlines() == ["OPS-12 fixed"]


def test_server_with_its_own_guard_is_refused() -> None:
    key = SigningKey.generate()
    result = _wrap(
        "fastmcp_wrap_server:main",
        env=_env(TENUO_TRUSTED_ROOT=key.public_key.to_bytes().hex(), WRAP_TEST_LOG=os.devnull, WRAP_TEST_OWN_GUARD="1"),
        stdin=INITIALIZE,
    )
    assert result.returncode == 2
    assert "its own TenuoMiddleware" in result.stderr
    assert '"result"' not in result.stdout


def test_server_parsing_flags_at_import_sees_only_its_own() -> None:
    key = SigningKey.generate()
    result = _wrap(
        "--trusted-root",
        key.public_key.to_bytes().hex(),
        "fastmcp_wrap_argv_server:main",
        env=_env(),
        stdin=INITIALIZE,
    )
    assert "unrecognized arguments" not in result.stderr
    assert '"result"' in result.stdout


def test_server_not_built_on_fastmcp_is_refused() -> None:
    key = SigningKey.generate()
    result = _wrap(
        "mcp_sdk_wrap_server:main",
        env=_env(TENUO_TRUSTED_ROOT=key.public_key.to_bytes().hex()),
        stdin=INITIALIZE,
    )
    assert result.returncode == 2
    assert "isn't built on FastMCP" in result.stderr
    assert '"result"' not in result.stdout  # never answered initialize


def test_requires_a_trusted_root() -> None:
    env = _env()
    env.pop("TENUO_TRUSTED_ROOT", None)
    result = _wrap("fastmcp_wrap_server:main", env=env)
    assert result.returncode == 2
    assert "no trust configured" in result.stderr and "--home" in result.stderr


def test_unknown_console_script() -> None:
    result = _wrap("no-such-mcp-server", env=_env(TENUO_TRUSTED_ROOT=SigningKey.generate().public_key.to_bytes().hex()))
    assert result.returncode == 2
    assert "no console script named 'no-such-mcp-server'" in result.stderr


def test_parse_roots_accepts_repeated_and_comma_separated_keys() -> None:
    a, b = (SigningKey.generate().public_key.to_bytes().hex() for _ in range(2))
    assert len(_parse_roots([f"{a}, {b}"])) == 2
    assert len(_parse_roots([a, b])) == 2
    assert _parse_roots([""]) == []
    with pytest.raises(WrapError, match="hex-encoded public key"):
        _parse_roots(["not-hex"])


def test_find_wrap_error_looks_inside_exception_groups() -> None:
    refused = WrapError("refused")
    group = BaseExceptionGroup("tg", [ValueError("x"), BaseExceptionGroup("inner", [refused])])
    assert _find_wrap_error(group) is refused
    try:
        try:
            raise refused
        except WrapError as exc:
            raise RuntimeError("wrapped") from exc
    except RuntimeError as outer:
        assert _find_wrap_error(outer) is refused
    assert _find_wrap_error(ValueError("x")) is None


@pytest.mark.skipif(not FASTMCP_SERVER_AVAILABLE, reason=FASTMCP_SERVER_SKIP_REASON)
@pytest.mark.asyncio
async def test_home_observes_any_client_then_enforces_without_a_restart(tmp_path: Path) -> None:
    """With --home, a plain MCP client works in observe mode; tenuo-cli mode enforce applies on the next call."""
    import json

    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    from tenuo.local_cli.workspace import Workspace

    home = tmp_path / ".tenuo"
    workspace = Workspace(home)
    workspace.initialize(dev=True)
    workspace.set_mode("observe")
    log = tmp_path / "calls.log"
    log.touch()
    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "tenuo.mcp.wrap", "--home", str(home), "fastmcp_wrap_server:main"],
        env=_env(WRAP_TEST_LOG=str(log)),
    )
    async with Client(transport) as client:
        await client.call_tool("comment", {"issue_key": "OPS-12", "body": "fixed"})
        workspace.set_mode("enforce")
        refused = await client.call_tool("comment", {"issue_key": "OPS-13", "body": "x"}, raise_on_error=False)
        assert refused.is_error
    assert log.read_text().splitlines() == ["OPS-12 fixed"]
    lines = [json.loads(line) for line in (home / "observations.jsonl").read_text().splitlines()]
    assert [(line["step"], line["tool"], line["args"], line["decision"]) for line in lines] == [
        ("fastmcp_wrap_server", "comment", {"issue_key": "OPS-12", "body": "fixed"}, None)
    ]


def test_home_and_trusted_root_are_exclusive(tmp_path: Path) -> None:
    from tenuo.local_cli.workspace import Workspace

    home = tmp_path / ".tenuo"
    Workspace(home).initialize(dev=True)
    result = _wrap("--home", str(home), "--trusted-root", "00" * 32, "fastmcp_wrap_server:main", env=_env())
    assert result.returncode == 2 and "drop --trusted-root" in result.stderr
    result = _wrap("--step", "x", "fastmcp_wrap_server:main", env=_env(TENUO_TRUSTED_ROOT="00" * 32))
    assert result.returncode == 2 and "need --home" in result.stderr
