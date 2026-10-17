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
            with pytest.raises(Exception, match="issue_key"):
                await client.tools["comment"](issue_key="OPS-40", body="closing")

        with pytest.raises(Exception, match="No warrant provided"):
            await client.call_tool(
                "comment", {"issue_key": "OPS-12", "body": "x"}, warrant_context=False, inject_warrant=False
            )

    assert log.read_text().splitlines() == ["OPS-12 fixed"]


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
    assert "no trusted root" in result.stderr


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
