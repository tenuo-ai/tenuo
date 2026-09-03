"""Job entry: start the holder, write mcp_config, tear down on exit."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Mapping, Optional

from .config import assert_no_runtime_secrets
from .holder import HolderClient, HolderError, HolderServer, assert_no_holder_secret


def guardrails(environ: Optional[Mapping[str, str]] = None) -> None:
    env = environ if environ is not None else os.environ
    assert_no_holder_secret(dict(env))
    assert_no_runtime_secrets(env)


def write_mcp_config(
    path: "str | Path",
    *,
    socket: str,
    gateway_url: str,
    command: Optional[List[str]] = None,
) -> Path:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    argv = command or [sys.executable, "-m", "tenuo_gha", "shim"]
    dest.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tenuo": {
                        "command": argv[0],
                        "args": argv[1:],
                        "env": {
                            "TENUO_HOLDER_SOCKET": socket,
                            "TENUO_GATEWAY_URL": gateway_url,
                        },
                    }
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return dest


def start_holder(socket_path: "str | Path") -> HolderServer:
    server = HolderServer(socket_path)
    server.start()
    return server


def wait_for_socket(socket_path: "str | Path", *, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    last: Optional[Exception] = None
    while time.time() < deadline:
        if Path(socket_path).exists():
            try:
                HolderClient(socket_path).public_key_hex()
                return
            except (OSError, HolderError) as exc:
                last = exc
        time.sleep(0.05)
    raise HolderError(f"holder socket did not come up: {last}")


def spawn_holder(
    socket_path: "str | Path",
    *,
    pid_path: Optional["str | Path"] = None,
    python: str = sys.executable,
) -> None:
    """Start a detached holder. The caller does not keep the secret."""
    cmd = [python, "-m", "tenuo_gha", "hold", "--socket", str(socket_path), "--daemon"]
    if pid_path:
        cmd.extend(["--pid", str(pid_path)])
    env = os.environ.copy()
    env.pop("TENUO_HOLDER_SECRET", None)
    env.pop("TENUO_HOLDER_FD", None)
    subprocess.Popen(
        cmd,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    wait_for_socket(socket_path)


def public_key_hex(socket_path: "str | Path") -> str:
    return HolderClient(socket_path).public_key_hex()


def deliver_warrant(socket_path: "str | Path", warrant_b64: str) -> None:
    HolderClient(socket_path).set_warrant(warrant_b64)


def stop_holder(socket_path: "str | Path", pid_path: Optional["str | Path"] = None) -> None:
    try:
        HolderClient(socket_path).shutdown()
    except (OSError, HolderError):
        pass
    if pid_path:
        path = Path(pid_path)
        if path.exists():
            try:
                os.kill(int(path.read_text(encoding="utf-8").strip()), 15)
            except (OSError, ValueError):
                pass
            path.unlink(missing_ok=True)


def main() -> None:
    """Start a detached holder and print public material plus mcp_config."""
    import argparse
    import tempfile

    parser = argparse.ArgumentParser(description="Start a Tenuo holder for this job")
    parser.add_argument("--gateway-url", default=os.environ.get("TENUO_GATEWAY_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--socket", default="")
    parser.add_argument("--mcp-config", default="")
    parser.add_argument("--pid", default="")
    args = parser.parse_args()
    guardrails()
    work = Path(tempfile.mkdtemp(prefix="tenuo-"))
    socket_path = Path(args.socket) if args.socket else work / "holder.sock"
    config_path = Path(args.mcp_config) if args.mcp_config else work / "mcp-config.json"
    pid_path = Path(args.pid) if args.pid else work / "holder.pid"
    spawn_holder(socket_path, pid_path=pid_path)
    write_mcp_config(config_path, socket=str(socket_path), gateway_url=args.gateway_url)
    payload = {
        "public_key": public_key_hex(socket_path),
        "mcp_config": str(config_path),
        "socket": str(socket_path),
        "pid": str(pid_path),
    }
    print(json.dumps(payload))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"mcp_config={payload['mcp_config']}\n")
            handle.write(f"public_key={payload['public_key']}\n")


if __name__ == "__main__":
    main()
