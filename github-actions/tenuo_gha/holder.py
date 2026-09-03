"""Holder process: key and warrant stay here; the socket never returns the secret."""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from tenuo.mcp import derive_terminal_leaf
from tenuo_core import SigningKey, Warrant, encode_warrant_stack

from .catalog import PACKS, TRIPWIRE_NAMES


class HolderError(ValueError):
    """Holder refused a request. Never includes key material."""


def assert_no_holder_secret(environ: Optional[Dict[str, str]] = None) -> None:
    env = environ if environ is not None else os.environ
    if env.get("TENUO_HOLDER_SECRET"):
        raise HolderError("TENUO_HOLDER_SECRET is not allowed")
    if env.get("TENUO_HOLDER_FD"):
        raise HolderError("TENUO_HOLDER_FD is not allowed")


def _warrant_tools(warrant: Warrant) -> List[str]:
    tools = getattr(warrant, "tools", None)
    if callable(tools):
        tools = tools()
    if tools:
        return [str(item) for item in tools]
    caps = getattr(warrant, "capabilities", None)
    if callable(caps):
        caps = caps()
    if isinstance(caps, dict):
        return [str(item) for item in caps.keys()]
    return []


def _encode_stack(warrants: List[Warrant]) -> str:
    try:
        return encode_warrant_stack(warrants)
    except Exception:
        return warrants[-1].to_base64()


class Holder:
    """In-process holder used by the socket server and by tests."""

    def __init__(self, *, allowlist: Optional[List[str]] = None, key: Optional[SigningKey] = None) -> None:
        assert_no_holder_secret()
        self._key = key or SigningKey.generate()
        self._warrant: Optional[Warrant] = None
        self._allowlist = allowlist

    def public_key_hex(self) -> str:
        return self._key.public_key.to_bytes().hex()

    def set_warrant(self, warrant_b64: str) -> None:
        self._warrant = Warrant.from_base64(warrant_b64)

    def tools(self) -> List[str]:
        if self._warrant is None:
            return []
        named = set(_warrant_tools(self._warrant))
        catalog = {spec.name for pack in PACKS.values() for spec in pack}
        chosen = sorted((named & catalog) - TRIPWIRE_NAMES)
        if self._allowlist is not None:
            chosen = [name for name in chosen if name in self._allowlist]
        return chosen

    def envelope(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, str]:
        if self._warrant is None:
            raise HolderError("no warrant has been set")
        ts = int(time.time())
        try:
            leaf, leaf_key = derive_terminal_leaf(self._warrant, self._key, tool, arguments)
            sig = leaf.sign(leaf_key, tool, arguments, ts)
            stack = _encode_stack([self._warrant, leaf])
        except Exception:
            # Widening and unknown tools still present the parent so the
            # gateway can emit a signed denial. Do not return the secret.
            try:
                sig = self._warrant.sign(self._key, tool, arguments, ts)
                stack = _encode_stack([self._warrant])
            except Exception as exc:
                raise HolderError("could not sign") from exc
        return {
            "warrant": stack,
            "signature": base64.b64encode(bytes(sig)).decode(),
        }


def _handle(holder: Holder, message: Dict[str, Any]) -> Dict[str, Any]:
    op = message.get("op")
    if op == "public_key":
        return {"ok": True, "public_key": holder.public_key_hex()}
    if op == "set_warrant":
        raw = message.get("warrant")
        if not isinstance(raw, str) or not raw:
            return {"ok": False, "error": "warrant is required"}
        holder.set_warrant(raw)
        return {"ok": True}
    if op == "tools":
        return {"ok": True, "tools": holder.tools()}
    if op == "envelope":
        tool = message.get("tool")
        arguments = message.get("arguments") or {}
        if not isinstance(tool, str) or not tool:
            return {"ok": False, "error": "tool is required"}
        if not isinstance(arguments, dict):
            return {"ok": False, "error": "arguments must be a mapping"}
        try:
            payload = holder.envelope(tool, arguments)
        except HolderError as exc:
            return {"ok": False, "error": str(exc)}
        payload["ok"] = True
        return payload
    if op == "shutdown":
        return {"ok": True, "shutdown": True}
    if op == "export_key":
        return {"ok": False, "error": "not supported"}
    return {"ok": False, "error": f"unknown op {op!r}"}


class HolderServer:
    """JSON-line Unix socket in front of a Holder."""

    def __init__(self, path: "str | Path", holder: Optional[Holder] = None) -> None:
        assert_no_holder_secret()
        self.path = Path(path)
        self.holder = holder or Holder()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self.path.exists():
            self.path.unlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bind = str(self.path)
        if len(bind) > 100:
            raise HolderError("holder socket path is too long")
        self._sock.bind(bind)
        os.chmod(self.path, 0o600)
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                self._one(conn)

    def _one(self, conn: socket.socket) -> None:
        buf = b""
        while not self._stop.is_set():
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    message = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    conn.sendall(b'{"ok":false,"error":"invalid json"}\n')
                    continue
                reply = _handle(self.holder, message)
                conn.sendall((json.dumps(reply) + "\n").encode("utf-8"))
                if reply.get("shutdown"):
                    self._stop.set()
                    return

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self.path.exists():
            self.path.unlink()

    def __enter__(self) -> "HolderServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


class HolderClient:
    """Talk to a HolderServer. Holds no secret."""

    def __init__(self, path: "str | Path") -> None:
        assert_no_holder_secret()
        self.path = str(path)

    def _rpc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        try:
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise HolderError("holder socket closed")
                buf += chunk
            reply = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        finally:
            sock.close()
        if not reply.get("ok"):
            raise HolderError(str(reply.get("error") or "holder refused"))
        return reply

    def public_key_hex(self) -> str:
        return str(self._rpc({"op": "public_key"})["public_key"])

    def set_warrant(self, warrant_b64: str) -> None:
        self._rpc({"op": "set_warrant", "warrant": warrant_b64})

    def tools(self) -> List[str]:
        return list(self._rpc({"op": "tools"})["tools"])

    def envelope(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, str]:
        reply = self._rpc({"op": "envelope", "tool": tool, "arguments": arguments})
        return {"warrant": str(reply["warrant"]), "signature": str(reply["signature"])}

    def shutdown(self) -> None:
        try:
            self._rpc({"op": "shutdown"})
        except OSError:
            pass


def daemonize() -> None:
    """Detach so the holder is not a child of the process that started it."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.umask(0o077)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    if devnull > 2:
        os.close(devnull)


def main() -> None:
    import argparse
    import signal

    parser = argparse.ArgumentParser(description="Tenuo holder process")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--pid", default="")
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    assert_no_holder_secret()
    if args.daemon:
        daemonize()
    if args.pid:
        Path(args.pid).write_text(str(os.getpid()), encoding="utf-8")
    allow = os.environ.get("TENUO_TOOL_ALLOWLIST")
    allowlist = [item.strip() for item in allow.split(",") if item.strip()] if allow else None
    server = HolderServer(args.socket, Holder(allowlist=allowlist))

    def _stop(*_sig: object) -> None:
        server.stop()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    server.start()
    try:
        while not server._stop.wait(timeout=1.0):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
