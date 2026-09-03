"""Holder process: key and warrant stay here; the socket never returns the secret."""

from __future__ import annotations

import base64
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tenuo import CEL, Exact
from tenuo.exceptions import IssuanceError, LimitError, MonotonicityError
from tenuo.mcp import exact_argument_constraints
from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack

from .catalog import COMMENT_BODY_CEL, PACKS, TRIPWIRE_NAMES, comment_body_digest
from .commitment import encode_proof, exchange_proof_preimage, exchange_request_hash


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
        encoded = encode_warrant_stack(warrants)
    except Exception:
        encoded = None
    if not encoded:
        raise HolderError("could not encode warrant stack")
    return encoded


def decode_exchange_stack(raw: str) -> List[Warrant]:
    """Decode an exchange response as a warrant stack.

    Cloud returns policy issuer → run warrant. A single-warrant encoding is
    still treated as a one-element stack, not as the only possible shape.
    """
    if not raw or not isinstance(raw, str):
        raise HolderError("warrant stack is required")
    try:
        stack = list(decode_warrant_stack_base64(raw))
        if stack:
            return stack
    except Exception:
        pass
    try:
        return [Warrant.from_base64(raw)]
    except Exception as exc:
        raise HolderError("warrant stack is invalid") from exc


def _warrant_expiry(warrant: Warrant) -> Optional[int]:
    exp = getattr(warrant, "expires_at", None)
    if exp is None:
        return None
    if callable(exp):
        exp = exp()
    if exp is None:
        return None
    if hasattr(exp, "timestamp"):
        return int(exp.timestamp())
    try:
        return int(exp)
    except (TypeError, ValueError):
        return None


def bind_call_arguments(tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Add body_sha256 for comment calls so the leaf digest is present at verify."""
    bound = dict(arguments)
    body = bound.get("body")
    if tool == "github.add_comment" and isinstance(body, str):
        bound["body_sha256"] = comment_body_digest(body)
    return bound


def _derive_leaf(warrant: Warrant, key: SigningKey, tool: str, arguments: Dict[str, Any]) -> Tuple[Warrant, SigningKey]:
    leaf_key = SigningKey.generate()
    constraints = exact_argument_constraints(arguments)
    body = arguments.get("body")
    if isinstance(body, str):
        # Size CEL stays on the chain; Exact(body) cannot replace it.
        constraints["body"] = CEL(COMMENT_BODY_CEL)
        constraints["body_sha256"] = Exact(comment_body_digest(body))
    leaf = (
        warrant.grant_builder()
        .capability(tool, constraints)
        .holder(leaf_key.public_key)
        .ttl(30)
        .terminal()
        .grant(key)
    )
    if not leaf.is_terminal():
        raise HolderError("derived leaf is not terminal")
    return leaf, leaf_key


class Holder:
    """In-process holder used by the socket server and by tests."""

    def __init__(self, *, allowlist: Optional[List[str]] = None, key: Optional[SigningKey] = None) -> None:
        assert_no_holder_secret()
        self._key = key or SigningKey.generate()
        self._stack: List[Warrant] = []
        self._warrant: Optional[Warrant] = None
        self._allowlist = allowlist
        self._expires_at: Optional[int] = None

    def public_key_hex(self) -> str:
        return self._key.public_key.to_bytes().hex()

    def set_warrant(self, warrant_b64: str) -> None:
        stack = decode_exchange_stack(warrant_b64)
        self._stack = stack
        self._warrant = stack[-1]
        expiries = [value for value in (_warrant_expiry(item) for item in stack) if value is not None]
        self._expires_at = min(expiries) if expiries else None

    def expired(self, *, now: Optional[int] = None) -> bool:
        if self._expires_at is None:
            return False
        return (now if now is not None else int(time.time())) >= self._expires_at

    def tools(self) -> List[str]:
        if self._warrant is None:
            return []
        named = set(_warrant_tools(self._warrant))
        catalog = {spec.name for pack in PACKS.values() for spec in pack}
        chosen = sorted((named & catalog) - TRIPWIRE_NAMES)
        if self._allowlist is not None:
            chosen = [name for name in chosen if name in self._allowlist]
        return chosen

    def sign_exchange(
        self,
        *,
        issuer: str,
        jti: str,
        ttl_seconds: int,
        capabilities: Dict[str, Any],
        task_binding: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Sign Cloud's compact exchange commitment. The private key never leaves."""
        request_hash = exchange_request_hash(
            issuer=issuer,
            jti=jti,
            holder_public_key=self.public_key_hex(),
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
            task_binding=task_binding,
        )
        signature = self._key.sign_raw(exchange_proof_preimage(request_hash))
        return encode_proof(bytes(signature))

    def envelope(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if self._warrant is None:
            raise HolderError("no warrant has been set")
        ts = int(time.time())
        raw_arguments = dict(arguments)
        bound_arguments = bind_call_arguments(tool, raw_arguments)
        parents = list(self._stack)
        try:
            leaf, leaf_key = _derive_leaf(self._warrant, self._key, tool, bound_arguments)
        except (MonotonicityError, LimitError, IssuanceError):
            # Core refused the grant. Present the parents so the gateway can
            # verify the chain and sign a denial. This envelope cannot allow:
            # the run warrant is not terminal.
            try:
                sig = self._warrant.sign(self._key, tool, raw_arguments, ts)
                stack = _encode_stack(parents)
            except Exception as exc:
                raise HolderError("could not sign") from exc
            return {
                "warrant": stack,
                "signature": base64.b64encode(bytes(sig)).decode(),
                "arguments": raw_arguments,
                "leaf_derived": False,
            }
        except HolderError:
            raise
        except Exception as exc:
            raise HolderError("could not derive terminal leaf") from exc
        sig = leaf.sign(leaf_key, tool, bound_arguments, ts)
        return {
            "warrant": _encode_stack(parents + [leaf]),
            "signature": base64.b64encode(bytes(sig)).decode(),
            "arguments": bound_arguments,
            "leaf_derived": True,
        }


def _handle(holder: Holder, message: Dict[str, Any]) -> Dict[str, Any]:
    op = message.get("op")
    if op == "public_key":
        return {"ok": True, "public_key": holder.public_key_hex()}
    if op == "set_warrant":
        raw = message.get("warrant")
        if not isinstance(raw, str) or not raw:
            return {"ok": False, "error": "warrant is required"}
        try:
            holder.set_warrant(raw)
        except HolderError as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True}
    if op == "sign_exchange":
        issuer = message.get("issuer")
        jti = message.get("jti")
        ttl = message.get("ttl_seconds")
        capabilities = message.get("capabilities")
        task_binding = message.get("task_binding")
        if not isinstance(issuer, str) or not issuer or not isinstance(jti, str) or not jti:
            return {"ok": False, "error": "issuer and jti are required"}
        try:
            ttl_i = int(ttl)
        except (TypeError, ValueError):
            return {"ok": False, "error": "ttl_seconds is required"}
        if not isinstance(capabilities, dict) or not capabilities:
            return {"ok": False, "error": "capabilities are required"}
        if task_binding is not None and not isinstance(task_binding, dict):
            return {"ok": False, "error": "task_binding must be a mapping"}
        try:
            proof = holder.sign_exchange(
                issuer=issuer,
                jti=jti,
                ttl_seconds=ttl_i,
                capabilities=capabilities,
                task_binding=task_binding,
            )
        except Exception:
            return {"ok": False, "error": "could not sign exchange commitment"}
        return {"ok": True, "holder_proof": proof}
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
            if self.holder.expired():
                self._stop.set()
                return
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

    def sign_exchange(
        self,
        *,
        issuer: str,
        jti: str,
        ttl_seconds: int,
        capabilities: Dict[str, Any],
        task_binding: Optional[Dict[str, Any]] = None,
    ) -> str:
        reply = self._rpc(
            {
                "op": "sign_exchange",
                "issuer": issuer,
                "jti": jti,
                "ttl_seconds": ttl_seconds,
                "capabilities": capabilities,
                "task_binding": task_binding,
            }
        )
        return str(reply["holder_proof"])

    def tools(self) -> List[str]:
        return list(self._rpc({"op": "tools"})["tools"])

    def envelope(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        reply = self._rpc({"op": "envelope", "tool": tool, "arguments": arguments})
        payload: Dict[str, Any] = {
            "warrant": str(reply["warrant"]),
            "signature": str(reply["signature"]),
            "leaf_derived": bool(reply.get("leaf_derived")),
        }
        if isinstance(reply.get("arguments"), dict):
            payload["arguments"] = dict(reply["arguments"])
        return payload

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
