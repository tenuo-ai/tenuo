"""Job entry: start the holder, exchange OIDC, write mcp_config."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

import httpx

from .commitment import normalize_holder_public_key
from .config import assert_no_runtime_secrets
from .holder import HolderClient, HolderError, HolderServer, assert_no_holder_secret
from .oidc import OidcError, fetch_actions_oidc, peek_oidc_claims
from .commitment import compact_task_binding
from .task import TaskError, infer_capabilities, infer_task_binding


class ActionError(RuntimeError):
    """The action could not finish. Never includes holder material."""


def holder_work_dir(base: "str | Path", *, run_id: str = "") -> Path:
    """Per-run directory so a later job cannot reuse this socket."""
    rid = (run_id or "local").strip() or "local"
    dest = Path(base) / rid
    dest.mkdir(parents=True, exist_ok=True)
    return dest


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


def cleanup_job(
    *,
    socket_path: Optional["str | Path"] = None,
    pid_path: Optional["str | Path"] = None,
    mcp_config: Optional["str | Path"] = None,
    work_dir: Optional["str | Path"] = None,
) -> None:
    """Stop the holder and remove temporary socket/config files."""
    if socket_path:
        stop_holder(socket_path, pid_path=pid_path)
    elif pid_path:
        stop_holder("", pid_path=pid_path)
    for item in (socket_path, pid_path, mcp_config):
        if not item:
            continue
        path = Path(item)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    if work_dir:
        dest = Path(work_dir)
        try:
            if dest.exists() and dest.is_dir() and not any(dest.iterdir()):
                dest.rmdir()
        except OSError:
            pass


def verify_exchange_roots(response_keys: Any, trusted_roots: List[str]) -> None:
    """Response roots must already be in configured trust. Never adopt them."""
    if not trusted_roots:
        return
    advertised = response_keys if isinstance(response_keys, list) else []
    trusted = set()
    for raw in trusted_roots:
        try:
            trusted.add(normalize_holder_public_key(str(raw)))
        except Exception as exc:
            raise ActionError("trusted root is invalid") from exc
    if not advertised:
        raise ActionError("exchange did not return root_public_keys")
    for raw in advertised:
        try:
            key = normalize_holder_public_key(str(raw))
        except Exception as exc:
            raise ActionError("exchange root_public_keys are invalid") from exc
        if key not in trusted:
            raise ActionError("exchange root_public_keys are not in configured trust")


def _parse_trusted_roots(raw: str) -> List[str]:
    text = (raw or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            loaded = json.loads(text)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, list):
            return [str(item).strip() for item in loaded if str(item).strip()]
    return [item.strip() for item in text.replace(",", " ").split() if item.strip()]


def exchange_warrant(
    exchange_url: str,
    oidc_token: str,
    *,
    holder_public_key: str,
    holder_proof: str,
    ttl_seconds: int,
    capabilities: Mapping[str, Any],
    task_binding: Optional[Mapping[str, Any]] = None,
    client: Optional[httpx.Client] = None,
) -> Dict[str, Any]:
    own = client is None
    http = client or httpx.Client(timeout=20.0)
    body: Dict[str, Any] = {
        "holder_public_key": holder_public_key,
        "holder_proof": holder_proof,
        "ttl_seconds": ttl_seconds,
        "capabilities": dict(capabilities),
    }
    binding = compact_task_binding(task_binding)
    if binding is not None:
        body["task_binding"] = binding
    try:
        response = http.post(
            exchange_url.rstrip("/") + "/v1/exchange",
            headers={"Authorization": f"Bearer {oidc_token}"},
            json=body,
        )
    finally:
        if own:
            http.close()
    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise ActionError(f"exchange returned non-JSON ({response.status_code})") from exc
    if response.status_code >= 400 or not payload.get("warrant"):
        raise ActionError(payload.get("detail") or payload.get("error") or "exchange refused")
    if payload.get("tenant_id") or payload.get("policy_id"):
        # Cloud may echo resolved ids; the action never sent them and does not store them.
        payload = {key: value for key, value in payload.items() if key not in {"tenant_id", "policy_id"}}
    return payload


def run_job(
    *,
    gateway_url: str,
    exchange_url: str,
    audience: str,
    socket_path: "str | Path",
    mcp_config: "str | Path",
    pid_path: Optional["str | Path"] = None,
    ttl_seconds: int = 900,
    event_name: str = "",
    repository: str = "",
    event: Optional[Mapping[str, Any]] = None,
    oidc_token: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
    http: Optional[httpx.Client] = None,
    holder_server: Optional[HolderServer] = None,
    fetch_oidc: Callable[[str, Mapping[str, str]], str] = fetch_actions_oidc,
    trusted_roots: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Start the holder, exchange OIDC, deliver the warrant, write mcp_config."""
    env = dict(environ if environ is not None else os.environ)
    guardrails(env)
    if holder_server is None:
        spawn_holder(socket_path, pid_path=pid_path)
    pubkey = public_key_hex(socket_path)
    token = oidc_token or fetch_oidc(audience, env)
    try:
        claims = peek_oidc_claims(token)
        capabilities = infer_capabilities(
            event_name=event_name,
            event=event,
            repository=repository,
        )
        task_binding = infer_task_binding(event_name=event_name, event=event)
    except (TaskError, OidcError) as exc:
        raise ActionError(str(exc)) from exc
    issuer = str(claims.get("iss") or "")
    jti = str(claims.get("jti") or "")
    if not issuer or not jti:
        raise ActionError("OIDC token is missing iss or jti")
    try:
        proof = HolderClient(socket_path).sign_exchange(
            issuer=issuer,
            jti=jti,
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
            task_binding=task_binding,
        )
        minted = exchange_warrant(
            exchange_url,
            token,
            holder_public_key=pubkey,
            holder_proof=proof,
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
            task_binding=task_binding,
            client=http,
        )
    except (OidcError, HolderError) as exc:
        raise ActionError(str(exc)) from exc
    verify_exchange_roots(minted.get("root_public_keys"), list(trusted_roots or []))
    deliver_warrant(socket_path, str(minted["warrant"]))
    write_mcp_config(mcp_config, socket=str(socket_path), gateway_url=gateway_url)
    return {
        "mcp_config": str(mcp_config),
        "warrant_id": str(minted.get("warrant_id") or ""),
        "expires_at": str(minted.get("expires_at") or ""),
        "gateway_url": gateway_url,
        "public_key": pubkey,
        "socket": str(socket_path),
    }


def _load_event(environ: Mapping[str, str]) -> Dict[str, Any]:
    path = environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def main() -> None:
    import argparse
    import tempfile

    parser = argparse.ArgumentParser(description="Start a Tenuo holder and exchange OIDC")
    parser.add_argument("--gateway-url", default=os.environ.get("TENUO_GATEWAY_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--exchange-url", default=os.environ.get("TENUO_EXCHANGE_URL", ""))
    parser.add_argument("--audience", default=os.environ.get("TENUO_EXCHANGE_AUDIENCE", ""))
    parser.add_argument("--ttl", default=os.environ.get("TENUO_TTL", "900"))
    parser.add_argument("--socket", default="")
    parser.add_argument("--mcp-config", default="")
    parser.add_argument("--pid", default="")
    parser.add_argument("--trusted-roots", default=os.environ.get("TENUO_TRUSTED_ROOTS", ""))
    parser.add_argument("--stop", action="store_true", help="Stop the holder and remove temp files")
    args = parser.parse_args()
    env = dict(os.environ)
    if args.stop:
        cleanup_job(
            socket_path=args.socket or None,
            pid_path=args.pid or None,
            mcp_config=args.mcp_config or None,
        )
        return
    work = holder_work_dir(
        Path(tempfile.mkdtemp(prefix="tenuo-")),
        run_id=env.get("GITHUB_RUN_ID", ""),
    )
    payload = run_job(
        gateway_url=args.gateway_url,
        exchange_url=args.exchange_url or args.gateway_url,
        audience=args.audience,
        socket_path=Path(args.socket) if args.socket else work / "holder.sock",
        mcp_config=Path(args.mcp_config) if args.mcp_config else work / "mcp-config.json",
        pid_path=Path(args.pid) if args.pid else work / "holder.pid",
        ttl_seconds=int(args.ttl),
        event_name=env.get("GITHUB_EVENT_NAME", ""),
        repository=env.get("GITHUB_REPOSITORY", ""),
        event=_load_event(env),
        environ=env,
        trusted_roots=_parse_trusted_roots(args.trusted_roots),
    )
    print(json.dumps({key: payload[key] for key in ("mcp_config", "warrant_id", "expires_at", "gateway_url", "public_key")}))
    github_output = env.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"mcp_config={payload['mcp_config']}\n")
            handle.write(f"warrant_id={payload['warrant_id']}\n")
            handle.write(f"expires_at={payload['expires_at']}\n")
            handle.write(f"gateway_url={payload['gateway_url']}\n")
            handle.write(f"public_key={payload['public_key']}\n")


if __name__ == "__main__":
    main()
