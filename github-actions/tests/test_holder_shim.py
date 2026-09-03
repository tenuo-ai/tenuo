"""Holder process keeps the key; the shim and agent never see it."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

pytest.importorskip("tenuo_core")

from tenuo import Exact, Pattern, Range
from tenuo.mcp import TENUO_CONSTRAINT_VIOLATION, TENUO_TOOL_NOT_AUTHORIZED
from tenuo_core import PublicKey, SigningKey, Warrant

from tenuo_gha.action import (
    deliver_warrant,
    guardrails,
    holder_work_dir,
    spawn_holder,
    start_holder,
    stop_holder,
    write_mcp_config,
)
from tenuo_gha.app import Gateway
from tenuo_gha.config import ConfigError, GatewayConfig
from tenuo_gha.github import GitHubApp
from tenuo_gha.holder import Holder, HolderClient, HolderError, HolderServer, _handle
from tenuo_gha.http import build_http
from tenuo_gha.shim import call_gateway


def _config(tmp_path: Path, issuer: SigningKey, *, with_app: bool = True) -> GatewayConfig:
    raw: dict = {
        "version": 1,
        "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
        "signing": {"provider": "memory"},
        "ceiling": {"repositories": ["acme/widgets"]},
        "tools": {"packs": ["github-triage"]},
        "receipts": {"path": str(tmp_path / "receipts.jsonl")},
    }
    if with_app:
        raw["credentials"] = {
            "github": {
                "provider": "app",
                "app_id": "123",
                "api_url": "https://api.github.com",
                "installation_id": "9",
            }
        }
    return GatewayConfig.from_mapping(
        raw,
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ROLE": "gateway",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )


def _warrant(issuer: SigningKey, holder_hex: str) -> Warrant:
    holder_pub = PublicKey.from_bytes(bytes.fromhex(holder_hex))
    return (
        Warrant.mint_builder()
        .capability("github.get_issue", repository=Exact("acme/widgets"), issue=Range(4127, 4127))
        .capability(
            "github.add_comment",
            repository=Exact("acme/widgets"),
            issue=Range(4127, 4127),
            body=Pattern("*"),
        )
        .holder(holder_pub)
        .ttl(900)
        .mint(issuer)
    )


def _mock_github(tmp_path: Path, issuer: SigningKey, recorded: list) -> Gateway:
    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((request.method, request.url.path, request.read()))
        if request.method == "POST" and request.url.path.endswith("/comments"):
            return httpx.Response(
                201,
                json={"id": 77, "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-77"},
            )
        return httpx.Response(404, json={"message": "not mocked"})

    github = GitHubApp(
        _config(tmp_path, issuer),
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://api.github.com",
        ),
        mint_token=lambda _repo: ("installation-token", int(time.time()) + 3600),
    )
    return Gateway(_config(tmp_path, issuer), github=github)


def test_holder_secret_env_refuses_before_construct(monkeypatch):
    monkeypatch.setenv("TENUO_HOLDER_SECRET", "should-never-be-read")
    with pytest.raises(HolderError, match="TENUO_HOLDER_SECRET"):
        Holder()


def test_holder_fd_env_is_a_startup_error(monkeypatch):
    monkeypatch.setenv("TENUO_HOLDER_FD", "3")
    with pytest.raises(HolderError, match="TENUO_HOLDER_FD"):
        Holder()


def test_config_refuses_holder_fd(tmp_path):
    issuer = SigningKey.generate()
    with pytest.raises(ConfigError, match="TENUO_HOLDER_FD"):
        GatewayConfig.from_mapping(
            {
                "version": 1,
                "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"]},
                "signing": {"provider": "memory"},
                "receipts": {"path": str(tmp_path / "r.jsonl")},
            },
            environ={
                "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
                "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
                "TENUO_HOLDER_FD": "3",
            },
        )


def test_holder_work_dir_includes_the_run_id(tmp_path):
    dest = holder_work_dir(tmp_path, run_id="33802215001")
    assert dest.name == "33802215001"
    assert dest.is_dir()


def test_holder_is_expired_after_warrant_ttl():
    issuer = SigningKey.generate()
    holder = Holder()
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    holder._expires_at = int(time.time()) - 1
    assert holder.expired()


def test_guardrails_refuse_holder_secret():
    with pytest.raises(HolderError, match="TENUO_HOLDER_SECRET"):
        guardrails({"TENUO_HOLDER_SECRET": "x", "PATH": "/usr/bin"})


def test_export_key_is_not_supported():
    holder = Holder()
    reply = _handle(holder, {"op": "export_key"})
    assert reply == {"ok": False, "error": "not supported"}
    dumped = json.dumps(reply)
    assert "secret" not in dumped
    assert holder.public_key_hex() not in dumped


def _sock(name: str) -> Path:
    path = Path(f"/tmp/tenuo-htest-{name}.sock")
    if path.exists():
        path.unlink()
    return path


def test_socket_mode_is_owner_only():
    path = _sock("mode")
    with HolderServer(path) as server:
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600
        client = HolderClient(path)
        assert len(client.public_key_hex()) == 64
        server.stop()


def test_tools_are_the_warrant_catalog_intersection():
    issuer = SigningKey.generate()
    holder = Holder()
    warrant = _warrant(issuer, holder.public_key_hex())
    holder.set_warrant(warrant.to_base64())
    tools = holder.tools()
    assert "github.get_issue" in tools
    assert "github.add_comment" in tools
    assert "github.workflow_dispatch" not in tools
    assert "github.get_file_contents" not in tools


def test_allowlist_filters_advertised_tools():
    issuer = SigningKey.generate()
    holder = Holder(allowlist=["github.get_issue"])
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    assert holder.tools() == ["github.get_issue"]


def test_holder_envelope_allows_a_bound_comment(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway = _mock_github(tmp_path, issuer, recorded)
    path = _sock("comment")
    with HolderServer(path) as server:
        client = HolderClient(path)
        deliver_warrant(path, _warrant(issuer, client.public_key_hex()).to_base64())
        args = {"repository": "acme/widgets", "issue": 4127, "body": "looks good"}
        envelope = client.envelope("github.add_comment", args)
        assert "signature" in envelope
        assert envelope["warrant"]
        result, payload = gateway.execute(
            "github.add_comment",
            args,
            meta={"tenuo": envelope},
        )
        assert result.allowed
        assert payload == {
            "comment_id": 77,
            "html_url": "https://github.com/acme/widgets/issues/4127#issuecomment-77",
        }
        assert recorded
        server.stop()


def test_holder_widening_still_presents_parent(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway = _mock_github(tmp_path, issuer, recorded)
    holder = Holder()
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    args = {"repository": "acme/payments-internal", "issue": 1}
    envelope = holder.envelope("github.get_issue", args)
    result, payload = gateway.execute("github.get_issue", args, meta={"tenuo": envelope})
    assert not result.allowed
    assert result.error_code == TENUO_CONSTRAINT_VIOLATION
    assert result.presented_chain
    assert payload is None
    assert recorded == []
    assert gateway.flush_receipts()
    assert (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").strip()


def test_tripwire_envelope_is_denied_without_github(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway = _mock_github(tmp_path, issuer, recorded)
    holder = Holder()
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    args = {"repository": "acme/widgets", "workflow": "release.yml"}
    envelope = holder.envelope("github.workflow_dispatch", args)
    result, payload = gateway.execute("github.workflow_dispatch", args, meta={"tenuo": envelope})
    assert not result.allowed
    assert result.error_code == TENUO_TOOL_NOT_AUTHORIZED
    assert payload is None
    assert recorded == []


def test_http_call_uses_the_holder_envelope(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway = _mock_github(tmp_path, issuer, recorded)
    holder = Holder()
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    args = {"repository": "acme/widgets", "issue": 4127, "body": "ship it"}
    envelope = holder.envelope("github.add_comment", args)
    client = TestClient(build_http(gateway.config, gateway=gateway))
    response = client.post(
        "/v1/call",
        json={"tool": "github.add_comment", "arguments": args, "meta": {"tenuo": envelope}},
    )
    assert response.status_code == 200
    assert response.json()["allowed"] is True
    assert response.json()["result"]["comment_id"] == 77


def test_shim_posts_envelope_and_maps_denial(tmp_path):
    issuer = SigningKey.generate()
    recorded: list = []
    gateway = _mock_github(tmp_path, issuer, recorded)
    holder = Holder()
    holder.set_warrant(_warrant(issuer, holder.public_key_hex()).to_base64())
    args = {"repository": "acme/payments-internal", "issue": 1}
    envelope = holder.envelope("github.get_issue", args)
    starlette = TestClient(build_http(gateway.config, gateway=gateway))

    class _Http:
        def post(self, url, json=None):
            return starlette.post("/v1/call", json=json)

        def close(self) -> None:
            return None

    outcome = call_gateway("http://test", "github.get_issue", args, envelope, client=_Http())
    assert outcome["allowed"] is False
    assert "DENIED" in outcome["message"]
    assert TENUO_CONSTRAINT_VIOLATION in outcome["message"]
    assert recorded == []


def test_mcp_config_has_no_secret(tmp_path):
    path = write_mcp_config(
        tmp_path / "mcp-config.json",
        socket=str(tmp_path / "holder.sock"),
        gateway_url="https://gateway.example",
    )
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text)
    env = payload["mcpServers"]["tenuo"]["env"]
    assert env["TENUO_HOLDER_SOCKET"].endswith("holder.sock")
    assert env["TENUO_GATEWAY_URL"] == "https://gateway.example"
    assert "TENUO_HOLDER_SECRET" not in env
    assert "TENUO_HOLDER_FD" not in text
    assert "ghs_" not in text


def test_long_socket_path_is_refused():
    path = Path("/tmp") / ("tenuo-" + ("x" * 120) + ".sock")
    with pytest.raises(HolderError, match="too long"):
        HolderServer(path).start()


def test_detached_holder_is_not_this_process():
    path = _sock("daemon")
    pid_path = Path("/tmp/tenuo-htest-daemon.pid")
    if pid_path.exists():
        pid_path.unlink()
    spawn_holder(path, pid_path=pid_path)
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        ppid = int(subprocess.check_output(["ps", "-o", "ppid=", "-p", str(pid)], text=True).strip())
        assert ppid != os.getpid()
        client = HolderClient(path)
        assert len(client.public_key_hex()) == 64
    finally:
        stop_holder(path, pid_path)


def test_in_process_action_delivers_warrant_to_holder(tmp_path):
    issuer = SigningKey.generate()
    path = _sock("action")
    server = start_holder(path)
    try:
        client = HolderClient(path)
        deliver_warrant(path, _warrant(issuer, client.public_key_hex()).to_base64())
        assert "github.get_issue" in client.tools()
    finally:
        server.stop()
