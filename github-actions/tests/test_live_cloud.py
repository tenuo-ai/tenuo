"""Live Cloud /v1/exchange. Off unless TENUO_LIVE_CLOUD=1."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest
from starlette.testclient import TestClient

pytest.importorskip("tenuo_core")

from tenuo_core import decode_warrant_stack_base64

from tenuo_gha.action import ActionError, _parse_trusted_roots, run_job
from tenuo_gha.app import Gateway
from tenuo_gha.config import GatewayConfig
from tenuo_gha.holder import HolderClient, HolderServer
from tenuo_gha.http import build_http
from tenuo_gha.live import (
    LiveError,
    app_credentials_from_env,
    close_issue,
    create_issue,
    find_comment,
    repo_info,
    _write_secret_mount,
)
from tenuo_gha.oidc import OidcError, fetch_actions_oidc
from tenuo_gha.shim import call_gateway
from tenuo import SigningKey


class _GatewayHttp:
    def __init__(self, app) -> None:
        self._client = TestClient(app)

    def post(self, url, headers=None, json=None):
        return self._client.post(urlparse(url).path or url, headers=headers, json=json)

    def close(self) -> None:
        return None


class _CountGithub:
    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls: list[str] = []

    def call(self, spec, arguments):
        self.calls.append(spec.name)
        return self._inner.call(spec, arguments)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _oidc(audience: str) -> str:
    token = os.environ.get("TENUO_OIDC_TOKEN", "").strip()
    if token:
        return token
    try:
        return fetch_actions_oidc(audience)
    except OidcError as exc:
        raise pytest.skip(str(exc)) from exc


@pytest.mark.live
def test_live_cloud_exchange_stack_leaf_one_call_trust_and_receipts(tmp_path):
    if os.environ.get("TENUO_LIVE_CLOUD") != "1":
        pytest.skip("set TENUO_LIVE_CLOUD=1 to call Cloud /v1/exchange")
    exchange_url = (os.environ.get("TENUO_EXCHANGE_URL") or "").rstrip("/")
    audience = (os.environ.get("TENUO_EXCHANGE_AUDIENCE") or "").strip()
    roots = _parse_trusted_roots(
        os.environ.get("TENUO_TRUSTED_ROOTS") or os.environ.get("TENUO_ROOT_PUBLIC_KEY") or ""
    )
    if not exchange_url or not audience or not roots:
        pytest.skip("set TENUO_EXCHANGE_URL, TENUO_EXCHANGE_AUDIENCE, and TENUO_TRUSTED_ROOTS")
    try:
        app = app_credentials_from_env()
    except LiveError as exc:
        pytest.skip(str(exc))
    if app is None:
        pytest.skip("set TENUO_GITHUB_APP_ID and TENUO_GITHUB_APP_KEY_FILE")

    repository = os.environ.get("TENUO_LIVE_GITHUB_REPO", "aimable100/tenuo-github-agentic-demo")
    foreign = os.environ.get("TENUO_LIVE_GITHUB_FOREIGN", "aimable100/tenuo-agentic-canary-private")
    issuer = SigningKey.generate()
    receipt = SigningKey.generate()
    pem = Path(app["key_file"]).read_bytes()
    mount = _write_secret_mount(tmp_path, issuer=issuer, receipt=receipt, app_pem=pem)
    receipts = tmp_path / "receipts.jsonl"
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": list(roots)},
            "signing": {
                "profile": "secret",
                "secret": {
                    "mount": str(mount),
                    "receipt_key": "receipt.pem",
                    "github_app_key": "app.pem",
                },
            },
            "role": "gateway",
            "tools": {"packs": ["github-triage"]},
            "credentials": {
                "github": {
                    "provider": "app",
                    "app_id": app["app_id"],
                    "api_url": "https://api.github.com",
                    **({"installation_id": app["installation_id"]} if app["installation_id"] else {}),
                }
            },
            "receipts": {"path": str(receipts)},
        },
        environ={"TENUO_ROLE": "gateway"},
        scan_roots=[tmp_path],
    )
    gateway = Gateway(config)
    counter = _CountGithub(gateway.github)
    gateway.github = counter
    token = gateway.github.token_for(repository)
    source = repo_info(token, repository)
    issue = None
    server = None
    cloud = httpx.Client(timeout=30.0)
    try:
        issue = create_issue(
            token,
            source["full_name"],
            title="Tenuo live Cloud e2e — disposable",
            body="Disposable target. Closed automatically.",
        )
        socket = Path(f"/tmp/tenuo-live-cloud-{issue}.sock")
        if socket.exists():
            socket.unlink()
        server = HolderServer(socket)
        server.start()
        local = _GatewayHttp(build_http(config, gateway=gateway))
        body = f"Authorized through Cloud /v1/exchange on issue {issue}."
        minted = run_job(
            gateway_url="http://gateway",
            exchange_url=exchange_url,
            audience=audience,
            socket_path=socket,
            mcp_config=tmp_path / "mcp-config.json",
            event_name="issues",
            repository=source["full_name"],
            event={"issue": {"number": issue}},
            oidc_token=_oidc(audience),
            environ={"PATH": "/usr/bin"},
            http=cloud,
            holder_server=server,
            trusted_roots=roots,
        )
        tools = set(HolderClient(socket).tools())
        assert tools == {
            "github.get_issue",
            "github.list_issue_comments",
            "github.add_comment",
        }
        args = {
            "repository": source["full_name"],
            "issue": issue,
            "body": body,
        }
        envelope = HolderClient(socket).envelope("github.add_comment", args)
        assert envelope["leaf_derived"] is True
        presented = decode_warrant_stack_base64(envelope["warrant"])
        assert len(presented) == 3
        assert not presented[0].is_terminal()
        assert not presented[1].is_terminal()
        assert presented[-1].is_terminal()
        outcome = call_gateway("http://gateway", "github.add_comment", args, envelope, client=local)
        assert outcome["allowed"] is True
        assert counter.calls == ["github.add_comment"]

        denied_args = {"repository": foreign, "issue": 1}
        denied_env = HolderClient(socket).envelope("github.get_issue", denied_args)
        denied = call_gateway("http://gateway", "github.get_issue", denied_args, denied_env, client=local)
        assert denied["allowed"] is False
        assert counter.calls == ["github.add_comment"]

        assert gateway.flush_receipts()
        journal = receipts.read_text(encoding="utf-8")
        assert journal.strip()
        assert "BEGIN " not in journal
        assert "installation-token" not in journal
        assert minted["warrant_id"]
        comment = find_comment(token, source["full_name"], issue, body)
        assert comment and comment.startswith("https://github.com/")
    except ActionError as exc:
        pytest.fail(str(exc))
    finally:
        if server is not None:
            server.stop()
        cloud.close()
        if issue is not None:
            close_issue(token, source["full_name"], issue)
