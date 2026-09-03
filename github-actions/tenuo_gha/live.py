"""Live GitHub mutation: disposable issue, holder path, then close.

The harness injects a personal token through ``mint_token``. That is not an
App JWT mint; the first real App signing path is still the unit test that
parses ``expires_at``. The token stays in this process and the gateway cache.
It is never passed to the holder, the shim, or mcp_config.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient
from tenuo_core import SigningKey

from .action import run_job
from .app import Gateway
from .check import CheckRow, all_passed, format_table, run_agent_table
from .config import GatewayConfig
from .exchange import Exchange
from .github import GitHubApp, GitHubError
from .holder import HolderClient, HolderServer
from .http import build_http


AUDIENCE = "tenuo:org/live"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"


class LiveError(RuntimeError):
    """Live harness failed. Never includes a token."""


@dataclass
class LiveResult:
    repository: str
    issue: int
    comment_url: str
    warrant_id: str
    rows: list
    receipts: str


def _token_from_env(environ: Optional[Dict[str, str]] = None) -> str:
    env = environ if environ is not None else os.environ
    token = env.get("TENUO_LIVE_GITHUB_TOKEN") or env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    if not token:
        raise LiveError("TENUO_LIVE_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN is required")
    return token


class _Http:
    def __init__(self, app) -> None:
        self._client = TestClient(app)

    def post(self, url, headers=None, json=None):
        return self._client.post(urlparse(url).path or url, headers=headers, json=json)

    def close(self) -> None:
        return None


def _rsa_jwks():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "live"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}, key


def _oidc(key, *, repository: str, repository_id: str, owner_id: str, jti: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": OIDC_ISSUER,
            "aud": AUDIENCE,
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "jti": jti,
            "repository": repository,
            "repository_id": repository_id,
            "repository_owner": repository.split("/", 1)[0],
            "repository_owner_id": owner_id,
            "job_workflow_ref": f"{repository}/.github/workflows/live.yml@refs/heads/main",
            "event_name": "issues",
            "run_id": str(now),
            "sub": f"repo:{repository}:ref:refs/heads/main",
        },
        key,
        algorithm="RS256",
        headers={"kid": "live"},
    )


def _api(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://api.github.com",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "tenuo-gha-live",
        },
        timeout=20.0,
    )


def repo_info(token: str, repository: str) -> Dict[str, str]:
    owner, _, name = repository.partition("/")
    with _api(token) as client:
        try:
            response = client.get(f"/repos/{owner}/{name}")
        except httpx.HTTPError as exc:
            raise LiveError("could not load repository") from exc
    if response.status_code >= 400:
        raise LiveError(f"could not load {repository} ({response.status_code})")
    data = response.json()
    return {
        "full_name": str(data.get("full_name") or repository),
        "id": str(data["id"]),
        "owner_id": str(data["owner"]["id"]),
    }


def create_issue(token: str, repository: str, *, title: str, body: str) -> int:
    owner, _, name = repository.partition("/")
    with _api(token) as client:
        response = client.post(f"/repos/{owner}/{name}/issues", json={"title": title, "body": body})
    if response.status_code >= 400:
        raise LiveError(f"could not create issue ({response.status_code})")
    return int(response.json()["number"])


def close_issue(token: str, repository: str, issue: int) -> None:
    owner, _, name = repository.partition("/")
    with _api(token) as client:
        try:
            client.patch(f"/repos/{owner}/{name}/issues/{issue}", json={"state": "closed"})
        except httpx.HTTPError:
            return


def find_comment(token: str, repository: str, issue: int, body: str) -> Optional[str]:
    owner, _, name = repository.partition("/")
    with _api(token) as client:
        response = client.get(f"/repos/{owner}/{name}/issues/{issue}/comments")
    if response.status_code >= 400:
        raise LiveError(f"could not list comments ({response.status_code})")
    for item in response.json():
        if item.get("body") == body:
            return str(item.get("html_url") or "")
    return None


def run_live(
    *,
    repository: str,
    foreign_repository: str,
    token: str,
    work: Path,
) -> LiveResult:
    source = repo_info(token, repository)
    nonce = uuid.uuid4().hex[:8]
    body = f"Tenuo live e2e {nonce} — authorized by a holder-bound warrant."
    issue = create_issue(
        token,
        source["full_name"],
        title=f"Tenuo live e2e — disposable {nonce}",
        body="Disposable target. Closed automatically.",
    )
    issuer = SigningKey.generate()
    receipts = work / "receipts.jsonl"
    socket = work / "holder.sock"
    if len(str(socket)) > 100:
        socket = Path(f"/tmp/tenuo-live-{nonce}.sock")
    config = GatewayConfig.from_mapping(
        {
            "version": 1,
            "trust": {"root_public_keys": ["${TENUO_ROOT_PUBLIC_KEY}"], "issuer": OIDC_ISSUER},
            "signing": {"provider": "memory"},
            "role": "both",
            "ceiling": {"repositories": [source["full_name"], foreign_repository]},
            "tools": {"packs": ["github-triage"]},
            "credentials": {
                "github": {
                    "provider": "app",
                    "app_id": "live",
                    "api_url": "https://api.github.com",
                    "installation_id": "1",
                }
            },
            "exchange": {
                "audience": AUDIENCE,
                "ttl_max": "15m",
                "jwks_url": "https://example.invalid/jwks",
                "conditions": {
                    "repository_owner_id": source["owner_id"],
                    "repository_id": [source["id"]],
                    "event_name": ["issues"],
                },
            },
            "receipts": {"path": str(receipts)},
        },
        environ={
            "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1",
            "TENUO_ALLOW_COMBINED_ROLES": "1",
            "TENUO_ROLE": "both",
            "TENUO_ROOT_PUBLIC_KEY": issuer.public_key.to_bytes().hex(),
        },
    )
    github = GitHubApp(
        config,
        mint_token=lambda _repo: (token, int(time.time()) + 3600),
    )
    gateway = Gateway(config, github=github)
    jwks, rsa_key = _rsa_jwks()
    exchange = Exchange(config, issuer_key=issuer, jwks=jwks)
    http = _Http(build_http(config, exchange=exchange, gateway=gateway))
    server = HolderServer(socket)
    server.start()
    rows: list[CheckRow] = []
    comment_url = ""
    warrant_id = ""
    try:
        minted = run_job(
            gateway_url="http://test",
            exchange_url="http://test",
            audience=AUDIENCE,
            socket_path=socket,
            mcp_config=work / "mcp-config.json",
            event_name="issues",
            repository=source["full_name"],
            event={"issue": {"number": issue}},
            oidc_token=_oidc(
                rsa_key,
                repository=source["full_name"],
                repository_id=source["id"],
                owner_id=source["owner_id"],
                jti=f"live-{nonce}",
            ),
            environ={"PATH": "/usr/bin", "TENUO_ALLOW_INSECURE_MEMORY_KEYS": "1"},
            http=http,
            holder_server=server,
        )
        warrant_id = minted["warrant_id"]
        config_text = Path(minted["mcp_config"]).read_text(encoding="utf-8")
        if token in config_text or "TENUO_HOLDER_SECRET" in config_text:
            raise LiveError("mcp_config contained a secret")
        rows = run_agent_table(
            HolderClient(socket),
            "http://test",
            bound_repository=source["full_name"],
            bound_issue=issue,
            foreign_repository=foreign_repository,
            comment_body=body,
            client=http,
            environ={"PATH": "/usr/bin"},
        )
        if not all_passed(rows):
            raise LiveError("scenario mismatch:\n" + format_table(rows))
        gateway.flush_receipts()
        comment_url = find_comment(token, source["full_name"], issue, body) or ""
        if not comment_url:
            raise LiveError("authorized comment was not on the issue")
    finally:
        server.stop()
        close_issue(token, source["full_name"], issue)
    return LiveResult(
        repository=source["full_name"],
        issue=issue,
        comment_url=comment_url,
        warrant_id=warrant_id,
        rows=rows,
        receipts=receipts.read_text(encoding="utf-8") if receipts.exists() else "",
    )


def main() -> None:
    import argparse
    import tempfile

    parser = argparse.ArgumentParser(description="Live GitHub e2e through the holder")
    parser.add_argument(
        "--repository",
        default=os.environ.get("TENUO_LIVE_GITHUB_REPO", "aimable100/tenuo-github-agentic-demo"),
    )
    parser.add_argument(
        "--foreign-repository",
        default=os.environ.get("TENUO_LIVE_GITHUB_FOREIGN", "aimable100/tenuo-agentic-canary-private"),
    )
    args = parser.parse_args()
    token = _token_from_env()
    work = Path(tempfile.mkdtemp(prefix="tenuo-live-"))
    try:
        result = run_live(
            repository=args.repository,
            foreign_repository=args.foreign_repository,
            token=token,
            work=work,
        )
    except GitHubError as exc:
        raise SystemExit(str(exc)) from exc
    print(format_table(result.rows))
    print(f"issue {result.issue} comment {result.comment_url}")
    print(f"warrant {result.warrant_id}")
    if not result.receipts.strip():
        raise SystemExit("no receipts")


if __name__ == "__main__":
    main()
