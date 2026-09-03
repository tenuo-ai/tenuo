"""GitHub App installation tokens and generated tool HTTP calls."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote

import httpx

from .catalog import ToolSpec
from .config import ConfigError, GatewayConfig

MintToken = Callable[[str], Tuple[str, int]]
SignAppJwt = Callable[[str], str]


class GitHubError(RuntimeError):
    """A GitHub API or token-mint failure. Never includes a token."""


def format_path(template: str, arguments: Dict[str, Any]) -> str:
    """Percent-encode path arguments. Repository keeps its slash."""
    encoded = {}
    for key, value in arguments.items():
        text = str(value)
        encoded[key] = quote(text, safe="/") if key == "repository" else quote(text, safe="")
    return template.format(**encoded)


def parse_github_expiry(value: Any) -> int:
    """Unix timestamp from GitHub's ``expires_at`` field."""
    if isinstance(value, (int, float)) and value > 0:
        return int(value)
    if isinstance(value, str) and value.strip():
        raw = value.strip().replace("Z", "+00:00")
        try:
            return int(datetime.fromisoformat(raw).timestamp())
        except ValueError:
            pass
    raise GitHubError("installation token mint returned no expiry")


def _format_template(template: Any, arguments: Dict[str, Any]) -> Any:
    if isinstance(template, str):
        if template.startswith("{") and template.endswith("}") and template[1:-1] in arguments:
            return arguments[template[1:-1]]
        return template.format(**arguments)
    if isinstance(template, dict):
        return {key: _format_template(value, arguments) for key, value in template.items()}
    if isinstance(template, list):
        return [_format_template(item, arguments) for item in template]
    return template


def _project(payload: Any, mapping: Optional[Dict[str, str]]) -> Any:
    if mapping is None or not isinstance(payload, dict):
        return payload
    return {out: payload.get(src) for out, src in mapping.items()}


class GitHubApp:
    """Mint and cache installation tokens. Tokens stay in this object."""

    def __init__(
        self,
        config: GatewayConfig,
        *,
        client: Optional[httpx.Client] = None,
        mint_token: Optional[MintToken] = None,
        sign_app_jwt: Optional[SignAppJwt] = None,
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        if not config.github_app_id:
            raise ConfigError("credentials.github.app_id is required")
        self._app_id = config.github_app_id
        self._api = config.github_api_url
        self._installation_id = config.github_installation_id
        self._client = client or httpx.Client(base_url=self._api, timeout=20.0)
        self._mint_token = mint_token
        self._sign_app_jwt = sign_app_jwt
        self._now = now
        self._cache: Dict[str, Tuple[str, int]] = {}

    def token_for(self, repository: str) -> str:
        now = self._now()
        cached = self._cache.get(repository)
        if cached and now < cached[1] - 300:
            return cached[0]
        token, expires_at = self._mint(repository)
        self._cache[repository] = (token, expires_at)
        return token

    def _http(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        # Blocking GitHub HTTP is acceptable for a single-tenant process.
        # An async client can replace this later without changing call().
        try:
            return self._client.request(method, url, **kwargs)
        except httpx.HTTPError:
            raise GitHubError("GitHub request failed (network)") from None

    def _mint(self, repository: str) -> Tuple[str, int]:
        if self._mint_token is not None:
            return self._mint_token(repository)
        if self._sign_app_jwt is None:
            raise GitHubError("no App JWT signer is configured")
        app_jwt = self._sign_app_jwt(self._app_id)
        installation_id = self._installation_id or self._discover(repository, app_jwt)
        owner, _, name = repository.partition("/")
        response = self._http(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
            json={"repositories": [name]} if name else {},
        )
        if response.status_code >= 400:
            raise GitHubError(f"installation token mint failed ({response.status_code})")
        data = response.json()
        token = data.get("token")
        if not token or not isinstance(token, str):
            raise GitHubError("installation token mint returned no token")
        return token, parse_github_expiry(data.get("expires_at"))

    def _discover(self, repository: str, app_jwt: str) -> str:
        owner, _, name = repository.partition("/")
        response = self._http(
            "GET",
            f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}/installation",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
        )
        if response.status_code >= 400:
            raise GitHubError(f"installation discovery failed ({response.status_code})")
        installation_id = response.json().get("id")
        if installation_id is None:
            raise GitHubError("installation discovery returned no id")
        return str(installation_id)

    def call(self, spec: ToolSpec, arguments: Dict[str, Any]) -> Any:
        if spec.tripwire or not spec.path:
            raise GitHubError(f"{spec.name} is not executable")
        token = self.token_for(str(arguments["repository"]))
        path = format_path(spec.path, arguments)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        }
        body = _format_template(spec.body, arguments) if spec.body else None
        response = self._http(spec.method, path, headers=headers, json=body)
        if response.status_code >= 400:
            raise GitHubError(f"{spec.name} failed ({response.status_code})")
        if response.status_code == 204 or not response.content:
            return {"ok": True}
        return _project(response.json(), spec.response)
