"""Verify a GitHub Actions OIDC JWT against a JWKS."""

from __future__ import annotations

import fnmatch
import json
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional

import jwt
from jwt import PyJWK

from .config import ConfigError


class OidcError(ValueError):
    """JWT failed verification or did not match the configured conditions."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def fetch_jwks(url: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def fetch_actions_oidc(
    audience: str,
    environ: Optional[Mapping[str, str]] = None,
    *,
    opener: Optional[Callable[..., Any]] = None,
) -> str:
    """Request a GitHub Actions OIDC JWT for ``audience``."""
    import os

    env = environ if environ is not None else os.environ
    url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not token:
        raise OidcError("untrusted_workflow", "ACTIONS_ID_TOKEN_REQUEST_URL is required")
    if not audience:
        raise OidcError("untrusted_workflow", "OIDC audience is required")
    request = urllib.request.Request(
        f"{url}{'&' if '?' in url else '?'}audience={urllib.parse.quote(audience)}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(request, timeout=10.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OidcError("untrusted_workflow", "OIDC token request failed") from exc
    jwt_token = payload.get("value") or payload.get("token")
    if not jwt_token or not isinstance(jwt_token, str):
        raise OidcError("untrusted_workflow", "OIDC token request returned no token")
    return jwt_token


def _audience_values(aud: Any) -> list[str]:
    if aud is None:
        return []
    if isinstance(aud, str):
        return [aud]
    return [str(item) for item in aud]


def peek_oidc_claims(token: str) -> Dict[str, Any]:
    """Read iss/jti for the exchange commitment. This is not verification."""
    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except jwt.InvalidTokenError as exc:
        raise OidcError("untrusted_workflow", "malformed token") from exc
    if not isinstance(payload, dict):
        raise OidcError("untrusted_workflow", "malformed token")
    return payload


def verify_oidc(
    token: str,
    *,
    issuer: str,
    audience: str,
    jwks: Mapping[str, Any],
    clock_tolerance_seconds: int = 30,
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify signature, issuer, audience, and expiry. Returns claims."""
    if not token:
        raise OidcError("untrusted_workflow", "missing bearer token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise OidcError("untrusted_workflow", f"malformed token: {exc}") from exc
    kid = header.get("kid")
    keys = list(jwks.get("keys") or [])
    matching = [key for key in keys if not kid or key.get("kid") == kid]
    if not matching:
        matching = keys
    last_error: Exception | None = None
    claims: Dict[str, Any] | None = None
    for key in matching:
        try:
            claims = jwt.decode(
                token,
                PyJWK.from_dict(dict(key)).key,
                algorithms=["RS256"],
                issuer=issuer,
                audience=audience,
                leeway=clock_tolerance_seconds,
                options={"require": ["exp", "iss", "aud"]},
            )
            break
        except jwt.InvalidTokenError as exc:
            last_error = exc
    if claims is None:
        raise OidcError("untrusted_workflow", f"token rejected: {last_error}")
    if now is None:
        now = int(time.time())
    exp = int(claims["exp"])
    if exp + clock_tolerance_seconds < now:
        raise OidcError("untrusted_workflow", "token expired")
    if audience not in _audience_values(claims.get("aud")):
        raise OidcError("untrusted_workflow", "audience mismatch")
    return claims


def assert_conditions(
    claims: Mapping[str, Any],
    *,
    repository_owner_id: Optional[str],
    repository_ids: list[str],
    job_workflow_ref: Optional[str],
    event_names: list[str],
    repositories: list[str],
) -> None:
    """Match numeric ids, workflow ref, event, and repository ceiling."""
    if repository_owner_id is not None:
        got = str(claims.get("repository_owner_id") or "")
        if got != str(repository_owner_id):
            raise OidcError("untrusted_workflow", "repository_owner_id mismatch")
    if repository_ids:
        got = str(claims.get("repository_id") or "")
        if got not in {str(item) for item in repository_ids}:
            raise OidcError("untrusted_workflow", "repository_id mismatch")
    ref = str(claims.get("job_workflow_ref") or "")
    if job_workflow_ref and not fnmatch.fnmatch(ref, job_workflow_ref):
        raise OidcError("untrusted_workflow", "job_workflow_ref mismatch")
    event = str(claims.get("event_name") or "")
    if event_names and event not in event_names:
        raise OidcError("untrusted_workflow", "event_name mismatch")
    repo = str(claims.get("repository") or "")
    if not repo:
        raise OidcError("untrusted_workflow", "repository claim missing")
    if repositories and repo not in repositories:
        raise OidcError("outside_ceiling", "repository is outside the ceiling")


def load_jwks(
    *,
    jwks: Optional[Mapping[str, Any]],
    jwks_url: Optional[str],
    fetcher: Optional[Callable[[str], Mapping[str, Any]]] = None,
) -> Mapping[str, Any]:
    if jwks is not None:
        return jwks
    if not jwks_url:
        raise ConfigError("exchange.jwks_url is required when no JWKS is supplied")
    fetch = fetcher or fetch_jwks
    return fetch(jwks_url)
