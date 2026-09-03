"""Gateway configuration. Stored tokens and PEMs are a startup error."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import yaml

_TOKEN_PREFIXES = ("ghs_", "github_pat_", "gho_", "ghu_")
_PEM_MARKERS = ("BEGIN ", "PRIVATE KEY", "-----")
_FORBIDDEN_NAMES = frozenset(
    {
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "TENUO_GITHUB_APP_PRIVATE_KEY",
        "TENUO_ISSUER_KEY",
        "TENUO_HOLDER_SECRET",
    }
)


class ConfigError(ValueError):
    """Invalid gateway configuration."""


def _expand(value: Any, environ: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in environ:
                raise ConfigError(f"unresolved environment variable ${{{key}}}")
            return environ[key]

        return re.sub(r"\$\{([^}]+)\}", repl, value)
    if isinstance(value, list):
        return [_expand(item, environ) for item in value]
    if isinstance(value, dict):
        return {key: _expand(item, environ) for key, item in value.items()}
    return value


def _looks_like_token(raw: str) -> bool:
    return any(raw.startswith(prefix) for prefix in _TOKEN_PREFIXES)


def _looks_like_pem(raw: str) -> bool:
    return any(marker in raw for marker in _PEM_MARKERS)


def assert_no_runtime_secrets(environ: Mapping[str, str]) -> None:
    """Refuse to start if a stored credential is visible in the environment."""
    for name, raw in environ.items():
        if not raw:
            continue
        if name in _FORBIDDEN_NAMES or name.endswith("_API_KEY"):
            raise ConfigError(f"{name} must not be present in the gateway environment")
        if _looks_like_token(raw):
            raise ConfigError(f"{name} looks like a GitHub token")
        if name.endswith("_KEY") or "PRIVATE_KEY" in name:
            if _looks_like_pem(raw):
                raise ConfigError(f"{name} looks like a PEM")


def _assert_no_embedded_secrets(data: Any, *, path: str = "config") -> None:
    """Refuse token or PEM material written into the YAML itself."""
    if isinstance(data, str):
        if _looks_like_token(data) or _looks_like_pem(data):
            raise ConfigError(f"{path} looks like a stored credential")
        return
    if isinstance(data, list):
        for index, item in enumerate(data):
            _assert_no_embedded_secrets(item, path=f"{path}[{index}]")
        return
    if isinstance(data, dict):
        for key, item in data.items():
            _assert_no_embedded_secrets(item, path=f"{path}.{key}")


_ROLES = frozenset({"exchange", "gateway", "both"})


def parse_duration(value: Any) -> int:
    """Parse seconds, or a string like ``15m`` / ``900s`` / ``1h``."""
    if isinstance(value, bool):
        raise ConfigError("duration must be an integer or a string")
    if isinstance(value, int):
        if value <= 0:
            raise ConfigError("duration must be positive")
        return value
    raw = str(value).strip()
    if raw.endswith("h"):
        return int(raw[:-1]) * 3600
    if raw.endswith("m"):
        return int(raw[:-1]) * 60
    if raw.endswith("s"):
        return int(raw[:-1])
    parsed = int(raw)
    if parsed <= 0:
        raise ConfigError("duration must be positive")
    return parsed


@dataclass
class GatewayConfig:
    version: int
    root_public_keys: List[str]
    packs: List[str]
    repositories: List[str]
    receipt_path: Path
    signing_provider: str
    role: str = "gateway"
    receipt_signing_key: Optional[str] = None
    exchange_signing_key: Optional[str] = None
    require_pop: bool = True
    audience: str = ""
    ttl_max: int = 900
    oidc_issuer: str = "https://token.actions.githubusercontent.com"
    jwks_url: Optional[str] = None
    clock_tolerance_seconds: int = 30
    repository_owner_id: Optional[str] = None
    repository_ids: List[str] = field(default_factory=list)
    job_workflow_ref: Optional[str] = None
    event_names: List[str] = field(default_factory=list)
    issuer_key_id: Optional[str] = None
    receipt_key_id: Optional[str] = None
    github_app_key_id: Optional[str] = None
    github_app_id: Optional[str] = None
    github_api_url: str = "https://api.github.com"
    github_installation_id: Optional[str] = None
    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], *, environ: Mapping[str, str]) -> "GatewayConfig":
        assert_no_runtime_secrets(environ)
        data = _expand(dict(raw), environ)
        if data.get("version") != 1:
            raise ConfigError(f"unsupported config version {data.get('version')!r}")

        signing = data.get("signing") or {}
        provider = signing.get("provider") or "memory"
        if provider == "memory":
            if environ.get("TENUO_ALLOW_INSECURE_MEMORY_KEYS") != "1":
                raise ConfigError(
                    "signing.provider=memory requires TENUO_ALLOW_INSECURE_MEMORY_KEYS=1"
                )
        elif provider != "kms":
            raise ConfigError(f"unsupported signing.provider {provider!r}")

        role = (environ.get("TENUO_ROLE") or data.get("role") or "gateway").strip()
        if role not in _ROLES:
            raise ConfigError(f"unsupported role {role!r}")
        if role == "both" and environ.get("TENUO_ALLOW_COMBINED_ROLES") != "1":
            raise ConfigError("role=both requires TENUO_ALLOW_COMBINED_ROLES=1")

        github_creds = (data.get("credentials") or {}).get("github") or {}
        github_app_id = None
        github_api_url = "https://api.github.com"
        github_installation_id = None
        if github_creds:
            if role == "exchange":
                raise ConfigError("exchange role cannot be configured with credentials.github")
            github_provider = github_creds.get("provider")
            if github_provider != "app":
                raise ConfigError("credentials.github.provider must be app")
            if github_creds.get("token_env") or github_creds.get("token"):
                raise ConfigError("token and token_env are not allowed")
            if github_creds.get("app_private_key_env") or github_creds.get("app_private_key"):
                raise ConfigError("app_private_key and app_private_key_env are not allowed")
            github_app_id = str(github_creds.get("app_id") or "") or None
            if not github_app_id:
                raise ConfigError("credentials.github.app_id is required")
            github_api_url = str(github_creds.get("api_url") or "https://api.github.com").rstrip("/")
            if github_creds.get("installation_id") is not None:
                github_installation_id = str(github_creds["installation_id"])
        _assert_no_embedded_secrets(data)

        kms = signing.get("kms") or {}
        issuer_key_id = kms.get("issuer_key_id") or None
        receipt_key_id = kms.get("receipt_key_id") or None
        github_app_key_id = kms.get("github_app_key_id") or None
        if role == "exchange":
            if receipt_key_id or github_app_key_id:
                raise ConfigError("exchange role cannot be configured with receipt or App key ids")
            if github_creds:
                raise ConfigError("exchange role cannot be configured with credentials.github")
        if role == "gateway":
            if issuer_key_id:
                raise ConfigError("gateway role cannot be configured with an issuer key id")

        trust = data.get("trust") or {}
        keys = trust.get("root_public_keys") or []
        if not keys:
            raise ConfigError("trust.root_public_keys is required")

        receipts = data.get("receipts") or {}
        path = receipts.get("path") or "/state/receipts.jsonl"
        tools = data.get("tools") or {}
        packs = tools.get("packs") or ["github-triage"]
        ceiling = data.get("ceiling") or {}
        repositories = ceiling.get("repositories") or []

        exchange = data.get("exchange") or {}
        conditions = exchange.get("conditions") or trust.get("conditions") or {}
        repo_ids = conditions.get("repository_id") or []
        if isinstance(repo_ids, (str, int)):
            repo_ids = [repo_ids]
        events = conditions.get("event_name") or []
        if isinstance(events, str):
            events = [events]

        return cls(
            version=1,
            root_public_keys=list(keys),
            packs=list(packs),
            repositories=[str(item) for item in repositories],
            receipt_path=Path(path),
            signing_provider=provider,
            role=role,
            receipt_signing_key=environ.get("TENUO_RECEIPT_SIGNING_KEY"),
            exchange_signing_key=environ.get("TENUO_EXCHANGE_SIGNING_KEY"),
            require_pop=bool(trust.get("require_pop", True)),
            audience=str(exchange.get("audience") or ""),
            ttl_max=parse_duration(exchange.get("ttl_max") or 900),
            oidc_issuer=str(
                exchange.get("issuer") or trust.get("issuer") or "https://token.actions.githubusercontent.com"
            ),
            jwks_url=exchange.get("jwks_url") or None,
            clock_tolerance_seconds=int(trust.get("clock_tolerance_seconds") or 30),
            repository_owner_id=(
                str(conditions["repository_owner_id"]) if conditions.get("repository_owner_id") is not None else None
            ),
            repository_ids=[str(item) for item in repo_ids],
            job_workflow_ref=conditions.get("job_workflow_ref") or None,
            event_names=[str(item) for item in events],
            issuer_key_id=str(issuer_key_id) if issuer_key_id else None,
            receipt_key_id=str(receipt_key_id) if receipt_key_id else None,
            github_app_key_id=str(github_app_key_id) if github_app_key_id else None,
            github_app_id=github_app_id,
            github_api_url=github_api_url,
            github_installation_id=github_installation_id,
            extras=data,
        )

    @classmethod
    def from_yaml(cls, path: "str | Path", *, environ: Optional[Mapping[str, str]] = None) -> "GatewayConfig":
        text = Path(path).read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            raise ConfigError("config must be a mapping")
        return cls.from_mapping(loaded, environ=environ or os.environ)
