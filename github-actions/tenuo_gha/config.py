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


@dataclass
class GatewayConfig:
    version: int
    root_public_keys: List[str]
    packs: List[str]
    repositories: List[str]
    receipt_path: Path
    signing_provider: str
    receipt_signing_key: Optional[str] = None
    require_pop: bool = True
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

        github_creds = (data.get("credentials") or {}).get("github") or {}
        if github_creds:
            raise ConfigError("credentials.github is not supported")
        _assert_no_embedded_secrets(data)

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

        return cls(
            version=1,
            root_public_keys=list(keys),
            packs=list(packs),
            repositories=[str(item) for item in repositories],
            receipt_path=Path(path),
            signing_provider=provider,
            receipt_signing_key=environ.get("TENUO_RECEIPT_SIGNING_KEY"),
            require_pop=bool(trust.get("require_pop", True)),
            extras=data,
        )

    @classmethod
    def from_yaml(cls, path: "str | Path", *, environ: Optional[Mapping[str, str]] = None) -> "GatewayConfig":
        text = Path(path).read_text(encoding="utf-8")
        loaded = yaml.safe_load(text)
        if not isinstance(loaded, dict):
            raise ConfigError("config must be a mapping")
        return cls.from_mapping(loaded, environ=environ or os.environ)
