"""Connect-token wrapper around the shared Rust parser.

The wire format is decoded only in Rust. This module adds credential-safe
``repr`` / ``str`` / pickle behavior and a small resolve helper.
"""

from __future__ import annotations

from typing import Any, Optional

from .exceptions import ConfigurationError

__all__ = ["ConnectToken"]


def _core_connect_token():
    try:
        from tenuo_core import ConnectToken as CoreConnectToken
    except ImportError as exc:  # pragma: no cover - extension missing
        raise RuntimeError(
            "tenuo_core python-server build is required for ConnectToken.parse"
        ) from exc
    return CoreConnectToken


class ConnectToken:
    """Parsed ``tenuo_ct_…`` token. Endpoint is a bare origin after parse."""

    __slots__ = ("_inner",)

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    @classmethod
    def parse(cls, raw: str) -> "ConnectToken":
        """Parse a complete ``tenuo_ct_<base64url-json>`` token.

        Accepts only version 1. Missing, ``v=0``, and future versions are
        rejected. Does not read environment variables.
        """
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigurationError(
                "Connect token must be a tenuo_ct_… string. "
                "Copy the full token, including the prefix."
            )
        try:
            inner = _core_connect_token().parse(raw.strip())
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None
        return cls(inner)

    @property
    def version(self) -> int:
        return int(self._inner.version)

    @property
    def endpoint(self) -> str:
        return str(self._inner.endpoint)

    @property
    def api_key(self) -> str:
        return str(self._inner.api_key)

    @property
    def agent_id(self) -> Optional[str]:
        value = self._inner.agent_id
        return str(value) if value is not None else None

    @property
    def registration_token(self) -> Optional[str]:
        value = self._inner.registration_token
        return str(value) if value is not None else None

    @property
    def needs_endpoint_base(self) -> bool:
        return bool(self._inner.needs_endpoint_base)

    def resolve_endpoint(self, local_base: Optional[str] = None) -> "ConnectToken":
        """Resolve a relative endpoint against ``local_base``.

        Absolute endpoints, including scheme-less hostnames, are left
        unchanged. Does not invent ``https://`` or a localhost default.
        """
        try:
            self._inner.resolve_endpoint(local_base)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from None
        return self

    def __repr__(self) -> str:
        agent = self.agent_id
        reg = "'[REDACTED]'" if self.registration_token is not None else "None"
        return (
            f"ConnectToken(version={self.version}, endpoint={self.endpoint!r}, "
            f"agent_id={agent!r}, api_key='[REDACTED]', registration_token={reg})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __getstate__(self) -> Any:
        raise TypeError("ConnectToken cannot be pickled")

    def __setstate__(self, state: Any) -> None:
        raise TypeError("ConnectToken cannot be pickled")
