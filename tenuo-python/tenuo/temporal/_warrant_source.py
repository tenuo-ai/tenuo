"""Pluggable warrant provisioning for Tenuo-Temporal workflows."""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional

from tenuo.temporal.exceptions import TenuoContextError


class WarrantSource(ABC):
    """Abstract base for warrant provisioning sources.

    A WarrantSource resolves (warrant, key_id) lazily at workflow-start time.
    Resolution runs client-side — warrants must be present in workflow start
    headers before a Temporal worker ever sees the workflow.

    Implementations raise WarrantExpired if the resolved warrant is past expires_at.
    """

    @abstractmethod
    async def resolve(self, *args: Any, **kwargs: Any) -> tuple:
        """Return (warrant, key_id). Raise WarrantExpired if expired."""


class LiteralWarrantSource(WarrantSource):
    """Wraps an already-minted Warrant. Symmetric with execute_workflow_authorized(warrant=...)."""

    def __init__(self, warrant: Any, key_id: str) -> None:
        self._warrant = warrant
        self._key_id = key_id

    async def resolve(self, *args: Any, **kwargs: Any) -> tuple:
        return (self._warrant, self._key_id)


class EnvWarrantSource(WarrantSource):
    """Reads a warrant from an environment variable (base64-encoded CBOR bytes).

    Mirrors EnvKeyResolver's pattern. Reads fresh on each resolve() call.
    Raises WarrantExpired if the resolved warrant's expires_at is in the past.

    Example::

        source = EnvWarrantSource("TENUO_WARRANT_AGENT1", "agent1")
        async with tenuo_warrant_context(source, "agent1"):
            await client.execute_workflow(...)
    """

    def __init__(self, env_var: str, key_id: str, *, encoding: str = "base64") -> None:
        self._env_var = env_var
        self._key_id = key_id
        self._encoding = encoding

    async def resolve(self, *args: Any, **kwargs: Any) -> tuple:
        import os
        import time

        from tenuo_core import Warrant as _Warrant  # type: ignore[import-not-found]

        raw = os.environ.get(self._env_var)
        if not raw:
            raise TenuoContextError(
                f"EnvWarrantSource: environment variable '{self._env_var}' is not set"
            )
        if self._encoding == "base64":
            try:
                warrant_bytes = base64.b64decode(raw)
            except Exception as e:
                raise TenuoContextError(
                    f"EnvWarrantSource: failed to base64-decode '{self._env_var}': {e}"
                ) from e
        else:
            warrant_bytes = raw.encode()

        warrant = _Warrant.from_bytes(warrant_bytes)

        if hasattr(warrant, "expires_at") and warrant.expires_at is not None:
            if warrant.expires_at < int(time.time()):
                raise TenuoContextError(
                    f"EnvWarrantSource: warrant in '{self._env_var}' has expired"
                )

        return (warrant, self._key_id)


class CloudTriggerWarrantSource(WarrantSource):
    """Fires a Tenuo Cloud trigger and returns the resulting warrant.

    Calls POST {base_url}/v1/triggers/{trigger_id}:fire at resolve() time.
    Uses the existing cloud fire API — no cloud changes needed. The event_mapper
    closure maps workflow args to the trigger's bind_from_event field.

    ``httpx`` is a soft dependency: imported inside ``resolve()`` only.

    Example::

        source = CloudTriggerWarrantSource(
            base_url="https://api.cloud.tenuo.ai",
            trigger_id="trig_abc123",
            api_key=os.environ["TENUO_API_KEY"],
            key_id="agent1",
            event_mapper=lambda patient_id, *args, **kw: {"patient_id": patient_id},
        )
        await execute_workflow_authorized(client, ..., warrant_source=source, args=[patient_id])
    """

    def __init__(
        self,
        base_url: str,
        trigger_id: str,
        api_key: str,
        key_id: str,
        *,
        event_mapper: Optional[Callable] = None,
        timeout: float = 5.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._trigger_id = trigger_id
        self._api_key = api_key
        self._key_id = key_id
        self._event_mapper = event_mapper
        self._timeout = timeout

    async def resolve(self, *args: Any, **kwargs: Any) -> tuple:
        import time

        try:
            import httpx
        except ImportError:
            raise TenuoContextError(
                "CloudTriggerWarrantSource requires 'httpx': pip install httpx"
            )
        from tenuo_core import Warrant as _Warrant  # type: ignore[import-not-found]

        event_data: Dict = {}
        if self._event_mapper is not None:
            event_data = self._event_mapper(*args, **kwargs) or {}

        url = f"{self._base_url}/v1/triggers/{self._trigger_id}:fire"
        payload = {"event_data": event_data}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()

        warrant_b64 = data.get("warrant")
        if not warrant_b64:
            raise TenuoContextError(
                f"CloudTriggerWarrantSource: fire response missing 'warrant' field: {data}"
            )

        warrant_bytes = base64.b64decode(warrant_b64)
        warrant = _Warrant.from_bytes(warrant_bytes)

        if hasattr(warrant, "expires_at") and warrant.expires_at is not None:
            if warrant.expires_at < int(time.time()):
                raise TenuoContextError(
                    "CloudTriggerWarrantSource: fired warrant has already expired"
                )

        return (warrant, self._key_id)
