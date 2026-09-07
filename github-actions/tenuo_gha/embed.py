"""In-process embed client for a host product (Pullfrog, Claude action, …).

The host keeps its agent, prompts, and tools. This module exchanges OIDC for a
holder-bound stack, derives a terminal leaf per call, and posts that envelope
to the customer gateway. The host never holds the issuer key or a GitHub token.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import httpx

from .action import (
    ActionError,
    deliver_warrant,
    exchange_warrant,
    guardrails,
    public_key_hex,
    start_holder,
    verify_exchange_roots,
)
from .config import ConfigError
from .holder import HolderClient, HolderError, HolderServer
from .oidc import OidcError, fetch_actions_oidc, peek_oidc_claims
from .shim import ShimError, call_gateway
from .task import TaskError, infer_capabilities, infer_task_binding


@dataclass(frozen=True)
class EmbedConfig:
    """The same four fields the GitHub Action takes, plus an optional TTL."""

    gateway_url: str
    exchange_url: str
    audience: str
    trusted_roots: List[str] = field(default_factory=list)
    ttl_seconds: int = 900


@dataclass(frozen=True)
class Grant:
    warrant_id: str
    expires_at: str
    tools: List[str]
    task_binding: Dict[str, Any]
    public_key: str


@dataclass(frozen=True)
class CallResult:
    allowed: bool
    result: Dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    message: str = ""
    leaf_derived: bool = False


class EmbedError(RuntimeError):
    """The embed client could not finish. Never includes holder material."""


class EmbedSession:
    """Start a holder, exchange, then call tools the way a host product would."""

    def __init__(
        self,
        config: EmbedConfig,
        *,
        work_dir: Optional["str | Path"] = None,
        http: Optional[httpx.Client] = None,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        if not config.gateway_url:
            raise EmbedError("gateway_url is required")
        if not config.exchange_url:
            raise EmbedError("exchange_url is required")
        if not config.audience:
            raise EmbedError("audience is required")
        self.config = config
        self._env = dict(environ if environ is not None else os.environ)
        self._http = http
        base = Path(work_dir) if work_dir is not None else Path(tempfile.mkdtemp(prefix="tenuo-embed-"))
        self._work = base
        self._work.mkdir(parents=True, exist_ok=True)
        socket = self._work / "holder.sock"
        if len(str(socket)) > 100:
            socket = Path(f"/tmp/tenuo-embed-{os.getpid()}.sock")
        self._socket = socket
        self._server: Optional[HolderServer] = None
        self._grant: Optional[Grant] = None
        self._own_work = work_dir is None

    @property
    def grant(self) -> Optional[Grant]:
        return self._grant

    def start(self) -> EmbedSession:
        """Start the holder. The host never sees the key."""
        try:
            guardrails(self._env)
        except ConfigError as exc:
            raise EmbedError(str(exc)) from exc
        if self._socket.exists():
            self._socket.unlink()
        self._server = start_holder(self._socket)
        return self

    def exchange(
        self,
        *,
        event_name: str,
        event: Mapping[str, Any],
        repository: str,
        oidc_token: Optional[str] = None,
    ) -> Grant:
        """POST /v1/exchange and deliver the stack to the holder."""
        if self._server is None:
            self.start()
        try:
            capabilities = infer_capabilities(
                event_name=event_name,
                event=event,
                repository=repository,
            )
            task_binding = infer_task_binding(event_name=event_name, event=event)
        except TaskError as exc:
            raise EmbedError(str(exc)) from exc
        token = oidc_token or fetch_actions_oidc(self.config.audience, self._env)
        try:
            claims = peek_oidc_claims(token)
        except OidcError as exc:
            raise EmbedError(str(exc)) from exc
        issuer = str(claims.get("iss") or "")
        jti = str(claims.get("jti") or "")
        if not issuer or not jti:
            raise EmbedError("OIDC token is missing iss or jti")
        pubkey = public_key_hex(self._socket)
        try:
            proof = HolderClient(self._socket).sign_exchange(
                issuer=issuer,
                jti=jti,
                ttl_seconds=self.config.ttl_seconds,
                capabilities=capabilities,
                task_binding=task_binding,
            )
            minted = exchange_warrant(
                self.config.exchange_url,
                token,
                holder_public_key=pubkey,
                holder_proof=proof,
                ttl_seconds=self.config.ttl_seconds,
                capabilities=capabilities,
                task_binding=task_binding,
                client=self._http,
            )
        except (ActionError, HolderError, OidcError) as exc:
            raise EmbedError(str(exc)) from exc
        try:
            verify_exchange_roots(minted.get("root_public_keys"), list(self.config.trusted_roots))
        except ActionError as exc:
            raise EmbedError(str(exc)) from exc
        deliver_warrant(self._socket, str(minted["warrant"]))
        tools = HolderClient(self._socket).tools()
        self._grant = Grant(
            warrant_id=str(minted.get("warrant_id") or ""),
            expires_at=str(minted.get("expires_at") or ""),
            tools=list(tools),
            task_binding=dict(task_binding),
            public_key=pubkey,
        )
        return self._grant

    def tools(self) -> List[str]:
        if self._grant is None:
            raise EmbedError("exchange has not completed")
        return list(self._grant.tools)

    def call(self, tool: str, arguments: Mapping[str, Any]) -> CallResult:
        """Derive a terminal leaf and POST it to the customer gateway."""
        if self._grant is None:
            raise EmbedError("exchange has not completed")
        if tool not in self._grant.tools:
            return CallResult(
                allowed=False,
                error_code="TENUO_TOOL_NOT_AUTHORIZED",
                message=f"DENIED (TENUO_TOOL_NOT_AUTHORIZED): {tool} is not on the warrant",
            )
        args = dict(arguments)
        try:
            envelope = HolderClient(self._socket).envelope(tool, args)
        except HolderError as exc:
            raise EmbedError(str(exc)) from exc
        try:
            outcome = call_gateway(
                self.config.gateway_url,
                tool,
                args,
                envelope,
                client=self._http,
            )
        except ShimError as exc:
            raise EmbedError(str(exc)) from exc
        return CallResult(
            allowed=bool(outcome.get("allowed")),
            result=dict(outcome.get("result") or {}) if isinstance(outcome.get("result"), dict) else {},
            error_code=str(outcome.get("error_code") or ""),
            message=str(outcome.get("message") or ""),
            leaf_derived=bool(envelope.get("leaf_derived")),
        )

    def close(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
        if self._own_work:
            try:
                if self._socket.exists():
                    self._socket.unlink()
            except OSError:
                pass

    def __enter__(self) -> EmbedSession:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.close()
