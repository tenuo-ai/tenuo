"""Holder Runtime: identity, trust, revocation, sessions, receipt outbox."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator, List, Optional, Sequence, Union

from tenuo_core import Authorizer, PublicKey, Warrant

from .bound_warrant import BoundWarrant
from .decorators import _chain_context, _keypair_context, _warrant_context
from .exceptions import ConfigurationError
from .identity import HolderIdentity
from .receipts import ReceiptBufferFull, ReceiptCollector

logger = logging.getLogger(__name__)

__all__ = [
    "Runtime",
    "Session",
    "get_runtime",
    "bind_runtime",
    "apply_runtime_revocation",
]

_runtime_context: ContextVar[Optional["Runtime"]] = ContextVar(
    "_runtime_context", default=None
)
_process_runtime: Optional["Runtime"] = None

SessionWarrant = Union[Warrant, str, bytes, bytearray, Sequence[Any]]


def get_runtime() -> Optional["Runtime"]:
    """Return the Runtime bound by ``session_scope`` or ``Runtime.install``."""
    scoped = _runtime_context.get()
    if scoped is not None:
        return scoped
    return _process_runtime


@contextmanager
def bind_runtime(runtime: Optional["Runtime"]) -> Iterator[Optional["Runtime"]]:
    """Bind ``runtime`` for the current task, or yield without changing scope."""
    if runtime is None:
        yield None
        return
    with runtime.bind():
        yield runtime


def apply_runtime_revocation(authorizer: Any) -> None:
    """Install the current Runtime SRL only when the authorizer has none.

    Never overwrites a list the caller already installed — a newer adapter
    SRL must not be rolled back by a stale Runtime list.
    """
    runtime = get_runtime()
    if runtime is None:
        return
    srl = runtime.revocation_list
    if srl is None:
        return
    installed = getattr(authorizer, "installed_revocation_list", None)
    if callable(installed) and installed() is not None:
        return
    setter = getattr(authorizer, "set_revocation_list", None)
    if setter is None:
        return
    setter(srl)


class Session:
    """One warrant bound to a Runtime's holder key and trust context."""

    __slots__ = ("_bound", "_runtime", "_parents", "_runtime_token", "_chain_token")

    def __init__(
        self,
        bound: BoundWarrant,
        runtime: "Runtime",
        parents: Optional[List[Warrant]] = None,
    ) -> None:
        self._bound = bound
        self._runtime = runtime
        self._parents = list(parents or [])
        self._runtime_token: Any = None
        self._chain_token: Any = None

    @property
    def warrant(self) -> Warrant:
        return self._bound.warrant

    @property
    def bound(self) -> BoundWarrant:
        return self._bound

    @property
    def runtime(self) -> "Runtime":
        return self._runtime

    def derive(self, warrant: SessionWarrant) -> "Session":
        """Bind a narrowed or child warrant to the same Runtime."""
        decoded, parents = self._runtime._decode_wire(warrant)
        return Session(
            BoundWarrant(
                decoded,
                self._runtime.identity.signing_key,
                trusted_roots=list(self._runtime.trusted_roots),
            ),
            self._runtime,
            parents=parents or (self._parents + [self.warrant]),
        )

    def __enter__(self) -> "Session":
        self._bound.__enter__()
        self._runtime_token = _runtime_context.set(self._runtime)
        # Always install parents (possibly empty) so an outer chain cannot leak in.
        self._chain_token = _chain_context.set(list(self._parents))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._chain_token is not None:
            _chain_context.reset(self._chain_token)
            self._chain_token = None
        if self._runtime_token is not None:
            _runtime_context.reset(self._runtime_token)
            self._runtime_token = None
        return self._bound.__exit__(exc_type, exc_val, exc_tb)


class Runtime:
    """Long-lived holder runtime.

    Owns identity, trusted roots, the current signed revocation list, and
    optional aggregate receipt collection. Does not perform network I/O.
    """

    def __init__(
        self,
        identity: HolderIdentity,
        trusted_roots: Sequence[PublicKey],
        revocation_list: Any = None,
        receipts: str = "off",
        *,
        receipt_maxsize: int = 10_000,
    ) -> None:
        if not isinstance(identity, HolderIdentity):
            raise ConfigurationError("Runtime requires a HolderIdentity")
        roots = list(trusted_roots)
        if not roots:
            raise ConfigurationError("Runtime requires at least one trusted root")
        if receipts not in ("collect", "off"):
            raise ConfigurationError("receipts must be 'collect' or 'off'")
        self.identity = identity
        self.trusted_roots = roots
        self._revocation_list = None
        self._collect = receipts == "collect"
        self._collector: Optional[ReceiptCollector] = (
            ReceiptCollector(maxsize=receipt_maxsize) if self._collect else None
        )
        self._issuer = None
        if self._collect:
            try:
                from tenuo_core import ReceiptIssuer
            except ImportError as exc:
                raise RuntimeError(
                    "tenuo_core python-server build is required for receipts='collect'"
                ) from exc
            self._issuer = ReceiptIssuer(identity.signing_key)
        if revocation_list is not None:
            self.apply_revocation_list(revocation_list)

    @property
    def revocation_list(self) -> Any:
        return self._revocation_list

    def apply_revocation_list(self, list_: Any) -> None:
        """Install a decoded or encoded signed revocation list."""
        self._revocation_list = _coerce_srl(list_)

    def authorizer(self) -> Authorizer:
        auth = Authorizer(trusted_roots=self.trusted_roots)
        if self._revocation_list is not None:
            auth.set_revocation_list(self._revocation_list)
        return auth

    def install(self) -> "Runtime":
        """Make this the process default when no ``session_scope`` is active.

        Inbound adapters (MCP verify, FastAPI, A2A, Temporal) collect receipts
        and apply this Runtime's revocation list without a per-request scope.
        """
        global _process_runtime
        _process_runtime = self
        return self

    @staticmethod
    def uninstall() -> None:
        """Clear the process-default Runtime."""
        global _process_runtime
        _process_runtime = None

    @contextmanager
    def bind(self) -> Iterator["Runtime"]:
        """Install this Runtime for inbound verify without binding a holder key.

        Unlike ``session_scope``, this does not require the presented warrant's
        holder to match this process. Use it on MCP, FastAPI, A2A, and Temporal
        verify paths so receipts and the signed revocation list apply.
        """
        token = _runtime_context.set(self)
        try:
            yield self
        finally:
            _runtime_context.reset(token)

    def session_from_wire(self, warrant: SessionWarrant) -> Session:
        """Bind a wire warrant to this runtime's holder key."""
        leaf, parents = self._decode_wire(warrant)
        holder = getattr(leaf, "holder_key", None)
        if holder is not None and holder != self.identity.public_key:
            raise ConfigurationError(
                "session_from_wire: warrant holder does not match Runtime identity"
            )
        bound = BoundWarrant(
            leaf,
            self.identity.signing_key,
            trusted_roots=list(self.trusted_roots),
        )
        return Session(bound, self, parents=parents)

    @contextmanager
    def session_scope(self, session: Union[Session, BoundWarrant]) -> Iterator[Session]:
        """Bind warrant, holder key, parent chain, and this Runtime.

        The decoded parent chain (root-first, excluding the leaf) is installed
        on ``chain_scope`` so ``@guard``, ``enforce_tool_call``, and MCP
        clients can verify a multi-hop stack. An empty parent list is still
        installed so an outer chain cannot leak into this session.
        """
        if isinstance(session, BoundWarrant):
            session = Session(session, self)
        if not isinstance(session, Session):
            raise ConfigurationError("session_scope expects a Session or BoundWarrant")
        warrant_token = _warrant_context.set(session.warrant)
        key_token = _keypair_context.set(self.identity.signing_key)
        runtime_token = _runtime_context.set(self)
        chain_token = _chain_context.set(list(session._parents))
        try:
            yield session
        finally:
            _chain_context.reset(chain_token)
            _runtime_context.reset(runtime_token)
            _keypair_context.reset(key_token)
            _warrant_context.reset(warrant_token)

    def peek_receipts(self) -> List[str]:
        if self._collector is None:
            return []
        return self._collector.peek()

    def drain_receipts(self) -> List[str]:
        """Snapshot pending receipts. They are removed only by ``acknowledge_receipts``."""
        if self._collector is None:
            return []
        return self._collector.drain()

    def acknowledge_receipts(self, count: int) -> int:
        if self._collector is None:
            return 0
        return self._collector.acknowledge(count)

    @property
    def receipt_overflows(self) -> int:
        """Receipts dropped because the outbox was full. Never evicts stored evidence."""
        if self._collector is None:
            return 0
        return self._collector.overflowed

    def close(self) -> None:
        """No background worker to stop; receipts stay until acknowledged."""
        return None

    def collect_result(
        self,
        result: object,
        chain_result: Optional[object] = None,
    ) -> None:
        if not self._collect or self._collector is None or self._issuer is None:
            return
        chain_result = chain_result if chain_result is not None else getattr(
            result, "chain_result", None
        )
        authorizer = getattr(result, "authorizer", None)
        if authorizer is not None:
            try:
                self._issuer.bind_authorizer(authorizer)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to bind authorizer for runtime receipt", exc_info=exc)
                return
        else:
            try:
                self._issuer.bind_authorizer(self.authorizer())
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to bind runtime authorizer for receipt", exc_info=exc)
                return

        request_id = getattr(result, "request_id", None) or str(uuid.uuid4())
        tool = getattr(result, "tool", "") or ""
        allowed = bool(getattr(result, "allowed", False))
        ts = int(time.time())
        try:
            if allowed:
                if chain_result is None:
                    return
                wire = self._issuer.issue_receipt(
                    chain_result, tool, True, ts, request_id, None
                )
            else:
                chain = getattr(result, "presented_chain", None)
                if not chain:
                    return
                from .control_plane import (
                    _DECISION_CODE_BY_ERROR_TYPE,
                    _POP_ESTABLISHED_ERROR_TYPES,
                )

                error_type = getattr(result, "error_type", None)
                if not error_type:
                    code = "authorization-failed"
                else:
                    code = _DECISION_CODE_BY_ERROR_TYPE.get(
                        str(error_type), str(error_type).replace("_", "-")
                    )
                args = getattr(result, "pop_auth_args", None)
                if args is None:
                    args = getattr(result, "arguments", None) or getattr(
                        result, "clean_arguments", None
                    ) or {}
                pop = (
                    getattr(result, "verified_pop", None)
                    if error_type in _POP_ESTABLISHED_ERROR_TYPES
                    else None
                )
                wire = self._issuer.issue_denial_receipt(
                    list(chain), tool, args, ts, request_id, code, pop
                )
        except Exception as exc:  # noqa: BLE001 — must not fail the tool call
            logger.warning("runtime receipt signing failed for %r", tool, exc_info=exc)
            return
        if not wire:
            return
        try:
            self._collector.push(wire)
        except ReceiptBufferFull:
            logger.warning(
                "receipt outbox is full (%s); authorized call continues, "
                "receipt was not stored",
                self._collector.maxsize,
            )

    def _decode_wire(self, warrant: SessionWarrant):
        if isinstance(warrant, Warrant):
            return warrant, []
        if isinstance(warrant, (bytes, bytearray)):
            return Warrant.from_bytes(bytes(warrant)), []
        if isinstance(warrant, str):
            text = warrant.strip()
            if not text:
                raise ConfigurationError("session_from_wire received an empty warrant")
            try:
                from tenuo_core import decode_warrant_stack_base64

                stack = list(decode_warrant_stack_base64(text))
                if len(stack) > 1:
                    return stack[-1], stack[:-1]
                if stack:
                    return stack[0], []
            except Exception:
                pass
            return Warrant.from_base64(text), []
        if isinstance(warrant, Sequence):
            items = list(warrant)
            if not items:
                raise ConfigurationError("session_from_wire received an empty chain")
            decoded = []
            for item in items:
                leaf, _parents = self._decode_wire(item)
                decoded.append(leaf)
            return decoded[-1], decoded[:-1]
        raise ConfigurationError(
            f"session_from_wire expected a Warrant, bytes, or base64 string, "
            f"got {type(warrant).__name__}"
        )


def _coerce_srl(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "set_revocation_list") or hasattr(value, "is_revoked"):
        return value
    from tenuo_core import SignedRevocationList

    if isinstance(value, (bytes, bytearray)):
        return SignedRevocationList.from_bytes(bytes(value))
    if isinstance(value, str):
        raw = value.strip()
        try:
            return SignedRevocationList.from_bytes(bytes.fromhex(raw))
        except Exception:
            import base64

            return SignedRevocationList.from_bytes(base64.b64decode(raw))
    raise ConfigurationError("revocation_list must be a SignedRevocationList, bytes, or encoded string")
