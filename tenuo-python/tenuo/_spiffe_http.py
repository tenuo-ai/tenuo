"""Shared HTTP plumbing for the single-request SPIFFE issuance exchanges.

Internal. :mod:`tenuo.spiffe_jwt` and :mod:`tenuo.spiffe_forwarded` build their
endpoints and clients on this, so limits, deadlines and error handling are the
same for both.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import http.client
import json
import logging
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

from tenuo import PublicKey, SigningKey, Warrant
from tenuo.spiffe import (
    SpiffeError,
    SpiffeHolderProof,
    SpiffeWarrantIssuer,
    _checked_warrant,
    _consume_result,
    _IssuerBusy,
    _positive_int,
)

logger = logging.getLogger("tenuo.spiffe")

_MAX_BODY_BYTES = 64 * 1024
_PROTOCOL_VERSION = 1
_REQUEST_FIELDS = frozenset({"v", "holder", "task", "timestamp", "nonce", "signature"})

_Scope = Mapping[str, Any]
_Receive = Callable[[], Awaitable[Mapping[str, Any]]]
_Send = Callable[[Mapping[str, Any]], Awaitable[None]]


class _Refusal(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


class _Slot:
    """One caller's place among the requests in progress. It is given up exactly once."""

    def __init__(self, counts: Dict[str, int], key: str):
        self._counts: Optional[Dict[str, int]] = counts
        self._key = key
        self.follows_work = False  # Set when a cancelled request leaves its work running.
        counts[key] = counts.get(key, 0) + 1

    def release(self, *_: Any) -> None:
        counts, self._counts = self._counts, None
        if counts is None:
            return
        remaining = counts[self._key] - 1
        if remaining:
            counts[self._key] = remaining
        else:
            del counts[self._key]


class _IssuerApp:
    """ASGI endpoint for one-request issuance. Subclasses say how the caller is identified."""

    _what = "issuance"  # For log lines.
    _challenge: Optional[bytes] = None  # WWW-Authenticate value sent with 401.

    def __init__(
        self,
        issuer: SpiffeWarrantIssuer,
        *,
        path: str = "/warrants",
        max_concurrent: int = 256,
        max_workers: int = 32,
        body_timeout: float = 10.0,
    ):
        if not path.startswith("/"):
            raise ValueError("path must start with /")
        for name, value in (("max_concurrent", max_concurrent), ("max_workers", max_workers)):
            if not _positive_int(value) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if body_timeout <= 0:
            raise ValueError("body_timeout must be positive")
        self.issuer = issuer
        self._path = path
        self._max_concurrent = max_concurrent
        self._body_timeout = body_timeout
        self._busy = 0
        self._reading = 0
        self._max_per_key: Optional[int] = None  # Requests in progress per caller, where the caller is known early.
        self._per_key: Dict[str, int] = {}
        self._pool = ThreadPoolExecutor(max_workers, thread_name_prefix="tenuo-spiffe-http")

    # -- hooks ------------------------------------------------------------

    def _credential(self, scope: _Scope) -> Any:
        """Take the caller's credential from the request, or raise ``_Refusal``. Runs before the body is read."""
        raise NotImplementedError

    def _limit_key(self, credential: Any) -> Optional[str]:
        """The caller to count requests against, when it is already known from the credential."""
        return None

    def _authorize(self, credential: Any, holder: PublicKey, task_id: Any, proof: SpiffeHolderProof) -> Warrant:
        """Authenticate the credential and issue. Runs in a worker thread; raises ``SpiffeError`` or ``_Refusal``."""
        raise NotImplementedError

    # -- ASGI -------------------------------------------------------------

    def close(self) -> None:
        """Release the worker threads. Called on ASGI lifespan shutdown."""
        self._pool.shutdown(wait=False)

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        try:
            status, reply = 200, {"warrant": (await self._issue(scope, receive)).to_base64()}
        except _Refusal as refusal:
            status, reply = refusal.status, {"error": refusal.error, "message": refusal.message}
            logger.info("%s refused (%d): %s", self._what, status, refusal.message)
        except Exception:
            logger.exception("%s failed", self._what)
            status, reply = 503, {"error": "unavailable", "message": "Issuer error"}
        body = json.dumps(reply, separators=(",", ":")).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if status == 401 and self._challenge is not None:
            headers.append((b"www-authenticate", self._challenge))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def _issue(self, scope: _Scope, receive: _Receive) -> Warrant:
        path, root = scope.get("path", ""), scope.get("root_path", "")
        if root and path.startswith(root):
            path = path[len(root) :]  # Mounted under a prefix.
        if path != self._path:
            raise _Refusal(404, "not_found", "No such endpoint")
        if scope.get("method") != "POST":
            raise _Refusal(405, "method_not_allowed", "Use POST")
        credential = self._credential(scope)
        key = self._limit_key(credential) if self._max_per_key is not None else None
        if key is None:
            return await self._serve(credential, receive, None)
        if self._per_key.get(key, 0) >= (self._max_per_key or 0):
            raise _Refusal(503, "unavailable", "Too many requests in progress for this workload; retry shortly")
        slot = _Slot(self._per_key, key)
        try:
            return await self._serve(credential, receive, slot)
        finally:
            # A cancelled request whose policy or audit call is still running
            # keeps its place until that call returns.
            if not slot.follows_work:
                slot.release()

    async def _serve(self, credential: Any, receive: _Receive, slot: Optional[_Slot]) -> Warrant:
        # Bound the requests being read as well as those being worked on, and
        # give each a deadline, so slow senders cannot pile up before the caller is checked.
        if self._reading >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        self._reading += 1
        try:
            body = await asyncio.wait_for(self._read_body(receive), self._body_timeout)
        except asyncio.TimeoutError:
            raise _Refusal(408, "timeout", "Request body was not received in time") from None
        finally:
            self._reading -= 1
        try:
            request = json.loads(body)
            if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
                raise ValueError
            if request["v"] != _PROTOCOL_VERSION:
                raise _Refusal(400, "invalid_request", "Unsupported protocol version")
            holder = PublicKey.from_bytes(base64.b64decode(request["holder"], validate=True))
            proof = SpiffeHolderProof(
                request["timestamp"],
                base64.b64decode(request["nonce"], validate=True),
                base64.b64decode(request["signature"], validate=True),
            )
        except _Refusal:
            raise
        except (ValueError, TypeError, RecursionError, binascii.Error):
            raise _Refusal(400, "invalid_request", "Malformed request") from None
        except Exception:  # A holder key the core rejects.
            raise _Refusal(400, "invalid_request", "Invalid holder key") from None
        task_id = request["task"]

        def work() -> Warrant:
            try:
                return self._authorize(credential, holder, task_id, proof)
            except _Refusal:
                raise
            except _IssuerBusy as exc:
                raise _Refusal(503, "unavailable", str(exc)) from exc
            except SpiffeError as exc:
                raise _Refusal(403, "refused", str(exc)) from exc

        return await self._in_worker(work, slot)

    @staticmethod
    async def _read_body(receive: _Receive) -> bytes:
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] != "http.request":
                raise _Refusal(400, "invalid_request", "Request was not completed")
            body += message.get("body", b"")
            if len(body) > _MAX_BODY_BYTES:
                raise _Refusal(413, "too_large", "Request body is too large")
            if not message.get("more_body"):
                return bytes(body)

    async def _in_worker(self, function: Callable[[], Warrant], slot: Optional[_Slot] = None) -> Warrant:
        """Run blocking work in the pool. Its places are held until the work itself has finished."""
        loop = asyncio.get_running_loop()
        if self._busy >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        self._busy += 1

        def release() -> None:
            self._busy -= 1

        def run() -> Warrant:
            try:
                return function()
            finally:
                try:
                    loop.call_soon_threadsafe(release)
                except RuntimeError:
                    pass  # The loop closed during shutdown.

        try:
            work = asyncio.wrap_future(self._pool.submit(run))
        except RuntimeError:
            self._busy -= 1
            raise _Refusal(503, "unavailable", "Issuer is shutting down") from None
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            if slot is not None:
                slot.follows_work = True
                work.add_done_callback(slot.release)
            work.add_done_callback(_consume_result)
            raise


# -- agent side -------------------------------------------------------------


def _request_body(holder_key: SigningKey, task_id: str, proof: SpiffeHolderProof) -> bytes:
    return json.dumps(
        {
            "v": _PROTOCOL_VERSION,
            "holder": base64.b64encode(bytes(holder_key.public_key.to_bytes())).decode("ascii"),
            "task": task_id,
            "timestamp": proof.timestamp,
            "nonce": base64.b64encode(proof.nonce).decode("ascii"),
            "signature": base64.b64encode(proof.signature).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _post_for_warrant(
    connect: Callable[[], http.client.HTTPConnection],
    where: str,
    path: str,
    body: bytes,
    headers: Dict[str, str],
    trusted: List[PublicKey],
    holder_key: SigningKey,
    before_request: Optional[Callable[[http.client.HTTPConnection], None]] = None,
) -> Warrant:
    """POST one issuance request and return the checked warrant. Every failure is a ``SpiffeError``.

    Redirects are never followed. ``before_request`` runs on the open
    connection before anything is sent (for example to authenticate the peer).
    """
    connection: Optional[http.client.HTTPConnection] = None
    try:
        connection = connect()
        if before_request is not None:
            connection.connect()
            before_request(connection)
        connection.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
        )
        response = connection.getresponse()
        status = response.status
        payload = response.read(_MAX_BODY_BYTES + 1)
    except SpiffeError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise SpiffeError(f"The TLS certificate presented by {where} was not accepted: {exc.verify_message}") from exc
    except ssl.SSLError as exc:
        raise SpiffeError(f"TLS with the issuer at {where} failed: {exc.reason or exc}") from exc
    except (OSError, http.client.HTTPException, UnicodeError) as exc:  # UnicodeError: an unusable host name.
        raise SpiffeError(f"Could not complete the exchange with the issuer at {where}: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()
    try:
        reply = json.loads(payload) if len(payload) <= _MAX_BODY_BYTES else None
    except (ValueError, RecursionError):
        reply = None
    if status != 200 or not isinstance(reply, dict):
        message = reply.get("message") if isinstance(reply, dict) else None
        if isinstance(message, str) and message:
            raise SpiffeError(f"Issuer refused (HTTP {status}): {message[:200]}")
        raise SpiffeError(f"The issuer at {where} answered HTTP {status} without a warrant")
    return _checked_warrant(reply.get("warrant"), trusted, holder_key)


def _split_url(url: str) -> Tuple[str, str, int, str]:
    """Return (scheme, host, port, path-and-query) for an http(s) URL without credentials or fragment."""
    import urllib.parse

    try:
        parts = urllib.parse.urlsplit(url)
        host, explicit_port = parts.hostname, parts.port
    except ValueError:
        raise ValueError("url must look like https://host[:port]/path") from None
    if parts.scheme not in ("https", "http") or not host or parts.username or parts.password or parts.fragment:
        raise ValueError("url must look like https://host[:port]/path")
    # Always pass the port: http.client would otherwise read the tail of a bare IPv6 address as one.
    port = explicit_port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.scheme, host, port, path


def _where(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
