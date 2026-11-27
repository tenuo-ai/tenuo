"""Shared HTTP plumbing for the single-request issuance exchanges.

Internal. The endpoints and clients of :mod:`tenuo.spiffe_jwt`,
:mod:`tenuo.spiffe_forwarded` and :mod:`tenuo.oauth` are built on this, so
limits, deadlines and error handling are the same for all of them.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import http.client
import json
import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple, Type

from tenuo import PublicKey, SigningKey, Warrant
from tenuo._issuance import (
    HolderProof,
    IssuanceBusy,
    IssuanceError,
    _CallbackFailed,
    _checked_warrant,
    _consume_result,
    _from_callback,
    _positive_int,
    _seconds,
)

logger = logging.getLogger("tenuo.spiffe")

_MAX_BODY_BYTES = 64 * 1024
# Each call runs its exchange in a thread of its own, and a call that reaches its
# deadline leaves that thread to end by itself: a stalled name lookup cannot be
# interrupted. No more than this many such threads exist in a process at once,
# in progress or left behind. A place is taken before a thread is started and
# given back when it ends, so calls that overlap cannot exceed it.
_MAX_EXCHANGES = 64
_exchanges = 0
_exchanges_lock = threading.Lock()


def _reserve_exchange() -> bool:
    global _exchanges
    with _exchanges_lock:
        if _exchanges >= _MAX_EXCHANGES:
            return False
        _exchanges += 1
        return True


def _release_exchange() -> None:
    global _exchanges
    with _exchanges_lock:
        _exchanges -= 1


_PROTOCOL_VERSION = 1
_REQUEST_FIELDS = frozenset({"v", "holder", "task", "timestamp", "nonce", "signature"})

_Scope = Mapping[str, Any]
_Receive = Callable[[], Awaitable[Mapping[str, Any]]]
_Send = Callable[[Mapping[str, Any]], Awaitable[None]]


class _Refusal(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


class _Places:
    """The requests in progress, overall and per caller, and the callers being checked, during one run.

    A restart (lifespan shutdown, then startup) begins a new count. A request
    of the earlier run that finishes late gives its place back to the earlier
    count, which nobody reads any more, so it can neither stay occupied for
    ever nor be subtracted from the new run's.
    """

    def __init__(self) -> None:
        self.in_progress = 0
        self.per_key: Dict[str, int] = {}
        self.checking = 0


class _Slot:
    """One request's place among those in progress, overall and for its caller. It is given up exactly once.

    Taken and given up on the event loop only.
    """

    def __init__(self, app: "_IssuerApp", key: Optional[str]):
        places = app._places
        self._places: Optional[_Places] = places
        self._key = key
        self.follows_work = False  # Set when a cancelled request leaves its work running.
        places.in_progress += 1
        if key is not None:
            places.per_key[key] = places.per_key.get(key, 0) + 1

    def release(self, *_: Any) -> None:
        places, self._places = self._places, None
        if places is None:
            return
        places.in_progress -= 1
        if self._key is None:
            return
        remaining = places.per_key[self._key] - 1
        if remaining:
            places.per_key[self._key] = remaining
        else:
            del places.per_key[self._key]


class _IssuerApp:
    """ASGI endpoint for one-request issuance. Subclasses say how the caller is identified."""

    _what = "issuance"  # For log lines.
    _challenge: Optional[bytes] = None  # WWW-Authenticate value sent with 401.
    _log = logging.getLogger("tenuo.spiffe")  # Each family logs under its own name.

    def __init__(
        self,
        issuer: Any,
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
        body_timeout = _seconds("body_timeout", body_timeout)
        self.issuer = issuer
        self._path = path
        self._max_concurrent = max_concurrent
        self._body_timeout = body_timeout
        self._places = _Places()  # Requests admitted and not finished: being read, or with work running.
        self._max_per_key: Optional[int] = None  # Requests in progress per caller, where the caller is known early.
        self._max_workers = max_workers
        self._closed = False
        self._pool = self._new_pool()

    # -- hooks ------------------------------------------------------------

    def _credential(self, scope: _Scope) -> Any:
        """Take the caller's credential from the request, or raise ``_Refusal``. Runs before the body is read."""
        raise NotImplementedError

    async def _checked(self, credential: Any) -> Any:
        """Verify the credential where that takes real work, before the request is admitted. May raise ``_Refusal``."""
        return credential

    def _limit_key(self, credential: Any) -> Optional[str]:
        """The caller to count requests against, when it is already known from the credential."""
        return None

    def _authorize(self, credential: Any, holder: PublicKey, task_id: Any, proof: HolderProof) -> Warrant:
        """Authenticate the credential and issue. Runs in a worker thread; raises the family's ``IssuanceError`` or ``_Refusal``."""
        raise NotImplementedError

    # -- ASGI -------------------------------------------------------------

    @property
    def _in_progress(self) -> int:
        return self._places.in_progress

    @property
    def _per_key(self) -> Dict[str, int]:
        return self._places.per_key

    def _new_pool(self) -> ThreadPoolExecutor:
        return ThreadPoolExecutor(self._max_workers, thread_name_prefix="tenuo-spiffe-http")

    def close(self) -> None:
        """Release the worker threads. Called on ASGI lifespan shutdown."""
        self._closed = True
        self._pool.shutdown(wait=False)

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if self._closed:  # Started again after a shutdown: the server was restarted in this process.
                        # Work the earlier run left behind may never report back (its event
                        # loop is gone), so this run counts its requests afresh.
                        self._pool, self._places, self._closed = self._new_pool(), _Places(), False
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
            self._log.info("%s refused (%d): %s", self._what, status, refusal.message)
        except Exception:
            self._log.exception("%s failed", self._what)
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
        credential = await self._checked(self._credential(scope))
        # A request takes one place before its body is read and keeps it until it
        # has finished, so one limit covers the requests being read and those
        # being worked on, and a request over the limit is refused at once.
        if self._in_progress >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        key = self._limit_key(credential) if self._max_per_key is not None else None
        if key is not None and self._per_key.get(key, 0) >= (self._max_per_key or 0):
            raise _Refusal(503, "unavailable", "Too many requests in progress for this workload; retry shortly")
        slot = _Slot(self, key)
        try:
            return await self._serve(credential, receive, slot)
        finally:
            # A cancelled request whose policy or audit call is still running
            # keeps its place until that call returns.
            if not slot.follows_work:
                slot.release()

    async def _serve(self, credential: Any, receive: _Receive, slot: _Slot) -> Warrant:
        # A deadline for the body, so a slow sender cannot hold its place for long.
        try:
            body = await asyncio.wait_for(self._read_body(receive), self._body_timeout)
        except asyncio.TimeoutError:
            raise _Refusal(408, "timeout", "Request body was not received in time") from None
        try:
            request = self._decode_request(body)
            if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
                raise ValueError
            if type(request["v"]) is not int or request["v"] != _PROTOCOL_VERSION:  # Not true, not 1.0.
                raise _Refusal(400, "invalid_request", "Unsupported protocol version")
            holder = PublicKey.from_bytes(base64.b64decode(request["holder"], validate=True))
            proof = HolderProof(
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
            except IssuanceError as exc:
                if _from_callback(exc):
                    # The policy or audit callback raised it. That is the issuer
                    # failing: logged in full here, and no detail sent to the caller.
                    raise _CallbackFailed() from exc
                if isinstance(exc, IssuanceBusy):
                    raise _Refusal(503, "unavailable", str(exc)) from exc
                raise _Refusal(403, "refused", str(exc)) from exc

        return await self._in_worker(work, slot)

    @staticmethod
    def _decode_request(body: bytes) -> Any:
        return json.loads(body)

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

    async def _in_worker(self, function: Callable[[], Warrant], slot: _Slot) -> Warrant:
        """Run blocking work in the pool. The request's place is held until the work itself has finished."""
        try:
            work = asyncio.wrap_future(self._pool.submit(function))
        except RuntimeError:
            raise _Refusal(503, "unavailable", "Issuer is shutting down") from None
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            slot.follows_work = True
            work.add_done_callback(slot.release)
            work.add_done_callback(_consume_result)
            raise


# -- agent side -------------------------------------------------------------


def _request_body(holder_key: SigningKey, task_id: str, proof: HolderProof) -> bytes:
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
    timeout: Optional[float] = None,
    error: Type[IssuanceError] = IssuanceError,
) -> Warrant:
    """POST one issuance request and return the checked warrant. Every failure is an ``error``.

    Redirects are never followed. ``before_request`` runs on the open
    connection before anything is sent (for example to authenticate the peer).
    ``timeout`` bounds the whole exchange, from looking up the host to the
    last byte of the reply.
    """
    guard = threading.Lock()
    opened: List[Any] = []  # The connection's socket, once there is one.
    abandoned = False  # The caller's deadline has passed.
    late = f"The issuer at {where} did not answer within {timeout:g} seconds" if timeout is not None else ""

    def hold_socket(connected: http.client.HTTPConnection) -> None:
        """Keep the socket for the deadline to act on, and stop if the deadline has already passed.

        The connection lets go of its socket as soon as a reply says it will
        close, while the reply's body is still to be read from it.
        """
        sock = getattr(connected, "sock", None)
        with guard:
            if sock is not None and not opened:
                opened.append(sock)
            gone = abandoned
        if gone:
            raise error(late)

    def exchange() -> Tuple[int, bytes]:
        connection = connect()
        try:
            connection.connect()
            hold_socket(connection)  # Nothing is sent once the caller has given up.
            if before_request is not None:
                before_request(connection)
            connection.request(
                "POST",
                path,
                body=body,
                headers={"Content-Type": "application/json", "Accept": "application/json", **headers},
            )
            response = connection.getresponse()
            return response.status, response.read(_MAX_BODY_BYTES + 1)
        finally:
            connection.close()

    def within_the_deadline() -> Tuple[int, bytes]:
        """Run the exchange in a thread of its own and wait for it no longer than ``timeout``.

        Nothing less covers every step. Looking up a host name has no time
        limit, each address tried gets a whole one, and each read of the reply
        starts another.
        """
        nonlocal abandoned
        if not _reserve_exchange():
            raise error(
                f"Could not complete the exchange with the issuer at {where}: "
                "too many exchanges are in progress or have not ended yet"
            )
        outcome: List[Tuple[bool, Any]] = []
        finished = threading.Event()

        def run() -> None:
            try:
                outcome.append((True, exchange()))
            except BaseException as exc:
                outcome.append((False, exc))
            finally:
                _release_exchange()
                finished.set()

        try:
            threading.Thread(target=run, name="tenuo-spiffe-exchange", daemon=True).start()
        except RuntimeError as exc:  # The interpreter cannot start another thread.
            _release_exchange()
            raise error(f"Could not complete the exchange with the issuer at {where}: {exc}") from exc
        if not finished.wait(timeout):
            with guard:
                abandoned = True
                sock = opened[0] if opened else None
            if sock is not None:
                try:
                    # The plain socket's own method: it wakes a read in progress and leaves the TLS state alone.
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)
                except OSError:
                    pass
            raise error(late)
        succeeded, value = outcome[0]
        if not succeeded:
            raise value
        return value

    try:
        status, payload = exchange() if timeout is None else within_the_deadline()
    except IssuanceError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise error(f"The TLS certificate presented by {where} was not accepted: {exc.verify_message}") from exc
    except ssl.SSLError as exc:
        raise error(f"TLS with the issuer at {where} failed: {exc.reason or exc}") from exc
    except (OSError, http.client.HTTPException, UnicodeError) as exc:  # UnicodeError: an unusable host name.
        raise error(f"Could not complete the exchange with the issuer at {where}: {exc}") from exc
    try:
        reply = json.loads(payload) if len(payload) <= _MAX_BODY_BYTES else None
    except (ValueError, RecursionError):
        reply = None
    if status != 200 or not isinstance(reply, dict):
        message = reply.get("message") if isinstance(reply, dict) else None
        if isinstance(message, str) and message:
            raise error(f"Issuer refused (HTTP {status}): {message[:200]}")
        raise error(f"The issuer at {where} answered HTTP {status} without a warrant")
    return _checked_warrant(reply.get("warrant"), trusted, holder_key, error)


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
