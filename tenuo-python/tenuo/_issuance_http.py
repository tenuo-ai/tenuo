"""Shared HTTP plumbing for the single-request issuance exchanges.

Internal. The endpoints and clients of :mod:`tenuo.spiffe_jwt`,
:mod:`tenuo.spiffe_forwarded` and :mod:`tenuo.oauth` are built on this, so
limits, deadlines and error handling are the same for all of them.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import http.client
import json
import logging
import socket
import ssl
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple, Type

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
# The OAuth 2.0 Token Exchange request shape (RFC 8693), for callers that already speak it.
_FORM = b"application/x-www-form-urlencoded"
_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_WARRANT_TOKEN_TYPE = "urn:tenuo:params:oauth:token-type:warrant"
_TASK_DETAIL_TYPE = "tenuo_task"
_EXCHANGE_FIELDS = frozenset(
    {"grant_type", "subject_token", "subject_token_type", "requested_token_type", "authorization_details"}
)
_TASK_DETAIL_FIELDS = frozenset({"type", "task", "holder", "timestamp", "nonce", "signature"})
# How each refusal is named in a token-exchange error reply (RFC 6749, section 5.2).
_EXCHANGE_ERRORS = {
    400: "invalid_request",
    401: "invalid_grant",
    403: "invalid_authorization_details",  # RFC 9396: the task in them was not granted.
    404: "invalid_request",
    405: "invalid_request",
    408: "invalid_request",
    413: "invalid_request",
    415: "invalid_request",
    503: "temporarily_unavailable",
}
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


def _strict_json(raw: Any) -> Any:
    """JSON with one meaning: no repeated member names, no NaN or Infinity."""

    def members(pairs: Any) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON member")
            result[name] = value
        return result

    def constant(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")

    return json.loads(raw, object_pairs_hook=members, parse_constant=constant)


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
        self.unverified = 0  # Token-exchange requests whose body is being read before the caller is known.


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
    _who = "workload"  # What this family calls a caller, in messages.

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

    # Whether checking a credential is real work (a signature, a key fetch) that belongs off the event loop.
    _check_in_pool = False

    def _verify(self, credential: Any) -> Any:
        """Check the credential and return what the rest of the exchange needs. May raise ``_Refusal``."""
        return credential

    async def _checked(self, credential: Any) -> Any:
        """Check the credential before the request is admitted, so only a caller with a valid one holds a place.

        Where that is real work it runs in a small pool of its own, so policy
        calls waiting on a slow dependency never hold up telling a valid
        caller from an invalid one. At most ``max_concurrent`` credentials are
        waiting or being checked: beyond that the answer is 503. A check that
        has been handed over is counted until it has run, whether or not its
        caller is still there.
        """
        if not self._check_in_pool:
            return self._verify(credential)
        places = self._places
        if places.checking >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        try:
            work = asyncio.wrap_future(self._check_pool.submit(self._verify, credential))
        except RuntimeError:
            raise _Refusal(503, "unavailable", "Issuer is shutting down") from None
        places.checking += 1

        def checked(done: "asyncio.Future[Any]") -> None:
            places.checking -= 1
            if not done.cancelled():
                done.exception()  # Looked at, so a caller that left does not leave a warning behind.

        work.add_done_callback(checked)
        return await asyncio.shield(work)

    async def _started(self) -> None:
        """Called when the server starts the application (ASGI lifespan). The server takes requests once it returns."""

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

    def _check_threads(self) -> int:
        """How many threads check credentials, where that is done in a pool."""
        return min(4, self._max_workers)

    def _new_pool(self) -> ThreadPoolExecutor:
        if self._check_in_pool:
            self._check_pool = ThreadPoolExecutor(self._check_threads(), thread_name_prefix="tenuo-issuance-check")
        return ThreadPoolExecutor(self._max_workers, thread_name_prefix="tenuo-issuance-http")

    def close(self) -> None:
        """Release the worker threads. Called on ASGI lifespan shutdown."""
        self._closed = True
        self._pool.shutdown(wait=False)
        if self._check_in_pool:
            self._check_pool.shutdown(wait=False)

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if self._closed:  # Started again after a shutdown: the server was restarted in this process.
                        # Work the earlier run left behind may never report back (its event
                        # loop is gone), so this run counts its requests afresh.
                        self._pool, self._places, self._closed = self._new_pool(), _Places(), False
                    await self._started()
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        exchange = self._is_exchange(scope)
        try:
            warrant = await self._issue(scope, receive)
            status, reply = 200, {"warrant": warrant.to_base64()}
            if exchange:
                remaining = datetime.fromisoformat(warrant.expires_at()).timestamp() - time.time()
                reply = {
                    "access_token": warrant.to_base64(),
                    "issued_token_type": _WARRANT_TOKEN_TYPE,
                    "token_type": "N_A",  # RFC 8693: not a token to present as a bearer access token.
                    "expires_in": max(0, int(remaining)),
                }
        except _Refusal as refusal:
            status, reply = refusal.status, {"error": refusal.error, "message": refusal.message}
            self._log.info("%s refused (%d): %s", self._what, status, refusal.message)
        except Exception:
            self._log.exception("%s failed", self._what)
            status, reply = 503, {"error": "unavailable", "message": "Issuer error"}
        if exchange and status != 200:
            # A token endpoint answers 400 for a token or a request it does not accept (RFC 6749, section 5.2).
            reply = {"error": _EXCHANGE_ERRORS.get(status, "invalid_request"), "error_description": reply["message"]}
            status = 400 if status in (401, 403) else status
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
        if self._is_exchange(scope):
            return await self._exchange(scope, receive)
        credential = await self._checked(self._credential(scope))
        slot = self._admit(credential)
        try:
            return await self._serve(credential, receive, slot)
        finally:
            # A cancelled request whose policy or audit call is still running
            # keeps its place until that call returns.
            if not slot.follows_work:
                slot.release()

    def _admit(self, credential: Any) -> _Slot:
        """Take a place for a request whose caller is known, or refuse it at once.

        The place is kept until the request has finished, so one limit covers
        the requests being read and those being worked on.
        """
        if self._in_progress >= self._max_concurrent:
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        key = self._limit_key(credential) if self._max_per_key is not None else None
        if key is not None and self._per_key.get(key, 0) >= (self._max_per_key or 0):
            raise _Refusal(503, "unavailable", f"Too many requests in progress for this {self._who}; retry shortly")
        return _Slot(self, key)

    async def _body(self, receive: _Receive) -> bytes:
        # A deadline for the body, so a slow sender cannot hold its place for long.
        try:
            return await asyncio.wait_for(self._read_body(receive), self._body_timeout)
        except asyncio.TimeoutError:
            raise _Refusal(408, "timeout", "Request body was not received in time") from None

    @staticmethod
    def _holder_and_proof(request: Any) -> Tuple[PublicKey, Any, HolderProof]:
        """The holder key, task and proof from the fields every request shape carries."""
        try:
            holder = PublicKey.from_bytes(base64.b64decode(request["holder"], validate=True))
            proof = HolderProof(
                request["timestamp"],
                base64.b64decode(request["nonce"], validate=True),
                base64.b64decode(request["signature"], validate=True),
            )
        except (ValueError, TypeError, KeyError, RecursionError, binascii.Error):
            raise _Refusal(400, "invalid_request", "Malformed request") from None
        except Exception:  # A holder key the core rejects.
            raise _Refusal(400, "invalid_request", "Invalid holder key") from None
        return holder, request["task"], proof

    async def _serve(self, credential: Any, receive: _Receive, slot: _Slot) -> Warrant:
        body = await self._body(receive)
        try:
            request = self._decode_request(body)
            if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
                raise ValueError
            if type(request["v"]) is not int or request["v"] != _PROTOCOL_VERSION:  # Not true, not 1.0.
                raise _Refusal(400, "invalid_request", "Unsupported protocol version")
        except _Refusal:
            raise
        except (ValueError, TypeError, RecursionError):
            raise _Refusal(400, "invalid_request", "Malformed request") from None
        holder, task_id, proof = self._holder_and_proof(request)
        return await self._work(credential, holder, task_id, proof, slot)

    async def _work(self, credential: Any, holder: PublicKey, task_id: Any, proof: HolderProof, slot: _Slot) -> Warrant:
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

    # -- the token-exchange request shape -----------------------------------

    # Subject token types this endpoint takes in an RFC 8693 request. Empty: JSON requests only.
    _subject_token_types: FrozenSet[str] = frozenset()

    def _is_exchange(self, scope: _Scope) -> bool:
        if not self._subject_token_types:
            return False
        types = [value for name, value in scope.get("headers", ()) if name.lower() == b"content-type"]
        return len(types) == 1 and types[0].split(b";")[0].strip().lower() == _FORM

    def _exchange_credential(self, token: str) -> Any:
        """The credential for a token that arrived in the body, in the form ``_credential`` returns."""
        raise NotImplementedError

    @staticmethod
    def _same_token(scope: _Scope, token: str) -> None:
        """Refuse a token-exchange request whose Authorization header is not its subject token.

        The request names its token in the body. Through a gateway that checks
        a bearer token it carries that header as well, and then the two must
        be one token: a header is never accepted and then ignored.
        """
        values = [value for name, value in scope.get("headers", ()) if name.lower() == b"authorization"]
        if not values:
            return
        scheme, _, value = (values[0] if len(values) == 1 else b"").partition(b" ")
        if scheme.lower() != b"bearer" or not hmac.compare_digest(value.strip(), token.encode("utf-8")):
            raise _Refusal(400, "invalid_request", "The Authorization header does not carry the subject token")

    async def _exchange(self, scope: _Scope, receive: _Receive) -> Warrant:
        """One RFC 8693 request: the token is in the body, so the body is read before the caller is known.

        Only a share of the places is open to such requests, so callers who
        have not shown a token yet cannot keep out those who have.
        """
        places = self._places
        if places.unverified >= max(1, self._max_concurrent // 4):
            raise _Refusal(503, "unavailable", "Issuer is busy; retry shortly")
        places.unverified += 1
        try:
            body = await self._body(receive)
        finally:
            places.unverified -= 1
        try:
            fields = urllib.parse.parse_qs(
                body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=16
            )
            if set(fields) != _EXCHANGE_FIELDS or any(len(values) != 1 for values in fields.values()):
                raise ValueError
            request = {name: values[0] for name, values in fields.items()}
            if request["grant_type"] != _EXCHANGE_GRANT or request["requested_token_type"] != _WARRANT_TOKEN_TYPE:
                raise ValueError
            if request["subject_token_type"] not in self._subject_token_types:
                raise ValueError
            details = self._decode_request(request["authorization_details"].encode("utf-8"))
            if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
                raise ValueError
            detail = details[0]
            if set(detail) != _TASK_DETAIL_FIELDS or detail["type"] != _TASK_DETAIL_TYPE:
                raise ValueError
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise _Refusal(400, "invalid_request", "Malformed token-exchange request") from None
        holder, task_id, proof = self._holder_and_proof(detail)
        self._same_token(scope, request["subject_token"])
        credential = await self._checked(self._exchange_credential(request["subject_token"]))
        slot = self._admit(credential)
        try:
            return await self._work(credential, holder, task_id, proof, slot)
        finally:
            if not slot.follows_work:
                slot.release()

    @staticmethod
    def _decode_request(body: bytes) -> Any:
        return _strict_json(body)

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
