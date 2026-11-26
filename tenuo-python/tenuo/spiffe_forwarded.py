"""Warrant issuance for workloads whose mutual TLS ends at a proxy.

Use this when a service mesh sidecar or an ingress proxy (Envoy, Istio)
terminates the agent's mutual TLS in front of the issuer and passes the
client's identity on in the ``x-forwarded-client-cert`` header.

The issuer cannot check this identity itself. It never sees the agent's
certificate or a signature made with the agent's key, only a header. So the
identity is exactly as trustworthy as two things you operate:

* the proxy, which must verify client certificates against the SPIFFE trust
  bundle and replace any ``x-forwarded-client-cert`` header the client sent, and
* the path from the proxy to this process, because anything that can reach the
  issuer's port from a trusted proxy address can write the header itself.

Where the issuer can see the SVID, prefer the mutual TLS exchange in
:mod:`tenuo.spiffe` or JWT-SVIDs in :mod:`tenuo.spiffe_jwt`: both are verified
by the issuer and do not depend on the proxy.

The exchange is one HTTP request, the same body as the JWT-SVID exchange. See
:class:`SpiffeForwardedIssuerApp` for the wire format.
"""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import logging
import re
import secrets
import ssl
import time
import urllib.parse
from typing import Any, List, Mapping, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes as certificate_hashes

from tenuo import PublicKey, SigningKey, Warrant
from tenuo._spiffe_http import _IssuerApp, _post_for_warrant, _Refusal, _request_body, _split_url, _where
from tenuo.spiffe import (
    _JWT_NONCE_BYTES,
    _MAX_TASK_ID,
    IssuerKeys,
    SpiffeError,
    SpiffeHolderProof,
    SpiffeIdentity,
    SpiffeTLS,
    SpiffeWarrantIssuer,
    _forwarded_proof_bytes,
    _key_list,
    _positive_int,
    _seconds,
    _trust_domain,
    _trust_domain_names,
)

__all__ = [
    "UNIX_SOCKET",
    "SpiffeForwardedIdentity",
    "SpiffeForwardedIssuerApp",
    "arequest_warrant_forwarded",
    "request_warrant_forwarded",
    "sign_forwarded_holder_proof",
]

logger = logging.getLogger("tenuo.spiffe")

UNIX_SOCKET = "unix"
"""Name for "the proxy reaches the issuer over a Unix socket" in ``trusted_proxies``."""

_HEADER = b"x-forwarded-client-cert"
# Headers an ASGI server or a middleware may take the client address from.
_ADDRESS_HEADERS = frozenset({b"x-forwarded-for", b"forwarded", b"x-real-ip"})
_ADDRESS_SEPARATORS = re.compile(rb'[\s,;="]+')
_MAX_HEADER_BYTES = 32 * 1024  # Room for a forwarded certificate and chain, which are ignored.
_MAX_WARRANT_SECONDS = 3600
_KEY = re.compile(r"[A-Za-z]+")
_QUOTED_STOP = re.compile(r'["\\;]')
# Envoy writes these bare. Reading a quoted one would let a quote decide where the identity ends.
_BARE_KEYS = frozenset({"by", "hash", "uri", "dns"})
# What Envoy writes ahead of the URI. None of it is text a client certificate controls unescaped.
_BEFORE_URI = frozenset({"by", "hash", "cert", "chain", "subject"})
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}")
_DNS_NAME = re.compile(r"[A-Za-z0-9*_.-]{1,253}")
_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_MAPPED_IPV4 = ipaddress.IPv6Network("::ffff:0:0/96")  # IPv4 addresses as a dual-stack listener reports them.


def _parse_forwarded(header: str) -> List[List[Tuple[str, str]]]:
    """Split a text ``x-forwarded-client-cert`` value into elements of (lower-case key, value) pairs.

    Elements are separated by commas and pairs by semicolons. A value may be
    quoted; inside quotes a backslash takes the next character literally.
    Anything else is refused: a lenient reading could let text a client
    controls pass for something the proxy wrote.

    A quoted value may not contain a bare semicolon, and ``By``, ``Hash``,
    ``URI`` and ``DNS`` may not be quoted. Envoy escapes semicolons in a
    quoted subject and encodes them in a certificate, so nothing it writes is
    lost, and a quote opened by a client can then never reach across the
    entry an appending proxy adds, which always contains one.
    """
    malformed = SpiffeError("Malformed x-forwarded-client-cert header")
    elements: List[List[Tuple[str, str]]] = []
    pairs: List[Tuple[str, str]] = []
    position, end = 0, len(header)
    while True:
        while not pairs and position < end and header[position] in " \t":
            position += 1  # Space after the comma between elements.
        equals = header.find("=", position)
        if equals < 0 or not _KEY.fullmatch(header, position, equals):
            raise malformed
        key, position = header[position:equals].lower(), equals + 1
        if position < end and header[position] == '"':
            if key in _BARE_KEYS:
                raise malformed
            position += 1
            parts: List[str] = []
            while True:
                stop = _QUOTED_STOP.search(header, position)
                if stop is None or stop[0] == ";" or (stop[0] == "\\" and stop.end() >= end):
                    raise malformed  # No closing quote, or a separator inside the quotes.
                parts.append(header[position : stop.start()])
                if stop[0] == '"':
                    position = stop.end()
                    break
                escaped = header[stop.end()]
                parts.append(escaped if escaped == '"' else "\\" + escaped)
                position = stop.end() + 1
            value = "".join(parts)
        else:
            start = position
            while position < end and header[position] not in ';,"':
                position += 1
            value = header[start:position]
        pairs.append((key, value))
        if position >= end:
            elements.append(pairs)
            return elements
        separator = header[position]
        position += 1
        if separator == ",":
            elements.append(pairs)
            pairs = []
        elif separator != ";":
            raise malformed


def _forwarded_certificate(encoded: str, uri: str, digest: str) -> float:
    """Check the certificate a proxy forwarded against the identity read from the header. Returns its expiry.

    The certificate must be the one the header's ``Hash`` names, be valid now,
    and carry exactly one URI name, equal to the header's ``URI`` character
    for character.
    """
    try:
        certificates = x509.load_pem_x509_certificates(urllib.parse.unquote_to_bytes(encoded))
    except ValueError:
        certificates = []
    if len(certificates) != 1:
        raise SpiffeError("The forwarded certificate cannot be read")
    leaf = certificates[0]
    if leaf.fingerprint(certificate_hashes.SHA256()).hex() != digest.lower():
        raise SpiffeError("The forwarded certificate is not the one the header's hash names")
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier
        )
        starts, expires = leaf.not_valid_before_utc.timestamp(), leaf.not_valid_after_utc.timestamp()
    except x509.ExtensionNotFound:
        names = []
        starts, expires = 0.0, 0.0
    except Exception as exc:  # The library reports unreadable content with several unrelated types.
        raise SpiffeError("The forwarded certificate cannot be read") from exc
    if names != [uri]:
        raise SpiffeError("The forwarded URI is not the certificate's only URI name")
    if not starts <= time.time() < expires:
        raise SpiffeError("The forwarded certificate is not currently valid")
    return expires


class SpiffeForwardedIdentity:
    """Accepts the client identity a trusted proxy forwarded in ``x-forwarded-client-cert``.

    ``trust_domain`` (and ``federates_with``) are the trust domains workloads
    may belong to. ``audience`` is a name for this issuer that agents sign into
    their holder proof, so a proof made for one issuer is useless at another.

    ``trusted_proxies`` lists where the proxy connects from: IP addresses or
    networks such as ``"127.0.0.1"`` for a sidecar you run yourself or
    ``"127.0.0.6"`` for an Istio sidecar, or :data:`UNIX_SOCKET`.
    Requests from anywhere else are refused before the header is read. There is
    no default, because this list is the whole security boundary: anything that
    can connect from one of these addresses can claim any identity. List
    :data:`UNIX_SOCKET` only when the ASGI server listens on a Unix socket and
    nothing else: it trusts every request the server reports no address for.

    The header must describe exactly one client certificate, with exactly one
    ``URI`` (the SPIFFE ID), its ``Hash``, and by default the certificate
    itself (``Cert``; for Envoy, ``cert: true``). That is what a proxy writes when
    it replaces the header or appends to an empty one (Envoy ``SANITIZE_SET``
    or ``APPEND_FORWARD``). A header with more than one entry is refused: the
    client sent one of its own, or the request crossed a second proxy. A proxy
    set to pass a client's header through unchanged (``FORWARD_ONLY``,
    ``ALWAYS_FORWARD_ONLY``) must not be used. Set ``expected_by`` to the
    proxy's own SPIFFE ID to also require that the entry names it in ``By``.

    The forwarded certificate is what the ``URI`` is checked against: it must
    be the certificate the ``Hash`` names, be valid now, and carry exactly one
    URI name, equal to the header's. Warrants never outlive it, and never
    last longer than ``max_warrant_seconds`` whatever the policy grants. This
    does not replace the proxy checking client certificates against the trust
    bundle: this class has no bundle and checks no signature.

    ``require_certificate=False`` accepts a header without the certificate,
    for a mesh that cannot forward it (Istio does not). The issuer then takes
    the proxy's reading of the name, with these consequences:

    * Envoy copies URI and DNS names from the certificate into the header as
      they are, so a certificate with separators in a name could add fields.
      The ``URI`` must therefore be the last thing in the header: the name is
      then read to its end, never cut short at a separator. A header with
      ``DNS`` names after the URI is refused for the same reason.
    * HTTP servers drop spaces and tabs from the end of a header value before
      this class sees it, so a certificate name that ended in them is read as
      the name without them.
    * Some meshes always forward DNS names (Istio does), so a certificate
      that has them could never be identified. ``allow_dns_names=True``
      accepts ``DNS`` names after the URI. The identity is then the URI up to
      the first separator, and a certificate whose URI name itself contained
      ``;DNS=`` would be read as the shorter name.

    So turn ``require_certificate`` off only when every authority the proxy
    trusts issues well-formed SPIFFE IDs, as SPIRE and Istio do.
    """

    def __init__(
        self,
        trust_domain: str,
        *,
        audience: str,
        trusted_proxies: Sequence[str],
        federates_with: Sequence[str] = (),
        expected_by: Optional[str] = None,
        max_warrant_seconds: int = 300,
        allow_dns_names: bool = False,
        require_certificate: bool = True,
    ):
        self.trust_domain = trust_domain
        if not isinstance(allow_dns_names, bool) or not isinstance(require_certificate, bool):
            raise ValueError("allow_dns_names and require_certificate must be True or False")
        self._allow_dns_names = allow_dns_names
        self._require_certificate = require_certificate
        self._domains = frozenset((trust_domain, *_trust_domain_names(trust_domain, federates_with)))
        if not isinstance(audience, str) or not audience or len(audience) > 2048:
            raise ValueError("audience must be a non-empty string of at most 2048 characters")
        self.audience = audience
        if isinstance(trusted_proxies, str) or not trusted_proxies:
            raise ValueError("trusted_proxies must list the addresses the proxy connects from")
        self._unix = False
        networks: List[_Network] = []
        for entry in trusted_proxies:
            if entry == UNIX_SOCKET:
                self._unix = True
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except (ValueError, TypeError):
                raise ValueError(f"trusted_proxies entries are IP addresses, networks, or 'unix': {entry!r}") from None
            if isinstance(network, ipaddress.IPv6Network):
                if _MAPPED_IPV4.subnet_of(network):
                    # Every IPv4 address, written the IPv6 way (or all of IPv6 with it).
                    raise ValueError("trusted_proxies must not cover every address")
                if network.subnet_of(_MAPPED_IPV4):
                    # An IPv4 address or network in its IPv4-mapped form. Peers are compared
                    # as IPv4 however the listener reports them, so keep one form here too.
                    network = ipaddress.IPv4Network(
                        (int(network.network_address) & 0xFFFFFFFF, network.prefixlen - 96), strict=False
                    )
            if network.prefixlen == 0:
                raise ValueError("trusted_proxies must not cover every address")
            networks.append(network)
        self._networks = tuple(networks)
        if expected_by is not None:
            try:
                _trust_domain(expected_by)
            except SpiffeError:
                raise ValueError("expected_by must be the proxy's SPIFFE ID") from None
        self._expected_by = expected_by
        if not _positive_int(max_warrant_seconds) or not 5 <= max_warrant_seconds <= _MAX_WARRANT_SECONDS:
            raise ValueError(f"max_warrant_seconds must be between 5 and {_MAX_WARRANT_SECONDS}")
        self._max_warrant_seconds = max_warrant_seconds

    def trusts_peer(self, peer: Optional[str]) -> bool:
        """Whether ``peer`` (an IP address, or :data:`UNIX_SOCKET`) is one of the trusted proxies."""
        if peer == UNIX_SOCKET:
            return self._unix
        if not isinstance(peer, str):
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:  # An IPv4 peer seen through a dual-stack listener.
            address = mapped
        return any(address.version == network.version and address in network for network in self._networks)

    def authenticate(self, header: str, *, peer: Optional[str]) -> SpiffeIdentity:
        """Return the identity the proxy at ``peer`` forwarded, or raise :class:`tenuo.spiffe.SpiffeError`.

        ``peer`` is the address the request arrived from, as the socket
        reports it: an IP address, or :data:`UNIX_SOCKET`. ``None`` is refused.
        ``header`` is the single ``x-forwarded-client-cert`` value.
        """
        if not self.trusts_peer(peer):
            raise SpiffeError("The request did not arrive from a trusted proxy")
        if not isinstance(header, str) or len(header) > _MAX_HEADER_BYTES:
            raise SpiffeError("Malformed x-forwarded-client-cert header")
        # No trimming here: the identity is read to the very end of the header as
        # the server delivered it. The server has already dropped spaces and tabs
        # from that end, which only a forwarded certificate can show.
        if header.lstrip(" \t").startswith("["):
            raise SpiffeError("The JSON form of x-forwarded-client-cert is not supported; use the text form")
        elements = _parse_forwarded(header)
        if len(elements) != 1:
            raise SpiffeError(
                "x-forwarded-client-cert describes more than one client certificate: the client sent its own "
                "header, or the request crossed more than one proxy"
            )
        element = elements[0]
        keys = [key for key, _ in element]
        uris = [value for key, value in element if key == "uri"]
        hashes = [value for key, value in element if key == "hash"]
        if len(uris) != 1:
            raise SpiffeError(
                "The proxy did not forward exactly one URI for the client certificate "
                "(for Envoy, enable uri in set_current_client_cert_details)"
            )
        if len(hashes) != 1 or not _SHA256_HEX.fullmatch(hashes[0]):
            raise SpiffeError("The proxy did not forward the client certificate hash")
        expires = time.time() + self._max_warrant_seconds
        forwarded = [value for key, value in element if key == "cert"]
        if len(forwarded) > 1:
            raise SpiffeError("Malformed x-forwarded-client-cert header")
        if forwarded:
            # With the certificate at hand the URI is checked against it, not taken as read.
            expires = min(expires, _forwarded_certificate(forwarded[0], uris[0], hashes[0]))
        elif self._require_certificate:
            raise SpiffeError(
                "The proxy did not forward the client certificate (for Envoy, enable cert in "
                "set_current_client_cert_details; for Istio, see require_certificate)"
            )
        # Without the certificate, the URI must end the header, after nothing but
        # what Envoy writes before it. Its value is then the certificate's whole
        # URI name: a name with a separator in it would leave something behind it
        # and be refused here.
        position = keys.index("uri")
        after = element[position + 1 :]
        if (forwarded or self._allow_dns_names) and all(
            key == "dns" and _DNS_NAME.fullmatch(value) for key, value in after
        ):
            after = []  # Checked against the certificate, or accepted by the operator.
        if after or not _BEFORE_URI.issuperset(keys[:position]):
            raise SpiffeError(
                "x-forwarded-client-cert must end with the certificate's URI: "
                "stop the proxy forwarding DNS names, or see allow_dns_names"
            )
        if self._expected_by is not None and [value for key, value in element if key == "by"] != [self._expected_by]:
            raise SpiffeError("The forwarded identity was not recorded by the expected proxy")
        if _trust_domain(uris[0]) not in self._domains:
            raise SpiffeError("Forwarded identity belongs to a different trust domain")
        return SpiffeIdentity(uris[0], hashes[0].lower(), expires, "forwarded")


# -- agent side -------------------------------------------------------------


def sign_forwarded_holder_proof(
    holder_key: SigningKey, *, audience: str, task_id: str, timestamp: Optional[int] = None
) -> SpiffeHolderProof:
    """Bind a holder key to one issuer audience and task, for the forwarded-identity exchange.

    Returns the proof for :meth:`tenuo.spiffe.SpiffeWarrantIssuer.issue_forwarded`.
    Each call uses a fresh random nonce, so a retry is a new proof. The proof
    does not name the workload: a workload behind a sidecar does not hold its
    certificate, and its identity comes from the proxy.
    """
    if not isinstance(task_id, str) or not task_id or len(task_id) > _MAX_TASK_ID:
        raise SpiffeError(f"task_id must contain 1–{_MAX_TASK_ID} characters")
    if not isinstance(audience, str) or not audience:
        raise SpiffeError("audience must be a non-empty string")
    stamp = int(time.time()) if timestamp is None else timestamp
    if not _positive_int(stamp) or not 0 <= stamp < 2**40:
        raise SpiffeError("timestamp must be Unix seconds")
    nonce = secrets.token_bytes(_JWT_NONCE_BYTES)
    holder = bytes(holder_key.public_key.to_bytes())
    message = _forwarded_proof_bytes(audience, holder, task_id, stamp, nonce)
    return SpiffeHolderProof(stamp, nonce, bytes(holder_key.sign_raw(message)))


def request_warrant_forwarded(
    url: str,
    *,
    audience: str,
    issuer_key: IssuerKeys,
    holder_key: SigningKey,
    task_id: str,
    tls: Optional[SpiffeTLS] = None,
    issuer_id: Optional[str] = None,
    timeout: float = 10.0,
) -> Warrant:
    """Obtain a warrant from a :class:`SpiffeForwardedIssuerApp`.

    There are two ways to reach the issuer's proxy:

    * ``http://`` with no ``tls``: the request leaves this process in plain
      HTTP and the workload's own sidecar adds mutual TLS. Without a sidecar
      the issuer's proxy sees no client certificate and the request is refused.
    * ``https://`` with a client-side ``tls`` and ``issuer_id``: this process
      opens the mutual TLS connection itself and pins the SPIFFE ID of the
      proxy in front of the issuer before sending anything. This is for a
      proxy you run yourself; an Istio sidecar does not accept it.

    ``audience`` must be the issuer's configured audience. Redirects are not
    followed. The returned warrant is checked against ``issuer_key`` and
    ``holder_key``. Every failure is raised as :class:`tenuo.spiffe.SpiffeError`.
    """
    trusted = _key_list(issuer_key)
    scheme, host, port, path = _split_url(url)
    if scheme == "https":
        if tls is None or issuer_id is None:
            raise ValueError("https:// needs tls= (a client-side SpiffeTLS) and issuer_id= (the proxy's SPIFFE ID)")
        if tls.server_side:
            raise ValueError("request_warrant_forwarded requires a client-side SpiffeTLS")
        _trust_domain(issuer_id)
    elif tls is not None or issuer_id is not None:
        raise ValueError("tls= and issuer_id= apply to https:// only; with http:// the sidecar provides mutual TLS")
    timeout = _seconds("timeout", timeout)
    proof = sign_forwarded_holder_proof(holder_key, audience=audience, task_id=task_id)

    def connect() -> http.client.HTTPConnection:
        if tls is None:
            return http.client.HTTPConnection(host, port, timeout=timeout)
        tls._refresh()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=tls.context)

    def pin_proxy(connection: http.client.HTTPConnection) -> None:
        assert tls is not None
        sock = connection.sock
        if not isinstance(sock, ssl.SSLSocket):
            raise SpiffeError("The connection to the issuer's proxy is not TLS")
        tls.authenticate(sock, expected_id=issuer_id)

    return _post_for_warrant(
        connect,
        _where(host, port),
        path,
        _request_body(holder_key, task_id, proof),
        {},
        trusted,
        holder_key,
        before_request=None if tls is None else pin_proxy,
        timeout=timeout,
    )


async def arequest_warrant_forwarded(url: str, **kwargs: Any) -> Warrant:
    """Async wrapper for :func:`request_warrant_forwarded` (runs in a worker thread)."""
    return await asyncio.to_thread(request_warrant_forwarded, url, **kwargs)


# -- issuer endpoint --------------------------------------------------------


class SpiffeForwardedIssuerApp(_IssuerApp):
    """ASGI application that issues warrants to workloads identified by a trusted proxy.

    Run it with any ASGI server, bound to an address only the proxy can reach
    (loopback or a Unix socket). The server must report the real socket peer:
    turn off any rewriting of the client address from ``X-Forwarded-For``
    (``uvicorn --no-proxy-headers``).

    One request per warrant, sent through the proxy::

        POST <path>
        Content-Type: application/json
        x-forwarded-client-cert: <set by the proxy>

        {"v": 1, "holder": "<base64 Ed25519 public key>", "task": "<task ID>",
         "timestamp": <unix seconds>, "nonce": "<base64, 16 bytes>",
         "signature": "<base64 holder proof>"}

    The reply is ``200 {"warrant": "<base64>"}``, or ``{"error": ..., "message":
    ...}`` with 400 (malformed), 403 (not from the proxy, no usable forwarded
    identity, or refused), 408, 413, or 503 (busy, or the policy or audit
    callback failed). Limits are those of
    :class:`tenuo.spiffe_jwt.SpiffeJWTIssuerApp`, and at most
    ``max_per_identity`` requests from one SPIFFE ID are in progress at once.
    The identity is read before the request body, so a request without a
    usable one costs nothing further.
    """

    _what = "Forwarded-identity issuance"

    def __init__(
        self,
        issuer: SpiffeWarrantIssuer,
        *,
        path: str = "/warrants",
        max_concurrent: int = 256,
        max_workers: int = 32,
        body_timeout: float = 10.0,
        max_per_identity: int = 16,
    ):
        if not isinstance(issuer.forwarded, SpiffeForwardedIdentity):
            raise ValueError(
                "SpiffeForwardedIssuerApp needs an issuer built with forwarded=SpiffeForwardedIdentity(...)"
            )
        if not _positive_int(max_per_identity) or max_per_identity < 1:
            raise ValueError("max_per_identity must be a positive integer")
        super().__init__(
            issuer, path=path, max_concurrent=max_concurrent, max_workers=max_workers, body_timeout=body_timeout
        )
        self._max_per_key = max_per_identity
        self._forwarded: SpiffeForwardedIdentity = issuer.forwarded
        self._warned_at = float("-inf")

    @staticmethod
    def _peer(scope: Mapping[str, Any]) -> Optional[str]:
        """The socket peer as the ASGI server reports it, or None when that is not a real socket address."""
        client, server = scope.get("client"), scope.get("server")
        if client is None:
            # A Unix socket has no client address, and its server address is a
            # path with port None (or, from older servers, missing). A TCP listener
            # that lost track of its peer still reports its own port, and is refused.
            if server is None or (isinstance(server, (list, tuple)) and len(server) == 2 and server[1] is None):
                return UNIX_SOCKET
            return None
        if not isinstance(client, (list, tuple)) or len(client) != 2:
            return None
        host, port = client
        if isinstance(port, str) and port.isascii() and port.isdigit():
            port = int(port)  # Granian reports ports as text.
        # A connected TCP peer always has a port. Port 0 is how Uvicorn marks an
        # address it took from a bare X-Forwarded-For entry, which the sender chose.
        if not isinstance(host, str) or not _positive_int(port) or port < 1:
            return None
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        return host

    @staticmethod
    def _named_in_headers(peer: str, scope: Mapping[str, Any]) -> bool:
        """Whether a header a server may rewrite the client address from names ``peer``.

        A server that rewrites takes the address, and the port when the header
        gives one, from such a header. The application cannot see which
        happened, so a peer address that is also written in the request is not
        proof of where the request came from.
        """
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False  # A Unix socket.
        mapped = getattr(address, "ipv4_mapped", None)
        address = mapped or address
        for name, value in scope.get("headers", ()):
            if name.lower() not in _ADDRESS_HEADERS:
                continue
            for piece in _ADDRESS_SEPARATORS.split(value[:_MAX_HEADER_BYTES]):
                text = piece.decode("latin-1")
                # An entry may be an address, address:port, [address] or [address]:port.
                for candidate in (text, text.rpartition(":")[0]):
                    try:
                        named = ipaddress.ip_address(candidate.strip("[]"))
                    except ValueError:
                        continue
                    if (getattr(named, "ipv4_mapped", None) or named) == address:
                        return True
        return False

    def _credential(self, scope: Mapping[str, Any]) -> SpiffeIdentity:
        peer = self._peer(scope)
        if not self._forwarded.trusts_peer(peer):
            now = time.monotonic()
            if now - self._warned_at >= 60:
                self._warned_at = now
                logger.warning(
                    "Refused a forwarded-identity request from %s, which is not a socket peer in trusted_proxies. "
                    "If that is your proxy's address, add it (an Istio sidecar connects from 127.0.0.6). "
                    "If it is the original client's, stop the ASGI server rewriting client addresses "
                    "(uvicorn --no-proxy-headers, and no FORWARDED_ALLOW_IPS in the environment). "
                    "This warning appears at most once a minute.",
                    scope.get("client") or "an unknown address",
                )
            raise _Refusal(403, "forbidden", "Requests must arrive through the issuer's proxy")
        if peer is not None and self._named_in_headers(peer, scope):
            now = time.monotonic()
            if now - self._warned_at >= 60:
                self._warned_at = now
                logger.warning(
                    "Refused a forwarded-identity request whose client address %s is also named in its "
                    "X-Forwarded-For, Forwarded or X-Real-IP header: the ASGI server may have taken the address "
                    "from there. Stop the server rewriting client addresses (uvicorn --no-proxy-headers). If a "
                    "caller really shares the proxy's address, have the proxy reach the issuer over a Unix "
                    "socket. This warning appears at most once a minute.",
                    peer,
                )
            raise _Refusal(403, "forbidden", "The client address is also named in a forwarding header")
        values = [value for name, value in scope.get("headers", ()) if name.lower() == _HEADER]
        if len(values) != 1 or not values[0].strip():
            raise _Refusal(
                403,
                "unauthenticated",
                "No forwarded client identity: the proxy must terminate mutual TLS and set x-forwarded-client-cert",
            )
        if len(values[0]) > _MAX_HEADER_BYTES:
            raise _Refusal(
                403, "unauthenticated", "x-forwarded-client-cert is too large; forward the URI without the certificate"
            )
        # Read the identity before the body, so only a request that has one can hold a slot.
        try:
            return self._forwarded.authenticate(values[0].decode("latin-1"), peer=peer)
        except SpiffeError as exc:
            raise _Refusal(403, "unauthenticated", str(exc)) from exc

    def _limit_key(self, credential: SpiffeIdentity) -> str:
        return credential.spiffe_id

    def _authorize(
        self, credential: SpiffeIdentity, holder: PublicKey, task_id: Any, proof: SpiffeHolderProof
    ) -> Warrant:
        return self.issuer._issue_forwarded(credential, holder, task_id, proof)
