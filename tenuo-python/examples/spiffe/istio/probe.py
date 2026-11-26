"""Requests a well-behaved agent would never send. Used by check.py to show what the issuer does with them.

Usage: probe.py MODE HOST:PORT
  plain    one request with no identity header, and one with a made-up one, in plain HTTP
  around   the same and more over this pod's own mesh certificate, connecting around its sidecar
  inside   from inside the issuer's pod, straight at the port
  gateway  through an ingress gateway (HOST, no port): plain HTTP, and mutual TLS with a certificate
           from an authority outside the mesh
"""

import http.client
import json
import socket
import ssl
import sys

from tenuo import SigningKey
from tenuo._spiffe_http import _request_body
from tenuo.spiffe_forwarded import sign_forwarded_holder_proof

ISSUER = "spiffe://cluster.local/ns/tenuo/sa/issuer"
AGENT = "spiffe://cluster.local/ns/tenuo/sa/agent"
ENTRY = f'By={ISSUER};Hash={"ab" * 32};Subject="";URI={AGENT}'
mode, target = sys.argv[1], sys.argv[2]
host, _, port = target.partition(":")
audience = sys.argv[3] if len(sys.argv) > 3 else f"http://{target}/warrants"


def post(headers, source=None, tls=False):
    holder = SigningKey.generate()
    proof = sign_forwarded_holder_proof(holder, audience=audience, task_id="refund-task-123")
    body = _request_body(holder, "refund-task-123", proof)
    if mode == "around":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Mesh certificates carry a SPIFFE ID, not a host name.
        context.load_verify_locations("/certs/root-cert.pem")
        context.load_cert_chain("/certs/cert-chain.pem", "/certs/key.pem")
        context.set_alpn_protocols(["istio"])  # What an Istio sidecar expects of a mesh peer.
        connection = http.client.HTTPSConnection(host, int(port), timeout=10, context=context)
    elif mode == "gateway":
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.load_verify_locations("/gateway-client/ca.crt")
            context.load_cert_chain("/gateway-client/client.crt", "/gateway-client/client.key")
            connection = http.client.HTTPSConnection(host, 443, timeout=10, context=context)
        else:
            connection = http.client.HTTPConnection(host, 80, timeout=10)
    else:
        connection = http.client.HTTPConnection(host, int(port), timeout=10, source_address=source)
    try:
        connection.putrequest("POST", "/warrants")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        reply = json.loads(response.read())
        return f"{response.status} {reply.get('error') or 'warrant'}: {reply.get('message', '')}"
    except (OSError, ValueError) as exc:
        return f"no reply ({type(exc).__name__})"
    finally:
        connection.close()


cases = {
    "nothing of its own": [],
    "a complete made-up entry": [("x-forwarded-client-cert", ENTRY)],
    "an entry that opens a quote": [("x-forwarded-client-cert", f'By={ISSUER};Hash={"ab" * 32};URI={AGENT};X="')],
    "two made-up header lines": [("x-forwarded-client-cert", ENTRY), ("x-forwarded-client-cert", ENTRY)],
    "a made-up X-Forwarded-For": [("X-Forwarded-For", "127.0.0.6")],
}
if mode == "inside":
    pod_address = socket.gethostbyname(socket.gethostname())
    for label, to, source in (
        ("loopback", "127.0.0.1", None),
        ("pod address", pod_address, None),
        ("pod address, as 127.0.0.6", pod_address, ("127.0.0.6", 0)),
    ):
        host = to
        print(f"{label}: {post(cases['a complete made-up entry'], source)}")
elif mode == "gateway":
    for transport, tls in (("plain HTTP", False), ("mutual TLS", True)):
        for label in ("nothing of its own", "a complete made-up entry"):
            print(f"{transport}, {label}: {post(cases[label], tls=tls)}")
else:
    for label, headers in cases.items():
        print(f"{label}: {post(headers)}")
