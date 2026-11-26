#!/usr/bin/env python3
"""Run a disposable real SPIRE server/agent and exercise demo.py with their SVIDs.

Requires Linux, spire-server and spire-agent on PATH. The accompanying Dockerfile
provides these. All sockets, credentials, data, and logs live in a temp directory.
After the demo, the harness waits for SPIRE to renew the short-lived SVIDs and
checks that a running issuer picks up the renewal without a restart, once with
credential files and once straight from the Workload API socket. It also
exchanges a real JWT-SVID for a warrant over HTTP, starts a second SPIRE
deployment for another trust domain to exercise federation, and, when envoy is
on PATH, puts a real Envoy in front of an issuer that takes the agent's
identity from the header Envoy sets.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from demo import AGENT_ID, ISSUER_ID, policy, run, tls_config
from tenuo import Exact, Range, SigningKey
from tenuo.spiffe import (
    SpiffeError,
    SpiffeGrant,
    SpiffeIssuerServer,
    SpiffeTLS,
    SpiffeWarrantIssuer,
    arequest_warrant,
)
from tenuo.spiffe_forwarded import (
    SpiffeForwardedIdentity,
    SpiffeForwardedIssuerApp,
    arequest_warrant_forwarded,
    sign_forwarded_holder_proof,
)
from tenuo.spiffe_jwt import SpiffeJWT, SpiffeJWTIssuerApp, arequest_warrant_jwt, fetch_jwt_svid

SVID_TTL_SECONDS = 120  # SPIRE renews at about half of this.
DOMAIN = "demo.test"
PARTNER_DOMAIN = "partner.test"
PARTNER_AGENT_ID = f"spiffe://{PARTNER_DOMAIN}/agent"


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=15)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def replace_file(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Write atomically, as a credential helper should."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.chmod(mode)
    os.replace(temporary, path)


def export_svids(agent_socket: str, exported: Path, directory: Path) -> dict:
    """Fetch both SVIDs from the Workload API. Returns role -> certificate fingerprint."""
    for stale in exported.glob("*"):
        stale.unlink()
    command("spire-agent", "api", "fetch", "x509", "-socketPath", agent_socket, "-write", str(exported))
    roles = {AGENT_ID: "agent", ISSUER_ID: "issuer"}
    found = {}
    for cert_path in exported.glob("svid.*.pem"):
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        identity = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        role = roles[identity.get_values_for_type(x509.UniformResourceIdentifier)[0]]
        # Key first: a reader that sees the new certificate also sees its key.
        replace_file(directory / f"{role}-key.pem", cert_path.with_suffix(".key").read_bytes(), 0o600)
        replace_file(directory / f"{role}.pem", cert_path.read_bytes())
        found[role] = cert.fingerprint(hashes.SHA256()).hex()
    if set(found) != {"agent", "issuer"}:
        raise RuntimeError("SPIRE did not return both workload identities")
    return found


async def rotation_check(directory: Path, refetch) -> None:
    """Keep one issuer running while SPIRE renews both SVIDs."""
    server_tls, client_tls = tls_config(directory, "issuer"), tls_config(directory, "agent")
    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=policy)
    options = dict(issuer_id=ISSUER_ID, issuer_key=root.public_key, holder_key=holder, task_id="approved-refund-123")
    async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0, reload_interval=0.5) as server:
        await arequest_warrant(client_tls, server.address, **options)
        before = (server_tls.identity.certificate_sha256, client_tls.identity.certificate_sha256)
        deadline = time.monotonic() + SVID_TTL_SECONDS
        while True:
            current = await asyncio.to_thread(refetch)
            if current["issuer"] != before[0] and current["agent"] != before[1]:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("SPIRE did not renew the SVIDs")
            await asyncio.sleep(2)
        await asyncio.sleep(1.5)  # Let the issuer's reload loop pick up the files.
        await arequest_warrant(client_tls, server.address, **options)
        if server_tls.identity.certificate_sha256 != current["issuer"]:
            raise RuntimeError("Issuer did not reload its renewed SVID")
        if client_tls.identity.certificate_sha256 != current["agent"]:
            raise RuntimeError("Agent did not reload its renewed SVID")
    print("Verified: a running issuer and agent switched to SVIDs renewed by SPIRE.")


async def workload_api_check(agent_socket: str) -> None:
    """Issuer and agent take their SVIDs from the Workload API and follow a renewal."""
    # Both demo identities belong to one Unix user, so each side names the SVID it wants.
    server_tls = SpiffeTLS.from_workload_api(
        trust_domain="demo.test", server_side=True, socket_path=agent_socket, spiffe_id=ISSUER_ID
    )
    client_tls = SpiffeTLS.from_workload_api(
        trust_domain="demo.test", server_side=False, socket_path=agent_socket, spiffe_id=AGENT_ID
    )
    try:
        root, holder = SigningKey.generate(), SigningKey.generate()
        issuer = SpiffeWarrantIssuer(tls=server_tls, signing_key=root, policy=policy)
        options = dict(
            issuer_id=ISSUER_ID, issuer_key=root.public_key, holder_key=holder, task_id="approved-refund-123"
        )
        async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0) as server:
            await arequest_warrant(client_tls, server.address, **options)
            before = (server_tls.identity.certificate_sha256, client_tls.identity.certificate_sha256)
            deadline = time.monotonic() + SVID_TTL_SECONDS
            while (
                server_tls.identity.certificate_sha256 == before[0]
                or client_tls.identity.certificate_sha256 == before[1]
            ):
                if time.monotonic() > deadline:
                    raise RuntimeError("The Workload API did not deliver renewed SVIDs")
                await asyncio.sleep(1)
            await arequest_warrant(client_tls, server.address, **options)
    finally:
        server_tls.close()
        client_tls.close()
    print("Verified: issuer and agent followed a renewal straight from the Workload API.")


async def jwt_check(agent_socket: str) -> None:
    """Exchange a JWT-SVID minted by SPIRE for a warrant, over HTTP."""
    import uvicorn

    audience = ISSUER_ID  # Tokens must be requested for this issuer.
    validator = SpiffeJWT.from_workload_api(trust_domain="demo.test", audience=audience, socket_path=agent_socket)
    root, holder = SigningKey.generate(), SigningKey.generate()
    app = SpiffeJWTIssuerApp(SpiffeWarrantIssuer(signing_key=root, policy=policy, jwt=validator))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    serving = asyncio.ensure_future(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("The JWT issuer endpoint did not start")
        url = f"http://127.0.0.1:{port}/warrants"  # Loopback only; production traffic is HTTPS.
        options = dict(audience=audience, issuer_key=root.public_key, holder_key=holder, task_id="approved-refund-123")

        def token(for_audience=audience, spiffe_id=AGENT_ID):
            return fetch_jwt_svid(for_audience, socket_path=agent_socket, spiffe_id=spiffe_id)

        warrant = await arequest_warrant_jwt(url, token=token, **options)
        if warrant.authorized_holder != holder.public_key:
            raise RuntimeError("The warrant is bound to the wrong holder")
        refused = []
        for label, bad_token in (
            ("a token for another audience", lambda: token("spiffe://demo.test/another-service")),
            ("a workload the policy does not approve", lambda: token(spiffe_id=ISSUER_ID)),
        ):
            try:
                await arequest_warrant_jwt(url, token=bad_token, **options)
            except SpiffeError:
                refused.append(label)
        if len(refused) != 2:
            raise RuntimeError(f"Expected two refusals, got {refused}")
    finally:
        server.should_exit = True
        await serving
        validator.close()
        app.close()
    print("Verified: a JWT-SVID from SPIRE was exchanged for a warrant; two improper requests were refused.")


async def federation_check(agent_socket: str, partner_socket: str) -> None:
    """A workload from partner.test obtains a warrant from the issuer in demo.test."""

    def partner_policy(identity, task_id):
        # With federation the policy must look at the trust domain as well.
        if (identity.trust_domain, identity.spiffe_id, task_id) == (
            PARTNER_DOMAIN,
            PARTNER_AGENT_ID,
            "approved-refund-123",
        ):
            return SpiffeGrant({"refund": {"customer": Exact("123"), "cents": Range(1, 500)}}, ttl_seconds=60)
        return None

    root, holder = SigningKey.generate(), SigningKey.generate()
    options = dict(issuer_id=ISSUER_ID, issuer_key=root.public_key, holder_key=holder, task_id="approved-refund-123")
    client_tls = SpiffeTLS.from_workload_api(
        trust_domain=PARTNER_DOMAIN,
        server_side=False,
        socket_path=partner_socket,
        spiffe_id=PARTNER_AGENT_ID,
        federates_with=[DOMAIN],
    )
    federated_tls = SpiffeTLS.from_workload_api(
        trust_domain=DOMAIN,
        server_side=True,
        socket_path=agent_socket,
        spiffe_id=ISSUER_ID,
        federates_with=[PARTNER_DOMAIN],
    )
    closed_tls = SpiffeTLS.from_workload_api(
        trust_domain=DOMAIN, server_side=True, socket_path=agent_socket, spiffe_id=ISSUER_ID
    )
    tokens = SpiffeJWT.from_workload_api(
        trust_domain=DOMAIN, audience=ISSUER_ID, socket_path=agent_socket, federates_with=[PARTNER_DOMAIN]
    )
    try:
        issuer = SpiffeWarrantIssuer(tls=federated_tls, signing_key=root, policy=partner_policy, jwt=tokens)
        async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0) as server:
            warrant = await arequest_warrant(client_tls, server.address, **options)
        if warrant.authorized_holder != holder.public_key:
            raise RuntimeError("The federated warrant is bound to the wrong holder")
        # The same issuer identity without federation must not accept the partner's workload.
        unfederated = SpiffeWarrantIssuer(tls=closed_tls, signing_key=root, policy=partner_policy)
        async with SpiffeIssuerServer(unfederated, host="127.0.0.1", port=0) as server:
            try:
                await arequest_warrant(client_tls, server.address, **options)
            except SpiffeError:
                pass
            else:
                raise RuntimeError("An issuer without federation accepted a foreign workload")
        # JWT-SVIDs: the partner's token is checked against the partner's keys.
        token = await asyncio.to_thread(
            fetch_jwt_svid, ISSUER_ID, socket_path=partner_socket, spiffe_id=PARTNER_AGENT_ID
        )
        identity = tokens.authenticate(token)
        if (identity.trust_domain, identity.spiffe_id) != (PARTNER_DOMAIN, PARTNER_AGENT_ID):
            raise RuntimeError(f"Unexpected federated JWT identity {identity.spiffe_id}")
    finally:
        for source in (client_tls, federated_tls, closed_tls, tokens):
            source.close()
    print(
        "Verified: a workload from a federated trust domain was accepted over mTLS and by JWT-SVID, and refused without federation."
    )


ENVOY_LISTENER = """
  - name: {name}
    address: {{socket_address: {{address: 127.0.0.1, port_value: {port}}}}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: {name}
          forward_client_cert_details: {mode}
          set_current_client_cert_details: {{uri: true}}
          route_config:
            virtual_hosts:
            - name: issuer
              domains: ["*"]
              routes: [{{match: {{prefix: "/"}}, route: {{cluster: issuer}}}}]
          http_filters:
          - name: envoy.filters.http.router
            typed_config: {{"@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router}}
"""
# The proxy presents the issuer's SVID and accepts only clients whose certificate chains to the trust bundle.
ENVOY_MUTUAL_TLS = """      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificates:
            - certificate_chain: {{filename: {directory}/issuer.pem}}
              private_key: {{filename: {directory}/issuer-key.pem}}
            validation_context: {{trusted_ca: {{filename: {bundle}}}}}
"""
ENVOY_CLUSTER = """
  clusters:
  - name: issuer
    type: STATIC
    load_assignment:
      cluster_name: issuer
      endpoints:
      - lb_endpoints: [{{endpoint: {{address: {{socket_address: {{address: 127.0.0.1, port_value: {port}}}}}}}}}]
"""


OTHER_DOMAIN = "other.test"


def crafted_client(directory: Path) -> ssl.SSLContext:
    """A client whose certificate, from an authority outside SPIRE, carries a name ending in a quote.

    SPIRE does not issue such names. Another authority a proxy trusts might,
    and Envoy copies the name into the header as it is.
    """
    now = datetime.now(timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other.test authority")])
    builder = x509.CertificateBuilder().issuer_name(ca_name).not_valid_before(now - timedelta(minutes=5))
    builder = builder.not_valid_after(now + timedelta(hours=1))
    authority = (
        builder.subject_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(True, None), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        builder.subject_name(x509.Name([]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f'spiffe://{OTHER_DOMAIN}/x"')]), True
        )
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "other-bundle.pem").write_bytes(authority.public_bytes(serialization.Encoding.PEM))
    (directory / "crafted.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    replace_file(
        directory / "crafted-key.pem",
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        0o600,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # The proxy presents an SVID, which has no host name.
    context.load_verify_locations(cafile=str(directory / "bundle.pem"))
    context.load_cert_chain(str(directory / "crafted.pem"), str(directory / "crafted-key.pem"))
    return context


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


async def forwarded_check(directory: Path, launch, refetch) -> None:
    """A real Envoy terminates the agent's mutual TLS and forwards its identity to the issuer."""
    import uvicorn

    if shutil.which("envoy") is None:
        print("Skipped: envoy is not on PATH, so the forwarded-identity check did not run.")
        return
    await asyncio.to_thread(refetch)  # Envoy reads the SVID files once, so start from fresh ones.
    audience = "https://issuer.demo.test/warrants"
    seen = []

    def recording_policy(identity, task_id):
        seen.append((identity.spiffe_id, identity.svid_type))
        return policy(identity, task_id)

    forwarded = SpiffeForwardedIdentity(
        DOMAIN,
        audience=audience,
        trusted_proxies=["127.0.0.1"],
        expected_by=ISSUER_ID,
        federates_with=[OTHER_DOMAIN],
    )
    root, holder = SigningKey.generate(), SigningKey.generate()
    app = SpiffeForwardedIssuerApp(SpiffeWarrantIssuer(signing_key=root, policy=recording_policy, forwarded=forwarded))
    ports = {name: free_port() for name in ("issuer", "replace", "append", "plain", "crafted")}
    crafted_tls = crafted_client(directory)
    # The issuer must see the real socket peer, so uvicorn's proxy-header rewriting is off.
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=ports["issuer"], log_level="warning", proxy_headers=False)
    )
    serving = asyncio.ensure_future(server.serve())
    mutual_tls = ENVOY_MUTUAL_TLS.format(directory=directory, bundle=directory / "bundle.pem")
    config = directory / "envoy.yaml"
    config.write_text(
        "static_resources:\n  listeners:"
        + ENVOY_LISTENER.format(name="replace", port=ports["replace"], mode="SANITIZE_SET")
        + mutual_tls
        + ENVOY_LISTENER.format(name="append", port=ports["append"], mode="APPEND_FORWARD")
        + mutual_tls
        + ENVOY_LISTENER.format(name="plain", port=ports["plain"], mode="APPEND_FORWARD")
        # An appending listener that also accepts clients of an authority outside SPIRE.
        + ENVOY_LISTENER.format(name="crafted", port=ports["crafted"], mode="APPEND_FORWARD")
        + ENVOY_MUTUAL_TLS.format(directory=directory, bundle=directory / "other-bundle.pem")
        + ENVOY_CLUSTER.format(port=ports["issuer"])
    )
    envoy = launch("envoy", "envoy", "-c", str(config), "--log-level", "warn", "--disable-hot-restart")
    agent_tls = tls_config(directory, "agent")
    unapproved_tls = SpiffeTLS(
        trust_domain=DOMAIN,
        bundle_file=str(directory / "bundle.pem"),
        cert_file=str(directory / "issuer.pem"),
        key_file=str(directory / "issuer-key.pem"),
        server_side=False,
    )
    options = dict(audience=audience, issuer_key=root.public_key, holder_key=holder, task_id="approved-refund-123")
    forged = f"By={ISSUER_ID};Hash={'ab' * 32};URI=spiffe://{DOMAIN}/someone-else"

    def post(listener: str, header=None, context=None):
        """One request, optionally with an identity header of the client's own. Returns the HTTP status."""
        proof = sign_forwarded_holder_proof(holder, audience=audience, task_id="approved-refund-123")
        body = json.dumps(
            {
                "v": 1,
                "holder": base64.b64encode(bytes(holder.public_key.to_bytes())).decode(),
                "task": "approved-refund-123",
                "timestamp": proof.timestamp,
                "nonce": base64.b64encode(proof.nonce).decode(),
                "signature": base64.b64encode(proof.signature).decode(),
            }
        )
        if listener == "plain":
            connection = http.client.HTTPConnection("127.0.0.1", ports[listener], timeout=10)
        else:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", ports[listener], timeout=10, context=context or agent_tls.context
            )
        try:
            headers = {"Content-Type": "application/json"}
            if header is not None:
                headers["x-forwarded-client-cert"] = header
            connection.request("POST", "/warrants", body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    try:
        for _ in range(200):
            if envoy.poll() is not None:
                raise RuntimeError("Envoy exited")
            try:
                if server.started and await asyncio.to_thread(post, "plain") == 403:
                    break
            except OSError:
                pass
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("Envoy did not start")
        for listener in ("replace", "append"):
            url = f"https://127.0.0.1:{ports[listener]}/warrants"
            warrant = await arequest_warrant_forwarded(url, tls=agent_tls, issuer_id=ISSUER_ID, **options)
            if warrant.authorized_holder != holder.public_key:
                raise RuntimeError("The warrant is bound to the wrong holder")
            try:
                await arequest_warrant_forwarded(url, tls=unapproved_tls, issuer_id=ISSUER_ID, **options)
            except SpiffeError:
                pass
            else:
                raise RuntimeError("A workload the policy does not approve received a warrant")
        if seen != [(AGENT_ID, "forwarded"), (ISSUER_ID, "forwarded")] * 2:
            raise RuntimeError(f"Unexpected forwarded identities {seen}")
        # An agent that sends an identity header of its own gains nothing:
        # a replacing proxy discards it, and behind an appending proxy the issuer refuses the request.
        seen.clear()
        statuses = {
            listener: await asyncio.to_thread(post, listener, forged) for listener in ("replace", "append", "plain")
        }
        if statuses != {"replace": 200, "append": 403, "plain": 403} or seen != [(AGENT_ID, "forwarded")]:
            raise RuntimeError(f"A client-supplied identity header was not handled safely: {statuses} {seen}")
        # A certificate name ending in a quote, with a header that opens one: the
        # two must not combine into an entry that names the approved agent.
        seen.clear()
        opening = f'By={ISSUER_ID};Hash={"ab" * 32};URI={AGENT_ID};X="'
        statuses = [await asyncio.to_thread(post, "crafted", header, crafted_tls) for header in (opening, None)]
        if statuses != [403, 403] or seen:
            raise RuntimeError(f"A crafted certificate name was not handled safely: {statuses} {seen}")
    finally:
        stop(envoy)
        server.should_exit = True
        await serving
        app.close()
    print(
        "Verified: Envoy forwarded the agent's SPIRE identity to the issuer; "
        "an unapproved workload, three requests carrying a made-up identity, "
        "and a certificate with a crafted name got nothing extra."
    )


async def renewal_checks(directory: Path, agent_socket: str, partner_socket: str, refetch, launch) -> None:
    await jwt_check(agent_socket)
    await federation_check(agent_socket, partner_socket)
    await forwarded_check(directory, launch, refetch)
    # Both checks wait for the same renewal, so run them together.
    await asyncio.gather(rotation_check(directory, refetch), workload_api_check(agent_socket))


def start_server(launch, directory: Path, trust_domain: str, port: int) -> str:
    """Start a SPIRE server for one trust domain. Returns its API socket; writes bundle.pem."""
    directory.mkdir(parents=True, exist_ok=True)
    server_socket = str(directory / "server.sock")
    server_conf = directory / "server.conf"
    server_conf.write_text(f'''
server {{
    bind_address = "127.0.0.1"
    bind_port = {port}
    socket_path = "{server_socket}"
    trust_domain = "{trust_domain}"
    data_dir = "{directory}/server-data"
    log_level = "WARN"
}}
plugins {{
    DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "{directory}/datastore.sqlite3" }} }}
    KeyManager "disk" {{ plugin_data {{ keys_path = "{directory}/server-keys.json" }} }}
    NodeAttestor "join_token" {{ plugin_data {{}} }}
}}
''')
    server = launch(f"server-{trust_domain}", "spire-server", "run", "-config", str(server_conf))
    for _ in range(100):
        if server.poll() is not None:
            raise RuntimeError(f"SPIRE server for {trust_domain} exited")
        try:
            bundle = command("spire-server", "bundle", "show", "-socketPath", server_socket)
            break
        except subprocess.CalledProcessError:
            time.sleep(0.1)
    else:
        raise RuntimeError(f"SPIRE server for {trust_domain} did not become ready")
    (directory / "bundle.pem").write_text(bundle)
    return server_socket


def share_bundle(source_socket: str, source_domain: str, target_socket: str, scratch: Path) -> None:
    """Give one SPIRE server the other trust domain's bundle (X.509 authorities and JWT keys)."""
    path = scratch / f"{source_domain}.spiffe-bundle.json"
    path.write_text(command("spire-server", "bundle", "show", "-format", "spiffe", "-socketPath", source_socket))
    command(
        "spire-server",
        "bundle",
        "set",
        "-format",
        "spiffe",
        "-id",
        f"spiffe://{source_domain}",
        "-path",
        str(path),
        "-socketPath",
        target_socket,
    )


def create_entry(server_socket: str, trust_domain: str, identity: str, federates_with: str = "") -> None:
    arguments = [
        "spire-server",
        "entry",
        "create",
        "-socketPath",
        server_socket,
        "-parentID",
        f"spiffe://{trust_domain}/node",
        "-spiffeID",
        identity,
        "-selector",
        f"unix:uid:{os.getuid()}",
        "-x509SVIDTTL",
        str(SVID_TTL_SECONDS),
    ]
    if federates_with:
        arguments += ["-federatesWith", f"spiffe://{federates_with}"]
    command(*arguments)


def start_agent(launch, directory: Path, trust_domain: str, port: int, server_socket: str):
    """Start a SPIRE agent with a one-time join token. Returns (process, Workload API socket)."""
    token_output = command(
        "spire-server",
        "token",
        "generate",
        "-socketPath",
        server_socket,
        "-spiffeID",
        f"spiffe://{trust_domain}/node",
    )
    token = re.search(r"Token:\s*(\S+)", token_output)
    if token is None:
        raise RuntimeError("SPIRE did not return a join token")
    agent_socket = str(directory / "agent.sock")
    agent_conf = directory / "agent.conf"
    agent_conf.write_text(f'''
agent {{
    server_address = "127.0.0.1"
    server_port = {port}
    socket_path = "{agent_socket}"
    trust_domain = "{trust_domain}"
    trust_bundle_path = "{directory}/bundle.pem"
    data_dir = "{directory}/agent-data"
    log_level = "WARN"
}}
plugins {{
    KeyManager "memory" {{ plugin_data {{}} }}
    NodeAttestor "join_token" {{ plugin_data {{}} }}
    WorkloadAttestor "unix" {{ plugin_data {{}} }}
}}
''')
    process = launch(f"agent-{trust_domain}", "spire-agent", "run", "-config", str(agent_conf), "-joinToken", token[1])
    return process, agent_socket


def main():
    with tempfile.TemporaryDirectory(prefix="spiffe-") as temp, ExitStack() as stack:
        directory = Path(temp)
        partner_directory = directory / "partner"
        logs = []

        def launch(label, binary, *args):
            log_path = directory / f"{label}.log"
            logs.append(log_path)
            log = stack.enter_context(log_path.open("w"))
            process = subprocess.Popen([binary, *args], stdout=log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            return process

        try:
            server_socket = start_server(launch, directory, DOMAIN, 18081)
            partner_server_socket = start_server(launch, partner_directory, PARTNER_DOMAIN, 18082)
            # Federation: each server learns the other's bundle before entries refer to it.
            share_bundle(server_socket, DOMAIN, partner_server_socket, directory)
            share_bundle(partner_server_socket, PARTNER_DOMAIN, server_socket, directory)
            create_entry(server_socket, DOMAIN, AGENT_ID)
            create_entry(server_socket, DOMAIN, ISSUER_ID, federates_with=PARTNER_DOMAIN)
            create_entry(partner_server_socket, PARTNER_DOMAIN, PARTNER_AGENT_ID, federates_with=DOMAIN)
            agent, agent_socket = start_agent(launch, directory, DOMAIN, 18081, server_socket)
            _, partner_socket = start_agent(launch, partner_directory, PARTNER_DOMAIN, 18082, partner_server_socket)
            exported = directory / "exported"
            exported.mkdir()
            for _ in range(120):
                if agent.poll() is not None:
                    raise RuntimeError("SPIRE agent exited")
                try:
                    export_svids(agent_socket, exported, directory)
                    break
                except (subprocess.CalledProcessError, RuntimeError, KeyError):
                    time.sleep(0.25)
            else:
                raise RuntimeError("SPIRE Workload API did not become ready")
            print("Using X.509-SVIDs issued by a real SPIRE server through its Workload API.")
            run(directory)
            asyncio.run(
                renewal_checks(
                    directory,
                    agent_socket,
                    partner_socket,
                    lambda: export_svids(agent_socket, exported, directory),
                    launch,
                )
            )
        except Exception:
            for log in logs:
                print(f"{log.name}:\n{log.read_text()}")
            raise


if __name__ == "__main__":
    main()
