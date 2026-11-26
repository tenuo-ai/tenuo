#!/usr/bin/env python3
"""Run a disposable real SPIRE server/agent and exercise demo.py with their SVIDs.

Requires Linux, spire-server and spire-agent on PATH. The accompanying Dockerfile
provides these. All sockets, credentials, data, and logs live in a temp directory.
After the demo, the harness waits for SPIRE to renew the short-lived SVIDs and
checks that a running issuer picks up the renewal without a restart, once with
credential files and once straight from the Workload API socket. It also
exchanges a real JWT-SVID for a warrant over HTTP, and starts a second SPIRE
deployment for another trust domain to exercise federation.
"""

from __future__ import annotations

import asyncio
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

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


async def renewal_checks(directory: Path, agent_socket: str, partner_socket: str, refetch) -> None:
    await jwt_check(agent_socket)
    await federation_check(agent_socket, partner_socket)
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
                    directory, agent_socket, partner_socket, lambda: export_svids(agent_socket, exported, directory)
                )
            )
        except Exception:
            for log in logs:
                print(f"{log.name}:\n{log.read_text()}")
            raise


if __name__ == "__main__":
    main()
