#!/usr/bin/env python3
"""Run a disposable real SPIRE server/agent and exercise demo.py with their SVIDs.

Requires Linux, spire-server and spire-agent on PATH. The accompanying Dockerfile
provides these. All sockets, credentials, data, and logs live in a temp directory.
After the demo, the harness waits for SPIRE to renew the short-lived SVIDs and
checks that a running issuer serves the renewed SVID without a restart.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from demo import AGENT_ID, ISSUER_ID, policy, run, tls_config
from tenuo import SigningKey
from tenuo.spiffe import SpiffeIssuerServer, SpiffeWarrantIssuer, arequest_warrant

SVID_TTL_SECONDS = 120  # SPIRE renews at about half of this.


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


def main():
    with tempfile.TemporaryDirectory(prefix="spiffe-") as temp, ExitStack() as stack:
        directory = Path(temp)
        server_socket = str(directory / "server.sock")
        agent_socket = str(directory / "agent.sock")
        server_conf = directory / "server.conf"
        server_conf.write_text(f'''
server {{
    bind_address = "127.0.0.1"
    bind_port = 18081
    socket_path = "{server_socket}"
    trust_domain = "demo.test"
    data_dir = "{directory}/server-data"
    log_level = "WARN"
}}
plugins {{
    DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "{directory}/datastore.sqlite3" }} }}
    KeyManager "disk" {{ plugin_data {{ keys_path = "{directory}/server-keys.json" }} }}
    NodeAttestor "join_token" {{ plugin_data {{}} }}
}}
''')
        logs = []

        def launch(binary, *args):
            log_path = directory / f"{binary}.log"
            logs.append(log_path)
            log = stack.enter_context(log_path.open("w"))
            process = subprocess.Popen([binary, *args], stdout=log, stderr=subprocess.STDOUT)
            stack.callback(stop, process)
            return process

        try:
            server = launch("spire-server", "run", "-config", str(server_conf))
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("SPIRE server exited")
                try:
                    bundle = command("spire-server", "bundle", "show", "-socketPath", server_socket)
                    break
                except subprocess.CalledProcessError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("SPIRE server did not become ready")
            (directory / "bundle.pem").write_text(bundle)
            token_output = command(
                "spire-server",
                "token",
                "generate",
                "-socketPath",
                server_socket,
                "-spiffeID",
                "spiffe://demo.test/node",
            )
            token = re.search(r"Token:\s*(\S+)", token_output)
            if token is None:
                raise RuntimeError("SPIRE did not return a join token")
            for identity in (AGENT_ID, ISSUER_ID):
                command(
                    "spire-server",
                    "entry",
                    "create",
                    "-socketPath",
                    server_socket,
                    "-parentID",
                    "spiffe://demo.test/node",
                    "-spiffeID",
                    identity,
                    "-selector",
                    f"unix:uid:{os.getuid()}",
                    "-x509SVIDTTL",
                    str(SVID_TTL_SECONDS),
                )
            agent_conf = directory / "agent.conf"
            agent_conf.write_text(f'''
agent {{
    server_address = "127.0.0.1"
    server_port = 18081
    socket_path = "{agent_socket}"
    trust_domain = "demo.test"
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
            agent = launch("spire-agent", "run", "-config", str(agent_conf), "-joinToken", token[1])
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
            asyncio.run(rotation_check(directory, lambda: export_svids(agent_socket, exported, directory)))
        except Exception:
            for log in logs:
                print(f"{log.name}:\n{log.read_text()}")
            raise


if __name__ == "__main__":
    main()
