#!/usr/bin/env python3
"""Run a disposable real SPIRE server/agent and exercise demo.py with their SVIDs.

Requires Linux, spire-server and spire-agent on PATH. The accompanying Dockerfile
provides these. All sockets, credentials, data, and logs live in a temp directory.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from cryptography import x509

from demo import AGENT_ID, ISSUER_ID, run


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
            for _ in range(30):
                if agent.poll() is not None:
                    raise RuntimeError("SPIRE agent exited")
                try:
                    command("spire-agent", "api", "fetch", "x509", "-socketPath", agent_socket, "-write", str(exported))
                    break
                except subprocess.CalledProcessError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("SPIRE Workload API did not become ready")
            roles = {AGENT_ID: "agent", ISSUER_ID: "issuer"}
            found = set()
            for cert_path in exported.glob("svid.*.pem"):
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                identity = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                role = roles[identity.get_values_for_type(x509.UniformResourceIdentifier)[0]]
                shutil.copyfile(cert_path, directory / f"{role}.pem")
                shutil.copyfile(cert_path.with_suffix(".key"), directory / f"{role}-key.pem")
                (directory / f"{role}-key.pem").chmod(0o600)
                found.add(role)
            if found != {"agent", "issuer"}:
                raise RuntimeError("SPIRE did not return both workload identities")
            print("Using X.509-SVIDs issued by a real SPIRE server through its Workload API.")
            run(directory)
        except Exception:
            for log in logs:
                print(f"{log.name}:\n{log.read_text()}")
            raise


if __name__ == "__main__":
    main()
