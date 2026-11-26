"""The forwarded-identity endpoint on the ASGI servers the guide lists, each started as the guide says.

Servers report the socket peer differently, and some rewrite it from request
headers. Each server that is installed is started as a real process; the rest
are skipped. CI runs this in the SPIFFE integration image, which has them all.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
if os.name == "nt":
    pytest.skip("starts POSIX server processes", allow_module_level=True)

from tenuo import SigningKey  # noqa: E402
from tenuo._spiffe_http import _request_body  # noqa: E402
from tenuo.spiffe_forwarded import sign_forwarded_holder_proof  # noqa: E402

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
ENTRY = "By=spiffe://example.test/issuer;Hash=" + "ab" * 32 + ";URI=spiffe://example.test/agent"

APPLICATION = """
import json, os
from tenuo import Exact, Range, SigningKey
from tenuo.spiffe import SpiffeGrant, SpiffeWarrantIssuer
from tenuo.spiffe_forwarded import SpiffeForwardedIdentity, SpiffeForwardedIssuerApp

# These tests are about where a request arrived from, so the header carries no certificate.
forwarded = SpiffeForwardedIdentity(
    "example.test", audience="aud", trusted_proxies=os.environ["TRUSTED"].split(","), require_certificate=False
)
issuer = SpiffeWarrantIssuer(
    signing_key=SigningKey.generate(),
    policy=lambda identity, task: SpiffeGrant({"refund": {"customer": Exact("123"), "cents": Range(1, 10)}}),
    forwarded=forwarded,
)
app = SpiffeForwardedIssuerApp(issuer)
"""
GUIDE = PACKAGE_ROOT.parent / "docs" / "spiffe.md"
# The worker the guide gives for Gunicorn, which has no switch for this. Taken from the guide when it is at hand.
WORKERS = """
from uvicorn_worker import UvicornWorker


class NoProxyHeaders(UvicornWorker):
    CONFIG_KWARGS = {"proxy_headers": False}
"""
if GUIDE.exists():
    import re

    WORKERS = re.search(r"```python\n# workers\.py\n(.*?)```", GUIDE.read_text(), re.S)[1]


def command(server: str, port: int, uds: str | None, rewriting: bool = False) -> list:
    """How the guide starts each server. ``rewriting`` leaves a server's own address rewriting on."""
    python = sys.executable
    where = {
        "uvicorn": ["--uds", uds] if uds else ["--host", "127.0.0.1", "--port", str(port)],
        "gunicorn": ["--bind", f"unix:{uds}" if uds else f"127.0.0.1:{port}"],
        "hypercorn": ["--bind", f"unix:{uds}" if uds else f"127.0.0.1:{port}"],
        "daphne": ["-u", uds] if uds else ["-b", "127.0.0.1", "-p", str(port)],
        "granian": ["--uds", uds] if uds else ["--host", "127.0.0.1", "--port", str(port)],
    }[server]
    uvicorn_switch = [] if rewriting else ["--no-proxy-headers"]
    worker = "uvicorn_worker.UvicornWorker" if rewriting else "workers.NoProxyHeaders"
    daphne_switch = ["--proxy-headers"] if rewriting else []
    return {
        "uvicorn": [python, "-m", "uvicorn", "issuer_app:app", "--log-level", "warning", *uvicorn_switch],
        "gunicorn": [python, "-m", "gunicorn", "issuer_app:app", "-k", worker, "--log-level", "warning"],
        "hypercorn": [python, "-m", "hypercorn", "issuer_app:app"],
        "daphne": [python, "-m", "daphne", "issuer_app:app", *daphne_switch],
        "granian": [python, "-m", "granian", "--interface", "asgi", "issuer_app:app"],
    }[server] + where  # fmt: skip


REQUIRES = {
    "uvicorn": ("uvicorn",),
    "gunicorn": ("gunicorn", "uvicorn_worker"),
    "hypercorn": ("hypercorn",),
    "daphne": ("daphne",),
    "granian": ("granian",),
}


class _Unix(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=5)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(self._path)


class Running:
    def __init__(
        self, server: str, transport: str, trusted: str, environment: dict | None = None, rewriting: bool = False
    ):
        for module in REQUIRES[server]:
            if importlib.util.find_spec(module) is None:
                pytest.skip(f"{module} is not installed")
        self.directory = tempfile.mkdtemp(prefix="asgi", dir="/tmp")  # Short: socket paths are length-limited.
        Path(self.directory, "issuer_app.py").write_text(APPLICATION)
        Path(self.directory, "workers.py").write_text(textwrap.dedent(WORKERS))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.uds = os.path.join(self.directory, "issuer.sock") if transport == "unix" else None
        env = {key: value for key, value in os.environ.items() if key != "FORWARDED_ALLOW_IPS"}
        env.update(
            TRUSTED=trusted, PYTHONPATH=os.pathsep.join([self.directory, str(PACKAGE_ROOT)]), **(environment or {})
        )
        self.process = subprocess.Popen(
            command(server, self.port, self.uds, rewriting),
            env=env,
            cwd=self.directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def post(self, headers: dict | None = None) -> tuple:
        holder = SigningKey.generate()
        proof = sign_forwarded_holder_proof(holder, audience="aud", task_id="task")
        connection = _Unix(self.uds) if self.uds else http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(
                "POST",
                "/warrants",
                body=_request_body(holder, "task", proof),
                headers={"Content-Type": "application/json", "x-forwarded-client-cert": ENTRY, **(headers or {})},
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def __enter__(self):
        deadline = time.monotonic() + 30
        while True:
            try:
                self.post()
                return self
            except OSError:
                if self.process.poll() is not None:
                    output = self.process.stdout.read().decode(errors="replace")[-600:]
                    self.__exit__()
                    raise AssertionError(f"The server did not start:\n{output}") from None
                if time.monotonic() > deadline:
                    self.__exit__()
                    raise AssertionError("The server did not answer") from None
                time.sleep(0.1)

    def __exit__(self, *_):
        self.process.terminate()
        try:
            self.process.wait(10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(10)
        self.process.stdout.close()
        import shutil

        shutil.rmtree(self.directory, ignore_errors=True)


SERVERS = list(REQUIRES)


@pytest.mark.parametrize("server", SERVERS)
def test_issues_to_its_proxy_over_tcp(server):
    with Running(server, "tcp", "127.0.0.1") as running:
        assert running.post()[0] == 200
        # A client-chosen X-Forwarded-For changes nothing: the socket peer is still the proxy.
        assert running.post({"X-Forwarded-For": "203.0.113.7"})[0] == 200


@pytest.mark.parametrize("server", SERVERS)
def test_issues_to_its_proxy_over_a_unix_socket(server):
    with Running(server, "unix", "unix") as running:
        status, reply = running.post()
        if server == "granian":
            # Granian reports an empty client address for a Unix socket, which is not accepted as one.
            assert (status, reply["error"]) == (403, "forbidden")
        else:
            assert status == 200, reply


@pytest.mark.parametrize("server", SERVERS)
@pytest.mark.parametrize("environment", [None, {"FORWARDED_ALLOW_IPS": "*"}], ids=["default", "allow-all"])
def test_a_caller_cannot_claim_the_proxys_address(server, environment):
    """The issuer trusts 10.0.0.5. A caller on loopback says it is 10.0.0.5, or that it is the Unix socket."""
    for trusted, claimed in (("10.0.0.5", "10.0.0.5"), ("unix", "unix")):
        with Running(server, "tcp", trusted, environment) as running:
            for headers in (
                None,
                {"X-Forwarded-For": claimed},
                {"X-Forwarded-For": f"{claimed}:40000"},
                {"X-Forwarded-For": claimed, "X-Forwarded-Port": "40000"},
                {"Forwarded": f"for={claimed}"},
                {"Forwarded": f'for="{claimed}:40000"'},
            ):
                status, reply = running.post(headers)
                assert (status, reply["error"]) == (403, "forbidden"), (trusted, headers)


@pytest.mark.parametrize("server", ["uvicorn", "gunicorn"])
def test_default_address_rewriting_fails_closed(server):
    """Uvicorn, and Gunicorn's Uvicorn worker, rewrite the client address unless told not to. That never widens trust."""
    with Running(server, "tcp", "127.0.0.1", rewriting=True) as running:
        assert running.post()[0] == 200
        status, reply = running.post({"X-Forwarded-For": "203.0.113.7"})
        assert (status, reply["error"]) == (403, "forbidden")  # Refused, not trusted as someone else.


@pytest.mark.parametrize("server", ["uvicorn", "gunicorn", "daphne"])
@pytest.mark.parametrize("environment", [None, {"FORWARDED_ALLOW_IPS": "*"}], ids=["default", "allow-all"])
def test_a_rewritten_address_with_a_port_is_not_trusted(server, environment):
    """With rewriting left on, a caller can hand the server the proxy's address and a port to go with it.

    The server then reports a peer that looks real. The issuer refuses it,
    because the address it was given is written in the request itself.
    """
    for trusted in ("10.0.0.5", "127.0.0.6"):
        with Running(server, "tcp", trusted, environment, rewriting=True) as running:
            for headers in (
                {"X-Forwarded-For": f"{trusted}:40000"},
                {"X-Forwarded-For": trusted, "X-Forwarded-Port": "40000"},
                {"X-Forwarded-For": f"203.0.113.7, {trusted}:40000"},
                # Uvicorn reads the port with int(), which takes more than digits.
                {"X-Forwarded-For": f"{trusted}:+40000"},
                {"X-Forwarded-For": f"{trusted}:4_0000"},
                {"X-Forwarded-For": f"{trusted}: 40000"},
                {"X-Forwarded-For": f"[{trusted}]:+40000"},
                {"X-Forwarded-For": trusted, "X-Forwarded-Port": "+40000"},
            ):
                status, reply = running.post(headers)
                assert (status, reply["error"]) == (403, "forbidden"), (trusted, headers)
