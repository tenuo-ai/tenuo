"""The mutual TLS issuer under failures around it: callbacks that raise, deadlines, unreadable certificates, reloads."""

from __future__ import annotations

import asyncio
import base64
import socket
import ssl
import threading
import weakref
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: E402

import tenuo.spiffe as spiffe  # noqa: E402
from tenuo import SigningKey  # noqa: E402
from tenuo.spiffe import (  # noqa: E402
    SpiffeError,
    SpiffeGrant,
    SpiffeIssuerServer,
    SpiffeWarrantIssuer,
    request_warrant,
)

from . import test_spiffe as ts  # noqa: E402
from .test_spiffe import ca, from_api, pki, served, workload_api  # noqa: E402, F401  (fixtures)

# -- callbacks that fail -------------------------------------------------------

FAILURES = {
    "RuntimeError": RuntimeError("task store down"),
    "ConnectionRefusedError": ConnectionRefusedError(61, "Connection refused"),
    "OSError": OSError(28, "No space left on device"),
    "TimeoutError": TimeoutError("task store timed out"),
}


@pytest.mark.parametrize("callback", ["policy", "audit"])
@pytest.mark.parametrize("name", list(FAILURES))
def test_a_failing_callback_is_the_issuers_error_whatever_it_raises(pki, caplog, callback, name):  # noqa: F811
    """A database that refuses a connection raises from the OSError family. That is not the agent's connection failing."""

    def fail(*_):
        raise FAILURES[name]

    root, holder = SigningKey.generate(), SigningKey.generate()
    issuer = SpiffeWarrantIssuer(
        tls=pki(server=True),
        signing_key=root,
        policy=fail if callback == "policy" else (lambda *_: SpiffeGrant(ts.REFUND, ttl_seconds=60)),
        audit=fail if callback == "audit" else None,
    )
    client_tls = pki()

    async def body(address):
        with pytest.raises(SpiffeError) as refused:
            await asyncio.to_thread(
                request_warrant,
                client_tls,
                address,
                issuer_id=ts.SERVER,
                issuer_key=root.public_key,
                holder_key=holder,
                task_id="task-123",
            )
        return str(refused.value)

    with caplog.at_level("INFO", logger="tenuo.spiffe"):
        message = ts.run_server(issuer, body)
    errors = [record.getMessage() for record in caplog.records if record.levelname == "ERROR"]
    assert "Issuer error; see the issuer's log" in message
    assert any("Issuance exchange failed" in line for line in errors)


def test_deadline_during_policy_leaves_no_challenge_behind(pki):  # noqa: F811
    """The policy call outlives the exchange's deadline. Its challenge must not count against the workload afterwards."""
    root, holder = SigningKey.generate(), SigningKey.generate()
    recovered, entered, finished = threading.Event(), threading.Event(), threading.Event()

    def policy(identity, task_id):
        entered.set()
        if not recovered.is_set():
            recovered.wait(30)  # The task store is slow for a moment.
            finished.set()
        return SpiffeGrant(ts.REFUND, ttl_seconds=60)

    issuer = SpiffeWarrantIssuer(tls=pki(server=True), signing_key=root, policy=policy, max_pending_per_identity=1)
    client_tls = pki()

    def fetch(address):
        return request_warrant(
            client_tls, address, issuer_id=ts.SERVER, issuer_key=root.public_key, holder_key=holder, task_id="t"
        )

    async def main():
        async with SpiffeIssuerServer(issuer, host="127.0.0.1", port=0, timeout=0.5) as server:
            with pytest.raises(SpiffeError):
                await asyncio.to_thread(fetch, server.address)  # The issuer's deadline ended this exchange.
            assert entered.is_set()
            recovered.set()
            assert await asyncio.to_thread(finished.wait, 10)
            await asyncio.sleep(0.2)  # Let the abandoned call's result reach the loop.
            return len(issuer._pending), await asyncio.to_thread(fetch, server.address)

    outstanding, warrant = asyncio.run(main())
    assert outstanding == 0 and warrant.authorized_holder == holder.public_key


# -- certificates the parser cannot read ---------------------------------------


def _length(size):
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def leaf_with_duplicate_extension(authority, identity, directory, name):
    """A correctly signed SVID-shaped leaf that carries the same private extension twice."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    first, second = "1.3.6.1.4.1.55555.1.1", "1.3.6.1.4.1.55555.1.2"
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(authority.name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=10))
        .not_valid_after(now + timedelta(seconds=600))
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.key.public_key()), False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(first), b"\x05\x00"), False)
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(second), b"\x05\x00"), False)
        .sign(authority.key, hashes.SHA256())
    )
    # Rename the second extension to the first, and sign the result again.
    tbs = cert.tbs_certificate_bytes
    changed = tbs.replace(bytes.fromhex("060a2b0601040183b2030102"), bytes.fromhex("060a2b0601040183b2030101"))
    assert changed != tbs and len(changed) == len(tbs)
    signature = authority.key.sign(changed, ec.ECDSA(hashes.SHA256()))
    algorithm = bytes.fromhex("300a06082a8648ce3d040302")  # ecdsa-with-SHA256
    body = changed + algorithm + b"\x03" + _length(len(signature) + 1) + b"\x00" + signature
    der = b"\x30" + _length(len(body)) + body
    paths = {part: directory / f"{name}.{part}.pem" for part in ("cert", "key")}
    paths["cert"].write_bytes(x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM))
    paths["key"].write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return paths


def test_an_unreadable_peer_certificate_is_a_refusal(ca, pki, served, tmp_path, caplog):  # noqa: F811
    """The TLS library accepts this certificate and the parser does not. That is a refusal, not an issuer error."""
    odd = leaf_with_duplicate_extension(ca, ts.AGENT, tmp_path, "odd-agent")
    server = pki(server=True)
    connection, _ = ts.connect(server, ts.raw_client(odd, ca.pem))
    with pytest.raises(SpiffeError, match="Malformed X.509-SVID"):
        server.authenticate(connection)
    # Through the bundled server: no challenge, and nothing logged as an error.
    issuer, _, _, holder = served
    request = b'{"v":1,"holder":"%s","task":"task-123"}\n' % base64.b64encode(bytes(holder.public_key.to_bytes()))

    def session(address):
        try:
            return ts._raw_session(ts.raw_client(odd, ca.pem), address, request)
        except OSError:
            return b""  # The issuer closed before the request was read, which resets the connection.

    async def body(address):
        return await asyncio.to_thread(session, address)

    with caplog.at_level("INFO", logger="tenuo.spiffe"):
        reply = ts.run_server(issuer, body)
    assert b"challenge" not in reply and b"unavailable" not in reply
    assert "Issuance refused: Malformed X.509-SVID" in caplog.text
    assert not [record for record in caplog.records if record.levelname == "ERROR"]


def test_the_client_reports_an_unreadable_issuer_certificate_as_spiffe_error(ca, pki, tmp_path):  # noqa: F811
    odd = leaf_with_duplicate_extension(ca, ts.SERVER, tmp_path, "odd-issuer")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ca.pem.decode())
    context.load_cert_chain(str(odd["cert"]), str(odd["key"]))
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(5)

    def serve():
        try:
            raw, _ = listener.accept()
            with raw:
                raw.settimeout(5)
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(65536)
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    root, holder = SigningKey.generate(), SigningKey.generate()
    try:
        with pytest.raises(SpiffeError):
            request_warrant(
                pki(),
                listener.getsockname()[:2],
                issuer_id=ts.SERVER,
                issuer_key=root.public_key,
                holder_key=holder,
                task_id="task-123",
                timeout=5,
            )
    finally:
        listener.close()
        thread.join(5)


def version_2_der(authority):
    """The authority's certificate with its version changed to one the parser refuses outright."""
    der = authority.cert.public_bytes(serialization.Encoding.DER)
    changed = der.replace(bytes.fromhex("a003020102"), bytes.fromhex("a003020101"), 1)  # v3 -> v2
    assert changed != der
    with pytest.raises(x509.InvalidVersion):
        x509.load_der_x509_certificate(changed)
    return changed


def test_an_unreadable_federated_bundle_file_does_not_hold_back_home_rotation(ca, tmp_path, pki):  # noqa: F811
    partner = ts.CA(tmp_path, "partner root")
    partner_bundle = tmp_path / "partner.pem"
    partner_bundle.write_bytes(partner.pem)
    paths = ca.files("fed-version", ts.SERVER)
    server = ts.tls_in(ts.DOMAIN, paths, True, {ts.PARTNER: partner_bundle})
    before = server.identity
    body = base64.encodebytes(version_2_der(partner)).decode()
    partner_bundle.write_bytes(f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n".encode())
    ts._rewrite(ca, paths, ts.SERVER)  # The home SVID is renewed at the same time.
    assert server.reload_if_changed() is True
    assert server.identity != before
    assert ts.partner_refused_home_served(server, ca, partner, pki)


def test_an_unreadable_federated_bundle_from_the_workload_api_does_not_hold_back_home_renewal(
    ca,  # noqa: F811
    tmp_path,
    pki,  # noqa: F811
    workload_api,  # noqa: F811
    from_api,  # noqa: F811
):
    partner = ts.CA(tmp_path, "partner root")
    api = workload_api()
    api.publish(ts.x509_response(ts.svid_entry(ca, ts.SERVER), federated=[(f"spiffe://{ts.PARTNER}", partner.pem)]))
    server = from_api(api, federates_with=[ts.PARTNER])
    before = server.identity
    entry = ts._field(1, f"spiffe://{ts.PARTNER}".encode()) + ts._field(2, version_2_der(partner))
    api.publish(ts.x509_response(ts.svid_entry(ca, ts.SERVER)) + ts._field(3, entry))
    assert ts.eventually(lambda: server.identity != before, seconds=3), server._watcher.last_error
    assert ts.partner_refused_home_served(server, ca, partner, pki)


# -- reloads -------------------------------------------------------------------


def test_a_new_unusable_update_is_retried_on_a_fresh_schedule():
    def not_valid_yet(snapshot):
        raise SpiffeError("Local SVID is not currently valid")

    watcher = spiffe._WorkloadAPIWatcher("127.0.0.1:1", spiffe._FETCH_X509_SVID, lambda raw: raw, not_valid_yet)
    try:
        with watcher._deliver_lock:
            watcher._offer("first update")
        assert watcher._retry_timer.interval == spiffe._PENDING_RETRY[0]
        for _ in range(5):  # The first update stays unusable, and its retries back off.
            watcher._retry_timer.cancel()
            watcher._retry_tick()
        assert watcher._retry_timer.interval > spiffe._PENDING_RETRY[0]
        with watcher._deliver_lock:
            watcher._offer("a newer update, usable in a second")
        assert watcher._retry_timer.interval == spiffe._PENDING_RETRY[0]
    finally:
        watcher.stop(join=False)


def test_authenticate_during_an_authority_removal_never_sees_a_gap(ca, tmp_path):  # noqa: F811
    """A connection accepted before and after a reload is accepted at every point inside it."""
    successor = ts.CA(tmp_path, "successor root")
    paths = ca.files("ca-rotation", ts.SERVER, bundle=ca.pem + successor.pem)
    server = ts._tls(paths, True)
    renewed = successor.files("renewed-agent", ts.AGENT, bundle=ca.pem + successor.pem)
    in_flight, _ = ts.connect(server, ts._tls(renewed, False))  # Its peer is anchored in the authority that stays.
    third = ts.CA(tmp_path, "third root")
    paths["bundle"].write_bytes(ca.pem + successor.pem + third.pem)  # First an authority is added:
    server.reload()  # the connection's generation is now an earlier one, kept as it is.
    assert server.authenticate(in_flight).spiffe_id == ts.AGENT
    ts._rewrite(successor, paths, ts.SERVER, bundle=successor.pem)  # Then the original authority is removed.
    seen = []

    class Observed(weakref.WeakSet):
        def add(self, item):  # Runs where another thread could be scheduled during the reload.
            try:
                seen.append(server.authenticate(in_flight).spiffe_id)
            except SpiffeError as exc:
                seen.append(f"refused: {exc}")
            super().add(item)

    server._retired = Observed()
    server.reload()
    assert server.authenticate(in_flight).spiffe_id == ts.AGENT
    assert seen and set(seen) == {ts.AGENT}


def test_a_partner_copy_of_the_issuers_own_intermediate_drops_the_partner(ca, tmp_path, caplog):  # noqa: F811
    """The intermediate above this workload's SVID is not in its bundle. A partner certificate imitating it still counts."""
    issuing = ts.sub_ca(ca, tmp_path, "home issuing ca")  # Signs home SVIDs; the home bundle holds only the root.
    partner = ts.CA(tmp_path, "partner root")
    partner_bundle = tmp_path / "partner.pem"
    paths = issuing.files("server", ts.SERVER, bundle=ca.pem)
    paths["cert"].write_bytes(paths["cert"].read_bytes() + issuing.pem)  # Leaf, then its issuer.
    agent = issuing.files("home-agent", ts.AGENT)
    agent["cert"].write_bytes(agent["cert"].read_bytes() + issuing.pem)

    partner_bundle.write_bytes(partner.pem)
    assert ts.PARTNER in ts.tls_in(ts.DOMAIN, paths, True, {ts.PARTNER: partner_bundle})._current.domains
    partner_bundle.write_bytes(partner.pem + ts.lookalike(issuing.cert))
    with caplog.at_level("WARNING", logger="tenuo.spiffe"):
        server = ts.tls_in(ts.DOMAIN, paths, True, {ts.PARTNER: partner_bundle})
    assert ts.PARTNER not in server._current.domains and "shares an authority" in caplog.text
    connection, _ = ts.connect(server, ts.raw_client(agent, ca.pem))  # Home workloads are served as before.
    if spiffe._verified_chain(connection) is not None:  # Python 3.9 cannot follow an intermediate with federation on.
        assert server.authenticate(connection).spiffe_id == ts.AGENT


def test_a_replaced_retry_timer_does_nothing_when_it_fires_late():
    offered = []

    def not_valid_yet(snapshot):
        offered.append(snapshot)
        raise SpiffeError("Local SVID is not currently valid")

    watcher = spiffe._WorkloadAPIWatcher("127.0.0.1:1", spiffe._FETCH_X509_SVID, lambda raw: raw, not_valid_yet)
    try:
        with watcher._deliver_lock:
            watcher._offer("first update")
        first = watcher._retry_timer
        with watcher._deliver_lock:
            watcher._offer("a newer update")  # Cancels the first timer and starts its own.
        second = watcher._retry_timer
        assert second is not first and second.interval == spiffe._PENDING_RETRY[0]
        watcher._retry_tick(first)  # The first had already fired and was waiting its turn.
        # Still the one timer, on its own schedule, and no retry outside it.
        assert watcher._retry_timer is second and offered == ["first update", "a newer update"]
    finally:
        watcher.stop(join=False)
