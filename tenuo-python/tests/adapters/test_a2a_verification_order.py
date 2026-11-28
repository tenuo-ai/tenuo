"""A2A server and client checks run with default settings and real warrants."""

import base64
import asyncio
import io
import os
import sys
import time

import httpx
import pytest

pytest.importorskip("starlette")
tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey, Subpath, Warrant, encode_warrant_stack  # noqa: E402

from tenuo.a2a import A2AClient, A2AServer  # noqa: E402
from tenuo.a2a.errors import ChainValidationError, KeyMismatchError  # noqa: E402

PING = {"task": {"skill": "ping", "arguments": {}}}


def make_server(issuer, trusted_issuers=None, **kwargs):
    server = A2AServer(
        name="agent",
        url="https://agent.example.com",
        public_key=SigningKey.generate().public_key,
        trusted_issuers=trusted_issuers or [issuer.public_key],
        audit_log=io.StringIO(),
        **kwargs,
    )

    @server.skill("read_file")
    async def read_file(path: str):
        return f"read {path}"

    @server.skill("ping")
    async def ping():
        return "pong"

    return server


async def send(server, body, headers):
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.post(
            "/a2a",
            json={"jsonrpc": "2.0", "method": "task/send", "params": body, "id": 1},
            headers=headers,
        )
    return response.json()


def pop(warrant, key, skill, args):
    signature = warrant.sign(key, skill, args, int(time.time()))
    return base64.urlsafe_b64encode(bytes(signature)).decode()


def delegate(parent, signer, holder):
    return parent.attenuate(
        capabilities={"ping": {}},
        signing_key=signer,
        holder=holder.public_key,
    )


async def test_request_without_valid_pop_does_not_use_up_the_warrant():
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    server = make_server(issuer)
    warrant = (
        Warrant.mint_builder()
        .capability("read_file", path=Subpath("/data"))
        .holder(holder.public_key)
        .ttl(600)
        .mint(issuer)
    )
    args = {"path": "/data/x"}
    body = {"task": {"skill": "read_file", "arguments": args}}
    token = warrant.to_base64()

    bad_pop = base64.urlsafe_b64encode(b"\0" * 64).decode()
    denied = await send(server, body, {"X-Tenuo-Warrant": token, "X-Tenuo-PoP": bad_pop})
    assert "error" in denied

    outside = {"task": {"skill": "read_file", "arguments": {"path": "/etc/x"}}}
    denied = await send(
        server,
        outside,
        {"X-Tenuo-Warrant": token, "X-Tenuo-PoP": pop(warrant, holder, "read_file", {"path": "/etc/x"})},
    )
    assert "error" in denied

    headers = {"X-Tenuo-Warrant": token, "X-Tenuo-PoP": pop(warrant, holder, "read_file", args)}
    allowed = await send(server, body, headers)
    assert allowed["result"]["output"] == "read /data/x"

    replayed = await send(server, body, headers)
    assert replayed["error"]["code"] == -32006


async def test_revoked_issuer_anywhere_in_the_chain_is_rejected():
    issuer, mid, holder, leaf_key = (SigningKey.generate() for _ in range(4))
    root = Warrant.mint_builder().capability("ping").holder(mid.public_key).ttl(600).mint(issuer)
    child = delegate(root, mid, holder)
    grandchild = delegate(child, holder, leaf_key)

    def headers(chain, key):
        return {
            "X-Tenuo-Warrant": encode_warrant_stack(chain),
            "X-Tenuo-PoP": pop(chain[-1], key, "ping", {}),
        }

    control = make_server(issuer, check_replay=False)
    assert (await send(control, PING, headers([root, child], holder)))["result"]["output"] == "pong"

    root_revoked = make_server(issuer, revoked_issuers=[issuer.public_key], check_replay=False)
    result = await send(root_revoked, PING, headers([root, child], holder))
    assert result["error"]["code"] == -32009

    mid_revoked = make_server(issuer, revoked_issuers=[mid.public_key], check_replay=False)
    result = await send(mid_revoked, PING, headers([root, child, grandchild], leaf_key))
    assert result["error"]["code"] == -32009


async def test_max_chain_depth_applies_to_a_warrant_stack():
    issuer = SigningKey.generate()
    keys = [SigningKey.generate() for _ in range(4)]
    chain = [Warrant.mint_builder().capability("ping").holder(keys[0].public_key).ttl(600).mint(issuer)]
    for i in range(1, 4):
        chain.append(delegate(chain[-1], keys[i - 1], keys[i]))
    headers = {
        "X-Tenuo-Warrant": encode_warrant_stack(chain),
        "X-Tenuo-PoP": pop(chain[-1], keys[-1], "ping", {}),
    }

    shallow = make_server(issuer, max_chain_depth=1, check_replay=False)
    assert (await send(shallow, PING, headers))["error"]["code"] == -32010

    deep = make_server(issuer, max_chain_depth=3, check_replay=False)
    assert (await send(deep, PING, headers))["result"]["output"] == "pong"


def test_client_validate_chain_uses_the_trusted_roots_in_any_key_form():
    root, holder, sub, attacker = (SigningKey.generate() for _ in range(4))
    parent = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(600).mint(root)
    child = delegate(parent, holder, sub)
    self_signed = Warrant.mint_builder().capability("ping").holder(attacker.public_key).ttl(600).mint(attacker)
    broader = Warrant.mint_builder().capability("admin").holder(sub.public_key).ttl(600).mint(holder)
    root_hex = bytes(root.public_key.to_bytes()).hex()
    client = A2AClient("http://agent.example.com")

    def tokens(*warrants):
        return [w.to_base64() for w in warrants]

    assert client.validate_chain(tokens(parent, child), trusted_roots=[root.public_key])
    assert client.validate_chain(tokens(parent, child), trusted_roots=[root_hex])

    for roots in ([root.public_key], [root_hex], ["not-a-key"]):
        with pytest.raises(ChainValidationError):
            client.validate_chain(tokens(self_signed), trusted_roots=roots)
    with pytest.raises(ChainValidationError):
        client.validate_chain(tokens(parent, broader), trusted_roots=[root.public_key])


async def test_pinned_key_requires_the_card_to_carry_a_key(monkeypatch):
    client = A2AClient("http://agent.example.com", pin_key="z6MkPinnedAgentKey")

    class Response:
        status_code = 200

        def json(self):
            return {"name": "agent", "url": "http://agent.example.com", "skills": []}

    class Http:
        async def get(self, *args, **kwargs):
            return Response()

        async def post(self, *args, **kwargs):
            return Response()

    async def get_client():
        return Http()

    monkeypatch.setattr(client, "_get_client", get_client)
    with pytest.raises(KeyMismatchError):
        await client.discover()


@pytest.mark.parametrize("carrier", ["stack", "legacy"])
async def test_presented_chain_policies_apply_even_with_a_directly_trusted_leaf_issuer(carrier):
    from tenuo.a2a.errors import RevokedError

    issuer, mid, holder = (SigningKey.generate() for _ in range(3))
    root = Warrant.mint_builder().capability("ping").holder(mid.public_key).ttl(600).mint(issuer)
    child = delegate(root, mid, holder)
    options = {"_preloaded_parents": [root]} if carrier == "stack" else {"warrant_chain": root.to_base64()}
    trusted = [issuer.public_key, mid.public_key]
    signature = bytes(child.sign(holder, "ping", {}, int(time.time())))
    revoked = make_server(issuer, trusted_issuers=trusted, revoked_issuers=[issuer.public_key], check_replay=False)
    with pytest.raises(RevokedError):
        await revoked.validate_warrant(child.to_base64(), "ping", {}, pop_signature=signature, **options)
    shallow = make_server(issuer, trusted_issuers=trusted, max_chain_depth=0, check_replay=False)
    with pytest.raises(ChainValidationError, match="depth"):
        await shallow.validate_warrant(child.to_base64(), "ping", {}, pop_signature=signature, **options)


async def test_signature_is_verified_when_pop_is_disabled():
    from tenuo.a2a.errors import InvalidSignatureError

    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(600).mint(issuer)
    server = make_server(issuer, require_pop=False, check_replay=False)
    assert await server.validate_warrant(warrant.to_base64(), "ping", {})
    forged = bytearray(warrant.to_bytes())
    forged[-1] ^= 1
    token = base64.urlsafe_b64encode(forged).decode().rstrip("=")
    with pytest.raises(Exception, match="invalid warrant signature"):
        Warrant.from_base64(token)
    with pytest.raises(InvalidSignatureError, match="invalid warrant signature"):
        await server.validate_warrant(token, "ping", {})


@pytest.mark.parametrize("method", ["task/send", "task/sendSubscribe"])
async def test_legacy_chain_header_is_enforced_through_both_http_endpoints(method):
    from tenuo.a2a.server import WARRANT_CHAIN_HEADER

    issuer, mid, holder = (SigningKey.generate() for _ in range(3))
    root = Warrant.mint_builder().capability("ping").holder(mid.public_key).ttl(600).mint(issuer)
    child = delegate(root, mid, holder)
    headers = {
        "X-Tenuo-Warrant": child.to_base64(),
        WARRANT_CHAIN_HEADER: root.to_base64(),
        "X-Tenuo-PoP": pop(child, holder, "ping", {}),
    }

    async def request(server):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="http://t") as client:
            return await client.post("/a2a", json={"jsonrpc": "2.0", "method": method, "params": PING, "id": 1}, headers=headers)

    allowed = await request(make_server(issuer, check_replay=False))
    if method == "task/send":
        assert allowed.json()["result"]["output"] == "pong"
    else:
        assert "text/event-stream" in allowed.headers["content-type"]
        assert "pong" in allowed.text
    trusted = [issuer.public_key, mid.public_key]
    revoked = await request(make_server(issuer, trusted_issuers=trusted, revoked_issuers=[issuer.public_key], check_replay=False))
    assert revoked.json()["error"]["code"] == -32009
    shallow = await request(make_server(issuer, trusted_issuers=trusted, max_chain_depth=0, check_replay=False))
    assert shallow.json()["error"]["code"] == -32010


def multibase_key(key):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(b"\xed\x01" + bytes(key.to_bytes()), "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "z" + encoded


@pytest.mark.parametrize("did", [False, True])
def test_multibase_roots_work_without_an_optional_decoder(monkeypatch, did):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    warrant = Warrant.mint_builder().capability("ping").holder(holder.public_key).ttl(600).mint(issuer)
    key = multibase_key(issuer.public_key)
    if did:
        key = "did:key:" + key
    monkeypatch.setitem(sys.modules, "base58", None)
    client = A2AClient("https://agent.example.com", pin_key=key)
    assert client.validate_chain([warrant.to_base64()])
    assert client.validate_chain([warrant.to_base64()], trusted_roots=[key])
    server = make_server(issuer, trusted_issuers=[key])
    assert bytes(issuer.public_key.to_bytes()).hex() in server.trusted_issuers


@pytest.mark.parametrize("did", [False, True])
async def test_pinned_key_compares_decoded_key_identity(monkeypatch, did):
    from unittest.mock import AsyncMock

    key = SigningKey.generate().public_key
    pin = multibase_key(key)
    if did:
        pin = "did:key:" + pin
    key_hex = bytes(key.to_bytes()).hex()
    client = A2AClient("https://agent.example.com", pin_key=pin)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
        "name": "agent", "url": "https://agent.example.com", "skills": [], "x-tenuo": {"public_key": key_hex},
    }))
    async with httpx.AsyncClient(transport=transport) as http:
        monkeypatch.setattr(client, "_get_client", AsyncMock(return_value=http))
        card = await client.discover()
    assert card.public_key == key_hex


@pytest.mark.parametrize("denial", ["replay", "server_constraint", "backend_failure", "cancelled_audit", "revoked_before_pep"])
async def test_local_denial_releases_only_its_approval_reservation(monkeypatch, denial):
    from unittest.mock import AsyncMock

    from tenuo.consumption import ApprovalConsumptionStore, current_idempotency_key
    from tenuo_core import ApprovalPayload, SignedApproval, py_compute_request_hash

    store = ApprovalConsumptionStore()
    monkeypatch.setattr("tenuo.consumption._default_store", store)
    issuer, holder, approver = (SigningKey.generate() for _ in range(3))
    args = {"path": "/private"}
    warrant = Warrant.issue(
        issuer, holder=holder.public_key, capabilities={"read_file": {}}, ttl_seconds=600,
        approval_gates={"read_file": None}, required_approvers=[approver.public_key], min_approvals=1,
    )
    server = make_server(issuer)
    now = int(time.time())
    signature = bytes(warrant.sign(holder, "read_file", args, now))

    def approval():
        return SignedApproval.create(ApprovalPayload(
            request_hash=py_compute_request_hash(warrant.id, "read_file", args, holder.public_key),
            nonce=os.urandom(16), external_id="review-test", approved_at=now, expires_at=now + 300,
        ), approver)

    retained = 0
    if denial in {"replay", "revoked_before_pep"}:
        await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature, approvals=[approval()])
        retained = 1
        if denial == "revoked_before_pep":
            server._revoked_issuers = frozenset({bytes(issuer.public_key.to_bytes()).hex()})
    elif denial == "server_constraint":
        server._skills["read_file"].constraints["path"] = Subpath("/data")
    elif denial == "backend_failure":
        server._replay_cache.check_and_add = AsyncMock(side_effect=ConnectionError("replay backend unavailable"))
    else:
        server._audit = AsyncMock(side_effect=asyncio.CancelledError())

    retry_approval = approval()
    with pytest.raises(asyncio.CancelledError if denial == "cancelled_audit" else Exception):
        await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature, approvals=[retry_approval])
    assert len(store) == retained
    assert current_idempotency_key() is None
    server.check_replay = False
    server._revoked_issuers = frozenset()
    server._audit = AsyncMock(return_value=None)
    server._skills["read_file"].constraints.clear()
    await server.validate_warrant(warrant.to_base64(), "read_file", args, pop_signature=signature, approvals=[retry_approval])
    assert len(store) == retained + 1
