"""A2A server and client checks run with default settings and real warrants."""

import base64
import io
import time

import httpx
import pytest

pytest.importorskip("starlette")
tenuo_core = pytest.importorskip("tenuo_core")

from tenuo_core import SigningKey, Subpath, Warrant, encode_warrant_stack  # noqa: E402

from tenuo.a2a import A2AClient, A2AServer  # noqa: E402
from tenuo.a2a.errors import ChainValidationError, KeyMismatchError  # noqa: E402

PING = {"task": {"skill": "ping", "arguments": {}}}


def make_server(issuer, **kwargs):
    server = A2AServer(
        name="agent",
        url="https://agent.example.com",
        public_key=SigningKey.generate().public_key,
        trusted_issuers=[issuer.public_key],
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
        ttl_seconds=300,
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
