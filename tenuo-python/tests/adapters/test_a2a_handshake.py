"""
A2A Automated Handshake (CSR Pattern) Test Suite.

Tests the full JSON-RPC stack for agent/register via httpx.AsyncClient +
the Starlette ASGI app, using real tenuo_core Ed25519 keys throughout.

The pattern:
  1. Agent creates self-signed challenge warrant (TTL=120s)
  2. Server verifies signature, issuer == public_key (proves key ownership)
  3. Handler decides what to grant, calls issue() oracle
  4. Client receives a usable warrant
"""

import pytest


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def server_key():
    """Server signing key."""
    try:
        from tenuo_core import SigningKey

        return SigningKey.generate()
    except ImportError:
        pytest.skip("tenuo_core not available")


@pytest.fixture
def agent_key():
    """Agent signing key (the one requesting registration)."""
    try:
        from tenuo_core import SigningKey

        return SigningKey.generate()
    except ImportError:
        pytest.skip("tenuo_core not available")


@pytest.fixture
def other_key():
    """Unrelated signing key (for mismatch tests)."""
    try:
        from tenuo_core import SigningKey

        return SigningKey.generate()
    except ImportError:
        pytest.skip("tenuo_core not available")


def _make_server(server_key, handler=None, require_warrant=False, require_pop=False):
    """Build a test A2AServer with registration support."""
    try:
        from httpx import ASGITransport, AsyncClient  # noqa: F401
    except ImportError:
        pytest.skip("httpx not available")

    try:
        from starlette.applications import Starlette  # noqa: F401
    except ImportError:
        pytest.skip("starlette not available")

    from tenuo.a2a.server import A2AServer

    server = A2AServer(
        name="Test Registration Agent",
        url="https://reg.example.com",
        public_key=server_key.public_key,
        trusted_issuers=[server_key.public_key],
        require_warrant=require_warrant,
        require_pop=require_pop,
        require_audience=False,  # Simplify: no aud required for CSR tests
        check_replay=True,
        signing_key=server_key,
        registration_handler=handler,
    )

    @server.skill("echo")
    async def echo(message: str) -> str:
        return f"echo:{message}"

    return server


def _make_challenge(agent_key):
    """Create a self-signed challenge warrant for registration."""
    from tenuo_core import Warrant

    # "_csr" is a sentinel capability — Rust core requires ≥1 capability but
    # the server ignores challenge token capabilities during registration.
    return Warrant.mint(
        keypair=agent_key,
        holder=agent_key.public_key,
        capabilities={"_csr": {}},
        ttl_seconds=120,
    )


async def _post_register(app, params):
    """Send agent/register request and return response data."""
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/a2a",
            json={"jsonrpc": "2.0", "method": "agent/register", "params": params, "id": 1},
        )
    return response.json()


# =============================================================================
# Test: Successful Registration
# =============================================================================


class TestSuccessfulRegistration:
    """Handler calls issue(), client receives a usable warrant."""

    async def test_successful_registration(self, server_key, agent_key):
        """Full happy path: registration returns a valid warrant."""
        from tenuo_core import Warrant

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)
        challenge = _make_challenge(agent_key)

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": {},
            },
        )

        assert "result" in data, f"Expected result, got: {data}"
        assert "warrant" in data["result"]
        # The returned warrant must be parseable
        issued = Warrant.from_base64(data["result"]["warrant"])
        assert issued is not None

    async def test_issued_warrant_usable_for_task(self, server_key, agent_key):
        """Warrant returned from registration is accepted by task/send."""
        from httpx import ASGITransport, AsyncClient

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler, require_warrant=True, require_pop=False)
        challenge = _make_challenge(agent_key)

        reg_data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": {},
            },
        )
        assert "result" in reg_data, f"Registration failed: {reg_data}"
        warrant_token = reg_data["result"]["warrant"]

        # Use the issued warrant for a task
        transport = ASGITransport(app=server.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/a2a",
                headers={"X-Tenuo-Warrant": warrant_token},
                json={
                    "jsonrpc": "2.0",
                    "method": "task/send",
                    "params": {"task": {"skill": "echo", "arguments": {"message": "hello"}}},
                    "id": 2,
                },
            )

        result_data = response.json()
        assert "result" in result_data, f"Task failed: {result_data}"
        assert result_data["result"]["output"] == "echo:hello"


# =============================================================================
# Test: Registration Disabled
# =============================================================================


class TestRegistrationDisabled:
    """No handler configured → RegistrationDisabledError."""

    async def test_registration_disabled_no_handler(self, server_key, agent_key):
        """Server without registration_handler returns REGISTRATION_DISABLED."""
        # Server without handler — no registration_handler passed
        server = _make_server(server_key, handler=None)
        challenge = _make_challenge(agent_key)

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": {},
            },
        )

        assert "error" in data
        assert data["error"]["code"] == -32017  # REGISTRATION_DISABLED

    def test_builder_without_handler_still_works(self, server_key):
        """Server built without registration_handler starts normally."""
        from tenuo.a2a import A2AServerBuilder

        server = (
            A2AServerBuilder()
            .name("No-reg Server")
            .url("https://noreg.example.com")
            .key(server_key)
            .trust(server_key.public_key)
            .build()
        )
        assert server._registration_handler is None


# =============================================================================
# Test: Handler Denies
# =============================================================================


class TestHandlerDenies:
    """Handler raises RegistrationDeniedError → client sees it."""

    async def test_handler_raises_denied(self, server_key, agent_key):
        """Handler that raises RegistrationDeniedError sends -32018 to client."""
        from tenuo.a2a.errors import RegistrationDeniedError

        async def handler(req, issue):
            raise RegistrationDeniedError("Key not pre-enrolled")

        server = _make_server(server_key, handler=handler)
        challenge = _make_challenge(agent_key)

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": {},
            },
        )

        assert "error" in data
        assert data["error"]["code"] == -32018  # REGISTRATION_DENIED
        assert "Key not pre-enrolled" in data["error"]["message"]


# =============================================================================
# Test: Handler Skips issue()
# =============================================================================


class TestHandlerSkipsIssue:
    """Handler returns without calling issue() → RegistrationDeniedError."""

    async def test_handler_skips_issue(self, server_key, agent_key):
        """Handler that doesn't call issue() causes REGISTRATION_DENIED."""

        async def handler(req, issue):
            pass  # Forgot to call issue()

        server = _make_server(server_key, handler=handler)
        challenge = _make_challenge(agent_key)

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": {},
            },
        )

        assert "error" in data
        assert data["error"]["code"] == -32018  # REGISTRATION_DENIED


# =============================================================================
# Test: Replay Protection
# =============================================================================


class TestReplayProtection:
    """Same challenge_token reused → ReplayDetectedError."""

    async def test_replay_detected_on_reuse(self, server_key, agent_key):
        """Reusing the same challenge_token is rejected on second attempt."""

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)
        challenge = _make_challenge(agent_key)
        params = {
            "public_key": agent_key.public_key.to_bytes().hex(),
            "capabilities": {"echo": {}},
            "challenge_token": challenge.to_base64(),
            "extensions": {},
        }

        # First call: should succeed
        data1 = await _post_register(server.app, params)
        assert "result" in data1, f"First registration failed: {data1}"

        # Second call with same challenge_token: replay detected
        data2 = await _post_register(server.app, params)
        assert "error" in data2
        assert data2["error"]["code"] == -32006  # REPLAY_DETECTED


# =============================================================================
# Test: Expired Challenge Token
# =============================================================================


class TestExpiredChallengeToken:
    """Expired challenge_token → InvalidSignatureError."""

    async def test_expired_challenge_rejected(self, server_key, agent_key):
        """Challenge token that is_expired() returns True is rejected."""
        from unittest.mock import MagicMock, patch

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)

        with patch("tenuo_core.Warrant") as MockWarrant:
            mock_w = MagicMock()
            mock_w.is_expired.return_value = True
            mock_w.issuer = MagicMock()
            mock_w.issuer.to_bytes.return_value = bytes.fromhex(
                agent_key.public_key.to_bytes().hex()
            )
            mock_w.id = "test-jti-expired"
            MockWarrant.from_base64.return_value = mock_w

            data = await _post_register(
                server.app,
                {
                    "public_key": agent_key.public_key.to_bytes().hex(),
                    "capabilities": {"echo": {}},
                    "challenge_token": "fake_token",
                    "extensions": {},
                },
            )

        assert "error" in data
        assert data["error"]["code"] == -32002  # INVALID_SIGNATURE (expired)


# =============================================================================
# Test: Key Mismatch
# =============================================================================


class TestKeyMismatch:
    """challenge_token signed by different key → InvalidSignatureError."""

    async def test_key_mismatch_rejected(self, server_key, agent_key, other_key):
        """Challenge signed by other_key but claiming agent_key is rejected."""

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)

        # Sign with other_key but claim to be agent_key
        challenge = _make_challenge(other_key)  # Signed by other_key

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),  # Claim agent_key
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),  # But signed by other_key
                "extensions": {},
            },
        )

        assert "error" in data
        assert data["error"]["code"] == -32002  # INVALID_SIGNATURE


# =============================================================================
# Test: Extensions Passthrough
# =============================================================================


class TestExtensionsPassthrough:
    """Extension data in request reaches handler unchanged."""

    async def test_extensions_reach_handler(self, server_key, agent_key):
        """TEE-style extension data is passed through to handler."""
        received_extensions = {}

        async def handler(req, issue):
            received_extensions.update(req.extensions)
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)
        challenge = _make_challenge(agent_key)

        tee_data = {
            "tee_type": "sgx",
            "mrenclave": "deadbeef" * 8,
            "report": "base64report==",
        }

        data = await _post_register(
            server.app,
            {
                "public_key": agent_key.public_key.to_bytes().hex(),
                "capabilities": {"echo": {}},
                "challenge_token": challenge.to_base64(),
                "extensions": tee_data,
            },
        )

        assert "result" in data, f"Registration failed: {data}"
        assert received_extensions == tee_data


# =============================================================================
# Test: Builder Validation
# =============================================================================


class TestBuilderValidation:
    """Builder rejects registration_handler without signing key."""

    def test_builder_rejects_handler_without_signing_key(self, server_key):
        """registration_handler() requires a SigningKey, not just a PublicKey."""
        from tenuo.a2a import A2AServerBuilder

        async def handler(req, issue):
            await issue(capabilities={}, ttl=3600)

        with pytest.raises(ValueError, match="signing key"):
            (
                A2AServerBuilder()
                .name("Test")
                .url("https://example.com")
                .public_key(server_key.public_key)  # Only public key
                .trust(server_key.public_key)
                .registration_handler(handler)
                .build()
            )

    def test_builder_accepts_handler_with_signing_key(self, server_key):
        """registration_handler() works when .key() receives a SigningKey."""
        from tenuo.a2a import A2AServerBuilder

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = (
            A2AServerBuilder()
            .name("Test")
            .url("https://example.com")
            .key(server_key)  # Full signing key
            .trust(server_key.public_key)
            .registration_handler(handler)
            .build()
        )
        assert server._registration_handler is handler
        assert server._signing_key is server_key


# =============================================================================
# Test: A2AClient.request_warrant()
# =============================================================================


class TestClientRequestWarrant:
    """A2AClient.request_warrant() integrates with the server correctly."""

    async def test_client_request_warrant_success(self, server_key, agent_key):
        """Client request_warrant() returns a usable Warrant."""
        import httpx
        from httpx import ASGITransport
        from tenuo_core import Warrant

        from tenuo.a2a.client import A2AClient

        async def handler(req, issue):
            await issue(capabilities={"echo": {}}, ttl=3600)

        server = _make_server(server_key, handler=handler)

        transport = ASGITransport(app=server.app)
        client = A2AClient("http://test")
        client._client = httpx.AsyncClient(transport=transport, base_url="http://test")
        client.url = "http://test"

        warrant = await client.request_warrant(
            signing_key=agent_key,
            capabilities={"echo": {}},
        )

        assert isinstance(warrant, Warrant)

    async def test_client_request_warrant_disabled(self, server_key, agent_key):
        """Client request_warrant() raises RegistrationDisabledError when no handler."""
        import httpx
        from httpx import ASGITransport

        from tenuo.a2a.client import A2AClient
        from tenuo.a2a.errors import RegistrationDisabledError

        server = _make_server(server_key, handler=None)

        transport = ASGITransport(app=server.app)
        client = A2AClient("http://test")
        client._client = httpx.AsyncClient(transport=transport, base_url="http://test")
        client.url = "http://test"

        with pytest.raises(RegistrationDisabledError):
            await client.request_warrant(
                signing_key=agent_key,
                capabilities={"echo": {}},
            )

    async def test_client_request_warrant_denied(self, server_key, agent_key):
        """Client request_warrant() raises RegistrationDeniedError when handler denies."""
        import httpx
        from httpx import ASGITransport

        from tenuo.a2a.client import A2AClient
        from tenuo.a2a.errors import RegistrationDeniedError

        async def handler(req, issue):
            raise RegistrationDeniedError("Not in allowlist")

        server = _make_server(server_key, handler=handler)

        transport = ASGITransport(app=server.app)
        client = A2AClient("http://test")
        client._client = httpx.AsyncClient(transport=transport, base_url="http://test")
        client.url = "http://test"

        with pytest.raises(RegistrationDeniedError):
            await client.request_warrant(
                signing_key=agent_key,
                capabilities={"echo": {}},
            )
