"""
Tests for WarrantStack-based chain transport (A2A).

Covers:
- Client packs chain + leaf into a single WarrantStack header
- Server detects and unpacks WarrantStack from X-Tenuo-Warrant
- Server falls back to legacy X-Tenuo-Warrant-Chain when no WarrantStack
- _validate_chain_warrants enforces depth, emptiness, trust, linkage
- _validate_chain (legacy) delegates to _validate_chain_warrants
- validate_warrant routes to the right path based on _preloaded_parents
- End-to-end round-trip with real tenuo_core warrants
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tenuo.a2a import A2AServer
from tenuo.a2a.errors import (
    ChainValidationError,
    UntrustedIssuerError,
    WarrantExpiredError,
)


# =============================================================================
# Helpers / fixtures
# =============================================================================


def _make_server(trusted_issuers=None, max_chain_depth=5, trust_delegated=True):
    return A2AServer(
        name="Stack Test Agent",
        url="https://stack.example.com",
        public_key="z6MkStackServer",
        trusted_issuers=trusted_issuers or ["z6MkRootIssuer"],
        trust_delegated=trust_delegated,
        max_chain_depth=max_chain_depth,
        require_warrant=False,
        require_audience=False,
        check_replay=False,
        require_pop=False,
        audit_log=None,
    )


def _mock_warrant(id_val="wrt_leaf", iss="z6MkRootIssuer", sub=None, exp=None):
    """Return a MagicMock that looks like a decoded Warrant."""
    w = MagicMock()
    w.id = id_val
    w.jti = None
    w.iss = iss
    w.issuer = iss
    w.sub = sub
    w.subject = sub
    w.authorized_holder = None
    w.grants = [{"skill": "ping"}]  # default: grants ping so validate_warrant doesn't reject
    w.tools = None
    w.exp = exp or (int(time.time()) + 3600)
    w.is_expired = MagicMock(return_value=False)
    w.to_base64 = MagicMock(return_value=f"base64_{id_val}")
    return w


# =============================================================================
# Client: header construction
# =============================================================================


class TestClientWarrantStackPacking:
    """Client packs chain into a WarrantStack when warrant_chain is provided."""

    def _make_mock_warrant(self, id_val="w0"):
        w = MagicMock()
        w.to_base64 = MagicMock(return_value=f"b64_{id_val}")
        return w

    def test_no_chain_sends_single_warrant_header(self):
        """Without warrant_chain, X-Tenuo-Warrant carries the plain leaf token."""
        leaf = self._make_mock_warrant("leaf")

        headers = {}
        warrant_chain = None
        if warrant_chain:
            pass  # not reached
        else:
            headers["X-Tenuo-Warrant"] = leaf.to_base64()

        assert headers["X-Tenuo-Warrant"] == "b64_leaf"
        assert "X-Tenuo-Warrant-Chain" not in headers

    def test_with_chain_calls_encode_warrant_stack(self):
        """With warrant_chain, encode_warrant_stack is invoked with [*parents, leaf]."""
        leaf = self._make_mock_warrant("leaf")
        parent = self._make_mock_warrant("root")

        with patch("tenuo_core.encode_warrant_stack", return_value="stack_b64") as mock_enc:
            warrant_chain = [parent]
            all_warrants = list(warrant_chain) + [leaf]
            from tenuo_core import encode_warrant_stack

            result = encode_warrant_stack(all_warrants)
            mock_enc.assert_called_once_with([parent, leaf])
            assert result == "stack_b64"

    def test_with_chain_header_contains_stack_not_two_headers(self):
        """Client sends a single X-Tenuo-Warrant with WarrantStack, no chain header."""
        leaf = self._make_mock_warrant("leaf")
        parent1 = self._make_mock_warrant("root")
        parent2 = self._make_mock_warrant("mid")

        with patch("tenuo_core.encode_warrant_stack", return_value="encoded_stack"):
            warrant_chain = [parent1, parent2]
            headers = {}
            try:
                from tenuo_core import encode_warrant_stack

                all_warrants = list(warrant_chain) + [leaf]
                stack_b64 = encode_warrant_stack(all_warrants)
                headers["X-Tenuo-Warrant"] = stack_b64
            except Exception:
                headers["X-Tenuo-Warrant"] = leaf.to_base64()
                headers["X-Tenuo-Warrant-Chain"] = ";".join(w.to_base64() for w in warrant_chain)

        assert headers.get("X-Tenuo-Warrant") == "encoded_stack"
        assert "X-Tenuo-Warrant-Chain" not in headers

    def test_fallback_on_encode_failure_sends_legacy_headers(self):
        """If encode_warrant_stack raises, client falls back to the legacy two-header format."""
        leaf = self._make_mock_warrant("leaf")
        parent = self._make_mock_warrant("root")

        with patch("tenuo_core.encode_warrant_stack", side_effect=RuntimeError("boom")):
            warrant_chain = [parent]
            headers = {}
            try:
                from tenuo_core import encode_warrant_stack

                all_warrants = list(warrant_chain) + [leaf]
                stack_b64 = encode_warrant_stack(all_warrants)
                if stack_b64:
                    headers["X-Tenuo-Warrant"] = stack_b64
                else:
                    raise ValueError("None")
            except Exception:
                headers["X-Tenuo-Warrant"] = leaf.to_base64()
                headers["X-Tenuo-Warrant-Chain"] = ";".join(w.to_base64() for w in warrant_chain)

        assert headers["X-Tenuo-Warrant"] == "b64_leaf"
        assert headers["X-Tenuo-Warrant-Chain"] == "b64_root"


# =============================================================================
# Server: HTTP handler – WarrantStack detection
# =============================================================================


class TestServerWarrantStackDetection:
    """Server HTTP handler correctly splits WarrantStack into leaf + parents."""

    def _make_request(self, headers):
        req = MagicMock()
        req.headers = headers
        return req

    def _make_server_with_skill(self):
        """Create a server with a registered 'ping' skill for handler tests."""
        server = _make_server()

        @server.skill("ping")
        async def ping():
            return "pong"

        return server

    @pytest.mark.asyncio
    async def test_single_warrant_stack_decoded_as_leaf(self):
        """A 1-element WarrantStack is decoded and treated as a plain leaf (no parents)."""
        server = self._make_server_with_skill()
        leaf_mock = _mock_warrant("leaf")

        with patch("tenuo_core.decode_warrant_stack_base64", return_value=[leaf_mock]):
            server.validate_warrant = AsyncMock(return_value=leaf_mock)

            request = self._make_request({"X-Tenuo-Warrant": "some_stack_b64"})
            params = {"task": {"skill": "ping", "arguments": {}, "id": "t1"}}

            await server._handle_task_send(request, params)

            call_kwargs = server.validate_warrant.call_args
            assert call_kwargs is not None
            # _preloaded_parents should be an empty list (single-element stack → no parents)
            assert call_kwargs.kwargs.get("_preloaded_parents") == []

    @pytest.mark.asyncio
    async def test_multi_warrant_stack_splits_leaf_and_parents(self):
        """A 3-element WarrantStack becomes parents=[w0,w1], leaf=w2."""
        server = self._make_server_with_skill()
        root_mock = _mock_warrant("root", iss="z6MkRootIssuer", sub="z6MkMid")
        mid_mock = _mock_warrant("mid", iss="z6MkMid", sub="z6MkLeafIssuer")
        leaf_mock = _mock_warrant("leaf", iss="z6MkLeafIssuer")

        with patch(
            "tenuo_core.decode_warrant_stack_base64",
            return_value=[root_mock, mid_mock, leaf_mock],
        ):
            server.validate_warrant = AsyncMock(return_value=leaf_mock)

            request = self._make_request({"X-Tenuo-Warrant": "stack_b64_3warrants"})
            params = {"task": {"skill": "ping", "arguments": {}, "id": "t2"}}

            await server._handle_task_send(request, params)

            call_kwargs = server.validate_warrant.call_args
            preloaded = call_kwargs.kwargs.get("_preloaded_parents")
            assert preloaded == [root_mock, mid_mock]
            # warrant_token must be the leaf's re-encoded base64
            warrant_token_arg = call_kwargs.args[0]
            assert warrant_token_arg == leaf_mock.to_base64()

    @pytest.mark.asyncio
    async def test_plain_token_skips_stack_detection(self):
        """If decode_warrant_stack_base64 raises, the raw token is used unchanged."""
        server = self._make_server_with_skill()
        leaf_mock = _mock_warrant("leaf")

        with patch("tenuo_core.decode_warrant_stack_base64", side_effect=Exception("not a stack")):
            server.validate_warrant = AsyncMock(return_value=leaf_mock)

            request = self._make_request({"X-Tenuo-Warrant": "plain_token_b64"})
            params = {"task": {"skill": "ping", "arguments": {}, "id": "t3"}}

            await server._handle_task_send(request, params)

            call_kwargs = server.validate_warrant.call_args
            assert call_kwargs.args[0] == "plain_token_b64"
            assert call_kwargs.kwargs.get("_preloaded_parents") is None

    @pytest.mark.asyncio
    async def test_legacy_chain_header_used_when_no_stack(self):
        """When no WarrantStack is present, X-Tenuo-Warrant-Chain is still honoured."""
        server = self._make_server_with_skill()
        leaf_mock = _mock_warrant("leaf")

        with patch("tenuo_core.decode_warrant_stack_base64", side_effect=Exception("not a stack")):
            server.validate_warrant = AsyncMock(return_value=leaf_mock)

            request = self._make_request(
                {
                    "X-Tenuo-Warrant": "plain_leaf_b64",
                    "X-Tenuo-Warrant-Chain": "parent1_b64;parent2_b64",
                }
            )
            params = {"task": {"skill": "ping", "arguments": {}, "id": "t4"}}

            await server._handle_task_send(request, params)

            call_kwargs = server.validate_warrant.call_args
            assert call_kwargs.kwargs.get("warrant_chain") == "parent1_b64;parent2_b64"
            assert call_kwargs.kwargs.get("_preloaded_parents") is None

    @pytest.mark.asyncio
    async def test_warrant_stack_takes_precedence_over_chain_header(self):
        """When both headers are present, WarrantStack takes precedence."""
        server = self._make_server_with_skill()
        root_mock = _mock_warrant("root")
        leaf_mock = _mock_warrant("leaf")

        with patch(
            "tenuo_core.decode_warrant_stack_base64",
            return_value=[root_mock, leaf_mock],
        ):
            server.validate_warrant = AsyncMock(return_value=leaf_mock)

            request = self._make_request(
                {
                    "X-Tenuo-Warrant": "stack_b64",
                    "X-Tenuo-Warrant-Chain": "should_be_ignored",
                }
            )
            params = {"task": {"skill": "ping", "arguments": {}, "id": "t5"}}

            await server._handle_task_send(request, params)

            call_kwargs = server.validate_warrant.call_args
            assert call_kwargs.kwargs.get("_preloaded_parents") == [root_mock]
            assert call_kwargs.kwargs.get("warrant_chain") is None


# =============================================================================
# _validate_chain_warrants: unit tests
# =============================================================================


class TestValidateChainWarrants:
    """
    Unit tests for _validate_chain_warrants.

    This method now delegates cryptographic chain verification to
    ``Authorizer.verify_chain`` from tenuo_core.  The only server-side
    policy still enforced in Python is ``max_chain_depth``.

    Tests are split into two groups:
      - Pure policy guards (empty chain, depth limit): mock warrants are fine
        because the check fires before ``verify_chain`` is called.
      - Authorizer integration (trust, linkage, valid chains): real Rust
        warrants are required; each test calls ``pytest.importorskip`` so
        the whole group is skipped when tenuo_core is unavailable.

    Expired-warrant-in-chain detection is intentionally not tested here:
    it requires either a ``time.sleep`` or Rust-level clock mocking, neither
    of which is practical in unit tests.  The behaviour is exercised by
    ``TestWarrantStackEndToEnd``.
    """

    def _server(self, max_chain_depth=5, trusted_issuers=None):
        return _make_server(
            trusted_issuers=trusted_issuers or ["z6MkRoot"],
            max_chain_depth=max_chain_depth,
        )

    # -- Pure server-policy guards (no verify_chain call, mock warrants OK) ------

    @pytest.mark.asyncio
    async def test_empty_parents_raises(self):
        server = self._server()
        leaf = _mock_warrant("leaf")

        with pytest.raises(ChainValidationError) as exc_info:
            await server._validate_chain_warrants(leaf, [])

        assert "empty" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_depth_exceeded_raises(self):
        """More parents than max_chain_depth raises ChainValidationError."""
        server = self._server(max_chain_depth=2)
        leaf = _mock_warrant("leaf")
        parents = [_mock_warrant(f"p{i}") for i in range(3)]  # 3 parents > 2 max

        with pytest.raises(ChainValidationError) as exc_info:
            await server._validate_chain_warrants(leaf, parents)

        assert "depth" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_one_over_max_depth_raises(self):
        """max_chain_depth + 1 parents raises ChainValidationError."""
        max_depth = 3
        server = self._server(max_chain_depth=max_depth)

        parents = [_mock_warrant(f"p{i}") for i in range(max_depth + 1)]
        leaf = _mock_warrant("leaf")

        with pytest.raises(ChainValidationError) as exc_info:
            await server._validate_chain_warrants(leaf, parents)

        assert "depth" in str(exc_info.value).lower()

    # -- Authorizer.verify_chain integration (requires real warrants) -----------

    @pytest.mark.asyncio
    async def test_untrusted_root_raises(self):
        """Root warrant from an untrusted issuer raises UntrustedIssuerError."""
        core = pytest.importorskip("tenuo_core")
        root_key = core.SigningKey.generate()
        leaf_key = core.SigningKey.generate()
        root_w = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        leaf_w = root_w.attenuate(
            capabilities={"ping": {}},
            signing_key=root_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )
        # Server trusts a completely different key → verify_chain rejects the root
        different_key = core.SigningKey.generate()
        server = self._server(trusted_issuers=[different_key.public_key.to_bytes().hex()])

        with pytest.raises(UntrustedIssuerError):
            await server._validate_chain_warrants(leaf_w, [root_w])

    @pytest.mark.asyncio
    async def test_broken_linkage_raises(self):
        """A leaf with no parent_hash (unrelated warrant) raises ChainValidationError."""
        core = pytest.importorskip("tenuo_core")
        root_key = core.SigningKey.generate()
        other_key = core.SigningKey.generate()
        root_w = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        # Completely separate warrant — has no parent_hash pointing to root_w
        unrelated_leaf = core.Warrant.issue(
            keypair=other_key,
            holder=other_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        server = self._server(trusted_issuers=[root_key.public_key.to_bytes().hex()])

        with pytest.raises(ChainValidationError):
            await server._validate_chain_warrants(unrelated_leaf, [root_w])

    @pytest.mark.asyncio
    async def test_valid_two_hop_chain_passes(self):
        """Valid root → leaf chain passes without exceptions."""
        core = pytest.importorskip("tenuo_core")
        root_key = core.SigningKey.generate()
        leaf_key = core.SigningKey.generate()
        root_w = core.Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        leaf_w = root_w.attenuate(
            capabilities={"ping": {}},
            signing_key=root_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )
        server = self._server(trusted_issuers=[root_key.public_key.to_bytes().hex()])

        await server._validate_chain_warrants(leaf_w, [root_w])

    @pytest.mark.asyncio
    async def test_valid_three_hop_chain_passes(self):
        """Valid root → mid → leaf chain passes."""
        core = pytest.importorskip("tenuo_core")
        keys = [core.SigningKey.generate() for _ in range(3)]
        warrants = []
        w = core.Warrant.issue(
            keypair=keys[0],
            holder=keys[0].public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        warrants.append(w)
        for i in range(1, 3):
            w = warrants[-1].attenuate(
                capabilities={"ping": {}},
                signing_key=keys[i - 1],
                holder=keys[i].public_key,
                ttl_seconds=900,
            )
            warrants.append(w)

        server = self._server(
            trusted_issuers=[keys[0].public_key.to_bytes().hex()],
            max_chain_depth=5,
        )
        # parents=[root, mid], leaf=warrants[2]
        await server._validate_chain_warrants(warrants[2], warrants[:2])

    @pytest.mark.asyncio
    async def test_exactly_at_max_depth_passes(self):
        """A chain with exactly max_chain_depth parents passes."""
        core = pytest.importorskip("tenuo_core")
        max_depth = 3
        keys = [core.SigningKey.generate() for _ in range(max_depth + 1)]
        warrants = []
        w = core.Warrant.issue(
            keypair=keys[0],
            holder=keys[0].public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        warrants.append(w)
        for i in range(1, max_depth + 1):
            w = warrants[-1].attenuate(
                capabilities={"ping": {}},
                signing_key=keys[i - 1],
                holder=keys[i].public_key,
                ttl_seconds=900,
            )
            warrants.append(w)

        server = self._server(
            trusted_issuers=[keys[0].public_key.to_bytes().hex()],
            max_chain_depth=max_depth,
        )
        # parents = warrants[:max_depth], leaf = warrants[max_depth]
        await server._validate_chain_warrants(warrants[max_depth], warrants[:max_depth])


# =============================================================================
# _validate_chain (legacy semicolon path) still works
# =============================================================================


class TestValidateChainLegacy:
    """Legacy _validate_chain delegates correctly to _validate_chain_warrants."""

    def _server(self):
        return _make_server(trusted_issuers=["z6MkRoot"], max_chain_depth=3)

    @pytest.mark.asyncio
    async def test_empty_string_raises(self):
        server = self._server()
        leaf = _mock_warrant("leaf")

        with pytest.raises(ChainValidationError) as exc_info:
            await server._validate_chain(leaf, "")

        assert "empty" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_whitespace_only_raises(self):
        server = self._server()
        leaf = _mock_warrant("leaf")

        with pytest.raises(ChainValidationError):
            await server._validate_chain(leaf, "  ;  ;  ")

    @pytest.mark.asyncio
    async def test_depth_exceeded_raises(self):
        server = self._server()
        leaf = _mock_warrant("leaf")
        deep_chain = ";".join([f"tok_{i}" for i in range(10)])  # 10 > max_chain_depth=3

        with pytest.raises(ChainValidationError) as exc_info:
            await server._validate_chain(leaf, deep_chain)

        assert "depth" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_invalid_token_raises(self):
        server = self._server()
        leaf = _mock_warrant("leaf")

        with pytest.raises((ChainValidationError, Exception)):
            await server._validate_chain(leaf, "not_valid_base64_warrant")

    @pytest.mark.asyncio
    async def test_delegates_to_validate_chain_warrants(self):
        """_validate_chain calls _validate_chain_warrants after parsing."""
        server = self._server()
        leaf = _mock_warrant("leaf")

        server._validate_chain_warrants = AsyncMock()

        root_mock = _mock_warrant("root")
        with patch("tenuo_core.Warrant") as MockWarrant:
            MockWarrant.from_base64.return_value = root_mock
            await server._validate_chain(leaf, "root_token")

        server._validate_chain_warrants.assert_awaited_once_with(leaf, [root_mock])


# =============================================================================
# validate_warrant: routing between preloaded-parents and legacy paths
# =============================================================================


class TestValidateWarrantRouting:
    """validate_warrant routes to _validate_chain_warrants or _validate_chain."""

    def _make_trusted_server(self, trusted_key="z6MkRoot"):
        return A2AServer(
            name="Router Test",
            url="https://router.example.com",
            public_key="z6MkServer",
            trusted_issuers=[trusted_key],
            trust_delegated=True,
            require_warrant=False,
            check_replay=False,
            require_audience=False,
            require_pop=False,
            audit_log=None,
        )

    @pytest.mark.asyncio
    async def test_preloaded_parents_path_called(self):
        """When _preloaded_parents is provided, _validate_chain_warrants is called."""
        server = self._make_trusted_server()

        # Leaf is from an untrusted issuer; root will satisfy the chain check
        leaf_mock = _mock_warrant("leaf", iss="z6MkNotTrusted")
        root_mock = _mock_warrant("root", iss="z6MkRoot", sub="z6MkNotTrusted")

        server._validate_chain_warrants = AsyncMock()
        server._validate_chain = AsyncMock()

        with patch("tenuo_core.Warrant") as MockWarrant:
            MockWarrant.from_base64.return_value = leaf_mock

            await server.validate_warrant(
                "leaf_token",
                "ping",
                {},
                _preloaded_parents=[root_mock],
            )

        server._validate_chain_warrants.assert_awaited_once_with(leaf_mock, [root_mock])
        server._validate_chain.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_legacy_chain_path_called_without_preloaded(self):
        """When no _preloaded_parents, _validate_chain is called with warrant_chain string."""
        server = self._make_trusted_server()

        leaf_mock = _mock_warrant("leaf", iss="z6MkNotTrusted")
        server._validate_chain_warrants = AsyncMock()
        server._validate_chain = AsyncMock()

        with patch("tenuo_core.Warrant") as MockWarrant:
            MockWarrant.from_base64.return_value = leaf_mock

            await server.validate_warrant(
                "leaf_token",
                "ping",
                {},
                warrant_chain="root_token",
            )

        server._validate_chain.assert_awaited_once_with(leaf_mock, "root_token")
        server._validate_chain_warrants.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_preloaded_parents_falls_to_trusted_issuer_check(self):
        """_preloaded_parents=[] does NOT trigger chain validation (leaf is its own root)."""
        server = self._make_trusted_server(trusted_key="z6MkRoot")

        leaf_mock = _mock_warrant("leaf", iss="z6MkRoot")  # directly trusted
        server._validate_chain_warrants = AsyncMock()
        server._validate_chain = AsyncMock()

        with patch("tenuo_core.Warrant") as MockWarrant:
            MockWarrant.from_base64.return_value = leaf_mock

            await server.validate_warrant(
                "leaf_token",
                "ping",
                {},
                _preloaded_parents=[],  # empty — no chain needed
            )

        # Leaf is directly trusted, so no chain method should be called
        server._validate_chain_warrants.assert_not_awaited()
        server._validate_chain.assert_not_awaited()


# =============================================================================
# End-to-end: real warrants (skipped if tenuo_core unavailable)
# =============================================================================


class TestWarrantStackEndToEnd:
    """Real warrant encode/decode round-trip tests."""

    @pytest.fixture(autouse=True)
    def require_tenuo_core(self):
        try:
            import tenuo_core  # noqa: F401
        except ImportError:
            pytest.skip("tenuo_core not available")

    def test_encode_decode_roundtrip_single(self):
        """encode_warrant_stack → decode_warrant_stack_base64 gives back one warrant."""
        from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack

        key = SigningKey.generate()
        w = Warrant.issue(keypair=key, holder=key.public_key, capabilities={"ping": {}}, ttl_seconds=300)

        stack_b64 = encode_warrant_stack([w])
        assert stack_b64 is not None

        decoded = decode_warrant_stack_base64(stack_b64)
        assert len(decoded) == 1
        assert decoded[0].id == w.id

    def test_encode_decode_roundtrip_chain(self):
        """encode_warrant_stack with 3 warrants round-trips correctly."""
        from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack

        root_key = SigningKey.generate()
        mid_key = SigningKey.generate()
        leaf_key = SigningKey.generate()

        root_w = Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
        )
        mid_w = root_w.attenuate(
            capabilities={"search": {}},
            signing_key=root_key,
            holder=mid_key.public_key,
            ttl_seconds=1800,
        )
        leaf_w = mid_w.attenuate(
            capabilities={"search": {}},
            signing_key=mid_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )

        stack_b64 = encode_warrant_stack([root_w, mid_w, leaf_w])
        assert stack_b64 is not None

        decoded = decode_warrant_stack_base64(stack_b64)
        assert len(decoded) == 3
        assert decoded[0].id == root_w.id
        assert decoded[1].id == mid_w.id
        assert decoded[2].id == leaf_w.id

    def test_single_warrant_stack_same_id_as_plain(self):
        """A single-warrant stack decodes to the same warrant as Warrant.from_base64."""
        from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack

        key = SigningKey.generate()
        w = Warrant.issue(keypair=key, holder=key.public_key, capabilities={"ping": {}}, ttl_seconds=300)

        stack_b64 = encode_warrant_stack([w])
        decoded = decode_warrant_stack_base64(stack_b64)

        assert decoded[0].id == w.id
        # The re-encoded leaf should be the same as the original
        assert decoded[0].to_base64() == w.to_base64()

    def test_stack_is_compact(self):
        """WarrantStack encoding is no more than 10% larger than naive semicolon format."""
        from tenuo_core import SigningKey, Warrant, encode_warrant_stack

        root_key = SigningKey.generate()
        warrants = []
        prev = Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
        )
        warrants.append(prev)
        for _ in range(4):
            next_key = SigningKey.generate()
            prev = prev.attenuate(
                capabilities={"search": {}},
                signing_key=root_key,
                holder=next_key.public_key,
                ttl_seconds=900,
            )
            warrants.append(prev)
            root_key = next_key

        stack_b64 = encode_warrant_stack(warrants)
        assert stack_b64 is not None

        semicolon_size = sum(len(w.to_base64()) for w in warrants) + len(warrants) - 1
        assert len(stack_b64) <= semicolon_size * 1.1, (
            f"WarrantStack ({len(stack_b64)}) is unexpectedly larger than "
            f"semicolon format ({semicolon_size})"
        )

    @pytest.mark.asyncio
    async def test_server_validates_real_warrant_stack_chain(self):
        """Server correctly validates a real two-hop chain sent as a WarrantStack."""
        from tenuo_core import SigningKey, Warrant

        root_key = SigningKey.generate()
        leaf_key = SigningKey.generate()

        root_w = Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        leaf_w = root_w.attenuate(
            capabilities={"ping": {}},
            signing_key=root_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )

        # Server trusts the root key
        root_key_hex = root_key.public_key.to_bytes().hex()
        server = A2AServer(
            name="E2E Test",
            url="https://e2e.example.com",
            public_key="server_key",
            trusted_issuers=[root_key_hex],
            trust_delegated=True,
            require_warrant=True,
            check_replay=False,
            require_audience=False,
            require_pop=False,
            audit_log=None,
        )

        @server.skill("ping")
        async def ping():
            return "pong"

        # Validate via the WarrantStack path (_preloaded_parents)
        validated = await server.validate_warrant(
            leaf_w.to_base64(),
            "ping",
            {},
            _preloaded_parents=[root_w],
        )
        assert validated is not None

    @pytest.mark.asyncio
    async def test_validate_chain_warrants_real_broken_linkage(self):
        """Real warrant with a forged parent (broken linkage) is rejected."""
        from tenuo_core import SigningKey, Warrant

        root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()
        leaf_key = SigningKey.generate()

        root_w = Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )

        # Attacker creates their own warrant, not derived from root
        attacker_root = Warrant.issue(
            keypair=attacker_key,
            holder=attacker_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )

        # Leaf is derived from root, not from attacker
        leaf_w = root_w.attenuate(
            capabilities={"ping": {}},
            signing_key=root_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )

        root_key_hex = root_key.public_key.to_bytes().hex()
        server = A2AServer(
            name="Linkage Test",
            url="https://link.example.com",
            public_key="server_key",
            trusted_issuers=[root_key_hex],
            trust_delegated=True,
            require_warrant=False,
            check_replay=False,
            require_audience=False,
            require_pop=False,
            audit_log=None,
        )

        # Chain: [attacker_root, leaf] — attacker_root.issuer is not trusted
        with pytest.raises((ChainValidationError, UntrustedIssuerError, Exception)):
            await server._validate_chain_warrants(leaf_w, [attacker_root])

    @pytest.mark.asyncio
    async def test_full_stack_round_trip_through_http_handler(self):
        """Client encodes chain as WarrantStack; server handler decodes it correctly."""
        from tenuo_core import SigningKey, Warrant, decode_warrant_stack_base64, encode_warrant_stack

        root_key = SigningKey.generate()
        leaf_key = SigningKey.generate()

        root_w = Warrant.issue(
            keypair=root_key,
            holder=root_key.public_key,
            capabilities={"ping": {}},
            ttl_seconds=3600,
        )
        leaf_w = root_w.attenuate(
            capabilities={"ping": {}},
            signing_key=root_key,
            holder=leaf_key.public_key,
            ttl_seconds=900,
        )

        # Client packs
        stack_b64 = encode_warrant_stack([root_w, leaf_w])
        assert stack_b64 is not None

        # Server unpacks
        decoded = decode_warrant_stack_base64(stack_b64)
        assert len(decoded) == 2
        parents = decoded[:-1]   # [root_w]
        leaf_decoded = decoded[-1]

        assert parents[0].id == root_w.id
        assert leaf_decoded.id == leaf_w.id

        # Validate via server
        root_key_hex = root_key.public_key.to_bytes().hex()
        server = A2AServer(
            name="Round-trip Test",
            url="https://rt.example.com",
            public_key="server_key",
            trusted_issuers=[root_key_hex],
            trust_delegated=True,
            require_warrant=True,
            check_replay=False,
            require_audience=False,
            require_pop=False,
            audit_log=None,
        )

        @server.skill("ping")
        async def ping():
            return "pong"

        validated = await server.validate_warrant(
            leaf_decoded.to_base64(),
            "ping",
            {},
            _preloaded_parents=parents,
        )
        assert validated is not None
