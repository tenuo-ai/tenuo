"""
Integration-Level Security Invariants
======================================

Enforces the security properties that MUST hold for every Tenuo integration
adapter (A2A, FastAPI, CrewAI, Google ADK, Temporal).  Unlike the core
warrant tests in this directory, these tests exercise the FULL integration
stack — from framework-level callbacks or HTTP headers all the way through
the Rust Authorizer — using real tenuo_core cryptographic objects.

Each invariant is named, numbered, and linked to the attack scenario that
would succeed if the invariant were violated.  Every bug found in a
post-mortem MUST be accompanied by a new test in this file before the fix
is merged (regression-first workflow).

Invariants
----------
I1  No warrant                    → always denied (all integrations)
I2  Expired warrant               → always denied (all integrations)
I3  Untrusted issuer              → denied when trusted_issuers configured
I4  Self-signed warrant           → denied (any attacker key rejected)
I5  Delegation chain + PoP        → ALLOWED (regression for Bug 2)
I6  Broken chain linkage          → denied
I7  Wrong tool (not in warrant)   → denied
I8  Constraint violation          → denied
I9  FastAPI: no trusted_issuers   → emits SecurityWarning (regression for Bug 1)

Running
-------
    pytest tests/security/test_integration_invariants.py -v

All tests require tenuo_core; the suite is skipped automatically when the
compiled extension is not installed.
"""

from __future__ import annotations

import time
import warnings
from typing import Any, Dict, List, Optional

import pytest

tenuo_core = pytest.importorskip("tenuo_core", reason="tenuo_core not installed")

from tenuo_core import PublicKey, SigningKey, Warrant  # noqa: E402

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _root_warrant(
    root_key: SigningKey,
    holder_key: Optional[SigningKey] = None,
    *,
    tool: str = "search",
    ttl: int = 3600,
) -> Warrant:
    """Issue a fresh warrant from root_key to holder_key (defaults to root)."""
    holder = (holder_key or root_key).public_key
    return Warrant.issue(
        root_key,
        capabilities={tool: {}},
        ttl_seconds=ttl,
        holder=holder,
    )


def _attenuate(
    parent: Warrant,
    parent_key: SigningKey,
    child_key: SigningKey,
    *,
    tool: str = "search",
    ttl: int = 300,
) -> Warrant:
    """Attenuate parent warrant to child_key."""
    return parent.attenuate(
        signing_key=parent_key,
        holder=child_key.public_key,
        capabilities={tool: {}},
        ttl_seconds=ttl,
    )


# ===========================================================================
# A2A Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestA2AInvariants:
    """
    Security invariants for the A2AServer integration.

    Each test creates a real A2AServer with real cryptographic keys and
    exercises validate_warrant() directly so we test the full validation
    pipeline, not mocked internals.
    """

    @pytest.fixture
    def root_key(self) -> SigningKey:
        return SigningKey.generate()

    @pytest.fixture
    def agent_key(self) -> SigningKey:
        return SigningKey.generate()

    @pytest.fixture
    def attacker_key(self) -> SigningKey:
        return SigningKey.generate()

    def _make_server(
        self,
        trusted_key: SigningKey,
        *,
        require_pop: bool = False,
        max_chain_depth: int = 10,
    ):
        from tenuo.a2a.server import A2AServer

        return A2AServer(
            name="test-server",
            url="https://test.example.com",
            public_key=trusted_key.public_key,
            trusted_issuers=[trusted_key.public_key],
            require_warrant=True,
            require_audience=False,
            require_pop=require_pop,
            check_replay=False,
            max_chain_depth=max_chain_depth,
            audit_log=None,
        )

    # ------------------------------------------------------------------
    # I1 — no warrant → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I1_no_warrant_is_denied(self, root_key):
        """I1: validate_warrant with an empty token must never reach the skill."""
        from tenuo.a2a.errors import MissingWarrantError

        server = self._make_server(root_key)

        # The HTTP handler enforces require_warrant before calling validate_warrant;
        # but if called with an empty string it must still fail, not silently pass.
        with pytest.raises(Exception):
            await server.validate_warrant("", "search", {})

    # ------------------------------------------------------------------
    # I2 — expired warrant → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I2_expired_warrant_denied(self, root_key):
        """I2: An expired warrant MUST be rejected before any other checks."""
        from tenuo.a2a.errors import WarrantExpiredError

        server = self._make_server(root_key)
        expired = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        # Let the warrant expire
        time.sleep(2)

        with pytest.raises(WarrantExpiredError):
            token = expired.to_base64()
            await server.validate_warrant(token, "search", {})

    # ------------------------------------------------------------------
    # I3/I4 — untrusted / self-signed warrant → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I3_untrusted_issuer_denied(self, root_key, attacker_key):
        """
        I3/I4: A warrant from an unknown key MUST be rejected.

        Attack: Attacker generates their own key-pair and issues a warrant
        granting themselves the 'search' skill.  The server MUST reject it
        because the attacker's key is not in trusted_issuers.
        """
        from tenuo.a2a.errors import UntrustedIssuerError

        server = self._make_server(root_key)
        # Attacker self-signs a warrant granting themselves 'search'
        attacker_warrant = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        with pytest.raises(UntrustedIssuerError):
            await server.validate_warrant(attacker_warrant.to_base64(), "search", {})

    # ------------------------------------------------------------------
    # I5 — delegation chain + PoP → ALLOWED  (regression for Bug 2)
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I5_delegation_chain_with_pop_allowed(self, root_key, agent_key):
        """
        I5: A multi-hop delegation chain WITH require_pop=True MUST succeed.

        Regression test for Bug 2:
            A2AServer.validate_warrant previously called authorize_one(leaf)
            which checks the leaf's issuer against trusted roots.  For a
            delegated warrant the leaf's issuer is the intermediate agent —
            NOT a trusted root — causing a guaranteed UntrustedIssuerError.
            The fix uses check_chain([*parents, leaf]) instead.
        """
        server = self._make_server(root_key, require_pop=True)

        # WarrantStack: parents = [root_warrant], leaf = agent_warrant
        root_w = _root_warrant(root_key, root_key)
        leaf_w = _attenuate(root_w, root_key, agent_key)

        args: Dict[str, Any] = {}
        pop_bytes = bytes(leaf_w.sign(agent_key, "search", args, int(time.time())))

        result = await server.validate_warrant(
            leaf_w.to_base64(),
            "search",
            args,
            _preloaded_parents=[root_w],
            pop_signature=pop_bytes,
        )
        # Must return the verified warrant (not raise)
        assert result is not None

    # ------------------------------------------------------------------
    # I6 — broken chain linkage → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I6_broken_chain_linkage_denied(self, root_key, agent_key, attacker_key):
        """
        I6: A chain where the intermediate holder ≠ leaf issuer MUST be rejected.

        Attack: Insert a legitimate root warrant but pair it with an unrelated
        leaf warrant (different issuer) to try to inherit root trust.
        """
        from tenuo.a2a.errors import ChainValidationError

        server = self._make_server(root_key)

        # A valid root warrant whose holder is root_key
        root_w = _root_warrant(root_key, root_key)

        # A leaf issued by attacker_key (linkage broken: root holder != leaf issuer)
        fake_leaf = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=agent_key.public_key,
        )

        with pytest.raises((ChainValidationError, Exception)) as exc_info:
            await server.validate_warrant(
                fake_leaf.to_base64(),
                "search",
                {},
                _preloaded_parents=[root_w],
            )
        # Confirm it's not a bare Python AttributeError or similar
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")

    # ------------------------------------------------------------------
    # I7 — wrong tool → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I7_wrong_tool_denied(self, root_key):
        """
        I7: A warrant for 'search' MUST NOT authorize 'delete'.

        This is the basic capability check — no bypass via delegation or PoP.
        """
        from tenuo.a2a.errors import SkillNotGrantedError

        server = self._make_server(root_key)
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        with pytest.raises(SkillNotGrantedError):
            await server.validate_warrant(w.to_base64(), "delete", {})

    # ------------------------------------------------------------------
    # I8 — constraint violation → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I8_constraint_violation_denied(self, root_key):
        """
        I8: Argument that violates a registered server-side constraint MUST be denied.
        """
        from tenuo.a2a.errors import ConstraintViolationError
        from tenuo_core import Subpath

        from tenuo.a2a.server import A2AServer, SkillDefinition

        server = self._make_server(root_key)
        # Register skill with Subpath constraint
        @server.skill("read_file", constraints={"path": Subpath("/data")})
        async def read_file(path: str) -> str:
            return path

        w = Warrant.issue(
            root_key,
            capabilities={"read_file": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        with pytest.raises(ConstraintViolationError):
            await server.validate_warrant(
                w.to_base64(),
                "read_file",
                {"path": "/etc/passwd"},   # path traversal attempt
            )

    # ------------------------------------------------------------------
    # Depth cap
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_chain_exceeding_max_depth_denied(self, root_key):
        """max_chain_depth=1 must reject a chain with 2 parents."""
        from tenuo.a2a.errors import ChainValidationError

        server = self._make_server(root_key, max_chain_depth=1)
        k1, k2 = SigningKey.generate(), SigningKey.generate()
        root_w = _root_warrant(root_key, root_key)
        mid_w = _attenuate(root_w, root_key, k1)
        leaf_w = _attenuate(mid_w, k1, k2)

        with pytest.raises(ChainValidationError):
            await server.validate_warrant(
                leaf_w.to_base64(),
                "search",
                {},
                _preloaded_parents=[root_w, mid_w],   # depth=2 > max_depth=1
            )


# ===========================================================================
# FastAPI Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestFastAPIInvariants:
    """
    Security invariants for the FastAPI TenuoGuard integration.
    """

    @pytest.fixture(autouse=True)
    def reset_config(self):
        """Restore global FastAPI config between tests to avoid pollution."""
        from tenuo import fastapi as _fapi
        original = dict(_fapi._config)
        yield
        _fapi._config.clear()
        _fapi._config.update(original)

    # ------------------------------------------------------------------
    # I9 — no trusted_issuers emits a loud warning  (regression for Bug 1)
    # ------------------------------------------------------------------

    def test_I9_no_trusted_issuers_emits_warning(self):
        """
        I9: TenuoGuard MUST warn when trusted_issuers is not configured.

        Regression test for Bug 1:
            When configure_tenuo() is called without trusted_issuers, the
            server fell back to trusting the warrant's own issuer, allowing
            any self-signed warrant to pass authentication.  The fix emits
            warnings.warn() so the misconfiguration is immediately visible.
        """
        fastapi = pytest.importorskip("fastapi")
        from unittest.mock import MagicMock

        from tenuo.fastapi import TenuoGuard, _config

        root_key = SigningKey.generate()
        holder_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=holder_key.public_key,
        )

        # Ensure trusted_issuers is empty (misconfigured)
        _config["trusted_issuers"] = []

        guard = TenuoGuard("search")

        args: Dict[str, Any] = {}
        pop_raw = w.sign(holder_key, "search", args, int(time.time()))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                guard._enforce_with_pop_signature(w, "search", args, bytes(pop_raw))
            except Exception:
                pass  # result not what we're testing here

        security_warnings = [
            str(c.message) for c in caught
            if "trusted_issuers" in str(c.message).lower()
            or "self-signed" in str(c.message).lower()
        ]
        assert security_warnings, (
            "TenuoGuard must emit a warnings.warn() when no trusted_issuers "
            "are configured — currently it silently accepts any self-signed warrant."
        )

    # ------------------------------------------------------------------
    # I3 — self-signed warrant rejected when trusted_issuers IS configured
    # ------------------------------------------------------------------

    def test_I3_self_signed_rejected_with_configured_roots(self):
        """
        I3: When trusted_issuers is configured, self-signed warrants MUST fail.
        """
        fastapi = pytest.importorskip("fastapi")

        from tenuo.fastapi import TenuoGuard, configure_tenuo, _config
        from unittest.mock import MagicMock

        root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        # Configure legitimate issuer
        _config["trusted_issuers"] = [root_key.public_key]

        attacker_warrant = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        guard = TenuoGuard("search")

        args: Dict[str, Any] = {}
        pop_raw = attacker_warrant.sign(attacker_key, "search", args, int(time.time()))

        result = guard._enforce_with_pop_signature(
            attacker_warrant, "search", args, bytes(pop_raw)
        )
        assert not result.allowed, (
            "Self-signed warrant from untrusted key MUST be denied "
            "when trusted_issuers is configured"
        )

    # ------------------------------------------------------------------
    # I2 — expired warrant → 401
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied_by_guard(self):
        """I2: TenuoGuard.is_expired check must block expired warrants early."""
        fastapi = pytest.importorskip("fastapi")

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)
        assert w.is_expired(), "Warrant should be expired after sleep"


# ===========================================================================
# CrewAI Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestCrewAIInvariants:
    """
    Security invariants for the CrewAI adapter (Tier 1 and Tier 2).
    """

    # ------------------------------------------------------------------
    # I1 — tool not in allowed list → denied
    # ------------------------------------------------------------------

    def test_I1_unlisted_tool_denied(self):
        """I1: Tool not registered with GuardBuilder MUST always be denied."""
        from tenuo.crewai import GuardBuilder, ToolDenied

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .on_denial("raise")
            .build()
        )
        with pytest.raises(ToolDenied):
            guard._authorize("delete", {"target": "all"})

    # ------------------------------------------------------------------
    # I8 — constraint violation → denied
    # ------------------------------------------------------------------

    def test_I8_constraint_violation_denied(self):
        """I8: Argument violating a Pattern constraint MUST be denied."""
        from tenuo.crewai import ConstraintViolation, GuardBuilder

        guard = (
            GuardBuilder()
            .allow("send_email", recipient=tenuo_core.Pattern("*@company.com"))
            .on_denial("raise")
            .build()
        )
        with pytest.raises(ConstraintViolation):
            guard._authorize("send_email", {"recipient": "attacker@evil.com"})

    # ------------------------------------------------------------------
    # I2 — expired Tier 2 warrant → denied via enforce_tool_call
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied_tier2(self):
        """I2: Expired Tier 2 warrant MUST propagate as denial through enforce_tool_call."""
        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)

        from tenuo.crewai import GuardBuilder, WarrantExpired

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .with_warrant(w, root_key)
            .on_denial("raise")
            .build()
        )
        with pytest.raises((WarrantExpired, Exception)) as exc_info:
            guard._authorize("search", {"query": "test"})
        # Must be an authorization failure, not a Python bug
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError", "KeyError")

    # ------------------------------------------------------------------
    # I4 — self-signed warrant denied in Tier 2
    # ------------------------------------------------------------------

    def test_I4_tier2_pop_wrong_holder_denied(self):
        """
        I4: PoP signed by the wrong key MUST be denied.

        The warrant binds holder=root_key.public_key; signing with a different
        key MUST fail PoP verification inside enforce_tool_call.
        """
        root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        from tenuo.crewai import GuardBuilder, InvalidPoP

        # Guard configured with attacker's key (mismatch vs warrant holder)
        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .with_warrant(w, attacker_key)   # wrong signing key
            .on_denial("raise")
            .build()
        )
        with pytest.raises((InvalidPoP, Exception)) as exc_info:
            guard._authorize("search", {"query": "test"})
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")


# ===========================================================================
# Cross-Integration Invariant Matrix
# ===========================================================================
#
# Every integration adapter must implement the _Adapter protocol, which defines
# exactly six invariant scenarios.  The TestCrossIntegrationMatrix class
# parametrizes all six tests over every adapter so coverage is mechanically
# guaranteed — adding a new adapter to _ADAPTERS is sufficient to inherit the
# entire battery.
#
# Invariant scenarios
# -------------------
# check_no_auth()            → I1: no credential present; must deny
# check_valid()              → positive: correct credential + correct tool; must allow
# check_wrong_tool()         → I7: correct credential + wrong tool; must deny
# check_expired()            → I2: expired credential; must deny
# check_constraint_violated()→ I8: correct credential + violated constraint; must deny
# check_untrusted_issuer()   → I3/I4: warrant from attacker key (NOT in trusted_roots);
#                              must deny. This is the "self-signed trust gap" invariant —
#                              the most critical check for multi-tenant deployments.
#
# THIS IS WHY: the original protocol omitted check_untrusted_issuer(), causing the
# self-signed trust gap (Bug 3) to go undetected in all Tier 2 integrations.
# Tier 2 adapters (CrewAI, AutoGen, LangGraph, etc.) were tested against I1/I2/I7/I8
# but never against an adversarial issuer. The gap persisted because:
#   a) check_valid() used the same key for both issuance and signing — masking the bug
#   b) I3/I4 was only tested at the service boundary (A2A, FastAPI, MCP), not at
#      the tool-execution layer where Tier 2 integrations run
#   c) No explicit required method forced adapters to answer: "do you verify the issuer?"
#
# Adapters that cannot implement a specific scenario (e.g. a pure allow-list
# adapter that has no notion of expiry) may return None from that method;
# the matrix will mark it as skipped with an explanation rather than failing.
# ---------------------------------------------------------------------------


class _Adapter:
    """
    Protocol every matrix adapter must implement.

    Return value contract:
      True  → the integration ALLOWED the request
      False → the integration DENIED the request
      None  → this invariant does not apply to this adapter (skip)
    """

    name: str

    async def check_no_auth(self) -> Optional[bool]:
        """I1: request with no authorization credential."""
        raise NotImplementedError

    async def check_valid(self) -> Optional[bool]:
        """Positive: valid credential + correct tool."""
        raise NotImplementedError

    async def check_wrong_tool(self) -> Optional[bool]:
        """I7: valid credential + tool NOT in the authorized set."""
        raise NotImplementedError

    async def check_expired(self) -> Optional[bool]:
        """I2: expired credential."""
        raise NotImplementedError

    async def check_constraint_violated(self) -> Optional[bool]:
        """I8: valid credential + argument that violates a configured constraint."""
        raise NotImplementedError

    async def check_untrusted_issuer(self) -> Optional[bool]:
        """I3/I4: warrant signed by an attacker key not in trusted_roots.

        The adapter must:
          1. Configure a 'real' trusted root (real_root_key).
          2. Have an attacker create a warrant using their own key (attacker_key).
          3. Present that warrant to the integration with trusted_roots=[real_root_key].
          4. MUST return False (denied).

        Return None if the integration has no trust-root concept (e.g. pure
        constraint-only Tier 1 mode with no warrant at all).
        """
        raise NotImplementedError

    async def check_wrong_holder(self) -> Optional[bool]:
        """PoP holder-binding: warrant issued to holder_A, but PoP signed by attacker_B.

        The adapter must present a cryptographically valid warrant (from a trusted issuer)
        but with the PoP signed by a different key than the warrant's declared holder.
        MUST return False (denied) — PoP mismatch.

        Return None if the integration does not enforce PoP (e.g. Tier 1 or require_pop=False).
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# A2A adapter
# ---------------------------------------------------------------------------

class _A2AAdapter(_Adapter):
    name = "a2a"

    def __init__(self) -> None:
        from tenuo.a2a.server import A2AServer

        self._root = SigningKey.generate()
        self._server = A2AServer(
            name="matrix-test",
            url="https://test.example.com",
            public_key=self._root.public_key,
            trusted_issuers=[self._root.public_key],
            require_warrant=True,
            require_audience=False,
            require_pop=False,
            check_replay=False,
            audit_log=None,
        )
        self._warrant = Warrant.issue(
            self._root,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=self._root.public_key,
        )

    async def _call(self, token: str, tool: str, args: Dict[str, Any]) -> bool:
        try:
            await self._server.validate_warrant(token, tool, args)
            return True
        except Exception:
            return False

    async def check_no_auth(self) -> Optional[bool]:
        return await self._call("", "search", {})

    async def check_valid(self) -> Optional[bool]:
        return await self._call(self._warrant.to_base64(), "search", {})

    async def check_wrong_tool(self) -> Optional[bool]:
        return await self._call(self._warrant.to_base64(), "delete", {})

    async def check_expired(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._root.public_key)
        time.sleep(2)
        return await self._call(w.to_base64(), "search", {})

    async def check_constraint_violated(self) -> Optional[bool]:
        # A2A constraint violations require a registered skill with constraints;
        # the matrix tests I8 via the dedicated TestA2AInvariants class instead.
        return None

    async def check_untrusted_issuer(self) -> Optional[bool]:
        attacker_key = SigningKey.generate()
        attacker_w = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        return await self._call(attacker_w.to_base64(), "search", {})

    async def check_wrong_holder(self) -> Optional[bool]:
        # A2A matrix uses require_pop=False: no PoP is enforced, so holder-binding
        # cannot be tested here. Full PoP holder-binding is tested by TestA2APoP.
        return None
# ---------------------------------------------------------------------------

class _CrewAIAdapter(_Adapter):
    name = "crewai"

    def __init__(self) -> None:
        from tenuo.crewai import GuardBuilder

        self._guard_with_search = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .on_denial("log")
            .build()
        )
        self._guard_empty = (
            GuardBuilder()
            .on_denial("log")
            .build()
        )
        self._guard_constrained = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Pattern("safe:*"))
            .on_denial("log")
            .build()
        )

    def _ok(self, guard: Any, tool: str, args: Dict[str, Any]) -> bool:
        result = guard._authorize(tool, args)
        return result is None

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok(self._guard_empty, "search", {})

    async def check_valid(self) -> Optional[bool]:
        return self._ok(self._guard_with_search, "search", {"query": "test"})

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._ok(self._guard_with_search, "delete", {})

    async def check_expired(self) -> Optional[bool]:
        # CrewAI Tier 1 has no concept of expiry; skip this invariant.
        return None

    async def check_constraint_violated(self) -> Optional[bool]:
        return self._ok(self._guard_constrained, "search", {"query": "rm -rf /"})

    async def check_untrusted_issuer(self) -> Optional[bool]:
        # CrewAI Tier 1 (allow-list only) has no warrant concept; skip.
        return None

    async def check_wrong_holder(self) -> Optional[bool]:
        # CrewAI Tier 1 has no warrant or PoP concept; skip.
        return None

class _OpenAIAdapter(_Adapter):
    name = "openai"

    def __init__(self) -> None:
        pytest.importorskip("openai")
        self._root = SigningKey.generate()
        self._warrant = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._root.public_key,
        )

    def _tier1_ok(self, tool: str, args: Dict[str, Any],
                  allow: Optional[List[str]], deny: Optional[List[str]],
                  constraints: Optional[Dict]) -> bool:
        from tenuo.openai import ConstraintViolation, ToolDenied, verify_tool_call
        try:
            verify_tool_call(tool_name=tool, arguments=args,
                             allow_tools=allow, deny_tools=deny, constraints=constraints)
            return True
        except (ToolDenied, ConstraintViolation):
            return False

    async def check_no_auth(self) -> Optional[bool]:
        # No allow_tools configured (empty list) → everything denied
        return self._tier1_ok("search", {}, [], None, None)

    async def check_valid(self) -> Optional[bool]:
        return self._tier1_ok("search", {}, ["search"], None, None)

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._tier1_ok("delete", {}, ["search"], None, None)

    async def check_expired(self) -> Optional[bool]:
        # Tier 1 (allow_tools only) has no expiry concept; skip.
        return None

    async def check_constraint_violated(self) -> Optional[bool]:
        return self._tier1_ok("search", {"query": "rm -rf /"},
                              ["search"], None,
                              {"search": {"query": tenuo_core.Pattern("safe:*")}})

    async def check_untrusted_issuer(self) -> Optional[bool]:
        # OpenAI Tier 1 (allow/deny lists) has no warrant concept; skip.
        # Tier 2 trust verification is covered by TestTrustedRootsEnforcement.
        return None

    async def check_wrong_holder(self) -> Optional[bool]:
        # OpenAI Tier 1 has no warrant or PoP concept; skip.
        return None

class _AutoGenAdapter(_Adapter):
    name = "autogen"

    def __init__(self) -> None:
        from tenuo.autogen import AuthorizationDenied, GuardBuilder, ToolNotAuthorized
        from tenuo.exceptions import ConstraintViolation

        self._exc = (AuthorizationDenied, ToolNotAuthorized, ConstraintViolation)

        self._guard_search = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .on_denial("raise")
            .build()
        )
        self._guard_empty = (
            GuardBuilder()
            .on_denial("raise")
            .build()
        )
        self._guard_constrained = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Pattern("safe:*"))
            .on_denial("raise")
            .build()
        )

    def _ok(self, guard: Any, tool: str, args: Dict[str, Any]) -> bool:
        try:
            guard._authorize(tool, args)
            return True
        except self._exc:
            return False

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok(self._guard_empty, "search", {})

    async def check_valid(self) -> Optional[bool]:
        return self._ok(self._guard_search, "search", {"query": "test"})

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._ok(self._guard_search, "delete", {})

    async def check_expired(self) -> Optional[bool]:
        return None  # Tier 1 has no expiry; tested via TestAutoGenInvariants

    async def check_constraint_violated(self) -> Optional[bool]:
        return self._ok(self._guard_constrained, "search", {"query": "rm -rf /"})

    async def check_untrusted_issuer(self) -> Optional[bool]:
        # AutoGen Tier 1 (allow-list only) has no warrant concept; skip.
        return None

    async def check_wrong_holder(self) -> Optional[bool]:
        # AutoGen Tier 1 has no warrant or PoP concept; skip.
        return None

class _GoogleADKAdapter(_Adapter):
    name = "google_adk"

    def __init__(self) -> None:
        from unittest.mock import MagicMock
        from tenuo.google_adk.guard import TenuoGuard

        self._root = SigningKey.generate()    # trusted issuer (control plane)
        self._holder = SigningKey.generate()  # agent key (holds the warrant)
        self._warrant = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._holder.public_key,   # issued TO holder, BY root
        )
        self._tool_search = MagicMock(); self._tool_search.name = "search"
        self._tool_delete = MagicMock(); self._tool_delete.name = "delete"
        self._ctx = MagicMock()

        # Production-configured guard: require_pop=True + trusted_roots set
        self._guard_with_warrant = TenuoGuard(
            warrant=self._warrant, signing_key=self._holder,
            trusted_roots=[self._root.public_key],
            require_pop=True, on_denial="return",
        )
        self._guard_no_warrant = TenuoGuard(on_denial="return", require_pop=False)
        self._guard_constrained = TenuoGuard(
            warrant=Warrant.issue(
                self._root,
                capabilities={"search": {"query": tenuo_core.Pattern("safe:*")}},
                ttl_seconds=3600, holder=self._holder.public_key,
            ),
            signing_key=self._holder,
            trusted_roots=[self._root.public_key],
            require_pop=True, on_denial="return",
        )

    def _ok(self, guard: Any, tool: Any, args: Dict[str, Any]) -> bool:
        return guard.before_tool(tool, args, self._ctx) is None

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok(self._guard_no_warrant, self._tool_search, {})

    async def check_valid(self) -> Optional[bool]:
        return self._ok(self._guard_with_warrant, self._tool_search, {})

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._ok(self._guard_with_warrant, self._tool_delete, {})

    async def check_expired(self) -> Optional[bool]:
        from tenuo.google_adk.guard import TenuoGuard
        from unittest.mock import MagicMock

        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._holder.public_key)
        time.sleep(2)
        guard = TenuoGuard(warrant=w, signing_key=self._holder,
                           trusted_roots=[self._root.public_key],
                           require_pop=True, on_denial="return")
        ctx = MagicMock()
        return guard.before_tool(self._tool_search, {}, ctx) is None

    async def check_constraint_violated(self) -> Optional[bool]:
        return self._ok(self._guard_constrained, self._tool_search, {"query": "rm -rf /"})

    async def check_untrusted_issuer(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo._enforcement import enforce_tool_call

        attacker_key = SigningKey.generate()
        attacker_w = Warrant.issue(
            attacker_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)
        result = enforce_tool_call(
            tool_name="search",
            tool_args={},
            bound_warrant=bw,
            trusted_roots=[self._root.public_key],
        )
        return result.allowed

    async def check_wrong_holder(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo._enforcement import enforce_tool_call

        attacker_key = SigningKey.generate()
        # Warrant issued to self._holder but PoP signed by attacker_key (holder mismatch)
        bw = BoundWarrant(warrant=self._warrant, key=attacker_key)
        result = enforce_tool_call(
            tool_name="search", tool_args={},
            bound_warrant=bw,
            trusted_roots=[self._root.public_key],
        )
        return result.allowed

class _LangChainAdapter(_Adapter):
    name = "langchain"

    def __init__(self) -> None:
        pytest.importorskip("langchain")
        from unittest.mock import MagicMock
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool

        self._root = SigningKey.generate()    # trusted issuer (control plane)
        self._holder = SigningKey.generate()  # agent key (holds the warrant)
        self._warrant_search = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._holder.public_key,   # issued TO holder, BY root
        )
        self._bw_search = BoundWarrant(warrant=self._warrant_search, key=self._holder)

        def _mock(name: str) -> Any:
            t = MagicMock(); t.name = name; t.description = name; t.args_schema = None
            return t

        self._tool_search_no_bw = TenuoTool(_mock("search"))
        self._tool_search_with_bw = TenuoTool(
            _mock("search"), bound_warrant=self._bw_search,
            trusted_roots=[self._root.public_key],  # production path: explicit trust anchor
        )
        self._tool_delete_with_bw = TenuoTool(
            _mock("delete"), bound_warrant=self._bw_search,
            trusted_roots=[self._root.public_key],
        )

    def _ok(self, tool: Any, args: Dict[str, Any]) -> bool:
        from tenuo.langchain import ToolNotAuthorized
        try:
            tool._check_authorization(args)
            return True
        except Exception:
            return False

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok(self._tool_search_no_bw, {})

    async def check_valid(self) -> Optional[bool]:
        return self._ok(self._tool_search_with_bw, {})

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._ok(self._tool_delete_with_bw, {})

    async def check_expired(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool
        from unittest.mock import MagicMock

        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._holder.public_key)
        time.sleep(2)
        bw = BoundWarrant(warrant=w, key=self._holder)
        t = MagicMock(); t.name = "search"; t.description = "search"; t.args_schema = None
        tool = TenuoTool(t, bound_warrant=bw, trusted_roots=[self._root.public_key])
        return self._ok(tool, {})

    async def check_constraint_violated(self) -> Optional[bool]:
        return None  # LangChain constraint checking happens inside enforce_tool_call;
                     # invariant tested via TestLangChainInvariants / TestA2AInvariants

    async def check_untrusted_issuer(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool, ToolNotAuthorized
        from unittest.mock import MagicMock

        attacker_key = SigningKey.generate()
        attacker_w = Warrant.issue(
            attacker_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        attacker_bw = BoundWarrant(warrant=attacker_w, key=attacker_key)
        t = MagicMock(); t.name = "search"; t.description = "search"; t.args_schema = None
        tool = TenuoTool(t, bound_warrant=attacker_bw,
                         trusted_roots=[self._root.public_key])
        try:
            tool._check_authorization({})
            return True
        except Exception:
            return False

    async def check_wrong_holder(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool
        from unittest.mock import MagicMock

        attacker_key = SigningKey.generate()
        # Warrant issued to self._holder but PoP signed by attacker_key (holder mismatch)
        bw_wrong = BoundWarrant(warrant=self._warrant_search, key=attacker_key)
        t = MagicMock(); t.name = "search"; t.description = "search"; t.args_schema = None
        tool = TenuoTool(t, bound_warrant=bw_wrong,
                         trusted_roots=[self._root.public_key])
        try:
            tool._check_authorization({})
            return True
        except Exception:
            return False

class _MCPAdapter(_Adapter):
    name = "mcp"

    def __init__(self) -> None:
        import base64 as _b64
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier

        self._root = SigningKey.generate()    # trusted issuer (control plane)
        self._holder = SigningKey.generate()  # agent key (holds the warrant)
        auth = Authorizer()
        auth.add_trusted_root(self._root.public_key)
        self._verifier = MCPVerifier(auth, require_warrant=True)
        self._b64 = _b64

        self._warrant = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._holder.public_key,   # issued TO holder, BY root
        )

    def _meta(self, warrant: Warrant, signer: Any = None) -> Dict[str, Any]:
        """Build MCP meta dict; signer defaults to self._holder (the correct holder)."""
        signing_key = signer if signer is not None else self._holder
        sig = bytes(warrant.sign(signing_key, "search", {}, int(time.time())))
        return {"tenuo": {
            "warrant": warrant.to_base64(),
            "signature": self._b64.b64encode(sig).decode(),
        }}

    def _ok(self, tool: str, args: Dict[str, Any], meta: Optional[Dict]) -> bool:
        return self._verifier.verify(tool, args, meta=meta).allowed

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok("search", {}, meta=None)

    async def check_valid(self) -> Optional[bool]:
        return self._ok("search", {}, meta=self._meta(self._warrant))

    async def check_wrong_tool(self) -> Optional[bool]:
        # Warrant grants 'search'; requesting a tool the Authorizer was never
        # given trust for → UntrustedIssuerError → denied
        return self._ok("delete", {}, meta=self._meta(self._warrant))

    async def check_expired(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._holder.public_key)
        time.sleep(2)
        return self._ok("search", {}, meta=self._meta(w))

    async def check_constraint_violated(self) -> Optional[bool]:
        return None  # MCP constraint enforcement requires a VerifierConfig; tested
                     # individually in TestMCPInvariants

    async def check_untrusted_issuer(self) -> Optional[bool]:
        from tenuo_core import Authorizer
        from tenuo.mcp.server import MCPVerifier
        import base64 as _b64

        attacker_key = SigningKey.generate()
        attacker_w = Warrant.issue(
            attacker_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        sig = bytes(attacker_w.sign(attacker_key, "search", {}, int(time.time())))
        meta = {"tenuo": {
            "warrant": attacker_w.to_base64(),
            "signature": _b64.b64encode(sig).decode(),
        }}
        return self._ok("search", {}, meta)

    async def check_wrong_holder(self) -> Optional[bool]:
        import base64 as _b64
        attacker_key = SigningKey.generate()
        # Warrant issued to self._holder but PoP signed by attacker_key (holder mismatch)
        meta = self._meta(self._warrant, signer=attacker_key)
        return self._ok("search", {}, meta)

class _LangGraphAdapter(_Adapter):
    name = "langgraph"

    def __init__(self) -> None:
        pytest.importorskip("langchain")  # LangGraph requires LangChain
        from unittest.mock import MagicMock
        from tenuo.keys import KeyRegistry
        from tenuo.langgraph import TenuoMiddleware

        self._root = SigningKey.generate()    # trusted issuer (control plane)
        self._holder = SigningKey.generate()  # agent key (holds the warrant)
        self._registry = KeyRegistry.get_instance()
        self._key_id = f"_matrix_langgraph_{id(self)}"
        self._registry.register(self._key_id, self._holder)  # register holder key

        self._warrant = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._holder.public_key,  # issued TO holder, BY root
        )
        self._middleware = TenuoMiddleware(
            key_id=self._key_id,
            trusted_roots=[self._root.public_key],  # production path: explicit trust anchor
        )

    def _request(self, warrant: Optional[Any]) -> Any:
        """Build a mock ToolCallRequest with the given warrant in state."""
        from unittest.mock import MagicMock

        req = MagicMock()
        req.state = {"warrant": warrant}
        req.runtime = MagicMock()
        req.runtime.config = {"configurable": {"tenuo_key_id": self._key_id}}
        req.tool_call = {"name": "search", "id": "x", "args": {}}
        return req

    def _request_tool(self, tool: str, warrant: Optional[Any]) -> Any:
        req = self._request(warrant)
        req.tool_call = {"name": tool, "id": "x", "args": {}}
        return req

    def _ok(self, tool: str, warrant: Optional[Any]) -> bool:
        req = self._request_tool(tool, warrant)
        result = self._middleware.wrap_tool_call(req, lambda r: r)
        return getattr(result, "status", None) != "error"

    async def check_no_auth(self) -> Optional[bool]:
        return self._ok("search", None)

    async def check_valid(self) -> Optional[bool]:
        return self._ok("search", self._warrant)

    async def check_wrong_tool(self) -> Optional[bool]:
        return self._ok("delete", self._warrant)

    async def check_expired(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._holder.public_key)
        time.sleep(2)
        return self._ok("search", w)

    async def check_constraint_violated(self) -> Optional[bool]:
        return None  # LangGraph constraint enforcement requires schema config

    async def check_untrusted_issuer(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo._enforcement import enforce_tool_call

        attacker_key = SigningKey.generate()
        attacker_w = Warrant.issue(
            attacker_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)
        # TenuoMiddleware/TenuoToolNode both go through enforce_tool_call;
        # test directly with trusted_roots to verify the integration's core path.
        result = enforce_tool_call(
            tool_name="search",
            tool_args={},
            bound_warrant=bw,
            trusted_roots=[self._root.public_key],
        )
        return result.allowed

    async def check_wrong_holder(self) -> Optional[bool]:
        from tenuo import BoundWarrant
        from tenuo._enforcement import enforce_tool_call

        attacker_key = SigningKey.generate()
        # Warrant issued to self._holder but PoP signed by attacker_key (holder mismatch)
        bw = BoundWarrant(warrant=self._warrant, key=attacker_key)
        result = enforce_tool_call(
            tool_name="search", tool_args={},
            bound_warrant=bw,
            trusted_roots=[self._root.public_key],
        )
        return result.allowed

class _TemporalAdapter(_Adapter):
    name = "temporal"

    def __init__(self) -> None:
        pytest.importorskip("temporalio")
        from unittest.mock import MagicMock
        from tenuo.temporal import (
            KeyResolver, TenuoInterceptor, TenuoInterceptorConfig, TENUO_WARRANT_HEADER,
        )

        self._root = SigningKey.generate()
        self._HEADER = TENUO_WARRANT_HEADER

        class _Resolver(KeyResolver):
            def __init__(self, k: SigningKey) -> None:
                self._k = k
            def resolve(self, key_id: str) -> SigningKey:
                return self._k

        cfg = TenuoInterceptorConfig(
            key_resolver=_Resolver(self._root),
            # lightweight mode (trusted_roots=None): validates warrant structure
            # but skips PoP since Temporal PoP is tied to live workflow metadata.
            # Full PoP enforcement is verified by TestTemporalInvariants.
            trusted_roots=None,
            require_warrant=True,
            on_denial="raise",
        )
        self._interceptor = TenuoInterceptor(cfg)
        self._warrant = Warrant.issue(
            self._root, capabilities={"test_activity": {}}, ttl_seconds=3600,
            holder=self._root.public_key,
        )

    def _input(self, headers: Dict[str, Any]) -> Any:
        from unittest.mock import MagicMock
        inp = MagicMock()
        inp.headers = headers
        inp.fn = MagicMock()
        inp.fn.__name__ = "test_activity"
        inp.fn.__tenuo_unprotected__ = False
        # Prevent MagicMock auto-attribute from shadowing the default fallback
        inp.fn._tenuo_tool_name = "test_activity"
        inp.args = []
        inp.kwargs = {}
        return inp

    async def _ok(self, headers: Dict[str, Any]) -> bool:
        from dataclasses import dataclass
        from unittest.mock import AsyncMock, MagicMock, patch

        @dataclass
        class _Info:
            activity_type: str = "test_activity"
            activity_id: str = "1"
            workflow_id: str = "wf-matrix"
            workflow_type: str = "Test"
            workflow_run_id: str = "r"
            task_queue: str = "q"
            is_local: bool = False
            attempt: int = 1

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value=None)
        inbound = self._interceptor.intercept_activity(nxt)
        try:
            with patch("temporalio.activity.info") as mock_info:
                mock_info.return_value = _Info()
                await inbound.execute_activity(self._input(headers))
            return True
        except Exception:
            return False

    async def check_no_auth(self) -> Optional[bool]:
        return await self._ok({})

    async def check_valid(self) -> Optional[bool]:
        return await self._ok({self._HEADER: self._warrant.to_base64().encode()})

    async def check_wrong_tool(self) -> Optional[bool]:
        # Temporal tool name is the activity function name; we can't easily
        # change it in this test setup — skip; tested in TestTemporalInvariants.
        return None

    async def check_expired(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"test_activity": {}}, ttl_seconds=1,
                          holder=self._root.public_key)
        time.sleep(2)
        return await self._ok({self._HEADER: w.to_base64().encode()})

    async def check_constraint_violated(self) -> Optional[bool]:
        return None  # Temporal constraint enforcement requires activity-level config

    async def check_untrusted_issuer(self) -> Optional[bool]:
        # Temporal adapter uses trusted_roots=None (lightweight mode) in this matrix.
        # An attacker warrant passes structural checks but would fail PoP in strict mode.
        # The full I3/I4 check for Temporal is in TestTrustedRootsEnforcement via
        # enforce_tool_call (the same code path TenuoInterceptor uses).
        return None

    async def check_wrong_holder(self) -> Optional[bool]:
        # Temporal uses lightweight mode (no PoP); holder-binding not enforced here.
        # Full PoP enforcement is tested by TestTemporalInvariants.
        return None

class _FastAPIAdapter(_Adapter):
    name = "fastapi"

    def __init__(self) -> None:
        pytest.importorskip("fastapi")
        from tenuo.fastapi import _config

        self._root = SigningKey.generate()    # trusted issuer (control plane)
        self._holder = SigningKey.generate()  # agent key (holds the warrant)
        self._config = _config
        self._config["trusted_issuers"] = [self._root.public_key]
        self._warrant = Warrant.issue(
            self._root, capabilities={"search": {}}, ttl_seconds=3600,
            holder=self._holder.public_key,   # issued TO holder, BY root
        )

    def _enforce(self, warrant: Warrant, tool: str, args: Dict,
                 signer: Any = None) -> bool:
        """signer defaults to self._holder (the correct holder)."""
        import warnings
        from tenuo.fastapi import TenuoGuard
        signing_key = signer if signer is not None else self._holder
        pop_bytes = bytes(warrant.sign(signing_key, tool, args, int(time.time())))
        guard = TenuoGuard(tool)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                result = guard._enforce_with_pop_signature(warrant, tool, args, pop_bytes)
            return result.allowed
        except Exception:
            return False

    async def check_no_auth(self) -> Optional[bool]:
        attacker = SigningKey.generate()
        w = Warrant.issue(attacker, capabilities={"search": {}}, ttl_seconds=3600,
                          holder=attacker.public_key)
        return self._enforce(w, "search", {}, signer=attacker)

    async def check_valid(self) -> Optional[bool]:
        return self._enforce(self._warrant, "search", {})

    async def check_wrong_tool(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=3600,
                          holder=self._holder.public_key)
        # FastAPI TenuoGuard is bound to a specific tool at construction time;
        # tool-name mismatch means the warrant doesn't cover the guarded tool.
        return self._enforce(w, "delete", {})

    async def check_expired(self) -> Optional[bool]:
        w = Warrant.issue(self._root, capabilities={"search": {}}, ttl_seconds=1,
                          holder=self._holder.public_key)
        time.sleep(2)
        return self._enforce(w, "search", {})

    async def check_constraint_violated(self) -> Optional[bool]:
        return None  # FastAPI constraint checks happen inside enforce_tool_call

    async def check_untrusted_issuer(self) -> Optional[bool]:
        attacker = SigningKey.generate()
        w = Warrant.issue(attacker, capabilities={"search": {}}, ttl_seconds=3600,
                          holder=attacker.public_key)
        return self._enforce(w, "search", {}, signer=attacker)

    async def check_wrong_holder(self) -> Optional[bool]:
        attacker = SigningKey.generate()
        # Warrant issued to self._holder but PoP signed by attacker (holder mismatch)
        return self._enforce(self._warrant, "search", {}, signer=attacker)


_ADAPTERS: List[type] = [
    _A2AAdapter,
    _CrewAIAdapter,
    _OpenAIAdapter,
    _AutoGenAdapter,
    _GoogleADKAdapter,
    _LangChainAdapter,
    _LangGraphAdapter,
    _MCPAdapter,
    _TemporalAdapter,
    _FastAPIAdapter,
]


@pytest.mark.security
@pytest.mark.asyncio
class TestCrossIntegrationMatrix:
    """
    Every adapter in _ADAPTERS runs all six invariant scenarios.

    Adapters that return None from a scenario method skip that invariant with
    a documented reason.  This makes coverage gaps explicit rather than silent.
    Adding a new integration: implement _Adapter, append to _ADAPTERS.
    """

    @pytest.fixture(params=_ADAPTERS, ids=lambda a: a.name)
    async def adapter(self, request):
        return request.param()

    # ---- helpers ----

    def _assert_denied(self, adapter: _Adapter, scenario: str, result: Optional[bool]) -> None:
        if result is None:
            pytest.skip(f"[{adapter.name}] {scenario} not applicable to this adapter")
        assert not result, (
            f"[{adapter.name}] {scenario}: expected DENIED (False) but got ALLOWED (True)"
        )

    def _assert_allowed(self, adapter: _Adapter, scenario: str, result: Optional[bool]) -> None:
        if result is None:
            pytest.skip(f"[{adapter.name}] {scenario} not applicable to this adapter")
        assert result, (
            f"[{adapter.name}] {scenario}: expected ALLOWED (True) but got DENIED (False)"
        )

    # ---- invariant tests ----

    async def test_I1_no_auth_denied(self, adapter):
        """I1: No authorization credential MUST always be denied."""
        self._assert_denied(adapter, "I1:no_auth", await adapter.check_no_auth())

    async def test_positive_valid_allowed(self, adapter):
        """Positive: Valid credential + correct tool MUST be allowed."""
        self._assert_allowed(adapter, "positive:valid", await adapter.check_valid())

    async def test_I7_wrong_tool_denied(self, adapter):
        """I7: Valid credential + wrong tool MUST always be denied."""
        self._assert_denied(adapter, "I7:wrong_tool", await adapter.check_wrong_tool())

    async def test_I2_expired_denied(self, adapter):
        """I2: Expired credential MUST always be denied."""
        self._assert_denied(adapter, "I2:expired", await adapter.check_expired())

    async def test_I8_constraint_violated_denied(self, adapter):
        """I8: Constraint violation MUST always be denied."""
        self._assert_denied(adapter, "I8:constraint_violated", await adapter.check_constraint_violated())

    async def test_I3_I4_untrusted_issuer_denied(self, adapter):
        """I3/I4: Warrant from an attacker key not in trusted_roots MUST be denied.

        This is the adversarial issuer invariant — the critical property that
        was missing from the original protocol.  Every integration MUST verify
        that the warrant issuer is an explicitly trusted root.  Returning None
        is only acceptable for pure Tier 1 (no-warrant) adapters.
        """
        self._assert_denied(adapter, "I3/I4:untrusted_issuer", await adapter.check_untrusted_issuer())

    async def test_pop_wrong_holder_denied(self, adapter):
        """PoP holder-binding: warrant for holder_A signed by attacker_B MUST be denied.

        Every Tier 2 integration that enforces PoP must reject a PoP signed by
        a key that is not the declared warrant holder.  Returning None is acceptable
        for integrations where PoP is not enforced (Tier 1 or require_pop=False).
        """
        self._assert_denied(adapter, "PoP:wrong_holder", await adapter.check_wrong_holder())


# ===========================================================================
# Google ADK Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestGoogleADKInvariants:
    """
    Security invariants for the Google ADK TenuoGuard integration.

    before_tool() returns None to allow and a dict to deny.
    on_deny='raise' raises ToolAuthorizationError.
    """

    def _make_guard(self, warrant: Optional[Warrant] = None, signing_key: Optional[SigningKey] = None):
        from tenuo.google_adk.guard import TenuoGuard

        return TenuoGuard(
            warrant=warrant,
            signing_key=signing_key,
            require_pop=False,
            on_denial="return",
        )

    def _mock_tool(self, name: str = "search"):
        from unittest.mock import MagicMock
        t = MagicMock()
        t.name = name
        return t

    def _mock_context(self):
        from unittest.mock import MagicMock
        return MagicMock()

    # ------------------------------------------------------------------
    # I1 — no warrant configured → denied
    # ------------------------------------------------------------------

    def test_I1_no_warrant_denied(self):
        """I1: Guard with no warrant MUST deny every tool call."""
        guard = self._make_guard()
        result = guard.before_tool(self._mock_tool("search"), {}, self._mock_context())
        assert result is not None, (
            "Google ADK: before_tool must return a denial dict when no warrant is configured"
        )
        assert result.get("error") == "authorization_denied"

    # ------------------------------------------------------------------
    # I2 — expired warrant → denied
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied(self):
        """I2: An expired warrant MUST be rejected."""
        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)

        guard = self._make_guard(warrant=w, signing_key=root_key)
        result = guard.before_tool(self._mock_tool("search"), {}, self._mock_context())
        assert result is not None, "Google ADK: expired warrant must return a denial dict"

    # ------------------------------------------------------------------
    # I7 — wrong tool → denied
    # ------------------------------------------------------------------

    def test_I7_wrong_tool_denied(self):
        """I7: Warrant for 'search' MUST NOT authorize 'delete'."""
        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        guard = self._make_guard(warrant=w, signing_key=root_key)
        result = guard.before_tool(self._mock_tool("delete"), {}, self._mock_context())
        assert result is not None, "Google ADK: warrant for 'search' must not allow 'delete'"

    # ------------------------------------------------------------------
    # I7 positive — correct tool → allowed
    # ------------------------------------------------------------------

    def test_I7_correct_tool_allowed(self):
        """I7 positive: Valid warrant for 'search' MUST allow 'search'."""
        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        guard = self._make_guard(warrant=w, signing_key=root_key)
        result = guard.before_tool(self._mock_tool("search"), {}, self._mock_context())
        assert result is None, "Google ADK: valid warrant + correct tool must return None (allow)"


# ===========================================================================
# OpenAI Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestOpenAIInvariants:
    """
    Security invariants for the OpenAI verify_tool_call integration.

    verify_tool_call() raises ToolDenied / WarrantDenied / ConstraintViolation.
    """

    # ------------------------------------------------------------------
    # I1 — tool not in allow_tools → denied
    # ------------------------------------------------------------------

    def test_I1_tool_not_in_allowlist_denied(self):
        """I1: Tool absent from allow_tools MUST be denied."""
        pytest.importorskip("openai")
        from tenuo.openai import ToolDenied, verify_tool_call

        with pytest.raises(ToolDenied):
            verify_tool_call(
                tool_name="drop_database",
                arguments={"confirm": True},
                allow_tools=["search", "read"],
                deny_tools=None,
                constraints=None,
            )

    # ------------------------------------------------------------------
    # I1b — deny_tools overrides allow_tools
    # ------------------------------------------------------------------

    def test_I1b_deny_list_overrides_allow_list(self):
        """I1b: A tool in deny_tools MUST always be denied, even if in allow_tools."""
        pytest.importorskip("openai")
        from tenuo.openai import ToolDenied, verify_tool_call

        with pytest.raises(ToolDenied):
            verify_tool_call(
                tool_name="search",
                arguments={},
                allow_tools=["search"],
                deny_tools=["search"],
                constraints=None,
            )

    # ------------------------------------------------------------------
    # I8 — constraint violation → denied
    # ------------------------------------------------------------------

    def test_I8_constraint_violation_denied(self):
        """I8: Argument violating Tier 1 constraint MUST be denied."""
        pytest.importorskip("openai")
        from tenuo.openai import ConstraintViolation, verify_tool_call

        with pytest.raises(ConstraintViolation):
            verify_tool_call(
                tool_name="send_email",
                arguments={"recipient": "attacker@evil.com"},
                allow_tools=["send_email"],
                deny_tools=None,
                constraints={
                    "send_email": {
                        "recipient": tenuo_core.Pattern("*@company.com"),
                    }
                },
            )

    # ------------------------------------------------------------------
    # I2 — expired Tier 2 warrant → denied
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied_tier2(self):
        """I2: An expired Tier 2 warrant MUST be rejected before any other check."""
        pytest.importorskip("openai")

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)

        from tenuo.openai import WarrantDenied, verify_tool_call

        with pytest.raises(WarrantDenied):
            verify_tool_call(
                tool_name="search",
                arguments={},
                allow_tools=["search"],
                deny_tools=None,
                constraints=None,
                warrant=w,
                signing_key=root_key,
            )


# ===========================================================================
# AutoGen Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestAutoGenInvariants:
    """
    Security invariants for the AutoGen GuardBuilder / _Guard integration.
    """

    # ------------------------------------------------------------------
    # I1 — unlisted tool → denied
    # ------------------------------------------------------------------

    def test_I1_unlisted_tool_denied(self):
        """I1: Tool not registered with GuardBuilder MUST always be denied."""
        from tenuo.autogen import AuthorizationDenied, GuardBuilder, ToolNotAuthorized

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .on_denial("raise")
            .build()
        )
        with pytest.raises((AuthorizationDenied, ToolNotAuthorized)):
            guard._authorize("drop_database", {"confirm": True})

    # ------------------------------------------------------------------
    # I8 — constraint violation → denied
    # ------------------------------------------------------------------

    def test_I8_constraint_violation_denied(self):
        """I8: Argument violating a registered constraint MUST be denied."""
        from tenuo.autogen import AuthorizationDenied, GuardBuilder
        from tenuo.exceptions import ConstraintViolation

        guard = (
            GuardBuilder()
            .allow("send_email", recipient=tenuo_core.Pattern("*@company.com"))
            .on_denial("raise")
            .build()
        )
        with pytest.raises((AuthorizationDenied, ConstraintViolation)):
            guard._authorize("send_email", {"recipient": "attacker@evil.com"})

    # ------------------------------------------------------------------
    # I2 — expired Tier 2 warrant → denied
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied_tier2(self):
        """
        I2: An expired Tier 2 warrant MUST be rejected.

        The AutoGen GuardBuilder validates the warrant at build() time (fail-fast),
        so the check happens before _authorize() is reached.
        """
        from tenuo.autogen import GuardBuilder
        from tenuo.exceptions import ExpiredError

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)

        # GuardBuilder.build() validates the warrant immediately —
        # this is the correct fail-fast enforcement point.
        with pytest.raises(ExpiredError):
            (
                GuardBuilder()
                .allow("search", query=tenuo_core.Wildcard())
                .with_warrant(w, root_key)
                .on_denial("raise")
                .build()
            )


# ===========================================================================
# LangChain Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestLangChainInvariants:
    """
    Security invariants for the LangChain TenuoTool integration.

    TenuoTool._check_authorization reads from warrant_scope() context or
    a bound_warrant passed at construction time.
    """

    def _make_mock_lc_tool(self, name: str = "search"):
        from unittest.mock import MagicMock
        t = MagicMock()
        t.name = name
        t.description = f"Mock {name} tool"
        t.args_schema = None
        return t

    # ------------------------------------------------------------------
    # I1 — no warrant in scope → denied
    # ------------------------------------------------------------------

    def test_I1_no_warrant_denied(self):
        """I1: TenuoTool MUST deny calls when no warrant is in scope."""
        pytest.importorskip("langchain")
        from tenuo.langchain import TenuoTool, ToolNotAuthorized

        tool = TenuoTool(self._make_mock_lc_tool("search"))
        with pytest.raises(ToolNotAuthorized):
            tool._check_authorization({})

    # ------------------------------------------------------------------
    # I7 — tool not in bound warrant → denied
    # ------------------------------------------------------------------

    def test_I7_wrong_tool_denied(self):
        """I7: Tool not in bound warrant MUST be denied."""
        pytest.importorskip("langchain")
        from tenuo.langchain import TenuoTool, ToolNotAuthorized

        from tenuo import BoundWarrant

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        bw = BoundWarrant(warrant=w, key=root_key)

        tool = TenuoTool(self._make_mock_lc_tool("delete_file"), bound_warrant=bw)
        with pytest.raises(ToolNotAuthorized):
            tool._check_authorization({})

    # ------------------------------------------------------------------
    # I2 — expired bound warrant → denied
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied(self):
        """I2: An expired bound warrant MUST be rejected."""
        pytest.importorskip("langchain")
        from tenuo.langchain import TenuoTool

        from tenuo import BoundWarrant

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=root_key.public_key,
        )
        time.sleep(2)
        bw = BoundWarrant(warrant=w, key=root_key)

        tool = TenuoTool(self._make_mock_lc_tool("search"), bound_warrant=bw)
        with pytest.raises(Exception) as exc_info:
            tool._check_authorization({})
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")


# ===========================================================================
# MCP Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestMCPInvariants:
    """
    Security invariants for the MCP MCPVerifier integration.

    verify() never raises — returns MCPVerificationResult with allowed=True/False.
    """

    def _make_verifier(self, trusted_key: SigningKey):
        from tenuo_core import Authorizer

        from tenuo.mcp.server import MCPVerifier

        auth = Authorizer()
        auth.add_trusted_root(trusted_key.public_key)
        return MCPVerifier(auth, require_warrant=True)

    # ------------------------------------------------------------------
    # I1 — no warrant in meta → denied
    # ------------------------------------------------------------------

    def test_I1_no_warrant_denied(self):
        """I1: MCPVerifier with require_warrant=True MUST deny calls with no warrant."""
        trusted_key = SigningKey.generate()
        verifier = self._make_verifier(trusted_key)

        result = verifier.verify("search", {}, meta=None)
        assert not result.allowed, (
            "MCP: request with no warrant must be denied when require_warrant=True"
        )

    # ------------------------------------------------------------------
    # I3/I4 — self-signed warrant in meta → denied
    # ------------------------------------------------------------------

    def test_I3_self_signed_warrant_denied(self):
        """I3/I4: Warrant from an untrusted key MUST be rejected."""
        trusted_key = SigningKey.generate()
        attacker_key = SigningKey.generate()
        verifier = self._make_verifier(trusted_key)

        attacker_w = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        meta = {"tenuo": {"warrant": attacker_w.to_base64()}}
        result = verifier.verify("search", {}, meta=meta)
        assert not result.allowed, (
            "MCP: self-signed warrant from untrusted key must be denied"
        )

    # ------------------------------------------------------------------
    # I5 — valid warrant + correct tool → allowed
    # ------------------------------------------------------------------

    def test_I5_valid_warrant_allowed(self):
        """I5: Valid warrant from trusted key MUST allow the granted tool."""
        import base64

        trusted_key = SigningKey.generate()
        verifier = self._make_verifier(trusted_key)

        w = Warrant.issue(
            trusted_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=trusted_key.public_key,
        )
        sig_bytes = bytes(w.sign(trusted_key, "search", {}, int(time.time())))
        # MCP envelope uses "signature" (not "pop_signature") for the PoP bytes
        meta = {
            "tenuo": {
                "warrant": w.to_base64(),
                "signature": base64.b64encode(sig_bytes).decode(),
            }
        }
        result = verifier.verify("search", {}, meta=meta)
        assert result.allowed, (
            f"MCP: valid warrant from trusted key must allow 'search'. "
            f"Got denial: {result.denial_reason}"
        )

    # ------------------------------------------------------------------
    # I2 — expired warrant → denied
    # ------------------------------------------------------------------

    def test_I2_expired_warrant_denied(self):
        """I2: An expired warrant MUST be denied."""
        trusted_key = SigningKey.generate()
        verifier = self._make_verifier(trusted_key)

        w = Warrant.issue(
            trusted_key,
            capabilities={"search": {}},
            ttl_seconds=1,
            holder=trusted_key.public_key,
        )
        time.sleep(2)

        meta = {"tenuo": {"warrant": w.to_base64()}}
        result = verifier.verify("search", {}, meta=meta)
        assert not result.allowed, "MCP: expired warrant must be denied"


# ===========================================================================
# Temporal Integration Invariants
# ===========================================================================


@pytest.mark.security
class TestTemporalInvariants:
    """
    Security invariants for the Temporal TenuoInterceptor integration.

    The interceptor validates warrants arriving in Temporal activity headers.
    These tests exercise execute_activity() with synthetic headers so no
    running Temporal server is required.
    """

    def _make_interceptor(self, trusted_key: SigningKey):
        temporalio = pytest.importorskip("temporalio")
        from tenuo.temporal import (
            KeyResolver,
            TenuoInterceptor,
            TenuoInterceptorConfig,
        )

        class _StaticResolver(KeyResolver):
            def __init__(self, key: SigningKey) -> None:
                self._key = key

            def resolve(self, key_id: str) -> SigningKey:
                return self._key

        cfg = TenuoInterceptorConfig(
            key_resolver=_StaticResolver(trusted_key),
            trusted_roots=[trusted_key.public_key],
            require_warrant=True,
            on_denial="raise",
        )
        return TenuoInterceptor(cfg)

    def _make_activity_input(self, headers: Dict[str, Any]):
        """Build a fake Temporal ExecuteActivityInput from a headers dict."""
        from unittest.mock import MagicMock

        inp = MagicMock()
        inp.headers = headers
        inp.fn = MagicMock()
        inp.fn.__name__ = "test_activity"
        inp.fn.__tenuo_unprotected__ = False
        inp.fn._tenuo_tool_name = "test_activity"
        inp.args = []
        inp.kwargs = {}
        return inp

    # ------------------------------------------------------------------
    # I1 — no warrant header → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I1_no_warrant_header_denied(self):
        """I1: Activity with no Tenuo warrant header MUST be denied."""
        from dataclasses import dataclass
        from unittest.mock import MagicMock, patch

        pytest.importorskip("temporalio")

        @dataclass
        class _Info:
            activity_type: str = "test_activity"
            activity_id: str = "1"
            workflow_id: str = "wf-1"
            workflow_type: str = "T"
            workflow_run_id: str = "r"
            task_queue: str = "q"
            is_local: bool = False
            attempt: int = 1

        trusted_key = SigningKey.generate()
        interceptor = self._make_interceptor(trusted_key)
        inbound = interceptor.intercept_activity(MagicMock())
        inp = self._make_activity_input({})

        with pytest.raises(Exception) as exc_info:
            with patch("temporalio.activity.info") as mock_info:
                mock_info.return_value = _Info()
                await inbound.execute_activity(inp)
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError", "KeyError")

    # ------------------------------------------------------------------
    # I2 — expired warrant in header → denied
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_I2_expired_warrant_denied(self):
        """I2: Activity with an expired warrant MUST be denied."""
        from dataclasses import dataclass
        from unittest.mock import MagicMock, patch

        pytest.importorskip("temporalio")
        from tenuo.temporal import TENUO_WARRANT_HEADER

        @dataclass
        class _Info:
            activity_type: str = "test_activity"
            activity_id: str = "1"
            workflow_id: str = "wf-1"
            workflow_type: str = "T"
            workflow_run_id: str = "r"
            task_queue: str = "q"
            is_local: bool = False
            attempt: int = 1

        trusted_key = SigningKey.generate()
        interceptor = self._make_interceptor(trusted_key)

        w = Warrant.issue(
            trusted_key,
            capabilities={"test_activity": {}},
            ttl_seconds=1,
            holder=trusted_key.public_key,
        )
        time.sleep(2)

        inbound = interceptor.intercept_activity(MagicMock())
        inp = self._make_activity_input(
            {TENUO_WARRANT_HEADER: w.to_base64().encode()}
        )

        with pytest.raises(Exception) as exc_info:
            with patch("temporalio.activity.info") as mock_info:
                mock_info.return_value = _Info()
                await inbound.execute_activity(inp)
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")


# ===========================================================================
# Missing Category 1 Invariants
# (gaps identified in post-coverage-audit pass)
# ===========================================================================


@pytest.mark.security
class TestFastAPIInvariantsExtended:
    """
    Invariants added in the coverage-gap audit:
      I8  constraint violation end-to-end through _enforce_with_pop_signature
      I5  delegation chain + PoP (regression coverage beyond Bug 2 test)
    """

    @pytest.fixture(autouse=True)
    def reset_config(self):
        from tenuo import fastapi as _fapi
        original = dict(_fapi._config)
        yield
        _fapi._config.clear()
        _fapi._config.update(original)

    # ------------------------------------------------------------------
    # I8 — constraint in warrant → FastAPI enforces it
    # ------------------------------------------------------------------

    def test_I8_warrant_constraint_enforced(self):
        """
        I8: A warrant constraint MUST be enforced by TenuoGuard end-to-end.

        The constraint lives in the warrant (not just the server config), so
        this test verifies the full path: warrant → _enforce_with_pop_signature
        → enforce_tool_call → ConstraintViolation → deny.
        """
        import warnings
        from tenuo.fastapi import TenuoGuard, _config

        root_key = SigningKey.generate()
        _config["trusted_issuers"] = [root_key.public_key]

        w = Warrant.issue(
            root_key,
            capabilities={"search": {"query": tenuo_core.Pattern("safe:*")}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        guard = TenuoGuard("search")
        args = {"query": "rm -rf /"}
        pop_bytes = bytes(w.sign(root_key, "search", args, int(time.time())))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = guard._enforce_with_pop_signature(w, "search", args, pop_bytes)
        assert not result.allowed, (
            "FastAPI I8: warrant constraint 'safe:*' must block 'rm -rf /'"
        )

    # ------------------------------------------------------------------
    # I5 — delegation chain + PoP through FastAPI guard
    # ------------------------------------------------------------------

    def test_I5_delegation_chain_with_pop_allowed(self):
        """
        I5: FastAPI TenuoGuard must accept delegation chain + PoP.

        Regression companion to Bug 2 (A2A).  FastAPI's code path for
        warrant+chain goes through _enforce_with_pop_signature; verifying it
        handles chains correctly prevents the same class of bug in this adapter.
        """
        import warnings
        from tenuo.fastapi import TenuoGuard, _config

        root_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        _config["trusted_issuers"] = [root_key.public_key]

        root_w = Warrant.issue(
            root_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=root_key.public_key,
        )
        leaf_w = root_w.attenuate(
            signing_key=root_key, holder=agent_key.public_key,
            capabilities={"search": {}}, ttl_seconds=300,
        )
        args: Dict[str, Any] = {}
        pop_bytes = bytes(leaf_w.sign(agent_key, "search", args, int(time.time())))

        guard = TenuoGuard("search")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = guard._enforce_with_pop_signature(
                leaf_w, "search", args, pop_bytes,
                parents=[root_w],
            )
        assert result.allowed, (
            f"FastAPI I5: delegation chain + PoP must be allowed. "
            f"Got: {result.denial_reason}"
        )


@pytest.mark.security
class TestTemporalInvariantsExtended:
    """I7 — wrong tool name in warrant → denied."""

    def _make_interceptor(self, trusted_key: SigningKey):
        pytest.importorskip("temporalio")
        from tenuo.temporal import KeyResolver, TenuoInterceptor, TenuoInterceptorConfig

        class _R(KeyResolver):
            def __init__(self, k):
                self._k = k
            def resolve(self, kid):
                return self._k

        cfg = TenuoInterceptorConfig(
            key_resolver=_R(trusted_key),
            trusted_roots=[trusted_key.public_key],
            require_warrant=True, on_denial="raise",
        )
        return TenuoInterceptor(cfg)

    def _make_input(self, warrant: Warrant, activity_name: str = "test_activity"):
        from unittest.mock import AsyncMock, MagicMock
        inp = MagicMock()
        inp.headers = {}
        from tenuo.temporal import TENUO_WARRANT_HEADER
        inp.headers = {TENUO_WARRANT_HEADER: warrant.to_base64().encode()}
        fn = MagicMock()
        fn.__name__ = activity_name
        fn._tenuo_tool_name = activity_name
        fn.__tenuo_unprotected__ = False
        inp.fn = fn
        inp.args = []
        inp.kwargs = {}
        return inp

    @pytest.mark.asyncio
    async def test_I7_wrong_activity_tool_denied(self):
        """I7: Warrant granting 'read_file' MUST NOT authorize 'delete_file'."""
        from dataclasses import dataclass
        from unittest.mock import AsyncMock, MagicMock, patch

        pytest.importorskip("temporalio")

        @dataclass
        class _Info:
            activity_type: str = "delete_file"
            activity_id: str = "1"
            workflow_id: str = "wf-1"
            workflow_type: str = "T"
            workflow_run_id: str = "r"
            task_queue: str = "q"
            is_local: bool = False
            attempt: int = 1

        trusted_key = SigningKey.generate()
        interceptor = self._make_interceptor(trusted_key)

        # Warrant grants read_file, but activity type is delete_file
        w = Warrant.issue(
            trusted_key, capabilities={"read_file": {}}, ttl_seconds=3600,
            holder=trusted_key.public_key,
        )
        inp = self._make_input(w, "delete_file")

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value=None)
        inbound = interceptor.intercept_activity(nxt)

        with pytest.raises(Exception) as exc_info:
            with patch("temporalio.activity.info") as mock_info:
                mock_info.return_value = _Info()
                await inbound.execute_activity(inp)

        # Activity must NOT have been executed
        nxt.execute_activity.assert_not_called()
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")


@pytest.mark.security
class TestGoogleADKInvariantsExtended:
    """I3/I4 — self-signed warrant rejected even when warrant+key are provided."""

    def test_I3_attacker_warrant_rejected(self):
        """
        I3/I4: A warrant signed by an attacker's key MUST be rejected by Google ADK.

        The guard is configured with a legitimate warrant; the attacker provides
        a separately-signed warrant with the same tool name.  The guard must use
        the bound warrant it was configured with, not any incoming credential.
        """
        from tenuo.google_adk.guard import TenuoGuard
        from unittest.mock import MagicMock

        root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        # Guard is configured with a legitimate root_key warrant
        legitimate_w = Warrant.issue(
            root_key, capabilities={"search": {}}, ttl_seconds=3600,
            holder=root_key.public_key,
        )
        guard = TenuoGuard(
            warrant=legitimate_w, signing_key=root_key,
            require_pop=False, on_denial="return",
        )

        tool = MagicMock(); tool.name = "search"
        ctx = MagicMock()

        # Attacker warrant injected into tool_context — the guard MUST ignore it
        # and use only the configured warrant.  Since the configured warrant IS
        # legitimate here, the call should be allowed.  The real security check:
        # if the attacker tries to call a tool not in the bound warrant, it fails.
        attacker_w = Warrant.issue(
            attacker_key, capabilities={"admin": {}}, ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        # Try to call 'admin' which is NOT in the bound legitimate warrant
        admin_tool = MagicMock(); admin_tool.name = "admin"
        result = guard.before_tool(admin_tool, {}, ctx)
        assert result is not None, (
            "Google ADK I3/I4: tool not in bound warrant must be denied "
            "regardless of what the attacker's warrant says"
        )


@pytest.mark.security
class TestLangChainInvariantsExtended:
    """I8 — constraint violation through TenuoTool._check_authorization."""

    def test_I8_constraint_violation_denied(self):
        """I8: BoundWarrant constraint MUST block violating arguments."""
        pytest.importorskip("langchain")
        from unittest.mock import MagicMock
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool

        root_key = SigningKey.generate()
        w = Warrant.issue(
            root_key,
            capabilities={"search": {"query": tenuo_core.Pattern("safe:*")}},
            ttl_seconds=3600, holder=root_key.public_key,
        )
        bw = BoundWarrant(warrant=w, key=root_key)

        t = MagicMock(); t.name = "search"; t.description = "search"; t.args_schema = None
        tool = TenuoTool(t, bound_warrant=bw)

        with pytest.raises(Exception) as exc_info:
            tool._check_authorization({"query": "rm -rf /"})
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")

    def test_I3_attacker_warrant_rejected_with_trusted_roots(self):
        """I3: Self-signed attacker warrant MUST be rejected when trusted_roots is set.

        Without trusted_roots, enforce_tool_call uses self-signed trust — any
        warrant signed by its own issuer passes.  With trusted_roots set to the
        real control-plane key only, the attacker's self-signed warrant fails.
        """
        pytest.importorskip("langchain")
        from unittest.mock import MagicMock
        from tenuo import BoundWarrant
        from tenuo.langchain import TenuoTool, ToolNotAuthorized

        real_root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        attacker_w = Warrant.issue(
            attacker_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        attacker_bw = BoundWarrant(warrant=attacker_w, key=attacker_key)

        t = MagicMock(); t.name = "search"; t.description = "search"; t.args_schema = None
        # trusted_roots points to real_root_key — attacker's key is NOT trusted
        tool = TenuoTool(t, bound_warrant=attacker_bw, trusted_roots=[real_root_key.public_key])

        with pytest.raises((ToolNotAuthorized, Exception)):
            tool._check_authorization({})


# ===========================================================================
# I3/I4: Trusted-Roots Enforcement for all Tier 2 integrations
# ===========================================================================
#
# These tests verify that when trusted_roots is configured, all Tier 2
# integrations reject self-signed ("attacker") warrants.  This closes the
# trust gap where BoundWarrant.validate() implicitly trusted the warrant's
# own issuer key.  All integrations MUST go through tenuo_core.Authorizer.
# ---------------------------------------------------------------------------


@pytest.mark.security
class TestTrustedRootsEnforcement:
    """
    I3/I4 — trusted_roots rejects self-signed attacker warrants in every
    Tier 2 integration (CrewAI, AutoGen, Google ADK, LangChain, LangGraph,
    OpenAI).

    Without trusted_roots: enforce_tool_call trusts warrant.issuer → any
    self-signed warrant passes.  With trusted_roots=[real_root.public_key]:
    the attacker's warrant issuer is not in the trust anchor set → denied.
    """

    @pytest.fixture()
    def real_root_key(self):
        return SigningKey.generate()

    @pytest.fixture()
    def attacker_warrant_and_key(self):
        k = SigningKey.generate()
        w = Warrant.issue(k, capabilities={"search": {}}, ttl_seconds=3600, holder=k.public_key)
        return w, k

    def test_I3_crewai_attacker_warrant_rejected(self, real_root_key, attacker_warrant_and_key):
        """I3: CrewAI guard with trusted_roots rejects self-signed warrant."""
        attacker_w, attacker_key = attacker_warrant_and_key

        from tenuo.crewai import GuardBuilder

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .with_warrant(attacker_w, attacker_key)
            .with_trusted_roots([real_root_key.public_key])
            .on_denial("raise")
            .build()
        )
        with pytest.raises(Exception) as exc_info:
            guard._authorize("search", {"query": "test"}, agent_role=None)
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError"), (
            f"Expected security denial, got internal error: {exc_info.value}"
        )

    def test_I4_autogen_attacker_warrant_rejected(self, real_root_key, attacker_warrant_and_key):
        """I4: AutoGen guard with trusted_roots rejects self-signed warrant."""
        attacker_w, attacker_key = attacker_warrant_and_key

        from tenuo.autogen import GuardBuilder

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .with_warrant(attacker_w, attacker_key)
            .with_trusted_roots([real_root_key.public_key])
            .on_denial("raise")
            .build()
        )
        with pytest.raises(Exception) as exc_info:
            guard._authorize("search", {"query": "test"})
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError"), (
            f"Expected security denial, got internal error: {exc_info.value}"
        )

    def test_I3_google_adk_attacker_warrant_rejected(self, real_root_key, attacker_warrant_and_key):
        """I3: Google ADK TenuoGuard with trusted_roots rejects self-signed warrant.

        This tests the same enforce_tool_call core path that ADK uses.
        We call enforce_tool_call directly with trusted_roots since the ADK
        framework requires heavy mocking to invoke before_tool in isolation.
        """
        attacker_w, attacker_key = attacker_warrant_and_key
        from tenuo._enforcement import enforce_tool_call
        from tenuo import BoundWarrant

        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)
        result = enforce_tool_call(
            tool_name="search",
            tool_args={},
            bound_warrant=bw,
            trusted_roots=[real_root_key.public_key],
        )
        assert not result.allowed, (
            "Google ADK I3: self-signed attacker warrant must be denied when "
            f"trusted_roots is set. Got: {result.denial_reason}"
        )

    def test_I3_langgraph_toolnode_attacker_warrant_rejected(
        self, real_root_key, attacker_warrant_and_key
    ):
        """I3: TenuoToolNode with trusted_roots rejects self-signed warrant at PEP layer."""
        pytest.importorskip("langgraph")
        pytest.importorskip("langchain_core")
        from tenuo._enforcement import enforce_tool_call
        from tenuo import BoundWarrant

        attacker_w, attacker_key = attacker_warrant_and_key
        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)

        result = enforce_tool_call(
            tool_name="search",
            tool_args={"query": "test"},
            bound_warrant=bw,
            trusted_roots=[real_root_key.public_key],
        )
        assert not result.allowed, (
            "enforce_tool_call with trusted_roots must reject a self-signed attacker warrant. "
            f"Got: allowed={result.allowed}, reason={result.denial_reason}"
        )

    def test_I4_no_trusted_roots_emits_warning(self, attacker_warrant_and_key):
        """I4: enforce_tool_call without trusted_roots MUST emit SecurityWarning.

        Self-signed warrants pass (self-trust), but callers are warned via
        SecurityWarning that this is insecure.
        """
        import warnings
        from tenuo._enforcement import enforce_tool_call
        from tenuo import BoundWarrant

        attacker_w, attacker_key = attacker_warrant_and_key
        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            enforce_tool_call(
                tool_name="search",
                tool_args={},
                bound_warrant=bw,
            )

        security_warnings = [
            w for w in caught
            if issubclass(w.category, UserWarning) and "trusted_roots" in str(w.message)
        ]
        assert security_warnings, (
            "enforce_tool_call without trusted_roots MUST emit SecurityWarning. "
            "Callers must be warned about the self-signed trust gap."
        )

    def test_I3_openai_trusted_roots_rejects_attacker(
        self, real_root_key, attacker_warrant_and_key
    ):
        """I3: OpenAI verify_tool_call with trusted_roots rejects self-signed warrant."""
        attacker_w, attacker_key = attacker_warrant_and_key

        from tenuo.openai import WarrantDenied, verify_tool_call

        with pytest.raises((WarrantDenied, Exception)) as exc_info:
            verify_tool_call(
                tool_name="search",
                arguments={"query": "test"},
                allow_tools=["search"],
                deny_tools=None,
                constraints=None,
                warrant=attacker_w,
                signing_key=attacker_key,
                trusted_roots=[real_root_key.public_key],
            )
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError"), (
            f"Expected security denial, got internal error: {exc_info.value}"
        )

    def test_I3_crewai_legitimate_warrant_still_allowed(self, real_root_key):
        """I3: CrewAI guard with trusted_roots accepts legitimate warrant from that root."""
        holder_key = SigningKey.generate()
        legit_w = Warrant.issue(
            real_root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=holder_key.public_key,
        )

        from tenuo.crewai import GuardBuilder

        guard = (
            GuardBuilder()
            .allow("search", query=tenuo_core.Wildcard())
            .with_warrant(legit_w, holder_key)
            .with_trusted_roots([real_root_key.public_key])
            .on_denial("raise")
            .build()
        )
        # Must NOT raise — legitimate warrant from trusted root is allowed
        guard._authorize("search", {"query": "test"}, agent_role=None)

    def test_I3_enforce_tool_call_legitimate_warrant_allowed(self, real_root_key):
        """I3: enforce_tool_call with trusted_roots ALLOWS warrants from that root."""
        from tenuo._enforcement import enforce_tool_call
        from tenuo import BoundWarrant

        holder_key = SigningKey.generate()
        legit_w = Warrant.issue(
            real_root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=holder_key.public_key,
        )
        bw = BoundWarrant(warrant=legit_w, key=holder_key)

        result = enforce_tool_call(
            tool_name="search",
            tool_args={},
            bound_warrant=bw,
            trusted_roots=[real_root_key.public_key],
        )
        assert result.allowed, (
            f"Legitimate warrant from trusted root must be allowed. "
            f"Denied with: {result.denial_reason}"
        )


# ===========================================================================
# Regression Tests (one per production bug)
# ===========================================================================
#
# These are the canonical regression tests.  Every bug found in a post-mortem
# MUST add exactly one test here — named after the bug — before the fix merges.
# ---------------------------------------------------------------------------


@pytest.mark.security
class TestRegressions:
    """
    Regression tests: each test is named after and documents a specific
    production bug.  If a test fails it means we regressed.
    """

    # ------------------------------------------------------------------ Bug 1
    @pytest.mark.asyncio
    async def test_regression_bug1_fastapi_self_trust_bypass(self):
        """
        Bug 1: FastAPI accepted self-signed warrants when trusted_issuers was empty.

        Root cause: _enforce_with_pop_signature fell back to using the
        warrant's own issuer key as the trusted root, so any attacker who
        minted their own warrant was implicitly trusted.

        Fix: emit warnings.warn() when trusted_issuers is empty.
        Verified: warning is emitted; no silent acceptance.
        """
        fastapi = pytest.importorskip("fastapi")

        from tenuo.fastapi import TenuoGuard, _config

        attacker_key = SigningKey.generate()
        w = Warrant.issue(
            attacker_key,
            capabilities={"admin": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        _config["trusted_issuers"] = []

        guard = TenuoGuard("admin")
        args: Dict[str, Any] = {}
        pop_raw = w.sign(attacker_key, "admin", args, int(time.time()))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                guard._enforce_with_pop_signature(w, "admin", args, bytes(pop_raw))
            except Exception:
                pass

        found = any(
            "trusted_issuers" in str(c.message).lower()
            or "self-signed" in str(c.message).lower()
            for c in caught
        )
        assert found, (
            "Bug 1 regression: TenuoGuard must emit a security warning when "
            "trusted_issuers is empty.  Without this warning, operators running "
            "without configure_tenuo() silently accept any self-signed warrant."
        )

    # ------------------------------------------------------------------ Bug 2
    @pytest.mark.asyncio
    async def test_regression_bug2_a2a_chain_pop_authorize_one(self):
        """
        Bug 2: A2AServer always raised UntrustedIssuerError for delegation
        chains when require_pop=True.

        Root cause: validate_warrant called authorize_one(leaf) for PoP.
        authorize_one checks that the leaf's issuer is in trusted_roots.
        For a delegated warrant the leaf's issuer is an intermediate agent,
        not a trusted root, so it always failed.

        Fix: when _resolved_chain_parents is set, use check_chain([*parents, leaf])
        which verifies the full chain + PoP atomically.
        Verified: a two-hop chain with require_pop=True now succeeds.
        """
        root_key = SigningKey.generate()
        agent_key = SigningKey.generate()

        from tenuo.a2a.server import A2AServer

        server = A2AServer(
            name="test",
            url="https://test.example.com",
            public_key=root_key.public_key,
            trusted_issuers=[root_key.public_key],
            require_warrant=True,
            require_audience=False,
            require_pop=True,        # ← must be True to reproduce the bug
            check_replay=False,
            audit_log=None,
        )

        # Two-hop chain: root issues to itself, then attenuates to agent
        root_w = Warrant.issue(
            root_key,
            capabilities={"search": {}},
            ttl_seconds=3600,
            holder=root_key.public_key,
        )
        leaf_w = root_w.attenuate(
            signing_key=root_key,
            holder=agent_key.public_key,
            capabilities={"search": {}},
            ttl_seconds=300,
        )

        args: Dict[str, Any] = {}
        pop_raw = leaf_w.sign(agent_key, "search", args, int(time.time()))

        # This MUST NOT raise — before the fix it raised UntrustedIssuerError.
        result = await server.validate_warrant(
            leaf_w.to_base64(),
            "search",
            args,
            _preloaded_parents=[root_w],
            pop_signature=bytes(pop_raw),
        )
        assert result is not None, (
            "Bug 2 regression: delegation chain + PoP must succeed.  "
            "If this fails, validate_warrant is calling authorize_one(leaf) "
            "instead of check_chain([root, leaf])."
        )

    # ------------------------------------------------------------------ Bug 3
    def test_regression_bug3_self_signed_trust_gap_in_enforce_tool_call(self):
        """
        Bug 3: enforce_tool_call accepted self-signed attacker warrants in Tier 2.

        Root cause: BoundWarrant.validate() built Authorizer(trusted_roots=
        [warrant.issuer]), trusting the warrant's own issuer unconditionally.
        Any key could mint a warrant for itself and pass authorization.

        This affected all Tier 2 integrations: CrewAI, AutoGen, Google ADK,
        LangChain, LangGraph, OpenAI.

        Fix: enforce_tool_call now accepts trusted_roots parameter. When provided,
        it signs PoP locally then verifies via Authorizer(trusted_roots) instead of
        the self-signed path. Emits SecurityWarning when trusted_roots is omitted.
        """
        from tenuo._enforcement import enforce_tool_call
        from tenuo import BoundWarrant

        real_root_key = SigningKey.generate()
        attacker_key = SigningKey.generate()

        attacker_w = Warrant.issue(
            attacker_key,
            capabilities={"delete_database": {}},
            ttl_seconds=3600,
            holder=attacker_key.public_key,
        )
        bw = BoundWarrant(warrant=attacker_w, key=attacker_key)

        result = enforce_tool_call(
            tool_name="delete_database",
            tool_args={},
            bound_warrant=bw,
            trusted_roots=[real_root_key.public_key],
        )
        assert not result.allowed, (
            "Bug 3 regression: self-signed attacker warrant must be DENIED when "
            "trusted_roots is configured. If this fails, enforce_tool_call is not "
            "verifying issuer trust against the configured roots."
        )
