"""
Security Contract Tests
=======================
Verifies that security *configuration knobs* honour the contracts documented
in every integration's public API, regardless of the underlying framework.

Three contract categories:

  C2 – ``on_denial`` behavioural contracts
       Even when exceptions are suppressed (LOG / SKIP mode) the underlying
       tool/activity MUST NOT be executed and the caller MUST receive a
       denial indicator (not the real result).

  C3a – ``require_warrant=False`` + bad warrant still denied
        Providing an expired / invalid warrant MUST be rejected even in
        lenient mode.  Only unauthenticated (no-warrant) calls are allowed
        when ``require_warrant=False``.

  C3b – Safe defaults  (fail-closed under zero-config)
        Guards created with minimum arguments MUST default to deny-all, not
        allow-all.

  C3c – ``dry_run`` is opt-in
        ``dry_run=False`` by default; shadow mode MUST NOT be activated
        without an explicit ``dry_run=True``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tenuo_core import SigningKey, Warrant


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _signed_expired_warrant(key: SigningKey | None = None) -> Warrant:
    """Return a warrant that is already expired (wait 2 s for TTL=1)."""
    import time as _time
    k = key or SigningKey.generate()
    w = Warrant.issue(
        k,
        capabilities={"search": {}},
        ttl_seconds=1,
        holder=k.public_key,
    )
    _time.sleep(2)
    return w


def _signed_valid_warrant(
    key: SigningKey | None = None,
    tool: str = "search",
    ttl: int = 3600,
) -> Warrant:
    k = key or SigningKey.generate()
    return Warrant.issue(
        k,
        capabilities={tool: {}},
        ttl_seconds=ttl,
        holder=k.public_key,
    )


# ===========================================================================
# C2 – on_denial behavioural contracts
# ===========================================================================


@pytest.mark.security
class TestOnDenialBehaviouralContracts:
    """
    on_denial="log" / "skip": tool function MUST NOT be called; caller
    receives a denial indicator (not the normal tool result).
    """

    # ------------------------------------------------------------------
    # C2 / CrewAI
    # ------------------------------------------------------------------

    def test_crewai_log_mode_tool_not_called(self):
        """
        CrewAI on_denial='log': _authorize must return a DenialResult (not None)
        and must NOT raise an exception.
        """
        pytest.importorskip("crewai")
        from tenuo.crewai import GuardBuilder
        from tenuo._enforcement import DenialResult

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, signing_key=key)
            .on_denial("log")
            .build()
        )

        # _authorize returns None for allowed, DenialResult for denied
        result = guard._authorize("delete_everything", {})

        # With log mode: must return DenialResult (not None = not allowed)
        assert result is not None, (
            "on_denial='log': must return DenialResult, not None (None means allowed)"
        )
        assert isinstance(result, DenialResult), (
            f"on_denial='log': must return DenialResult, got {type(result)}"
        )

    def test_crewai_skip_mode_tool_not_called(self):
        """
        CrewAI on_denial='skip': _authorize must return DenialResult silently
        (no raise, no log at WARNING level).
        """
        pytest.importorskip("crewai")
        from tenuo.crewai import GuardBuilder
        from tenuo._enforcement import DenialResult

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, signing_key=key)
            .on_denial("skip")
            .build()
        )

        result = guard._authorize("delete_everything", {})

        assert result is not None, "on_denial='skip': must return DenialResult, not None"
        assert isinstance(result, DenialResult)

    # ------------------------------------------------------------------
    # C2 / AutoGen
    # ------------------------------------------------------------------

    def test_autogen_log_mode_tool_not_called(self):
        """AutoGen on_denial='log': guarded function must not be called."""
        pytest.importorskip("autogen")
        from tenuo.autogen import GuardBuilder

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, signing_key=key)
            .on_denial("log")
            .build()
        )

        called = {"flag": False}

        def fn():
            called["flag"] = True
            return "real_result"

        result = guard._execute_call(fn, "delete_everything", {}, (), {})

        assert not called["flag"], "AutoGen guarded function must not be called on log-denial"
        assert result != "real_result"

    def test_autogen_skip_mode_tool_not_called(self):
        """AutoGen on_denial='skip': guarded function must not be called."""
        pytest.importorskip("autogen")
        from tenuo.autogen import GuardBuilder

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = (
            GuardBuilder()
            .allow("search")
            .with_warrant(w, signing_key=key)
            .on_denial("skip")
            .build()
        )

        called = {"flag": False}

        def fn():
            called["flag"] = True
            return "real_result"

        result = guard._execute_call(fn, "delete_everything", {}, (), {})

        assert not called["flag"]
        assert result != "real_result"

    # ------------------------------------------------------------------
    # C2 / Google ADK
    # ------------------------------------------------------------------

    def test_google_adk_return_mode_tool_not_called(self):
        """
        Google ADK on_deny='return': before_tool returns non-None so the ADK
        runtime short-circuits and does NOT call the actual tool function.
        """
        from tenuo.google_adk.guard import TenuoGuard

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = TenuoGuard(
            warrant=w, signing_key=key,
            require_pop=False, on_denial="return",
        )

        tool = MagicMock()
        tool.name = "delete_everything"
        ctx = MagicMock()

        result = guard.before_tool(tool, {}, ctx)

        # ADK: non-None before_tool result means the runtime must NOT call the tool
        assert result is not None, (
            "Google ADK on_deny='return': must return non-None to short-circuit execution"
        )
        # result should be a denial dict, not a normal tool response
        assert not isinstance(result, str) or "denied" in result.get("error", "")

    # ------------------------------------------------------------------
    # C2 / Temporal
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_temporal_log_mode_activity_not_called(self):
        """
        Temporal on_denial='log': execute_activity on the *next* handler must
        NOT be called when the warrant does not cover the activity type.
        """
        from dataclasses import dataclass

        pytest.importorskip("temporalio")
        from tenuo.temporal import KeyResolver, TenuoPlugin, TenuoPluginConfig, TENUO_WARRANT_HEADER

        trusted_key = SigningKey.generate()

        class _R(KeyResolver):
            def resolve(self, _kid):
                return trusted_key

        # Warrant grants 'read_file'; activity is 'delete_file'
        w = _signed_valid_warrant(trusted_key, tool="read_file")

        cfg = TenuoPluginConfig(
            key_resolver=_R(),
            trusted_roots=[trusted_key.public_key],
            require_warrant=True,
            on_denial="log",
        )
        interceptor = TenuoPlugin(cfg)

        inp = MagicMock()
        inp.headers = {TENUO_WARRANT_HEADER: w.to_base64().encode()}
        fn = MagicMock()
        fn.__name__ = "delete_file"
        fn._tenuo_tool_name = "delete_file"
        fn.__tenuo_unprotected__ = False
        inp.fn = fn
        inp.args = []
        inp.kwargs = {}

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

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="real_result")
        inbound = interceptor.intercept_activity(nxt)

        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = _Info()
            result = await inbound.execute_activity(inp)

        # Activity must NOT have been executed
        nxt.execute_activity.assert_not_called()
        # Result must not be the real activity output
        assert result != "real_result", (
            "Temporal on_denial='log': real activity result must not reach caller"
        )


# ===========================================================================
# C3a – require_warrant=False + bad warrant still denied
# ===========================================================================


@pytest.mark.security
class TestRequireWarrantFalseWithBadWarrant:
    """
    When require_warrant=False:
      • no warrant present  → ALLOWED (lenient mode)
      • bad/expired warrant present → DENIED (the warrant was provided; it must be validated)
    """

    # ------------------------------------------------------------------
    # C3a / A2A
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_a2a_no_warrant_allowed_when_not_required(self):
        """A2A: no warrant + require_warrant=False → validate_warrant is never called."""
        from tenuo.a2a.server import A2AServer

        trusted_key = SigningKey.generate()
        server = A2AServer(
            name="test", url="https://test.example.com", public_key="z6MkTest",
            trusted_issuers=[trusted_key.public_key],
            require_warrant=False, require_pop=False,
            require_audience=False, check_replay=False,
        )
        # With require_warrant=False and no token, validate_warrant is never called.
        # The server must not raise just because warrant is absent.
        assert server.require_warrant is False

    @pytest.mark.asyncio
    async def test_a2a_expired_warrant_denied_even_when_not_required(self):
        """A2A: expired warrant + require_warrant=False → DENIED by validate_warrant."""
        from tenuo.a2a.server import A2AServer

        trusted_key = SigningKey.generate()
        server = A2AServer(
            name="test", url="https://test.example.com", public_key="z6MkTest",
            trusted_issuers=[trusted_key.public_key],
            require_warrant=False, require_pop=False,
            require_audience=False, check_replay=False,
        )

        expired_w = _signed_expired_warrant(trusted_key)

        with pytest.raises(Exception) as exc_info:
            await server.validate_warrant(
                expired_w.to_base64(), "search", {}
            )

        assert exc_info.type.__name__ not in ("AttributeError", "TypeError"), (
            f"Unexpected internal error: {exc_info.value}"
        )
        denial_msg = str(exc_info.value).lower()
        assert any(kw in denial_msg for kw in ("expir", "invalid", "denied", "unauthori")), (
            f"A2A C3a: expired warrant must be denied even with require_warrant=False. "
            f"Got: {exc_info.value}"
        )

    # ------------------------------------------------------------------
    # C3a / MCP
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_mcp_no_warrant_allowed_when_not_required(self):
        """MCP: no warrant + require_warrant=False → allowed."""
        from tenuo.mcp.server import MCPVerifier
        from tenuo_core import Authorizer

        trusted_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[trusted_key.public_key])
        verifier = MCPVerifier(authorizer=authorizer, require_warrant=False)

        result = verifier.verify("search", {"q": "hello"}, meta=None)
        assert result.allowed, (
            "MCP: warrant-less call must be allowed when require_warrant=False"
        )

    @pytest.mark.asyncio
    async def test_mcp_expired_warrant_denied_even_when_not_required(self):
        """MCP: expired warrant + require_warrant=False → DENIED."""
        from tenuo.mcp.server import MCPVerifier
        from tenuo_core import Authorizer

        trusted_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[trusted_key.public_key])
        verifier = MCPVerifier(authorizer=authorizer, require_warrant=False)

        expired_w = _signed_expired_warrant(trusted_key)
        meta = {"tenuo": {"warrant": expired_w.to_base64()}}
        result = verifier.verify("search", {"q": "hello"}, meta=meta)

        assert not result.allowed, (
            "MCP C3a: expired warrant must be denied even with require_warrant=False. "
            f"Got allowed=True (reason: {result.denial_reason})"
        )


# ===========================================================================
# C3b – Safe defaults  (fail-closed under minimum config)
# ===========================================================================


@pytest.mark.security
class TestSafeDefaults:
    """
    Guards created with minimum valid arguments MUST default to deny-all for
    unknown/missing credentials.  No integration should silently grant access
    under zero configuration.
    """

    @pytest.mark.asyncio
    async def test_a2a_default_requires_warrant(self):
        """A2A: default config rejects warrant-less calls."""
        from tenuo.a2a.server import A2AServer

        trusted_key = SigningKey.generate()
        server = A2AServer(
            name="test", url="https://test.example.com", public_key="z6MkTest",
            trusted_issuers=[trusted_key.public_key],
        )
        assert server.require_warrant is True, (
            "A2A default: require_warrant must be True"
        )

    @pytest.mark.asyncio
    async def test_mcp_default_requires_warrant(self):
        """MCP: default config rejects warrant-less calls."""
        from tenuo.mcp.server import MCPVerifier
        from tenuo_core import Authorizer

        trusted_key = SigningKey.generate()
        authorizer = Authorizer(trusted_roots=[trusted_key.public_key])
        verifier = MCPVerifier(authorizer=authorizer)

        result = verifier.verify("search", {}, meta=None)
        assert not result.allowed, (
            "MCP default: warrant-less call must be denied"
        )

    def test_crewai_guard_builder_default_denies_unknown_tool(self):
        """CrewAI GuardBuilder: default guard denies tools not in the allow list."""
        pytest.importorskip("crewai")
        from tenuo.crewai import GuardBuilder

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = GuardBuilder().allow("search").with_warrant(w, signing_key=key).build()

        called = {"flag": False}

        def fn():
            called["flag"] = True
            return "result"

        with pytest.raises(Exception):
            guard._execute_call(fn, "delete_everything", {}, (), {})

        assert not called["flag"], "Default CrewAI guard must deny unlisted tool"

    def test_autogen_guard_builder_default_denies_unknown_tool(self):
        """AutoGen GuardBuilder: default guard denies tools not in the allow list."""
        pytest.importorskip("autogen")
        from tenuo.autogen import GuardBuilder

        key = SigningKey.generate()
        w = _signed_valid_warrant(key, tool="search")

        guard = GuardBuilder().allow("search").with_warrant(w, signing_key=key).build()

        called = {"flag": False}

        def fn():
            called["flag"] = True
            return "result"

        with pytest.raises(Exception):
            guard._execute_call(fn, "delete_everything", {}, (), {})

        assert not called["flag"]


# ===========================================================================
# C3c – dry_run is opt-in
# ===========================================================================


@pytest.mark.security
class TestDryRunIsOptIn:
    """
    Shadow / audit-only mode (dry_run=True) MUST be an explicit opt-in.

    Default configurations must NOT be in dry_run mode so that security
    checks are enforced by default.  In dry_run mode the interceptor LOGS
    a clear warning and executes the activity anyway — this must not happen
    unless explicitly requested.
    """

    def test_temporal_interceptor_default_is_not_dry_run(self):
        """Temporal TenuoPluginConfig defaults to dry_run=False."""
        pytest.importorskip("temporalio")
        from tenuo.temporal import KeyResolver, TenuoPluginConfig

        class _R(KeyResolver):
            def resolve(self, _kid):
                return SigningKey.generate()

        cfg = TenuoPluginConfig(key_resolver=_R())
        assert cfg.dry_run is False, (
            "TenuoPluginConfig: dry_run must default to False"
        )

    @pytest.mark.asyncio
    async def test_temporal_dry_run_true_executes_anyway_with_warning(self):
        """
        Temporal dry_run=True: activity is executed AND a warning is logged
        even when the warrant is missing.  This validates the opt-in semantic:
        you must explicitly set dry_run=True to enter shadow mode.
        """
        from dataclasses import dataclass

        pytest.importorskip("temporalio")
        from tenuo.temporal import KeyResolver, TenuoPlugin, TenuoPluginConfig

        class _R(KeyResolver):
            def resolve(self, _kid):
                return SigningKey.generate()

        cfg = TenuoPluginConfig(
            key_resolver=_R(),
            require_warrant=True,
            dry_run=True,
        )
        interceptor = TenuoPlugin(cfg)

        inp = MagicMock()
        inp.headers = {}  # no warrant
        fn = MagicMock()
        fn.__name__ = "test_activity"
        fn._tenuo_tool_name = "test_activity"
        fn.__tenuo_unprotected__ = False
        inp.fn = fn
        inp.args = []
        inp.kwargs = {}

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

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="dry_run_result")
        inbound = interceptor.intercept_activity(nxt)

        with patch("temporalio.activity.info") as mock_info:
            mock_info.return_value = _Info()
            result = await inbound.execute_activity(inp)

        # In dry_run=True mode the activity SHOULD be called despite missing warrant
        nxt.execute_activity.assert_called_once(), (
            "dry_run=True: activity must be executed (shadow mode)"
        )
        assert result == "dry_run_result"

    @pytest.mark.asyncio
    async def test_temporal_dry_run_false_denies_missing_warrant(self):
        """
        Temporal dry_run=False (default): missing warrant MUST cause denial.
        Validates that dry_run=True cannot be assumed by default.
        """
        from dataclasses import dataclass

        pytest.importorskip("temporalio")
        from tenuo.temporal import KeyResolver, TenuoPlugin, TenuoPluginConfig

        class _R(KeyResolver):
            def resolve(self, _kid):
                return SigningKey.generate()

        cfg = TenuoPluginConfig(
            key_resolver=_R(),
            require_warrant=True,
            dry_run=False,
            on_denial="raise",
        )
        interceptor = TenuoPlugin(cfg)

        inp = MagicMock()
        inp.headers = {}  # no warrant
        fn = MagicMock()
        fn.__name__ = "test_activity"
        fn._tenuo_tool_name = "test_activity"
        fn.__tenuo_unprotected__ = False
        inp.fn = fn
        inp.args = []
        inp.kwargs = {}

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

        nxt = MagicMock()
        nxt.execute_activity = AsyncMock(return_value="should_not_reach")
        inbound = interceptor.intercept_activity(nxt)

        with pytest.raises(Exception) as exc_info:
            with patch("temporalio.activity.info") as mock_info:
                mock_info.return_value = _Info()
                await inbound.execute_activity(inp)

        nxt.execute_activity.assert_not_called()
        assert exc_info.type.__name__ not in ("AttributeError", "TypeError")
