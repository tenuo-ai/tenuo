"""Property tests for adapter behavioral invariants.

These tests verify security-critical properties across ALL framework adapters.
They catch the class of bugs that existing structural tests missed:

1. Strict mode semantics: denied calls must NOT be reported as unguarded
2. Async enforcement parity: every adapter async path must use
   enforce_tool_call_async — using the sync variant in async code can block
   the event loop and break async approval handlers
3. Tier 2 routing: every adapter with warrant support must actually call
   enforce_tool_call (sync) or enforce_tool_call_async (async)
4. Sync-fallback in async paths must not block the event loop
5. Docstring accuracy: no references to nonexistent API methods

Security rationale: if an adapter's async path silently falls back to sync
enforcement, async approval handlers will never fire — meaning approval gates
can be bypassed by using the async client.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings

from tenuo._enforcement import EnforcementResult

from .strategies import st_warrant_bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_method_source(module_path: str, method_name: str) -> str | None:
    """Extract the source of a specific method from a module via AST."""
    try:
        mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
    except ImportError:
        return None

    source = inspect.getsource(mod)
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == method_name:
                return ast.get_source_segment(source, node)
    return None


def _has_bare_sync_enforce(method_source: str) -> bool:
    """Check if source calls enforce_tool_call (sync) outside a comment."""
    for line in method_source.split("\n"):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "enforce_tool_call(" in stripped and "enforce_tool_call_async" not in stripped:
            return True
    return False


# ==========================================================================
# 1. CrewAI strict mode: denied != unguarded
# ==========================================================================


class TestStrictModeSemantic:
    """Denied tool calls are guarded (the guard evaluated them).

    The ``report_unguarded_call`` function should ONLY be called for calls
    that bypass the guard entirely, never for calls that the guard
    evaluated and denied.
    """

    @given(data=st_warrant_bundle())
    @settings(max_examples=15, deadline=None)
    def test_denied_call_not_reported_as_unguarded(self, data):
        """Sync hook: denied tool must NOT appear in unguarded list."""
        _, key, tool, _ = data
        try:
            from tenuo.crewai import (
                GuardBuilder,
                _guarded_zone,
                get_unguarded_calls,
            )
        except ImportError:
            pytest.skip("crewai not installed")

        guard = GuardBuilder().allow("only_this_tool").build()

        if tool == "only_this_tool":
            return

        with _guarded_zone(guard, strict=True):
            hook = guard._create_hook()
            ctx = MagicMock()
            ctx.tool_name = tool
            ctx.tool_input = {}
            ctx.agent = None

            result = hook(ctx)
            assert result is False, "Unlisted tool should be denied"

            unguarded = get_unguarded_calls()
            assert tool not in unguarded, (
                f"Denied tool '{tool}' was incorrectly reported as unguarded. "
                "Denied means the guard evaluated it — it IS guarded."
            )

    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_denied_async_hook_not_reported_as_unguarded(self, data):
        """Async hook: denied tool must NOT appear in unguarded list."""
        _, key, tool, _ = data
        try:
            from tenuo.crewai import (
                GuardBuilder,
                _guarded_zone,
                get_unguarded_calls,
            )
        except ImportError:
            pytest.skip("crewai not installed")

        guard = GuardBuilder().allow("only_this_tool").build()

        if tool == "only_this_tool":
            return

        with _guarded_zone(guard, strict=True):
            async_hook = guard._create_async_hook()
            ctx = MagicMock()
            ctx.tool_name = tool
            ctx.tool_input = {}
            ctx.agent = None

            result = asyncio.run(async_hook(ctx))
            assert result is False

            unguarded = get_unguarded_calls()
            assert tool not in unguarded, (
                f"Denied tool '{tool}' was incorrectly reported as unguarded in async hook"
            )


# ==========================================================================
# 2. Async enforcement parity — ALL adapters
# ==========================================================================


_ASYNC_ENFORCEMENT_CASES = [
    # (module_path, async_method_name, must_contain)
    # -- LangChain --
    ("tenuo.langchain", "_acheck_authorization", "enforce_tool_call_async"),
    ("tenuo.langchain", "_run_enforcement_async", "enforce_tool_call_async"),
    # -- CrewAI --
    ("tenuo.crewai", "_authorize_async", "enforce_tool_call_async"),
    # -- LangGraph --
    ("tenuo.langgraph", "_authorize_tool_request_async", "enforce_tool_call_async"),
    # -- AutoGen --
    ("tenuo.autogen", "_authorize_async", "enforce_tool_call_async"),
    # -- Google ADK --
    ("tenuo.google_adk.guard", "async_before_tool", "enforce_tool_call_async"),
    # -- MCP Client --
    ("tenuo.mcp.client", "validate_tool", "enforce_tool_call_async"),
]

_NO_SYNC_ENFORCE_CASES = [
    # These async methods must NOT call the sync enforce_tool_call directly.
    ("tenuo.langchain", "_run_enforcement_async"),
    ("tenuo.crewai", "_authorize_async"),
    ("tenuo.langgraph", "_authorize_tool_request_async"),
    ("tenuo.autogen", "_authorize_async"),
    ("tenuo.google_adk.guard", "async_before_tool"),
    ("tenuo.mcp.client", "validate_tool"),
]


class TestAsyncEnforcementParity:
    """Adapters with async code paths must use enforce_tool_call_async.

    Using the sync variant in an async context:
    - Blocks the event loop
    - Breaks async approval handlers (approval gates silently skipped)
    - Makes concurrent warrant enforcement sequential
    """

    @pytest.mark.parametrize(
        "module_path,async_method,expected_call",
        _ASYNC_ENFORCEMENT_CASES,
        ids=[f"{m.split('.')[-1]}.{f}" for m, f, _ in _ASYNC_ENFORCEMENT_CASES],
    )
    def test_async_method_uses_async_enforcement(
        self, module_path, async_method, expected_call
    ):
        """Async methods must call the async enforcement function."""
        method_source = _get_method_source(module_path, async_method)
        if method_source is None:
            pytest.skip(f"{module_path}.{async_method} not found")

        assert expected_call in method_source, (
            f"{module_path}.{async_method} must call {expected_call}, "
            f"not the sync variant. Sync enforcement in async code blocks "
            f"the event loop and breaks async approval handlers."
        )

    @pytest.mark.parametrize(
        "module_path,async_method",
        _NO_SYNC_ENFORCE_CASES,
        ids=[f"{m.split('.')[-1]}.{f}" for m, f in _NO_SYNC_ENFORCE_CASES],
    )
    def test_async_method_does_not_call_sync_enforce(
        self, module_path, async_method
    ):
        """Async methods must NOT call the sync enforce_tool_call directly."""
        method_source = _get_method_source(module_path, async_method)
        if method_source is None:
            pytest.skip(f"{module_path}.{async_method} not found")

        assert not _has_bare_sync_enforce(method_source), (
            f"{module_path}.{async_method} calls sync enforce_tool_call — "
            f"must use enforce_tool_call_async. Sync enforcement in async "
            f"context blocks the event loop and bypasses async approval gates."
        )


# ==========================================================================
# 3. Tier 2 routing — all adapters call enforce_tool_call
# ==========================================================================


class TestLangChainTier2:
    """LangChain TenuoTool must route through enforce_tool_call for Tier 2."""

    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_bound_warrant_calls_enforce(self, data):
        warrant, key, tool, _ = data
        try:
            from tenuo.langchain import TenuoTool
        except ImportError:
            pytest.skip("langchain not installed")

        bound = warrant.bind(key)

        with patch("tenuo.langchain.enforce_tool_call") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={},
            )
            try:
                wrapped_tool = MagicMock()
                wrapped_tool.name = tool
                wrapped_tool.description = "test"
                wrapped_tool.func = lambda **kw: "ok"
                wrapped_tool.args_schema = None

                tt = TenuoTool(
                    wrapped_tool,
                    bound_warrant=bound,
                    trusted_roots=[key.public_key],
                )
                tt._run()
            except Exception:
                pass
            spy.assert_called()

    @given(data=st_warrant_bundle())
    @settings(max_examples=15)
    def test_bound_warrant_async_calls_enforce_async(self, data):
        warrant, key, tool, _ = data
        try:
            from tenuo.langchain import TenuoTool
        except ImportError:
            pytest.skip("langchain not installed")

        bound = warrant.bind(key)

        with patch("tenuo.langchain.enforce_tool_call_async") as spy:
            spy.return_value = EnforcementResult(
                allowed=True, tool=tool, arguments={},
            )

            async def run():
                wrapped_tool = MagicMock()
                wrapped_tool.name = tool
                wrapped_tool.description = "test"
                wrapped_tool.coroutine = None
                wrapped_tool.func = lambda **kw: "ok"
                wrapped_tool.args_schema = None

                tt = TenuoTool(
                    wrapped_tool,
                    bound_warrant=bound,
                    trusted_roots=[key.public_key],
                )
                try:
                    await tt._arun()
                except Exception:
                    pass

            asyncio.run(run())
            spy.assert_called()


class TestOpenAITier2Async:
    """OpenAI adapter async paths (acreate, _guard_stream_async) must use
    enforce_tool_call_async inside verify_tool_call, not sync enforcement."""

    def test_acreate_path_eventually_calls_async_enforce(self):
        """The async create path must not call sync enforce_tool_call."""
        try:
            mod = __import__("tenuo.openai", fromlist=["openai"])
        except ImportError:
            pytest.skip("openai not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_guard_stream_async":
                method_source = ast.get_source_segment(source, node) or ""
                if "verify_tool_call" in method_source:
                    # Acceptable if it calls verify_tool_call_async
                    if "verify_tool_call_async" not in method_source:
                        # Check if verify_tool_call itself is async-safe
                        vtc_source = _get_method_source("tenuo.openai", "verify_tool_call_async")
                        if vtc_source is None:
                            pytest.fail(
                                "OpenAI._guard_stream_async calls sync verify_tool_call. "
                                "Need verify_tool_call_async for async paths."
                            )


class TestAutoGenTier2Async:
    """AutoGen _execute_call_async must use async enforcement."""

    def test_execute_call_async_uses_async_authorize(self):
        """_execute_call_async must call _authorize_async, not _authorize."""
        method_source = _get_method_source("tenuo.autogen", "_execute_call_async")
        if method_source is None:
            pytest.skip("tenuo.autogen._execute_call_async not found")

        assert "_authorize_async" in method_source, (
            "AutoGen._execute_call_async calls sync _authorize — must use "
            "_authorize_async for async enforcement and approval handlers"
        )


class TestGoogleADKTier2Async:
    """Google ADK async_before_tool must not simply delegate to sync before_tool."""

    def test_async_before_tool_has_own_enforcement(self):
        """async_before_tool must do its own async enforcement, not just
        delegate to the sync before_tool."""
        method_source = _get_method_source("tenuo.google_adk.guard", "async_before_tool")
        if method_source is None:
            pytest.skip("tenuo.google_adk.guard.async_before_tool not found")

        delegates_to_sync = "self.before_tool(" in method_source and "enforce_tool_call_async" not in method_source
        if delegates_to_sync:
            pytest.fail(
                "Google ADK async_before_tool delegates to sync before_tool "
                "without async enforcement. Async approval handlers will never fire."
            )


class TestMCPClientTier2Async:
    """MCP SecureMCPClient async methods must use enforce_tool_call_async."""

    @pytest.mark.parametrize("method", ["validate_tool", "call_tool"])
    def test_async_method_uses_async_enforce(self, method):
        method_source = _get_method_source("tenuo.mcp.client", method)
        if method_source is None:
            pytest.skip(f"tenuo.mcp.client.{method} not found")

        if "enforce_tool_call" in method_source:
            assert "enforce_tool_call_async" in method_source, (
                f"MCP client.{method} (async def) calls sync enforce_tool_call — "
                f"must use enforce_tool_call_async"
            )


# ==========================================================================
# 4. Sync fallback in async paths
# ==========================================================================


class TestAsyncSyncFallback:
    """When async methods fall back to calling sync code, they must offload
    via run_in_executor to avoid blocking the event loop."""

    def test_langchain_arun_sync_fallback_uses_executor(self):
        """LangChain _arun calling wrapped._run should go through run_in_executor."""
        try:
            mod = __import__("tenuo.langchain", fromlist=["langchain"])
        except ImportError:
            pytest.skip("langchain not installed")

        source = inspect.getsource(mod)
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_arun":
                method_source = ast.get_source_segment(source, node) or ""
                if "self.wrapped._run" in method_source:
                    assert "run_in_executor" in method_source, (
                        "_arun calls self.wrapped._run without run_in_executor — "
                        "this blocks the event loop when the wrapped tool is sync-only"
                    )
                break


# ==========================================================================
# 5. Docstring accuracy — all builders/entry points
# ==========================================================================


class TestDocstringAccuracy:
    """Adapter docstrings must not reference methods that don't exist.

    Phantom method references in docstrings mislead users into calling
    APIs that raise AttributeError. This is especially dangerous for
    security-critical code where a user might skip authorization
    because the documented method doesn't exist.
    """

    @pytest.mark.parametrize("module_path,class_name,forbidden_methods", [
        ("tenuo.crewai", "GuardBuilder", [".protect(", ".seal("]),
    ])
    def test_no_phantom_methods_in_docstring(
        self, module_path, class_name, forbidden_methods
    ):
        """Class docstrings must not reference methods that don't exist."""
        try:
            mod = __import__(module_path, fromlist=[class_name])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        cls = getattr(mod, class_name)
        docstring = cls.__doc__ or ""

        existing_methods = {
            name for name in dir(cls)
            if callable(getattr(cls, name, None)) and not name.startswith("__")
        }

        for forbidden in forbidden_methods:
            method_name = forbidden.strip(".").strip("(")
            if forbidden in docstring:
                assert method_name in existing_methods, (
                    f"{class_name} docstring references {forbidden} "
                    f"but no '{method_name}' method exists on the class"
                )

    def test_langgraph_require_warrant_no_phantom_authorize(self):
        """LangGraph require_warrant docstring must not reference BoundWarrant.authorize()."""
        try:
            from tenuo.langgraph import require_warrant
        except ImportError:
            pytest.skip("langgraph not installed")

        docstring = require_warrant.__doc__ or ""

        if "bw.authorize(" in docstring or "bound.authorize(" in docstring:
            from tenuo.bound_warrant import BoundWarrant
            assert hasattr(BoundWarrant, "authorize"), (
                "require_warrant docstring references bw.authorize() but "
                "BoundWarrant has no authorize() method — users will get "
                "AttributeError following the example"
            )

    def test_all_builders_reference_existing_methods(self):
        """Scan all GuardBuilder subclasses for phantom method references in docstrings."""
        phantom_refs = {
            ".protect(": "protect",
            ".seal(": "seal",
        }
        builder_locations = [
            ("tenuo.crewai", "GuardBuilder"),
            ("tenuo.autogen", "GuardBuilder"),
            ("tenuo.openai", "GuardBuilder"),
        ]
        for module_path, class_name in builder_locations:
            try:
                mod = __import__(module_path, fromlist=[class_name])
            except ImportError:
                continue

            cls = getattr(mod, class_name, None)
            if cls is None:
                continue

            docstring = cls.__doc__ or ""
            existing = {
                name for name in dir(cls)
                if callable(getattr(cls, name, None)) and not name.startswith("__")
            }

            for ref, method_name in phantom_refs.items():
                if ref in docstring and method_name not in existing:
                    pytest.fail(
                        f"{module_path}.{class_name} docstring references "
                        f"'{ref}' but no '{method_name}' method exists"
                    )


# ==========================================================================
# 6. Import parity — all adapters that import enforce_tool_call must also
#    import enforce_tool_call_async if they have async methods
# ==========================================================================


class TestImportParity:
    """If a module imports enforce_tool_call and has async def methods, it
    must also import enforce_tool_call_async."""

    @pytest.mark.parametrize("module_path", [
        "tenuo.langchain",
        "tenuo.langgraph",
        "tenuo.crewai",
        "tenuo.autogen",
        "tenuo.google_adk.guard",
        "tenuo.mcp.client",
    ])
    def test_async_module_imports_async_enforce(self, module_path):
        """Modules with async methods and sync enforce must also import async enforce."""
        try:
            mod = __import__(module_path, fromlist=[module_path.split(".")[-1]])
        except ImportError:
            pytest.skip(f"{module_path} not installed")

        source = inspect.getsource(mod)

        has_async_def = "async def " in source
        has_sync_enforce = "enforce_tool_call" in source

        if has_async_def and has_sync_enforce:
            assert "enforce_tool_call_async" in source, (
                f"{module_path} has async methods and imports enforce_tool_call "
                f"but does NOT import enforce_tool_call_async. Async code paths "
                f"will silently use sync enforcement, blocking the event loop "
                f"and bypassing async approval handlers."
            )
