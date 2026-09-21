"""The framework-agnostic enforcement entry points are part of the public API."""

import tenuo


def test_enforce_tool_call_is_exported():
    assert tenuo.enforce_tool_call is tenuo._enforcement.enforce_tool_call
    assert tenuo.enforce_tool_call_async is tenuo._enforcement.enforce_tool_call_async
    assert tenuo.EnforcementResult is tenuo._enforcement.EnforcementResult


def test_enforcement_names_are_in_all():
    for name in ("enforce_tool_call", "enforce_tool_call_async", "EnforcementResult"):
        assert name in tenuo.__all__
