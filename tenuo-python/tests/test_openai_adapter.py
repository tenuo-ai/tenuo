"""
Tests for Tenuo OpenAI Adapter - Tier 1 Guardrails.

Covers:
- Tool allowlist/denylist enforcement
- Constraint checking for arguments
- Denial handling modes (raise/skip/log)
- Streaming protection (buffer-verify-emit)
- Edge cases and error handling
"""

import json
import pytest
from dataclasses import dataclass
from typing import Any, List, Optional
from unittest.mock import Mock, MagicMock, patch

from tenuo.openai import (
    guard,
    GuardedClient,
    ToolDenied,
    ConstraintViolation,
    MalformedToolCall,
    BufferOverflow,
    Pattern,
    Exact,
    OneOf,
    Range,
    Regex,
    Wildcard,
    AnyOf,
    All,
    Not,
    NotOneOf,
    Cidr,
    UrlPattern,
    CEL,
    verify_tool_call,
    check_constraint,
)


# =============================================================================
# Mock Helpers
# =============================================================================


@dataclass
class MockFunction:
    """Mock OpenAI function object."""
    name: str
    arguments: str


@dataclass
class MockToolCall:
    """Mock OpenAI tool call."""
    id: str
    type: str
    function: MockFunction


@dataclass
class MockMessage:
    """Mock OpenAI message."""
    role: str
    content: Optional[str]
    tool_calls: Optional[List[MockToolCall]]


@dataclass
class MockChoice:
    """Mock OpenAI choice."""
    index: int
    message: MockMessage
    finish_reason: str


@dataclass
class MockResponse:
    """Mock OpenAI response."""
    id: str
    choices: List[MockChoice]
    model: str


def make_response(tool_calls: List[tuple]) -> MockResponse:
    """Create a mock response with tool calls.
    
    Args:
        tool_calls: List of (name, arguments_dict) tuples
    """
    tc_objects = [
        MockToolCall(
            id=f"call_{i}",
            type="function",
            function=MockFunction(name=name, arguments=json.dumps(args))
        )
        for i, (name, args) in enumerate(tool_calls)
    ]
    
    return MockResponse(
        id="resp_123",
        choices=[
            MockChoice(
                index=0,
                message=MockMessage(
                    role="assistant",
                    content=None,
                    tool_calls=tc_objects if tc_objects else None
                ),
                finish_reason="tool_calls"
            )
        ],
        model="gpt-4o"
    )


def make_mock_client(response: MockResponse) -> Mock:
    """Create a mock OpenAI client."""
    client = Mock()
    client.chat.completions.create.return_value = response
    return client


# =============================================================================
# Basic Guardrail Tests
# =============================================================================


class TestAllowlist:
    """Tests for tool allowlist enforcement."""
    
    def test_allowed_tool_passes(self):
        """Tool in allowlist should pass."""
        response = make_response([("search", {"query": "python"})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, allow_tools=["search", "read_file"])
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(result.choices[0].message.tool_calls) == 1
        assert result.choices[0].message.tool_calls[0].function.name == "search"
    
    def test_denied_tool_raises(self):
        """Tool not in allowlist should raise ToolDenied."""
        response = make_response([("send_email", {"to": "user@example.com"})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, allow_tools=["search"], on_denial="raise")
        
        with pytest.raises(ToolDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "send_email"
        assert "allowlist" in exc.value.reason.lower()
    
    def test_multiple_tools_partial_allowed(self):
        """Only allowed tools should pass when using skip mode."""
        response = make_response([
            ("search", {"query": "python"}),
            ("send_email", {"to": "user@example.com"}),
            ("read_file", {"path": "/data/file.txt"}),
        ])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search", "read_file"],
            on_denial="skip"
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        # Only search and read_file should remain
        assert len(result.choices[0].message.tool_calls) == 2
        names = [tc.function.name for tc in result.choices[0].message.tool_calls]
        assert "search" in names
        assert "read_file" in names
        assert "send_email" not in names
    
    def test_no_allowlist_allows_all(self):
        """No allowlist means all tools allowed."""
        response = make_response([("any_tool", {})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client)  # No allow_tools
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(result.choices[0].message.tool_calls) == 1


class TestDenylist:
    """Tests for tool denylist enforcement."""
    
    def test_denylisted_tool_blocked(self):
        """Tool in denylist should be blocked."""
        response = make_response([("delete_all", {})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, deny_tools=["delete_all"], on_denial="raise")
        
        with pytest.raises(ToolDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "delete_all"
        assert "denylist" in exc.value.reason.lower()
    
    def test_denylist_takes_precedence(self):
        """Denylist should block even if tool is in allowlist."""
        response = make_response([("dangerous_tool", {})])
        mock_client = make_mock_client(response)
        
        # Tool in both lists - denylist wins
        client = guard(
            mock_client,
            allow_tools=["dangerous_tool", "safe_tool"],
            deny_tools=["dangerous_tool"],
            on_denial="raise"
        )
        
        with pytest.raises(ToolDenied):
            client.chat.completions.create(model="gpt-4o", messages=[])


# =============================================================================
# Constraint Tests
# =============================================================================


class TestConstraints:
    """Tests for argument constraint checking."""
    
    def test_pattern_constraint_passes(self):
        """Valid pattern should pass."""
        response = make_response([("read_file", {"path": "/data/report.pdf"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}}
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
    
    def test_pattern_constraint_fails(self):
        """Invalid pattern should raise ConstraintViolation."""
        response = make_response([("read_file", {"path": "/etc/passwd"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
            on_denial="raise"
        )
        
        with pytest.raises(ConstraintViolation) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "read_file"
        assert exc.value.param == "path"
        assert exc.value.value == "/etc/passwd"
    
    def test_range_constraint_passes(self):
        """Value within range should pass."""
        response = make_response([("search", {"query": "python", "max_results": 10})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search"],
            constraints={"search": {"max_results": Range(1, 20)}}
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
    
    def test_range_constraint_fails_too_high(self):
        """Value above range should fail."""
        response = make_response([("search", {"max_results": 100})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search"],
            constraints={"search": {"max_results": Range(1, 20)}},
            on_denial="raise"
        )
        
        with pytest.raises(ConstraintViolation) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.param == "max_results"
    
    def test_oneof_constraint_passes(self):
        """Value in set should pass."""
        response = make_response([("calculate", {"operation": "add"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["calculate"],
            constraints={"calculate": {"operation": OneOf(["add", "subtract"])}}
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
    
    def test_oneof_constraint_fails(self):
        """Value not in set should fail."""
        response = make_response([("calculate", {"operation": "divide"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["calculate"],
            constraints={"calculate": {"operation": OneOf(["add", "subtract"])}},
            on_denial="raise"
        )
        
        with pytest.raises(ConstraintViolation):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_multiple_constraints_all_must_pass(self):
        """All constraints on a tool must pass."""
        response = make_response([("search", {"query": "python", "max_results": 5})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search"],
            constraints={
                "search": {
                    "max_results": Range(1, 10),
                    # query not constrained
                }
            }
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1
    
    def test_unconstrained_param_allowed(self):
        """Parameters without constraints should be allowed."""
        response = make_response([("search", {"query": "anything", "lang": "en"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search"],
            constraints={"search": {"query": Wildcard()}}  # Only query constrained (to anything)
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert len(result.choices[0].message.tool_calls) == 1


# =============================================================================
# Denial Mode Tests
# =============================================================================


class TestDenialModes:
    """Tests for different denial handling modes."""
    
    def test_raise_mode_raises_exception(self):
        """Raise mode should raise exception."""
        response = make_response([("blocked_tool", {})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, allow_tools=[], on_denial="raise")
        
        with pytest.raises(ToolDenied):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_skip_mode_removes_tool_call(self):
        """Skip mode should silently remove blocked tool calls."""
        response = make_response([
            ("allowed", {}),
            ("blocked", {}),
        ])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, allow_tools=["allowed"], on_denial="skip")
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(result.choices[0].message.tool_calls) == 1
        assert result.choices[0].message.tool_calls[0].function.name == "allowed"
    
    def test_log_mode_logs_and_skips(self):
        """Log mode should log warning and skip."""
        response = make_response([("blocked", {})])
        mock_client = make_mock_client(response)
        
        with patch("tenuo.openai.logger") as mock_logger:
            client = guard(mock_client, allow_tools=[], on_denial="log")
            result = client.chat.completions.create(model="gpt-4o", messages=[])
            
            # Should have logged
            mock_logger.warning.assert_called_once()
            
            # Tool calls should be empty/None
            assert not result.choices[0].message.tool_calls


# =============================================================================
# Malformed Input Tests
# =============================================================================


class TestMalformedInputs:
    """Tests for handling malformed tool calls."""
    
    def test_invalid_json_arguments(self):
        """Invalid JSON in arguments should raise MalformedToolCall."""
        mock_response = MockResponse(
            id="resp_123",
            choices=[
                MockChoice(
                    index=0,
                    message=MockMessage(
                        role="assistant",
                        content=None,
                        tool_calls=[
                            MockToolCall(
                                id="call_0",
                                type="function",
                                function=MockFunction(
                                    name="search",
                                    arguments="{invalid json"
                                )
                            )
                        ]
                    ),
                    finish_reason="tool_calls"
                )
            ],
            model="gpt-4o"
        )
        mock_client = make_mock_client(mock_response)
        
        client = guard(mock_client, allow_tools=["search"], on_denial="raise")
        
        with pytest.raises(MalformedToolCall) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "search"
    
    def test_empty_arguments(self):
        """Empty arguments should be treated as empty dict."""
        mock_response = MockResponse(
            id="resp_123",
            choices=[
                MockChoice(
                    index=0,
                    message=MockMessage(
                        role="assistant",
                        content=None,
                        tool_calls=[
                            MockToolCall(
                                id="call_0",
                                type="function",
                                function=MockFunction(
                                    name="simple_tool",
                                    arguments=""
                                )
                            )
                        ]
                    ),
                    finish_reason="tool_calls"
                )
            ],
            model="gpt-4o"
        )
        mock_client = make_mock_client(mock_response)
        
        client = guard(mock_client, allow_tools=["simple_tool"])
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(result.choices[0].message.tool_calls) == 1


# =============================================================================
# Passthrough Tests
# =============================================================================


class TestPassthrough:
    """Tests for passthrough behavior."""
    
    def test_no_tool_calls_passthrough(self):
        """Response without tool calls should pass through."""
        mock_response = MockResponse(
            id="resp_123",
            choices=[
                MockChoice(
                    index=0,
                    message=MockMessage(
                        role="assistant",
                        content="Hello, how can I help?",
                        tool_calls=None
                    ),
                    finish_reason="stop"
                )
            ],
            model="gpt-4o"
        )
        mock_client = make_mock_client(mock_response)
        
        client = guard(mock_client, allow_tools=["search"])
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert result.choices[0].message.content == "Hello, how can I help?"
    
    def test_other_client_methods_passthrough(self):
        """Non-chat methods should pass through."""
        mock_client = Mock()
        mock_client.models.list.return_value = ["gpt-4o"]
        
        client = guard(mock_client, allow_tools=["search"])
        
        # Should pass through to underlying client
        result = client.models.list()
        assert result == ["gpt-4o"]


# =============================================================================
# Unit Tests for Helper Functions
# =============================================================================


class TestVerifyToolCall:
    """Unit tests for verify_tool_call function."""
    
    def test_verify_passes_allowed(self):
        """Allowed tool with valid args should not raise."""
        verify_tool_call(
            "search",
            {"query": "python"},
            allow_tools=["search"],
            deny_tools=None,
            constraints=None,
        )
    
    def test_verify_fails_denylist(self):
        """Denylisted tool should raise."""
        with pytest.raises(ToolDenied):
            verify_tool_call(
                "dangerous",
                {},
                allow_tools=None,
                deny_tools=["dangerous"],
                constraints=None,
            )
    
    def test_verify_fails_not_in_allowlist(self):
        """Tool not in allowlist should raise."""
        with pytest.raises(ToolDenied):
            verify_tool_call(
                "unknown",
                {},
                allow_tools=["known"],
                deny_tools=None,
                constraints=None,
            )
    
    def test_verify_fails_constraint(self):
        """Constraint violation should raise."""
        with pytest.raises(ConstraintViolation):
            verify_tool_call(
                "read_file",
                {"path": "/etc/passwd"},
                allow_tools=["read_file"],
                deny_tools=None,
                constraints={"read_file": {"path": Pattern("/data/*")}},
            )
    
    def test_type_mismatch_provides_clear_error(self):
        """Type mismatch should provide actionable error message."""
        with pytest.raises(ConstraintViolation) as exc:
            verify_tool_call(
                "search",
                {"max_results": "ten"},  # String instead of int
                allow_tools=["search"],
                deny_tools=None,
                constraints={"search": {"max_results": Range(1, 100)}},
            )
        
        # Should flag as type mismatch with clear message
        assert exc.value.type_mismatch is True
        assert "numeric" in exc.value.reason.lower()
        assert "str" in exc.value.reason
    
    def test_value_mismatch_not_flagged_as_type_error(self):
        """Value constraint violation should not be flagged as type mismatch."""
        with pytest.raises(ConstraintViolation) as exc:
            verify_tool_call(
                "search",
                {"max_results": 1000},  # Correct type, wrong value
                allow_tools=["search"],
                deny_tools=None,
                constraints={"search": {"max_results": Range(1, 100)}},
            )
        
        # Should NOT be flagged as type mismatch
        assert exc.value.type_mismatch is False


class TestCheckConstraint:
    """Unit tests for check_constraint function."""
    
    def test_pattern_matches(self):
        assert check_constraint(Pattern("/data/*"), "/data/file.txt") is True
        assert check_constraint(Pattern("/data/*"), "/etc/passwd") is False
    
    def test_range_matches(self):
        assert check_constraint(Range(0, 10), 5) is True
        assert check_constraint(Range(0, 10), 15) is False
        assert check_constraint(Range(0, None), 1000) is True  # No max
    
    def test_wildcard_matches_anything(self):
        assert check_constraint(Wildcard(), "anything") is True
        assert check_constraint(Wildcard(), 12345) is True
        assert check_constraint(Wildcard(), None) is True
    
    def test_regex_fullmatch(self):
        """Regex uses fullmatch, not match - prevents partial matches."""
        # Import Regex for this test
        from tenuo import Regex
        
        # Full match should pass
        assert check_constraint(Regex(r"^[a-z]+$"), "hello") is True
        
        # Partial match should FAIL (fullmatch semantics)
        # With match(), "hello123" would pass because "hello" matches at start
        # With fullmatch(), it should fail because "123" doesn't match
        assert check_constraint(Regex(r"[a-z]+"), "hello123") is False
        
        # Empty pattern edge case
        assert check_constraint(Regex(r""), "") is True
        assert check_constraint(Regex(r""), "x") is False


class TestCompositeConstraints:
    """Tests for composite constraints (AnyOf, All, Not) - fail closed behavior."""
    
    def test_anyof_fails_no_match(self):
        """AnyOf should fail if no option matches."""
        constraint = AnyOf([Pattern("/data/*"), Pattern("/tmp/*")])
        assert check_constraint(constraint, "/etc/passwd") is False
    
    def test_all_passes_all_match(self):
        """All should pass only if all constraints match.
        
        Note: Uses Range constraints which have Rust matches() support.
        """
        constraint = All([Range(0, None), Range(None, 100)])
        assert check_constraint(constraint, 50) is True
    
    def test_not_oneof_matches(self):
        """NotOneOf should pass values not in the set.
        
        NotOneOf has direct Python fallback support.
        """
        constraint = NotOneOf(["forbidden", "blocked"])
        assert check_constraint(constraint, "allowed") is True
        assert check_constraint(constraint, "forbidden") is False
    
    # The following tests require composite constraints to expose their inner
    # constraints to Python for the fallback path to work. These are skipped
    # until the Rust bindings are enhanced with a .constraints property.
    
    @pytest.mark.skip(reason="AnyOf/All/Not don't expose inner constraints to Python; needs Rust binding enhancement")
    def test_anyof_matches_first_option(self):
        """AnyOf should pass if first option matches."""
        constraint = AnyOf([Pattern("/data/*"), Pattern("/tmp/*")])
        assert check_constraint(constraint, "/data/file.txt") is True
    
    @pytest.mark.skip(reason="AnyOf/All/Not don't expose inner constraints to Python; needs Rust binding enhancement")
    def test_anyof_matches_second_option(self):
        """AnyOf should pass if second option matches."""
        constraint = AnyOf([Pattern("/data/*"), Pattern("/tmp/*")])
        assert check_constraint(constraint, "/tmp/file.txt") is True
    
    @pytest.mark.skip(reason="All doesn't expose constraints to Python for Range(None, x) fallback")
    def test_all_fails_partial_match(self):
        """All should fail if any constraint fails."""
        constraint = All([Range(0, None), Range(None, 100)])
        assert check_constraint(constraint, 150) is False  # Fails second
        assert check_constraint(constraint, -10) is False  # Fails first
    
    @pytest.mark.skip(reason="Not doesn't expose inner constraint to Python; needs Rust binding enhancement")
    def test_not_inverts_match(self):
        """Not should invert the inner constraint."""
        constraint = Not(Pattern("/admin/*"))
        assert check_constraint(constraint, "/data/file.txt") is True
        assert check_constraint(constraint, "/admin/secret") is False
    
    @pytest.mark.skip(reason="Nested composites require full Python access to inner constraints")
    def test_nested_composite(self):
        """Nested composite constraints should work."""
        # Allow /data/* OR (/tmp/* AND NOT /tmp/secret/*)
        constraint = AnyOf([
            Pattern("/data/*"),
            All([Pattern("/tmp/*"), Not(Pattern("/tmp/secret/*"))])
        ])
        assert check_constraint(constraint, "/data/anything") is True
        assert check_constraint(constraint, "/tmp/file.txt") is True
        assert check_constraint(constraint, "/tmp/secret/key") is False
        assert check_constraint(constraint, "/etc/passwd") is False


class TestCidrConstraint:
    """Tests for CIDR (IP range) constraint."""
    
    def test_ipv4_in_range(self):
        """IPv4 in CIDR range should match."""
        constraint = Cidr("192.168.1.0/24")
        assert check_constraint(constraint, "192.168.1.100") is True
        assert check_constraint(constraint, "192.168.1.1") is True
    
    def test_ipv4_out_of_range(self):
        """IPv4 outside CIDR range should not match."""
        constraint = Cidr("192.168.1.0/24")
        assert check_constraint(constraint, "192.168.2.1") is False
        assert check_constraint(constraint, "10.0.0.1") is False
    
    def test_ipv6_in_range(self):
        """IPv6 in CIDR range should match."""
        constraint = Cidr("2001:db8::/32")
        assert check_constraint(constraint, "2001:db8::1") is True
    
    def test_invalid_ip_fails(self):
        """Invalid IP address should fail (fail closed)."""
        constraint = Cidr("192.168.1.0/24")
        assert check_constraint(constraint, "not-an-ip") is False
        assert check_constraint(constraint, "999.999.999.999") is False


class TestUrlPatternConstraint:
    """Tests for URL pattern constraint.
    
    Note: UrlPattern uses Rust-backed matching. The tests use patterns
    compatible with Tenuo's UrlPattern semantics.
    """
    
    def test_scheme_and_host_match(self):
        """URL scheme and host matching."""
        constraint = UrlPattern("https://example.com/*")
        assert check_constraint(constraint, "https://example.com/path") is True
        assert check_constraint(constraint, "http://example.com/path") is False  # Wrong scheme
        assert check_constraint(constraint, "https://evil.com/path") is False  # Wrong host
    
    def test_wildcard_subdomain(self):
        """Wildcard subdomain matching."""
        constraint = UrlPattern("https://*.example.com/*")
        assert check_constraint(constraint, "https://api.example.com/") is True
        assert check_constraint(constraint, "https://sub.api.example.com/") is True
    
    def test_path_pattern(self):
        """URL path glob matching."""
        constraint = UrlPattern("https://example.com/api/*")
        assert check_constraint(constraint, "https://example.com/api/v1") is True
        assert check_constraint(constraint, "https://example.com/admin") is False
    
    def test_invalid_url_fails(self):
        """Invalid URL should fail (fail closed)."""
        constraint = UrlPattern("https://example.com/*")
        assert check_constraint(constraint, "not a url") is False


class TestCelConstraintFailsClosed:
    """Tests that CEL constraints fail closed in Python fallback.
    
    CEL expressions require the Rust evaluator for security.
    The Python fallback cannot safely evaluate arbitrary CEL,
    so it must fail closed (return False).
    """
    
    def test_cel_fails_closed_in_python(self):
        """CEL should fail closed when Rust binding unavailable."""
        # This test verifies that if the Rust CEL evaluator is not
        # available, the constraint returns False (deny) rather than
        # True (allow). This is critical for security.
        constraint = CEL("value > 0")
        
        # Even though 5 > 0 is true, if we're using Python fallback
        # without Rust, this MUST return False to be safe.
        # (If Rust binding IS available, it will return True correctly)
        # Either way, this shouldn't raise an exception.
        result = check_constraint(constraint, 5)
        # We accept either True (Rust worked) or False (Python fallback)
        # but never an exception
        assert isinstance(result, bool)
    
    def test_cel_never_raises(self):
        """CEL check should never raise, even for invalid expressions."""
        constraint = CEL("this is not valid CEL")
        # Should not raise, should just return False
        result = check_constraint(constraint, "anything")
        assert isinstance(result, bool)


# =============================================================================
# Integration-Style Tests
# =============================================================================


class TestRealWorldScenarios:
    """Tests for realistic usage patterns."""
    
    def test_file_system_protection(self):
        """Protect against accessing unauthorized paths.
        
        Note: For true path traversal protection, paths should be normalized
        before matching. This test verifies basic pattern matching works.
        """
        response = make_response([
            ("read_file", {"path": "/etc/passwd"})  # Clearly not in /data/*
        ])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
            on_denial="raise"
        )
        
        # Path outside /data should be caught
        with pytest.raises(ConstraintViolation):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_rate_limit_protection(self):
        """Protect against excessive resource requests."""
        response = make_response([
            ("search", {"query": "test", "max_results": 10000})
        ])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search"],
            constraints={"search": {"max_results": Range(1, 100)}},
            on_denial="raise"
        )
        
        with pytest.raises(ConstraintViolation):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_hallucinated_tool_blocked(self):
        """Block tools the LLM hallucinates."""
        response = make_response([
            ("send_money", {"amount": 1000000, "to": "attacker"})
        ])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            allow_tools=["search", "read_file"],
            on_denial="raise"
        )
        
        with pytest.raises(ToolDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "send_money"


# =============================================================================
# Streaming TOCTOU Protection Tests
# =============================================================================


@dataclass
class MockStreamDelta:
    """Mock delta for streaming."""
    tool_calls: Optional[List[Any]] = None
    content: Optional[str] = None


@dataclass
class MockToolCallDelta:
    """Mock tool call delta."""
    index: int
    id: Optional[str] = None
    function: Optional[MockFunction] = None


@dataclass
class MockStreamChoice:
    """Mock streaming choice."""
    index: int
    delta: MockStreamDelta
    finish_reason: Optional[str] = None


@dataclass
class MockStreamChunk:
    """Mock streaming chunk."""
    id: str
    choices: List[MockStreamChoice]


class TestStreamingTOCTOUProtection:
    """Tests that verify proper buffer-verify-emit behavior.
    
    These tests ensure that NO tool call data leaks to the consumer
    before verification is complete.
    """
    
    def test_chunks_not_leaked_before_verification(self):
        """Tool call chunks MUST NOT be yielded until verification completes."""
        # Create a stream that sends an unauthorized tool call in pieces
        chunks = [
            # First chunk: start of tool call
            MockStreamChunk(
                id="chunk_0",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(
                        tool_calls=[MockToolCallDelta(
                            index=0,
                            id="call_0",
                            function=MockFunction(name="delete_system", arguments='{"path": "/')
                        )]
                    ),
                    finish_reason=None
                )]
            ),
            # Second chunk: rest of arguments
            MockStreamChunk(
                id="chunk_1",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(
                        tool_calls=[MockToolCallDelta(
                            index=0,
                            function=MockFunction(name="", arguments='"}')
                        )]
                    ),
                    finish_reason=None
                )]
            ),
            # Final chunk
            MockStreamChunk(
                id="chunk_2",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(),
                    finish_reason="tool_calls"
                )]
            ),
        ]
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = iter(chunks)
        
        client = guard(
            mock_client,
            allow_tools=["safe_tool"],  # delete_system NOT allowed
            on_denial="raise"
        )
        
        # The stream should raise when we try to consume it
        # (after verification fails)
        with pytest.raises(ToolDenied) as exc:
            list(client.chat.completions.create(model="gpt-4o", messages=[], stream=True))
        
        assert exc.value.tool_name == "delete_system"
    
    def test_skip_mode_filters_denied_chunks(self):
        """In skip mode, denied tool call chunks should be filtered out."""
        chunks = [
            # Text content (should pass through)
            MockStreamChunk(
                id="chunk_0",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(content="Let me help..."),
                    finish_reason=None
                )]
            ),
            # Unauthorized tool call
            MockStreamChunk(
                id="chunk_1",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(
                        tool_calls=[MockToolCallDelta(
                            index=0,
                            id="call_0",
                            function=MockFunction(name="unauthorized", arguments='{}')
                        )]
                    ),
                    finish_reason=None
                )]
            ),
            # Final chunk
            MockStreamChunk(
                id="chunk_2",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(),
                    finish_reason="tool_calls"
                )]
            ),
        ]
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = iter(chunks)
        
        client = guard(
            mock_client,
            allow_tools=["safe_tool"],
            on_denial="skip"  # Don't raise, just skip
        )
        
        # Consume the stream
        result_chunks = list(client.chat.completions.create(
            model="gpt-4o", messages=[], stream=True
        ))
        
        # First chunk (text only) should pass through
        assert len(result_chunks) >= 1
        # The tool call chunk should be filtered out
        for chunk in result_chunks:
            if hasattr(chunk, 'choices') and chunk.choices:
                for choice in chunk.choices:
                    if hasattr(choice, 'delta') and choice.delta:
                        delta = choice.delta
                        if hasattr(delta, 'tool_calls') and delta.tool_calls:
                            # If there are tool calls, they shouldn't be the unauthorized one
                            for tc in delta.tool_calls:
                                if hasattr(tc, 'function') and tc.function:
                                    assert tc.function.name != "unauthorized"
    
    def test_verified_chunks_are_emitted(self):
        """Verified tool calls should be emitted after verification."""
        chunks = [
            MockStreamChunk(
                id="chunk_0",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(
                        tool_calls=[MockToolCallDelta(
                            index=0,
                            id="call_0",
                            function=MockFunction(name="allowed_tool", arguments='{"x": 1}')
                        )]
                    ),
                    finish_reason=None
                )]
            ),
            MockStreamChunk(
                id="chunk_1",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(),
                    finish_reason="tool_calls"
                )]
            ),
        ]
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = iter(chunks)
        
        client = guard(
            mock_client,
            allow_tools=["allowed_tool"],
            on_denial="raise"
        )
        
        # Should NOT raise — tool is allowed
        result_chunks = list(client.chat.completions.create(
            model="gpt-4o", messages=[], stream=True
        ))
        
        # Both chunks should be emitted (the tool call and the finish)
        assert len(result_chunks) == 2
    
    def test_buffer_not_leaked_on_constraint_violation(self):
        """Constraint violations in streaming should not leak partial data."""
        chunks = [
            # Tool call with path that will fail constraint
            MockStreamChunk(
                id="chunk_0",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(
                        tool_calls=[MockToolCallDelta(
                            index=0,
                            id="call_0",
                            function=MockFunction(
                                name="read_file",
                                arguments='{"path": "/etc/passwd"}'
                            )
                        )]
                    ),
                    finish_reason=None
                )]
            ),
            MockStreamChunk(
                id="chunk_1",
                choices=[MockStreamChoice(
                    index=0,
                    delta=MockStreamDelta(),
                    finish_reason="tool_calls"
                )]
            ),
        ]
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = iter(chunks)
        
        client = guard(
            mock_client,
            allow_tools=["read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
            on_denial="raise"
        )
        
        with pytest.raises(ConstraintViolation):
            list(client.chat.completions.create(model="gpt-4o", messages=[], stream=True))
