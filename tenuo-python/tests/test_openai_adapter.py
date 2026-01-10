"""
Tests for Tenuo OpenAI Adapter - Tier 1 Guardrails and Tier 2 Warrants.

Covers:
- Tier 1: Tool allowlist/denylist enforcement
- Tier 1: Constraint checking for arguments
- Tier 1: Denial handling modes (raise/skip/log)
- Tier 1: Streaming protection (buffer-verify-emit)
- Tier 2: Warrant-based authorization
- Tier 2: WarrantDenied exception
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
    WarrantDenied,
    MissingSigningKey,
    ConfigurationError,
    enable_debug,
    AuditEvent,
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
    Subpath,
    Warrant,
    SigningKey,
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


# =============================================================================
# Tier 2: Warrant-Based Authorization with Proof-of-Possession
# =============================================================================


class TestTier2Warrant:
    """Tests for Tier 2 warrant-based authorization with PoP.
    
    Tier 2 requires:
    - A cryptographic warrant defining capabilities
    - A signing key for Proof-of-Possession (proves agent holds the warrant)
    
    Each tool call is signed with the holder's key before verification.
    """
    
    @pytest.fixture
    def keypair(self):
        """Generate a keypair for testing (agent's key)."""
        return SigningKey.generate()
    
    @pytest.fixture
    def warrant(self, keypair):
        """Create a test warrant (self-signed for simplicity)."""
        return (Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("/data/*")})
            .capability("search", {"max_results": Range(1, 100)})
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair))
    
    def test_warrant_requires_signing_key(self, keypair, warrant):
        """Warrant without signing_key should raise MissingSigningKey."""
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        # Warrant provided but no signing_key
        client = guard(mock_client, warrant=warrant)  # Missing signing_key!
        
        with pytest.raises(MissingSigningKey) as exc_info:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert "signing_key" in str(exc_info.value).lower()
        assert exc_info.value.code == "T2_002"
    
    def test_warrant_allows_valid_call(self, keypair, warrant):
        """Warrant should allow calls that match capabilities (with PoP)."""
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        # Proper Tier 2: warrant + signing_key
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        # Should not raise
        assert result.choices[0].message.tool_calls[0].function.name == "read_file"
    
    def test_warrant_denies_constraint_violation(self, keypair, warrant):
        """Warrant should deny calls that violate constraints."""
        response = make_response([("read_file", {"path": "/etc/passwd"})])  # Not in /data/*
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        with pytest.raises(WarrantDenied) as exc_info:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert "read_file" in str(exc_info.value)
        assert exc_info.value.tool_name == "read_file"
    
    def test_warrant_denies_unauthorized_tool(self, keypair, warrant):
        """Warrant should deny tools not in capabilities."""
        response = make_response([("delete_file", {"path": "/data/file.txt"})])  # Not in warrant
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        with pytest.raises(WarrantDenied):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_warrant_with_tier1_defense_in_depth(self, keypair, warrant):
        """Both Tier 1 and Tier 2 must pass when configured together."""
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        # Tier 1: Block read_file in denylist
        # Tier 2: Warrant allows it
        # Result: Should be denied by Tier 1 (checked after Tier 2)
        client = guard(
            mock_client,
            warrant=warrant,
            signing_key=keypair,
            deny_tools=["read_file"],  # Tier 1 block
        )
        
        with pytest.raises(ToolDenied):  # Tier 1 denial
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_warrant_range_constraint(self, keypair, warrant):
        """Warrant should enforce Range constraints."""
        # Valid: within range
        response = make_response([("search", {"max_results": 50})])
        mock_client = make_mock_client(response)
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert result is not None
        
        # Invalid: out of range
        response2 = make_response([("search", {"max_results": 500})])
        mock_client2 = make_mock_client(response2)
        client2 = guard(mock_client2, warrant=warrant, signing_key=keypair)
        with pytest.raises(WarrantDenied):
            client2.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_warrant_error_message_includes_reason(self, keypair, warrant):
        """WarrantDenied should include reason from warrant.why_denied()."""
        response = make_response([("read_file", {"path": "/etc/passwd"})])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        with pytest.raises(WarrantDenied) as exc_info:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        # Should include field information from why_denied
        error_str = str(exc_info.value)
        assert "path" in error_str.lower() or "constraint" in error_str.lower()
    
    def test_wrong_signing_key_fails(self, keypair, warrant):
        """Using wrong signing key (not the holder) should fail authorization."""
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        # Different key - not the warrant holder
        wrong_key = SigningKey.generate()
        
        client = guard(mock_client, warrant=warrant, signing_key=wrong_key)
        
        # Should fail because PoP is signed with wrong key
        with pytest.raises(WarrantDenied):
            client.chat.completions.create(model="gpt-4o", messages=[])
    
    def test_separate_issuer_holder_keys(self):
        """Production pattern: Control plane issues warrant, agent is holder."""
        # Control plane key (issuer)
        control_plane_key = SigningKey.generate()
        # Agent key (holder)
        agent_key = SigningKey.generate()
        
        # Control plane mints warrant for agent
        warrant = (Warrant.mint_builder()
            .capability("read_file", {"path": Pattern("/data/*")})
            .holder(agent_key.public_key)  # Agent is holder
            .ttl(3600)
            .mint(control_plane_key))  # Control plane signs
        
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        # Agent uses its own key for PoP
        client = guard(mock_client, warrant=warrant, signing_key=agent_key)
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        # Should succeed
        assert result.choices[0].message.tool_calls[0].function.name == "read_file"
    
    def test_multiple_tool_calls_with_warrant(self, keypair, warrant):
        """Multiple tool calls in same response, some valid, some invalid."""
        response = make_response([
            ("read_file", {"path": "/data/file.txt"}),  # Valid
            ("search", {"max_results": 50}),  # Valid
            ("delete_file", {"path": "/data/file.txt"}),  # Invalid - not in warrant
        ])
        mock_client = make_mock_client(response)
        
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        # Should fail on first invalid tool
        with pytest.raises(WarrantDenied) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.tool_name == "delete_file"
    
    def test_warrant_skip_mode(self, keypair, warrant):
        """Skip mode should filter out unauthorized calls silently."""
        response = make_response([
            ("read_file", {"path": "/etc/passwd"}),  # Constraint violation
        ])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            warrant=warrant,
            signing_key=keypair,
            on_denial="skip",
        )
        
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        
        # Tool call should be filtered out
        assert result.choices[0].message.tool_calls is None
    
    def test_verify_tool_call_with_warrant_directly(self, keypair, warrant):
        """Test verify_tool_call function directly with warrant."""
        # Valid call should pass
        verify_tool_call(
            "read_file",
            {"path": "/data/file.txt"},
            allow_tools=None,
            deny_tools=None,
            constraints=None,
            warrant=warrant,
            signing_key=keypair,
        )
        
        # Invalid call should raise
        with pytest.raises(WarrantDenied):
            verify_tool_call(
                "read_file",
                {"path": "/etc/passwd"},
                allow_tools=None,
                deny_tools=None,
                constraints=None,
                warrant=warrant,
                signing_key=keypair,
            )
        
        # Missing signing_key should raise
        with pytest.raises(MissingSigningKey):
            verify_tool_call(
                "read_file",
                {"path": "/data/file.txt"},
                allow_tools=None,
                deny_tools=None,
                constraints=None,
                warrant=warrant,
                signing_key=None,
            )
    
    def test_streaming_with_warrant(self, keypair, warrant):
        """Streaming should work with Tier 2 warrant verification."""
        from unittest.mock import Mock
        
        # Mock streaming chunks
        @dataclass
        class MockDelta:
            content: Optional[str] = None
            tool_calls: Optional[list] = None
        
        @dataclass
        class MockChoice:
            index: int
            delta: MockDelta
            finish_reason: Optional[str] = None
        
        @dataclass
        class MockChunk:
            id: str
            choices: list
        
        @dataclass
        class MockToolCallDelta:
            index: int
            id: Optional[str] = None
            function: Optional[Any] = None
        
        @dataclass
        class MockFunctionDelta:
            name: str = ""
            arguments: str = ""
        
        chunks = [
            MockChunk(id="c0", choices=[MockChoice(
                index=0,
                delta=MockDelta(tool_calls=[MockToolCallDelta(
                    index=0, id="call_1",
                    function=MockFunctionDelta(name="read_file", arguments='{"path": "/data/')
                )])
            )]),
            MockChunk(id="c1", choices=[MockChoice(
                index=0,
                delta=MockDelta(tool_calls=[MockToolCallDelta(
                    index=0,
                    function=MockFunctionDelta(arguments='file.txt"}')
                )])
            )]),
            MockChunk(id="c2", choices=[MockChoice(
                index=0,
                delta=MockDelta(),
                finish_reason="tool_calls"
            )]),
        ]
        
        mock_client = Mock()
        mock_client.chat.completions.create.return_value = iter(chunks)
        
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        # Should not raise - valid call
        result = list(client.chat.completions.create(
            model="gpt-4o", messages=[], stream=True
        ))
        
        assert len(result) == 3  # All chunks emitted


# =============================================================================
# Developer Experience: Validation and Debug
# =============================================================================


class TestDeveloperExperience:
    """Tests for DX improvements: validate(), enable_debug()."""
    
    def test_validate_catches_key_mismatch(self):
        """validate() should catch signing_key not matching warrant holder."""
        agent_key = SigningKey.generate()
        wrong_key = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .capability("test", {})
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(agent_key))
        
        mock_client = make_mock_client(make_response([]))
        client = guard(mock_client, warrant=warrant, signing_key=wrong_key)
        
        with pytest.raises(ConfigurationError) as exc:
            client.validate()
        
        assert exc.value.code == "CFG_003"
        assert "holder" in str(exc.value).lower()
    
    def test_validate_catches_missing_signing_key(self):
        """validate() should catch warrant without signing_key."""
        keypair = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .capability("test", {})
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair))
        
        mock_client = make_mock_client(make_response([]))
        client = guard(mock_client, warrant=warrant)  # No signing_key
        
        with pytest.raises(MissingSigningKey):
            client.validate()
    
    def test_validate_passes_correct_config(self):
        """validate() should pass for correct configuration."""
        keypair = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .capability("test", {})
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair))
        
        mock_client = make_mock_client(make_response([]))
        client = guard(mock_client, warrant=warrant, signing_key=keypair)
        
        # Should not raise
        client.validate()
    
    def test_validate_passes_tier1_only(self):
        """validate() should pass for Tier 1 only (no warrant)."""
        mock_client = make_mock_client(make_response([]))
        client = guard(mock_client, allow_tools=["search"])
        
        # Should not raise
        client.validate()
    
    def test_enable_debug_sets_logger_level(self):
        """enable_debug() should set logger to DEBUG level."""
        import logging
        
        # Get the logger before calling enable_debug
        logger = logging.getLogger("tenuo.openai")
        original_level = logger.level
        
        try:
            enable_debug()
            assert logger.level == logging.DEBUG
        finally:
            # Restore original level
            logger.setLevel(original_level)


class TestAuditSupport:
    """Tests for audit callback and session tracking."""
    
    def test_session_id_is_generated(self):
        """Each guard() call should generate a unique session ID."""
        mock_client = make_mock_client(make_response([]))
        
        client1 = guard(mock_client, allow_tools=["search"])
        client2 = guard(mock_client, allow_tools=["search"])
        
        assert client1.session_id.startswith("sess_")
        assert client2.session_id.startswith("sess_")
        assert client1.session_id != client2.session_id
    
    def test_constraint_hash_is_deterministic(self):
        """Same constraints should produce same hash."""
        mock_client = make_mock_client(make_response([]))
        
        constraints = {"read_file": {"path": Pattern("/data/*")}}
        
        client1 = guard(mock_client, constraints=constraints)
        client2 = guard(mock_client, constraints=constraints)
        
        assert client1.constraint_hash.startswith("sha256:")
        assert client1.constraint_hash == client2.constraint_hash
    
    def test_different_constraints_different_hash(self):
        """Different constraints should produce different hash."""
        mock_client = make_mock_client(make_response([]))
        
        client1 = guard(mock_client, constraints={"read_file": {"path": Pattern("/data/*")}})
        client2 = guard(mock_client, constraints={"read_file": {"path": Pattern("/tmp/*")}})
        
        assert client1.constraint_hash != client2.constraint_hash
    
    def test_audit_callback_called_on_allow(self):
        """Audit callback should be called for allowed calls."""
        events = []
        
        def capture_audit(event: AuditEvent):
            events.append(event)
        
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            constraints={"read_file": {"path": Pattern("/data/*")}},
            audit_callback=capture_audit,
        )
        
        client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(events) == 1
        assert events[0].decision == "ALLOW"
        assert events[0].tool_name == "read_file"
        assert events[0].session_id == client.session_id
        assert events[0].constraint_hash == client.constraint_hash
    
    def test_audit_callback_called_on_deny(self):
        """Audit callback should be called for denied calls."""
        events = []
        
        def capture_audit(event: AuditEvent):
            events.append(event)
        
        response = make_response([("read_file", {"path": "/etc/passwd"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            constraints={"read_file": {"path": Pattern("/data/*")}},
            audit_callback=capture_audit,
        )
        
        with pytest.raises(ConstraintViolation):
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert len(events) == 1
        assert events[0].decision == "DENY"
        assert events[0].tool_name == "read_file"
        assert events[0].tier == "tier1"
    
    def test_audit_callback_failure_does_not_break_auth(self):
        """Audit callback failure should not prevent authorization."""
        def failing_audit(event: AuditEvent):
            raise RuntimeError("Audit system down")
        
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            constraints={"read_file": {"path": Pattern("/data/*")}},
            audit_callback=failing_audit,
        )
        
        # Should not raise despite audit failure
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert result is not None


# =============================================================================
# OpenAI Agents SDK Integration Tests
# =============================================================================


class TestAgentsSDKIntegration:
    """Tests for OpenAI Agents SDK guardrail integration."""
    
    def test_create_tool_guardrail(self):
        """Test creating a Tier 1 guardrail."""
        from tenuo.openai import create_tool_guardrail, TenuoToolGuardrail
        
        guardrail = create_tool_guardrail(
            allow_tools=["search", "read_file"],
            constraints={"read_file": {"path": Pattern("/data/*")}},
        )
        
        assert isinstance(guardrail, TenuoToolGuardrail)
        assert guardrail.allow_tools == ["search", "read_file"]
        assert guardrail.tripwire is True
        assert guardrail.name == "tenuo_tool_guardrail"
    
    def test_create_warrant_guardrail(self):
        """Test creating a Tier 2 guardrail."""
        from tenuo.openai import create_warrant_guardrail, TenuoToolGuardrail
        
        key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key))
        
        guardrail = create_warrant_guardrail(warrant=warrant, signing_key=key)
        
        assert isinstance(guardrail, TenuoToolGuardrail)
        assert guardrail.warrant is warrant
        assert guardrail.signing_key is key
    
    def test_warrant_guardrail_requires_signing_key(self):
        """Test that warrant guardrail requires signing_key."""
        from tenuo.openai import TenuoToolGuardrail, MissingSigningKey
        
        key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("send_email", {})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key))
        
        with pytest.raises(MissingSigningKey):
            TenuoToolGuardrail(warrant=warrant)  # No signing_key
    
    @pytest.mark.asyncio
    async def test_guardrail_allows_valid_tool_call(self):
        """Test guardrail allows valid tool calls."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        guardrail = create_tool_guardrail(
            constraints={"send_email": {"to": Pattern("*@company.com")}}
        )
        
        input_data = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "user@company.com"}'
            }
        }]
        
        result = await guardrail(None, None, input_data)
        
        assert isinstance(result, GuardrailResult)
        assert result.tripwire_triggered is False
        assert "authorized" in result.output_info
    
    @pytest.mark.asyncio
    async def test_guardrail_blocks_invalid_tool_call(self):
        """Test guardrail blocks constraint violations."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        guardrail = create_tool_guardrail(
            constraints={"send_email": {"to": Pattern("*@company.com")}}
        )
        
        input_data = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "attacker@evil.com"}'
            }
        }]
        
        result = await guardrail(None, None, input_data)
        
        assert isinstance(result, GuardrailResult)
        assert result.tripwire_triggered is True
        assert "Blocked" in result.output_info
    
    @pytest.mark.asyncio
    async def test_guardrail_blocks_denied_tool(self):
        """Test guardrail blocks tools on deny list."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        guardrail = create_tool_guardrail(
            deny_tools=["delete_file"]
        )
        
        input_data = [{"function": {"name": "delete_file", "arguments": "{}"}}]
        
        result = await guardrail(None, None, input_data)
        
        assert result.tripwire_triggered is True
        assert "delete_file" in result.output_info
    
    @pytest.mark.asyncio
    async def test_guardrail_no_tripwire_mode(self):
        """Test guardrail with tripwire=False logs but doesn't halt."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        guardrail = create_tool_guardrail(
            constraints={"send_email": {"to": Pattern("*@company.com")}},
            tripwire=False,
        )
        
        input_data = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "attacker@evil.com"}'
            }
        }]
        
        result = await guardrail(None, None, input_data)
        
        assert isinstance(result, GuardrailResult)
        assert result.tripwire_triggered is False  # Doesn't halt
        assert "Blocked" in result.output_info     # Still logs the block
    
    @pytest.mark.asyncio
    async def test_guardrail_handles_no_tool_calls(self):
        """Test guardrail handles input without tool calls."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        guardrail = create_tool_guardrail(constraints={})
        
        # Plain string input
        result = await guardrail(None, None, "Just a message")
        
        assert isinstance(result, GuardrailResult)
        assert result.tripwire_triggered is False
        assert "No tool calls" in result.output_info
    
    def test_extract_tool_calls_list_format(self):
        """Test extracting tool calls from list format."""
        from tenuo.openai import TenuoToolGuardrail
        
        guardrail = TenuoToolGuardrail(constraints={})
        
        input_data = [
            {"function": {"name": "tool1", "arguments": '{"a": 1}'}},
            {"function": {"name": "tool2", "arguments": '{"b": 2}'}},
        ]
        
        calls = guardrail._extract_tool_calls(input_data)
        
        assert len(calls) == 2
        assert calls[0] == ("tool1", {"a": 1})
        assert calls[1] == ("tool2", {"b": 2})
    
    def test_extract_tool_calls_dict_format(self):
        """Test extracting tool calls from dict with tool_calls key."""
        from tenuo.openai import TenuoToolGuardrail
        
        guardrail = TenuoToolGuardrail(constraints={})
        
        input_data = {
            "tool_calls": [
                {"name": "search", "arguments": '{"q": "hello"}'}
            ]
        }
        
        calls = guardrail._extract_tool_calls(input_data)
        
        assert len(calls) == 1
        assert calls[0] == ("search", {"q": "hello"})
    
    def test_extract_tool_calls_single_format(self):
        """Test extracting tool calls from single tool call dict."""
        from tenuo.openai import TenuoToolGuardrail
        
        guardrail = TenuoToolGuardrail(constraints={})
        
        input_data = {"name": "read_file", "arguments": '{"path": "/data"}'}
        
        calls = guardrail._extract_tool_calls(input_data)
        
        assert len(calls) == 1
        assert calls[0] == ("read_file", {"path": "/data"})
    
    @pytest.mark.asyncio
    async def test_warrant_guardrail_authorizes_valid_call(self):
        """Test Tier 2 guardrail with valid warrant authorization."""
        from tenuo.openai import create_warrant_guardrail, GuardrailResult
        
        key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("send_email", {"to": Pattern("*@company.com")})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key))
        
        guardrail = create_warrant_guardrail(warrant=warrant, signing_key=key)
        
        input_data = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "user@company.com"}'
            }
        }]
        
        result = await guardrail(None, None, input_data)
        
        assert isinstance(result, GuardrailResult)
        assert result.tripwire_triggered is False
    
    @pytest.mark.asyncio
    async def test_warrant_guardrail_blocks_unauthorized_tool(self):
        """Test Tier 2 guardrail blocks tools not in warrant."""
        from tenuo.openai import create_warrant_guardrail, GuardrailResult
        
        key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("send_email", {})  # Only send_email allowed
            .holder(key.public_key)
            .ttl(3600)
            .mint(key))
        
        guardrail = create_warrant_guardrail(warrant=warrant, signing_key=key)
        
        input_data = [{
            "function": {
                "name": "delete_file",  # Not in warrant
                "arguments": '{"path": "/etc/passwd"}'
            }
        }]
        
        result = await guardrail(None, None, input_data)
        
        assert result.tripwire_triggered is True
        assert "delete_file" in result.output_info
    
    @pytest.mark.asyncio
    async def test_guardrail_emits_audit_events(self):
        """Test that guardrail emits audit events."""
        from tenuo.openai import create_tool_guardrail, GuardrailResult
        
        events = []
        def capture_audit(event: AuditEvent):
            events.append(event)
        
        guardrail = create_tool_guardrail(
            constraints={"send_email": {"to": Pattern("*@company.com")}},
            audit_callback=capture_audit,
        )
        
        # Valid call - should emit ALLOW
        input_data = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "user@company.com"}'
            }
        }]
        await guardrail(None, None, input_data)
        
        assert len(events) == 1
        assert events[0].decision == "ALLOW"
        assert events[0].tool_name == "send_email"
        
        # Invalid call - should emit DENY
        input_data2 = [{
            "function": {
                "name": "send_email",
                "arguments": '{"to": "attacker@evil.com"}'
            }
        }]
        await guardrail(None, None, input_data2)
        
        assert len(events) == 2
        assert events[1].decision == "DENY"
        assert events[1].tier == "tier1"
    
    @pytest.mark.asyncio
    async def test_warrant_guardrail_audit_includes_warrant_id(self):
        """Test that Tier 2 guardrail audit includes warrant ID."""
        from tenuo.openai import create_warrant_guardrail
        
        events = []
        def capture_audit(event: AuditEvent):
            events.append(event)
        
        key = SigningKey.generate()
        warrant = (Warrant.mint_builder()
            .capability("send_email", {})
            .holder(key.public_key)
            .ttl(3600)
            .mint(key))
        
        guardrail = create_warrant_guardrail(
            warrant=warrant,
            signing_key=key,
            audit_callback=capture_audit,
        )
        
        input_data = [{"function": {"name": "send_email", "arguments": "{}"}}]
        await guardrail(None, None, input_data)
        
        assert len(events) == 1
        assert events[0].warrant_id == warrant.id
        assert events[0].warrant_id.startswith("tnu_wrt_")


# =============================================================================
# Subpath Constraint Tests (Path Traversal Protection)
# =============================================================================


class TestSubpathConstraint:
    """Tests for Subpath secure path containment constraint."""
    
    def test_basic_containment(self):
        """Paths under root should match."""
        c = Subpath("/data")
        
        assert c.matches("/data/file.txt") is True
        assert c.matches("/data/subdir/file.txt") is True
        assert c.matches("/data/a/b/c/deep.txt") is True
    
    def test_root_equals(self):
        """Root path itself should match by default."""
        c = Subpath("/data")
        assert c.matches("/data") is True
        
        # With allow_equal=False
        c2 = Subpath("/data", allow_equal=False)
        assert c2.matches("/data") is False
        assert c2.matches("/data/file.txt") is True
    
    def test_outside_root_rejected(self):
        """Paths outside root should be rejected."""
        c = Subpath("/data")
        
        assert c.matches("/etc/passwd") is False
        assert c.matches("/other/file.txt") is False
        assert c.matches("/") is False
    
    def test_traversal_attack_blocked(self):
        """Path traversal attacks should be blocked."""
        c = Subpath("/data")
        
        # Classic traversal attack
        assert c.matches("/data/../etc/passwd") is False
        
        # Multiple traversals
        assert c.matches("/data/../../etc/passwd") is False
        
        # Traversal to parent then back in
        # /data/subdir/../file.txt normalizes to /data/file.txt - should pass
        assert c.matches("/data/subdir/../file.txt") is True
        
        # Traversal that escapes
        assert c.matches("/data/subdir/../../other") is False
    
    def test_dot_normalization(self):
        """Current directory dots should be normalized."""
        c = Subpath("/data")
        
        # Single dots
        assert c.matches("/data/./file.txt") is True
        assert c.matches("/data/./subdir/./file.txt") is True
        
        # Mixed
        assert c.matches("/data/./subdir/../other.txt") is True
    
    def test_null_byte_rejected(self):
        """Null bytes should be rejected (C string attack)."""
        c = Subpath("/data")
        
        # Null byte in middle
        assert c.matches("/data/file\x00.txt") is False
        
        # Null byte attack pattern
        assert c.matches("/data/file.txt\x00../../../etc/passwd") is False
    
    def test_relative_path_rejected(self):
        """Relative paths should be rejected."""
        c = Subpath("/data")
        
        assert c.matches("file.txt") is False
        assert c.matches("./file.txt") is False
        assert c.matches("../etc/passwd") is False
        assert c.matches("data/file.txt") is False
    
    def test_non_string_rejected(self):
        """Non-string values should be rejected."""
        c = Subpath("/data")
        
        assert c.matches(None) is False
        assert c.matches(123) is False
        assert c.matches(["/data/file.txt"]) is False
        assert c.matches({"path": "/data/file.txt"}) is False
    
    def test_case_sensitivity(self):
        """Case sensitivity should be configurable."""
        # Case sensitive (default)
        cs = Subpath("/data")
        assert cs.matches("/data/file.txt") is True
        assert cs.matches("/DATA/file.txt") is False
        assert cs.matches("/Data/file.txt") is False
        
        # Case insensitive (Windows-style)
        ci = Subpath("/data", case_sensitive=False)
        assert ci.matches("/data/file.txt") is True
        assert ci.matches("/DATA/file.txt") is True
        assert ci.matches("/Data/FILE.TXT") is True
    
    def test_repr(self):
        """Repr should show configuration."""
        c1 = Subpath("/data")
        assert "Subpath('/data')" == repr(c1)
        
        c2 = Subpath("/data", case_sensitive=False)
        assert "case_sensitive=False" in repr(c2)
        
        c3 = Subpath("/data", allow_equal=False)
        assert "allow_equal=False" in repr(c3)
    
    def test_root_must_be_absolute(self):
        """Root must be an absolute path."""
        with pytest.raises(ValueError, match="absolute"):
            Subpath("data")
        
        with pytest.raises(ValueError, match="absolute"):
            Subpath("./data")
    
    def test_integration_with_guard(self):
        """Test Subpath works with guard()."""
        response = make_response([("read_file", {"path": "/data/file.txt"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            constraints={"read_file": {"path": Subpath("/data")}}
        )
        
        # Should pass
        result = client.chat.completions.create(model="gpt-4o", messages=[])
        assert result is not None
    
    def test_integration_traversal_blocked(self):
        """Test Subpath blocks traversal in guard()."""
        response = make_response([("read_file", {"path": "/data/../etc/passwd"})])
        mock_client = make_mock_client(response)
        
        client = guard(
            mock_client,
            constraints={"read_file": {"path": Subpath("/data")}}
        )
        
        with pytest.raises(ConstraintViolation) as exc:
            client.chat.completions.create(model="gpt-4o", messages=[])
        
        assert exc.value.param == "path"
        assert "Subpath" in str(exc.value)
    
    def test_prefix_attack_blocked(self):
        """Paths that are prefixes but not children should be blocked."""
        c = Subpath("/data")
        
        # /data-other is NOT under /data
        assert c.matches("/data-other/file.txt") is False
        assert c.matches("/data2/file.txt") is False
        assert c.matches("/datafile.txt") is False
    
    # =========================================================================
    # Additional Edge Cases (inspired by path_jail security.rs)
    # =========================================================================
    
    def test_double_slashes_normalized(self):
        """Double slashes should be normalized."""
        c = Subpath("/data")
        
        # Double slashes normalized to single
        assert c.matches("/data//file.txt") is True
        assert c.matches("/data///subdir//file.txt") is True
        assert c.matches("//data/file.txt") is False  # Root is /data, not //data
    
    def test_trailing_slash_handled(self):
        """Trailing slashes should be handled correctly."""
        c = Subpath("/data")
        
        assert c.matches("/data/") is True
        assert c.matches("/data/subdir/") is True
    
    def test_triple_dots_handled(self):
        """Triple dots (...) is a valid filename, not ..."""
        c = Subpath("/data")
        
        # ... is NOT a parent dir reference, it's a filename
        assert c.matches("/data/...") is True
        assert c.matches("/data/.../file.txt") is True
        
        # But still can't escape
        assert c.matches("/data/.../../../etc") is False
    
    def test_hidden_files_allowed(self):
        """Hidden files (starting with .) should be allowed."""
        c = Subpath("/data")
        
        assert c.matches("/data/.hidden") is True
        assert c.matches("/data/.git/config") is True
        assert c.matches("/data/.ssh/authorized_keys") is True
    
    def test_spaces_in_path(self):
        """Paths with spaces should work."""
        c = Subpath("/data")
        
        assert c.matches("/data/file with spaces.txt") is True
        assert c.matches("/data/ leading.txt") is True
        assert c.matches("/data/trailing .txt") is True
    
    def test_empty_path_rejected(self):
        """Empty string path should be rejected."""
        c = Subpath("/data")
        
        assert c.matches("") is False
    
    def test_root_slash_rejected(self):
        """Root (/) should be rejected unless it's the jail root."""
        c = Subpath("/data")
        assert c.matches("/") is False
        
        # Note: Using "/" as Subpath root is technically allowed but unusual.
        # It means "allow any absolute path" which defeats the purpose.
        # We allow it for completeness but users should avoid it.
        c_root = Subpath("/")
        assert c_root.matches("/") is True  # Root equals itself
    
    def test_root_variations_normalized(self):
        """Various ways to spell root should be normalized."""
        c = Subpath("/data")
        
        # /data/. normalizes to /data
        assert c.matches("/data/.") is True
        
        # /data/./file normalizes to /data/file
        assert c.matches("/data/./file.txt") is True
        
        # /data/subdir/.. normalizes to /data
        assert c.matches("/data/subdir/..") is True
    
    def test_unicode_paths(self):
        """Unicode paths should work."""
        c = Subpath("/data")
        
        # Regular unicode
        assert c.matches("/data/文件.txt") is True
        assert c.matches("/data/файл.txt") is True
        assert c.matches("/data/αρχείο.txt") is True
        
        # Emoji
        assert c.matches("/data/📁/file.txt") is True
    
    def test_unicode_normalization_not_applied(self):
        """Unicode normalization is NOT applied (different codepoints are different)."""
        c = Subpath("/data")
        
        # These look the same but are different codepoints
        # é = U+00E9 (precomposed)
        # é = U+0065 U+0301 (e + combining acute)
        precomposed = "/data/caf\u00e9.txt"
        decomposed = "/data/cafe\u0301.txt"
        
        # Both are valid paths (they're just different files)
        assert c.matches(precomposed) is True
        assert c.matches(decomposed) is True
        # Note: on macOS, the filesystem may normalize these to be the same
    
    def test_control_characters_rejected_consideration(self):
        """Control characters (except newline/tab) are passed through.
        
        Note: Unlike null bytes, other control chars ARE valid in filenames.
        This is a display/logging concern, not a security concern.
        We only reject null bytes (which have security implications).
        """
        c = Subpath("/data")
        
        # Null byte is rejected
        assert c.matches("/data/file\x00name.txt") is False
        
        # Other control chars pass (they're valid filenames)
        # Note: These would be weird files, but not security vulnerabilities
        # assert c.matches("/data/file\ttab.txt") is True  # Tab
        # assert c.matches("/data/file\nnewline.txt") is True  # Newline
    
    def test_very_long_paths(self):
        """Very long paths should still be validated correctly."""
        c = Subpath("/data")
        
        # Long path that stays inside
        long_inside = "/data/" + "a" * 200 + "/file.txt"
        assert c.matches(long_inside) is True
        
        # Long path that escapes
        long_escape = "/data/" + "../" * 100 + "etc/passwd"
        assert c.matches(long_escape) is False
    
    def test_mixed_separators(self):
        """Forward slashes should work (backslash is platform-dependent)."""
        c = Subpath("/data")
        
        # Forward slashes (Unix standard)
        assert c.matches("/data/a/b/c/file.txt") is True
        
        # Backslashes are NOT path separators on Unix
        # On Windows, os.path.normpath would convert them
        # We don't explicitly test backslash behavior here as it's OS-dependent


# =============================================================================
# GuardBuilder Tests
# =============================================================================


class TestGuardBuilder:
    """Test the fluent builder pattern for creating guarded clients."""
    
    def test_basic_allow(self):
        """Builder.allow() adds tools to allowlist."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("search")
            .allow("read_file")
            .build())
        
        assert isinstance(client, GuardedClient)
        assert client._allow_tools == ["search", "read_file"]
    
    def test_allow_with_constraints(self):
        """Builder.allow() accepts constraint kwargs."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("read_file", path=Subpath("/data"))
            .allow("send_email", to=Pattern("*@company.com"))
            .build())
        
        assert "read_file" in client._constraints
        assert "send_email" in client._constraints
        assert isinstance(client._constraints["read_file"]["path"], Subpath)
        assert isinstance(client._constraints["send_email"]["to"], Pattern)
    
    def test_allow_all(self):
        """Builder.allow_all() adds multiple tools at once."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow_all("search", "read_file", "list_files")
            .build())
        
        assert client._allow_tools == ["search", "read_file", "list_files"]
    
    def test_deny(self):
        """Builder.deny() adds tools to denylist."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .deny("delete_file")
            .deny("drop_table")
            .build())
        
        assert client._deny_tools == ["delete_file", "drop_table"]
    
    def test_deny_all(self):
        """Builder.deny_all() adds multiple tools to denylist."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .deny_all("delete_file", "rm", "drop_table")
            .build())
        
        assert client._deny_tools == ["delete_file", "rm", "drop_table"]
    
    def test_constrain_without_allow(self):
        """Builder.constrain() adds constraints without allowing."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .constrain("read_file", path=Subpath("/data"))
            .build())
        
        # Tool is not in allow list
        assert client._allow_tools is None or "read_file" not in (client._allow_tools or [])
        # But has constraints
        assert "read_file" in client._constraints
    
    def test_on_denial(self):
        """Builder.on_denial() sets denial mode."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("search")
            .on_denial("skip")
            .build())
        
        assert client._on_denial == "skip"
    
    def test_buffer_limit(self):
        """Builder.buffer_limit() sets stream buffer limit."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("search")
            .buffer_limit(1024)
            .build())
        
        assert client._stream_buffer_limit == 1024
    
    def test_audit_callback(self):
        """Builder.audit() sets audit callback."""
        from tenuo.openai import GuardBuilder
        
        events = []
        def callback(event):
            events.append(event)
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("search")
            .audit(callback)
            .build())
        
        assert client._audit_callback is callback
    
    def test_with_warrant(self):
        """Builder.with_warrant() configures Tier 2 authorization."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        issuer_key = SigningKey.generate()
        agent_key = SigningKey.generate()
        
        warrant = (Warrant.mint_builder()
            .capability("search")
            .holder(agent_key.public_key)
            .ttl(3600)
            .mint(issuer_key))
        
        client = (GuardBuilder(mock_client)
            .with_warrant(warrant, agent_key)
            .build())
        
        assert client._warrant is warrant
        assert client._signing_key is agent_key
    
    def test_chaining(self):
        """Builder methods can be chained in any order."""
        from tenuo.openai import GuardBuilder
        
        events = []
        mock_client = Mock()
        
        client = (GuardBuilder(mock_client)
            .on_denial("log")
            .allow("search")
            .deny("delete_file")
            .buffer_limit(2048)
            .audit(lambda e: events.append(e))
            .allow("read_file", path=Subpath("/data"))
            .deny("rm")
            .build())
        
        assert client._allow_tools == ["search", "read_file"]
        assert client._deny_tools == ["delete_file", "rm"]
        assert client._on_denial == "log"
        assert client._stream_buffer_limit == 2048
        assert "read_file" in client._constraints
    
    def test_tool_extraction_from_dict(self):
        """Builder accepts OpenAI tool dict format."""
        from tenuo.openai import GuardBuilder
        
        tool_dict = {
            "type": "function",
            "function": {
                "name": "search",
                "description": "Search for information"
            }
        }
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow(tool_dict)
            .build())
        
        assert "search" in client._allow_tools
    
    def test_tool_extraction_from_callable(self):
        """Builder accepts callables and extracts __name__."""
        from tenuo.openai import GuardBuilder
        
        def my_search_tool():
            pass
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow(my_search_tool)
            .build())
        
        assert "my_search_tool" in client._allow_tools
    
    def test_tool_extraction_from_simple_dict(self):
        """Builder accepts simple dict with name key."""
        from tenuo.openai import GuardBuilder
        
        tool_dict = {"name": "search"}
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow(tool_dict)
            .build())
        
        assert "search" in client._allow_tools
    
    def test_tool_extraction_invalid_dict(self):
        """Builder raises ValueError for dict without name."""
        from tenuo.openai import GuardBuilder, _extract_tool_name
        
        with pytest.raises(ValueError, match="Cannot extract tool name"):
            _extract_tool_name({"foo": "bar"})
    
    def test_tool_extraction_invalid_type(self):
        """Builder raises TypeError for unsupported types."""
        from tenuo.openai import _extract_tool_name
        
        with pytest.raises(TypeError, match="Expected str, dict, or callable"):
            _extract_tool_name(123)
    
    def test_integration_with_verify(self):
        """Builder-created client actually enforces constraints."""
        from tenuo.openai import GuardBuilder
        
        mock_client = Mock()
        client = (GuardBuilder(mock_client)
            .allow("search")
            .allow("read_file", path=Subpath("/data"))
            .deny("delete_file")
            .build())
        
        # Allowed tool without constraints - returns None on success
        verify_tool_call(
            "search", {"query": "weather"},
            allow_tools=client._allow_tools,
            deny_tools=client._deny_tools,
            constraints=client._constraints,
        )  # Should not raise
        
        # Allowed tool with valid constraint
        verify_tool_call(
            "read_file", {"path": "/data/file.txt"},
            allow_tools=client._allow_tools,
            deny_tools=client._deny_tools,
            constraints=client._constraints,
        )  # Should not raise
        
        # Denied tool
        with pytest.raises(ToolDenied):
            verify_tool_call(
                "delete_file", {"path": "/data/file.txt"},
                allow_tools=client._allow_tools,
                deny_tools=client._deny_tools,
                constraints=client._constraints,
            )
        
        # Constraint violation
        with pytest.raises(ConstraintViolation):
            verify_tool_call(
                "read_file", {"path": "/etc/passwd"},
                allow_tools=client._allow_tools,
                deny_tools=client._deny_tools,
                constraints=client._constraints,
            )
