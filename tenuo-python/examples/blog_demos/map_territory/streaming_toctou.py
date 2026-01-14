#!/usr/bin/env python3
"""
Streaming TOCTOU Demo

Companion to "The Map is not the Territory"
https://niyikiza.com/posts/map-territory/

Demonstrates Time-of-Check-to-Time-of-Use vulnerabilities in LLM tool calls.

Run:
    python streaming_toctou.py             # Filesystem TOCTOU (symlink attack) — default
    python streaming_toctou.py --streaming # Streaming TOCTOU (partial JSON buffering)
"""

import argparse
import time
import os

# Optional imports for --live mode
HAS_LIVE_DEPS = False
try:
    import openai  # noqa: F401
    from tenuo.openai import GuardBuilder, ConstraintViolation  # noqa: F401
    from tenuo import Subpath  # noqa: F401

    HAS_LIVE_DEPS = True
except ImportError:
    pass

# ============================================================================
#  DISPLAY HELPERS
# ============================================================================


class Colors:
    GRAY = "\033[90m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def header(text: str):
    print()
    print(f"{Colors.BOLD}{'=' * 65}{Colors.RESET}")
    print(f"{Colors.BOLD}  {text}{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 65}{Colors.RESET}")
    print()


def subheader(text: str):
    print()
    print(f"┌{'─' * 63}┐")
    print(f"│  {text:<60}│")
    print(f"└{'─' * 63}┘")
    print()


# ============================================================================
#  BUFFER STATES
# ============================================================================

# What the buffer looks like as tokens arrive
# (buffer_content, looks_like_complete_json, extracted_path_if_complete)

BUFFER_STATES = [
    ('{"path": "/data/', False, None),
    ('{"path": "/data/report', False, None),
    ('{"path": "/data/report.txt"}', True, "/data/report.txt"),  # <-- Looks complete!
    # ...but attacker keeps sending tokens...
    ('{"path": "/data/report.txt/../', False, None),
    ('{"path": "/data/report.txt/../../../', False, None),
    ('{"path": "/data/report.txt/../../../etc/', False, None),
    ('{"path": "/data/report.txt/../../../etc/passwd"}', True, "/data/report.txt/../../../etc/passwd"),
]


# ============================================================================
#  VULNERABLE IMPLEMENTATION
# ============================================================================


def demo_vulnerable():
    """Show the vulnerable validate-as-you-go approach."""
    subheader("VULNERABLE: Validate-As-You-Go")

    print(f"  {Colors.DIM}Simulating LLM token stream arriving...{Colors.RESET}")
    print()

    executed = False

    for i, (buffer, looks_complete, extracted_path) in enumerate(BUFFER_STATES):
        # Show buffer state
        print(f"  {Colors.GRAY}[Buffer  ]{Colors.RESET} {buffer}")
        time.sleep(0.25)

        # Vulnerable: validate as soon as JSON looks complete
        if looks_complete and not executed:
            print()
            print(f'  {Colors.YELLOW}[VALIDATE]{Colors.RESET} JSON complete! Checking: "{extracted_path}"')
            time.sleep(0.15)

            # Naive prefix check
            if extracted_path.startswith("/data/"):
                print(f"  {Colors.GREEN}[VALIDATE]{Colors.RESET} ✅ PASS — starts with /data/")
                print()
                print(f'  {Colors.RED}[EXECUTE ]{Colors.RESET} 🚀 read_file("{extracted_path}") — TRIGGERED')
                executed = True
                time.sleep(0.4)
                print()
                print(f"  {Colors.DIM}          ...but more tokens are still arriving...{Colors.RESET}")
                print()
                time.sleep(0.3)

    # Show final result
    print()
    print(f"  {Colors.RED}{'─' * 61}{Colors.RESET}")
    print(f"  {Colors.RED}[RESULT  ] 💀 ATTACK SUCCEEDED{Colors.RESET}")
    print()
    print('            Validated: "/data/report.txt"')
    print('            Executed:  "/data/report.txt/../../../etc/passwd"')
    print('            Opened:    "/etc/passwd"')
    print(f"  {Colors.RED}{'─' * 61}{Colors.RESET}")
    print()
    print(f"  {Colors.YELLOW}Check ran on PARTIAL value. Execution got COMPLETE value.{Colors.RESET}")


# ============================================================================
#  SAFE IMPLEMENTATION
# ============================================================================


def demo_safe():
    """Show the safe buffer-verify-emit approach."""
    subheader("SAFE: Buffer-Verify-Emit (Tenuo)")

    print(f"  {Colors.DIM}Same token stream, different handling...{Colors.RESET}")
    print()

    for i, (buffer, looks_complete, extracted_path) in enumerate(BUFFER_STATES):
        # Show buffer state
        print(f"  {Colors.GRAY}[Buffer  ]{Colors.RESET} {buffer}")
        time.sleep(0.25)

        # Safe: even if JSON looks complete, wait for end-of-stream
        if looks_complete and i < len(BUFFER_STATES) - 1:
            print(f"  {Colors.CYAN}[WAIT    ]{Colors.RESET} Looks complete, but waiting for end-of-stream...")
            time.sleep(0.2)

    # Stream truly ended — NOW validate
    print()
    print(f"  {Colors.CYAN}[STREAM  ]{Colors.RESET} ✓ End-of-stream signal received")
    print()

    final_path = "/data/report.txt/../../../etc/passwd"
    print(f"  {Colors.YELLOW}[TENUO   ]{Colors.RESET} Now checking COMPLETE value:")
    print(f'            "{final_path}"')
    time.sleep(0.3)

    # Normalize
    normalized = os.path.normpath(final_path)
    print()
    print(f'  {Colors.YELLOW}[TENUO   ]{Colors.RESET} Subpath("/data").contains() normalizes path:')
    print(f'            "{final_path}"')
    print(f'            → "{normalized}"')
    time.sleep(0.3)

    # Check containment
    print()
    print(f'  {Colors.YELLOW}[TENUO   ]{Colors.RESET} Check: "{normalized}" starts with "/data/"?')
    time.sleep(0.2)
    print(f"  {Colors.RED}[TENUO   ]{Colors.RESET} ❌ NO — escapes jail")

    print()
    print(f"  {Colors.GREEN}{'─' * 61}{Colors.RESET}")
    print(f"  {Colors.GREEN}[RESULT  ] 🛡️ BLOCKED by Tenuo — attack prevented{Colors.RESET}")
    print(f"  {Colors.GREEN}{'─' * 61}{Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}Tenuo validated COMPLETE value. Caught the attack.{Colors.RESET}")


# ============================================================================
#  COMPARISON
# ============================================================================


def demo_comparison():
    """Side-by-side comparison."""
    subheader("THE DIFFERENCE")

    print(f"""
  ┌───────────────────────────────┬───────────────────────────────┐
  │  {Colors.RED}VULNERABLE{Colors.RESET}                     │  {Colors.GREEN}SAFE (Tenuo){Colors.RESET}                  │
  ├───────────────────────────────┼───────────────────────────────┤
  │                               │                               │
  │  Token arrives                │  Token arrives                │
  │       ↓                       │       ↓                       │
  │  JSON looks complete?         │  Append to buffer             │
  │       ↓ YES                   │       ↓                       │
  │  {Colors.YELLOW}Validate now{Colors.RESET}                  │  End-of-stream?               │
  │       ↓ PASS                  │       ↓ NO                    │
  │  {Colors.RED}Execute immediately{Colors.RESET}           │  {Colors.CYAN}Keep buffering...{Colors.RESET}            │
  │       ↓                       │       ↓                       │
  │  More tokens arrive...        │  End-of-stream?               │
  │       ↓                       │       ↓ YES                   │
  │  {Colors.RED}💀 Already executed{Colors.RESET}            │  {Colors.GREEN}Tenuo validates complete{Colors.RESET}     │
  │     wrong value!              │       ↓                       │
  │                               │  {Colors.GREEN}Block or execute{Colors.RESET}             │
  │                               │                               │
  └───────────────────────────────┴───────────────────────────────┘
    """)


# ============================================================================
#  CODE FIX
# ============================================================================


def show_code():
    """Show the code fix and Tenuo's actual implementation."""
    subheader("THE FIX: Buffer-Verify-Emit Pattern")

    print(f"  {Colors.BOLD}Concept:{Colors.RESET}")
    code = f"""
  {Colors.GRAY}# Buffer tool arguments. Verify complete JSON. Then execute.{Colors.RESET}

  tool_args_buffer = []

  async for chunk in llm.stream():
      if chunk.is_tool_call:
          tool_args_buffer.append(chunk.args_delta)  {Colors.CYAN}# BUFFER{Colors.RESET}

          if chunk.is_tool_call_complete:
              complete_args = json.loads("".join(tool_args_buffer))
              validated = verify(complete_args)         {Colors.CYAN}# VERIFY{Colors.RESET}
              if validated:
                  yield ToolCall(complete_args)         {Colors.CYAN}# EMIT{Colors.RESET}
              tool_args_buffer = []
      else:
          yield chunk  {Colors.GRAY}# Text streams immediately{Colors.RESET}
"""
    print(code)

    print(f"  {Colors.BOLD}Tenuo's actual implementation:{Colors.RESET}")
    print()
    tenuo_code = f"""
  {Colors.CYAN}from tenuo.openai import GuardBuilder, Subpath{Colors.RESET}

  {Colors.GRAY}# Tenuo wraps the client — buffer-verify-emit is automatic{Colors.RESET}
  client = (GuardBuilder(openai.OpenAI())
      .allow("read_file", path=Subpath("/data"))
      .build())

  {Colors.GRAY}# Streaming is protected by default{Colors.RESET}
  stream = client.chat.completions.create(
      model="gpt-4",
      messages=[...],
      tools=[...],
      {Colors.GREEN}stream=True  # TOCTOU protection built-in{Colors.RESET}
  )

  for chunk in stream:
      {Colors.GRAY}# Only verified tool calls reach here{Colors.RESET}
      {Colors.GRAY}# Malicious trailing tokens were already blocked{Colors.RESET}
      print(chunk)
"""
    print(tenuo_code)
    print()
    print(f"  {Colors.BOLD}See:{Colors.RESET} tenuo/openai.py → GuardedCompletions._guard_stream()")
    print("       Full implementation with ToolCallBuffer + verify-on-complete")
    print()
    print(f"  {Colors.BOLD}Key insight:{Colors.RESET} Text streams normally. Only tool arguments buffer.")
    print("              Minimal latency cost. Essential security gain.")


# ============================================================================
#  LIVE MODE (Real OpenAI API)
# ============================================================================

READ_FILE_TOOL = {
    "type": "function",
    "function": {
        "name": "read_file",
        "description": "Read contents of a file from the filesystem",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the file to read"}},
            "required": ["path"],
        },
    },
}


def demo_race(wait=None):
    """Filesystem race window demo (symlink attack)."""
    # No external deps needed - we simulate the token stream

    if wait is None:
        # Default to blocking input
        wait = lambda msg: input(msg)  # noqa: E731

    header("FILESYSTEM TOCTOU: The Race Window")

    print("  TOCTOU: Time-of-Check to Time-of-Use")
    print(f"  The {Colors.BOLD}race window{Colors.RESET} between validation and execution.")
    print()
    print(f"  {Colors.GRAY}Real-world examples:{Colors.RESET}")
    print("    • CVE-2018-15664 (Docker): symlink race → container escape")
    print("    • CVE-2022-3590 (WordPress): DNS rebinding → SSRF")
    print()

    wait("  Press Enter to see the race window...")
    print()

    # =========================================================================
    # EXPLOIT: Show the real race condition
    # =========================================================================

    subheader("THE RACE WINDOW")

    # REAL TOCTOU: The race is between validation and execution.
    #
    # This is NOT about partial JSON parsing (real SDKs handle that correctly).
    # This IS about filesystem/network state changing in the race window.
    #
    # Real examples:
    # - CVE-2018-15664 (Docker): path validated, symlink swapped, container escape
    # - CVE-2022-3590 (WordPress): DNS validated, record changed, SSRF
    #
    # OpenAI SDK behavior (https://github.com/openai/openai-python):
    #   - stream=True returns ChatCompletionChunk objects
    #   - Tool call args accumulate in delta.tool_calls[i].function.arguments
    #   - SDK does NOT buffer for you - you get raw chunks
    #   - finish_reason="tool_calls" signals completion

    PATH = "/data/report.txt"

    print(f"  {Colors.BOLD}Real SDK behavior (OpenAI Python):{Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}# https://github.com/openai/openai-python{Colors.RESET}")
    print(f"  {Colors.GRAY}stream = client.chat.completions.create(stream=True, ...){Colors.RESET}")
    print(f"  {Colors.GRAY}for chunk in stream:{Colors.RESET}")
    print(f"  {Colors.GRAY}    # You receive raw chunks - SDK doesn't buffer{Colors.RESET}")
    print()

    time.sleep(0.5)

    print(f"  {Colors.BOLD}The Race Window:{Colors.RESET}")
    print()
    print(f'  {Colors.YELLOW}[T=0ms]{Colors.RESET}  Tool call complete: read_file("{PATH}")')
    time.sleep(0.4)
    print(f'  {Colors.GREEN}[T=1ms]{Colors.RESET}  Layer 1.5 validates: "{PATH}" is inside /data/ ✓')
    time.sleep(0.4)
    print()
    print(f"  {Colors.RED}[T=2ms]{Colors.RESET}  ══════════ RACE WINDOW ══════════")
    print(f"          {Colors.GRAY}Validation passed. Execution pending.{Colors.RESET}")
    print(f"          {Colors.GRAY}Attacker acts NOW:{Colors.RESET}")
    time.sleep(0.3)
    print(f"          {Colors.RED}$ ln -sf /etc/passwd /data/report.txt{Colors.RESET}")
    time.sleep(0.4)
    print(f"  {Colors.RED}[T=3ms]{Colors.RESET}  ═══════════════════════════════════")
    print()
    time.sleep(0.3)
    print(f'  {Colors.YELLOW}[T=4ms]{Colors.RESET}  Execution: open("{PATH}")')
    time.sleep(0.3)
    print(f"  {Colors.YELLOW}[T=5ms]{Colors.RESET}  Kernel resolves symlink...")
    time.sleep(0.3)
    print(f"  {Colors.RED}[T=6ms]{Colors.RESET}  Actually opens: /etc/passwd")

    print()
    print(f"  {Colors.RED}{'─' * 59}{Colors.RESET}")
    print(f"  {Colors.RED}💀 TOCTOU EXPLOIT (CVE-2018-15664 class){Colors.RESET}")
    print()
    print(f'  {Colors.GRAY}What Layer 1.5 validated:{Colors.RESET} "{PATH}" (the string)')
    print(f"  {Colors.GRAY}What kernel opened:{Colors.RESET}       /etc/passwd (the inode)")
    print()
    print(f"  {Colors.GRAY}The Map (string) was valid. The Territory (filesystem) changed.{Colors.RESET}")
    print(f"  {Colors.GRAY}This is why you need Layer 2 (path_jail) at open() time.{Colors.RESET}")
    print(f"  {Colors.RED}{'─' * 59}{Colors.RESET}")

    # =========================================================================
    # SAFE: Tenuo's approach
    # =========================================================================

    print()
    wait("  Press Enter to see how Tenuo prevents this...")
    print()

    subheader("THE FIX: Layer 1.5 + Layer 2")

    print(f"  {Colors.BOLD}Layer 1.5 alone can't prevent this.{Colors.RESET}")
    print(f"  {Colors.GRAY}Subpath validates the STRING. The filesystem can still change.{Colors.RESET}")
    print()
    print(f"  {Colors.BOLD}You need Layer 2: validate at open() time.{Colors.RESET}")
    print()

    time.sleep(0.3)

    print(f"  {Colors.CYAN}from path_jail import safe_open{Colors.RESET}")
    print(f"  {Colors.CYAN}from tenuo import Subpath{Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}# Layer 1.5: Validate the string (catches encoding tricks){Colors.RESET}")
    print(f'  {Colors.GRAY}if Subpath("/data").contains(path):{Colors.RESET}')
    print()
    print(f"  {Colors.GRAY}    # Layer 2: Validate at execution (catches symlink races){Colors.RESET}")
    print(f'  {Colors.GRAY}    with safe_open(path, root="/data") as f:{Colors.RESET}')
    print(f"  {Colors.GRAY}        # safe_open() calls realpath() BEFORE open(){Colors.RESET}")
    print(f"  {Colors.GRAY}        # If symlink escapes /data, raises SecurityError{Colors.RESET}")
    print(f"  {Colors.GRAY}        return f.read(){Colors.RESET}")
    print()

    time.sleep(0.3)

    print(f"  {Colors.BOLD}With path_jail, the attack fails:{Colors.RESET}")
    print()
    print(f'  {Colors.YELLOW}[T=0ms]{Colors.RESET}  Tool call: read_file("{PATH}")')
    time.sleep(0.2)
    print(f'  {Colors.GREEN}[T=1ms]{Colors.RESET}  Layer 1.5 (Subpath): "{PATH}" ✓')
    time.sleep(0.2)
    print(f"  {Colors.RED}[T=2ms]{Colors.RESET}  Attacker: ln -sf /etc/passwd {PATH}")
    time.sleep(0.2)
    print(f'  {Colors.YELLOW}[T=3ms]{Colors.RESET}  Layer 2 (path_jail): safe_open("{PATH}")')
    time.sleep(0.2)
    print(f"  {Colors.YELLOW}[T=4ms]{Colors.RESET}  → realpath() resolves symlink")
    time.sleep(0.2)
    print(f"  {Colors.YELLOW}[T=5ms]{Colors.RESET}  → resolved: /etc/passwd")
    time.sleep(0.2)
    print(f"  {Colors.YELLOW}[T=6ms]{Colors.RESET}  → /etc/passwd inside /data? {Colors.RED}NO{Colors.RESET}")
    time.sleep(0.2)
    print(
        f"  {Colors.GREEN}[T=7ms]{Colors.RESET}  → {Colors.GREEN}SecurityError raised. File NOT opened.{Colors.RESET}"
    )

    print()
    print(f"  {Colors.GREEN}{'─' * 59}{Colors.RESET}")
    print(f"  {Colors.GREEN}🛡️ ATTACK BLOCKED BY LAYER 2{Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}Layer 1.5 (Subpath): Validates the Map (string semantics){Colors.RESET}")
    print(f"  {Colors.GRAY}Layer 2 (path_jail): Validates the Territory (filesystem state){Colors.RESET}")
    print()
    print(f"  {Colors.GRAY}The race window still exists, but the attacker can't win.{Colors.RESET}")
    print(f"  {Colors.GRAY}path_jail checks reality at the moment of open().{Colors.RESET}")
    print(f"  {Colors.GREEN}{'─' * 59}{Colors.RESET}")

    print()
    print(f"  {Colors.BOLD}Defense in depth:{Colors.RESET}")
    print()
    print(f"    {Colors.CYAN}Layer 1.5:{Colors.RESET} Catches ../encoding/../tricks before they reach tools")
    print(f"    {Colors.CYAN}Layer 2:{Colors.RESET}   Catches TOCTOU races at execution time")
    print()
    print(f"  {Colors.GRAY}# Install: pip install tenuo path_jail{Colors.RESET}")
    print(f"  {Colors.GRAY}# Docs: https://github.com/tenuo-ai/path-jail-python{Colors.RESET}")
    print()

    return True


# ============================================================================
#  MAIN
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="TOCTOU Demo - Shows vulnerability and Tenuo's fix")
    parser.add_argument(
        "--streaming",
        action="store_true",
        help="Show streaming TOCTOU (partial JSON buffering illustration)",
    )
    parser.add_argument("--auto", action="store_true", help="Non-interactive mode (for piped/curl usage)")
    args = parser.parse_args()

    # Auto-detect if we're being piped (no tty)
    import sys

    interactive = sys.stdin.isatty() and not args.auto

    def wait(msg: str = ""):
        if interactive:
            input(msg)
        else:
            time.sleep(0.5)  # Brief pause for readability

    if args.streaming:
        # Streaming demo (pedagogical illustration)
        demo_streaming(interactive, wait)
        return

    # Filesystem race demo (default) — the bulletproof example
    demo_race(wait)


def demo_streaming(interactive: bool, wait):
    """Streaming TOCTOU demo — illustrates why buffering matters."""
    header("STREAMING TOCTOU DEMO")
    print("  Companion to 'The Map is not the Territory'")
    print("  https://niyikiza.com/posts/map-territory/")
    print()
    print(f"  {Colors.BOLD}TOCTOU{Colors.RESET} = Time-of-Check to Time-of-Use")
    print()
    print("  A classic vulnerability pattern applied to LLM streaming:")
    print("  Validate a partial value, execute a different complete value.")
    print()

    # Add the caveat
    print(f"  {Colors.YELLOW}{'─' * 59}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Note:{Colors.RESET} Modern OpenAI SDKs signal when tool calls are complete")
    print("        (finish_reason='tool_calls'). This demo illustrates")
    print("        why that matters — and what goes wrong if you build")
    print("        your own streaming handler and validate partial buffers.")
    print(f"  {Colors.YELLOW}{'─' * 59}{Colors.RESET}")
    print()

    if interactive:
        print(f"  {Colors.GRAY}Default mode (no flags) shows the filesystem race — a real{Colors.RESET}")
        print(f"  {Colors.GRAY}exploit vector that doesn't depend on SDK implementation.{Colors.RESET}")
        print()

    wait("  Press Enter to see the vulnerable implementation...")
    demo_vulnerable()

    wait("\n  Press Enter to see the safe implementation...")
    demo_safe()

    wait("\n  Press Enter to see the comparison...")
    demo_comparison()

    wait("\n  Press Enter to see the code fix...")
    show_code()

    print()
    print(f"  {'=' * 63}")
    print(f"  {Colors.BOLD}RULE:{Colors.RESET} Never validate partial tool arguments.")
    print("        Buffer the complete JSON. Verify. Only then execute.")
    print(f"  {'=' * 63}")
    print()
    print("  Read more: https://niyikiza.com/posts/map-territory/")
    print()


if __name__ == "__main__":
    main()
