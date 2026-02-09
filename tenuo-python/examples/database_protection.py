#!/usr/bin/env python3
"""
OpenAI + Tenuo: Database Tool Protection Example

Demonstrates how to protect database access tools for AI agents using Tenuo's
existing constraint semantics. This example shows the STRUCTURED TOOL approach
where the agent controls parameters (table, columns, limit) instead of raw SQL.

=== APPROACH ===

The key insight: don't let the agent write SQL. Instead, design tools where:
  - The agent selects from constrained parameters (table, columns, operation)
  - Your trusted code builds the actual SQL from those parameters
  - Tenuo enforces that parameters stay within policy

This is analogous to parameterized queries preventing SQL injection — the agent
never touches the query language itself.

=== WHAT THIS DEMONSTRATES ===

  1. Tool-level gating: agent can call query_db but not admin_db
  2. OneOf constraints: lock tables and operations to explicit allow-lists
  3. Subset constraints: agent can only request permitted columns
  4. Range constraints: bound result set sizes
  5. Zero-trust argument handling: unknown/extra args are rejected
  6. Delegation (attenuation): orchestrator narrows DB access for workers
  7. Audit trail: every DB access attempt is logged

=== KNOWN LIMITATIONS (see PR description) ===

  - No ad-hoc query capability — agent can only use pre-shaped operations
  - WHERE clause / filter expressions remain a weak link
  - No SqlSafe semantic constraint (like Subpath for paths, UrlSafe for URLs)
  - Requires careful upfront tool design; not developer-friendly for quick prototyping

Requirements:
    uv pip install openai tenuo
"""

import json

# Universal constraints (work with any integration)
from tenuo import (
    OneOf,
    Subset,
    Range,
    Pattern,
    Wildcard,
    Exact,
    SigningKey,
    Warrant,
)

# OpenAI-specific
from tenuo.openai import (
    GuardBuilder,
    guard,
    ToolDenied,
    ConstraintViolation,
    AuditEvent,
)


# ============================================================================
# Mock OpenAI Client
# ============================================================================


class MockOpenAIClient:
    """Mock OpenAI client that simulates various agent tool-call attempts.

    Each scenario simulates what a real LLM might try to do — including
    both legitimate queries and dangerous ones.
    """

    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                from dataclasses import dataclass, field

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
                    content: str | None
                    tool_calls: list

                @dataclass
                class Choice:
                    message: Message

                @dataclass
                class Response:
                    choices: list

                messages = kwargs.get("messages", [])
                user_msg = messages[-1]["content"] if messages else ""

                # Simulate different agent behaviors based on the prompt
                if "drop" in user_msg.lower() or "admin" in user_msg.lower():
                    # Agent tries to call an admin tool
                    tool_name = "admin_db"
                    args = json.dumps({"command": "DROP TABLE users"})
                elif "credentials" in user_msg.lower():
                    # Agent tries to access a forbidden table
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "credentials",
                        "operation": "select",
                        "columns": ["password_hash", "secret_key"],
                        "limit": 1000,
                    })
                elif "delete" in user_msg.lower():
                    # Agent tries a write operation when only reads are allowed
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "orders",
                        "operation": "delete",
                        "columns": ["id"],
                        "limit": 1,
                    })
                elif "unlimited" in user_msg.lower():
                    # Agent tries to dump entire table (limit out of range)
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "orders",
                        "operation": "select",
                        "columns": ["id", "name", "price"],
                        "limit": 999999,
                    })
                elif "inject" in user_msg.lower():
                    # Agent tries to sneak in a raw SQL argument
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "orders",
                        "operation": "select",
                        "columns": ["id", "name"],
                        "limit": 10,
                        "raw_where": "1=1; DROP TABLE orders; --",
                    })
                elif "export" in user_msg.lower():
                    # Agent tries to access sensitive columns
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "users",
                        "operation": "select",
                        "columns": ["id", "name", "email", "ssn", "password_hash"],
                        "limit": 50,
                    })
                else:
                    # Legitimate query
                    tool_name = "query_db"
                    args = json.dumps({
                        "table": "orders",
                        "operation": "select",
                        "columns": ["id", "name", "price"],
                        "limit": 10,
                    })

                return Response(
                    choices=[
                        Choice(
                            message=Message(
                                role="assistant",
                                content=None,
                                tool_calls=[
                                    ToolCall(
                                        id="call_1",
                                        function=Function(name=tool_name, arguments=args),
                                    )
                                ],
                            )
                        )
                    ]
                )


# ============================================================================
# Helper
# ============================================================================


def attempt(client, description: str, prompt: str) -> None:
    """Run a tool call attempt and report the result."""
    print(f"\n  Attempt: {description}")
    print(f"  Prompt:  \"{prompt}\"")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
        )
        tool_call = response.choices[0].message.tool_calls[0]
        args = json.loads(tool_call.function.arguments)
        print(f"  Result:  ALLOWED")
        print(f"           tool={tool_call.function.name}, args={args}")
    except ToolDenied as e:
        print(f"  Result:  BLOCKED (tool denied)")
        print(f"           {e}")
    except ConstraintViolation as e:
        print(f"  Result:  BLOCKED (constraint violation)")
        print(f"           tool={e.tool_name}, param={e.param}, value={e.value}")


# ============================================================================
# Demo 1: Tier 1 Guardrails (No Cryptography)
# ============================================================================


def demo_tier1_guardrails():
    """Protect database tools with runtime guardrails.

    This is the simplest approach — no keys, no warrants, just constraints.
    Suitable for single-process applications where you trust the runtime.
    """
    print("=" * 70)
    print("DEMO 1: Tier 1 Guardrails — Structured Database Protection")
    print("=" * 70)
    print()
    print("Policy: Agent can SELECT from 'orders' and 'products' tables only,")
    print("        limited columns, max 100 rows. No writes. No admin tools.")
    print()

    # Build the protected client
    client = (
        GuardBuilder(MockOpenAIClient())

        # --- Allow query_db with tight constraints on every parameter ---
        .allow("query_db",
            table=OneOf(["orders", "products"]),             # Only these 2 tables
            operation=OneOf(["select"]),                      # Read-only
            columns=Subset(["id", "name", "price",           # Only safe columns
                           "quantity", "created_at",
                           "status", "product_id"]),
            limit=Range(1, 100),                              # Bounded result sets
        )

        # --- Explicitly deny dangerous tools ---
        .deny("admin_db")
        .deny("execute_sql")
        .deny("migrate_db")

        .on_denial("raise")
        .build()
    )

    # --- Legitimate query: should pass ---
    attempt(client,
        "Legitimate SELECT on orders",
        "Show me recent orders")

    # --- Blocked: forbidden table ---
    attempt(client,
        "Access forbidden table (credentials)",
        "Show me credentials")

    # --- Blocked: write operation ---
    attempt(client,
        "DELETE operation (only SELECT allowed)",
        "Delete old orders")

    # --- Blocked: limit too high ---
    attempt(client,
        "Dump entire table (limit=999999)",
        "Export unlimited orders")

    # --- Blocked: extra argument injection ---
    attempt(client,
        "Sneak in raw_where argument (zero-trust rejects it)",
        "Inject a filter clause")

    # --- Blocked: admin tool ---
    attempt(client,
        "Call admin_db tool (denied tool)",
        "Drop the users table via admin")

    print()


# ============================================================================
# Demo 2: Tier 1 with Audit Trail
# ============================================================================


def demo_audit_logging():
    """Every authorization decision is logged for compliance."""
    print("=" * 70)
    print("DEMO 2: Audit Trail — Every DB Access Attempt Is Logged")
    print("=" * 70)
    print()

    audit_log: list[AuditEvent] = []

    def on_audit(event: AuditEvent):
        audit_log.append(event)
        status = "ALLOWED" if event.decision == "ALLOW" else "DENIED"
        print(f"  [AUDIT] {status}: tool={event.tool_name}, "
              f"session={event.session_id[:8]}...")

    client = (
        GuardBuilder(MockOpenAIClient())
        .allow("query_db",
            table=OneOf(["orders", "products"]),
            operation=OneOf(["select"]),
            columns=Subset(["id", "name", "price", "quantity"]),
            limit=Range(1, 100),
        )
        .deny("admin_db")
        .on_denial("raise")
        .audit(on_audit)
        .build()
    )

    print(f"  Session: {client.session_id}")
    print(f"  Constraint hash: {client.constraint_hash}")
    print()

    # Legitimate call
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Show me recent orders"}],
        )
    except Exception:
        pass

    # Blocked call
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Drop the admin table"}],
        )
    except Exception:
        pass

    print(f"\n  Total audit events: {len(audit_log)}")
    print()


# ============================================================================
# Demo 3: Tier 2 Warrant — Cryptographic Protection with Delegation
# ============================================================================


def demo_tier2_warrant():
    """Demonstrate warrant-based DB protection with delegation.

    Scenario:
      1. Control plane issues a broad DB warrant to an orchestrator
      2. Orchestrator attenuates it for a worker (fewer tables, shorter TTL)
      3. Worker can only operate within the narrowed scope
    """
    print("=" * 70)
    print("DEMO 3: Tier 2 Warrant — Delegation & Attenuation")
    print("=" * 70)
    print()

    # --- Key setup ---
    control_key = SigningKey.generate()
    orchestrator_key = SigningKey.generate()
    worker_key = SigningKey.generate()

    # --- Step 1: Control plane issues warrant to orchestrator ---
    print("  Step 1: Control plane issues warrant to orchestrator")
    orchestrator_warrant = (
        Warrant.mint_builder()
        .capability("query_db",
            table=OneOf(["orders", "products", "users", "inventory"]),
            operation=OneOf(["select", "insert", "update"]),
            columns=Wildcard(),         # Orchestrator can access any column
            limit=Range(1, 1000),
        )
        .holder(orchestrator_key.public_key)
        .ttl(3600)  # 1 hour
        .mint(control_key)
    )
    print(f"         Tools: {orchestrator_warrant.tools}")
    print(f"         TTL:   {orchestrator_warrant.ttl_remaining}")
    print()

    # --- Step 2: Orchestrator delegates narrower warrant to worker ---
    print("  Step 2: Orchestrator attenuates warrant for worker")
    worker_warrant = (
        orchestrator_warrant.grant_builder()
        .capability("query_db",
            table=OneOf(["orders", "products"]),       # Fewer tables (narrowed)
            operation=OneOf(["select"]),                 # Read-only (narrowed)
            columns=Subset(["id", "name", "price"]),    # Specific columns (narrowed)
            limit=Range(1, 50),                          # Smaller limit (narrowed)
        )
        .holder(worker_key.public_key)
        .ttl(300)  # 5 minutes (shorter TTL)
        .grant(orchestrator_key)
    )
    print(f"         Tools: {worker_warrant.tools}")
    print(f"         TTL:   {worker_warrant.ttl_remaining}")
    print(f"         Depth: {worker_warrant.depth}")
    print()

    # --- Step 3: Worker uses the narrowed warrant ---
    print("  Step 3: Worker validates operations against warrant")
    bound = worker_warrant.bind(worker_key)

    # Valid operation
    result = bound.validate("query_db", {
        "table": "orders",
        "operation": "select",
        "columns": ["id", "name", "price"],
        "limit": 10,
    })
    print(f"         SELECT orders (id,name,price) LIMIT 10: "
          f"{'ALLOWED' if result else 'DENIED'}")

    # Try wider table — should fail
    result = bound.validate("query_db", {
        "table": "users",
        "operation": "select",
        "columns": ["id", "name"],
        "limit": 10,
    })
    print(f"         SELECT users: "
          f"{'ALLOWED' if result else 'DENIED — table not in worker scope'}")

    # Try write operation — should fail
    result = bound.validate("query_db", {
        "table": "orders",
        "operation": "update",
        "columns": ["status"],
        "limit": 1,
    })
    print(f"         UPDATE orders: "
          f"{'ALLOWED' if result else 'DENIED — worker is read-only'}")

    # --- Step 4: Demonstrate attenuation prevents escalation ---
    print()
    print("  Step 4: Worker CANNOT escalate permissions")
    try:
        escalated = (
            worker_warrant.grant_builder()
            .capability("query_db",
                table=OneOf(["orders", "products", "users", "credentials"]),  # WIDER!
                operation=OneOf(["select", "delete"]),                         # WIDER!
                columns=Wildcard(),
                limit=Range(1, 99999),
            )
            .holder(SigningKey.generate().public_key)
            .ttl(7200)  # Longer TTL than parent!
            .grant(worker_key)
        )
        print("         ERROR: Escalation should have been blocked!")
    except Exception as e:
        print(f"         Blocked: {type(e).__name__}")
        print(f"         Attenuation enforced — child can only narrow, never widen.")

    print()


# ============================================================================
# Demo 4: The Limitation — What Happens With Free-Form Filters
# ============================================================================


def demo_filter_limitation():
    """Show the limitation: free-form filter strings can't be safely validated.

    This demonstrates WHY a SqlSafe constraint would be valuable.
    Current workaround: don't expose free-form filter strings as parameters.
    """
    print("=" * 70)
    print("DEMO 4: Limitation — Free-Form Filters Are the Weak Link")
    print("=" * 70)
    print()
    print("  Current constraints can lock down tables, columns, operations,")
    print("  and limits. But what about WHERE clauses or filter expressions?")
    print()

    # If you added a 'filter' parameter with Pattern or Regex...
    client = (
        GuardBuilder(MockOpenAIClient())
        .allow("query_db",
            table=OneOf(["orders"]),
            operation=OneOf(["select"]),
            columns=Subset(["id", "name", "price"]),
            limit=Range(1, 100),
            # This is the weak link: Pattern can't understand SQL semantics
            filter=Pattern("*"),  # Allows ANY filter string — not ideal
        )
        .on_denial("raise")
        .build()
    )

    print("  If we add filter=Pattern('*'), any filter string is accepted.")
    print("  If we add filter=Regex('^[a-zA-Z]+ [><=] .+$'), the agent could")
    print("  craft strings that match but contain subqueries or injections.")
    print()
    print("  --- What's missing ---")
    print()
    print("  Tenuo has semantic constraints for:")
    print("    - File paths:     Subpath('/data')       — blocks traversal")
    print("    - URLs:           UrlSafe()              — blocks SSRF")
    print("    - Shell commands: Shlex(allow=[...])     — blocks injection")
    print()
    print("  But NOT for SQL:")
    print("    - SQL queries:    SqlSafe(???)           — DOES NOT EXIST YET")
    print()
    print("  A hypothetical SqlSafe would parse SQL and enforce:")
    print("    SqlSafe(")
    print("        allow_operations=['SELECT'],")
    print("        allow_tables=['orders', 'products'],")
    print("        allow_columns=['id', 'name', 'price'],")
    print("        require_limit=100,")
    print("        block_subqueries=True,")
    print("    )")
    print()
    print("  WORKAROUND: Don't expose filter as a free-form string.")
    print("  Instead, design structured filter parameters:")
    print()
    print("    .allow('query_db',")
    print("        filter_column=OneOf(['price', 'status', 'created_at']),")
    print("        filter_op=OneOf(['=', '>', '<', '>=', '<=']),")
    print("        filter_value=Range(0, 100000),  # or Pattern/OneOf")
    print("    )")
    print()


# ============================================================================
# Demo 5: Recommended Pattern — Fully Structured Tool Design
# ============================================================================


def demo_recommended_pattern():
    """The recommended approach: fully structured tools with no free-form SQL.

    Every parameter is individually constrained. SQL is built by YOUR code,
    not by the agent. This is the safest pattern available today.
    """
    print("=" * 70)
    print("DEMO 5: Recommended Pattern — Fully Structured Tool Design")
    print("=" * 70)
    print()
    print("  Define separate, focused tools instead of one generic query_db:")
    print()

    client = (
        GuardBuilder(MockOpenAIClient())

        # Tool 1: Search orders (read-only, specific columns, bounded)
        .allow("search_orders",
            status=OneOf(["pending", "shipped", "delivered", "cancelled"]),
            sort_by=OneOf(["created_at", "price", "name"]),
            sort_order=OneOf(["asc", "desc"]),
            limit=Range(1, 50),
        )

        # Tool 2: Get order by ID (single record, exact match)
        .allow("get_order",
            order_id=Range(1, 999999999),
        )

        # Tool 3: List products (read-only catalog)
        .allow("list_products",
            category=OneOf(["electronics", "books", "clothing", "food"]),
            min_price=Range(0, 100000),
            max_price=Range(0, 100000),
            limit=Range(1, 50),
        )

        # Deny everything else
        .deny("admin_db")
        .deny("execute_sql")
        .deny("query_db")  # No generic query tool

        .on_denial("raise")
        .build()
    )

    print("  Tools defined:")
    print("    - search_orders(status, sort_by, sort_order, limit)")
    print("    - get_order(order_id)")
    print("    - list_products(category, min_price, max_price, limit)")
    print()
    print("  Each parameter is individually constrained.")
    print("  SQL is built by trusted application code, never by the agent.")
    print("  Zero-trust rejects any extra arguments the agent tries to pass.")
    print()
    print("  Tradeoff: agent can't do ad-hoc queries, but it CAN'T do")
    print("  dangerous ones either. Safety over flexibility.")
    print()


# ============================================================================
# Main
# ============================================================================


def main():
    print()
    print("=" * 70)
    print("  Tenuo × OpenAI: Database Tool Protection")
    print("  Protecting AI Agent Database Access with Existing Semantics")
    print("=" * 70)
    print()
    print("  This example demonstrates how Tenuo's constraint system can")
    print("  protect database tools using the STRUCTURED TOOL approach —")
    print("  agents control parameters, not queries.")
    print()
    print("  See docs/analysis-database-tool-protection.md for full analysis.")
    print()

    demo_tier1_guardrails()
    demo_audit_logging()
    demo_tier2_warrant()
    demo_filter_limitation()
    demo_recommended_pattern()

    print("=" * 70)
    print("  Summary")
    print("=" * 70)
    print()
    print("  WORKS TODAY:")
    print("    - Tool-level gating (allow/deny specific tools)")
    print("    - OneOf: lock tables and operations to allow-lists")
    print("    - Subset: restrict accessible columns")
    print("    - Range: bound result set sizes")
    print("    - Zero-trust: reject unknown/extra arguments")
    print("    - Warrant delegation: orchestrator -> worker attenuation")
    print("    - Audit trail: every attempt logged")
    print()
    print("  LIMITATIONS:")
    print("    - No ad-hoc query capability for agents")
    print("    - Free-form filters/WHERE clauses are a weak link")
    print("    - No SqlSafe semantic constraint (like Subpath, UrlSafe, Shlex)")
    print("    - Requires careful upfront tool design")
    print("    - Not developer-friendly for rapid prototyping")
    print()
    print("  NEXT STEP: SqlSafe constraint that parses and validates SQL")
    print("  the way Shlex parses shell commands and Subpath validates paths.")
    print()


if __name__ == "__main__":
    main()
