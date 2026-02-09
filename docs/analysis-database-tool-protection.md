# Can Tenuo Protect a Database Tool for AI Agents?

**Date:** February 9, 2026
**Status:** Honest assessment of current semantics

---

## Short Answer

**Partially yes, but there's a real gap.**

Tenuo has the right *foundational architecture* for this problem, but it's missing a critical semantic constraint for SQL — the same way it already has `Subpath` for file paths, `UrlSafe` for URLs, and `Shlex` for shell commands.

---

## What Tenuo Gets Right

The foundational pieces are excellent for this use case:

### 1. Tool-level gating

You can restrict an agent to only calling `query_db` and not `admin_db` or `drop_table`. The warrant's tool list enforces this with cryptographic proof.

### 2. Closed-world (zero-trust) argument handling

Once you define *any* constraint on a tool, ALL arguments must be explicitly allowed or they're rejected. This is exactly the right default for database access.

### 3. Attenuation / delegation

An orchestrator with broad DB access can delegate a *narrower* warrant to a worker — e.g., only `SELECT` on specific tables, with a 5-minute TTL. The worker cannot escalate.

### 4. Proof-of-Possession (PoP)

Even if a warrant is intercepted in logs or state, an attacker can't use it without the private key.

### 5. Short TTLs

A 5-minute warrant for a DB operation naturally limits blast radius.

---

## Where It Works Today (With Careful Tool Design)

If you design a **structured** database tool (not raw SQL), Tenuo's existing constraints can cover a lot:

```python
# Structured tool — NOT raw SQL
@guard(tool="query_db")
def query_db(table: str, operation: str, columns: list, limit: int) -> list:
    ...

# Warrant constraining each argument
warrant = (Warrant.mint_builder()
    .capability("query_db",
        table=OneOf(["orders", "products"]),     # Only these tables
        operation=OneOf(["select"]),              # Read-only, no DELETE/DROP
        columns=Subset(["id", "name", "price"]), # Only safe columns
        limit=Range(1, 100),                     # Bounded result sets
    )
    .holder(agent_key.public_key)
    .ttl(300)
    .mint(control_key))
```

This works because:

- **`OneOf`** locks down tables and operations to an explicit allow-list
- **`Subset`** ensures the agent can only request allowed columns
- **`Range`** prevents unbounded queries
- **Zero-trust** rejects any argument not listed (e.g., if the agent tries to sneak in a `raw_sql` arg)

You could even use CEL for richer policies:

```python
# CEL: "only allow queries where amount < 10000 and region is 'us-east'"
.capability("query_db",
    filter=Cel("amount < 10000 && region == 'us-east'"))
```

---

## The Honest Gap: No `SqlSafe` Semantic Constraint

Here's where Tenuo falls short. Consider this pattern from the existing codebase:

| Domain | Naive Constraint | Why It Fails | Semantic Constraint |
|--------|-----------------|--------------|-------------------|
| File paths | `Pattern("/data/*")` | `/data/../etc/passwd` bypasses it | **`Subpath("/data")`** |
| URLs | `Pattern("https://*")` | SSRF via `http://169.254.169.254` | **`UrlSafe()`** |
| Shell cmds | String checks | `ls; rm -rf /` bypasses it | **`Shlex(allow_binaries=[...])`** |
| **SQL** | `Regex("^SELECT.*")` | `SELECT * FROM users; DROP TABLE users` | **??? — Nothing exists** |

### The problem

**If your tool takes any form of query string, filter expression, or WHERE clause — even a partial one — Tenuo has no constraint that understands SQL semantics.**

- **`Pattern` and `Regex`** match string shapes but don't parse SQL. An agent can craft a string that *looks* like it matches but contains injection payloads (`UNION SELECT`, stacked queries via `;`, subqueries, etc.)
- **`Exact` and `OneOf`** would require pre-enumerating every possible query (impractical)
- **`CEL`** operates on the *argument values*, not on the *SQL semantics* — you can't write a CEL expression that reliably parses and validates SQL

This is the exact same class of vulnerability that motivated `Subpath` (path traversal), `UrlSafe` (SSRF), and `Shlex` (shell injection). The codebase even references CVE-2025-66032 about why pattern matching isn't enough for semantic domains.

---

## What Would Be Needed

A `SqlSafe` constraint (or similar) that understands SQL the way `Shlex` understands shell commands:

1. **Parse the SQL** — not regex-match it — using a real SQL parser
2. **Allowlist operations** — only `SELECT`, never `DROP`, `ALTER`, `DELETE`, `TRUNCATE`
3. **Allowlist tables** — only `orders`, `products`, never `users`, `credentials`
4. **Allowlist columns** — prevent access to sensitive columns
5. **Block dangerous patterns** — stacked queries (`;`), `UNION`, subqueries, comments (`--`, `/**/`)
6. **Limit clauses** — enforce `LIMIT` is present and bounded

### Hypothetical API

```python
# Hypothetical SqlSafe constraint
SqlSafe(
    allow_operations=["SELECT"],
    allow_tables=["orders", "products"],
    allow_columns=["id", "name", "price", "quantity"],
    require_limit=100,
    block_subqueries=True,
)
```

This would be a new constraint type ID (19 or 20), with attenuation rules analogous to the existing semantic constraints — child can only narrow the allowed tables, operations, and columns.

---

## Practical Recommendation Right Now

Without `SqlSafe`, you can still get meaningful protection by **not exposing raw SQL as a tool parameter**:

1. **Design structured tools** — `query_db(table, columns, filters, limit)` instead of `query_db(sql)`
2. **Use `OneOf`** for tables and operations
3. **Use `Subset`** for columns
4. **Use `Range`** for limits
5. **Build the SQL in your tool implementation**, not in the agent's arguments
6. **Use `Regex` or `CEL`** for simple filter expressions if needed, but be aware this is the weak link

This pushes the SQL construction to your trusted code path rather than the agent's untrusted input. Tenuo then ensures the agent can only control the *parameters* that flow into your SQL builder, not the SQL itself.

---

## Summary Scorecard

| Aspect | Grade | Notes |
|--------|-------|-------|
| Architecture (POLA, attenuation, PoP) | **Excellent** | Right foundation for this problem |
| Tool-level gating | **Excellent** | Agent can't call unauthorized tools |
| Structured arg constraints | **Good** | `OneOf`, `Subset`, `Range` cover structured tool designs |
| Zero-trust unknown args | **Excellent** | Prevents argument injection |
| Raw SQL / query string safety | **Gap** | No `SqlSafe` — analogous to lacking path safety without `Subpath` |
| CEL for complex policies | **Good** | Useful for business logic but can't validate SQL |

---

## Conclusion

**The semantics are right. The constraint vocabulary is incomplete for this domain.**

Tenuo needs a `SqlSafe` semantic constraint to handle database tools the way it handles file paths, URLs, and shell commands today. Until then, the mitigation is to design tools that don't expose raw query strings as arguments — push SQL construction into trusted application code and let Tenuo constrain the structured parameters that feed into it.
