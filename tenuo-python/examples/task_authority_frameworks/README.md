# Give an agent room to act, within the task

A coordinator may pay **INV-123 to its verified bank, up to $500**. It delegates
**up to $250 for 60 seconds** to a specialist. The specialist chooses a useful
$200 payment. An already-fooled model then requests a different bank, $400, and
another invoice. **The same payment tool rejects all three before its effect.**

The interesting boundary is the task's resource, destination and delegated
amount—not a read/write permission. These controls constrain tool requests even
when the model asks for the wrong action; they do not prevent prompt injection
or make arbitrary code running beside the verifier safe.

Install [uv](https://docs.astral.sh/uv/), use a checkout of this repo, and run
**one** command from the repository root. No model/provider key, Cloud account,
or real payment is needed. `uv` downloads Python/dependencies on first use.

| Execution path | Quick command |
|---|---|
| OpenAI Agents `Runner` → function tool → payment service | `uv run --no-project tenuo-python/examples/task_authority_frameworks/openai_agents.py` |
| Compiled LangGraph → LangChain `ToolNode` → payment service | `uv run --no-project tenuo-python/examples/task_authority_frameworks/langgraph_tools.py` |
| Temporal workflow → activity → payment service | `uv run --no-project tenuo-python/examples/task_authority_frameworks/temporal.py` |
| MCP 1 client → stdio server → verified tool | `uv run --no-project tenuo-python/examples/task_authority_frameworks/mcp_stdio.py` |
| Same MCP transport with MCP 2 | `uv run --no-project tenuo-python/examples/task_authority_frameworks/mcp2_stdio.py` |

Temporal starts a disposable local server. First use may download the Temporal
CLI/server binary and take longer; it needs permission to bind localhost ports.
The other examples have no external service. MCP uses a temporary local journal
as its fake effect and removes it on exit.

Each prints:

```text
Task: INV-123 → verified-bank. Parent <= $500; worker <= $250, 60s.
ALLOWED worker chooses $200 payment: effects=1
DENIED  fooled model changes destination: effects=0
DENIED  worker spends $400 of parent’s $500: effects=0
DENIED  worker selects another invoice: effects=0
```

All requests—including malicious ones—receive a genuine holder signature. The
receiver verifies the full root-first chain against only the issuer's public
key. A counter/journal after verification proves that denied effects did not
run. Setup errors, failed imports and dispatch failures abort the command;
they cannot satisfy a successful denial demonstration.

## What these integrations demonstrate

Every script pins **released Tenuo 0.3.2** in its inline dependency declaration;
none relies on `main` or a pending API. Pins select a reproducible public API
surface, not every transitive dependency. OpenAI Agents 0.22.0, LangGraph 1.2.11
with LangChain Core 1.6.12, Temporal 1.34.0, MCP 1.30.0/FastMCP 3.4.9 and
MCP 2.3.0/FastMCP 4.1.0 are the tested framework combinations.

OpenAI, LangGraph and Temporal are **generic handler/service integrations**,
not recipes certifying the official Tenuo adapters. They reuse the compact
[`PaymentService`](../task_authority.py), which checks the same argument values
that reach its effect. OpenAI reads original tool JSON because the framework
can coerce typed parameters; LangGraph uses strict parameter types. Temporal
transports only public warrants and a call proof in workflow history and
verifies inside the activity, outside the deterministic workflow. It explicitly
does not retry this demo's authorization denial.

MCP uses the installed SDK's `sign_meta` encoder and `MCPVerifier` with actual
`_meta.tenuo` received over stdio. Its verifier process receives **only the root
public key**, public warrant chain and call proof. It never receives an issuer
or worker private key. There is no invented protocol envelope. Successful
stdio initialization is required before any call can be counted as denied.

These are **development loops**. The other examples co-locate ephemeral issuer,
worker and fake service for quick startup; production must separate issuer and
effect ownership according to the threat model. They demonstrate per-call
attenuation, not cumulative spend, exactly-once execution, replay prevention,
revocation, long-lived workflow renewal, MCP multi-tenant identity, hosted tools,
handoffs or every route through a production framework. The OpenAI script
specifically does not use the released input guardrail as tool authorization.

For no framework dependencies, start with
`uv run --no-project tenuo-python/examples/task_authority.py`.

Focused verification (five actual framework commands plus receiver probes):

```bash
uv run --no-project tenuo-python/examples/task_authority_frameworks/tests/test_examples.py
```
