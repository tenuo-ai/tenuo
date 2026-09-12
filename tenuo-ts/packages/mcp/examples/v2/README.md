# Minimal `@tenuo/mcp` v2 example

The smallest runnable picture of where Tenuo attaches and verifies MCP
authority with the official `@modelcontextprotocol/client` and
`@modelcontextprotocol/server` v2 packages. No network, no credentials.

```text
main.ts   in-memory server + client, one guarded tool, one allowed and one denied call
```

Client side, `tenuo.mcp.attach()` from `@tenuo/core` checks the arguments
against the agent's session and signs them onto `_meta.tenuo`. Server side,
`guardTools()` from `@tenuo/mcp` verifies that envelope in Rust before the
handler runs. The denied call reuses a valid envelope with swapped arguments;
the proof no longer matches, the guard answers with a JSON-RPC error, and the
handler never executes.

From `tenuo-ts`:

```bash
pnpm example:mcp:v2
```

Expected output:

```text
allowed  read_file /data/reports/q3.pdf -> contents of /data/reports/q3.pdf
denied   read_file /data/hr/payroll.csv -> TENUO_INVALID_POP (JSON-RPC -32001)
handler executed for: ["/data/reports/q3.pdf"]
```

For the full multi-agent quarterly-close scenario, see
[`packages/core/examples/mcp`](../../../core/examples/mcp/README.md).
