/**
 * Minimal `@tenuo/mcp` example for the official MCP TypeScript v2 packages.
 *
 * One in-memory server, one in-memory client, one guarded tool.
 *
 *   client side  tenuo.mcp.attach()   (@tenuo/core)  puts a warrant and a
 *                                      proof-of-possession on `_meta.tenuo`
 *   server side  guardTools()         (@tenuo/mcp)   verifies that envelope in
 *                                      Rust before the tool handler runs
 *
 * Two requests are sent: one that is allowed and one whose arguments were
 * changed after attach. The second is denied and the handler never executes.
 *
 * Run from `tenuo-ts`: `pnpm example:mcp:v2`
 */
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { createTenuo, under } from "@tenuo/core";
import { guardTools } from "@tenuo/mcp";
import { z } from "zod";

export type ExampleOutcome = {
  /** The allowed call: the handler ran and returned its text. */
  readonly allowed: { readonly isError: boolean; readonly text: string };
  /** The denied call: a JSON-RPC error body, and the handler never ran. */
  readonly denied: {
    readonly isError: boolean;
    readonly rpc?: { readonly code: number; readonly data?: { readonly tenuo?: { readonly code: string } } };
  };
  /** Every path the `read_file` handler actually executed for. */
  readonly executed: readonly string[];
};

export async function runMinimalExample(log: (line: string) => void = console.log): Promise<ExampleOutcome> {
  // Dev-only: one process holds the root key and also verifies. In production
  // the server is built with `trustedRoots: [publicKey]` and never sees a
  // holder secret.
  const tenuo = createTenuo({ root: createTenuo.devRoot() });

  // ---------------------------------------------------------------- server
  // The host ceiling: `read_file` may only ever touch `/data`, whatever the
  // warrant says. `allow` is AND'd with the warrant in Rust and is not
  // advertised to clients.
  const executed: string[] = [];
  const server = new McpServer({ name: "tenuo-minimal", version: "0.3.0" });
  guardTools(tenuo, server).register(
    "read_file",
    {
      description: "Read a file under /data",
      inputSchema: z.object({ path: z.string() }),
      allow: { path: under("/data") },
    },
    async ({ path }) => {
      executed.push(path);
      return { content: [{ type: "text", text: `contents of ${path}` }] };
    },
  );

  // ---------------------------------------------------------------- client
  // A session is a warrant for one agent. This one may read `/data/reports`.
  const session = tenuo.session({
    allow: { read_file: { path: under("/data/reports") } },
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "tenuo-minimal-client", version: "0.3.0" });
  await client.connect(clientTransport);

  try {
    // 1. Allowed. `attach` checks the arguments against the session, then
    //    signs them so the server can prove they were not changed in flight.
    const call = tenuo.mcp.attach(session, "read_file", { path: "/data/reports/q3.pdf" });
    const allowed = summarize(
      await client.callTool({ name: call.name, arguments: call.arguments, _meta: call._meta }),
    );
    log(`allowed  read_file ${call.arguments.path} -> ${allowed.text}`);

    // 2. Denied. Same envelope, but the arguments are swapped after attach.
    //    The proof-of-possession no longer matches, so the guard rejects the
    //    call before the handler runs.
    //    Note the session ceiling above: `attach()` would have refused
    //    `/data/hr/payroll.csv` outright, since it is outside
    //    `/data/reports`. This call is the in-flight swap, which only the
    //    server can catch.
    const denied = summarize(
      await client.callTool({
        name: call.name,
        arguments: { path: "/data/hr/payroll.csv" },
        _meta: call._meta,
      }),
    );
    log(
      `denied   read_file /data/hr/payroll.csv -> ${String(denied.rpc?.data?.tenuo?.code)} (JSON-RPC ${String(denied.rpc?.code)})`,
    );
    log(`handler executed for: ${JSON.stringify(executed)}`);

    return { allowed, denied, executed };
  } finally {
    await client.close();
    await server.close();
  }
}

function summarize(result: Awaited<ReturnType<Client["callTool"]>>): {
  isError: boolean;
  text: string;
  rpc?: { code: number; data?: { tenuo?: { code: string } } };
} {
  const isError = "isError" in result && result.isError === true;
  const content = "content" in result && Array.isArray(result.content) ? result.content : [];
  const first = content[0];
  const text =
    first !== undefined && typeof first === "object" && "text" in first && typeof first.text === "string"
      ? first.text
      : "";
  if (!isError) {
    return { isError, text };
  }
  try {
    return { isError, text, rpc: JSON.parse(text) as { code: number; data?: { tenuo?: { code: string } } } };
  } catch {
    return { isError, text };
  }
}
